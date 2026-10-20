#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"
READY_FILE=/run/amnezia-lb-v2/egress-policy-ready

[ "$(docker inspect -f '{{.State.Running}}' "$EGRESS_CONTAINER" 2>/dev/null)" = true ]
pid=$(docker inspect -f '{{.State.Pid}}' "$EGRESS_CONTAINER")
case "$pid" in
    ''|*[!0-9]*|0*) exit 1 ;;
esac

# Docker 29 keeps /proc/sys read-only inside an unprivileged container. The
# container therefore publishes readiness only after all RPDB/filter/NAT
# policy is installed; the host then flips the namespaced sysctl. A PID check
# on both sides prevents enabling a replacement namespace by mistake.
docker exec "$EGRESS_CONTAINER" test -s "$READY_FILE"
"$BASE_DIR/host/guard-check.sh"
[ "$(docker inspect -f '{{.State.Pid}}' "$EGRESS_CONTAINER")" = "$pid" ]

current=$(nsenter -t "$pid" -n sysctl -n net.ipv4.ip_forward)
case "$current" in
    0) nsenter -t "$pid" -n sysctl -q -w net.ipv4.ip_forward=1 ;;
    1) ;;
    *) echo "Unexpected egress ip_forward value: $current" >&2; exit 1 ;;
esac

[ "$(docker inspect -f '{{.State.Pid}}' "$EGRESS_CONTAINER")" = "$pid" ]
[ "$(nsenter -t "$pid" -n sysctl -n net.ipv4.ip_forward)" = 1 ]
