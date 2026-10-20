#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"
deadline=$(( $(date +%s) + READY_TIMEOUT_SECONDS ))

while [ "$(date +%s)" -lt "$deadline" ]; do
    pid=$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER" 2>/dev/null || true)
    recorded=$(sed -n '1p' /run/amnezia-lb-v2/ingress.ready 2>/dev/null || true)
    if [ -n "$pid" ] && [ "$pid" = "$recorded" ] && \
       "$BASE_DIR/host/transit-host-check.sh" >/dev/null 2>&1 && \
       "$BASE_DIR/host/ingress-check.sh" "$pid" >/dev/null 2>&1; then
        exit 0
    fi
    sleep 2
done

echo "Ingress namespace was not ready within ${READY_TIMEOUT_SECONDS}s" >&2
exit 1
