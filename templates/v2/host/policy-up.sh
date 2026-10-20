#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"
STATE_ROOT=/var/lib/amnezia-lb
MAINTENANCE_FILE="$STATE_ROOT/maintenance"
LOCK_FILE="$STATE_ROOT/state.lock"
install -d -m 0700 "$STATE_ROOT"
touch "$LOCK_FILE"
chmod 0600 "$LOCK_FILE"
exec 9>"$LOCK_FILE"
flock -x 9
[ ! -e "$MAINTENANCE_FILE" ] || {
    echo 'Target admission remains closed during maintenance' >&2
    exit 1
}
pid=$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER")
[ -n "$pid" ] && [ "$pid" != 0 ]

transit_if=$(nsenter -t "$pid" -n ip -o -4 addr show | \
    awk -v wanted="$INGRESS_TRANSIT_IP/24" '
        $4 == wanted { name=$2; sub(/:$/, "", name); print name; exit }
    ')
[ -n "$transit_if" ]

nsenter -t "$pid" -n ip route replace default \
    via "$TRANSIT_GATEWAY" dev "$transit_if" onlink \
    src "$INGRESS_TRANSIT_IP" \
    table "$TARGET_ROUTE_TABLE"
nsenter -t "$pid" -n ip route flush cache
