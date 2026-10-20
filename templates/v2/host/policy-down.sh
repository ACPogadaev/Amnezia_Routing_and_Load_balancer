#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"
STATE_ROOT=/var/lib/amnezia-lb
LOCK_FILE="$STATE_ROOT/state.lock"
install -d -m 0700 "$STATE_ROOT"
touch "$LOCK_FILE"
chmod 0600 "$LOCK_FILE"
exec 9>"$LOCK_FILE"
flock -x 9
pid=$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER" 2>/dev/null || true)
if [ -n "$pid" ] && [ "$pid" != 0 ]; then
    nsenter -t "$pid" -n ip route flush table "$TARGET_ROUTE_TABLE" 2>/dev/null || true
    nsenter -t "$pid" -n ip route flush cache
fi
