#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"

pid=${1:-$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER")}
[ -n "$pid" ] && [ "$pid" != 0 ]
ns() { nsenter -t "$pid" -n -- "$@"; }

transit_if=$(ns ip -o -4 addr show | awk -v wanted="$INGRESS_TRANSIT_IP/24" '
    $4 == wanted { name=$2; sub(/:$/, "", name); print name; exit }
')
[ -n "$transit_if" ]

ns ip -j route show table "$TARGET_ROUTE_TABLE" | \
    "$BASE_DIR/host/default-route-check.py" \
        "$TRANSIT_GATEWAY" "$transit_if" "$INGRESS_TRANSIT_IP"
