#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"
nft delete table inet amnezia_lb_v2_trace 2>/dev/null || true
pid=$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER" 2>/dev/null || true)
if [ -n "$pid" ] && [ "$pid" != 0 ]; then
    nsenter -t "$pid" -n nft delete table inet amnezia_lb_v2_trace 2>/dev/null || true
fi
