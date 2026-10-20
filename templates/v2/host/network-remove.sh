#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"

for network in "$DIRECT_NETWORK" "$TRANSIT_NETWORK"; do
    if docker network inspect "$network" >/dev/null 2>&1; then
        docker network disconnect -f "$network" "$INGRESS_CONTAINER" 2>/dev/null || true
        docker network rm "$network" >/dev/null
    fi
done
