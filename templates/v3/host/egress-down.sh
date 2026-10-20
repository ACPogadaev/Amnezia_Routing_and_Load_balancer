#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
docker compose --env-file "$BASE_DIR/multi.env" \
    -f "$BASE_DIR/egress/compose.yaml" down --remove-orphans
