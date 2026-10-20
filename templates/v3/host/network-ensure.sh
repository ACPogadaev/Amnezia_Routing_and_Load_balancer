#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
. "$BASE_DIR/multi.env"

ensure_network() {
    name=$1 bridge=$2 subnet=$3 gateway=$4
    if ! docker network inspect "$name" >/dev/null 2>&1; then
        docker network create --driver bridge --subnet "$subnet" --gateway "$gateway" \
            --opt "com.docker.network.bridge.name=$bridge" "$name" >/dev/null
    fi
    [ "$(docker network inspect -f '{{index .Options "com.docker.network.bridge.name"}}' "$name")" = "$bridge" ]
    [ "$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "$name")" = "$subnet" ]
    [ "$(docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' "$name")" = "$gateway" ]
}

ensure_network "$PGDL_NETWORK" "$PGDL_BRIDGE" "$PGDL_SUBNET" "$PGDL_GATEWAY"
ensure_network "$AE_NETWORK" "$AE_BRIDGE" "$AE_SUBNET" "$AE_GATEWAY"
