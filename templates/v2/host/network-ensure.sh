#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"

ensure_network() {
    name=$1
    bridge=$2
    subnet=$3
    gateway=$4

    if ! docker network inspect "$name" >/dev/null 2>&1; then
        docker network create \
            --driver bridge \
            --subnet "$subnet" \
            --gateway "$gateway" \
            --opt "com.docker.network.bridge.name=$bridge" \
            "$name" >/dev/null
    fi

    actual_bridge=$(docker network inspect -f \
        '{{index .Options "com.docker.network.bridge.name"}}' "$name")
    actual_subnet=$(docker network inspect -f \
        '{{(index .IPAM.Config 0).Subnet}}' "$name")
    actual_gateway=$(docker network inspect -f \
        '{{(index .IPAM.Config 0).Gateway}}' "$name")
    [ "$actual_bridge" = "$bridge" ]
    [ "$actual_subnet" = "$subnet" ]
    [ "$actual_gateway" = "$gateway" ]
}

ensure_attachment() {
    network=$1
    address=$2
    current=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"$network\"}}{{.IPAddress}}{{end}}" \
        "$INGRESS_CONTAINER")
    if [ -z "$current" ]; then
        docker network connect --ip "$address" "$network" "$INGRESS_CONTAINER"
        current=$(docker inspect -f \
            "{{with index .NetworkSettings.Networks \"$network\"}}{{.IPAddress}}{{end}}" \
            "$INGRESS_CONTAINER")
    fi
    [ "$current" = "$address" ] || {
        echo "$INGRESS_CONTAINER has $current on $network; expected $address" >&2
        exit 1
    }
}

docker inspect -f '{{.State.Running}}' "$INGRESS_CONTAINER" | grep -Fxq true
ensure_network "$DIRECT_NETWORK" "$DIRECT_BRIDGE" "$DIRECT_SUBNET" "$DIRECT_GATEWAY"
ensure_network "$TRANSIT_NETWORK" "$TRANSIT_BRIDGE" "$TRANSIT_SUBNET" "$TRANSIT_GATEWAY"
ensure_attachment "$DIRECT_NETWORK" "$INGRESS_DIRECT_IP"
ensure_attachment "$TRANSIT_NETWORK" "$INGRESS_TRANSIT_IP"
