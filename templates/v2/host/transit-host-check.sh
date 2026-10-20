#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"

ip link show "$TRANSIT_BRIDGE" >/dev/null
[ "$(sysctl -n "net.ipv4.conf.$TRANSIT_BRIDGE.rp_filter")" = 0 ]
ip -j route show table "$HOST_TRANSIT_ROUTE_TABLE" | \
    "$BASE_DIR/host/next-hop-default-check.py" \
        "$EGRESS_CONTAINER_IP" "$TRANSIT_BRIDGE"
ip -N -j rule show | \
    "$BASE_DIR/host/host-rpdb-check.py" "$BASE_DIR/pilot.env"
