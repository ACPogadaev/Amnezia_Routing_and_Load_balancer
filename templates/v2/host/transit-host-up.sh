#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"
RUNTIME_DIR=/run/amnezia-lb-v2
RP_STATE="$RUNTIME_DIR/host-transit-rp-filter"

ip link show "$TRANSIT_BRIDGE" >/dev/null
install -d -m 0755 "$RUNTIME_DIR"
if [ ! -s "$RP_STATE" ]; then
    value=$(sysctl -n "net.ipv4.conf.$TRANSIT_BRIDGE.rp_filter")
    printf 'net.ipv4.conf.%s.rp_filter=%s\n' \
        "$TRANSIT_BRIDGE" "$value" > "$RP_STATE.tmp"
    mv -f "$RP_STATE.tmp" "$RP_STATE"
fi
sysctl -q -w "net.ipv4.conf.$TRANSIT_BRIDGE.rp_filter=0"

replace_rule() {
    priority=$1
    shift
    existing=$(ip -N -o rule show | grep -E "^${priority}:" || true)
    if [ -n "$existing" ]; then
        if ! printf '%s\n' "$existing" | grep -Eq ' proto 99([[:space:]]|$)'; then
            echo "Refusing to replace non-pilot host rule at priority $priority" >&2
            exit 1
        fi
        while ip rule del priority "$priority" 2>/dev/null; do :; done
    fi
    ip rule add priority "$priority" protocol 99 "$@"
}

ip route flush table "$HOST_TRANSIT_ROUTE_TABLE" 2>/dev/null || true
ip route replace default \
    via "$EGRESS_CONTAINER_IP" dev "$TRANSIT_BRIDGE" onlink \
    table "$HOST_TRANSIT_ROUTE_TABLE"
replace_rule "$HOST_TRANSIT_LOOKUP_PRIORITY" \
    iif "$TRANSIT_BRIDGE" from "$INGRESS_TRANSIT_IP/32" \
    lookup "$HOST_TRANSIT_ROUTE_TABLE"
replace_rule "$HOST_TRANSIT_UNREACHABLE_PRIORITY" \
    iif "$TRANSIT_BRIDGE" from "$INGRESS_TRANSIT_IP/32" \
    unreachable
ip route flush cache

exec "$BASE_DIR/host/transit-host-check.sh"
