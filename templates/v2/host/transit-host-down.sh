#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"

for priority in "$HOST_TRANSIT_LOOKUP_PRIORITY" "$HOST_TRANSIT_UNREACHABLE_PRIORITY"; do
    rule=$(ip -N -o rule show | grep -E "^${priority}:" || true)
    if [ -z "$rule" ]; then
        continue
    fi
    if printf '%s\n' "$rule" | grep -Eq ' proto 99([[:space:]]|$)'; then
        while ip rule del priority "$priority" 2>/dev/null; do :; done
    else
        echo "Leaving non-pilot host rule at priority $priority" >&2
    fi
done
ip route flush table "$HOST_TRANSIT_ROUTE_TABLE" 2>/dev/null || true

RP_STATE=/run/amnezia-lb-v2/host-transit-rp-filter
if [ -s "$RP_STATE" ]; then
    while IFS='=' read -r key value; do
        case "$key" in
            net.ipv4.conf.*.rp_filter) sysctl -q -w "$key=$value" 2>/dev/null || true ;;
        esac
    done < "$RP_STATE"
    rm -f "$RP_STATE"
fi
ip route flush cache
