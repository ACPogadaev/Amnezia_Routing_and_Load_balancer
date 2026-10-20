#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"
CHAIN=AMNEZIA_LB_V2

iptables -w 5 -N "$CHAIN" 2>/dev/null || true
iptables -w 5 -F "$CHAIN"

# Docker publishes UDP 46777 by DNAT to INGRESS_OUTER_IP on amn0. Preserve
# that exact conntrack reverse path and allow only locally tagged AWG transport.
iptables -w 5 -A "$CHAIN" \
    -i "$INGRESS_OUTER_BRIDGE" -o "$PUBLIC_IF" \
    -s "$INGRESS_OUTER_IP/32" -p udp --sport "$INGRESS_AWG_PORT" \
    -m dscp --dscp "$OUTER_TRANSPORT_DSCP" -j ACCEPT
iptables -w 5 -A "$CHAIN" \
    -i "$INGRESS_OUTER_BRIDGE" -o "$PUBLIC_IF" \
    -s "$INGRESS_OUTER_IP/32" -j DROP

# Docker's default bridge is attached to the ingress container but is never a
# valid Internet path for this pilot.
iptables -w 5 -A "$CHAIN" \
    -i "$INGRESS_AUX_BRIDGE" -o "$PUBLIC_IF" \
    -s "$INGRESS_AUX_IP/32" -j DROP

# Ordinary client traffic leaves through the dedicated direct bridge. The
# earlier native nft guard drops every destination in target_v4 before this
# iptables-nft chain is reached.
iptables -w 5 -A "$CHAIN" \
    -i "$DIRECT_BRIDGE" -o "$PUBLIC_IF" \
    -s "$INGRESS_DIRECT_IP/32" -j ACCEPT
iptables -w 5 -A "$CHAIN" \
    -i "$PUBLIC_IF" -o "$DIRECT_BRIDGE" \
    -d "$INGRESS_DIRECT_IP/32" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Target traffic stays on the transit bridge between the two containers.
iptables -w 5 -A "$CHAIN" \
    -i "$TRANSIT_BRIDGE" -o "$TRANSIT_BRIDGE" \
    -s "$INGRESS_TRANSIT_IP/32" \
    -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -w 5 -A "$CHAIN" \
    -i "$TRANSIT_BRIDGE" -o "$TRANSIT_BRIDGE" \
    -d "$INGRESS_TRANSIT_IP/32" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w 5 -A "$CHAIN" \
    -i "$TRANSIT_BRIDGE" -o "$TRANSIT_BRIDGE" -j DROP

# The egress router has one permitted direct flow: encrypted AWG transport.
iptables -w 5 -A "$CHAIN" \
    -i "$TRANSIT_BRIDGE" -o "$PUBLIC_IF" \
    -s "$EGRESS_CONTAINER_IP/32" -d "$EGRESS_AWG_ENDPOINT_IP/32" \
    -p udp --dport "$EGRESS_AWG_ENDPOINT_PORT" -j ACCEPT
iptables -w 5 -A "$CHAIN" \
    -i "$PUBLIC_IF" -o "$TRANSIT_BRIDGE" \
    -d "$EGRESS_CONTAINER_IP/32" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w 5 -A "$CHAIN" \
    -i "$TRANSIT_BRIDGE" -o "$PUBLIC_IF" -j DROP

iptables -w 5 -A "$CHAIN" -j RETURN

while :; do
    number=$(iptables -w 5 -S DOCKER-USER | awk -v wanted="$CHAIN" '
        $1 == "-A" { n++ }
        $1 == "-A" && $0 ~ ("-j " wanted "([[:space:]]|$)") {
            print n
            exit
        }
    ')
    [ -n "$number" ] || break
    iptables -w 5 -D DOCKER-USER "$number"
done
iptables -w 5 -I DOCKER-USER 1 -j "$CHAIN"

exec "$BASE_DIR/host/docker-user-check.sh"
