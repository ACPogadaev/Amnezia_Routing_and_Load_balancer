#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
. "$BASE_DIR/multi.env"
CHAIN=AMNEZIA_LB_MULTI_V3
NAT_CHAIN=AMNEZIA_LB_MULTI_V3_NAT
RAW_CHAIN=AMNEZIA_LB_MULTI_V3_RAW

# Cross-bridge replies legitimately carry an Internet source address.  Keep
# loose RPF on the public and existing interfaces, but disable it on the two
# egress bridges.  Linux uses max(conf/all, conf/IF), so conf/all must be zero.
"$BASE_DIR/host/sysctl-state.sh" apply-v3

# Docker installs raw/PREROUTING drops that reject packets addressed to a
# container when they arrive through another Docker bridge. Permit only the
# return path from the two known egress bridges to the exact ingress transit
# address, before Docker's broader direct-access drop is evaluated.
iptables -w 5 -t raw -N "$RAW_CHAIN" 2>/dev/null || true
iptables -w 5 -t raw -F "$RAW_CHAIN"
iptables -w 5 -t raw -A "$RAW_CHAIN" -i "$PGDL_BRIDGE" \
    -d "$INGRESS_TRANSIT_IP/32" -j ACCEPT
iptables -w 5 -t raw -A "$RAW_CHAIN" -i "$AE_BRIDGE" \
    -d "$INGRESS_TRANSIT_IP/32" -j ACCEPT
iptables -w 5 -t raw -A "$RAW_CHAIN" -j RETURN
while iptables -w 5 -t raw -D PREROUTING -j "$RAW_CHAIN" 2>/dev/null; do :; done
iptables -w 5 -t raw -I PREROUTING 1 -j "$RAW_CHAIN"

# Docker normally masquerades packets when they leave one user-defined bridge
# through another.  Preserve the ingress transit address for the two routed
# inter-bridge paths so that the egress containers can enforce their exact
# source-address fail-closed rules and return traffic through conntrack.
iptables -w 5 -t nat -N "$NAT_CHAIN" 2>/dev/null || true
iptables -w 5 -t nat -F "$NAT_CHAIN"
iptables -w 5 -t nat -A "$NAT_CHAIN" -s "$INGRESS_TRANSIT_IP/32" \
    -o "$PGDL_BRIDGE" -j ACCEPT
iptables -w 5 -t nat -A "$NAT_CHAIN" -s "$INGRESS_TRANSIT_IP/32" \
    -o "$AE_BRIDGE" -j ACCEPT
iptables -w 5 -t nat -A "$NAT_CHAIN" -j RETURN
while iptables -w 5 -t nat -D POSTROUTING -j "$NAT_CHAIN" 2>/dev/null; do :; done
iptables -w 5 -t nat -I POSTROUTING 1 -j "$NAT_CHAIN"

iptables -w 5 -N "$CHAIN" 2>/dev/null || true
iptables -w 5 -F "$CHAIN"

for spec in "$PGDL_BRIDGE:$PGDL_CONTAINER_IP" "$AE_BRIDGE:$AE_CONTAINER_IP"; do
    bridge=${spec%%:*}
    ip=${spec#*:}
    iptables -w 5 -A "$CHAIN" -i "$INGRESS_TRANSIT_BRIDGE" -o "$bridge" \
        -s "$INGRESS_TRANSIT_IP/32" \
        -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
    iptables -w 5 -A "$CHAIN" -i "$bridge" -o "$INGRESS_TRANSIT_BRIDGE" \
        -d "$INGRESS_TRANSIT_IP/32" \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -w 5 -A "$CHAIN" -i "$INGRESS_TRANSIT_BRIDGE" -o "$bridge" -j DROP
    iptables -w 5 -A "$CHAIN" -i "$bridge" -o "$INGRESS_TRANSIT_BRIDGE" -j DROP
done

iptables -w 5 -A "$CHAIN" -i "$PGDL_BRIDGE" -o "$PUBLIC_IF" \
    -s "$PGDL_CONTAINER_IP/32" -d "$PGDL_ENDPOINT_IP/32" \
    -p udp --dport "$PGDL_ENDPOINT_PORT" -j ACCEPT
iptables -w 5 -A "$CHAIN" -i "$PUBLIC_IF" -o "$PGDL_BRIDGE" \
    -d "$PGDL_CONTAINER_IP/32" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w 5 -A "$CHAIN" -i "$PGDL_BRIDGE" -o "$PUBLIC_IF" -j DROP

iptables -w 5 -A "$CHAIN" -i "$AE_BRIDGE" -o "$PUBLIC_IF" \
    -s "$AE_CONTAINER_IP/32" -d "$AE_ENDPOINT_IP/32" \
    -p udp --dport "$AE_ENDPOINT_PORT" -j ACCEPT
iptables -w 5 -A "$CHAIN" -i "$PUBLIC_IF" -o "$AE_BRIDGE" \
    -d "$AE_CONTAINER_IP/32" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w 5 -A "$CHAIN" -i "$AE_BRIDGE" -o "$PUBLIC_IF" -j DROP
iptables -w 5 -A "$CHAIN" -j RETURN

while iptables -w 5 -D DOCKER-USER -j "$CHAIN" 2>/dev/null; do :; done
v2_position=$(iptables -w 5 -S DOCKER-USER | awk '
    $1 == "-A" { n++ }
    $1 == "-A" && $0 ~ /-j AMNEZIA_LB_V2([[:space:]]|$)/ { print n; exit }
')
[ -n "$v2_position" ] || {
    echo 'The v2 DOCKER-USER jump is missing' >&2
    exit 1
}
iptables -w 5 -I DOCKER-USER "$((v2_position + 1))" -j "$CHAIN"
exec "$BASE_DIR/host/docker-user-check.sh"
