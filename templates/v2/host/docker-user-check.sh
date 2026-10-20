#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"
CHAIN=AMNEZIA_LB_V2

rules=$(iptables -w 5 -S "$CHAIN")
count=$(printf '%s\n' "$rules" | awk '$1 == "-A" { n++ } END { print n + 0 }')
[ "$count" -eq 12 ]

require_rule_at() {
    position=$1
    shift
    line=$(printf '%s\n' "$rules" | awk -v wanted="$position" '
        $1 == "-A" { n++ }
        n == wanted { print; exit }
    ')
    [ -n "$line" ]
    for needle in "$@"; do
        printf '%s\n' "$line" | grep -Fq -- "$needle"
    done
}

jumps=$(iptables -w 5 -S DOCKER-USER)
refs=$(printf '%s\n' "$jumps" | awk -v wanted="$CHAIN" '
    $1 == "-A" && $0 ~ ("-j " wanted "([[:space:]]|$)") { n++ }
    END { print n + 0 }
')
[ "$refs" -eq 1 ]
first=$(printf '%s\n' "$jumps" | awk '$1 == "-A" { print; exit }')
printf '%s\n' "$first" | grep -Eq -- "-j ${CHAIN}([[:space:]]|$)"

iptables -w 5 -C "$CHAIN" \
    -i "$INGRESS_OUTER_BRIDGE" -o "$PUBLIC_IF" \
    -s "$INGRESS_OUTER_IP/32" -p udp --sport "$INGRESS_AWG_PORT" \
    -m dscp --dscp "$OUTER_TRANSPORT_DSCP" -j ACCEPT
iptables -w 5 -C "$CHAIN" \
    -i "$INGRESS_OUTER_BRIDGE" -o "$PUBLIC_IF" \
    -s "$INGRESS_OUTER_IP/32" -j DROP
iptables -w 5 -C "$CHAIN" \
    -i "$INGRESS_AUX_BRIDGE" -o "$PUBLIC_IF" \
    -s "$INGRESS_AUX_IP/32" -j DROP

iptables -w 5 -C "$CHAIN" \
    -i "$DIRECT_BRIDGE" -o "$PUBLIC_IF" \
    -s "$INGRESS_DIRECT_IP/32" -j ACCEPT
iptables -w 5 -C "$CHAIN" \
    -i "$PUBLIC_IF" -o "$DIRECT_BRIDGE" \
    -d "$INGRESS_DIRECT_IP/32" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -w 5 -C "$CHAIN" \
    -i "$TRANSIT_BRIDGE" -o "$TRANSIT_BRIDGE" \
    -s "$INGRESS_TRANSIT_IP/32" \
    -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -w 5 -C "$CHAIN" \
    -i "$TRANSIT_BRIDGE" -o "$TRANSIT_BRIDGE" \
    -d "$INGRESS_TRANSIT_IP/32" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w 5 -C "$CHAIN" \
    -i "$TRANSIT_BRIDGE" -o "$TRANSIT_BRIDGE" -j DROP

iptables -w 5 -C "$CHAIN" \
    -i "$TRANSIT_BRIDGE" -o "$PUBLIC_IF" \
    -s "$EGRESS_CONTAINER_IP/32" -d "$EGRESS_AWG_ENDPOINT_IP/32" \
    -p udp --dport "$EGRESS_AWG_ENDPOINT_PORT" -j ACCEPT
iptables -w 5 -C "$CHAIN" \
    -i "$PUBLIC_IF" -o "$TRANSIT_BRIDGE" \
    -d "$EGRESS_CONTAINER_IP/32" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w 5 -C "$CHAIN" \
    -i "$TRANSIT_BRIDGE" -o "$PUBLIC_IF" -j DROP
iptables -w 5 -C "$CHAIN" -j RETURN

# -C plus the exact count proves the set of rules. These positional
# signatures additionally prove their evaluation order without depending on
# cosmetic iptables -S differences such as an inserted "-m udp" token.
require_rule_at 1 \
    "-i $INGRESS_OUTER_BRIDGE" "-o $PUBLIC_IF" \
    "--sport $INGRESS_AWG_PORT" "--dscp" "-j ACCEPT"
require_rule_at 2 \
    "-i $INGRESS_OUTER_BRIDGE" "-o $PUBLIC_IF" \
    "-s $INGRESS_OUTER_IP/32" "-j DROP"
require_rule_at 3 \
    "-i $INGRESS_AUX_BRIDGE" "-s $INGRESS_AUX_IP/32" "-j DROP"
require_rule_at 4 \
    "-i $DIRECT_BRIDGE" "-s $INGRESS_DIRECT_IP/32" "-j ACCEPT"
require_rule_at 5 \
    "-i $PUBLIC_IF" "-o $DIRECT_BRIDGE" "-d $INGRESS_DIRECT_IP/32" \
    "--ctstate" "-j ACCEPT"
require_rule_at 6 \
    "-i $TRANSIT_BRIDGE" "-o $TRANSIT_BRIDGE" \
    "-s $INGRESS_TRANSIT_IP/32" \
    "--ctstate" "-j ACCEPT"
require_rule_at 7 \
    "-i $TRANSIT_BRIDGE" "-o $TRANSIT_BRIDGE" \
    "-d $INGRESS_TRANSIT_IP/32" \
    "--ctstate" "-j ACCEPT"
require_rule_at 8 \
    "-i $TRANSIT_BRIDGE" "-o $TRANSIT_BRIDGE" "-j DROP"
require_rule_at 9 \
    "-s $EGRESS_CONTAINER_IP/32" "-d $EGRESS_AWG_ENDPOINT_IP/32" \
    "--dport $EGRESS_AWG_ENDPOINT_PORT" "-j ACCEPT"
require_rule_at 10 \
    "-i $PUBLIC_IF" "-o $TRANSIT_BRIDGE" "-d $EGRESS_CONTAINER_IP/32" \
    "--ctstate" "-j ACCEPT"
require_rule_at 11 \
    "-i $TRANSIT_BRIDGE" "-o $PUBLIC_IF" "-j DROP"
require_rule_at 12 "-A $CHAIN -j RETURN"
