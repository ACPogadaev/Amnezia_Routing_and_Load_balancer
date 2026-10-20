#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
. "$BASE_DIR/multi.env"
CHAIN=AMNEZIA_LB_MULTI_V3
NAT_CHAIN=AMNEZIA_LB_MULTI_V3_NAT
RAW_CHAIN=AMNEZIA_LB_MULTI_V3_RAW
"$BASE_DIR/host/sysctl-state.sh" check-v3
rules=$(iptables -w 5 -S "$CHAIN")
count=$(printf '%s\n' "$rules" | awk '$1=="-A" {n++} END {print n+0}')
[ "$count" -eq 15 ]

require_rule_at() {
    data=$1 position=$2
    shift 2
    line=$(printf '%s\n' "$data" | awk -v wanted="$position" \
        '$1=="-A" {n++} n==wanted {print; exit}')
    [ -n "$line" ]
    for needle in "$@"; do
        printf '%s\n' "$line" | grep -Fq -- "$needle"
    done
}
refs=$(iptables -w 5 -S DOCKER-USER | grep -Ec -- "-j ${CHAIN}([[:space:]]|$)" || true)
[ "$refs" -eq 1 ]
first_two=$(iptables -w 5 -S DOCKER-USER | awk '$1=="-A" {print; n++} n==2 {exit}')
printf '%s\n' "$first_two" | sed -n '1p' | grep -Eq -- '-j AMNEZIA_LB_V2([[:space:]]|$)'
printf '%s\n' "$first_two" | sed -n '2p' | grep -Eq -- "-j ${CHAIN}([[:space:]]|$)"

raw_rules=$(iptables -w 5 -t raw -S "$RAW_CHAIN")
raw_count=$(printf '%s\n' "$raw_rules" | awk '$1=="-A" {n++} END {print n+0}')
[ "$raw_count" -eq 3 ]
raw_refs=$(iptables -w 5 -t raw -S PREROUTING | \
    grep -Ec -- "-j ${RAW_CHAIN}([[:space:]]|$)" || true)
[ "$raw_refs" -eq 1 ]
first_raw=$(iptables -w 5 -t raw -S PREROUTING | awk '$1=="-A" {print; exit}')
printf '%s\n' "$first_raw" | grep -Eq -- "-j ${RAW_CHAIN}([[:space:]]|$)"
iptables -w 5 -t raw -C PREROUTING -j "$RAW_CHAIN"
iptables -w 5 -t raw -C "$RAW_CHAIN" -i "$PGDL_BRIDGE" \
    -d "$INGRESS_TRANSIT_IP/32" -j ACCEPT
iptables -w 5 -t raw -C "$RAW_CHAIN" -i "$AE_BRIDGE" \
    -d "$INGRESS_TRANSIT_IP/32" -j ACCEPT
iptables -w 5 -t raw -C "$RAW_CHAIN" -j RETURN
printf '%s\n' "$raw_rules" | tail -n 1 | \
    grep -Eq -- "^-A ${RAW_CHAIN} -j RETURN$"
require_rule_at "$raw_rules" 1 "-i $PGDL_BRIDGE" "-d $INGRESS_TRANSIT_IP/32" "-j ACCEPT"
require_rule_at "$raw_rules" 2 "-i $AE_BRIDGE" "-d $INGRESS_TRANSIT_IP/32" "-j ACCEPT"
require_rule_at "$raw_rules" 3 "-A $RAW_CHAIN -j RETURN"

nat_rules=$(iptables -w 5 -t nat -S "$NAT_CHAIN")
nat_count=$(printf '%s\n' "$nat_rules" | awk '$1=="-A" {n++} END {print n+0}')
[ "$nat_count" -eq 3 ]
nat_refs=$(iptables -w 5 -t nat -S POSTROUTING | \
    grep -Ec -- "-j ${NAT_CHAIN}([[:space:]]|$)" || true)
[ "$nat_refs" -eq 1 ]
first_nat=$(iptables -w 5 -t nat -S POSTROUTING | awk '$1=="-A" {print; exit}')
printf '%s\n' "$first_nat" | grep -Eq -- "-j ${NAT_CHAIN}([[:space:]]|$)"
iptables -w 5 -t nat -C POSTROUTING -j "$NAT_CHAIN"
iptables -w 5 -t nat -C "$NAT_CHAIN" -s "$INGRESS_TRANSIT_IP/32" \
    -o "$PGDL_BRIDGE" -j ACCEPT
iptables -w 5 -t nat -C "$NAT_CHAIN" -s "$INGRESS_TRANSIT_IP/32" \
    -o "$AE_BRIDGE" -j ACCEPT
iptables -w 5 -t nat -C "$NAT_CHAIN" -j RETURN
printf '%s\n' "$nat_rules" | tail -n 1 | \
    grep -Eq -- "^-A ${NAT_CHAIN} -j RETURN$"
require_rule_at "$nat_rules" 1 "-s $INGRESS_TRANSIT_IP/32" "-o $PGDL_BRIDGE" "-j ACCEPT"
require_rule_at "$nat_rules" 2 "-s $INGRESS_TRANSIT_IP/32" "-o $AE_BRIDGE" "-j ACCEPT"
require_rule_at "$nat_rules" 3 "-A $NAT_CHAIN -j RETURN"

for spec in "$PGDL_BRIDGE:$PGDL_CONTAINER_IP" "$AE_BRIDGE:$AE_CONTAINER_IP"; do
    bridge=${spec%%:*}
    ip=${spec#*:}
    iptables -w 5 -C "$CHAIN" -i "$INGRESS_TRANSIT_BRIDGE" -o "$bridge" \
        -s "$INGRESS_TRANSIT_IP/32" \
        -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
    iptables -w 5 -C "$CHAIN" -i "$bridge" -o "$INGRESS_TRANSIT_BRIDGE" \
        -d "$INGRESS_TRANSIT_IP/32" \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -w 5 -C "$CHAIN" -i "$INGRESS_TRANSIT_BRIDGE" -o "$bridge" -j DROP
    iptables -w 5 -C "$CHAIN" -i "$bridge" -o "$INGRESS_TRANSIT_BRIDGE" -j DROP
done

require_rule_at "$rules" 1 "-i $INGRESS_TRANSIT_BRIDGE" "-o $PGDL_BRIDGE" "-s $INGRESS_TRANSIT_IP/32" "--ctstate" "-j ACCEPT"
require_rule_at "$rules" 2 "-i $PGDL_BRIDGE" "-o $INGRESS_TRANSIT_BRIDGE" "-d $INGRESS_TRANSIT_IP/32" "--ctstate" "-j ACCEPT"
require_rule_at "$rules" 3 "-i $INGRESS_TRANSIT_BRIDGE" "-o $PGDL_BRIDGE" "-j DROP"
require_rule_at "$rules" 4 "-i $PGDL_BRIDGE" "-o $INGRESS_TRANSIT_BRIDGE" "-j DROP"
require_rule_at "$rules" 5 "-i $INGRESS_TRANSIT_BRIDGE" "-o $AE_BRIDGE" "-s $INGRESS_TRANSIT_IP/32" "--ctstate" "-j ACCEPT"
require_rule_at "$rules" 6 "-i $AE_BRIDGE" "-o $INGRESS_TRANSIT_BRIDGE" "-d $INGRESS_TRANSIT_IP/32" "--ctstate" "-j ACCEPT"
require_rule_at "$rules" 7 "-i $INGRESS_TRANSIT_BRIDGE" "-o $AE_BRIDGE" "-j DROP"
require_rule_at "$rules" 8 "-i $AE_BRIDGE" "-o $INGRESS_TRANSIT_BRIDGE" "-j DROP"

iptables -w 5 -C "$CHAIN" -i "$PGDL_BRIDGE" -o "$PUBLIC_IF" \
    -s "$PGDL_CONTAINER_IP/32" -d "$PGDL_ENDPOINT_IP/32" \
    -p udp --dport "$PGDL_ENDPOINT_PORT" -j ACCEPT
iptables -w 5 -C "$CHAIN" -i "$PUBLIC_IF" -o "$PGDL_BRIDGE" \
    -d "$PGDL_CONTAINER_IP/32" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w 5 -C "$CHAIN" -i "$PGDL_BRIDGE" -o "$PUBLIC_IF" -j DROP
iptables -w 5 -C "$CHAIN" -i "$AE_BRIDGE" -o "$PUBLIC_IF" \
    -s "$AE_CONTAINER_IP/32" -d "$AE_ENDPOINT_IP/32" \
    -p udp --dport "$AE_ENDPOINT_PORT" -j ACCEPT
iptables -w 5 -C "$CHAIN" -i "$PUBLIC_IF" -o "$AE_BRIDGE" \
    -d "$AE_CONTAINER_IP/32" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w 5 -C "$CHAIN" -i "$AE_BRIDGE" -o "$PUBLIC_IF" -j DROP
iptables -w 5 -C "$CHAIN" -j RETURN
printf '%s\n' "$rules" | tail -n 1 | grep -Eq -- "^-A ${CHAIN} -j RETURN$"
require_rule_at "$rules" 9 "-i $PGDL_BRIDGE" "-o $PUBLIC_IF" "-s $PGDL_CONTAINER_IP/32" "-d $PGDL_ENDPOINT_IP/32" "--dport $PGDL_ENDPOINT_PORT" "-j ACCEPT"
require_rule_at "$rules" 10 "-i $PUBLIC_IF" "-o $PGDL_BRIDGE" "-d $PGDL_CONTAINER_IP/32" "--ctstate" "-j ACCEPT"
require_rule_at "$rules" 11 "-i $PGDL_BRIDGE" "-o $PUBLIC_IF" "-j DROP"
require_rule_at "$rules" 12 "-i $AE_BRIDGE" "-o $PUBLIC_IF" "-s $AE_CONTAINER_IP/32" "-d $AE_ENDPOINT_IP/32" "--dport $AE_ENDPOINT_PORT" "-j ACCEPT"
require_rule_at "$rules" 13 "-i $PUBLIC_IF" "-o $AE_BRIDGE" "-d $AE_CONTAINER_IP/32" "--ctstate" "-j ACCEPT"
require_rule_at "$rules" 14 "-i $AE_BRIDGE" "-o $PUBLIC_IF" "-j DROP"
require_rule_at "$rules" 15 "-A $CHAIN -j RETURN"
