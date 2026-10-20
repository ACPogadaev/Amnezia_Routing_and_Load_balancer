#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"

pid=${1:-$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER")}
[ -n "$pid" ] && [ "$pid" != 0 ]
ns() { nsenter -t "$pid" -n -- "$@"; }

iface_for_ip() {
    address=$1
    ns ip -o -4 addr show | awk -v wanted="$address" '
        $4 == wanted { name=$2; sub(/:$/, "", name); print name; exit }
    '
}

chain_rule_count() {
    command=$1
    table=$2
    chain=$3
    ns "$command" -w 5 -t "$table" -S "$chain" | \
        awk '$1 == "-A" { n++ } END { print n + 0 }'
}

require_chain_rule_at() {
    command=$1
    table=$2
    chain=$3
    position=$4
    shift 4
    line=$(ns "$command" -w 5 -t "$table" -S "$chain" | \
        awk -v wanted="$position" '
            $1 == "-A" { n++ }
            n == wanted { print; exit }
        ')
    [ -n "$line" ]
    for needle in "$@"; do
        printf '%s\n' "$line" | grep -Fq -- "$needle"
    done
}

require_single_first_jump() {
    command=$1
    table=$2
    builtin=$3
    target=$4
    data=$(ns "$command" -w 5 -t "$table" -S "$builtin")
    refs=$(printf '%s\n' "$data" | awk -v wanted="$target" '
        $1 == "-A" && $0 ~ ("-j " wanted "([[:space:]]|$)") { n++ }
        END { print n + 0 }
    ')
    [ "$refs" -eq 1 ]
    first=$(printf '%s\n' "$data" | awk '$1 == "-A" { print; exit }')
    printf '%s\n' "$first" | grep -Eq -- "-j ${target}([[:space:]]|$)"
}

outer_if=$(iface_for_ip "$INGRESS_OUTER_IP/24")
aux_if=$(iface_for_ip "$INGRESS_AUX_IP/16")
direct_if=$(iface_for_ip "$INGRESS_DIRECT_IP/24")
transit_if=$(iface_for_ip "$INGRESS_TRANSIT_IP/24")
for value in "$outer_if" "$aux_if" "$direct_if" "$transit_if"; do
    [ -n "$value" ]
done

for pair in \
    "$INGRESS_OUTER_NETWORK:$INGRESS_OUTER_IP" \
    "$INGRESS_DNS_NETWORK:$INGRESS_DNS_IP" \
    "$INGRESS_AUX_NETWORK:$INGRESS_AUX_IP" \
    "$DIRECT_NETWORK:$INGRESS_DIRECT_IP" \
    "$TRANSIT_NETWORK:$INGRESS_TRANSIT_IP"; do
    network=${pair%%:*}
    address=${pair#*:}
    actual=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"$network\"}}{{.IPAddress}}{{end}}" \
        "$INGRESS_CONTAINER")
    [ "$actual" = "$address" ]
done

ns ip -j route show table main default | \
    "$BASE_DIR/host/default-route-check.py" \
        "$INGRESS_OUTER_GATEWAY" "$outer_if" "$INGRESS_OUTER_IP"
ns ip -j route show table "$OUTER_ROUTE_TABLE" | \
    "$BASE_DIR/host/default-route-check.py" \
        "$INGRESS_OUTER_GATEWAY" "$outer_if" "$INGRESS_OUTER_IP"
ns ip -j route show table "$DIRECT_ROUTE_TABLE" | \
    "$BASE_DIR/host/default-route-check.py" \
        "$DIRECT_GATEWAY" "$direct_if" "$INGRESS_DIRECT_IP"
ns ip -N -j rule show | "$BASE_DIR/host/rpdb-check.py" "$BASE_DIR/pilot.env"
"$BASE_DIR/host/docker-dnat-check.sh"

if ns iptables -w 5 -t mangle -S AMNEZIA_LB_V2_CLASSIFY >/dev/null 2>&1; then
    echo "Legacy scalar classifier is still present" >&2
    exit 1
fi
if ns iptables -w 5 -t mangle -S PREROUTING | \
    grep -Eq -- '-j AMNEZIA_LB_V2_CLASSIFY([[:space:]]|$)'; then
    echo "Legacy scalar classifier jump is still present" >&2
    exit 1
fi
"$BASE_DIR/host/ingress-targets-check.sh" "$pid"

ns iptables -w 5 -t mangle -C OUTPUT -j AMNEZIA_LB_V2_OUTER
require_single_first_jump iptables mangle OUTPUT AMNEZIA_LB_V2_OUTER
[ "$(chain_rule_count iptables mangle AMNEZIA_LB_V2_OUTER)" -eq 2 ]
ns iptables -w 5 -t mangle -C AMNEZIA_LB_V2_OUTER \
    -o "$outer_if" -p udp --sport "$INGRESS_AWG_PORT" \
    -j DSCP --set-dscp "$OUTER_TRANSPORT_DSCP"
ns iptables -w 5 -t mangle -C AMNEZIA_LB_V2_OUTER -j RETURN
require_chain_rule_at iptables mangle AMNEZIA_LB_V2_OUTER 1 \
    "-o $outer_if" "--sport $INGRESS_AWG_PORT" \
    "-j DSCP" "--set-dscp"
require_chain_rule_at iptables mangle AMNEZIA_LB_V2_OUTER 2 \
    "-A AMNEZIA_LB_V2_OUTER -j RETURN"

ns iptables -w 5 -t nat -C POSTROUTING -j AMNEZIA_LB_V2_NAT
require_single_first_jump iptables nat POSTROUTING AMNEZIA_LB_V2_NAT
[ "$(chain_rule_count iptables nat AMNEZIA_LB_V2_NAT)" -eq 3 ]
ns iptables -w 5 -t nat -C AMNEZIA_LB_V2_NAT \
    -s "$INGRESS_CLIENT_SUBNET" -o "$transit_if" \
    -j SNAT --to-source "$INGRESS_TRANSIT_IP"
ns iptables -w 5 -t nat -C AMNEZIA_LB_V2_NAT \
    -s "$INGRESS_CLIENT_SUBNET" -o "$direct_if" \
    -j SNAT --to-source "$INGRESS_DIRECT_IP"
ns iptables -w 5 -t nat -C AMNEZIA_LB_V2_NAT -j RETURN
require_chain_rule_at iptables nat AMNEZIA_LB_V2_NAT 1 \
    "-s $INGRESS_CLIENT_SUBNET" "-o $transit_if" \
    "--to-source $INGRESS_TRANSIT_IP"
require_chain_rule_at iptables nat AMNEZIA_LB_V2_NAT 2 \
    "-s $INGRESS_CLIENT_SUBNET" "-o $direct_if" \
    "--to-source $INGRESS_DIRECT_IP"
require_chain_rule_at iptables nat AMNEZIA_LB_V2_NAT 3 \
    "-A AMNEZIA_LB_V2_NAT -j RETURN"

ns iptables -w 5 -C FORWARD -j AMNEZIA_LB_V2_FORWARD
require_single_first_jump iptables filter FORWARD AMNEZIA_LB_V2_FORWARD
[ "$(chain_rule_count iptables filter AMNEZIA_LB_V2_FORWARD)" -eq 7 ]
ns iptables -w 5 -C AMNEZIA_LB_V2_FORWARD -j AMNEZIA_LB_V2_TEST
ns iptables -w 5 -C AMNEZIA_LB_V2_TEST -j RETURN
require_chain_rule_at iptables filter AMNEZIA_LB_V2_TEST \
    "$(chain_rule_count iptables filter AMNEZIA_LB_V2_TEST)" \
    "-A AMNEZIA_LB_V2_TEST -j RETURN"
ns iptables -w 5 -C AMNEZIA_LB_V2_FORWARD \
    -i "$transit_if" -o "$INGRESS_AWG_IF" \
    -d "$INGRESS_CLIENT_SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED \
    -j ACCEPT
ns iptables -w 5 -C AMNEZIA_LB_V2_FORWARD \
    -i "$direct_if" -o "$INGRESS_AWG_IF" \
    -d "$INGRESS_CLIENT_SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED \
    -j ACCEPT
ns iptables -w 5 -C AMNEZIA_LB_V2_FORWARD \
    -i "$INGRESS_AWG_IF" -o "$transit_if" \
    -s "$INGRESS_CLIENT_SUBNET" -j ACCEPT
ns iptables -w 5 -C AMNEZIA_LB_V2_FORWARD \
    -i "$INGRESS_AWG_IF" -o "$direct_if" \
    -s "$INGRESS_CLIENT_SUBNET" -j ACCEPT
ns iptables -w 5 -C AMNEZIA_LB_V2_FORWARD \
    -i "$INGRESS_AWG_IF" -s "$INGRESS_CLIENT_SUBNET" -j REJECT
ns iptables -w 5 -C AMNEZIA_LB_V2_FORWARD -j RETURN
require_chain_rule_at iptables filter AMNEZIA_LB_V2_FORWARD 1 \
    "-A AMNEZIA_LB_V2_FORWARD -j AMNEZIA_LB_V2_TEST"
require_chain_rule_at iptables filter AMNEZIA_LB_V2_FORWARD 2 \
    "-i $transit_if" "-o $INGRESS_AWG_IF" \
    "-d $INGRESS_CLIENT_SUBNET" "--ctstate" "-j ACCEPT"
require_chain_rule_at iptables filter AMNEZIA_LB_V2_FORWARD 3 \
    "-i $direct_if" "-o $INGRESS_AWG_IF" \
    "-d $INGRESS_CLIENT_SUBNET" "--ctstate" "-j ACCEPT"
require_chain_rule_at iptables filter AMNEZIA_LB_V2_FORWARD 4 \
    "-i $INGRESS_AWG_IF" "-o $transit_if" \
    "-s $INGRESS_CLIENT_SUBNET" "-j ACCEPT"
require_chain_rule_at iptables filter AMNEZIA_LB_V2_FORWARD 5 \
    "-i $INGRESS_AWG_IF" "-o $direct_if" \
    "-s $INGRESS_CLIENT_SUBNET" "-j ACCEPT"
require_chain_rule_at iptables filter AMNEZIA_LB_V2_FORWARD 6 \
    "-i $INGRESS_AWG_IF" "-s $INGRESS_CLIENT_SUBNET" "-j REJECT"
require_chain_rule_at iptables filter AMNEZIA_LB_V2_FORWARD 7 \
    "-A AMNEZIA_LB_V2_FORWARD -j RETURN"

ns ip6tables -w 5 -C FORWARD -j AMNEZIA_LB_V2_IPV6
require_single_first_jump ip6tables filter FORWARD AMNEZIA_LB_V2_IPV6
[ "$(chain_rule_count ip6tables filter AMNEZIA_LB_V2_IPV6)" -eq 2 ]
ns ip6tables -w 5 -C AMNEZIA_LB_V2_IPV6 \
    -i "$INGRESS_AWG_IF" -j REJECT
ns ip6tables -w 5 -C AMNEZIA_LB_V2_IPV6 -j RETURN
require_chain_rule_at ip6tables filter AMNEZIA_LB_V2_IPV6 1 \
    "-i $INGRESS_AWG_IF" "-j REJECT"
require_chain_rule_at ip6tables filter AMNEZIA_LB_V2_IPV6 2 \
    "-A AMNEZIA_LB_V2_IPV6 -j RETURN"

docker exec "$INGRESS_CONTAINER" \
    awg show "$INGRESS_AWG_IF" listen-port | grep -Fxq "$INGRESS_AWG_PORT"
[ "$(ns sysctl -n net.ipv4.conf.all.rp_filter)" = 2 ]
for iface in "$outer_if" "$aux_if" "$direct_if" "$transit_if" "$INGRESS_AWG_IF"; do
    [ "$(ns sysctl -n "net.ipv4.conf.$iface.rp_filter")" = 2 ]
done
