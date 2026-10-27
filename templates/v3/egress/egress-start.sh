#!/bin/bash
set -Eeuo pipefail

: "${EGRESS_AWG_IF:?}"
: "${EGRESS_AWG_IP:?}"
: "${EGRESS_AWG_ENDPOINT_IP:?}"
: "${EGRESS_AWG_ENDPOINT_PORT:?}"
: "${TRANSIT_GATEWAY:?}"
: "${EGRESS_POLICY_TABLE:?}"
: "${INGRESS_TRANSIT_IP:?}"

CONF="/etc/amnezia/amneziawg/${EGRESS_AWG_IF}.conf"
READY_FILE=/run/amnezia-lb-multi-v3/egress-policy-ready
OUTER_IF=eth0
FORWARD_LOOKUP_PRIORITY=20100
FORWARD_UNREACHABLE_PRIORITY=20101
HEALTH_LOOKUP_PRIORITY=20110
HEALTH_UNREACHABLE_PRIORITY=20111
TUNNEL_MSS=1160

remove_owned_rules() {
    for priority in "$FORWARD_LOOKUP_PRIORITY" "$FORWARD_UNREACHABLE_PRIORITY" \
        "$HEALTH_LOOKUP_PRIORITY" "$HEALTH_UNREACHABLE_PRIORITY"; do
        while ip rule del priority "$priority" protocol 99 2>/dev/null; do :; done
    done
}

remove_filter_rules() {
    while iptables -t mangle -D FORWARD -i "$OUTER_IF" -o "$EGRESS_AWG_IF" \
        -s "$INGRESS_TRANSIT_IP/32" -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --set-mss "$TUNNEL_MSS" 2>/dev/null; do :; done
    while iptables -t mangle -D FORWARD -i "$EGRESS_AWG_IF" -o "$OUTER_IF" \
        -d "$INGRESS_TRANSIT_IP/32" -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --set-mss "$TUNNEL_MSS" 2>/dev/null; do :; done
    while iptables -D OUTPUT -s "$EGRESS_AWG_IP/32" ! -o "$EGRESS_AWG_IF" \
        -j REJECT 2>/dev/null; do :; done
    while iptables -t nat -D POSTROUTING -s "$INGRESS_TRANSIT_IP/32" \
        -o "$EGRESS_AWG_IF" -j SNAT --to-source "$EGRESS_AWG_IP" \
        2>/dev/null; do :; done
}

cleanup() {
    rm -f "$READY_FILE"
    iptables -P FORWARD DROP >/dev/null 2>&1 || true
    iptables -F FORWARD >/dev/null 2>&1 || true
    remove_filter_rules || true
    remove_owned_rules || true
    awg-quick down "$CONF" >/dev/null 2>&1 || true
}
trap cleanup EXIT

[ "$(sysctl -n net.ipv4.ip_forward)" = 0 ]
rm -f "$READY_FILE"
rm -f /run/amnezia-lb-health/result.json /run/amnezia-lb-health/probe.lock
iptables -P FORWARD DROP
iptables -F FORWARD
ip6tables -P FORWARD DROP 2>/dev/null || true
ip6tables -F FORWARD 2>/dev/null || true
test -r "$CONF"

awg-quick down "$CONF" >/dev/null 2>&1 || true
remove_filter_rules
remove_owned_rules

ip route replace "$EGRESS_AWG_ENDPOINT_IP/32" via "$TRANSIT_GATEWAY" dev "$OUTER_IF"
ip route replace "$INGRESS_TRANSIT_IP/32" via "$TRANSIT_GATEWAY" dev "$OUTER_IF"

export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
awg-quick up "$CONF"
ip link set dev "$EGRESS_AWG_IF" mtu 1280 up
ip route replace default dev "$EGRESS_AWG_IF" table "$EGRESS_POLICY_TABLE"

ip rule add priority "$FORWARD_LOOKUP_PRIORITY" protocol 99 \
    iif "$OUTER_IF" from "$INGRESS_TRANSIT_IP/32" lookup "$EGRESS_POLICY_TABLE"
ip rule add priority "$FORWARD_UNREACHABLE_PRIORITY" protocol 99 \
    iif "$OUTER_IF" from "$INGRESS_TRANSIT_IP/32" unreachable
ip rule add priority "$HEALTH_LOOKUP_PRIORITY" protocol 99 \
    from "$EGRESS_AWG_IP/32" lookup "$EGRESS_POLICY_TABLE"
ip rule add priority "$HEALTH_UNREACHABLE_PRIORITY" protocol 99 \
    from "$EGRESS_AWG_IP/32" unreachable

iptables -A FORWARD -i "$OUTER_IF" -o "$EGRESS_AWG_IF" \
    -s "$INGRESS_TRANSIT_IP/32" -j ACCEPT
iptables -A FORWARD -i "$EGRESS_AWG_IF" -o "$OUTER_IF" \
    -d "$INGRESS_TRANSIT_IP/32" -m conntrack \
    --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t mangle -A FORWARD -i "$OUTER_IF" -o "$EGRESS_AWG_IF" \
    -s "$INGRESS_TRANSIT_IP/32" -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss "$TUNNEL_MSS"
iptables -t mangle -A FORWARD -i "$EGRESS_AWG_IF" -o "$OUTER_IF" \
    -d "$INGRESS_TRANSIT_IP/32" -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss "$TUNNEL_MSS"
iptables -t nat -A POSTROUTING -s "$INGRESS_TRANSIT_IP/32" \
    -o "$EGRESS_AWG_IF" -j SNAT --to-source "$EGRESS_AWG_IP"
iptables -A OUTPUT -s "$EGRESS_AWG_IP/32" ! -o "$EGRESS_AWG_IF" -j REJECT
ip route flush cache

mkdir -p "$(dirname "$READY_FILE")"
INSTANCE_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || printf '%s-%s\n' "$(date +%s)" "$$")
printf '%s\n' "$INSTANCE_ID" > "$READY_FILE.tmp"
mv -f "$READY_FILE.tmp" "$READY_FILE"

while [ "$(sysctl -n net.ipv4.ip_forward)" != 1 ]; do
    sleep 1
done

trap 'exit 0' TERM INT
while :; do sleep 3600 & wait $!; done
