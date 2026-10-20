#!/bin/bash
set -Eeuo pipefail

: "${EGRESS_AWG_IF:?}"
: "${EGRESS_AWG_IP:?}"
: "${EGRESS_AWG_ENDPOINT_IP:?}"
: "${EGRESS_AWG_ENDPOINT_PORT:?}"
: "${TRANSIT_GATEWAY:?}"
: "${EGRESS_POLICY_TABLE:?}"
: "${INGRESS_TRANSIT_IP:?}"
: "${EGRESS_START_DELAY_SECONDS:=0}"

CONF="/etc/amnezia/amneziawg/${EGRESS_AWG_IF}.conf"
READY_FILE=/run/amnezia-lb-v2/egress-policy-ready
OUTER_IF=eth0
FORWARD_LOOKUP_PRIORITY=20100
FORWARD_UNREACHABLE_PRIORITY=20101
HEALTH_LOOKUP_PRIORITY=20110
HEALTH_UNREACHABLE_PRIORITY=20111
TUNNEL_MSS=1160

remove_owned_rules() {
    for priority in \
        "$FORWARD_LOOKUP_PRIORITY" "$FORWARD_UNREACHABLE_PRIORITY" \
        "$HEALTH_LOOKUP_PRIORITY" "$HEALTH_UNREACHABLE_PRIORITY"; do
        while ip rule del priority "$priority" protocol 99 2>/dev/null; do :; done
    done
}

remove_filter_rules() {
    while iptables -t mangle -D FORWARD \
        -i "$OUTER_IF" -o "$EGRESS_AWG_IF" \
        -s "$INGRESS_TRANSIT_IP/32" -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --set-mss "$TUNNEL_MSS" 2>/dev/null; do :; done
    while iptables -t mangle -D FORWARD \
        -i "$EGRESS_AWG_IF" -o "$OUTER_IF" \
        -d "$INGRESS_TRANSIT_IP/32" -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --set-mss "$TUNNEL_MSS" 2>/dev/null; do :; done
    while iptables -D OUTPUT \
        -s "$EGRESS_AWG_IP/32" ! -o "$EGRESS_AWG_IF" -j REJECT \
        2>/dev/null; do :; done
    while iptables -t nat -D POSTROUTING \
        -s "$INGRESS_TRANSIT_IP/32" \
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

# Compose creates this namespace with forwarding disabled. Docker 29 mounts
# /proc/sys read-only inside an unprivileged container, so verify the initial
# value here; the host enables this namespaced sysctl only after READY_FILE.
[ "$(sysctl -n net.ipv4.ip_forward)" = 0 ]
rm -f "$READY_FILE"
iptables -P FORWARD DROP
iptables -F FORWARD
ip6tables -P FORWARD DROP 2>/dev/null || true
ip6tables -F FORWARD 2>/dev/null || true
test -r "$CONF"

# A Docker restart may reuse a sandbox briefly. Clean only this pilot's stale
# selectors before the delay/fresh setup; forwarding is already disabled.
awg-quick down "$CONF" >/dev/null 2>&1 || true
remove_filter_rules
remove_owned_rules

case "$EGRESS_START_DELAY_SECONDS" in
    ''|*[!0-9]*) echo "EGRESS_START_DELAY_SECONDS must be a non-negative integer" >&2; exit 1 ;;
esac
if [ "$EGRESS_START_DELAY_SECONDS" -gt 0 ]; then
    sleep "$EGRESS_START_DELAY_SECONDS"
fi

# The encrypted endpoint has a single explicit outer route. Table=off prevents
# awg-quick from altering the namespace default route.
ip route replace "$EGRESS_AWG_ENDPOINT_IP/32" \
    via "$TRANSIT_GATEWAY" dev "$OUTER_IF"
# The return path to ingress is forced through the host gateway. This makes
# both directions L3-forwarded and therefore visible to host DOCKER-USER even
# when br_netfilter is not loaded.
ip route replace "$INGRESS_TRANSIT_IP/32" \
    via "$TRANSIT_GATEWAY" dev "$OUTER_IF"

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

iptables -A FORWARD \
    -i "$OUTER_IF" -o "$EGRESS_AWG_IF" \
    -s "$INGRESS_TRANSIT_IP/32" -j ACCEPT
iptables -A FORWARD \
    -i "$EGRESS_AWG_IF" -o "$OUTER_IF" \
    -d "$INGRESS_TRANSIT_IP/32" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -t mangle -A FORWARD \
    -i "$OUTER_IF" -o "$EGRESS_AWG_IF" \
    -s "$INGRESS_TRANSIT_IP/32" -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss "$TUNNEL_MSS"
iptables -t mangle -A FORWARD \
    -i "$EGRESS_AWG_IF" -o "$OUTER_IF" \
    -d "$INGRESS_TRANSIT_IP/32" -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss "$TUNNEL_MSS"

iptables -t nat -A POSTROUTING \
    -s "$INGRESS_TRANSIT_IP/32" -o "$EGRESS_AWG_IF" \
    -j SNAT --to-source "$EGRESS_AWG_IP"

# A probe bound to the AWG address cannot report success over Docker/main.
iptables -A OUTPUT \
    -s "$EGRESS_AWG_IP/32" ! -o "$EGRESS_AWG_IF" -j REJECT

# No forwarded IPv6 is permitted in this IPv4-only pilot.
ip route flush cache

# Publish readiness only after every selector, terminal fallback, filter, SNAT
# rule and host-independent OUTPUT guard exists. The host validates its guard,
# checks the container PID and enables this namespace's forwarding via nsenter.
mkdir -p "$(dirname "$READY_FILE")"
chmod 0755 "$(dirname "$READY_FILE")"
printf '%s\n' "$$" > "$READY_FILE.tmp"
mv -f "$READY_FILE.tmp" "$READY_FILE"

i=0
while [ "$i" -lt 60 ]; do
    [ "$(sysctl -n net.ipv4.ip_forward)" = 1 ] && break
    i=$((i + 1))
    sleep 1
done
[ "$(sysctl -n net.ipv4.ip_forward)" = 1 ] || {
    echo "Host did not enable egress forwarding after policy readiness" >&2
    exit 1
}

trap 'exit 0' TERM INT
while :; do
    sleep 3600 &
    wait $!
done
