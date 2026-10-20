#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"

pid=$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER")
[ -n "$pid" ] && [ "$pid" != 0 ]

ns() {
    nsenter -t "$pid" -n -- "$@"
}

remove_jump() {
    command=$1
    table=$2
    builtin=$3
    target=$4
    while :; do
        number=$(ns "$command" -w 5 -t "$table" -S "$builtin" | \
            awk -v wanted="$target" '
                $1 == "-A" { n++ }
                $1 == "-A" && $0 ~ ("-j " wanted "([[:space:]]|$)") {
                    print n
                    exit
                }
            ')
        [ -n "$number" ] || break
        ns "$command" -w 5 -t "$table" -D "$builtin" "$number"
    done
}

iface_for_ip() {
    address=$1
    ns ip -o -4 addr show | awk -v wanted="$address" '
        $4 == wanted { name=$2; sub(/:$/, "", name); print name; exit }
    '
}

outer_if=$(iface_for_ip "$INGRESS_OUTER_IP/24")
aux_if=$(iface_for_ip "$INGRESS_AUX_IP/16")
direct_if=$(iface_for_ip "$INGRESS_DIRECT_IP/24")
transit_if=$(iface_for_ip "$INGRESS_TRANSIT_IP/24")

for value in "$outer_if" "$aux_if" "$direct_if" "$transit_if"; do
    [ -n "$value" ] || {
        echo "Unable to resolve an ingress interface by its fixed address" >&2
        exit 1
    }
done
ns ip link show "$INGRESS_AWG_IF" >/dev/null

# Loose reverse-path validation is required because replies arrive on the
# direct/transit interfaces while their forward selectors are policy rules.
RUNTIME_DIR=/run/amnezia-lb-v2
RP_STATE="$RUNTIME_DIR/ingress-rp-filter.$pid"
install -d -m 0755 "$RUNTIME_DIR"
if [ ! -s "$RP_STATE" ]; then
    tmp="$RP_STATE.tmp"
    : > "$tmp"
    for key in all default "$outer_if" "$aux_if" "$direct_if" "$transit_if" "$INGRESS_AWG_IF"; do
        printf 'net.ipv4.conf.%s.rp_filter=%s\n' \
            "$key" "$(ns sysctl -n "net.ipv4.conf.$key.rp_filter")" >> "$tmp"
    done
    mv -f "$tmp" "$RP_STATE"
fi
ns sysctl -q -w net.ipv4.conf.all.rp_filter=2
ns sysctl -q -w net.ipv4.conf.default.rp_filter=2
for iface in "$outer_if" "$aux_if" "$direct_if" "$transit_if" "$INGRESS_AWG_IF"; do
    ns sysctl -q -w "net.ipv4.conf.$iface.rp_filter=2"
done

replace_rule() {
    priority=$1
    shift
    existing=$(ns ip -N -o rule show | grep -E "^${priority}:" || true)
    if [ -n "$existing" ]; then
        if ! printf '%s\n' "$existing" | grep -Eq ' proto 99([[:space:]]|$)'; then
            echo "Refusing to replace non-pilot ingress rule at priority $priority" >&2
            exit 1
        fi
        while ns ip rule del priority "$priority" 2>/dev/null; do :; done
    fi
    ns ip rule add priority "$priority" protocol 99 "$@"
}

# Three independent paths. The target table deliberately starts empty; the
# health controller is the only component allowed to add its route.
ns ip route replace default via "$INGRESS_OUTER_GATEWAY" dev "$outer_if" \
    src "$INGRESS_OUTER_IP" table "$OUTER_ROUTE_TABLE"
ns ip route flush table "$TARGET_ROUTE_TABLE" 2>/dev/null || true
ns ip route replace default via "$DIRECT_GATEWAY" dev "$direct_if" \
    src "$INGRESS_DIRECT_IP" table "$DIRECT_ROUTE_TABLE"

replace_rule "$OUTER_LOOKUP_PRIORITY" \
    iif lo ipproto udp sport "$INGRESS_AWG_PORT" lookup "$OUTER_ROUTE_TABLE"
replace_rule "$OUTER_UNREACHABLE_PRIORITY" \
    iif lo ipproto udp sport "$INGRESS_AWG_PORT" unreachable
replace_rule "$TARGET_LOOKUP_PRIORITY" \
    iif "$INGRESS_AWG_IF" fwmark "$TARGET_MARK/$TARGET_MARK_MASK" \
    lookup "$TARGET_ROUTE_TABLE"
replace_rule "$TARGET_UNREACHABLE_PRIORITY" \
    iif "$INGRESS_AWG_IF" fwmark "$TARGET_MARK/$TARGET_MARK_MASK" unreachable
replace_rule "$DIRECT_LOOKUP_PRIORITY" \
    iif "$INGRESS_AWG_IF" lookup "$DIRECT_ROUTE_TABLE"
replace_rule "$DIRECT_UNREACHABLE_PRIORITY" \
    iif "$INGRESS_AWG_IF" unreachable

# Remove the previous scalar classifier, if this host is being upgraded from
# the one-/32 pilot. The native nftables classifier below owns target_v4 as a
# single atomic interval set and also resets client-supplied DSCP.
remove_jump iptables mangle PREROUTING AMNEZIA_LB_V2_CLASSIFY
ns iptables -w 5 -t mangle -F AMNEZIA_LB_V2_CLASSIFY 2>/dev/null || true
ns iptables -w 5 -t mangle -X AMNEZIA_LB_V2_CLASSIFY 2>/dev/null || true
"$BASE_DIR/host/ingress-targets-load.sh" "$pid"

# Tag only packets created by the local AWG socket. Unlike an skb mark, the
# IPv4 DSCP field survives the veth/netns boundary and is checked on the host.
ns iptables -w 5 -t mangle -N AMNEZIA_LB_V2_OUTER 2>/dev/null || true
ns iptables -w 5 -t mangle -F AMNEZIA_LB_V2_OUTER
ns iptables -w 5 -t mangle -A AMNEZIA_LB_V2_OUTER \
    -o "$outer_if" -p udp --sport "$INGRESS_AWG_PORT" \
    -j DSCP --set-dscp "$OUTER_TRANSPORT_DSCP"
ns iptables -w 5 -t mangle -A AMNEZIA_LB_V2_OUTER -j RETURN
remove_jump iptables mangle OUTPUT AMNEZIA_LB_V2_OUTER
ns iptables -w 5 -t mangle -I OUTPUT 1 -j AMNEZIA_LB_V2_OUTER

# Make the source seen by each next hop explicit. Docker host MASQUERADE is
# used only after the direct path has the stable source 172.30.249.10.
ns iptables -w 5 -t nat -N AMNEZIA_LB_V2_NAT 2>/dev/null || true
ns iptables -w 5 -t nat -F AMNEZIA_LB_V2_NAT
ns iptables -w 5 -t nat -A AMNEZIA_LB_V2_NAT \
    -s "$INGRESS_CLIENT_SUBNET" -o "$transit_if" \
    -j SNAT --to-source "$INGRESS_TRANSIT_IP"
ns iptables -w 5 -t nat -A AMNEZIA_LB_V2_NAT \
    -s "$INGRESS_CLIENT_SUBNET" -o "$direct_if" \
    -j SNAT --to-source "$INGRESS_DIRECT_IP"
ns iptables -w 5 -t nat -A AMNEZIA_LB_V2_NAT -j RETURN
remove_jump iptables nat POSTROUTING AMNEZIA_LB_V2_NAT
ns iptables -w 5 -t nat -I POSTROUTING 1 -j AMNEZIA_LB_V2_NAT

# Own jump is first, ahead of Amnezia's broad awg0 ACCEPT rule.  Temporary
# self-test permits live in their own project-owned chain, so the reconciler
# can continue to validate the production chain while a test is running.
ns iptables -w 5 -N AMNEZIA_LB_V2_TEST 2>/dev/null || true
ns iptables -w 5 -F AMNEZIA_LB_V2_TEST
ns iptables -w 5 -A AMNEZIA_LB_V2_TEST -j RETURN
ns iptables -w 5 -N AMNEZIA_LB_V2_FORWARD 2>/dev/null || true
ns iptables -w 5 -F AMNEZIA_LB_V2_FORWARD
ns iptables -w 5 -A AMNEZIA_LB_V2_FORWARD -j AMNEZIA_LB_V2_TEST
ns iptables -w 5 -A AMNEZIA_LB_V2_FORWARD \
    -i "$transit_if" -o "$INGRESS_AWG_IF" \
    -d "$INGRESS_CLIENT_SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED \
    -j ACCEPT
ns iptables -w 5 -A AMNEZIA_LB_V2_FORWARD \
    -i "$direct_if" -o "$INGRESS_AWG_IF" \
    -d "$INGRESS_CLIENT_SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED \
    -j ACCEPT
ns iptables -w 5 -A AMNEZIA_LB_V2_FORWARD \
    -i "$INGRESS_AWG_IF" -o "$transit_if" \
    -s "$INGRESS_CLIENT_SUBNET" -j ACCEPT
ns iptables -w 5 -A AMNEZIA_LB_V2_FORWARD \
    -i "$INGRESS_AWG_IF" -o "$direct_if" \
    -s "$INGRESS_CLIENT_SUBNET" -j ACCEPT
ns iptables -w 5 -A AMNEZIA_LB_V2_FORWARD \
    -i "$INGRESS_AWG_IF" -s "$INGRESS_CLIENT_SUBNET" -j REJECT
ns iptables -w 5 -A AMNEZIA_LB_V2_FORWARD -j RETURN
remove_jump iptables filter FORWARD AMNEZIA_LB_V2_FORWARD
ns iptables -w 5 -I FORWARD 1 -j AMNEZIA_LB_V2_FORWARD

# The requested target list is IPv4-only. Reject any IPv6 arriving through the
# VPN rather than silently allowing an untested alternate path.
ns ip6tables -w 5 -N AMNEZIA_LB_V2_IPV6 2>/dev/null || true
ns ip6tables -w 5 -F AMNEZIA_LB_V2_IPV6
ns ip6tables -w 5 -A AMNEZIA_LB_V2_IPV6 -i "$INGRESS_AWG_IF" -j REJECT
ns ip6tables -w 5 -A AMNEZIA_LB_V2_IPV6 -j RETURN
remove_jump ip6tables filter FORWARD AMNEZIA_LB_V2_IPV6
ns ip6tables -w 5 -I FORWARD 1 -j AMNEZIA_LB_V2_IPV6

# Keep the audited main default on the same amn0 address that receives Docker's
# public UDP DNAT. AmneziaWG's in-kernel reply path does not reliably expose the
# UDP source-port selector during its first route lookup, so table 300 alone is
# insufficient for a fresh handshake. Decrypted client packets cannot use this
# fallback: the two iif=awg0 lookups each have an adjacent terminal unreachable,
# and the host guard accepts only tagged UDP/46777 from this bridge.
while ns ip route del default table main 2>/dev/null; do :; done
ns ip route replace default via "$INGRESS_OUTER_GATEWAY" dev "$outer_if" \
    src "$INGRESS_OUTER_IP" table main
ns ip route flush cache

"$BASE_DIR/host/ingress-check.sh" "$pid"
