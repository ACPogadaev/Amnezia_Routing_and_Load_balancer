#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"
pid=$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER" 2>/dev/null || true)
[ -n "$pid" ] && [ "$pid" != 0 ] || exit 0
ns() { nsenter -t "$pid" -n -- "$@"; }

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
dns_if=$(iface_for_ip "$INGRESS_DNS_IP/24")
[ -n "$dns_if" ]

# Restore the audited original main default before removing pilot selectors.
ns ip route replace default via "$INGRESS_DNS_GATEWAY" dev "$dns_if"

remove_owned_priority() {
    priority=$1
    rule=$(ns ip -N -o rule show | grep -E "^${priority}:" || true)
    [ -z "$rule" ] && return 0
    if printf '%s\n' "$rule" | grep -Eq ' proto 99([[:space:]]|$)'; then
        while ns ip rule del priority "$priority" 2>/dev/null; do :; done
    else
        echo "Leaving non-pilot ingress rule at priority $priority" >&2
    fi
}
for priority in \
    "$OUTER_LOOKUP_PRIORITY" "$OUTER_UNREACHABLE_PRIORITY" \
    "$TARGET_LOOKUP_PRIORITY" "$TARGET_UNREACHABLE_PRIORITY" \
    "$DIRECT_LOOKUP_PRIORITY" "$DIRECT_UNREACHABLE_PRIORITY"; do
    remove_owned_priority "$priority"
done

for table in "$OUTER_ROUTE_TABLE" "$TARGET_ROUTE_TABLE" "$DIRECT_ROUTE_TABLE"; do
    ns ip route flush table "$table" 2>/dev/null || true
done

# Remove every reference to pilot-owned chains, including a manually damaged
# selector that would not match the original exact -D command.
remove_jump iptables mangle PREROUTING AMNEZIA_LB_V2_CLASSIFY
remove_jump iptables mangle OUTPUT AMNEZIA_LB_V2_OUTER
remove_jump iptables nat POSTROUTING AMNEZIA_LB_V2_NAT
remove_jump iptables filter FORWARD AMNEZIA_LB_V2_FORWARD
remove_jump ip6tables filter FORWARD AMNEZIA_LB_V2_IPV6

ns iptables -w 5 -t mangle -F AMNEZIA_LB_V2_CLASSIFY 2>/dev/null || true
ns iptables -w 5 -t mangle -X AMNEZIA_LB_V2_CLASSIFY 2>/dev/null || true
ns iptables -w 5 -t mangle -F AMNEZIA_LB_V2_OUTER 2>/dev/null || true
ns iptables -w 5 -t mangle -X AMNEZIA_LB_V2_OUTER 2>/dev/null || true
ns iptables -w 5 -t nat -F AMNEZIA_LB_V2_NAT 2>/dev/null || true
ns iptables -w 5 -t nat -X AMNEZIA_LB_V2_NAT 2>/dev/null || true
ns iptables -w 5 -F AMNEZIA_LB_V2_FORWARD 2>/dev/null || true
ns iptables -w 5 -X AMNEZIA_LB_V2_FORWARD 2>/dev/null || true
ns iptables -w 5 -F AMNEZIA_LB_V2_TEST 2>/dev/null || true
ns iptables -w 5 -X AMNEZIA_LB_V2_TEST 2>/dev/null || true
ns ip6tables -w 5 -F AMNEZIA_LB_V2_IPV6 2>/dev/null || true
ns ip6tables -w 5 -X AMNEZIA_LB_V2_IPV6 2>/dev/null || true
ns nft delete table inet amnezia_lb_v2_targets 2>/dev/null || true
rm -f "/run/amnezia-lb-v2/ingress-targets.$pid.sha256"

RP_STATE="/run/amnezia-lb-v2/ingress-rp-filter.$pid"
if [ -s "$RP_STATE" ]; then
    while IFS='=' read -r key value; do
        case "$key" in
            net.ipv4.conf.*.rp_filter) ns sysctl -q -w "$key=$value" ;;
        esac
    done < "$RP_STATE"
    rm -f "$RP_STATE"
fi

ns ip route flush cache
