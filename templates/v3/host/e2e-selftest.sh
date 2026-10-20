#!/bin/bash
set -Eeuo pipefail

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
. "$BASE_DIR/multi.env"
TEST_IF=amlv3t0
PEER_IF=amlv3t1
TEST_IP=10.8.1.254
LINK_GATEWAY=10.255.255.1
LINK_PEER=10.255.255.2
HOST_TEST_TABLE=amnezia_lb_v3_selftest_host
PORT_BASE=$((40000 + $$ % 20000))
MAIN_PORT=$PORT_BASE
PGDL_PORT=$((PORT_BASE + 1))
AE_PORT=$((PORT_BASE + 2))
TEST_PID=
INGRESS_PID=$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER")
TRANSIT_IF=$(nsenter -t "$INGRESS_PID" -n ip -o -4 addr show | \
    awk -v wanted="$INGRESS_TRANSIT_IP/24" '$4==wanted && found=="" {gsub(/:$/, "", $2); found=$2} END {print found}')
[ -n "$TRANSIT_IF" ]

counter() {
    container=$1
    docker exec "$container" iptables -t nat -vnxL POSTROUTING | \
        awk -v source="$INGRESS_TRANSIT_IP" '$0 ~ source {value=$1} END {if(value!="") print value}'
}

cleanup() {
    (
    set +e
    nft delete table inet "$HOST_TEST_TABLE" 2>/dev/null
    nsenter -t "$INGRESS_PID" -n iptables -D AMNEZIA_LB_V2_TEST \
        -i "$TEST_IF" -o "$TRANSIT_IF" -s "$TEST_IP/32" -j ACCEPT 2>/dev/null
    nsenter -t "$INGRESS_PID" -n iptables -D AMNEZIA_LB_V2_TEST \
        -i "$TRANSIT_IF" -o "$TEST_IF" -d "$TEST_IP/32" \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    nsenter -t "$INGRESS_PID" -n ip rule del priority 108 protocol 99 2>/dev/null
    nsenter -t "$INGRESS_PID" -n ip rule del priority 109 protocol 99 2>/dev/null
    nsenter -t "$INGRESS_PID" -n nft delete table inet amnezia_lb_v3_selftest 2>/dev/null
    nsenter -t "$INGRESS_PID" -n ip route del "$TEST_IP/32" dev "$TEST_IF" 2>/dev/null
    nsenter -t "$INGRESS_PID" -n ip link del "$TEST_IF" 2>/dev/null
    [ -z "$TEST_PID" ] || kill "$TEST_PID" 2>/dev/null
    )
}
trap cleanup EXIT HUP INT TERM
cleanup

before_main=$(counter amnezia-egress-main-pilot-v2)
before_pgdl=$(counter "$PGDL_CONTAINER")
before_ae=$(counter "$AE_CONTAINER")

nsenter -t "$INGRESS_PID" -n unshare -n -- sleep 120 &
TEST_PID=$!
sleep 1
nsenter -t "$INGRESS_PID" -n ip link add "$TEST_IF" type veth peer name "$PEER_IF"
nsenter -t "$INGRESS_PID" -n ip link set "$PEER_IF" netns "$TEST_PID"
nsenter -t "$INGRESS_PID" -n ip addr add "$LINK_GATEWAY/30" dev "$TEST_IF"
nsenter -t "$INGRESS_PID" -n ip link set "$TEST_IF" up
nsenter -t "$INGRESS_PID" -n ip route replace "$TEST_IP/32" dev "$TEST_IF"
nsenter -t "$TEST_PID" -n ip link set lo up
nsenter -t "$TEST_PID" -n ip link set "$PEER_IF" up
nsenter -t "$TEST_PID" -n ip addr add "$LINK_PEER/30" dev "$PEER_IF"
nsenter -t "$TEST_PID" -n ip addr add "$TEST_IP/32" dev "$PEER_IF"
nsenter -t "$TEST_PID" -n ip route add default via "$LINK_GATEWAY" \
    dev "$PEER_IF" src "$TEST_IP"

nsenter -t "$INGRESS_PID" -n nft -f - <<EOF
add table inet amnezia_lb_v3_selftest
add chain inet amnezia_lb_v3_selftest classify { type filter hook prerouting priority -152; policy accept; }
add rule inet amnezia_lb_v3_selftest classify iifname "$TEST_IF" ip saddr $TEST_IP counter meta mark set 0x101
EOF
nsenter -t "$INGRESS_PID" -n ip rule add priority 108 protocol 99 \
    fwmark 0x101/0xffffffff iif "$TEST_IF" lookup 301
nsenter -t "$INGRESS_PID" -n ip rule add priority 109 protocol 99 \
    fwmark 0x101/0xffffffff iif "$TEST_IF" unreachable
nsenter -t "$INGRESS_PID" -n iptables -I AMNEZIA_LB_V2_TEST 1 \
    -i "$TEST_IF" -o "$TRANSIT_IF" -s "$TEST_IP/32" -j ACCEPT
nsenter -t "$INGRESS_PID" -n iptables -I AMNEZIA_LB_V2_TEST 1 \
    -i "$TRANSIT_IF" -o "$TEST_IF" -d "$TEST_IP/32" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

nft -f - <<EOF
add table inet $HOST_TEST_TABLE
add chain inet $HOST_TEST_TABLE steer { type filter hook prerouting priority -6; policy accept; }
add rule inet $HOST_TEST_TABLE steer iifname "$INGRESS_TRANSIT_BRIDGE" ip saddr $INGRESS_TRANSIT_IP ip daddr 1.1.1.1 tcp sport $MAIN_PORT ct mark set $MAIN_MARK meta mark set $MAIN_MARK
add rule inet $HOST_TEST_TABLE steer iifname "$INGRESS_TRANSIT_BRIDGE" ip saddr $INGRESS_TRANSIT_IP ip daddr 1.1.1.1 tcp sport $PGDL_PORT ct mark set $PGDL_MARK meta mark set $PGDL_MARK
add rule inet $HOST_TEST_TABLE steer iifname "$INGRESS_TRANSIT_BRIDGE" ip saddr $INGRESS_TRANSIT_IP ip daddr 1.1.1.1 tcp sport $AE_PORT ct mark set $AE_MARK meta mark set $AE_MARK
EOF

nsenter -t "$TEST_PID" -n ip route get 1.1.1.1
nsenter -t "$INGRESS_PID" -n ip route get 1.1.1.1 \
    from "$TEST_IP" iif "$TEST_IF" mark 0x101
probe_exit() {
    name=$1 port=$2 expected=$3
    trace=$(nsenter -t "$TEST_PID" -n curl --silent --show-error --fail --ipv4 \
        --connect-timeout 8 --max-time 12 --local-port "$port" \
        https://1.1.1.1/cdn-cgi/trace)
    observed=$(printf '%s\n' "$trace" | \
        awk -F= '$1=="ip" && value=="" {value=$2} END {print value}')
    if [ "$observed" != "$expected" ]; then
        printf '%s exit mismatch: expected=%s observed=%s\n' \
            "$name" "$expected" "${observed:-missing}" >&2
        exit 1
    fi
    printf '%s_exit=%s\n' "$name" "$observed"
}

probe_exit main "$MAIN_PORT" "$MAIN_EXPECTED_EXIT_IP"
probe_exit pgdl "$PGDL_PORT" "$PGDL_EXPECTED_EXIT_IP"
probe_exit ae "$AE_PORT" "$AE_EXPECTED_EXIT_IP"

after_main=$(counter amnezia-egress-main-pilot-v2)
after_pgdl=$(counter "$PGDL_CONTAINER")
after_ae=$(counter "$AE_CONTAINER")
delta_main=$((after_main - before_main))
delta_pgdl=$((after_pgdl - before_pgdl))
delta_ae=$((after_ae - before_ae))
nsenter -t "$INGRESS_PID" -n nft list table inet amnezia_lb_v3_selftest
if [ "$delta_main" -le 0 ] || [ "$delta_pgdl" -le 0 ] || [ "$delta_ae" -le 0 ]; then
    printf 'missing SNAT activity: main=%s pgdl=%s ae=%s\n' \
        "$delta_main" "$delta_pgdl" "$delta_ae" >&2
    exit 1
fi
printf 'all_https_paths=ok snat_delta_main=%s snat_delta_pgdl=%s snat_delta_ae=%s\n' \
    "$delta_main" "$delta_pgdl" "$delta_ae"
