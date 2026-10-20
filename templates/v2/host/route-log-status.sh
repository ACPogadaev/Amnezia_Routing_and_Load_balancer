#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"

TABLE=amnezia_lb_v2_route_log
RUNTIME_DIR=/run/amnezia-lb-v2
ACTIVE_FILE="$RUNTIME_DIR/route-log.active"
LAST_FILE="$RUNTIME_DIR/route-log.last"
NF_LOG_SYSCTL=net.netfilter.nf_log_all_netns
NF_LOG_STATE="$RUNTIME_DIR/route-log.nf-log-all-netns.original"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root" >&2
    exit 1
fi

if [ -s "$ACTIVE_FILE" ]; then
    echo "route-log: enabled since epoch $(sed -n '1p' "$ACTIVE_FILE")"
else
    echo "route-log: disabled"
    if [ -s "$LAST_FILE" ]; then
        read -r started stopped < "$LAST_FILE"
        echo "last journal interval: $started .. $stopped"
    fi
fi
echo "$NF_LOG_SYSCTL=$(sysctl -n "$NF_LOG_SYSCTL" 2>/dev/null || echo unavailable)"
if [ -s "$NF_LOG_STATE" ]; then
    echo "saved pre-test value: $(sed -n '1p' "$NF_LOG_STATE")"
fi

show_table() {
    label=$1
    shift
    echo "--- $label counters ---"
    if ! "$@" nft list chain inet "$TABLE" prerouting 2>/dev/null; then
        echo "diagnostic table is absent"
        return
    fi
    "$@" nft list chain inet "$TABLE" forward 2>/dev/null || true
}

show_table host

ingress_pid=$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER" 2>/dev/null || true)
ingress_running=0
case "$ingress_pid" in
    ''|*[!0-9]*|0*) echo "--- ingress counters ---"; echo "container is not running" ;;
    *) ingress_running=1; show_table ingress nsenter -t "$ingress_pid" -n ;;
esac

egress_pid=$(docker inspect -f '{{.State.Pid}}' "$EGRESS_CONTAINER" 2>/dev/null || true)
egress_running=0
case "$egress_pid" in
    ''|*[!0-9]*|0*) echo "--- egress counters ---"; echo "container is not running" ;;
    *) egress_running=1; show_table egress nsenter -t "$egress_pid" -n ;;
esac

echo "--- route decisions ---"
if [ "$ingress_running" -eq 1 ]; then
    echo "ingress unqualified local route (expected main via $INGRESS_OUTER_GATEWAY from $INGRESS_OUTER_IP):"
    nsenter -t "$ingress_pid" -n ip route get 9.9.9.9 2>&1 || true
    echo "ingress AWG transport (expected via $INGRESS_OUTER_GATEWAY from $INGRESS_OUTER_IP):"
    nsenter -t "$ingress_pid" -n ip route get 9.9.9.9 \
        ipproto udp sport "$INGRESS_AWG_PORT" 2>&1 || true
    echo "ingress target (expected via $TRANSIT_GATEWAY):"
    nsenter -t "$ingress_pid" -n ip route get "$ACTIVE_TEST_IP" \
        from "$VERIFY_CLIENT_IP" iif "$INGRESS_AWG_IF" \
        mark "$TARGET_MARK" 2>&1 || true
    echo "ingress non-target 9.9.9.9 (expected via $DIRECT_GATEWAY):"
    nsenter -t "$ingress_pid" -n ip route get 9.9.9.9 \
        from "$VERIFY_CLIENT_IP" iif "$INGRESS_AWG_IF" 2>&1 || true
fi
echo "host target (expected via $EGRESS_CONTAINER_IP):"
ip route get "$ACTIVE_TEST_IP" from "$INGRESS_TRANSIT_IP" \
    iif "$TRANSIT_BRIDGE" 2>&1 || true
if [ "$egress_running" -eq 1 ]; then
    echo "egress target (expected via $EGRESS_AWG_IF):"
    nsenter -t "$egress_pid" -n ip route get "$ACTIVE_TEST_IP" \
        from "$INGRESS_TRANSIT_IP" iif eth0 2>&1 || true
fi

echo "Expected successful direction: INGRESS_SEEN -> INGRESS_TRANSIT ->"
echo "HOST_SEEN -> HOST_EGRESS -> EGRESS_SEEN -> EGRESS_AWG."
echo "Expected reply direction ends with EGRESS_RETURN -> HOST_REPLY -> INGRESS_REPLY."
echo "Ordinary traffic uses INGRESS_DIRECT -> HOST_DIRECT and matching reply counters."
echo "A fresh client handshake must increment TRANSPORT_OK."
echo "Every LEAK_* counter must remain zero."
