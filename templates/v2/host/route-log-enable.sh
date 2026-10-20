#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"

TABLE=amnezia_lb_v2_route_log
RUNTIME_DIR=/run/amnezia-lb-v2
ACTIVE_FILE="$RUNTIME_DIR/route-log.active"
NF_LOG_SYSCTL=net.netfilter.nf_log_all_netns
NF_LOG_STATE="$RUNTIME_DIR/route-log.nf-log-all-netns.original"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root" >&2
    exit 1
fi

ingress_pid=$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER")
egress_pid=$(docker inspect -f '{{.State.Pid}}' "$EGRESS_CONTAINER")
for value in "$ingress_pid" "$egress_pid"; do
    case "$value" in
        ''|*[!0-9]*|0*)
            echo "Ingress and egress containers must both be running" >&2
            exit 1
            ;;
    esac
done

ingress_ns() {
    nsenter -t "$ingress_pid" -n -- "$@"
}

egress_ns() {
    nsenter -t "$egress_pid" -n -- "$@"
}

iface_for_ip() {
    address=$1
    ingress_ns ip -o -4 addr show | awk -v wanted="$address" '
        $4 == wanted { name=$2; sub(/:$/, "", name); print name; exit }
    '
}

direct_if=$(iface_for_ip "$INGRESS_DIRECT_IP/24")
transit_if=$(iface_for_ip "$INGRESS_TRANSIT_IP/24")
for value in "$direct_if" "$transit_if"; do
    [ -n "$value" ] || {
        echo "Unable to resolve an ingress diagnostic interface" >&2
        exit 1
    }
done
target_elements=$(awk '
    NF {
        if (seen++) printf ", "
        printf "%s", $0
    }
    END { print "" }
' "$ACTIVE_TARGETS_FILE")
[ -n "$target_elements" ]
ingress_ns ip link show "$INGRESS_AWG_IF" >/dev/null
egress_ns ip link show eth0 >/dev/null
egress_ns ip link show "$EGRESS_AWG_IF" >/dev/null

cleanup_tables() {
    nft delete table inet "$TABLE" 2>/dev/null || true
    ingress_ns nft delete table inet "$TABLE" 2>/dev/null || true
    egress_ns nft delete table inet "$TABLE" 2>/dev/null || true
}

restore_nf_log_all_netns() {
    [ -s "$NF_LOG_STATE" ] || return 0
    original=$(sed -n '1p' "$NF_LOG_STATE")
    case "$original" in
        0|1) ;;
        *)
            echo "Invalid saved $NF_LOG_SYSCTL value; backup retained at $NF_LOG_STATE" >&2
            return 1
            ;;
    esac
    if ! sysctl -q -w "$NF_LOG_SYSCTL=$original"; then
        echo "Failed to restore $NF_LOG_SYSCTL=$original; backup retained at $NF_LOG_STATE" >&2
        return 1
    fi
    rm -f "$NF_LOG_STATE"
}

# Re-enabling resets only diagnostic counters and never touches routing or
# verdict-bearing firewall rules.
install -d -m 0755 "$RUNTIME_DIR"
if ! "$BASE_DIR/host/route-log-disable.sh" >/dev/null; then
    echo "Unable to finish the previous route-log cleanup; enable aborted." >&2
    echo "Retry: $BASE_DIR/host/route-log-disable.sh" >&2
    exit 1
fi
cleanup_tables
rm -f "$ACTIVE_FILE"
cleanup_failed_enable() {
    status=$?
    trap - EXIT HUP INT TERM
    cleanup_tables
    rm -f "$ACTIVE_FILE"
    if ! restore_nf_log_all_netns; then
        echo "Route-log enable failed and sysctl cleanup is incomplete." >&2
        exit 1
    fi
    exit "$status"
}
trap cleanup_failed_enable EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# The kernel suppresses LOG from non-init network namespaces by default.
# Preserve and temporarily enable the global switch so ingress/egress events
# reach the host journal; disable/rollback restores the exact prior value.
original=$(sysctl -n "$NF_LOG_SYSCTL")
case "$original" in
    0|1) ;;
    *)
        echo "Unexpected $NF_LOG_SYSCTL value: $original" >&2
        exit 1
        ;;
esac
printf '%s\n' "$original" > "$NF_LOG_STATE.tmp"
mv -f "$NF_LOG_STATE.tmp" "$NF_LOG_STATE"
sysctl -q -w "$NF_LOG_SYSCTL=1"

# Counter precedes limit: every matching packet is counted, while only a
# bounded sample reaches the kernel journal. All diagnostic chains accept.
ingress_ns nft -f - <<EOF
add table inet $TABLE
add set inet $TABLE target_v4 { type ipv4_addr; flags interval; }
add element inet $TABLE target_v4 { $target_elements }
add chain inet $TABLE prerouting { type filter hook prerouting priority -310; policy accept; }
add chain inet $TABLE forward { type filter hook forward priority -10; policy accept; }
add rule inet $TABLE prerouting iifname "$INGRESS_AWG_IF" ip saddr $INGRESS_CLIENT_SUBNET ip daddr @target_v4 counter limit rate 10/second burst 20 packets log prefix "AMLB2 INGRESS_SEEN "
add rule inet $TABLE prerouting iifname "$INGRESS_AWG_IF" ip saddr $INGRESS_CLIENT_SUBNET ip daddr != @target_v4 counter limit rate 10/second burst 20 packets log prefix "AMLB2 INGRESS_DIRECT_SEEN "
add rule inet $TABLE forward iifname "$INGRESS_AWG_IF" oifname "$transit_if" ip saddr $INGRESS_CLIENT_SUBNET ip daddr @target_v4 counter limit rate 10/second burst 20 packets log prefix "AMLB2 INGRESS_TRANSIT "
add rule inet $TABLE forward iifname "$transit_if" oifname "$INGRESS_AWG_IF" ip saddr @target_v4 ip daddr $INGRESS_CLIENT_SUBNET counter limit rate 10/second burst 20 packets log prefix "AMLB2 INGRESS_REPLY "
add rule inet $TABLE forward iifname "$INGRESS_AWG_IF" oifname "$direct_if" ip saddr $INGRESS_CLIENT_SUBNET ip daddr != @target_v4 counter limit rate 10/second burst 20 packets log prefix "AMLB2 INGRESS_DIRECT "
add rule inet $TABLE forward iifname "$direct_if" oifname "$INGRESS_AWG_IF" ip daddr $INGRESS_CLIENT_SUBNET ct state established,related counter limit rate 10/second burst 20 packets log prefix "AMLB2 INGRESS_DIRECT_REPLY "
EOF

# Host forward priority -10 is immediately before the permanent guard at -5.
# Exact pilot interface/source selectors record a wrong route choice even when
# the guard then drops it, without counting unrelated Docker traffic. The
# three LEAK_TRANSPORT rules are the complement of the allowed AWG transport
# tuple; TRANSPORT_OK positively proves that the expected reply left the
# namespace and reached host forwarding.
nft -f - <<EOF
add table inet $TABLE
add set inet $TABLE target_v4 { type ipv4_addr; flags interval; }
add element inet $TABLE target_v4 { $target_elements }
add chain inet $TABLE prerouting { type filter hook prerouting priority -310; policy accept; }
add chain inet $TABLE forward { type filter hook forward priority -10; policy accept; }
add rule inet $TABLE prerouting iifname "$TRANSIT_BRIDGE" ip saddr $INGRESS_TRANSIT_IP/32 ip daddr @target_v4 counter limit rate 10/second burst 20 packets log prefix "AMLB2 HOST_SEEN "
add rule inet $TABLE forward iifname "$TRANSIT_BRIDGE" oifname "$TRANSIT_BRIDGE" ip saddr $INGRESS_TRANSIT_IP/32 ip daddr @target_v4 counter limit rate 10/second burst 20 packets log prefix "AMLB2 HOST_EGRESS "
add rule inet $TABLE forward iifname "$TRANSIT_BRIDGE" oifname "$TRANSIT_BRIDGE" ip saddr @target_v4 ip daddr $INGRESS_TRANSIT_IP/32 counter limit rate 10/second burst 20 packets log prefix "AMLB2 HOST_REPLY "
add rule inet $TABLE forward iifname "$DIRECT_BRIDGE" oifname "$PUBLIC_IF" ip daddr @target_v4 counter limit rate 10/second burst 20 packets log prefix "AMLB2 LEAK_DIRECT "
add rule inet $TABLE forward iifname "$TRANSIT_BRIDGE" oifname "$PUBLIC_IF" ip saddr $INGRESS_TRANSIT_IP/32 ip daddr @target_v4 counter limit rate 10/second burst 20 packets log prefix "AMLB2 LEAK_TRANSIT_IN "
add rule inet $TABLE forward iifname "$TRANSIT_BRIDGE" oifname "$PUBLIC_IF" ip saddr $EGRESS_CONTAINER_IP/32 ip daddr @target_v4 ip daddr != $EGRESS_AWG_ENDPOINT_IP counter limit rate 10/second burst 20 packets log prefix "AMLB2 LEAK_TRANSIT_EG "
add rule inet $TABLE forward iifname "$INGRESS_AUX_BRIDGE" oifname "$PUBLIC_IF" ip saddr $INGRESS_AUX_IP/32 counter limit rate 10/second burst 20 packets log prefix "AMLB2 LEAK_AUX "
add rule inet $TABLE forward iifname "$INGRESS_OUTER_BRIDGE" oifname "$PUBLIC_IF" ip saddr $INGRESS_OUTER_IP/32 meta l4proto != udp counter limit rate 10/second burst 20 packets log prefix "AMLB2 LEAK_TRANSPORT_PROTO "
add rule inet $TABLE forward iifname "$INGRESS_OUTER_BRIDGE" oifname "$PUBLIC_IF" ip saddr $INGRESS_OUTER_IP/32 meta l4proto udp udp sport != $INGRESS_AWG_PORT counter limit rate 10/second burst 20 packets log prefix "AMLB2 LEAK_TRANSPORT_PORT "
add rule inet $TABLE forward iifname "$INGRESS_OUTER_BRIDGE" oifname "$PUBLIC_IF" ip saddr $INGRESS_OUTER_IP/32 meta l4proto udp udp sport $INGRESS_AWG_PORT ip dscp != $OUTER_TRANSPORT_DSCP counter limit rate 10/second burst 20 packets log prefix "AMLB2 LEAK_TRANSPORT_DSCP "
add rule inet $TABLE forward iifname "$INGRESS_OUTER_BRIDGE" oifname "$PUBLIC_IF" ip saddr $INGRESS_OUTER_IP/32 meta l4proto udp udp sport $INGRESS_AWG_PORT ip dscp $OUTER_TRANSPORT_DSCP counter limit rate 10/second burst 20 packets log prefix "AMLB2 TRANSPORT_OK "
add rule inet $TABLE forward iifname "$DIRECT_BRIDGE" oifname "$PUBLIC_IF" ip saddr $INGRESS_DIRECT_IP/32 ip daddr != @target_v4 counter limit rate 10/second burst 20 packets log prefix "AMLB2 HOST_DIRECT "
add rule inet $TABLE forward iifname "$PUBLIC_IF" oifname "$DIRECT_BRIDGE" ip daddr $INGRESS_DIRECT_IP/32 ct state established,related counter limit rate 10/second burst 20 packets log prefix "AMLB2 HOST_DIRECT_REPLY "
EOF

egress_ns nft -f - <<EOF
add table inet $TABLE
add set inet $TABLE target_v4 { type ipv4_addr; flags interval; }
add element inet $TABLE target_v4 { $target_elements }
add chain inet $TABLE prerouting { type filter hook prerouting priority -310; policy accept; }
add chain inet $TABLE forward { type filter hook forward priority -10; policy accept; }
add rule inet $TABLE prerouting iifname "eth0" ip saddr $INGRESS_TRANSIT_IP/32 ip daddr @target_v4 counter limit rate 10/second burst 20 packets log prefix "AMLB2 EGRESS_SEEN "
add rule inet $TABLE forward iifname "eth0" oifname "$EGRESS_AWG_IF" ip saddr $INGRESS_TRANSIT_IP/32 ip daddr @target_v4 counter limit rate 10/second burst 20 packets log prefix "AMLB2 EGRESS_AWG "
add rule inet $TABLE prerouting iifname "$EGRESS_AWG_IF" ip saddr @target_v4 counter limit rate 10/second burst 20 packets log prefix "AMLB2 EGRESS_REPLY "
add rule inet $TABLE forward iifname "$EGRESS_AWG_IF" oifname "eth0" ip saddr @target_v4 ip daddr $INGRESS_TRANSIT_IP/32 counter limit rate 10/second burst 20 packets log prefix "AMLB2 EGRESS_RETURN "
EOF

started=$(date +%s)
printf '%s\n' "$started" > "$ACTIVE_FILE.tmp"
mv -f "$ACTIVE_FILE.tmp" "$ACTIVE_FILE"
trap - EXIT HUP INT TERM

echo "Route logging enabled at epoch $started."
echo "$NF_LOG_SYSCTL was temporarily enabled; disable restores its prior value."
echo "Follow sampled events: $BASE_DIR/host/route-log-follow.sh"
echo "Inspect exact counters: $BASE_DIR/host/route-log-status.sh"
echo "Disable: $BASE_DIR/host/route-log-disable.sh"
