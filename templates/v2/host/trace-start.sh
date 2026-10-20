#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"
pid=$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER")

"$BASE_DIR/host/trace-stop.sh" >/dev/null 2>&1 || true

# nftrace is namespace-local and is scrubbed at a cross-netns boundary, so it
# is deliberately enabled once inside ingress and again on the host.
nsenter -t "$pid" -n nft -f - <<EOF
add table inet amnezia_lb_v2_trace
add chain inet amnezia_lb_v2_trace prerouting { type filter hook prerouting priority -301; policy accept; }
add rule inet amnezia_lb_v2_trace prerouting iifname "$INGRESS_AWG_IF" ip daddr $ACTIVE_TEST_IP meta nftrace set 1 comment "v2 trace decrypted target"
EOF

nft -f - <<EOF
add table inet amnezia_lb_v2_trace
add chain inet amnezia_lb_v2_trace prerouting { type filter hook prerouting priority -301; policy accept; }
add rule inet amnezia_lb_v2_trace prerouting iifname "$DIRECT_BRIDGE" ip daddr $ACTIVE_TEST_IP meta nftrace set 1 comment "v2 trace forbidden direct target"
add rule inet amnezia_lb_v2_trace prerouting iifname "$TRANSIT_BRIDGE" ip daddr $ACTIVE_TEST_IP meta nftrace set 1 comment "v2 trace transit target"
add rule inet amnezia_lb_v2_trace prerouting iifname "$INGRESS_OUTER_BRIDGE" ip saddr $INGRESS_OUTER_IP/32 udp sport $INGRESS_AWG_PORT ip dscp $OUTER_TRANSPORT_DSCP meta nftrace set 1 comment "v2 trace tagged DNAT reply transport"
EOF

echo "Tracing enabled. In another terminal run: nft monitor trace"
echo "Remove it with: $BASE_DIR/host/trace-stop.sh"
