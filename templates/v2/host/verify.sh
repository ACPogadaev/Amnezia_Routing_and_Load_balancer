#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"

"$BASE_DIR/host/guard-check.sh"
"$BASE_DIR/host/wait-ready.sh"
pid=$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER")
"$BASE_DIR/host/transit-host-check.sh"
"$BASE_DIR/host/ingress-check.sh" "$pid"
"$BASE_DIR/host/docker-dnat-check.sh"

"$BASE_DIR/host/docker-user-check.sh"
docker inspect -f '{{.State.Running}}' "$EGRESS_CONTAINER" | grep -Fxq true
"$BASE_DIR/host/target-route-check.sh" "$pid"

target_route=$(nsenter -t "$pid" -n ip route get "$ACTIVE_TEST_IP" \
    from "$VERIFY_CLIENT_IP" iif "$INGRESS_AWG_IF" \
    mark "$TARGET_MARK" 2>/dev/null)
printf '%s\n' "$target_route" | grep -Fq "via $TRANSIT_GATEWAY"

direct_route=$(nsenter -t "$pid" -n ip route get 9.9.9.9 \
    from "$VERIFY_CLIENT_IP" iif "$INGRESS_AWG_IF" 2>/dev/null)
printf '%s\n' "$direct_route" | grep -Fq "via $DIRECT_GATEWAY"

transport_route=$(nsenter -t "$pid" -n ip route get 9.9.9.9 \
    ipproto udp sport "$INGRESS_AWG_PORT" 2>/dev/null)
printf '%s\n' "$transport_route" | grep -Fq "via $INGRESS_OUTER_GATEWAY"

probe=$(docker exec "$EGRESS_CONTAINER" \
    curl --silent --show-error --fail --ipv4 --max-time 6 \
    --interface "$EGRESS_AWG_IP" "$HEALTH_URL")
printf '%s\n' "$probe" | grep -Fq "ip=$EXPECTED_EXIT_IP"

banner=$(docker exec "$EGRESS_CONTAINER" \
    curl --silent --ipv4 --max-time 3 --interface "$EGRESS_AWG_IP" \
    "telnet://$TARGET_IP:$TARGET_TCP_PORT" 2>/dev/null || true)
printf '%s\n' "$banner" | grep -Fq 'SSH-2.0-'

echo "Host, ingress, egress, external-IP and target-TCP checks passed."
echo "A fresh ingress client handshake is still required before acceptance."
