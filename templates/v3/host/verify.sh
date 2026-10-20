#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
. "$BASE_DIR/multi.env"
test -s "$BASE_DIR/installed-manifest.sha256"
sha256sum -c --quiet "$BASE_DIR/installed-manifest.sha256"
"$BASE_DIR/host/guard-check.sh"
"$BASE_DIR/host/balance-check.sh"
"$BASE_DIR/host/host-policy-check.sh"
"$BASE_DIR/host/docker-user-check.sh"
"$V2_DIR/host/guard-check.sh"
"$V2_DIR/host/docker-user-check.sh"

for container in amnezia-egress-main-pilot-v2 "$PGDL_CONTAINER" "$AE_CONTAINER"; do
    [ "$(docker inspect -f '{{.State.Running}}' "$container")" = true ]
    [ "$(docker inspect -f '{{.RestartCount}}' "$container")" -eq 0 ]
done

check_mss() {
    container=$1 awg_if=$2
    docker exec "$container" iptables -t mangle -C FORWARD \
        -i eth0 -o "$awg_if" -s "$INGRESS_TRANSIT_IP/32" \
        -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1160
    docker exec "$container" iptables -t mangle -C FORWARD \
        -i "$awg_if" -o eth0 -d "$INGRESS_TRANSIT_IP/32" \
        -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1160
}
check_mss amnezia-egress-main-pilot-v2 awg-main
check_mss "$PGDL_CONTAINER" "$PGDL_AWG_IF"
check_mss "$AE_CONTAINER" "$AE_AWG_IF"

check_exit() {
    container=$1 address=$2 expected=$3
    output=$(docker exec "$container" curl --silent --show-error --fail --ipv4 \
        --max-time "$HEALTH_TIMEOUT_SECONDS" --interface "$address" "$HEALTH_URL")
    printf '%s\n' "$output" | grep -Fqx "ip=$expected"
}
check_exit amnezia-egress-main-pilot-v2 "$MAIN_AWG_IP" "$MAIN_EXPECTED_EXIT_IP"
check_exit "$PGDL_CONTAINER" "$PGDL_AWG_IP" "$PGDL_EXPECTED_EXIT_IP"
check_exit "$AE_CONTAINER" "$AE_AWG_IP" "$AE_EXPECTED_EXIT_IP"

python3 - "$RUNTIME_DIR/state.json" "$RELEASE_ID" <<'PY'
import json, sys, time
s=json.load(open(sys.argv[1]))
assert time.time()-s["time"] < 30, s
assert s["release"] == sys.argv[2], s
assert s["infra_valid"] is True and s["admission_open"] is True, s
assert s["maintenance"] is False, s
assert s["mode"] == "balanced", s
assert set(s["healthy"]) == {"main", "pgdl", "ae"}, s
assert sum(s["bucket_counts"].values()) == 256, s
assert s["bucket_counts"]["fail"] == 0, s
assert all(s["bucket_counts"][x] > 0 for x in ("main", "pgdl", "ae")), s
PY

route=$(ip route get 8.8.8.8 from "$INGRESS_TRANSIT_IP" iif "$INGRESS_TRANSIT_BRIDGE" mark "$MAIN_MARK")
printf '%s\n' "$route" | grep -Fq 'via 172.30.250.11 dev amlt0'
route=$(ip route get 8.8.8.8 from "$INGRESS_TRANSIT_IP" iif "$INGRESS_TRANSIT_BRIDGE" mark "$PGDL_MARK")
printf '%s\n' "$route" | grep -Fq "via $PGDL_CONTAINER_IP dev $PGDL_BRIDGE"
route=$(ip route get 8.8.8.8 from "$INGRESS_TRANSIT_IP" iif "$INGRESS_TRANSIT_BRIDGE" mark "$AE_MARK")
printf '%s\n' "$route" | grep -Fq "via $AE_CONTAINER_IP dev $AE_BRIDGE"
if ip route get 8.8.8.8 from "$INGRESS_TRANSIT_IP" iif "$INGRESS_TRANSIT_BRIDGE" mark "$FAIL_MARK" >/dev/null 2>&1; then
    echo 'Fail mark unexpectedly has a route' >&2
    exit 1
fi

echo 'Three-egress balancing, external IPs and fail-closed selectors passed.'
