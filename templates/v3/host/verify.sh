#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
. "$BASE_DIR/multi.env"
case "$#:$*" in
    0:) ;;
    1:--maintenance) ;;
    *) echo 'usage: verify.sh [--maintenance]' >&2; exit 2 ;;
esac
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
    [ "$(docker inspect -f '{{.State.OOMKilled}}' "$container")" = false ]
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$container")" = healthy ]
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

python3 "$BASE_DIR/host/verify-state.py" \
    "$RUNTIME_DIR/state.json" "$BASE_DIR/multi.env" "$BASE_DIR/egresses.json" "$RELEASE_ID" "$@"

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


if [ "$#" -eq 1 ]; then
    echo 'Three-egress maintenance verification passed; admission remains closed.'
else
    echo 'Three-egress functional health, recovery state, quarantine and fail-closed selectors passed.'
fi
