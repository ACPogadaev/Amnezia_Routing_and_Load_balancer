#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"

latest_handshake() {
    docker exec "$INGRESS_CONTAINER" \
        awg show "$INGRESS_AWG_IF" latest-handshakes | \
        awk '$2 > newest { newest=$2 } END { print newest + 0 }'
}

before=$(latest_handshake)
LOG_DIR=/var/log/amnezia-lb-v2
install -d -m 0700 "$LOG_DIR"

rollback_on_error() {
    status=$?
    trap - EXIT HUP INT TERM
    "$BASE_DIR/host/route-log-status.sh" \
        > "$LOG_DIR/failed-activation-route-log.txt" 2>&1 || true
    "$BASE_DIR/host/rollback.sh" --restore-baseline || true
    echo "Validated activation failed; baseline rollback was requested." >&2
    exit "$status"
}
trap rollback_on_error EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$BASE_DIR/host/activate.sh"
"$BASE_DIR/host/route-log-enable.sh"
echo "Reconnect one VPN client now; waiting up to ${CLIENT_HANDSHAKE_TIMEOUT_SECONDS}s."
"$BASE_DIR/host/client-handshake-check.sh" \
    "$before" "$CLIENT_HANDSHAKE_TIMEOUT_SECONDS"
"$BASE_DIR/host/route-log-status.sh" \
    > "$LOG_DIR/successful-activation-route-log.txt"

trap - EXIT HUP INT TERM
echo "Validated activation passed: a post-change ingress handshake was observed."
echo "Route logging remains enabled for client traffic checks."
