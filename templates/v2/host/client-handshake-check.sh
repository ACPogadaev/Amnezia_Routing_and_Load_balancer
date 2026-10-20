#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"

if [ "$#" -gt 2 ]; then
    echo "usage: $0 [MINIMUM_EXCLUSIVE_EPOCH] [TIMEOUT_SECONDS]" >&2
    exit 2
fi

minimum=${1:-0}
timeout=${2:-$CLIENT_HANDSHAKE_TIMEOUT_SECONDS}
case "$minimum:$timeout" in
    *[!0-9:]*|:*|*:) echo "Handshake threshold and timeout must be integers" >&2; exit 2 ;;
esac

latest_handshake() {
    docker exec "$INGRESS_CONTAINER" \
        awg show "$INGRESS_AWG_IF" latest-handshakes | \
        awk '$2 > newest { newest=$2 } END { print newest + 0 }'
}

deadline=$(( $(date +%s) + timeout ))
while :; do
    latest=$(latest_handshake)
    if [ "$latest" -gt "$minimum" ]; then
        age=$(( $(date +%s) - latest ))
        echo "Fresh ingress handshake observed: epoch=$latest age=${age}s threshold=$minimum."
        exit 0
    fi
    [ "$(date +%s)" -lt "$deadline" ] || break
    sleep 2
done

echo "No ingress handshake newer than epoch $minimum within ${timeout}s." >&2
exit 1
