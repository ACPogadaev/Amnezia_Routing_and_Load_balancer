#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"
RUNTIME_DIR=/run/amnezia-lb-v2
STATE_FILE="$RUNTIME_DIR/health.state"
STATE_ROOT=/var/lib/amnezia-lb
MODE_FILE="$STATE_ROOT/mode"
MAINTENANCE_FILE="$STATE_ROOT/maintenance"
successes=0
failures=0
state=down

install -d -m 0755 "$RUNTIME_DIR"

write_state() {
    printf '%s pid=%s time=%s\n' "$state" "$$" "$(date +%s)" > "$STATE_FILE.tmp"
    mv -f "$STATE_FILE.tmp" "$STATE_FILE"
}

set_down() {
    "$BASE_DIR/host/policy-down.sh"
    state=down
    write_state
}

set_up() {
    "$BASE_DIR/host/policy-up.sh"
    state=up
    write_state
}

probe() {
    test -s "$RUNTIME_DIR/ingress.ready" || return 1
    ready_pid=$(sed -n '1p' "$RUNTIME_DIR/ingress.ready") || return 1
    current_pid=$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER" 2>/dev/null) || return 1
    [ -n "$current_pid" ] && [ "$current_pid" != 0 ] || return 1
    [ "$ready_pid" = "$current_pid" ] || return 1

    # Idempotently enables forwarding for a freshly created egress namespace
    # only after its entrypoint published policy readiness and host guard was
    # revalidated. This also heals an automatic Docker container restart.
    "$BASE_DIR/host/egress-forward-enable.sh" >/dev/null 2>&1 || return 1

    output=$(docker exec "$EGRESS_CONTAINER" \
        curl --silent --show-error --fail --ipv4 \
        --max-time "$HEALTH_TIMEOUT_SECONDS" \
        --interface "$EGRESS_AWG_IP" "$HEALTH_URL") || return 1
    observed_ip=$(printf '%s\n' "$output" | sed -n 's/^ip=//p' | head -n 1)
    [ "$observed_ip" = "$EXPECTED_EXIT_IP" ] || return 1

    banner=$(docker exec "$EGRESS_CONTAINER" \
        curl --silent --ipv4 --max-time 3 \
        --interface "$EGRESS_AWG_IP" \
        "telnet://$TARGET_IP:$TARGET_TCP_PORT" 2>/dev/null || true)
    printf '%s\n' "$banner" | grep -Fq 'SSH-2.0-' || return 1

    handshake=$(docker exec "$EGRESS_CONTAINER" \
        awg show "$EGRESS_AWG_IF" latest-handshakes 2>/dev/null | \
        awk 'NR == 1 { print $2 }') || return 1
    [ -n "$handshake" ] && [ "$handshake" -gt 0 ] || return 1
    # Read the clock after the handshake: it may advance while the HTTP/TCP
    # probes are running, and a newly updated handshake is valid.
    now=$(date +%s)
    age=$((now - handshake))
    [ "$age" -ge 0 ] && [ "$age" -le "$HEALTH_MAX_HANDSHAKE_AGE_SECONDS" ] || return 1

    return 0
}

cleanup() {
    trap - EXIT TERM INT
    set_down || true
    exit 0
}
trap cleanup TERM INT EXIT
set_down

while :; do
    mode=$(sed -n '1p' "$MODE_FILE" 2>/dev/null || true)
    if [ -e "$MAINTENANCE_FILE" ] || [ "$mode" = v3 ]; then
        successes=0
        failures=0
        set_down
        sleep "$HEALTH_INTERVAL_SECONDS"
        continue
    fi
    if probe; then
        successes=$((successes + 1))
        failures=0
        if [ "$state" = down ]; then
            if [ "$successes" -ge "$HEALTH_SUCCESS_THRESHOLD" ]; then
                set_up
            fi
        else
            # Reassert idempotently so a lost route heals on the next success.
            set_up
        fi
    else
        failures=$((failures + 1))
        successes=0
        if [ "$state" = up ] && [ "$failures" -ge "$HEALTH_FAILURE_THRESHOLD" ]; then
            set_down
        elif [ "$state" = down ]; then
            "$BASE_DIR/host/policy-down.sh"
        fi
    fi
    sleep "$HEALTH_INTERVAL_SECONDS"
done
