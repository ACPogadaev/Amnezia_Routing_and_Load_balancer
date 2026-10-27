#!/bin/bash
set -u

MODE=${1:---docker}
case "$MODE" in
    --docker|--json) ;;
    *) echo 'usage: egress-healthcheck.sh [--docker|--json]' >&2; exit 1 ;;
esac

: "${EGRESS_AWG_IF:?}"
: "${EGRESS_AWG_IP:?}"
: "${EGRESS_POLICY_TABLE:?}"
: "${INGRESS_TRANSIT_IP:?}"
: "${EGRESS_READY_FILE:?}"
: "${EGRESS_EXPECTED_EXIT_IP:?}"
: "${HEALTH_URL:?}"
: "${HEALTH_URL_SECONDARY:?}"
: "${HEALTH_MAX_HANDSHAKE_AGE_SECONDS:?}"
: "${HEALTH_MAX_SAMPLE_AGE_SECONDS:?}"

OUTER_IF=${EGRESS_OUTER_IF:-eth0}
PROBE_TIMEOUT=${HEALTH_PROBE_TIMEOUT_SECONDS:-15}
CONNECT_TIMEOUT=${HEALTH_CONNECT_TIMEOUT_SECONDS:-3}
HTTP_TIMEOUT=${HEALTH_HTTP_TIMEOUT_SECONDS:-6}
CONFIG_GENERATION=${HEALTH_CONFIG_GENERATION:-unknown}
RUN_DIR=/run/amnezia-lb-health
CACHE=$RUN_DIR/result.json
LOCK=$RUN_DIR/probe.lock
CONF=/etc/amnezia/amneziawg/${EGRESS_AWG_IF}.conf
STARTED=$(date +%s)
SAMPLE_ID="${STARTED}-$$"
INSTANCE_ID=$(sed -n '1p' "$EGRESS_READY_FILE" 2>/dev/null || true)

mkdir -p "$RUN_DIR"
chmod 0755 "$RUN_DIR"
exec 9>"$LOCK"
if ! flock -n 9; then
    # The controller and Docker intentionally share one probe lock.  Docker's
    # 30-second scheduler can coincide with the controller's 10-second probe;
    # reuse the last complete sample in Docker mode instead of turning a mere
    # collector collision into a false container-health failure.
    if [ "$MODE" = --docker ] && [ -s "$CACHE" ]; then
        cache_epoch=$(sed -nE 's/.*"sample_epoch":([0-9]+).*/\1/p' "$CACHE")
        cache_generation=$(sed -nE 's/.*"config_generation":"([^"]+)".*/\1/p' "$CACHE")
        cache_instance=$(sed -nE 's/.*"instance_id":"([^"]+)".*/\1/p' "$CACHE")
        case "$cache_epoch" in ''|*[!0-9]*) cache_epoch=0 ;; esac
        cache_age=$((STARTED - cache_epoch))
        if [ "$cache_generation" = "$CONFIG_GENERATION" ] && \
           [ -n "$INSTANCE_ID" ] && [ "$cache_instance" = "$INSTANCE_ID" ] && \
           [ "$cache_age" -ge 0 ] && [ "$cache_age" -le "$HEALTH_MAX_SAMPLE_AGE_SECONDS" ]; then
            cat "$CACHE"
            grep -q '"healthy":true' "$CACHE"
            exit $?
        fi
        printf '{"schema_version":1,"sample_id":"%s","sample_epoch":%s,"instance_id":"%s","config_generation":"%s","healthy":false,"reason":"collector_stale","reason_scope":"collector","observer":null,"exit_ip":null,"handshake_age":null,"rx_bytes":null,"tx_bytes":null,"duration_ms":0}\n' \
            "$SAMPLE_ID" "$STARTED" "$INSTANCE_ID" "$CONFIG_GENERATION"
        exit 1
    fi
    printf '{"schema_version":1,"sample_id":"%s","sample_epoch":%s,"instance_id":"%s","config_generation":"%s","healthy":false,"reason":"probe_busy","reason_scope":"collector","observer":null,"exit_ip":null,"handshake_age":null,"rx_bytes":null,"tx_bytes":null,"duration_ms":%s}\n' \
        "$SAMPLE_ID" "$STARTED" "$INSTANCE_ID" "$CONFIG_GENERATION" "$((PROBE_TIMEOUT * 1000))"
    exit 1
fi

duration_ms() {
    now=$(date +%s)
    case "$STARTED$now" in
        *[!0-9]*) echo 0 ;;
        *) echo $(((now - STARTED) * 1000)) ;;
    esac
}

write_result() {
    healthy=$1 reason=$2 scope=$3 observer=$4 exit_ip=$5 age=$6 rx=$7 tx=$8
    [ "$observer" = null ] || observer="\"$observer\""
    [ "$exit_ip" = null ] || exit_ip="\"$exit_ip\""
    tmp="$CACHE.$$"
    printf '{"schema_version":1,"sample_id":"%s","sample_epoch":%s,"instance_id":"%s","config_generation":"%s","healthy":%s,"reason":"%s","reason_scope":"%s","observer":%s,"exit_ip":%s,"handshake_age":%s,"rx_bytes":%s,"tx_bytes":%s,"duration_ms":%s}\n' \
        "$SAMPLE_ID" "$STARTED" "$INSTANCE_ID" "$CONFIG_GENERATION" "$healthy" "$reason" "$scope" \
        "$observer" "$exit_ip" "$age" "$rx" "$tx" "$(duration_ms)" > "$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$CACHE"
    cat "$CACHE"
    [ "$healthy" = true ]
}

fail() {
    write_result false "$1" "$2" null null null null null
    exit 1
}

valid_ipv4() {
    awk -v ip="$1" 'BEGIN {
        n=split(ip,a,"."); if(n!=4) exit 1;
        for(i=1;i<=4;i++) if(a[i] !~ /^[0-9]+$/ || a[i] < 0 || a[i] > 255) exit 1;
        exit 0
    }'
}

for tool in awg curl ip iptables sysctl awk sed grep flock; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing_tool" "local"
done
[ -s "$EGRESS_READY_FILE" ] || fail "starting" "local"
[ -n "$INSTANCE_ID" ] || fail "starting" "local"
[ -r "$CONF" ] || fail "missing_config" "local"
ip link show dev "$EGRESS_AWG_IF" >/dev/null 2>&1 || fail "missing_interface" "local"
ip -o link show dev "$EGRESS_AWG_IF" | grep -Eq '<[^>]*UP([,>])' || fail "interface_down" "local"
ip -o -4 addr show dev "$EGRESS_AWG_IF" | awk '{print $4}' | grep -Fxq "$EGRESS_AWG_IP/32" || fail "wrong_interface_address" "local"
[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = 1 ] || fail "forwarding_disabled" "local"

ip -4 route show table "$EGRESS_POLICY_TABLE" | grep -Eq "^default dev ${EGRESS_AWG_IF}([[:space:]]|$)" || fail "missing_policy_default" "local"
ip -o -4 rule show priority 20100 | grep -Fq "iif $OUTER_IF" || fail "missing_forward_lookup" "local"
ip -o -4 rule show priority 20100 | grep -Fq "from $INGRESS_TRANSIT_IP" || fail "missing_forward_lookup" "local"
ip -o -4 rule show priority 20100 | grep -Eq "lookup ${EGRESS_POLICY_TABLE}([[:space:]]|$)" || fail "missing_forward_lookup" "local"
ip -o -4 rule show priority 20101 | grep -Fq "iif $OUTER_IF" || fail "missing_forward_unreachable" "local"
ip -o -4 rule show priority 20101 | grep -Fq "from $INGRESS_TRANSIT_IP" || fail "missing_forward_unreachable" "local"
ip -o -4 rule show priority 20101 | grep -Fq "unreachable" || fail "missing_forward_unreachable" "local"
ip -o -4 rule show priority 20110 | grep -Fq "from $EGRESS_AWG_IP" || fail "missing_health_lookup" "local"
ip -o -4 rule show priority 20110 | grep -Eq "lookup ${EGRESS_POLICY_TABLE}([[:space:]]|$)" || fail "missing_health_lookup" "local"
ip -o -4 rule show priority 20111 | grep -Fq "from $EGRESS_AWG_IP" || fail "missing_health_unreachable" "local"
ip -o -4 rule show priority 20111 | grep -Fq "unreachable" || fail "missing_health_unreachable" "local"

iptables -C FORWARD -i "$OUTER_IF" -o "$EGRESS_AWG_IF" -s "$INGRESS_TRANSIT_IP/32" -j ACCEPT >/dev/null 2>&1 || fail "missing_forward_out" "local"
iptables -C FORWARD -i "$EGRESS_AWG_IF" -o "$OUTER_IF" -d "$INGRESS_TRANSIT_IP/32" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || fail "missing_forward_return" "local"
iptables -t nat -C POSTROUTING -s "$INGRESS_TRANSIT_IP/32" -o "$EGRESS_AWG_IF" -j SNAT --to-source "$EGRESS_AWG_IP" >/dev/null 2>&1 || fail "missing_snat" "local"
iptables -C OUTPUT -s "$EGRESS_AWG_IP/32" ! -o "$EGRESS_AWG_IF" -j REJECT >/dev/null 2>&1 || fail "missing_output_guard" "local"

observer=null
observed=null
primary=$(curl --silent --show-error --fail --ipv4 --noproxy '*' \
    --connect-timeout "$CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" \
    --max-filesize 4096 --interface "$EGRESS_AWG_IP" "$HEALTH_URL" 2>/dev/null || true)
candidate=$(printf '%s\n' "$primary" | awk -F= '$1=="ip" {print $2; exit}')
if [ -n "$candidate" ] && valid_ipv4 "$candidate"; then
    [ "$candidate" = "$EGRESS_EXPECTED_EXIT_IP" ] || fail "wrong_exit_ip" "security"
    observer=primary
    observed=$candidate
else
    secondary=$(curl --silent --show-error --fail --ipv4 --noproxy '*' \
        --connect-timeout "$CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" \
        --max-filesize 4096 --interface "$EGRESS_AWG_IP" "$HEALTH_URL_SECONDARY" 2>/dev/null || true)
    candidate=$(printf '%s\n' "$secondary" | sed -nE 's/^[[:space:]]*\{[[:space:]]*"ip"[[:space:]]*:[[:space:]]*"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"[[:space:]]*\}[[:space:]]*$/\1/p')
    if [ -n "$candidate" ] && valid_ipv4 "$candidate"; then
        [ "$candidate" = "$EGRESS_EXPECTED_EXIT_IP" ] || fail "wrong_exit_ip" "security"
        observer=secondary
        observed=$candidate
    else
        fail "https_unavailable" "network"
    fi
fi

peer=$(awk '/^[[:space:]]*PublicKey[[:space:]]*=/{sub(/^[^=]*=[[:space:]]*/,""); gsub(/[[:space:]]/,""); print; exit}' "$CONF")
[ -n "$peer" ] || fail "expected_peer_missing" "local"
latest=$(awg show "$EGRESS_AWG_IF" latest-handshakes 2>/dev/null | awk -v wanted="$peer" '$1==wanted {print $2; exit}')
case "$latest" in ''|*[!0-9]*) fail "handshake_missing" "local" ;; esac
now=$(date +%s)
age=$((now - latest))
[ "$age" -ge 0 ] || fail "clock_error" "infrastructure"
[ "$age" -le "$HEALTH_MAX_HANDSHAKE_AGE_SECONDS" ] || fail "handshake_stale" "local"

rx=$(cat "/sys/class/net/$EGRESS_AWG_IF/statistics/rx_bytes" 2>/dev/null || true)
tx=$(cat "/sys/class/net/$EGRESS_AWG_IF/statistics/tx_bytes" 2>/dev/null || true)
case "$rx:$tx" in *[!0-9:]*) fail "counter_error" "local" ;; esac
write_result true ok none "$observer" "$observed" "$age" "$rx" "$tx"
