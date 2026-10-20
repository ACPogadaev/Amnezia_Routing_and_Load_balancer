#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
. "$BASE_DIR/multi.env"
action=${1:-}
STATE_DIR="$STATE_ROOT/recovery/$RELEASE_ID"
BASELINE="$STATE_DIR/sysctl-baseline"

install -d -m 0700 "$STATE_ROOT" "$STATE_ROOT/recovery" "$STATE_DIR"
touch "$LOCK_FILE"
chmod 0600 "$LOCK_FILE"
exec 9>"$LOCK_FILE"
flock -x 9

key_exists() {
    sysctl -n "$1" >/dev/null 2>&1
}

save_baseline() {
    [ -s "$BASELINE" ] && return 0
    tmp="$BASELINE.tmp.$$"
    : > "$tmp"
    chmod 0600 "$tmp"
    for key in \
        net.ipv4.conf.all.rp_filter \
        net.ipv4.conf.default.rp_filter \
        "net.ipv4.conf.$PUBLIC_IF.rp_filter" \
        "net.ipv4.conf.$INGRESS_TRANSIT_BRIDGE.rp_filter" \
        "net.ipv4.conf.$PGDL_BRIDGE.rp_filter" \
        "net.ipv4.conf.$AE_BRIDGE.rp_filter"
    do
        if key_exists "$key"; then
            printf '%s=%s\n' "$key" "$(sysctl -n "$key")" >> "$tmp"
        fi
    done
    mv -f "$tmp" "$BASELINE"
}

write_checked() {
    key=$1 value=$2
    sysctl -q -w "$key=$value"
    actual=$(sysctl -n "$key")
    [ "$actual" = "$value" ] || {
        echo "$key readback mismatch: expected=$value actual=$actual" >&2
        return 1
    }
}

check_value() {
    key=$1 value=$2
    actual=$(sysctl -n "$key")
    [ "$actual" = "$value" ] || {
        echo "$key mismatch: expected=$value actual=$actual" >&2
        return 1
    }
}

apply_v3() {
    save_baseline
    write_checked net.ipv4.conf.all.rp_filter 0
    write_checked "net.ipv4.conf.$INGRESS_TRANSIT_BRIDGE.rp_filter" 0
    write_checked "net.ipv4.conf.$PGDL_BRIDGE.rp_filter" 0
    write_checked "net.ipv4.conf.$AE_BRIDGE.rp_filter" 0
}

apply_v2() {
    save_baseline
    write_checked net.ipv4.conf.all.rp_filter 0
    write_checked "net.ipv4.conf.$INGRESS_TRANSIT_BRIDGE.rp_filter" 0
    for iface in "$PGDL_BRIDGE" "$AE_BRIDGE"; do
        key="net.ipv4.conf.$iface.rp_filter"
        key_exists "$key" && write_checked "$key" 0
    done
}

restore_full() {
    [ -s "$BASELINE" ] || {
        echo "sysctl baseline is missing: $BASELINE" >&2
        return 1
    }
    failed=0
    while IFS='=' read -r key value; do
        [ -n "$key" ] || continue
        if ! key_exists "$key"; then
            case "$key" in
                "net.ipv4.conf.$PGDL_BRIDGE.rp_filter"|"net.ipv4.conf.$AE_BRIDGE.rp_filter")
                    continue
                    ;;
                *)
                    echo "$key disappeared; baseline retained" >&2
                    failed=1
                    continue
                    ;;
            esac
        fi
        if ! write_checked "$key" "$value"; then
            failed=1
        fi
    done < "$BASELINE"
    [ "$failed" -eq 0 ] || return 1
    mv -f "$BASELINE" "$BASELINE.restored"
}

case "$action" in
    apply-v3) apply_v3 ;;
    apply-v2) apply_v2 ;;
    check-v3)
        check_value net.ipv4.conf.all.rp_filter 0
        check_value "net.ipv4.conf.$INGRESS_TRANSIT_BRIDGE.rp_filter" 0
        check_value "net.ipv4.conf.$PGDL_BRIDGE.rp_filter" 0
        check_value "net.ipv4.conf.$AE_BRIDGE.rp_filter" 0
        ;;
    check-v2)
        check_value net.ipv4.conf.all.rp_filter 0
        check_value "net.ipv4.conf.$INGRESS_TRANSIT_BRIDGE.rp_filter" 0
        ;;
    restore-full) restore_full ;;
    *)
        echo 'usage: sysctl-state.sh apply-v3|apply-v2|check-v3|check-v2|restore-full' >&2
        exit 2
        ;;
esac
