#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
. "$BASE_DIR/multi.env"
install -d -m 0700 "$STATE_ROOT" "$STATE_ROOT/recovery/$RELEASE_ID"
touch "$LOCK_FILE"
chmod 0600 "$LOCK_FILE"
exec 9>"$LOCK_FILE"
flock -x 9
tmp="$MAINTENANCE_FILE.tmp.$$"
printf 'release=%s\noperation=rollback\ntime=%s\n' \
    "$RELEASE_ID" "$(date +%s)" > "$tmp"
chmod 0600 "$tmp"
mv -f "$tmp" "$MAINTENANCE_FILE"
flock -u 9

"$V2_DIR/host/guard-load.sh"
"$V2_DIR/host/policy-down.sh"
systemctl disable --now amnezia-lb-multi-v3-controller.service >/dev/null 2>&1 || true
"$BASE_DIR/host/balance-fail.sh"

rm -f /etc/systemd/system/docker.service.d/20-amnezia-lb-multi-v3-guard.conf
systemctl daemon-reload
if systemctl show docker -p DropInPaths -p Requires -p After | \
    grep -Fq '20-amnezia-lb-multi-v3-guard.conf'; then
    echo 'Docker still references the v3 guard drop-in' >&2
    exit 1
fi

systemctl disable --now amnezia-lb-multi-v3-egress.service >/dev/null 2>&1 || true
for container in "$PGDL_CONTAINER" "$AE_CONTAINER"; do
    if docker inspect "$container" >/dev/null 2>&1; then
        echo "Additional egress remains after rollback: $container" >&2
        exit 1
    fi
done

systemctl disable --now amnezia-lb-multi-v3-guard.service >/dev/null 2>&1 || true
"$BASE_DIR/host/docker-user-remove.sh"
"$BASE_DIR/host/host-policy-down.sh"
nft delete table inet amnezia_lb_balance_v3 2>/dev/null || true
nft delete table inet amnezia_lb_route_log_v3 2>/dev/null || true
nft delete table inet amnezia_lb_multi_v3 2>/dev/null || true
"$BASE_DIR/host/sysctl-state.sh" apply-v2

printf '%s\n' v2 > "$MODE_FILE.tmp.$$"
chmod 0600 "$MODE_FILE.tmp.$$"
mv -f "$MODE_FILE.tmp.$$" "$MODE_FILE"
rm -f "$MAINTENANCE_FILE"
systemctl enable --now amnezia-lb-v2-health.service >/dev/null
"$V2_DIR/host/guard-check.sh"
"$V2_DIR/host/transit-host-check.sh"
"$V2_DIR/host/docker-user-check.sh"
printf 'release=%s rollback=%s\n' "$RELEASE_ID" "$(date +%s)" > \
    "$STATE_ROOT/recovery/$RELEASE_ID/rollback-complete"
chmod 0600 "$STATE_ROOT/recovery/$RELEASE_ID/rollback-complete"
echo 'Restored strengthened v2 single-egress mode; its normal warm-up applies.'
