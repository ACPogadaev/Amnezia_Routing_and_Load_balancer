#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
. "$BASE_DIR/multi.env"
install -d -m 0700 "$STATE_ROOT" "$STATE_ROOT/recovery/$RELEASE_ID"
touch "$LOCK_FILE"
chmod 0600 "$LOCK_FILE"

set_maintenance() {
    exec 9>"$LOCK_FILE"
    flock -x 9
    tmp="$MAINTENANCE_FILE.tmp.$$"
    printf 'release=%s\noperation=activate\ntime=%s\n' \
        "$RELEASE_ID" "$(date +%s)" > "$tmp"
    chmod 0600 "$tmp"
    mv -f "$tmp" "$MAINTENANCE_FILE"
    printf '%s\n' v3 > "$MODE_FILE.tmp.$$"
    chmod 0600 "$MODE_FILE.tmp.$$"
    mv -f "$MODE_FILE.tmp.$$" "$MODE_FILE"
    flock -u 9
}

clear_maintenance() {
    exec 9>"$LOCK_FILE"
    flock -x 9
    rm -f "$MAINTENANCE_FILE"
    flock -u 9
}

set_maintenance
"$V2_DIR/host/policy-down.sh"
rollback_needed=1
cleanup() {
    rc=$?
    trap - EXIT HUP INT TERM
    if [ "$rc" -ne 0 ] && [ "$rollback_needed" -eq 1 ]; then
        echo 'Activation failed; restoring the single-egress v2 controller.' >&2
        "$BASE_DIR/host/rollback.sh" || true
    fi
    exit "$rc"
}
trap cleanup EXIT HUP INT TERM

systemctl stop amnezia-lb-multi-v3-controller.service 2>/dev/null || true
systemctl disable --now amnezia-lb-v2-health.service >/dev/null 2>&1 || true

"$V2_DIR/host/guard-load.sh"
"$V2_DIR/host/guard-check.sh"
"$BASE_DIR/host/guard-load.sh"
"$BASE_DIR/host/network-ensure.sh"
"$BASE_DIR/host/balance-load.sh"
"$BASE_DIR/host/host-policy-up.sh"
"$V2_DIR/host/docker-user-install.sh"
"$BASE_DIR/host/docker-user-install.sh"

# The continuously running ingress manager owns this namespace.  Installing a
# stricter checker makes it reconcile the new dedicated self-test chain; wait
# for that confirmed state before starting the v3 controller.
i=0
while [ "$i" -lt 20 ]; do
    if "$V2_DIR/host/ingress-check.sh" >/dev/null 2>&1; then
        break
    fi
    i=$((i + 1))
    sleep 1
done
[ "$i" -lt 20 ]

install -d -m 0755 /etc/systemd/system/docker.service.d
install -m 0644 "$BASE_DIR/systemd/20-amnezia-lb-multi-v3-guard.conf" \
    /etc/systemd/system/docker.service.d/20-amnezia-lb-multi-v3-guard.conf
systemctl daemon-reload
systemctl show docker -p Requires -p After -p DropInPaths | \
    grep -Fq '20-amnezia-lb-multi-v3-guard.conf'

systemctl enable amnezia-lb-multi-v3-guard.service \
    amnezia-lb-multi-v3-egress.service \
    amnezia-lb-multi-v3-controller.service >/dev/null
systemctl start amnezia-lb-multi-v3-guard.service
systemctl start amnezia-lb-multi-v3-egress.service
systemctl start amnezia-lb-multi-v3-controller.service

i=0
while [ "$i" -lt 75 ]; do
    if python3 - "$RUNTIME_DIR/state.json" "$RELEASE_ID" <<'PY' 2>/dev/null
import json, sys
s=json.load(open(sys.argv[1]))
ok=(s.get("release")==sys.argv[2] and s.get("infra_valid") is True
    and s.get("maintenance") is True and len(s.get("healthy", []))==3)
raise SystemExit(0 if ok else 1)
PY
    then
        break
    fi
    i=$((i + 1))
    sleep 1
done
[ "$i" -lt 75 ]
clear_maintenance
i=0
while [ "$i" -lt 30 ]; do
    if python3 - "$RUNTIME_DIR/state.json" "$RELEASE_ID" <<'PY' 2>/dev/null
import json, sys, time
s=json.load(open(sys.argv[1]))
ok=(s.get("release")==sys.argv[2] and time.time()-s.get("time", 0)<30
    and s.get("infra_valid") is True and s.get("maintenance") is False
    and s.get("admission_open") is True and s.get("mode") in {"balanced", "degraded"})
raise SystemExit(0 if ok else 1)
PY
    then
        break
    fi
    i=$((i + 1))
    sleep 1
done
[ "$i" -lt 30 ]
"$BASE_DIR/host/verify.sh"
rollback_needed=0
printf 'release=%s activated=%s\n' "$RELEASE_ID" "$(date +%s)" > \
    "$STATE_ROOT/recovery/$RELEASE_ID/activation-complete"
chmod 0600 "$STATE_ROOT/recovery/$RELEASE_ID/activation-complete"
echo 'v3 balancing is active; route logging remains disabled by default.'
