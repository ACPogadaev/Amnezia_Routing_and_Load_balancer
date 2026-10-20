#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
RUNTIME_DIR=/run/amnezia-lb-multi-v3
if nft list table inet amnezia_lb_multi_v3 >/dev/null 2>&1; then
    ruleset=$BASE_DIR/host/guard.replace.nft
    expected_sha256=@@V3_GUARD_REPLACE_SHA@@
else
    ruleset=$BASE_DIR/host/guard.create.nft
    expected_sha256=@@V3_GUARD_CREATE_SHA@@
fi
printf '%s  %s\n' "$expected_sha256" "$ruleset" | sha256sum -c - >/dev/null
nft -c -f "$ruleset"
nft -f "$ruleset"
install -d -m 0755 "$RUNTIME_DIR"
fingerprint=$("$BASE_DIR/host/nft-fingerprint.py" amnezia_lb_multi_v3)
tmp="$RUNTIME_DIR/guard.sha256.tmp"
printf '%s\n' "$fingerprint" > "$tmp"
chmod 0600 "$tmp"
mv -f "$tmp" "$RUNTIME_DIR/guard.sha256"
exec "$BASE_DIR/host/guard-check.sh"
