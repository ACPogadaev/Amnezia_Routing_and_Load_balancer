#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
RUNTIME_DIR=/run/amnezia-lb-v2
CREATE_SHA256=@@V2_GUARD_CREATE_SHA@@
REPLACE_SHA256=@@V2_GUARD_REPLACE_SHA@@

if nft list table inet amnezia_lb_v2 >/dev/null 2>&1; then
    ruleset="$BASE_DIR/guard.replace.nft"
    expected_sha256=$REPLACE_SHA256
else
    ruleset="$BASE_DIR/guard.create.nft"
    expected_sha256=$CREATE_SHA256
fi

# Check and apply the complete table as one nftables transaction. A failure in
# the replacement leaves the preceding table intact and prevents Docker start.
printf '%s  %s\n' "$expected_sha256" "$ruleset" | sha256sum -c - >/dev/null
nft -c -f "$ruleset"
nft -f "$ruleset"

install -d -m 0755 "$RUNTIME_DIR"
fingerprint=$("$BASE_DIR/host/guard-fingerprint.py")
tmp="$RUNTIME_DIR/guard.sha256.tmp"
printf '%s\n' "$fingerprint" > "$tmp"
chmod 0600 "$tmp"
mv -f "$tmp" "$RUNTIME_DIR/guard.sha256"

exec "$BASE_DIR/host/guard-check.sh"
