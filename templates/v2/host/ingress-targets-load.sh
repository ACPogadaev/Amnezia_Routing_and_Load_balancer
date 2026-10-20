#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"
pid=${1:-$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER")}
[ -n "$pid" ] && [ "$pid" != 0 ]

CREATE_SHA256=@@V2_INGRESS_CREATE_SHA@@
REPLACE_SHA256=@@V2_INGRESS_REPLACE_SHA@@

ns() { nsenter -t "$pid" -n -- "$@"; }

if ns nft list table inet amnezia_lb_v2_targets >/dev/null 2>&1; then
    ruleset="$BASE_DIR/ingress-targets.replace.nft"
    expected_sha256=$REPLACE_SHA256
else
    ruleset="$BASE_DIR/ingress-targets.create.nft"
    expected_sha256=$CREATE_SHA256
fi

# Syntax validation and application are both whole nftables transactions. A
# failed replacement leaves the preceding classifier and set intact.
printf '%s  %s\n' "$expected_sha256" "$ruleset" | sha256sum -c - >/dev/null
ns nft -c -f "$ruleset"
ns nft -f "$ruleset"

RUNTIME_DIR=/run/amnezia-lb-v2
install -d -m 0755 "$RUNTIME_DIR"
fingerprint=$(ns nft -j list table inet amnezia_lb_v2_targets | \
    "$BASE_DIR/host/nft-json-fingerprint.py")
state="$RUNTIME_DIR/ingress-targets.$pid.sha256"
printf '%s\n' "$fingerprint" > "$state.tmp"
chmod 0600 "$state.tmp"
mv -f "$state.tmp" "$state"

exec "$BASE_DIR/host/ingress-targets-check.sh" "$pid"
