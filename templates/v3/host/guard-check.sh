#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
EXPECTED=/run/amnezia-lb-multi-v3/guard.sha256
test -s "$EXPECTED"
expected=$(sed -n '1p' "$EXPECTED")
actual=$("$BASE_DIR/host/nft-fingerprint.py" amnezia_lb_multi_v3)
[ "$actual" = "$expected" ] || {
    echo 'amnezia_lb_multi_v3 ruleset fingerprint mismatch' >&2
    exit 1
}
