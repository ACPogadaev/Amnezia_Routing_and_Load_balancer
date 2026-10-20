#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
if nft list table inet amnezia_lb_balance_v3 >/dev/null 2>&1; then
    ruleset=$BASE_DIR/host/balance.replace.nft
else
    ruleset=$BASE_DIR/host/balance.create.nft
fi
nft -c -f "$ruleset"
nft -f "$ruleset"
exec "$BASE_DIR/host/balance-check.sh"
