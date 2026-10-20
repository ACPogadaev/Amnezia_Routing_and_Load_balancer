#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
nft list table inet amnezia_lb_balance_v3 >/dev/null
nft -j list table inet amnezia_lb_balance_v3 | "$BASE_DIR/host/balance-check.py"
