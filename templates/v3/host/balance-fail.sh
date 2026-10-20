#!/bin/sh
set -eu

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT HUP INT TERM
{
    echo 'flush chain inet amnezia_lb_balance_v3 select'
    echo 'add rule inet amnezia_lb_balance_v3 select meta mark set 0x000002ff comment "v3 select fail"'
} > "$tmp"
nft -c -f "$tmp"
nft -f "$tmp"
