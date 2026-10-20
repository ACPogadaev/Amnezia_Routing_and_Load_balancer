#!/bin/sh
set -eu

for priority in 20500 20501 20502 20503 20504 20505 20506 20507; do
    while ip rule del priority "$priority" protocol 99 2>/dev/null; do :; done
done
ip route flush table 402 2>/dev/null || true
ip route flush table 403 2>/dev/null || true
ip route flush cache
