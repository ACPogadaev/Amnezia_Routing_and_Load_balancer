#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
. "$BASE_DIR/multi.env"
CHAIN=AMNEZIA_LB_MULTI_V3
NAT_CHAIN=AMNEZIA_LB_MULTI_V3_NAT
RAW_CHAIN=AMNEZIA_LB_MULTI_V3_RAW
while iptables -w 5 -D DOCKER-USER -j "$CHAIN" 2>/dev/null; do :; done
iptables -w 5 -F "$CHAIN" 2>/dev/null || true
iptables -w 5 -X "$CHAIN" 2>/dev/null || true
while iptables -w 5 -t nat -D POSTROUTING -j "$NAT_CHAIN" 2>/dev/null; do :; done
iptables -w 5 -t nat -F "$NAT_CHAIN" 2>/dev/null || true
iptables -w 5 -t nat -X "$NAT_CHAIN" 2>/dev/null || true
while iptables -w 5 -t raw -D PREROUTING -j "$RAW_CHAIN" 2>/dev/null; do :; done
iptables -w 5 -t raw -F "$RAW_CHAIN" 2>/dev/null || true
iptables -w 5 -t raw -X "$RAW_CHAIN" 2>/dev/null || true
"$BASE_DIR/host/sysctl-state.sh" apply-v2
