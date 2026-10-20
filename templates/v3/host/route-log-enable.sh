#!/bin/sh
set -eu

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT HUP INT TERM
cat > "$tmp" <<'EOF'
add table inet amnezia_lb_route_log_v3
add chain inet amnezia_lb_route_log_v3 prerouting { type filter hook prerouting priority 0; policy accept; }
add rule inet amnezia_lb_route_log_v3 prerouting iifname "amlt0" ip saddr 172.30.250.10 ct state new meta mark 0x201 limit rate 20/second burst 40 packets log prefix "AML-V3 main " counter
add rule inet amnezia_lb_route_log_v3 prerouting iifname "amlt0" ip saddr 172.30.250.10 ct state new meta mark 0x202 limit rate 20/second burst 40 packets log prefix "AML-V3 pgdl " counter
add rule inet amnezia_lb_route_log_v3 prerouting iifname "amlt0" ip saddr 172.30.250.10 ct state new meta mark 0x203 limit rate 20/second burst 40 packets log prefix "AML-V3 ae " counter
add rule inet amnezia_lb_route_log_v3 prerouting iifname "amlt0" ip saddr 172.30.250.10 ct state new meta mark 0x2ff limit rate 20/second burst 40 packets log prefix "AML-V3 fail " counter
EOF
if nft list table inet amnezia_lb_route_log_v3 >/dev/null 2>&1; then
    sed -i '1c flush table inet amnezia_lb_route_log_v3' "$tmp"
fi
nft -c -f "$tmp"
nft -f "$tmp"
echo 'Route logging enabled. Follow with: journalctl -k -f -g AML-V3'
