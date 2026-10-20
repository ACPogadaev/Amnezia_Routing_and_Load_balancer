#!/bin/sh
set -eu
nft delete table inet amnezia_lb_route_log_v3 2>/dev/null || true
echo 'Route logging disabled.'
