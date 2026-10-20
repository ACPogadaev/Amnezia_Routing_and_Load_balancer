#!/bin/sh
set -eu
if nft list table inet amnezia_lb_route_log_v3 >/dev/null 2>&1; then
    echo enabled
    nft list table inet amnezia_lb_route_log_v3
else
    echo disabled
fi
