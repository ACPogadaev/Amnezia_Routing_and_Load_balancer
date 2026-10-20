#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
exec "$BASE_DIR/host/host-policy-check.py" "$BASE_DIR/multi.env"
