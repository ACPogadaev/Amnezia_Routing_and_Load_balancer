#!/bin/sh
set -eu
BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
exec python3 "$BASE_DIR/host/ingress-router.py"
