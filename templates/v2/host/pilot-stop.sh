#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"

# Diagnostic nft tables never block packets, but remove them when the pilot is
# intentionally stopped so an old active marker cannot mislead an operator.
route_log_cleanup_failed=0
if ! "$BASE_DIR/host/route-log-disable.sh"; then
    route_log_cleanup_failed=1
    echo "Pilot stop will continue, but route-log sysctl cleanup must be retried." >&2
fi

# Keep ingress direct routing and every fail-closed guard. Thus ordinary client
# traffic continues, while target_v4 stays unreachable.
"$BASE_DIR/host/policy-down.sh"
docker compose \
    --env-file "$BASE_DIR/pilot.env" \
    -f "$BASE_DIR/egress/compose.yaml" down --remove-orphans

if [ "$route_log_cleanup_failed" -ne 0 ]; then
    echo "Pilot stopped with incomplete route-log cleanup." >&2
    exit 1
fi
