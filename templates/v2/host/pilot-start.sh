#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"

test -s "/opt/amnezia-lb-v2/secrets/$EGRESS_AWG_IF.conf"
"$BASE_DIR/host/guard-check.sh"
"$BASE_DIR/host/wait-ingress-ready.sh"
"$BASE_DIR/host/docker-user-install.sh"

docker compose \
    --env-file "$BASE_DIR/pilot.env" \
    -f "$BASE_DIR/egress/compose.yaml" up -d

i=0
while [ "$i" -lt 60 ]; do
    if docker exec "$EGRESS_CONTAINER" test -s /run/amnezia-lb-v2/egress-policy-ready 2>/dev/null && \
        "$BASE_DIR/host/egress-forward-enable.sh" >/dev/null 2>&1; then
        exit 0
    fi
    i=$((i + 1))
    sleep 1
done

echo "Egress container did not publish local policy readiness" >&2
docker logs --tail 50 "$EGRESS_CONTAINER" >&2 || true
exit 1
