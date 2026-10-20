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
    status=$(docker inspect -f '{{.State.Health.Status}}' "$EGRESS_CONTAINER" 2>/dev/null || true)
    case "$status" in
        healthy)
            if "$BASE_DIR/host/egress-forward-enable.sh" >/dev/null 2>&1; then
                exit 0
            fi
            ;;
        unhealthy)
            docker logs --tail 50 "$EGRESS_CONTAINER" >&2 || true
            exit 1
            ;;
    esac
    i=$((i + 1))
    sleep 1
done

echo "Egress container did not become healthy with forwarding enabled" >&2
docker logs --tail 50 "$EGRESS_CONTAINER" >&2 || true
exit 1
