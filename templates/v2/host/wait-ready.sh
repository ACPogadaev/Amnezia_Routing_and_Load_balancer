#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"
deadline=$(( $(date +%s) + READY_TIMEOUT_SECONDS ))

while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -Eq '^up([[:space:]]|$)' /run/amnezia-lb-v2/health.state 2>/dev/null && \
       docker inspect -f '{{.State.Health.Status}}' "$EGRESS_CONTAINER" 2>/dev/null | \
           grep -Fxq healthy; then
        pid=$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER" 2>/dev/null || true)
        recorded=$(sed -n '1p' /run/amnezia-lb-v2/ingress.ready 2>/dev/null || true)
        if [ -n "$pid" ] && [ "$pid" = "$recorded" ] && \
           "$BASE_DIR/host/target-route-check.sh" "$pid" >/dev/null 2>&1; then
            exit 0
        fi
    fi
    sleep 2
done

echo "Pilot did not become healthy within ${READY_TIMEOUT_SECONDS}s" >&2
systemctl --no-pager --full status amnezia-lb-v2-health.service >&2 || true
docker logs --tail 50 "$EGRESS_CONTAINER" >&2 || true
exit 1
