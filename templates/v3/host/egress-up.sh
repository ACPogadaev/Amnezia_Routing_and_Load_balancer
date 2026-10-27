#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
. "$BASE_DIR/multi.env"
test -s /opt/amnezia-lb-multi-v3/secrets/awg-pgdl.conf
test -s /opt/amnezia-lb-multi-v3/secrets/awg-ae.conf
"$BASE_DIR/host/guard-check.sh"
"$BASE_DIR/host/network-ensure.sh"
"$BASE_DIR/host/docker-user-install.sh"

# The staged probe containers use the same peer keys; stop and remove only
# those two known temporary containers before starting production peers.
for container in amnezia-egress-pgdl-stage-v2 amnezia-egress-ae-stage-v2; do
    docker rm -f "$container" >/dev/null 2>&1 || true
done

docker compose --env-file "$BASE_DIR/multi.env" \
    -f "$BASE_DIR/egress/compose.yaml" up -d

for tuple in "$PGDL_CONTAINER:/run/amnezia-lb-multi-v3/egress-policy-ready" \
             "$AE_CONTAINER:/run/amnezia-lb-multi-v3/egress-policy-ready"; do
    container=${tuple%%:*}
    ready=/${tuple#*/}
    i=0
    while [ "$i" -lt 90 ]; do
        # The functional healthcheck requires forwarding, while forwarding may
        # only be enabled after the container publishes its local policy-ready
        # token. Waiting for Docker health here would therefore deadlock.
        if docker exec "$container" test -s "$ready" 2>/dev/null && \
            "$BASE_DIR/host/egress-forward-enable.sh" "$container" "$ready" >/dev/null 2>&1; then
            break
        fi
        i=$((i + 1))
        sleep 1
    done
    [ "$i" -lt 90 ] || {
        echo "$container did not publish local policy readiness" >&2
        docker logs --tail 50 "$container" >&2 || true
        exit 1
    }
done
