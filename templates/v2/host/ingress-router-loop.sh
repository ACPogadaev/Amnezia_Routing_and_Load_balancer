#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"
RUNTIME_DIR=/run/amnezia-lb-v2
READY="$RUNTIME_DIR/ingress.ready"
last_pid=

install -d -m 0755 "$RUNTIME_DIR"
trap 'rm -f "$READY"; exit 0' TERM INT EXIT

while :; do
    pid=$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER" 2>/dev/null || true)
    if [ -n "$pid" ] && [ "$pid" != 0 ]; then
        recorded=$(sed -n '1p' "$READY" 2>/dev/null || true)
        if [ "$pid" != "$last_pid" ] || [ "$recorded" != "$pid" ] || \
           ! "$BASE_DIR/host/transit-host-check.sh" >/dev/null 2>&1 || \
           ! "$BASE_DIR/host/docker-user-check.sh" >/dev/null 2>&1 || \
           ! "$BASE_DIR/host/ingress-check.sh" "$pid" >/dev/null 2>&1; then
            rm -f "$READY"
            "$BASE_DIR/host/network-ensure.sh"
            "$BASE_DIR/host/transit-host-up.sh"
            pid=$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER")
            "$BASE_DIR/host/ingress-configure.sh"
            "$BASE_DIR/host/docker-user-install.sh"
            printf '%s\n' "$pid" > "$READY.tmp"
            mv -f "$READY.tmp" "$READY"
            last_pid=$pid
        fi
    else
        rm -f "$READY"
        last_pid=
    fi
    sleep "$INGRESS_CHECK_INTERVAL_SECONDS"
done
