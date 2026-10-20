#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 CONTAINER READY_FILE" >&2
    exit 2
fi
container=$1
ready_file=$2
BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}

[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" = true ]
pid=$(docker inspect -f '{{.State.Pid}}' "$container")
case "$pid" in ''|*[!0-9]*|0*) exit 1 ;; esac
docker exec "$container" test -s "$ready_file"
"$BASE_DIR/host/guard-check.sh"
"$BASE_DIR/host/docker-user-check.sh"
[ "$(docker inspect -f '{{.State.Pid}}' "$container")" = "$pid" ]
current=$(nsenter -t "$pid" -n sysctl -n net.ipv4.ip_forward)
case "$current" in
    0) nsenter -t "$pid" -n sysctl -q -w net.ipv4.ip_forward=1 ;;
    1) ;;
    *) exit 1 ;;
esac
[ "$(docker inspect -f '{{.State.Pid}}' "$container")" = "$pid" ]
[ "$(nsenter -t "$pid" -n sysctl -n net.ipv4.ip_forward)" = 1 ]
