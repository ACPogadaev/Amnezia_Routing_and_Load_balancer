#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"

rules=$(iptables -w 5 -t nat -S DOCKER)
matches=$(printf '%s\n' "$rules" | awk -v port="$INGRESS_AWG_PORT" '
    $1 == "-A" && $2 == "DOCKER" && $0 ~ ("--dport " port "([[:space:]]|$)") &&
    $0 ~ /-j DNAT([[:space:]]|$)/ { print }
')
count=$(printf '%s\n' "$matches" | awk 'NF { n++ } END { print n + 0 }')

if [ "$count" -ne 1 ]; then
    echo "Expected exactly one Docker DNAT rule for UDP $INGRESS_AWG_PORT; found $count" >&2
    printf '%s\n' "$matches" >&2
    exit 1
fi

printf '%s\n' "$matches" | grep -Fq -- "-p udp"
printf '%s\n' "$matches" | \
    grep -Fq -- "--to-destination $INGRESS_OUTER_IP:$INGRESS_AWG_PORT"

echo "Docker DNAT for UDP $INGRESS_AWG_PORT terminates at $INGRESS_OUTER_IP."
