#!/bin/bash
set -Eeuo pipefail

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"

for command in docker nft ip iptables ip6tables nsenter curl awk sed grep python3 timeout sysctl sha256sum journalctl; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "Missing command: $command" >&2
        exit 1
    }
done

docker compose version >/dev/null
docker info >/dev/null
docker image inspect amnezia-awg2 >/dev/null
[ "$(docker inspect -f '{{.State.Running}}' "$INGRESS_CONTAINER")" = true ]

network_ip() {
    network=$1
    docker inspect -f \
        "{{with index .NetworkSettings.Networks \"$network\"}}{{.IPAddress}}{{end}}" \
        "$INGRESS_CONTAINER"
}
[ "$(network_ip "$INGRESS_OUTER_NETWORK")" = "$INGRESS_OUTER_IP" ]
[ "$(network_ip "$INGRESS_DNS_NETWORK")" = "$INGRESS_DNS_IP" ]
[ "$(network_ip "$INGRESS_AUX_NETWORK")" = "$INGRESS_AUX_IP" ]

[ "$(docker network inspect -f '{{index .Options "com.docker.network.bridge.name"}}' "$INGRESS_OUTER_NETWORK")" = "$INGRESS_OUTER_BRIDGE" ]
[ "$(docker network inspect -f '{{index .Options "com.docker.network.bridge.name"}}' "$INGRESS_DNS_NETWORK")" = "$INGRESS_DNS_BRIDGE" ]
[ "$(docker network inspect -f '{{index .Options "com.docker.network.bridge.name"}}' "$INGRESS_AUX_NETWORK")" = "$INGRESS_AUX_BRIDGE" ]
ip -o link show "$INGRESS_OUTER_BRIDGE" >/dev/null
ip -o link show "$INGRESS_DNS_BRIDGE" >/dev/null
ip -o link show "$INGRESS_AUX_BRIDGE" >/dev/null
ip -o link show "$PUBLIC_IF" >/dev/null
test -c /dev/net/tun

pid=$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER")
ingress_addresses=$(nsenter -t "$pid" -n ip -o -4 addr show)
grep -Fq "$INGRESS_OUTER_IP/24" <<<"$ingress_addresses"
grep -Fq "$INGRESS_DNS_IP/24" <<<"$ingress_addresses"
grep -Fq "$INGRESS_AUX_IP/16" <<<"$ingress_addresses"
ingress_main_routes=$(nsenter -t "$pid" -n ip route show table main)
grep -Fq "default via $INGRESS_DNS_GATEWAY" <<<"$ingress_main_routes"
[ "$(docker exec "$INGRESS_CONTAINER" \
    awg show "$INGRESS_AWG_IF" listen-port)" = "$INGRESS_AWG_PORT" ]
"$BASE_DIR/host/docker-dnat-check.sh"

iptables_version=$(iptables --version)
grep -Fq 'nf_tables' <<<"$iptables_version"
iptables -m dscp -h >/dev/null
[ "$(sysctl -n net.ipv4.ip_forward)" = 1 ]
sysctl -n net.netfilter.nf_log_all_netns >/dev/null

for network in "$DIRECT_NETWORK" "$TRANSIT_NETWORK"; do
    ! docker network inspect "$network" >/dev/null 2>&1 || {
        echo "Docker network already exists: $network" >&2
        exit 1
    }
done
for bridge in "$DIRECT_BRIDGE" "$TRANSIT_BRIDGE"; do
    ! ip link show "$bridge" >/dev/null 2>&1 || {
        echo "Bridge name already exists: $bridge" >&2
        exit 1
    }
done
! docker inspect "$EGRESS_CONTAINER" >/dev/null 2>&1 || {
    echo "Egress container name already exists: $EGRESS_CONTAINER" >&2
    exit 1
}
! nft list table inet amnezia_lb_v2 >/dev/null 2>&1 || {
    echo "nft table inet amnezia_lb_v2 already exists" >&2
    exit 1
}

ingress_rules=$(nsenter -t "$pid" -n ip -o rule show)
for priority in \
    "$OUTER_LOOKUP_PRIORITY" "$OUTER_UNREACHABLE_PRIORITY" \
    "$TARGET_LOOKUP_PRIORITY" "$TARGET_UNREACHABLE_PRIORITY" \
    "$DIRECT_LOOKUP_PRIORITY" "$DIRECT_UNREACHABLE_PRIORITY"; do
    ! grep -Eq "^${priority}:" <<<"$ingress_rules" || {
        echo "Ingress RPDB priority already occupied: $priority" >&2
        exit 1
    }
done

host_rules=$(ip -o rule show)
for priority in "$HOST_TRANSIT_LOOKUP_PRIORITY" "$HOST_TRANSIT_UNREACHABLE_PRIORITY"; do
    ! grep -Eq "^${priority}:" <<<"$host_rules" || {
        echo "Host RPDB priority already occupied: $priority" >&2
        exit 1
    }
done
[ -z "$(ip route show table "$HOST_TRANSIT_ROUTE_TABLE" 2>/dev/null)" ]

[ "$TARGET_IP" != "$EGRESS_AWG_ENDPOINT_IP" ]
[ "$TARGET_IP" != "@@BALANCER_PUBLIC_IP@@" ]

# Read-only TCP banner check. No package or service is installed on the target.
banner=$(timeout 5 bash -c \
    "exec 3<>/dev/tcp/$TARGET_IP/$TARGET_TCP_PORT; IFS= read -r -t 3 line <&3; printf '%s' \"\$line\"" \
    2>/dev/null || true)
grep -Fq 'SSH-2.0-' <<<"$banner"

# Parse/validate the inactive configuration without applying it.
nft -c -f "$BASE_DIR/guard.create.nft"
docker compose \
    --env-file "$BASE_DIR/pilot.env" \
    -f "$BASE_DIR/egress/compose.yaml" config --quiet

echo "Preflight passed. Existing Amnezia state was not changed."
