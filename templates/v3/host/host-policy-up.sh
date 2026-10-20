#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
. "$BASE_DIR/multi.env"

replace_rule() {
    priority=$1
    shift
    existing=$(ip -N -o rule show | grep -E "^${priority}:" || true)
    if [ -n "$existing" ] && ! printf '%s\n' "$existing" | grep -Eq ' proto 99([[:space:]]|$)'; then
        echo "Refusing to replace non-v3 rule at priority $priority" >&2
        exit 1
    fi
    while ip rule del priority "$priority" 2>/dev/null; do :; done
    ip rule add priority "$priority" protocol 99 "$@"
}

ip link show "$INGRESS_TRANSIT_BRIDGE" >/dev/null
ip link show "$PGDL_BRIDGE" >/dev/null
ip link show "$AE_BRIDGE" >/dev/null
"$BASE_DIR/host/sysctl-state.sh" apply-v3

ip route replace default via 172.30.250.11 dev "$INGRESS_TRANSIT_BRIDGE" onlink table "$HOST_MAIN_TABLE"
ip route replace default via "$PGDL_CONTAINER_IP" dev "$PGDL_BRIDGE" onlink table "$HOST_PGDL_TABLE"
ip route replace default via "$AE_CONTAINER_IP" dev "$AE_BRIDGE" onlink table "$HOST_AE_TABLE"

replace_rule 20500 fwmark "$MAIN_MARK/0xffffffff" lookup "$HOST_MAIN_TABLE"
replace_rule 20501 fwmark "$MAIN_MARK/0xffffffff" unreachable
replace_rule 20502 fwmark "$PGDL_MARK/0xffffffff" lookup "$HOST_PGDL_TABLE"
replace_rule 20503 fwmark "$PGDL_MARK/0xffffffff" unreachable
replace_rule 20504 fwmark "$AE_MARK/0xffffffff" lookup "$HOST_AE_TABLE"
replace_rule 20505 fwmark "$AE_MARK/0xffffffff" unreachable
replace_rule 20506 fwmark "$FAIL_MARK/0xffffffff" unreachable
replace_rule 20507 iif "$INGRESS_TRANSIT_BRIDGE" from "$INGRESS_TRANSIT_IP/32" unreachable
ip route flush cache
exec "$BASE_DIR/host/host-policy-check.sh"
