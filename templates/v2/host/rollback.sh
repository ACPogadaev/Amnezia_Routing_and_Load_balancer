#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"
mode=${1:---blocked}

case "$mode" in
    --blocked|--restore-baseline) ;;
    *)
        echo "Usage: $0 [--blocked|--restore-baseline]" >&2
        exit 2
        ;;
esac

# Both diagnostic modes are optional and non-blocking. Rollback removes them
# first so no stale counter table survives a test session.
route_log_cleanup_failed=0
route_log_state=/run/amnezia-lb-v2/route-log.nf-log-all-netns.original
if ! "$BASE_DIR/host/route-log-disable.sh"; then
    route_log_cleanup_failed=1
    echo "Rollback will continue, but route-log sysctl cleanup is incomplete." >&2
fi
"$BASE_DIR/host/trace-stop.sh" || true

case "$mode" in
    --blocked)
        systemctl disable --now amnezia-lb-v2-health.service 2>/dev/null || true
        systemctl disable --now amnezia-lb-v2-pilot.service 2>/dev/null || true
        "$BASE_DIR/host/policy-down.sh" || true
        echo "Egress stopped. The active target_v4 set remains fail-closed."
        echo "Non-target IPv4 continues through the dedicated direct bridge."
        ;;
    --restore-baseline)
        systemctl disable --now amnezia-lb-v2-health.service 2>/dev/null || true
        systemctl disable --now amnezia-lb-v2-pilot.service 2>/dev/null || true
        systemctl disable --now amnezia-lb-v2-ingress-router.service 2>/dev/null || true

        "$BASE_DIR/host/policy-down.sh" || true
        docker compose \
            --env-file "$BASE_DIR/pilot.env" \
            -f "$BASE_DIR/egress/compose.yaml" down --remove-orphans || true
        "$BASE_DIR/host/ingress-cleanup.sh"
        "$BASE_DIR/host/docker-user-remove.sh" || true
        "$BASE_DIR/host/transit-host-down.sh" || true
        "$BASE_DIR/host/network-remove.sh"

        # Remove Docker's dependency first. After daemon-reload, stopping the
        # oneshot guard cannot propagate a stop to the running Docker daemon.
        rm -f /etc/systemd/system/docker.service.d/10-amnezia-lb-v2-guard.conf
        systemctl daemon-reload
        nft delete table inet amnezia_lb_v2 2>/dev/null || true
        systemctl disable amnezia-lb-v2-guard.service 2>/dev/null || true
        systemctl stop amnezia-lb-v2-guard.service 2>/dev/null || true
        systemctl reset-failed \
            amnezia-lb-v2-guard.service \
            amnezia-lb-v2-ingress-router.service \
            amnezia-lb-v2-pilot.service \
            amnezia-lb-v2-health.service 2>/dev/null || true
        # Preserve the sysctl recovery value if logging cleanup failed. Other
        # rollback operations still complete and are verified below.
        if [ ! -s "$route_log_state" ]; then
            rm -rf /run/amnezia-lb-v2
            route_log_cleanup_failed=0
        else
            route_log_cleanup_failed=1
            echo "Runtime state retained for route-log cleanup retry: $route_log_state" >&2
        fi

        # Verify the audited original Amnezia route and absence of pilot state.
        pid=$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER")
        nsenter -t "$pid" -n ip route show table main | \
            grep -Fq "default via $INGRESS_DNS_GATEWAY"
        ! nft list table inet amnezia_lb_v2 >/dev/null 2>&1
        ! nsenter -t "$pid" -n nft list table inet amnezia_lb_v2_targets \
            >/dev/null 2>&1
        ! docker network inspect "$DIRECT_NETWORK" >/dev/null 2>&1
        ! docker network inspect "$TRANSIT_NETWORK" >/dev/null 2>&1
        for priority in \
            "$HOST_TRANSIT_LOOKUP_PRIORITY" \
            "$HOST_TRANSIT_UNREACHABLE_PRIORITY"; do
            ! ip -o rule show | grep -Eq "^${priority}:"
        done
        [ -z "$(ip route show table "$HOST_TRANSIT_ROUTE_TABLE" 2>/dev/null)" ]
        echo "Original ingress routing restored; Amnezia container was not recreated."
        ;;
esac

if [ "$route_log_cleanup_failed" -ne 0 ] && [ ! -s "$route_log_state" ]; then
    echo "Route-log sysctl cleanup succeeded during service shutdown."
    route_log_cleanup_failed=0
fi
if [ "$route_log_cleanup_failed" -ne 0 ] && [ -s "$route_log_state" ]; then
    echo "Rollback completed with one cleanup error." >&2
    echo "Retry: $BASE_DIR/host/route-log-disable.sh" >&2
    exit 1
fi
