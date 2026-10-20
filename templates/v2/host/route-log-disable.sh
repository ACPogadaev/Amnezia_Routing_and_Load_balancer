#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"

TABLE=amnezia_lb_v2_route_log
RUNTIME_DIR=/run/amnezia-lb-v2
ACTIVE_FILE="$RUNTIME_DIR/route-log.active"
LAST_FILE="$RUNTIME_DIR/route-log.last"
NF_LOG_SYSCTL=net.netfilter.nf_log_all_netns
NF_LOG_STATE="$RUNTIME_DIR/route-log.nf-log-all-netns.original"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root" >&2
    exit 1
fi

started=
if [ -s "$ACTIVE_FILE" ]; then
    started=$(sed -n '1p' "$ACTIVE_FILE")
fi
stopped=$(date +%s)

nft delete table inet "$TABLE" 2>/dev/null || true

for container in "$INGRESS_CONTAINER" "$EGRESS_CONTAINER"; do
    pid=$(docker inspect -f '{{.State.Pid}}' "$container" 2>/dev/null || true)
    case "$pid" in
        ''|*[!0-9]*|0*) continue ;;
    esac
    nsenter -t "$pid" -n nft delete table inet "$TABLE" 2>/dev/null || true
done

if [ -s "$NF_LOG_STATE" ]; then
    original=$(sed -n '1p' "$NF_LOG_STATE")
    case "$original" in
        0|1) ;;
        *)
            echo "Refusing invalid saved $NF_LOG_SYSCTL value; backup retained at $NF_LOG_STATE" >&2
            exit 1
            ;;
    esac
    if ! sysctl -q -w "$NF_LOG_SYSCTL=$original"; then
        echo "Failed to restore $NF_LOG_SYSCTL=$original; backup retained at $NF_LOG_STATE" >&2
        exit 1
    fi
    rm -f "$NF_LOG_STATE"
fi

if [ -n "$started" ]; then
    install -d -m 0755 "$RUNTIME_DIR"
    printf '%s %s\n' "$started" "$stopped" > "$LAST_FILE.tmp"
    mv -f "$LAST_FILE.tmp" "$LAST_FILE"
fi
rm -f "$ACTIVE_FILE"

echo "Route logging disabled; the prior netns logging sysctl was restored."
echo "Routing and verdict-bearing firewall policy were not changed."
if [ -n "$started" ]; then
    echo "Saved journal interval: $started .. $stopped"
    echo "journalctl -k --since=@$started --until=@$stopped --no-pager --grep='AMLB2 '"
fi
