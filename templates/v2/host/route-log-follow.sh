#!/bin/sh
set -eu

RUNTIME_DIR=/run/amnezia-lb-v2
ACTIVE_FILE="$RUNTIME_DIR/route-log.active"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root" >&2
    exit 1
fi

if [ ! -s "$ACTIVE_FILE" ]; then
    echo "Route logging is disabled" >&2
    exit 1
fi
started=$(sed -n '1p' "$ACTIVE_FILE")
case "$started" in
    ''|*[!0-9]*)
        echo "Invalid route-log start time" >&2
        exit 1
        ;;
esac

echo "Following rate-limited AMLB2 kernel events since epoch $started."
echo "Packet payloads are not logged. Press Ctrl+C to stop following;"
echo "logging itself remains enabled until route-log-disable.sh is run."
exec journalctl -k -f --since="@$started" --no-pager \
    -o short-iso-precise --grep='AMLB2 '
