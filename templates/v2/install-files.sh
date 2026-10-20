#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root" >&2
    exit 1
fi
if [ "$#" -ne 1 ]; then
    echo "usage: $0 /path/to/ams3-main-a2.conf" >&2
    exit 2
fi

SOURCE_CONF=$1
PACKAGE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ETC_DIR=/etc/amnezia-lb-v2
SECRET_DIR=/opt/amnezia-lb-v2/secrets

test -r "$SOURCE_CONF"
install -d -m 0755 "$ETC_DIR/host" "$ETC_DIR/egress" "$ETC_DIR/systemd"
install -d -m 0700 "$SECRET_DIR"
install -m 0644 "$PACKAGE_DIR/config/pilot.env" "$ETC_DIR/pilot.env"
. "$ETC_DIR/pilot.env"
install -m 0644 "$PACKAGE_DIR/config/active-target-v4.txt" \
    "$ETC_DIR/active-target-v4.txt"
install -m 0600 "$PACKAGE_DIR/host/guard.create.nft" "$ETC_DIR/guard.create.nft"
install -m 0600 "$PACKAGE_DIR/host/guard.replace.nft" "$ETC_DIR/guard.replace.nft"
install -m 0600 "$PACKAGE_DIR/host/ingress-targets.create.nft" \
    "$ETC_DIR/ingress-targets.create.nft"
install -m 0600 "$PACKAGE_DIR/host/ingress-targets.replace.nft" \
    "$ETC_DIR/ingress-targets.replace.nft"
install -m 0755 "$PACKAGE_DIR"/host/*.sh "$ETC_DIR/host/"
install -m 0755 "$PACKAGE_DIR"/host/*.py "$ETC_DIR/host/"
install -m 0755 "$PACKAGE_DIR"/egress/*.sh "$ETC_DIR/egress/"
install -m 0644 "$PACKAGE_DIR/egress/compose.yaml" "$ETC_DIR/egress/compose.yaml"
install -m 0644 "$PACKAGE_DIR/systemd/10-amnezia-lb-v2-guard.conf" \
    "$ETC_DIR/systemd/10-amnezia-lb-v2-guard.conf"

"$ETC_DIR/egress/prepare-egress-config.sh" \
    "$SOURCE_CONF" "$SECRET_DIR/awg-main.conf" \
    "$EGRESS_AWG_IP/32" "$EGRESS_AWG_ENDPOINT_IP:$EGRESS_AWG_ENDPOINT_PORT"

# This read-only check runs before the Docker dependency is installed.
"$ETC_DIR/host/preflight.sh"

for unit in \
    amnezia-lb-v2-guard.service \
    amnezia-lb-v2-ingress-router.service \
    amnezia-lb-v2-pilot.service \
    amnezia-lb-v2-health.service; do
    install -m 0644 "$PACKAGE_DIR/systemd/$unit" "/etc/systemd/system/$unit"
done
systemd-analyze verify \
    /etc/systemd/system/amnezia-lb-v2-guard.service \
    /etc/systemd/system/amnezia-lb-v2-ingress-router.service \
    /etc/systemd/system/amnezia-lb-v2-pilot.service \
    /etc/systemd/system/amnezia-lb-v2-health.service
systemctl daemon-reload

echo "v2 files staged; no service, firewall rule, route or Docker dependency was activated."
