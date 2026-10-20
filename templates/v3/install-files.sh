#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then echo 'Run as root' >&2; exit 1; fi
if [ "$#" -ne 0 ] && [ "$#" -ne 2 ]; then
    echo 'usage: install-files.sh [PGDL_CONF AE_CONF]' >&2
    exit 2
fi
PACKAGE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ETC_DIR=/etc/amnezia-lb-multi-v3
SECRET_DIR=/opt/amnezia-lb-multi-v3/secrets

test -d /etc/amnezia-lb-v2
install -d -m 0755 "$ETC_DIR/host" "$ETC_DIR/egress" "$ETC_DIR/systemd"
install -d -m 0700 "$SECRET_DIR"
install -m 0644 "$PACKAGE_DIR/config/multi.env" "$ETC_DIR/multi.env"
install -m 0644 "$PACKAGE_DIR/config/egresses.json" "$ETC_DIR/egresses.json"
install -m 0600 "$PACKAGE_DIR"/host/*.nft "$ETC_DIR/host/"
install -m 0755 "$PACKAGE_DIR"/host/*.sh "$ETC_DIR/host/"
install -m 0755 "$PACKAGE_DIR"/host/*.py "$ETC_DIR/host/"
install -m 0755 "$PACKAGE_DIR"/egress/*.sh "$ETC_DIR/egress/"
install -m 0644 "$PACKAGE_DIR/egress/compose.yaml" "$ETC_DIR/egress/compose.yaml"
install -m 0644 "$PACKAGE_DIR"/systemd/* "$ETC_DIR/systemd/"

if [ "$#" -eq 2 ]; then
    PGDL_SOURCE=$1
    AE_SOURCE=$2
    test -r "$PGDL_SOURCE"
    test -r "$AE_SOURCE"
    "$ETC_DIR/egress/prepare-egress-config.sh" "$PGDL_SOURCE" \
        "$SECRET_DIR/awg-pgdl.conf" @@EGRESS2_AWG_IP@@/32 @@EGRESS2_ENDPOINT_IP@@:@@EGRESS2_ENDPOINT_PORT@@
    "$ETC_DIR/egress/prepare-egress-config.sh" "$AE_SOURCE" \
        "$SECRET_DIR/awg-ae.conf" @@EGRESS3_AWG_IP@@/32 @@EGRESS3_ENDPOINT_IP@@:@@EGRESS3_ENDPOINT_PORT@@
else
    test -s "$SECRET_DIR/awg-pgdl.conf"
    test -s "$SECRET_DIR/awg-ae.conf"
fi

for unit in amnezia-lb-multi-v3-guard.service \
            amnezia-lb-multi-v3-egress.service \
            amnezia-lb-multi-v3-controller.service; do
    install -m 0644 "$PACKAGE_DIR/systemd/$unit" "/etc/systemd/system/$unit"
done
python3 -m py_compile "$ETC_DIR/host/controller.py"
systemd-analyze verify \
    /etc/systemd/system/amnezia-lb-multi-v3-guard.service \
    /etc/systemd/system/amnezia-lb-multi-v3-egress.service \
    /etc/systemd/system/amnezia-lb-multi-v3-controller.service
systemctl daemon-reload
find "$ETC_DIR" -type f ! -name installed-manifest.sha256 -print0 | \
    sort -z | xargs -0 sha256sum > "$ETC_DIR/installed-manifest.sha256"
chmod 0600 "$ETC_DIR/installed-manifest.sha256"
echo 'v3 active files installed; Docker drop-in and runtime activation are still unchanged.'
