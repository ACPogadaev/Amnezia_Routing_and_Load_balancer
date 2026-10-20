#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
DROPIN_DIR=/etc/systemd/system/docker.service.d
DROPIN="$DROPIN_DIR/10-amnezia-lb-v2-guard.conf"

# The guard is active before either Docker's dependency or ingress routing is
# introduced. A later failure therefore leaves the protected target blocked.
systemctl enable amnezia-lb-v2-guard.service
systemctl restart amnezia-lb-v2-guard.service
"$BASE_DIR/host/guard-check.sh"

install -d -m 0755 "$DROPIN_DIR"
install -m 0644 "$BASE_DIR/systemd/10-amnezia-lb-v2-guard.conf" "$DROPIN"
systemctl daemon-reload

systemctl enable amnezia-lb-v2-ingress-router.service
systemctl restart amnezia-lb-v2-ingress-router.service
"$BASE_DIR/host/wait-ingress-ready.sh"
systemctl enable amnezia-lb-v2-pilot.service
systemctl restart amnezia-lb-v2-pilot.service
systemctl enable amnezia-lb-v2-health.service
systemctl restart amnezia-lb-v2-health.service

"$BASE_DIR/host/verify.sh"
echo "Amnezia LB v2 single-egress pilot is active for every 10.8.1.0/24 client."
echo "Run activate-validated.sh for a fresh-handshake gate and automatic rollback."
