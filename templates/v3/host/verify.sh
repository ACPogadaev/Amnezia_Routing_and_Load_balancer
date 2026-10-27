#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_MULTI_DIR:-/etc/amnezia-lb-multi-v3}
. "$BASE_DIR/multi.env"
test -s "$BASE_DIR/installed-manifest.sha256"
sha256sum -c --quiet "$BASE_DIR/installed-manifest.sha256"
"$BASE_DIR/host/guard-check.sh"
"$BASE_DIR/host/balance-check.sh"
"$BASE_DIR/host/host-policy-check.sh"
"$BASE_DIR/host/docker-user-check.sh"
"$V2_DIR/host/guard-check.sh"
"$V2_DIR/host/docker-user-check.sh"

for container in amnezia-egress-main-pilot-v2 "$PGDL_CONTAINER" "$AE_CONTAINER"; do
    [ "$(docker inspect -f '{{.State.Running}}' "$container")" = true ]
    [ "$(docker inspect -f '{{.State.OOMKilled}}' "$container")" = false ]
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$container")" = healthy ]
done

check_mss() {
    container=$1 awg_if=$2
    docker exec "$container" iptables -t mangle -C FORWARD \
        -i eth0 -o "$awg_if" -s "$INGRESS_TRANSIT_IP/32" \
        -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1160
    docker exec "$container" iptables -t mangle -C FORWARD \
        -i "$awg_if" -o eth0 -d "$INGRESS_TRANSIT_IP/32" \
        -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1160
}
check_mss amnezia-egress-main-pilot-v2 awg-main
check_mss "$PGDL_CONTAINER" "$PGDL_AWG_IF"
check_mss "$AE_CONTAINER" "$AE_AWG_IF"

python3 - "$RUNTIME_DIR/state.json" "$RELEASE_ID" "$BASE_DIR/multi.env" "$BASE_DIR/egresses.json" <<'PY'
import json, sys, time
def read_env(path):
    result = {}
    for raw in open(path, encoding="utf-8"):
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result

s=json.load(open(sys.argv[1]))
env=read_env(sys.argv[3])
egresses=json.load(open(sys.argv[4]))
active={item["name"] for item in egresses}
expected_exit={item["name"]: item["expected_exit_ip"] for item in egresses}
retired={int(item.strip(), 0) for item in env.get("RETIRED_MARKS", "").split(",") if item.strip()}
allowed={item for item in env.get("RECOVERY_ALLOWED_EGRESSES", "").split(",") if item}
assert time.time()-s["time"] < 30, s
assert s["release"] == sys.argv[2], s
assert s["infra_valid"] is True and s["admission_open"] is True, s
assert s["maintenance"] is False, s
assert s["mode"] == "balanced", s
assert set(s["healthy"]) == active, s
assert set(s["eligible"]) == active, s
assert s["recovery_enabled"] is (env.get("RECOVERY_ENABLED", "0") == "1"), s
assert set(s["recovery_allowed_egresses"]) == allowed, s
assert s["recovery_allow_crashloop_containment"] is (env.get("RECOVERY_ALLOW_CRASHLOOP_CONTAINMENT", "0") == "1"), s
assert s["recovery_journal_valid"] is True and s["recovery_journal_error"] is None, s
assert s["recovery_pending"] is None, s
assert set(s["retired_quarantined_marks"]) == retired, s
assert sum(s["bucket_counts"].values()) == 256, s
assert s["bucket_counts"]["fail"] == 0, s
assert all(s["bucket_counts"][name] > 0 for name in active), s
for name in active:
    item=s["egresses"][name]
    assert item["healthy"] is True and item["eligible"] is True, item
    assert item["reason"] == "ok" and item["failures"] == 0, item
    assert item["exit_ip"] == expected_exit[name], item
PY

route=$(ip route get 8.8.8.8 from "$INGRESS_TRANSIT_IP" iif "$INGRESS_TRANSIT_BRIDGE" mark "$MAIN_MARK")
printf '%s\n' "$route" | grep -Fq 'via 172.30.250.11 dev amlt0'
route=$(ip route get 8.8.8.8 from "$INGRESS_TRANSIT_IP" iif "$INGRESS_TRANSIT_BRIDGE" mark "$PGDL_MARK")
printf '%s\n' "$route" | grep -Fq "via $PGDL_CONTAINER_IP dev $PGDL_BRIDGE"
route=$(ip route get 8.8.8.8 from "$INGRESS_TRANSIT_IP" iif "$INGRESS_TRANSIT_BRIDGE" mark "$AE_MARK")
printf '%s\n' "$route" | grep -Fq "via $AE_CONTAINER_IP dev $AE_BRIDGE"
if ip route get 8.8.8.8 from "$INGRESS_TRANSIT_IP" iif "$INGRESS_TRANSIT_BRIDGE" mark "$FAIL_MARK" >/dev/null 2>&1; then
    echo 'Fail mark unexpectedly has a route' >&2
    exit 1
fi

python3 - "$BASE_DIR/multi.env" <<'PY'
import json, subprocess, sys
env={}
for raw in open(sys.argv[1], encoding="utf-8"):
    line=raw.strip()
    if line and not line.startswith("#") and "=" in line:
        key, value=line.split("=", 1)
        env[key]=value
expected={int(item.strip(), 0) for item in env.get("RETIRED_MARKS", "").split(",") if item.strip()}
data=json.loads(subprocess.check_output([
    "nft", "-j", "list", "set", "inet", "amnezia_lb_balance_v3", "quarantined_marks"
]))["nftables"]
qset=next(item["set"] for item in data if "set" in item)
actual={int(value) for value in qset.get("elem", [])}
assert actual == expected, (actual, expected)
PY

echo 'Three-egress functional health, recovery state, quarantine and fail-closed selectors passed.'
