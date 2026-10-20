#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"
pid=${1:-$(docker inspect -f '{{.State.Pid}}' "$INGRESS_CONTAINER")}
[ -n "$pid" ] && [ "$pid" != 0 ]
ns() { nsenter -t "$pid" -n -- "$@"; }

state="/run/amnezia-lb-v2/ingress-targets.$pid.sha256"
test -s "$state"
expected=$(sed -n '1p' "$state")
actual=$(ns nft -j list table inet amnezia_lb_v2_targets | \
    "$BASE_DIR/host/nft-json-fingerprint.py")
[ "$actual" = "$expected" ] || {
    echo "ingress target classifier fingerprint mismatch" >&2
    exit 1
}

ns nft -j list set inet amnezia_lb_v2_targets target_v4 | \
    "$BASE_DIR/host/active-targets-verify.py" \
        "$ACTIVE_TARGETS_FILE" amnezia_lb_v2_targets target_v4

ns nft -j list table inet amnezia_lb_v2_targets | python3 -c '
import json, sys
d=json.load(sys.stdin)["nftables"]
chains=[x["chain"] for x in d if "chain" in x and x["chain"].get("name")=="classify"]
assert len(chains)==1
c=chains[0]
assert c.get("hook")=="prerouting" and c.get("prio")==-151 and c.get("policy")=="accept"
rules=[x["rule"] for x in d if "rule" in x and x["rule"].get("chain")=="classify"]
assert len(rules)==2
assert [r.get("comment") for r in rules] == [
    "v2 reset client DSCP", "v2 classify active targets"
]
'
