#!/bin/sh
set -eu

BASE_DIR=${AMNEZIA_LB_DIR:-/etc/amnezia-lb-v2}
. "$BASE_DIR/pilot.env"
EXPECTED=/run/amnezia-lb-v2/guard.sha256

test -s "$EXPECTED"
expected=$(sed -n '1p' "$EXPECTED")
actual=$("$BASE_DIR/host/guard-fingerprint.py")
[ "$actual" = "$expected" ] || {
    echo "amnezia_lb_v2 ruleset fingerprint mismatch" >&2
    exit 1
}

nft -j list set inet amnezia_lb_v2 target_v4 | \
    "$BASE_DIR/host/active-targets-verify.py" \
        "$ACTIVE_TARGETS_FILE" amnezia_lb_v2 target_v4

# Explicit semantic checks complement the full normalized-JSON fingerprint.
nft -j list table inet amnezia_lb_v2 | python3 -c '
import json, sys
d=json.load(sys.stdin)["nftables"]
chains=[x["chain"] for x in d if "chain" in x and x["chain"].get("name")=="forward_guard"]
assert len(chains)==1
c=chains[0]
assert c.get("hook")=="forward" and c.get("prio")==-5 and c.get("policy")=="accept"
rules=[x["rule"] for x in d if "rule" in x and x["rule"].get("chain")=="forward_guard"]
assert len(rules)==8
comments={r.get("comment") for r in rules}
assert len(comments)==8 and None not in comments
'
