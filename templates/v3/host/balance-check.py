#!/usr/bin/env python3
import argparse
import ipaddress
import json
import sys


TABLE = "amnezia_lb_balance_v3"
MARKS = {
    "v3 buckets main": 0x201,
    "v3 buckets pgdl": 0x202,
    "v3 buckets ae": 0x203,
}
FAIL_MARK = 0x2FF

parser = argparse.ArgumentParser()
parser.add_argument("--expected-state")
args = parser.parse_args()


def fail(message):
    raise SystemExit(message)


def match(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


def meta(key):
    return {"meta": {"key": key}}


def payload(protocol, field):
    return {"payload": {"protocol": protocol, "field": field}}


def ct(key):
    return {"ct": {"key": key}}


def set_meta_mark(value):
    return {"mangle": {"key": meta("mark"), "value": value}}


def canonical_expr(rule):
    result = []
    for expr in rule.get("expr", []):
        if "counter" in expr:
            continue
        result.append(expr)
    return result


try:
    data = json.load(sys.stdin)["nftables"]
except (KeyError, TypeError, ValueError) as error:
    fail(f"invalid nft JSON: {error}")

tables = [item["table"] for item in data if "table" in item]
if len(tables) != 1 or tables[0].get("family") != "inet" or tables[0].get("name") != TABLE:
    fail("unexpected table definition")

chains = [item["chain"] for item in data if "chain" in item]
if len(chains) != 3:
    fail("expected exactly three chains")
by_name = {chain.get("name"): chain for chain in chains}
if set(by_name) != {"prerouting", "quarantine", "select"}:
    fail("unexpected chain names")
prerouting = by_name["prerouting"]
if not (
    prerouting.get("family") == "inet"
    and prerouting.get("table") == TABLE
    and prerouting.get("type") == "filter"
    and prerouting.get("hook") == "prerouting"
    and prerouting.get("prio") == -5
    and prerouting.get("policy") == "accept"
):
    fail("invalid prerouting chain")
select = by_name["select"]
if set(select).difference({"family", "table", "name", "handle"}):
    fail("select must be a regular chain")
quarantine = by_name["quarantine"]
if not (
    quarantine.get("family") == "inet"
    and quarantine.get("table") == TABLE
    and quarantine.get("type") == "filter"
    and quarantine.get("hook") == "forward"
    and quarantine.get("prio") == -5
    and quarantine.get("policy") == "accept"
):
    fail("invalid quarantine chain")

sets = [item["set"] for item in data if "set" in item]
if len(sets) != 1:
    fail("expected exactly one quarantine set")
qset = sets[0]
if qset.get("family") != "inet" or qset.get("table") != TABLE or qset.get("name") != "quarantined_marks" or qset.get("type") != "mark":
    fail("invalid quarantine set")

allowed_quarantine = {0x201, 0x202, 0x203}
actual_quarantine = set()
for value in qset.get("elem", []):
    actual_quarantine.add(int(value))
for item in data:
    if "element" not in item:
        continue
    element = item["element"]
    if element.get("name") != "quarantined_marks":
        fail("unexpected set elements")
    values = element.get("elem", [])
    actual_quarantine.update(int(value) for value in values)
if actual_quarantine - allowed_quarantine:
    fail("quarantine set contains an unowned mark")

rules = [item["rule"] for item in data if "rule" in item]
pre_rules = [rule for rule in rules if rule.get("chain") == "prerouting"]
select_rules = [rule for rule in rules if rule.get("chain") == "select"]
quarantine_rules = [rule for rule in rules if rule.get("chain") == "quarantine"]
if len(quarantine_rules) != 1:
    fail("expected one quarantine rule")
qrule = quarantine_rules[0]
expected_quarantine_expr = [match(ct("mark"), "@quarantined_marks"), {"drop": None}]
if qrule.get("comment") != "v4 quarantine ct mark both directions" or canonical_expr(qrule) != expected_quarantine_expr:
    fail("invalid quarantine rule")
if len(pre_rules) != 6:
    fail("expected six prerouting rules")

base = [
    match(meta("iifname"), "amlt0"),
    match(payload("ip", "saddr"), "172.30.250.10"),
]
expected = [
    ("v3 restore main", base + [match(ct("mark"), 0x201), set_meta_mark(0x201)]),
    ("v3 restore pgdl", base + [match(ct("mark"), 0x202), set_meta_mark(0x202)]),
    ("v3 restore ae", base + [match(ct("mark"), 0x203), set_meta_mark(0x203)]),
    ("v3 restore fail", base + [match(ct("mark"), FAIL_MARK), set_meta_mark(FAIL_MARK)]),
    ("v3 select new flow", base + [match(ct("mark"), 0), {"jump": {"target": "select"}}]),
    (
        "v3 pin new flow",
        base + [
            match(ct("mark"), 0),
            {"mangle": {"key": ct("mark"), "value": meta("mark")}},
        ],
    ),
]
for rule, (comment, expressions) in zip(pre_rules, expected):
    if rule.get("comment") != comment or canonical_expr(rule) != expressions:
        fail(f"invalid or out-of-order prerouting rule: {comment}")

if not select_rules:
    fail("select chain is empty")
fail_rule = select_rules[-1]
if fail_rule.get("comment") != "v3 select fail" or canonical_expr(fail_rule) != [set_meta_mark(FAIL_MARK)]:
    fail("invalid select fallback")

covered = set()
seen_marks = set()
actual_buckets = [FAIL_MARK] * 256
for rule in select_rules[:-1]:
    comment = rule.get("comment")
    if comment not in MARKS or comment in seen_marks:
        fail(f"unexpected or duplicate bucket rule: {comment}")
    seen_marks.add(comment)
    expressions = canonical_expr(rule)
    if len(expressions) != 3 or expressions[1] != set_meta_mark(MARKS[comment]) or expressions[2] != {"return": None}:
        fail(f"invalid mark/return for {comment}")
    try:
        condition = expressions[0]["match"]
        left = condition["left"]["&"]
        values = condition["right"]["set"]
    except (KeyError, TypeError):
        fail(f"invalid bucket match for {comment}")
    if condition.get("op") != "==" or left != [payload("ip", "daddr"), "0.0.0.255"]:
        fail(f"invalid selector expression for {comment}")
    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as error:
            fail(f"invalid bucket {value}: {error}")
        bucket = int(address)
        if bucket > 255 or bucket in covered:
            fail(f"overlapping or out-of-range bucket {value}")
        covered.add(bucket)
        actual_buckets[bucket] = MARKS[comment]

if covered and covered != set(range(256)):
    fail(f"bucket coverage is incomplete: {len(covered)}/256")

if args.expected_state:
    try:
        expected_state = json.loads(open(args.expected_state, encoding="utf-8").read())
        expected_quarantine = {int(value) for value in expected_state["quarantined_marks"]}
        expected_buckets = [int(value) for value in expected_state["bucket_marks"]]
    except (OSError, KeyError, TypeError, ValueError) as error:
        fail(f"invalid expected state: {error}")
    if len(expected_buckets) != 256:
        fail("expected bucket map must contain 256 marks")
    if expected_quarantine != actual_quarantine:
        fail(
            f"quarantine readback mismatch: expected={sorted(expected_quarantine)} "
            f"actual={sorted(actual_quarantine)}"
        )
    if expected_buckets != actual_buckets:
        fail("bucket map readback mismatch")
