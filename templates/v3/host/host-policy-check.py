#!/usr/bin/env python3
import ipaddress
import json
import pathlib
import subprocess
import sys


def fail(message):
    raise SystemExit(message)


def read_env(path):
    values = {}
    for raw in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def command_json(*args):
    result = subprocess.run(args, check=True, stdout=subprocess.PIPE, text=True, timeout=10)
    return json.loads(result.stdout)


def network(rule, key):
    raw = rule.get(key, "all")
    length = int(rule.get(key + "len", 0 if raw == "all" else 32))
    address = "0.0.0.0" if raw == "all" else raw
    return ipaddress.ip_network(f"{address}/{length}", strict=False)


if len(sys.argv) != 2:
    fail("usage: host-policy-check.py MULTI_ENV")
env = read_env(sys.argv[1])
rules = command_json("ip", "-j", "-4", "rule", "show")


def one(priority):
    matches = [item for item in rules if int(item.get("priority", -1)) == priority]
    if len(matches) != 1:
        fail(f"priority {priority} occurs {len(matches)} times")
    rule = matches[0]
    if str(rule.get("protocol")) not in {"99", "openr"}:
        fail(f"priority {priority} is not protocol 99")
    return rule


def exact_keys(priority, rule, allowed):
    extra = set(rule) - set(allowed)
    if extra:
        fail(f"priority {priority} has unexpected selectors: {sorted(extra)}")


def marked(priority, mark, *, table=None):
    rule = one(priority)
    exact_keys(
        priority,
        rule,
        {"priority", "src", "fwmark", "fwmask", "protocol", "table", "action"},
    )
    if network(rule, "src") != ipaddress.ip_network("0.0.0.0/0") or network(rule, "dst") != ipaddress.ip_network("0.0.0.0/0"):
        fail(f"priority {priority} has source/destination selectors")
    if int(str(rule.get("fwmark", "-1")), 0) != mark:
        fail(f"priority {priority} has wrong fwmark")
    if "fwmask" in rule and int(str(rule["fwmask"]), 0) != 0xFFFFFFFF:
        fail(f"priority {priority} has non-exact fwmask")
    if table is None:
        if str(rule.get("action")) not in {"7", "unreachable"} or "table" in rule:
            fail(f"priority {priority} is not terminal unreachable")
    elif str(rule.get("table")) != str(table) or "action" in rule:
        fail(f"priority {priority} has wrong table/action")


marked(20500, 0x201, table=int(env["HOST_MAIN_TABLE"]))
marked(20501, 0x201)
marked(20502, 0x202, table=int(env["HOST_PGDL_TABLE"]))
marked(20503, 0x202)
marked(20504, 0x203, table=int(env["HOST_AE_TABLE"]))
marked(20505, 0x203)
marked(20506, 0x2FF)

terminal = one(20507)
exact_keys(20507, terminal, {"priority", "src", "srclen", "iif", "action", "protocol"})
if terminal.get("iif") != env["INGRESS_TRANSIT_BRIDGE"] or network(terminal, "src") != ipaddress.ip_network(env["INGRESS_TRANSIT_IP"] + "/32"):
    fail("priority 20507 has wrong ingress selector")
if str(terminal.get("action")) not in {"7", "unreachable"} or "table" in terminal:
    fail("priority 20507 is not terminal unreachable")

routes = [
    (int(env["HOST_MAIN_TABLE"]), "172.30.250.11", env["INGRESS_TRANSIT_BRIDGE"]),
    (int(env["HOST_PGDL_TABLE"]), env["PGDL_CONTAINER_IP"], env["PGDL_BRIDGE"]),
    (int(env["HOST_AE_TABLE"]), env["AE_CONTAINER_IP"], env["AE_BRIDGE"]),
]
for table, gateway, device in routes:
    items = command_json("ip", "-j", "-4", "route", "show", "table", str(table))
    expected = [item for item in items if item.get("dst") == "default"]
    if len(items) != 1 or len(expected) != 1:
        fail(f"table {table} must contain exactly one default route")
    route = expected[0]
    extra = set(route) - {"dst", "gateway", "dev", "flags"}
    if extra:
        fail(f"table {table} has unexpected route attributes: {sorted(extra)}")
    if route.get("gateway") != gateway or route.get("dev") != device or "onlink" not in route.get("flags", []):
        fail(f"table {table} has wrong next hop")
