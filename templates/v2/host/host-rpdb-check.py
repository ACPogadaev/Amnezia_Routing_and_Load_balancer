#!/usr/bin/env python3
import ipaddress
import json
import pathlib
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


def selector_network(rule, key):
    length_key = key + "len"
    raw = rule.get(key, "all")
    if raw == "all":
        address = "0.0.0.0"
        embedded_length = 0
    else:
        try:
            parsed = ipaddress.ip_network(str(raw), strict=False)
        except ValueError as error:
            fail(f"priority {rule.get('priority')} has invalid {key}: {error}")
        address = str(parsed.network_address)
        embedded_length = parsed.prefixlen
    if length_key in rule:
        try:
            explicit_length = int(rule[length_key])
        except (TypeError, ValueError):
            fail(f"priority {rule.get('priority')} has invalid {length_key}")
        if "/" in str(raw) and explicit_length != embedded_length:
            fail(f"priority {rule.get('priority')} has inconsistent {key}/{length_key}")
        length = explicit_length
    else:
        length = embedded_length
    try:
        return ipaddress.ip_network(f"{address}/{length}", strict=False)
    except ValueError as error:
        fail(f"priority {rule.get('priority')} has invalid {key} length: {error}")


if len(sys.argv) != 2:
    fail("usage: host-rpdb-check.py PILOT_ENV")

env = read_env(sys.argv[1])
try:
    rules = json.load(sys.stdin)
except (ValueError, TypeError) as error:
    fail(f"invalid ip rule JSON: {error}")


def checked(priority_name, *, terminal):
    priority = int(env[priority_name], 0)
    matches = [item for item in rules if int(item.get("priority", -1)) == priority]
    if len(matches) != 1:
        fail(f"priority {priority} occurs {len(matches)} times")
    rule = matches[0]
    if str(rule.get("protocol")) != "99":
        fail(f"priority {priority} is not owned by protocol 99")
    if rule.get("iif") != env["TRANSIT_BRIDGE"]:
        fail(f"priority {priority} has the wrong iif")
    if selector_network(rule, "src") != ipaddress.ip_network(env["INGRESS_TRANSIT_IP"] + "/32"):
        fail(f"priority {priority} has the wrong source")
    if selector_network(rule, "dst") != ipaddress.ip_network("0.0.0.0/0"):
        fail(f"priority {priority} has the wrong destination")
    if terminal:
        if str(rule.get("action")) not in {"7", "unreachable"} or "table" in rule:
            fail(f"priority {priority} is not terminal unreachable")
    elif str(rule.get("table")) != str(int(env["HOST_TRANSIT_ROUTE_TABLE"], 0)) or "action" in rule:
        fail(f"priority {priority} has the wrong lookup/action")
    allowed = {
        "priority", "protocol", "src", "dst", "srclen", "dstlen", "iif",
        "action" if terminal else "table",
    }
    extras = set(rule).difference(allowed)
    if extras:
        fail(f"priority {priority} has unexpected fields: {sorted(extras)}")


checked("HOST_TRANSIT_LOOKUP_PRIORITY", terminal=False)
checked("HOST_TRANSIT_UNREACHABLE_PRIORITY", terminal=True)
