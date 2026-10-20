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
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


if len(sys.argv) != 2:
    fail("usage: rpdb-check.py PILOT_ENV")

env = read_env(sys.argv[1])
try:
    rules = json.load(sys.stdin)
except (ValueError, TypeError) as error:
    fail(f"invalid ip rule JSON: {error}")


def number(name):
    return int(env[name], 0)


def network_selector(rule, key):
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


def one(priority):
    matches = [rule for rule in rules if int(rule.get("priority", -1)) == priority]
    if len(matches) != 1:
        fail(f"priority {priority} occurs {len(matches)} times")
    rule = matches[0]
    if str(rule.get("protocol")) != "99":
        fail(f"priority {priority} is not owned by protocol 99")
    if network_selector(rule, "src") != ipaddress.ip_network("0.0.0.0/0") or \
       network_selector(rule, "dst") != ipaddress.ip_network("0.0.0.0/0"):
        fail(f"priority {priority} has an unexpected source/destination selector")
    return rule


BASE_FIELDS = {"priority", "protocol", "src", "dst", "srclen", "dstlen"}


def no_extra_fields(rule, allowed):
    extras = set(rule).difference(BASE_FIELDS | allowed)
    if extras:
        fail(f"priority {rule['priority']} has unexpected fields: {sorted(extras)}")


def lookup(priority_name, table_name, iif, *, outer=False, marked=False):
    rule = one(number(priority_name))
    if str(rule.get("table")) != str(number(table_name)) or "action" in rule:
        fail(f"priority {rule['priority']} has the wrong lookup/action")
    allowed = selectors(rule, iif, outer=outer, marked=marked)
    no_extra_fields(rule, allowed | {"table"})


def unreachable(priority_name, iif, *, outer=False, marked=False):
    rule = one(number(priority_name))
    if str(rule.get("action")) not in {"7", "unreachable"} or "table" in rule:
        fail(f"priority {rule['priority']} is not terminal unreachable")
    allowed = selectors(rule, iif, outer=outer, marked=marked)
    no_extra_fields(rule, allowed | {"action"})


def selectors(rule, iif, *, outer, marked):
    if rule.get("iif") != iif:
        fail(f"priority {rule['priority']} has the wrong iif")
    allowed = {"iif"}
    if outer:
        allowed.update({"ipproto", "sport", "sport_mask"})
        if str(rule.get("ipproto")) not in {"17", "udp", "ipproto-17"}:
            fail(f"priority {rule['priority']} is not UDP")
        if int(rule.get("sport", -1)) != number("INGRESS_AWG_PORT"):
            fail(f"priority {rule['priority']} has the wrong source port")
        mask = rule.get("sport_mask")
        if mask is not None and str(mask) not in {"65535", "0xffff"}:
            fail(f"priority {rule['priority']} has a non-exact source port")
    if marked:
        allowed.update({"fwmark", "fwmask"})
        if int(str(rule.get("fwmark", "-1")), 0) != number("TARGET_MARK"):
            fail(f"priority {rule['priority']} has the wrong fwmark")
        mask = rule.get("fwmask")
        if mask is not None and int(str(mask), 0) != number("TARGET_MARK_MASK"):
            fail(f"priority {rule['priority']} has the wrong fwmask")
    return allowed


lookup("OUTER_LOOKUP_PRIORITY", "OUTER_ROUTE_TABLE", "lo", outer=True)
unreachable("OUTER_UNREACHABLE_PRIORITY", "lo", outer=True)
lookup(
    "TARGET_LOOKUP_PRIORITY", "TARGET_ROUTE_TABLE", env["INGRESS_AWG_IF"],
    marked=True,
)
unreachable(
    "TARGET_UNREACHABLE_PRIORITY", env["INGRESS_AWG_IF"], marked=True,
)
lookup("DIRECT_LOOKUP_PRIORITY", "DIRECT_ROUTE_TABLE", env["INGRESS_AWG_IF"])
unreachable("DIRECT_UNREACHABLE_PRIORITY", env["INGRESS_AWG_IF"])
