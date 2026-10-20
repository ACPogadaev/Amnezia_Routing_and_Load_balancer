#!/usr/bin/env python3
"""Verify one nftables interval set against the normalized active list."""

import ipaddress
import json
import pathlib
import sys


def fail(message):
    raise SystemExit(message)


def networks_from_value(value):
    if isinstance(value, str):
        yield ipaddress.ip_network(value if "/" in value else value + "/32", strict=False)
        return
    if not isinstance(value, dict):
        fail(f"unsupported nft element: {value!r}")
    if "prefix" in value:
        prefix = value["prefix"]
        yield ipaddress.ip_network(
            f"{prefix.get('addr')}/{prefix.get('len')}", strict=False
        )
        return
    if "range" in value:
        first, last = value["range"]
        if isinstance(first, dict):
            first = first.get("addr", first.get("val"))
        if isinstance(last, dict):
            last = last.get("addr", last.get("val"))
        yield from ipaddress.summarize_address_range(
            ipaddress.ip_address(first), ipaddress.ip_address(last)
        )
        return
    if "elem" in value:
        nested = value["elem"]
        if isinstance(nested, dict) and "val" in nested:
            nested = nested["val"]
        yield from networks_from_value(nested)
        return
    fail(f"unsupported nft element object: {value!r}")


if len(sys.argv) != 4:
    fail("usage: active-targets-verify.py TARGET-V4.TXT TABLE SET")

expected_path = pathlib.Path(sys.argv[1])
table, set_name = sys.argv[2:]
expected = list(
    ipaddress.collapse_addresses(
        ipaddress.ip_network(line.strip(), strict=True)
        for line in expected_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    )
)

try:
    document = json.load(sys.stdin)
except (ValueError, TypeError) as error:
    fail(f"invalid nft JSON: {error}")

matching = []
for entry in document.get("nftables", []):
    item = entry.get("set")
    if item and item.get("family") == "inet" and \
       item.get("table") == table and item.get("name") == set_name:
        matching.append(item)
if len(matching) != 1:
    fail(f"expected one inet {table}/{set_name}, found {len(matching)}")
item = matching[0]
if item.get("type") != "ipv4_addr" or "interval" not in item.get("flags", []):
    fail("target set has the wrong type or flags")

actual = []
for value in item.get("elem", []):
    actual.extend(networks_from_value(value))
actual = list(ipaddress.collapse_addresses(actual))
if actual != expected:
    fail(
        f"target set differs: expected {len(expected)} prefixes, "
        f"got {len(actual)} semantic prefixes"
    )
print(f"Verified {len(expected)} prefixes in inet {table}/{set_name}.")
