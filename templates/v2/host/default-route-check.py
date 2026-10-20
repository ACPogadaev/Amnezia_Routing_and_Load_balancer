#!/usr/bin/env python3
import json
import sys


def fail(message):
    raise SystemExit(message)


if len(sys.argv) != 4:
    fail("usage: default-route-check.py GATEWAY INTERFACE SOURCE")

gateway, interface, source = sys.argv[1:]
try:
    routes = json.load(sys.stdin)
except (ValueError, TypeError) as error:
    fail(f"invalid iproute JSON: {error}")

if not isinstance(routes, list) or len(routes) != 1:
    fail("policy table must contain exactly one route")

route = routes[0]
if route.get("dst") != "default":
    fail(f"unexpected route destination: {route.get('dst')}")
if route.get("gateway") != gateway:
    fail(f"unexpected gateway: {route.get('gateway')}")
if route.get("dev") != interface:
    fail(f"unexpected interface: {route.get('dev')}")
if route.get("prefsrc") != source:
    fail(f"unexpected preferred source: {route.get('prefsrc')}")
