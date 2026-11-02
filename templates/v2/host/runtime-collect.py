#!/usr/bin/env python3
"""Collect a bounded read-only snapshot after one namespace entry."""
import json
import subprocess
import sys


def collect(specs):
    if not isinstance(specs, dict) or not 1 <= len(specs) <= 16:
        raise ValueError("invalid collection request")
    result = {}
    for key, args in specs.items():
        if not isinstance(args, list) or not args or args[0] not in {"ip", "iptables-save", "ip6tables-save", "nft", "sysctl"}:
            raise ValueError("unsupported read-only collector")
        result[key] = subprocess.run(args, check=True, capture_output=True, text=True, timeout=5).stdout
    return result


if __name__ == "__main__":
    json.dump(collect(json.load(sys.stdin)), sys.stdout)
