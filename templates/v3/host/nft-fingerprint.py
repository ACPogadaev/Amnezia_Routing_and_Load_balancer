#!/usr/bin/env python3
import hashlib
import json
import subprocess
import sys


def scrub(value):
    if isinstance(value, dict):
        ignored = {"handle", "index", "packets", "bytes", "last", "expires"}
        return {
            key: scrub(item)
            for key, item in sorted(value.items())
            if key not in ignored
        }
    if isinstance(value, list):
        return [scrub(item) for item in value]
    return value


if len(sys.argv) != 2:
    raise SystemExit("usage: nft-fingerprint.py TABLE")

result = subprocess.run(
    ["nft", "-j", "list", "table", "inet", sys.argv[1]],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
    timeout=10,
)
document = json.loads(result.stdout)
objects = [item for item in document["nftables"] if "metainfo" not in item]
payload = json.dumps(scrub(objects), sort_keys=True, separators=(",", ":"))
sys.stdout.write(hashlib.sha256(payload.encode("utf-8")).hexdigest() + "\n")
