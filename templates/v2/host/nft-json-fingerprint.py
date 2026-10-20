#!/usr/bin/env python3
import hashlib
import json
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


document = json.load(sys.stdin)
objects = [item for item in document["nftables"] if "metainfo" not in item]
payload = json.dumps(scrub(objects), sort_keys=True, separators=(",", ":"))
print(hashlib.sha256(payload.encode("utf-8")).hexdigest())
