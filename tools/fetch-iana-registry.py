#!/usr/bin/env python3
"""Download the current official IANA IPv4 special-purpose registry."""

from __future__ import annotations

import argparse
import pathlib
import tempfile
import urllib.request


URL = "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=pathlib.Path("data/iana-ipv4-special-registry.csv"),
    )
    args = parser.parse_args()
    target = args.output.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(URL, headers={"User-Agent": "amnezia-route-balancer/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read()
    if b"Address Block" not in payload or b"Globally Reachable" not in payload:
        raise SystemExit("downloaded IANA document does not look like the expected CSV")
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as stream:
        stream.write(payload)
        temporary = pathlib.Path(stream.name)
    temporary.replace(target)
    print(target)


if __name__ == "__main__":
    main()
