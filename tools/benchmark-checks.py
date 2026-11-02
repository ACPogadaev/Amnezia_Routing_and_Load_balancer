#!/usr/bin/env python3
"""Synthetic CIDR validator benchmark; never accesses Docker or networking."""
import argparse
import ipaddress
import json
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "templates/v2/host"))
from runtime_checks import TargetVerifier


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--networks", type=int, default=4103)
    parser.add_argument("--iterations", type=int, default=10)
    args = parser.parse_args()
    if not 1 <= args.networks <= 100000 or not 1 <= args.iterations <= 100:
        parser.error("networks must be 1..100000; iterations 1..100")
    scratch = ROOT / "work"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch) as directory:
        path = Path(directory) / "targets.txt"
        addresses = [str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("94.0.0.1")) + 512 * index)) for index in range(args.networks)]
        path.write_text("".join(address + "/32\n" for address in addresses), encoding="utf-8")
        document = {"nftables": [{"set": {"family": "inet", "table": "benchmark", "name": "target_v4", "type": "ipv4_addr", "flags": ["interval"], "elem": addresses}}]}
        payload = json.dumps(document)
        verifier = TargetVerifier()
        timings = {"legacy_cli_ms": [], "batched_warm_ms": []}
        start = time.perf_counter()
        verifier.verify(json.loads(payload), path, "benchmark")
        cold_ms = (time.perf_counter() - start) * 1000
        for _ in range(args.iterations):
            start = time.perf_counter()
            subprocess.run([sys.executable, str(ROOT / "templates/v2/host/active-targets-verify.py"), str(path), "benchmark", "target_v4"],
                           input=payload, text=True, capture_output=True, check=True)
            timings["legacy_cli_ms"].append((time.perf_counter() - start) * 1000)
            start = time.perf_counter()
            verifier.verify(json.loads(payload), path, "benchmark")
            timings["batched_warm_ms"].append((time.perf_counter() - start) * 1000)
        print(json.dumps({"networks": args.networks, "iterations": args.iterations,
                          "scope": "synthetic CIDR validation only; includes legacy interpreter startup; excludes kernel collection and VPN traffic",
                          "batched_cold_ms": round(cold_ms, 3),
                          **{key: round(statistics.median(values), 3) for key, values in timings.items()}}, indent=2))


if __name__ == "__main__":
    main()
