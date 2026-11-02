#!/usr/bin/env python3
"""Stage a CPU-only upgrade over a private three-egress runtime backup.

This tool never writes /etc, changes services, follows profile mounts or calls Docker.
Compose JSON inputs must come from `docker compose config --format json`.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path, PurePosixPath
import shutil


PAYLOAD = {
    "v2": ["host/runtime_checks.py", "host/runtime-collect.py", "host/ingress-router.py",
           "host/ingress-router-loop.sh", "host/ingress-check.sh", "host/ingress-targets-check.sh",
           "host/guard-check.sh", "host/docker-user-check.sh", "host/default-route-check.py",
           "host/rpdb-check.py", "egress/egress-healthcheck.sh",
           "systemd/amnezia-lb-v2-ingress-router.service"],
    "v3": ["host/controller.py", "host/guard-check.sh", "host/docker-user-check.sh",
           "host/verify.sh", "host/verify-state.py", "egress/egress-healthcheck.sh"],
}
LIVE = {"v2": "/etc/amnezia-lb-v2", "v3": "/etc/amnezia-lb-multi-v3"}
UNIT = "amnezia-lb-v2-ingress-router.service"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_env(path):
    return dict(line.split("=", 1) for raw in Path(path).read_text(encoding="utf-8").splitlines()
                if (line := raw.strip()) and not line.startswith("#") and "=" in line)


def validate_release(release):
    entries = {}
    for line in (release / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        sha, relative = line.split("  ", 1)
        path = PurePosixPath(relative)
        require(not path.is_absolute() and ".." not in path.parts and "\\" not in relative, "invalid release manifest path")
        require(relative not in entries and len(sha) == 64 and all(char in "0123456789abcdef" for char in sha), "invalid release digest")
        target = release / relative
        require(target.resolve().is_relative_to(release.resolve()), "release path escapes its root")
        require(digest(target) == sha, f"release checksum mismatch: {relative}")
        entries[relative] = sha
    for version, paths in PAYLOAD.items():
        require(all(f"{version}/{path}" in entries for path in paths), f"release misses {version} upgrade payload")
    return entries


def validate_baseline(v2, v3):
    pilot, multi = read_env(v2 / "pilot.env"), read_env(v3 / "multi.env")
    inventory = json.loads((v3 / "egresses.json").read_text(encoding="utf-8"))
    require({item["name"] for item in inventory} == {"main", "pgdl", "ae"} and len(inventory) == 3,
            "a validated main+pgdl+ae baseline is required; this tool does not add the third egress")
    require(len({item["container"] for item in inventory}) == 3, "egress container names must be unique")
    require(len({str(ipaddress.IPv4Address(item["awg_ip"])) for item in inventory}) == 3, "egress AWG addresses must be unique")
    active_marks = {int(item["mark"]) for item in inventory}
    require(active_marks == {0x201, 0x202, 0x203}, "unexpected three-egress mark inventory")
    retired = {int(item.strip(), 0) for item in multi.get("RETIRED_MARKS", "").split(",") if item.strip()}
    require(not retired & active_marks, "an active egress mark is still retired")
    require(multi.get("RECOVERY_ENABLED") == "0" and multi.get("RECOVERY_ALLOW_CRASHLOOP_CONTAINMENT") == "0",
            "canary baseline requires recovery and containment disabled")
    require({name for name in multi.get("RECOVERY_ALLOWED_EGRESSES", "").split(",") if name} <= {"main", "pgdl", "ae"},
            "recovery allowlist contains an inactive name")
    require(int(pilot["HEALTH_INTERVAL_SECONDS"]) > 0 and pilot["HEALTH_INTERVAL_SECONDS"] == multi["HEALTH_INTERVAL_SECONDS"], "health intervals must match")
    endpoints = [(pilot["EGRESS_AWG_ENDPOINT_IP"], int(pilot["EGRESS_AWG_ENDPOINT_PORT"]))]
    endpoints += [(multi[prefix + "_ENDPOINT_IP"], int(multi[prefix + "_ENDPOINT_PORT"])) for prefix in ("PGDL", "AE")]
    require(len(set(endpoints)) == 3, "egress endpoint IP:port pairs must be unique")
    for address, port in endpoints:
        ipaddress.IPv4Address(address)
        require(1 <= port <= 65535, "invalid endpoint port")
    for item in inventory:
        ipaddress.IPv4Address(item["expected_exit_ip"])
    targets = v2 / "active-target-v4.txt"
    networks = [ipaddress.IPv4Network(line, strict=True) for line in targets.read_text().splitlines() if line.strip()]
    require(networks and len(networks) == int(pilot["ACTIVE_TARGETS_COUNT"]), "baseline target count mismatch")
    return pilot, multi, inventory, len(networks)


def compose_with_interval(path, inventory, interval):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    services = document["services"]
    require({item["compose_project"] for item in inventory} == {document.get("name")}, "compose project mismatch")
    require(set(services) == {item["compose_service"] for item in inventory}, "unexpected compose services; no service may be silently dropped")
    for item in inventory:
        service = services[item["compose_service"]]
        require(service["container_name"] == item["container"], "compose/inventory container mismatch")
        require(isinstance(service.get("environment"), dict), "expected resolved Compose environment")
        service["environment"]["HEALTH_INTERVAL_SECONDS"] = interval
    return document


def make_manifest(directory, live):
    entries = []
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.name != "installed-manifest.sha256":
            entries.append(f"{digest(path)}  {live}/{path.relative_to(directory).as_posix()}\n")
    manifest = directory / "installed-manifest.sha256"
    manifest.write_text("".join(entries), encoding="utf-8", newline="\n")
    manifest.chmod(0o600)


def prepare(release, baseline_v2, baseline_v3, compose_v2, compose_v3, output):
    release, baseline_v2, baseline_v3, output = map(Path, (release, baseline_v2, baseline_v3, output))
    require(not output.exists(), "output already exists; select a new staging directory")
    for source in (release, baseline_v2, baseline_v3):
        require(not output.resolve().is_relative_to(source.resolve()) and not source.resolve().is_relative_to(output.resolve()),
                "staging output must be separate from its inputs")
    validate_release(release)
    pilot, multi, inventory, count = validate_baseline(baseline_v2, baseline_v3)
    for baseline in (baseline_v2, baseline_v3):
        require(not baseline.is_symlink() and not any(path.is_symlink() for path in baseline.rglob("*")), "review and dereference baseline symlinks before staging")
    compose = {
        "v2": compose_with_interval(compose_v2, [item for item in inventory if item["name"] == "main"], pilot["HEALTH_INTERVAL_SECONDS"]),
        "v3": compose_with_interval(compose_v3, [item for item in inventory if item["name"] != "main"], multi["HEALTH_INTERVAL_SECONDS"]),
    }
    output.mkdir(mode=0o700, parents=True)
    # Preserve the complete local runtime first. Only the reviewed CPU payload
    # is replaced: no new subnets, guards, loader hashes, endpoints or AWG keys.
    for version, baseline in (("v2", baseline_v2), ("v3", baseline_v3)):
        target = output / version
        shutil.copytree(baseline, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"))
        for relative in PAYLOAD[version]:
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(release / version / relative, destination)
            destination.chmod(0o755 if destination.suffix in {".py", ".sh"} else 0o644)
        (target / "egress/compose.yaml").write_text(json.dumps(compose[version], indent=2) + "\n", encoding="utf-8", newline="\n")
        make_manifest(target, LIVE[version])
    (output / "units").mkdir()
    shutil.copy2(output / "v2/systemd" / UNIT, output / "units" / UNIT)
    (output / "unit-manifest.sha256").write_text(f"{digest(output / 'units' / UNIT)}  /etc/systemd/system/{UNIT}\n", encoding="utf-8")
    report = {"schema": 1, "egresses": ["main", "pgdl", "ae"], "target_networks": count,
              "target_list_sha256": digest(baseline_v2 / "active-target-v4.txt"),
              "release_manifest_sha256": digest(release / "SHA256SUMS"),
              "payload": PAYLOAD, "note": "private staged runtime; no services changed; /opt secret profile directories are outside the payload"}
    (output / "upgrade-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("release", "baseline-v2", "baseline-v3", "compose-v2", "compose-v3", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    try:
        report = prepare(args.release, args.baseline_v2, args.baseline_v3, args.compose_v2, args.compose_v3, args.output)
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, f"upgrade staging: {error}\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
