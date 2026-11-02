#!/usr/bin/env python3
"""Stage a CPU-only upgrade over a private three-egress runtime backup.

This tool never writes /etc, changes services, follows profile mounts or calls Docker.
Compose JSON inputs must come from `docker compose config --format json`.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
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
MANIFEST = "installed-manifest.sha256"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_env(path):
    return dict(line.split("=", 1) for raw in Path(path).read_text(encoding="utf-8").splitlines()
                if (line := raw.strip()) and not line.startswith("#") and "=" in line)


def sha256_value(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value), "invalid SHA256 value")
    return value.lower()


def canonical_relative(value):
    require(isinstance(value, str) and value, "missing baseline relative path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.parts and ".." not in path.parts
            and path.as_posix() == value and "\\" not in value and "\x00" not in value,
            "invalid baseline relative path")
    require(value != MANIFEST, "baseline manifest cannot list itself")
    return value


def copied_path(relative):
    # Match copytree's exclusions, including directories with these names.
    return all(part != "__pycache__" and not part.endswith((".pyc", ".pyo"))
               for part in PurePosixPath(relative).parts)


def regular_files(directory):
    require(directory.is_dir() and not directory.is_symlink()
            and not getattr(directory, "is_junction", lambda: False)(), "baseline root must be a regular directory")
    root = directory.resolve()
    files = {}
    for path in directory.rglob("*"):
        require(not path.is_symlink() and not getattr(path, "is_junction", lambda: False)(), "baseline symlinks/junctions are not supported")
        require(path.resolve().is_relative_to(root), "baseline path escapes its root")
        require(path.is_dir() or path.is_file(), "baseline contains a non-regular file")
        if path.is_file():
            files[path.relative_to(directory).as_posix()] = path
    return files


def read_baseline_manifest(directory, version):
    files = regular_files(directory)
    require(MANIFEST in files, f"missing {version} baseline {MANIFEST}")
    content = files[MANIFEST].read_bytes()
    entries, resolved = {}, set()
    for number, line in enumerate(content.decode("utf-8").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-fA-F]{64}) ([ *])(.+)", line)
        require(match is not None, f"invalid {version} baseline manifest line {number}")
        sha, _, absolute = match.groups()
        prefix = LIVE[version] + "/"
        require(absolute.startswith(prefix), f"{version} baseline manifest path is outside {LIVE[version]}")
        relative = canonical_relative(absolute[len(prefix):])
        require(relative not in entries, f"duplicate {version} baseline manifest path: {relative}")
        target = directory / relative
        require(target.resolve().is_relative_to(directory.resolve()), "baseline manifest path escapes its root")
        require(target.is_file() and not target.is_symlink(), f"missing/non-regular {version} baseline file: {relative}")
        require(target.resolve() not in resolved, f"duplicate resolved {version} baseline manifest path: {relative}")
        resolved.add(target.resolve())
        entries[relative] = sha256_value(sha)
    require(entries, f"empty {version} baseline manifest")
    unlisted = {name for name in files if name != MANIFEST and copied_path(name)} - entries.keys()
    require(not unlisted, f"unlisted {version} baseline files: {', '.join(sorted(unlisted))}")
    return {"directory": directory, "entries": entries, "manifest_sha256": hashlib.sha256(content).hexdigest()}


def read_baseline_review(path, manifests):
    if path is None:
        return {}, None
    content = Path(path).read_bytes()
    document = json.loads(content)
    fields = {"schema", "reviewed_by", "reviewed_at", "reference", "baseline_manifests", "changes"}
    require(isinstance(document, dict) and set(document) == fields
            and type(document["schema"]) is int and document["schema"] == 1,
            "invalid baseline review schema")
    for field in ("reviewed_by", "reviewed_at", "reference"):
        require(isinstance(document[field], str) and document[field].strip(), f"baseline review requires {field}")
    stamp = datetime.fromisoformat(document["reviewed_at"].replace("Z", "+00:00"))
    require(stamp.utcoffset() is not None, "baseline review timestamp requires a timezone")
    require(isinstance(document["baseline_manifests"], dict) and set(document["baseline_manifests"]) == set(LIVE),
            "baseline review must bind both manifests")
    for version, manifest in manifests.items():
        require(sha256_value(document["baseline_manifests"][version]) == manifest["manifest_sha256"],
                f"baseline review is bound to a different {version} manifest")
    require(isinstance(document["changes"], list) and document["changes"], "baseline review has no reviewed changes")
    changes = {}
    for item in document["changes"]:
        require(isinstance(item, dict) and set(item) == {"baseline", "path", "expected_sha256", "reviewed_sha256", "reason"},
                "invalid baseline review entry")
        version = item["baseline"]
        require(isinstance(version, str) and version in LIVE, "baseline review references an unknown baseline")
        relative = canonical_relative(item["path"])
        key = (version, relative)
        require(key not in changes, f"duplicate baseline review entry: {version}/{relative}")
        require(relative in manifests[version]["entries"], "baseline review may only change manifest-listed files")
        expected, reviewed = sha256_value(item["expected_sha256"]), sha256_value(item["reviewed_sha256"])
        require(expected == manifests[version]["entries"][relative], "baseline review expected hash differs from manifest")
        require(expected != reviewed, "baseline review entry has no hash change")
        require(isinstance(item["reason"], str) and item["reason"].strip(), "baseline review requires a reason")
        changes[key] = {**item, "expected_sha256": expected, "reviewed_sha256": reviewed}
    return changes, {"sha256": hashlib.sha256(content).hexdigest(), **document}


def verify_baseline_manifest(manifest, version, changes):
    approved, used = {}, set()
    for relative, expected in manifest["entries"].items():
        actual = digest(manifest["directory"] / relative)
        change = changes.get((version, relative))
        if actual != expected:
            require(change is not None and actual == change["reviewed_sha256"],
                    f"{version} baseline checksum mismatch: {relative}; a separately reviewed record is required")
            used.add((version, relative))
        if copied_path(relative):
            approved[relative] = actual
    require(used == {key for key in changes if key[0] == version}, f"unused/stale {version} baseline review entries")
    approved[MANIFEST] = manifest["manifest_sha256"]
    return approved


def verify_baseline_copy(directory, approved):
    files = regular_files(directory)
    require(set(files) == set(approved), "baseline inventory changed while copying")
    for relative, expected in approved.items():
        require(digest(files[relative]) == expected, f"baseline changed while copying: {relative}")


def validate_release(release):
    entries = {}
    content = (release / "SHA256SUMS").read_bytes()
    for line in content.decode("utf-8").splitlines():
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
    return entries, hashlib.sha256(content).hexdigest()


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
        if path.is_file() and path != directory / MANIFEST:
            entries.append(f"{digest(path)}  {live}/{path.relative_to(directory).as_posix()}\n")
    manifest = directory / "installed-manifest.sha256"
    manifest.write_text("".join(entries), encoding="utf-8", newline="\n")
    manifest.chmod(0o600)


def prepare(release, baseline_v2, baseline_v3, compose_v2, compose_v3, output, *, baseline_review=None):
    release, baseline_v2, baseline_v3, output = map(Path, (release, baseline_v2, baseline_v3, output))
    require(not output.exists(), "output already exists; select a new staging directory")
    for source in (release, baseline_v2, baseline_v3):
        require(not output.resolve().is_relative_to(source.resolve()) and not source.resolve().is_relative_to(output.resolve()),
                "staging output must be separate from its inputs")
    release_entries, release_manifest_sha = validate_release(release)
    manifests = {version: read_baseline_manifest(baseline, version)
                 for version, baseline in (("v2", baseline_v2), ("v3", baseline_v3))}
    changes, review = read_baseline_review(baseline_review, manifests)
    approved = {version: verify_baseline_manifest(manifest, version, changes) for version, manifest in manifests.items()}
    pilot, multi, inventory, count = validate_baseline(baseline_v2, baseline_v3)
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
        verify_baseline_copy(target, approved[version])
    # Both original manifests and both copied snapshots have passed before any
    # replacement or new installed manifest is written.
    for version in ("v2", "v3"):
        target = output / version
        for relative in PAYLOAD[version]:
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(release / version / relative, destination)
            require(digest(destination) == release_entries[f"{version}/{relative}"], f"release changed while copying: {version}/{relative}")
            destination.chmod(0o755 if destination.suffix in {".py", ".sh"} else 0o644)
        (target / "egress/compose.yaml").write_text(json.dumps(compose[version], indent=2) + "\n", encoding="utf-8", newline="\n")
    for version in ("v2", "v3"):
        make_manifest(output / version, LIVE[version])
    (output / "units").mkdir()
    shutil.copy2(output / "v2/systemd" / UNIT, output / "units" / UNIT)
    (output / "unit-manifest.sha256").write_text(f"{digest(output / 'units' / UNIT)}  /etc/systemd/system/{UNIT}\n", encoding="utf-8")
    report = {"schema": 1, "egresses": ["main", "pgdl", "ae"], "target_networks": count,
              "target_list_sha256": digest(output / "v2/active-target-v4.txt"),
              "release_manifest_sha256": release_manifest_sha,
              "baseline_manifests": {version: {"sha256": manifest["manifest_sha256"], "verified_entries": len(manifest["entries"])}
                                     for version, manifest in manifests.items()},
              "baseline_review": review,
              "payload": PAYLOAD, "note": "private staged runtime; no services changed; /opt secret profile directories are outside the payload"}
    (output / "upgrade-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("release", "baseline-v2", "baseline-v3", "compose-v2", "compose-v3", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--baseline-review", type=Path, help="separately reviewed, hash-bound exceptions for local changes")
    args = parser.parse_args()
    try:
        report = prepare(args.release, args.baseline_v2, args.baseline_v3, args.compose_v2, args.compose_v3, args.output,
                         baseline_review=args.baseline_review)
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, f"upgrade staging: {error}\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
