#!/usr/bin/env python3
"""Build a deployable release without storing secrets or route data in Git."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import pathlib
import re
import shutil
import stat
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOKEN = re.compile(r"@@([A-Z0-9_]+)@@")
REQUIRED = {
    "BALANCER_PUBLIC_IP",
    "PUBLIC_IF",
    "INGRESS_CONTAINER",
    "INGRESS_AWG_IF",
    "INGRESS_CLIENT_SUBNET",
    "VERIFY_CLIENT_IP",
    "INGRESS_AWG_PORT",
    "INGRESS_OUTER_NETWORK",
    "INGRESS_OUTER_BRIDGE",
    "INGRESS_OUTER_IP",
    "INGRESS_OUTER_GATEWAY",
    "INGRESS_DNS_NETWORK",
    "INGRESS_DNS_BRIDGE",
    "INGRESS_DNS_IP",
    "INGRESS_DNS_GATEWAY",
    "INGRESS_AUX_NETWORK",
    "INGRESS_AUX_BRIDGE",
    "INGRESS_AUX_IP",
    "HEALTH_TARGET_IP",
    "HEALTH_TARGET_TCP_PORT",
    "ACTIVE_TEST_IP",
    "MAIN_AWG_IP",
    "MAIN_ENDPOINT_IP",
    "MAIN_ENDPOINT_PORT",
    "MAIN_EXPECTED_EXIT_IP",
    "EGRESS2_AWG_IP",
    "EGRESS2_ENDPOINT_IP",
    "EGRESS2_ENDPOINT_PORT",
    "EGRESS2_EXPECTED_EXIT_IP",
    "EGRESS3_AWG_IP",
    "EGRESS3_ENDPOINT_IP",
    "EGRESS3_ENDPOINT_PORT",
    "EGRESS3_EXPECTED_EXIT_IP",
    "HEALTH_URL",
    "HEALTH_URL_SECONDARY",
    "HEALTH_INTERVAL_SECONDS",
    "HEALTH_TIMEOUT_SECONDS",
    "HEALTH_FAILURE_THRESHOLD",
    "HEALTH_SUCCESS_THRESHOLD",
    "HEALTH_MAX_HANDSHAKE_AGE_SECONDS",
    "LOAD_EWMA_ALPHA",
    "LOAD_REFERENCE_BPS",
    "LOAD_WEIGHT_FLOOR",
}


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def load_env(path: pathlib.Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail(f"{path}:{number}: expected KEY=value")
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            fail(f"{path}:{number}: invalid key {key!r}")
        if key in values:
            fail(f"{path}:{number}: duplicate key {key}")
        if (value.startswith("\"") and value.endswith("\"")) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        values[key] = value
    missing = sorted(REQUIRED.difference(values))
    if missing:
        fail(f"configuration is missing keys: {', '.join(missing)}")
    placeholders = sorted(key for key in REQUIRED if not values[key] or "CHANGE_ME" in values[key])
    if placeholders:
        fail(f"replace placeholder values first: {', '.join(placeholders)}")
    return values


def validate(values: dict[str, str], networks: list[ipaddress.IPv4Network]) -> None:
    ipv4_keys = {
        "BALANCER_PUBLIC_IP",
        "VERIFY_CLIENT_IP",
        "INGRESS_OUTER_IP",
        "INGRESS_OUTER_GATEWAY",
        "INGRESS_DNS_IP",
        "INGRESS_DNS_GATEWAY",
        "INGRESS_AUX_IP",
        "HEALTH_TARGET_IP",
        "ACTIVE_TEST_IP",
        "MAIN_AWG_IP",
        "MAIN_ENDPOINT_IP",
        "MAIN_EXPECTED_EXIT_IP",
        "EGRESS2_AWG_IP",
        "EGRESS2_ENDPOINT_IP",
        "EGRESS2_EXPECTED_EXIT_IP",
        "EGRESS3_AWG_IP",
        "EGRESS3_ENDPOINT_IP",
        "EGRESS3_EXPECTED_EXIT_IP",
    }
    parsed: dict[str, ipaddress.IPv4Address] = {}
    for key in ipv4_keys:
        try:
            parsed[key] = ipaddress.IPv4Address(values[key])
        except ipaddress.AddressValueError as error:
            fail(f"{key} is not an IPv4 address: {values[key]} ({error})")
    try:
        client_subnet = ipaddress.IPv4Network(values["INGRESS_CLIENT_SUBNET"], strict=True)
    except ValueError as error:
        fail(f"INGRESS_CLIENT_SUBNET is invalid: {error}")
    if parsed["VERIFY_CLIENT_IP"] not in client_subnet:
        fail("VERIFY_CLIENT_IP must belong to INGRESS_CLIENT_SUBNET")
    if not any(parsed["ACTIVE_TEST_IP"] in network for network in networks):
        fail("ACTIVE_TEST_IP must belong to the normalized route list")
    if any(parsed["HEALTH_TARGET_IP"] in network for network in networks):
        fail("HEALTH_TARGET_IP must remain outside the route list")
    if parsed["BALANCER_PUBLIC_IP"] in client_subnet:
        fail("BALANCER_PUBLIC_IP unexpectedly overlaps the client subnet")
    for key in (
        "INGRESS_AWG_PORT",
        "HEALTH_TARGET_TCP_PORT",
        "MAIN_ENDPOINT_PORT",
        "EGRESS2_ENDPOINT_PORT",
        "EGRESS3_ENDPOINT_PORT",
    ):
        try:
            port = int(values[key])
        except ValueError:
            fail(f"{key} must be an integer")
        if not 1 <= port <= 65535:
            fail(f"{key} must be between 1 and 65535")
    endpoint_pairs = {
        (parsed["MAIN_ENDPOINT_IP"], int(values["MAIN_ENDPOINT_PORT"])),
        (parsed["EGRESS2_ENDPOINT_IP"], int(values["EGRESS2_ENDPOINT_PORT"])),
        (parsed["EGRESS3_ENDPOINT_IP"], int(values["EGRESS3_ENDPOINT_PORT"])),
    }
    if len(endpoint_pairs) != 3:
        fail("the three egress endpoint IP:port pairs must be distinct")


def load_normalizer():
    path = ROOT / "tools" / "normalize-targets.py"
    spec = importlib.util.spec_from_file_location("amnezia_normalize_targets", path)
    if spec is None or spec.loader is None:
        fail(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def render_tree(source: pathlib.Path, destination: pathlib.Path, mapping: dict[str, str]) -> None:
    shutil.copytree(source, destination)
    for path in sorted(destination.rglob("*")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        text = TOKEN.sub(lambda match: mapping.get(match.group(1), match.group(0)), text)
        path.write_text(text, encoding="utf-8", newline="\n")
        if path.suffix == ".in":
            rendered = path.with_suffix("")
            path.replace(rendered)


def replace_token(path: pathlib.Path, token: str, value: str) -> None:
    text = path.read_text(encoding="utf-8")
    marker = f"@@{token}@@"
    if marker not in text:
        fail(f"internal build error: {marker} missing from {path}")
    path.write_text(text.replace(marker, value), encoding="utf-8", newline="\n")


def make_manifest(root: pathlib.Path) -> None:
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            entries.append(f"{sha256(path)}  {path.relative_to(root).as_posix()}\n")
    (root / "SHA256SUMS").write_text("".join(entries), encoding="utf-8", newline="\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=pathlib.Path)
    parser.add_argument("--routes", required=True, type=pathlib.Path)
    parser.add_argument("--iana-csv", required=True, type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "dist" / "release")
    args = parser.parse_args()

    output = args.output.resolve()
    if output.exists():
        fail(f"output already exists; remove it deliberately before rebuilding: {output}")
    values = load_env(args.config.resolve())
    normalizer = load_normalizer()
    registry = normalizer.load_registry(args.iana_csv.resolve())
    source_networks, input_stats = normalizer.load_input(args.routes.resolve())
    networks, excluded = normalizer.filter_networks(source_networks, registry)
    if not networks:
        fail("all route-list entries were excluded; refusing to build an empty release")
    validate(values, networks)

    mapping = dict(values)
    mapping["ACTIVE_TARGETS_COUNT"] = str(len(networks))
    mapping["TARGET_ELEMENTS"] = ",\n    ".join(str(network) for network in networks)
    mapping.update(
        {
            "V2_GUARD_CREATE_SHA": "@@V2_GUARD_CREATE_SHA@@",
            "V2_GUARD_REPLACE_SHA": "@@V2_GUARD_REPLACE_SHA@@",
            "V2_INGRESS_CREATE_SHA": "@@V2_INGRESS_CREATE_SHA@@",
            "V2_INGRESS_REPLACE_SHA": "@@V2_INGRESS_REPLACE_SHA@@",
            "V3_GUARD_CREATE_SHA": "@@V3_GUARD_CREATE_SHA@@",
            "V3_GUARD_REPLACE_SHA": "@@V3_GUARD_REPLACE_SHA@@",
        }
    )

    try:
        render_tree(ROOT / "templates" / "v2", output / "v2", mapping)
        render_tree(ROOT / "templates" / "v3", output / "v3", mapping)
        active = output / "v2" / "config" / "active-target-v4.txt"
        active.write_text("".join(f"{network}\n" for network in networks), encoding="utf-8")

        hashes = {
            "V2_GUARD_CREATE_SHA": sha256(output / "v2" / "host" / "guard.create.nft"),
            "V2_GUARD_REPLACE_SHA": sha256(output / "v2" / "host" / "guard.replace.nft"),
            "V2_INGRESS_CREATE_SHA": sha256(output / "v2" / "host" / "ingress-targets.create.nft"),
            "V2_INGRESS_REPLACE_SHA": sha256(output / "v2" / "host" / "ingress-targets.replace.nft"),
            "V3_GUARD_CREATE_SHA": sha256(output / "v3" / "host" / "guard.create.nft"),
            "V3_GUARD_REPLACE_SHA": sha256(output / "v3" / "host" / "guard.replace.nft"),
        }
        replace_token(output / "v2" / "host" / "guard-load.sh", "V2_GUARD_CREATE_SHA", hashes["V2_GUARD_CREATE_SHA"])
        replace_token(output / "v2" / "host" / "guard-load.sh", "V2_GUARD_REPLACE_SHA", hashes["V2_GUARD_REPLACE_SHA"])
        replace_token(output / "v2" / "host" / "ingress-targets-load.sh", "V2_INGRESS_CREATE_SHA", hashes["V2_INGRESS_CREATE_SHA"])
        replace_token(output / "v2" / "host" / "ingress-targets-load.sh", "V2_INGRESS_REPLACE_SHA", hashes["V2_INGRESS_REPLACE_SHA"])
        replace_token(output / "v3" / "host" / "guard-load.sh", "V3_GUARD_CREATE_SHA", hashes["V3_GUARD_CREATE_SHA"])
        replace_token(output / "v3" / "host" / "guard-load.sh", "V3_GUARD_REPLACE_SHA", hashes["V3_GUARD_REPLACE_SHA"])

        unresolved = []
        for path in output.rglob("*"):
            if path.is_file():
                try:
                    found = TOKEN.findall(path.read_text(encoding="utf-8"))
                except UnicodeDecodeError:
                    continue
                if found:
                    unresolved.append(f"{path.relative_to(output)}: {sorted(set(found))}")
        if unresolved:
            fail("unresolved template tokens:\n" + "\n".join(unresolved))

        report = {
            "schema": 1,
            "route_source_sha256": sha256(args.routes.resolve()),
            "iana_registry_sha256": sha256(args.iana_csv.resolve()),
            "input": input_stats,
            "output_networks": len(networks),
            "output_addresses": sum(network.num_addresses for network in networks),
            "excluded": dict(sorted(excluded.items())),
            "note": "AWG profiles are intentionally not included in this release.",
        }
        (output / "build-report.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        make_manifest(output)
        for path in output.rglob("*.sh"):
            path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except BaseException:
        if output.exists():
            shutil.rmtree(output)
        raise
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"release={output}")


if __name__ == "__main__":
    main()
