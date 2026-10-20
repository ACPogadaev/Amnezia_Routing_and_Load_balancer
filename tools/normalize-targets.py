#!/usr/bin/env python3
"""Normalize an IPv4 target list and remove non-global destinations.

The IANA registry contains overlapping assignments. Classification therefore
uses the most-specific matching registry prefix, not a flat subtraction of all
rows marked false. IPv4 multicast is excluded separately because it lives in a
different IANA registry.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import tempfile
from collections import Counter
from dataclasses import dataclass


TABLE = "amnezia_lb_targets_stage_v1"
SET = "target_v4"
MULTICAST = ipaddress.ip_network("224.0.0.0/4")
FOOTNOTE = re.compile(r"\s*\[[^]]+\]\s*$")


@dataclass(frozen=True)
class RegistryRecord:
    network: ipaddress.IPv4Network
    globally_reachable: bool
    name: str


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def clean_block(raw: str) -> str:
    return FOOTNOTE.sub("", raw.strip())


def parse_global(raw: str) -> bool:
    # Official CSV values can carry a bracketed footnote. Empty/N/A values in
    # the special-purpose registry are intentionally not treated as global.
    value = FOOTNOTE.sub("", (raw or "").strip()).lower()
    return value == "true"


def load_registry(path: pathlib.Path) -> list[RegistryRecord]:
    records: list[RegistryRecord] = []
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        required = {"Address Block", "Name", "Globally Reachable"}
        missing = required.difference(reader.fieldnames or [])
        if missing:
            raise SystemExit(f"registry CSV is missing columns: {sorted(missing)}")
        for row_number, row in enumerate(reader, 2):
            blocks = row["Address Block"] or ""
            for raw_block in blocks.split(","):
                block = clean_block(raw_block)
                if not block:
                    continue
                try:
                    network = ipaddress.ip_network(block, strict=True)
                except ValueError as error:
                    raise SystemExit(
                        f"invalid IANA block on CSV row {row_number}: {block}: {error}"
                    ) from error
                if network.version != 4:
                    raise SystemExit(f"non-IPv4 IANA block on CSV row {row_number}: {block}")
                records.append(
                    RegistryRecord(
                        network=network,
                        globally_reachable=parse_global(row["Globally Reachable"]),
                        name=(row["Name"] or "unnamed special-purpose range").strip(),
                    )
                )

    if not records:
        raise SystemExit("registry CSV contains no IPv4 records")

    seen: dict[ipaddress.IPv4Network, RegistryRecord] = {}
    for record in records:
        previous = seen.get(record.network)
        if previous and previous.globally_reachable != record.globally_reachable:
            raise SystemExit(f"conflicting IANA classification for {record.network}")
        seen[record.network] = record
    return sorted(seen.values(), key=lambda item: (item.network.prefixlen, int(item.network.network_address)))


def load_input(path: pathlib.Path) -> tuple[list[ipaddress.IPv4Network], dict[str, int]]:
    parsed: list[ipaddress.IPv4Network] = []
    stats = Counter()
    with path.open("r", encoding="utf-8-sig") as stream:
        for line_number, raw_line in enumerate(stream, 1):
            stats["physical_lines"] += 1
            token = raw_line.split("#", 1)[0].strip()
            if not token:
                stats["blank_or_comment_lines"] += 1
                continue
            if any(character.isspace() for character in token):
                raise SystemExit(f"line {line_number}: expected one CIDR, got {token!r}")
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError as error:
                raise SystemExit(f"line {line_number}: invalid CIDR {token!r}: {error}") from error
            if network.version != 4:
                raise SystemExit(f"line {line_number}: IPv6 is not accepted: {token}")
            if token != str(network):
                stats["canonicalized_entries"] += 1
            parsed.append(network)
            stats["parsed_entries"] += 1

    if not parsed:
        raise SystemExit("input contains no IPv4 CIDRs")
    stats["unique_entries"] = len(set(parsed))
    stats["duplicate_entries"] = len(parsed) - stats["unique_entries"]
    collapsed = list(ipaddress.collapse_addresses(parsed))
    stats["collapsed_input_entries"] = len(collapsed)
    stats["input_addresses"] = sum(network.num_addresses for network in collapsed)
    return collapsed, dict(stats)


def classification(
    address: ipaddress.IPv4Address,
    records: list[RegistryRecord],
) -> tuple[bool, str]:
    if address in MULTICAST:
        return False, f"IPv4 Multicast ({MULTICAST})"
    matches = [record for record in records if address in record.network]
    if not matches:
        return True, "ordinary globally reachable IPv4"
    most_specific = max(record.network.prefixlen for record in matches)
    winners = [record for record in matches if record.network.prefixlen == most_specific]
    states = {record.globally_reachable for record in winners}
    if len(states) != 1:
        raise SystemExit(f"ambiguous IANA classification at {address}")
    winner = winners[0]
    return winner.globally_reachable, f"{winner.name} ({winner.network})"


def filter_networks(
    networks: list[ipaddress.IPv4Network],
    records: list[RegistryRecord],
) -> tuple[list[ipaddress.IPv4Network], Counter[str]]:
    boundaries: set[int] = {int(MULTICAST.network_address), int(MULTICAST.broadcast_address) + 1}
    for record in records:
        boundaries.add(int(record.network.network_address))
        boundaries.add(int(record.network.broadcast_address) + 1)

    kept_ranges: list[tuple[int, int]] = []
    excluded: Counter[str] = Counter()
    sorted_boundaries = sorted(boundaries)
    for network in networks:
        first = int(network.network_address)
        after_last = int(network.broadcast_address) + 1
        points = [first]
        points.extend(point for point in sorted_boundaries if first < point < after_last)
        points.append(after_last)
        for left, right in zip(points, points[1:]):
            allowed, reason = classification(ipaddress.IPv4Address(left), records)
            if allowed:
                kept_ranges.append((left, right - 1))
            else:
                excluded[reason] += right - left

    kept: list[ipaddress.IPv4Network] = []
    for first, last in kept_ranges:
        kept.extend(
            ipaddress.summarize_address_range(
                ipaddress.IPv4Address(first), ipaddress.IPv4Address(last)
            )
        )
    return list(ipaddress.collapse_addresses(kept)), excluded


def nft_batch(networks: list[ipaddress.IPv4Network], *, replace: bool, metadata: str) -> str:
    operation = f"flush set inet {TABLE} {SET}\n" if replace else (
        f"add table inet {TABLE}\n"
        f"add set inet {TABLE} {SET} {{ type ipv4_addr; flags interval; }}\n"
    )
    elements = ",\n    ".join(str(network) for network in networks)
    return (
        f"# Generated target set; {metadata}\n"
        f"{operation}"
        f"add element inet {TABLE} {SET} {{\n    {elements}\n}}\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=pathlib.Path)
    parser.add_argument("--iana-csv", required=True, type=pathlib.Path)
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    arguments = parser.parse_args()

    source = arguments.input.resolve()
    registry = arguments.iana_csv.resolve()
    output = arguments.output_dir.resolve()
    records = load_registry(registry)
    input_networks, input_stats = load_input(source)
    normalized, excluded = filter_networks(input_networks, records)
    if not normalized:
        raise SystemExit("all input addresses were excluded; refusing to build an empty set")

    output.mkdir(parents=True, exist_ok=True)
    normalized_path = output / "target-v4.txt"
    atomic_write(normalized_path, "".join(f"{network}\n" for network in normalized))

    output_addresses = sum(network.num_addresses for network in normalized)
    report = {
        "schema": 1,
        "source": {"path": str(source), "sha256": sha256(source)},
        "iana_registry": {
            "path": str(registry),
            "sha256": sha256(registry),
            "records": len(records),
        },
        "multicast_exclusion": str(MULTICAST),
        "input": input_stats,
        "output": {
            "networks": len(normalized),
            "addresses": output_addresses,
            "sha256": sha256(normalized_path),
        },
        "excluded_addresses": input_stats["input_addresses"] - output_addresses,
        "excluded_by_most_specific_assignment": dict(sorted(excluded.items())),
    }
    report_path = output / "report.json"
    atomic_write(report_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    metadata = (
        f"source-sha256={report['source']['sha256']} "
        f"list-sha256={report['output']['sha256']} entries={len(normalized)}"
    )
    create_path = output / "target-v4.create.nft"
    replace_path = output / "target-v4.replace.nft"
    atomic_write(create_path, nft_batch(normalized, replace=False, metadata=metadata))
    atomic_write(replace_path, nft_batch(normalized, replace=True, metadata=metadata))

    checksums = []
    for path in (normalized_path, report_path, create_path, replace_path):
        checksums.append(f"{sha256(path)}  {path.name}\n")
    atomic_write(output / "SHA256SUMS", "".join(checksums))
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
