#!/usr/bin/env python3
"""Build deterministic installable archives, including the complete runtime."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def package(output):
    output = Path(output)
    if output.exists():
        raise ValueError("Output already exists")
    patterns = ("amnezia_router/*.py", "tests/*.py", "tools/package.py", "examples/*.json", "examples/*.txt",
                "data/iana-ipv4-special-registry.csv", "data/SOURCE.md", "routerctl.py", "install.sh",
                "egress-start.sh", "egress-healthcheck.sh", "README.md")
    paths = {path for pattern in patterns for path in ROOT.glob(pattern)}
    inventory = {p.relative_to(ROOT).as_posix(): p.read_bytes() for p in paths if p.is_file() and not p.is_symlink()}
    for name in ("install.sh", "routerctl.py", "egress-start.sh", "egress-healthcheck.sh", "data/iana-ipv4-special-registry.csv",
                 "amnezia_router/cli.py", "amnezia_router/runtime.py", "README.md"):
        if name not in inventory:
            raise ValueError("Missing runtime payload: " + name)
    inventory["LICENSE"] = (ROOT / "LICENSE" if (ROOT / "LICENSE").exists() else ROOT.parent / "LICENSE").read_bytes()
    inventory["SHA256SUMS"] = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(inventory.items())).encode()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in sorted(inventory.items()):
            entry = tarfile.TarInfo("amnezia-router/" + name)
            entry.size = len(data)
            entry.mode = 0o755 if name.endswith(".sh") or name == "routerctl.py" else 0o644
            entry.uid = entry.gid = entry.mtime = 0
            archive.addfile(entry, io.BytesIO(data))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(gzip.compress(stream.getvalue(), mtime=0))
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_name(output.name + ".sha256").write_text(f"{digest}  {output.name}\n", encoding="utf-8", newline="\n")
    return digest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(package(args.output))
