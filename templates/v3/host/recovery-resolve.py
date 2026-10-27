#!/usr/bin/env python3
"""Manually resolve a durable outcome_unknown fence after evidence review."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


BASE = Path(os.environ.get("AMNEZIA_LB_MULTI_DIR", "/etc/amnezia-lb-multi-v3"))
UNIT = "amnezia-lb-multi-v3-controller.service"


def read_env(path):
    result = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def atomic_json(path, payload, mode=0o600):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as stream:
            json.dump(payload, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def validate_evidence(evidence, action_id, conclusion):
    if not isinstance(evidence, dict):
        raise ValueError("evidence must be a JSON object")
    if evidence.get("action_id") != action_id:
        raise ValueError("evidence action_id does not match")
    if evidence.get("conclusion") != conclusion:
        raise ValueError("evidence conclusion does not match")
    if not isinstance(evidence.get("summary"), str) or not evidence["summary"].strip():
        raise ValueError("evidence summary must be a non-empty string")


def resolve_document(journal, action_id, conclusion, evidence_record, active_names, release, now):
    if journal.get("schema_version") != 2 or not isinstance(journal.get("egresses"), dict):
        raise ValueError("recovery journal schema is invalid")
    pending = journal.get("pending")
    if not isinstance(pending, dict) or pending.get("status") != "outcome_unknown":
        raise ValueError("journal has no outcome_unknown fence")
    if pending.get("action_id") != action_id:
        raise ValueError("pending action_id does not match")
    egress = pending.get("egress")
    if egress not in active_names or egress not in journal["egresses"]:
        raise ValueError("pending egress is not active")
    resolution = {
        "time": now,
        "status": f"manually_resolved_{conclusion.replace('-', '_')}",
        "action_id": action_id,
        "egress": egress,
        "action": pending.get("action"),
        "previous_pending": pending,
        **evidence_record,
    }
    journal["egresses"][egress]["last_outcome"] = resolution
    journal.setdefault("manual_resolutions", []).append(resolution)
    journal["pending"] = None
    journal["release"] = release
    journal["updated_at"] = now
    return journal


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--action-id", required=True)
    parser.add_argument("--conclusion", required=True, choices=("completed", "not-executed"))
    parser.add_argument("--evidence-json", required=True, type=Path)
    return parser.parse_args()


def main():
    args = parse_args()
    if os.geteuid() != 0:
        raise SystemExit("must run as root")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", args.action_id):
        raise SystemExit("action_id contains unsupported characters")
    env = read_env(BASE / "multi.env")
    if (
        env.get("RECOVERY_ENABLED") != "0"
        or env.get("RECOVERY_ALLOWED_EGRESSES", "") != ""
        or env.get("RECOVERY_ALLOW_CRASHLOOP_CONTAINMENT") != "0"
    ):
        raise SystemExit("recovery must be disabled with an empty allowlist and containment off")
    active_names = {item["name"] for item in json.loads((BASE / "egresses.json").read_text())}
    state_path = Path(env["RECOVERY_STATE_FILE"])
    lock_path = Path(env["RECOVERY_LOCK_FILE"])
    evidence_bytes = args.evidence_json.read_bytes()
    evidence = json.loads(evidence_bytes)
    validate_evidence(evidence, args.action_id, args.conclusion)

    lock_path.touch(mode=0o600, exist_ok=True)
    with lock_path.open("r+") as lock_stream:
        fcntl.flock(lock_stream, fcntl.LOCK_EX)
        active = subprocess.run(
            ["systemctl", "is-active", "--quiet", UNIT],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode == 0
        if active:
            raise SystemExit(f"stop {UNIT} before resolving the fence")
        journal = json.loads(state_path.read_text())
        now = int(time.time())
        evidence_dir = state_path.parent / "recovery-evidence"
        evidence_path = evidence_dir / f"{args.action_id}-{now}.json"
        evidence_record = {
            "evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
            "evidence_file": str(evidence_path),
            "operator_summary": evidence["summary"].strip(),
        }
        resolve_document(
            journal, args.action_id, args.conclusion, evidence_record,
            active_names, env["RELEASE_ID"], now,
        )
        atomic_json(evidence_path, evidence)
        atomic_json(state_path, journal)
        fcntl.flock(lock_stream, fcntl.LOCK_UN)
    print(json.dumps({
        "event": "pending_manually_resolved", "time": now,
        "action_id": args.action_id, "conclusion": args.conclusion,
        "evidence_sha256": evidence_record["evidence_sha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
