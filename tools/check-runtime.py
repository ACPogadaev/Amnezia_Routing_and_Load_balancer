#!/usr/bin/env python3
"""Read-only monitoring check for an installed Amnezia load balancer."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time


OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3


def finish(code: int, message: str, details: dict | None = None) -> "NoReturn":
    names = {OK: "OK", WARNING: "WARNING", CRITICAL: "CRITICAL", UNKNOWN: "UNKNOWN"}
    payload = {"status": names[code], "message": message}
    if details:
        payload["details"] = details
    print(json.dumps(payload, sort_keys=True, ensure_ascii=False))
    raise SystemExit(code)


def load_json(path: pathlib.Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        finish(UNKNOWN, f"cannot read {path}: {error}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=pathlib.Path, default=pathlib.Path("/run/amnezia-lb-multi-v3/state.json"))
    parser.add_argument("--egresses", type=pathlib.Path, default=pathlib.Path("/etc/amnezia-lb-multi-v3/egresses.json"))
    parser.add_argument("--max-age", type=int, default=30)
    parser.add_argument("--now", type=float, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.max_age <= 0:
        finish(UNKNOWN, "--max-age must be greater than zero")

    state = load_json(args.state)
    egresses = load_json(args.egresses)
    if not isinstance(state, dict) or not isinstance(egresses, list):
        finish(UNKNOWN, "state or egress configuration has an unexpected type")

    now = args.now if args.now is not None else time.time()
    timestamp = state.get("time")
    if not isinstance(timestamp, (int, float)):
        finish(UNKNOWN, "state has no numeric timestamp")
    age = now - timestamp
    details = {
        "age_seconds": round(age, 3),
        "release": state.get("release"),
        "mode": state.get("mode"),
        "healthy": state.get("healthy"),
        "eligible": state.get("eligible"),
        "bucket_counts": state.get("bucket_counts"),
        "recovery_pending": state.get("recovery_pending"),
    }
    if age < -5:
        finish(CRITICAL, "state timestamp is in the future; check time synchronization", details)
    if age > args.max_age:
        finish(CRITICAL, "controller state is stale", details)

    active = {item.get("name") for item in egresses if isinstance(item, dict)}
    if not active or None in active or len(active) != len(egresses):
        finish(UNKNOWN, "egress configuration has missing or duplicate names", details)
    healthy = set(state.get("healthy") or [])
    eligible = set(state.get("eligible") or [])
    buckets = state.get("bucket_counts")
    if not isinstance(buckets, dict):
        finish(UNKNOWN, "state has no bucket_counts object", details)
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in buckets.values()):
        finish(UNKNOWN, "bucket map contains a non-integer or negative value", details)
    if sum(buckets.values()) != 256:
        finish(CRITICAL, "bucket map does not contain exactly 256 assignments", details)

    if state.get("infra_valid") is not True:
        finish(CRITICAL, "infrastructure validation failed", details)
    if state.get("recovery_journal_valid") is not True or state.get("recovery_journal_error"):
        finish(CRITICAL, "recovery journal is invalid", details)
    pending = state.get("recovery_pending")
    if isinstance(pending, dict) and pending.get("status") == "outcome_unknown":
        finish(CRITICAL, "recovery outcome is unknown and lifecycle actions are fenced", details)
    if state.get("maintenance") is True or state.get("admission_open") is not True:
        finish(CRITICAL, "new-flow admission is closed", details)
    if buckets.get("fail", 0) != 0:
        finish(CRITICAL, "one or more buckets point to fail-closed", details)

    mode = state.get("mode")
    if mode == "balanced" and healthy == active and eligible == active and pending is None:
        finish(OK, "all configured egresses are healthy and eligible", details)
    if mode == "degraded" and eligible and eligible <= active:
        finish(WARNING, "balancer is degraded but still has an eligible egress", details)
    if pending is not None:
        finish(WARNING, "a controlled recovery action is pending", details)
    finish(CRITICAL, "balancer is not in an accepted operational mode", details)


if __name__ == "__main__":
    main()
