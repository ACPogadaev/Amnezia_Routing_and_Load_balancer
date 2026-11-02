#!/usr/bin/env python3
"""Verify a fully healthy runtime before or after opening admission."""
import argparse
import json
from pathlib import Path
import subprocess
import time


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_env(path):
    return dict(line.split("=", 1) for raw in Path(path).read_text(encoding="utf-8").splitlines()
                if (line := raw.strip()) and not line.startswith("#") and "=" in line)


def validate_state(state, env, egresses, release, *, maintenance=False, now=None):
    now = time.time() if now is None else now
    active = {item["name"] for item in egresses}
    require(active and len(active) == len(egresses), "invalid egress inventory")
    expected_exit = {item["name"]: item["expected_exit_ip"] for item in egresses}
    retired = {int(item.strip(), 0) for item in env.get("RETIRED_MARKS", "").split(",") if item.strip()}
    allowed = {item for item in env.get("RECOVERY_ALLOWED_EGRESSES", "").split(",") if item}
    age = now - state["time"]
    require(0 <= age < 30, "controller state is stale or in the future")
    require(state["release"] == release, "unexpected runtime release")
    require(state["infra_valid"] is True, "infrastructure is not validated")
    require(state["maintenance"] is maintenance, "unexpected maintenance state")
    require(state["admission_open"] is (not maintenance), "unexpected admission state")
    require(state["mode"] == ("reconciling" if maintenance else "balanced"), "unexpected controller mode")
    require(set(state["healthy"]) == active and set(state["eligible"]) == active, "not all egresses are healthy/eligible")
    require(state["recovery_enabled"] is (env.get("RECOVERY_ENABLED", "0") == "1"), "recovery configuration mismatch")
    require(set(state["recovery_allowed_egresses"]) == allowed, "recovery allowlist mismatch")
    require(state["recovery_allow_crashloop_containment"] is (env.get("RECOVERY_ALLOW_CRASHLOOP_CONTAINMENT", "0") == "1"), "containment configuration mismatch")
    require(state["recovery_journal_valid"] is True and state["recovery_journal_error"] is None, "invalid recovery journal")
    require(state["recovery_pending"] is None, "recovery has an unresolved pending action")
    require(set(state["retired_quarantined_marks"]) == retired, "retired quarantine mismatch")
    buckets = state["bucket_counts"]
    require(set(buckets) == active | {"fail"}, "unexpected bucket owners")
    require(all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in buckets.values())
            and sum(buckets.values()) == 256, "invalid bucket counts")
    if maintenance:
        require(state["recovery_enabled"] is False, "canary preparation requires recovery disabled")
        require(buckets["fail"] == 256 and all(buckets[name] == 0 for name in active), "maintenance must keep all buckets fail-closed")
    else:
        require(buckets["fail"] == 0 and all(buckets[name] > 0 for name in active), "not all egresses have active buckets")
    for name in active:
        item = state["egresses"][name]
        require(item["healthy"] is True and item["eligible"] is True, f"{name} is not healthy/eligible")
        require(item["reason"] == "ok" and item["failures"] == 0, f"{name} has probe failures")
        require(item["exit_ip"] == expected_exit[name], f"{name} has wrong exit IP")
    return retired | ({int(item["mark"]) for item in egresses} if maintenance else set())


def validate_quarantine(document, expected):
    sets = [entry["set"] for entry in document["nftables"] if "set" in entry
            and entry["set"].get("name") == "quarantined_marks"]
    require(len(sets) == 1, "expected one quarantine set")
    actual = {int(value) for value in sets[0].get("elem", [])}
    require(actual == expected, "quarantine readback mismatch")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("state", type=Path)
    parser.add_argument("environment", type=Path)
    parser.add_argument("egresses", type=Path)
    parser.add_argument("release")
    parser.add_argument("--maintenance", action="store_true")
    args = parser.parse_args()
    try:
        expected = validate_state(json.loads(args.state.read_text()), read_env(args.environment),
                                  json.loads(args.egresses.read_text()), args.release, maintenance=args.maintenance)
        result = subprocess.run(["nft", "-j", "list", "set", "inet", "amnezia_lb_balance_v3", "quarantined_marks"],
                                check=True, capture_output=True, text=True, timeout=10)
        validate_quarantine(json.loads(result.stdout), expected)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"runtime verification: {error}\n")


if __name__ == "__main__":
    main()
