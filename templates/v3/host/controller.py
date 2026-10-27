#!/usr/bin/env python3
import fcntl
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

BASE = Path(os.environ.get("AMNEZIA_LB_MULTI_DIR", "/etc/amnezia-lb-multi-v3"))


def read_env(path):
    result = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


ENV = read_env(BASE / "multi.env")
EGRESSES = json.loads((BASE / "egresses.json").read_text())
RUNTIME = Path(ENV["RUNTIME_DIR"])
STATE = RUNTIME / "state.json"
STATE_ROOT = Path(ENV["STATE_ROOT"])
MAINTENANCE = Path(ENV["MAINTENANCE_FILE"])
RECOVERY_STATE = Path(ENV["RECOVERY_STATE_FILE"])
RECOVERY_LOCK = Path(ENV["RECOVERY_LOCK_FILE"])
DRAIN_DIR = Path(ENV["DRAIN_DIR"])
RELEASE_ID = ENV["RELEASE_ID"]
FAIL_MARK = int(ENV["FAIL_MARK"], 0)
INTERVAL = int(ENV["HEALTH_INTERVAL_SECONDS"])
FAIL_THRESHOLD = int(ENV["HEALTH_FAILURE_THRESHOLD"])
SUCCESS_THRESHOLD = int(ENV["HEALTH_SUCCESS_THRESHOLD"])
MAX_HANDSHAKE_AGE = int(ENV["HEALTH_MAX_HANDSHAKE_AGE_SECONDS"])
MAX_SAMPLE_AGE = int(ENV.get("HEALTH_MAX_SAMPLE_AGE_SECONDS", "45"))
ALLOW_LEGACY_PROBE = ENV.get("ALLOW_LEGACY_PROBE", "0") == "1"
ALPHA = float(ENV["LOAD_EWMA_ALPHA"])
REFERENCE_BPS = float(ENV["LOAD_REFERENCE_BPS"])
WEIGHT_FLOOR = float(ENV["LOAD_WEIGHT_FLOOR"])
PROBE_TIMEOUT = int(ENV.get("HEALTH_PROBE_TIMEOUT_SECONDS", "15")) + 10
RECOVERY_ENABLED = ENV.get("RECOVERY_ENABLED", "0") == "1"
RECOVERY_ALLOWED = {item for item in ENV.get("RECOVERY_ALLOWED_EGRESSES", "").split(",") if item}
RECOVERY_ALLOW_CRASHLOOP_CONTAINMENT = ENV.get("RECOVERY_ALLOW_CRASHLOOP_CONTAINMENT", "0") == "1"
RECOVERY_FAILURE_THRESHOLD = int(ENV.get("RECOVERY_FAILURE_THRESHOLD", "6"))
RECOVERY_COOLDOWN = int(ENV.get("RECOVERY_COOLDOWN_SECONDS", "300"))
RECOVERY_WINDOW = int(ENV.get("RECOVERY_WINDOW_SECONDS", "1800"))
RECOVERY_MAX_RESTARTS = int(ENV.get("RECOVERY_MAX_RESTARTS", "3"))
RECOVERY_MAX_PARALLEL = int(ENV.get("RECOVERY_MAX_PARALLEL", "1"))
STARTUP_GRACE = int(ENV.get("RECOVERY_STARTUP_GRACE_SECONDS", "90"))
stopping = False


def recovery_log(event, **fields):
    payload = {"event": event, "time": int(time.time()), **fields}
    print(
        "recovery_event=" + json.dumps(payload, sort_keys=True, separators=(",", ":")),
        flush=True,
    )


def parse_marks(raw):
    return {int(item.strip(), 0) for item in raw.split(",") if item.strip()}


RETIRED_MARKS = parse_marks(ENV.get("RETIRED_MARKS", ""))
ACTIVE_NAMES = {item["name"] for item in EGRESSES}
ACTIVE_MARKS = {int(item["mark"]) for item in EGRESSES}
if len(ACTIVE_NAMES) != len(EGRESSES) or len(ACTIVE_MARKS) != len(EGRESSES):
    raise RuntimeError("duplicate egress name or mark")
if RECOVERY_ALLOWED - ACTIVE_NAMES:
    recovery_log("configuration_rejected", reason="unknown_recovery_egress", names=sorted(RECOVERY_ALLOWED - ACTIVE_NAMES))
    raise RuntimeError(f"unknown recovery egresses: {sorted(RECOVERY_ALLOWED - ACTIVE_NAMES)}")
if RETIRED_MARKS & ACTIVE_MARKS:
    recovery_log("configuration_rejected", reason="retired_mark_overlaps_active")
    raise RuntimeError("retired marks overlap active egress marks")
if RECOVERY_MAX_PARALLEL != 1:
    recovery_log("configuration_rejected", reason="recovery_max_parallel_must_equal_one", value=RECOVERY_MAX_PARALLEL)
    raise RuntimeError("RECOVERY_MAX_PARALLEL must be exactly 1")

HARD_REASONS = {
    "wrong_exit_ip", "missing_interface", "interface_down", "wrong_interface_address",
    "forwarding_disabled", "missing_policy_default", "missing_forward_lookup",
    "missing_forward_unreachable", "missing_health_lookup", "missing_health_unreachable",
    "missing_forward_out", "missing_forward_return", "missing_snat", "missing_output_guard",
    "v4_probe_missing", "probe_schema_mismatch", "probe_generation_mismatch",
    "probe_instance_mismatch",
}
RECOVERABLE_REASONS = {
    "container_stopped", "starting_timeout", "missing_interface", "interface_down",
    "handshake_missing", "handshake_stale", "https_unavailable", "docker_exec_error",
}


def is_recoverable_measurement(result, any_probe_success):
    """Return true only for a fresh failure that may advance lifecycle recovery."""
    reason = result.get("reason")
    scope = result.get("reason_scope", "collector")
    if result.get("healthy") or reason == "container_stopped":
        return False
    if reason not in RECOVERABLE_REASONS or scope not in {"local", "network"}:
        return False
    if reason == "https_unavailable" and not any_probe_success:
        return False
    return True


def update_recoverable_streak(state, result, any_probe_success):
    if is_recoverable_measurement(result, any_probe_success):
        state["recoverable_failures"] = state.get("recoverable_failures", 0) + 1
        state["recoverable_reason"] = result.get("reason")
    else:
        state["recoverable_failures"] = 0
        state["recoverable_reason"] = None


def run(args, *, timeout=15, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=timeout)


def helper(path, *args, timeout=30):
    return run([path, *args], timeout=timeout)


def docker_exec(container, args, timeout=15, check=True):
    return run(["docker", "exec", container, *args], timeout=timeout, check=check)


def atomic_json(path, payload, mode=0o600, durable=False):
    path.parent.mkdir(mode=0o700 if path.parent == STATE_ROOT else 0o755, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as stream:
            json.dump(payload, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            if durable:
                os.fsync(stream.fileno())
        os.replace(name, path)
        if durable:
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def fresh_recovery_journal():
    return {
        "schema_version": 2,
        "release": RELEASE_ID,
        "pending": None,
        "egresses": {
            item["name"]: {
                "attempts": [], "last_outcome": None, "recovery_exhausted": False,
                "last_restart_count": None, "engine_restart_events": [],
                "engine_crashloop_suspended": False,
            }
            for item in EGRESSES
        },
    }


def is_timestamp(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def valid_identity_key(value):
    if value is None:
        return True
    return (
        isinstance(value, (list, tuple)) and len(value) == 4
        and isinstance(value[0], str) and isinstance(value[1], str)
        and isinstance(value[2], int) and value[2] > 0
        and isinstance(value[3], int) and value[3] > 0
    )


def validate_recovery_record(name, record):
    if not isinstance(record, dict):
        raise ValueError(f"journal record {name} is not an object")
    for field in ("attempts", "engine_restart_events"):
        values = record.get(field)
        if not isinstance(values, list) or any(not is_timestamp(value) for value in values):
            raise ValueError(f"journal record {name}.{field} is invalid")
    for field in ("recovery_exhausted", "engine_crashloop_suspended"):
        if not isinstance(record.get(field), bool):
            raise ValueError(f"journal record {name}.{field} is invalid")
    restart_count = record.get("last_restart_count")
    if restart_count is not None and (
        not isinstance(restart_count, int) or isinstance(restart_count, bool) or restart_count < 0
    ):
        raise ValueError(f"journal record {name}.last_restart_count is invalid")
    outcome = record.get("last_outcome")
    if outcome is not None and not isinstance(outcome, dict):
        raise ValueError(f"journal record {name}.last_outcome is invalid")


def validate_pending(pending):
    if pending is None:
        return
    if not isinstance(pending, dict):
        raise ValueError("journal pending is not an object")
    if pending.get("egress") not in ACTIVE_NAMES:
        raise ValueError("journal pending references an inactive egress")
    if pending.get("action") not in {"start", "restart", "stop"}:
        raise ValueError("journal pending action is invalid")
    if not isinstance(pending.get("action_id"), str) or not pending["action_id"]:
        raise ValueError("journal pending action_id is invalid")
    if not is_timestamp(pending.get("time")):
        raise ValueError("journal pending time is invalid")
    if not valid_identity_key(pending.get("pre_identity")):
        raise ValueError("journal pending identity is invalid")
    status = pending.get("status", "intent_recorded")
    if status not in {"intent_recorded", "rpc_dispatched", "outcome_unknown"}:
        raise ValueError("journal pending status is invalid")


def load_recovery_journal():
    if not RECOVERY_STATE.exists():
        journal = fresh_recovery_journal()
        atomic_json(RECOVERY_STATE, journal, durable=True)
        return journal, True, None
    try:
        journal = json.loads(RECOVERY_STATE.read_text())
        original_schema = journal.get("schema_version")
        if original_schema not in {1, 2} or not isinstance(journal.get("egresses"), dict):
            raise ValueError("unsupported recovery journal schema")
        defaults = fresh_recovery_journal()["egresses"]
        for item in EGRESSES:
            journal["egresses"].setdefault(item["name"], defaults[item["name"]])
        for name, record in journal["egresses"].items():
            if isinstance(record, dict) and isinstance(record.get("last_outcome"), str):
                record["last_outcome"] = {"status": record["last_outcome"], "time": 0}
            validate_recovery_record(name, record)
        validate_pending(journal.get("pending"))
        journal["schema_version"] = 2
        if original_schema != 2:
            atomic_json(RECOVERY_STATE, journal, durable=True)
        return journal, True, None
    except Exception as exc:
        return fresh_recovery_journal(), False, str(exc)


def save_recovery_journal(journal):
    journal["release"] = RELEASE_ID
    journal["updated_at"] = int(time.time())
    atomic_json(RECOVERY_STATE, journal, durable=True)


def container_inspect(container):
    result = run(["docker", "inspect", container], timeout=8, check=False)
    if result.returncode != 0:
        return None
    parsed = json.loads(result.stdout)
    return parsed[0] if parsed else None


def identity_from_inspect(data):
    if not data or not data.get("State", {}).get("Running"):
        return None
    pid = int(data["State"].get("Pid", 0))
    if pid <= 0:
        return None
    return {
        "container_id": data["Id"], "started_at": data["State"]["StartedAt"],
        "pid": pid, "netns_inode": os.stat(f"/proc/{pid}/ns/net").st_ino,
        "restart_count": int(data.get("RestartCount", 0)),
    }


def identity_key(identity):
    if not identity:
        return None
    return (identity["container_id"], identity["started_at"], identity["pid"], identity["netns_inode"])


def started_epoch(identity):
    if not identity:
        return 0
    try:
        return int(datetime.fromisoformat(identity["started_at"].replace("Z", "+00:00")).timestamp())
    except ValueError:
        return 0


def check_container_labels(egress, data):
    labels = (data or {}).get("Config", {}).get("Labels") or {}
    if labels.get("com.docker.compose.project") != egress["compose_project"]:
        raise RuntimeError("unexpected compose project")
    if labels.get("com.docker.compose.service") != egress["compose_service"]:
        raise RuntimeError("unexpected compose service")
    if labels.get("com.docker.compose.project.config_files") != egress["compose_file"]:
        raise RuntimeError("unexpected compose file")


def check_ingress(identity):
    ready = Path("/run/amnezia-lb-v2/ingress.ready")
    if not ready.is_file() or ready.read_text().strip() != str(identity["pid"]):
        raise RuntimeError("ingress readiness does not match current namespace")
    helper(str(Path(ENV["V2_DIR"]) / "host/ingress-check.sh"), str(identity["pid"]), timeout=25)
    helper(str(Path(ENV["V2_DIR"]) / "host/ingress-targets-check.sh"), timeout=25)


def close_admission():
    run([str(Path(ENV["V2_DIR"]) / "host/policy-down.sh")], timeout=25, check=False)


def ensure_infrastructure():
    checks = [
        ([str(BASE / "host/guard-check.sh")], [str(BASE / "host/guard-load.sh")]),
        ([str(BASE / "host/balance-check.sh")], [str(BASE / "host/balance-load.sh")]),
        ([str(BASE / "host/host-policy-check.sh")], [str(BASE / "host/host-policy-up.sh")]),
        ([str(BASE / "host/docker-user-check.sh")], [str(BASE / "host/docker-user-install.sh")]),
        ([str(Path(ENV["V2_DIR"]) / "host/docker-user-check.sh")],
         [str(Path(ENV["V2_DIR"]) / "host/docker-user-install.sh")]),
    ]
    repaired = False
    for check, repair in checks:
        result = subprocess.run(check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=25)
        if result.returncode != 0:
            close_admission()
            run(repair, timeout=35)
            run(check, timeout=25)
            repaired = True
    return repaired


def enable_forwarding(egress):
    if egress["name"] == "main":
        helper(egress["forward_helper"], timeout=20)
    else:
        helper(egress["forward_helper"], egress["container"], egress["ready_file"], timeout=20)


def read_legacy_bytes(egress):
    result = docker_exec(
        egress["container"],
        ["sh", "-c", f"cat /sys/class/net/{egress['awg_if']}/statistics/rx_bytes; "
                       f"cat /sys/class/net/{egress['awg_if']}/statistics/tx_bytes"], timeout=5,
    )
    values = [int(item) for item in result.stdout.split()]
    if len(values) != 2:
        raise RuntimeError("invalid byte counters")
    return values[0], values[1]


def legacy_probe(egress):
    observed = None
    observer = None
    secondary_url = ENV["HEALTH_URL_SECONDARY"].split("?", 1)[0]
    for name, url in (("primary", ENV["HEALTH_URL"]), ("secondary", secondary_url)):
        result = docker_exec(
            egress["container"],
            ["curl", "--silent", "--show-error", "--fail", "--ipv4", "--max-time", "6",
             "--interface", egress["awg_ip"], url], timeout=10, check=False,
        )
        if result.returncode != 0:
            continue
        candidate = next(
            (line[3:].strip() for line in result.stdout.splitlines() if line.startswith("ip=")),
            result.stdout.strip().splitlines()[0] if result.stdout.strip() else "",
        )
        if candidate and candidate != egress["expected_exit_ip"]:
            return {"healthy": False, "reason": "wrong_exit_ip", "reason_scope": "security", "probe_version": "legacy"}
        if candidate == egress["expected_exit_ip"]:
            observed, observer = candidate, name
            break
    if not observed:
        return {"healthy": False, "reason": "https_unavailable", "reason_scope": "network", "probe_version": "legacy"}
    handshakes = docker_exec(egress["container"], ["awg", "show", egress["awg_if"], "latest-handshakes"], timeout=5).stdout
    timestamps = []
    for line in handshakes.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            timestamps.append(int(parts[1]))
    latest = max(timestamps, default=0)
    age = int(time.time()) - latest
    if latest <= 0:
        return {"healthy": False, "reason": "handshake_missing", "reason_scope": "local", "probe_version": "legacy"}
    if age < 0:
        return {"healthy": False, "reason": "clock_error", "reason_scope": "infrastructure", "probe_version": "legacy"}
    if age > MAX_HANDSHAKE_AGE:
        return {"healthy": False, "reason": "handshake_stale", "reason_scope": "local", "probe_version": "legacy"}
    rx, tx = read_legacy_bytes(egress)
    return {
        "healthy": True, "reason": "ok", "reason_scope": "none", "observer": observer,
        "exit_ip": observed, "handshake_age": age, "rx_bytes": rx, "tx_bytes": tx,
        "sample_id": f"legacy-{time.time_ns()}", "probe_version": "legacy",
    }


def functional_probe(egress, expected_instance):
    present = docker_exec(egress["container"], ["test", "-x", "/run/amnezia-lb-health/egress-healthcheck.sh"], timeout=5, check=False)
    if present.returncode != 0:
        if ALLOW_LEGACY_PROBE:
            return legacy_probe(egress)
        return {"healthy": False, "reason": "v4_probe_missing", "reason_scope": "installation", "probe_version": "none"}
    result = docker_exec(
        egress["container"],
        ["timeout", str(int(ENV.get("HEALTH_PROBE_TIMEOUT_SECONDS", "15")) + 1),
         "/run/amnezia-lb-health/egress-healthcheck.sh", "--json"],
        timeout=PROBE_TIMEOUT, check=False,
    )
    candidates = [line for line in result.stdout.splitlines() if line.strip().startswith("{")]
    if not candidates:
        return {"healthy": False, "reason": "docker_exec_error", "reason_scope": "local", "detail": result.stderr[-300:]}
    try:
        payload = json.loads(candidates[-1])
    except ValueError:
        return {"healthy": False, "reason": "probe_output_invalid", "reason_scope": "collector"}
    now = int(time.time())
    sample_epoch = payload.get("sample_epoch")
    if payload.get("schema_version") != 1:
        return {"healthy": False, "reason": "probe_schema_mismatch", "reason_scope": "installation"}
    if payload.get("config_generation") != ENV["HEALTH_CONFIG_GENERATION"]:
        return {"healthy": False, "reason": "probe_generation_mismatch", "reason_scope": "installation"}
    if payload.get("instance_id") != expected_instance:
        return {"healthy": False, "reason": "probe_instance_mismatch", "reason_scope": "collector"}
    if not isinstance(sample_epoch, int) or isinstance(sample_epoch, bool) or sample_epoch > now or now - sample_epoch > MAX_SAMPLE_AGE:
        return {"healthy": False, "reason": "probe_sample_stale", "reason_scope": "collector"}
    if not isinstance(payload.get("sample_id"), str) or not payload["sample_id"]:
        return {"healthy": False, "reason": "probe_sample_invalid", "reason_scope": "collector"}
    payload["probe_version"] = "v4"
    return payload


def probe_one(egress, initial_identity):
    if not initial_identity:
        return {"healthy": False, "reason": "container_stopped", "reason_scope": "local"}, None
    age = int(time.time()) - started_epoch(initial_identity)
    ready = docker_exec(egress["container"], ["cat", egress["ready_file"]], timeout=5, check=False)
    instance_id = ready.stdout.strip()
    if ready.returncode != 0 or not instance_id:
        reason = "starting" if age < STARTUP_GRACE else "starting_timeout"
        return {"healthy": False, "reason": reason, "reason_scope": "local"}, initial_identity
    try:
        enable_forwarding(egress)
    except Exception as exc:
        reason = "starting" if age < STARTUP_GRACE else "forwarding_prepare_failed"
        return {"healthy": False, "reason": reason, "reason_scope": "local", "detail": str(exc)[-300:]}, initial_identity
    result = functional_probe(egress, instance_id)
    final_identity = identity_from_inspect(container_inspect(egress["container"]))
    if identity_key(final_identity) != identity_key(initial_identity):
        return {"healthy": False, "reason": "identity_changed", "reason_scope": "collector"}, final_identity
    return result, final_identity


def rendezvous_map(eligible):
    result = []
    for bucket in range(256):
        best = None
        for egress in eligible:
            digest = hashlib.sha256(f"amnezia-v4:{bucket}:{egress['name']}".encode()).digest()
            u = (int.from_bytes(digest, "big") + 1) / ((1 << 256) + 1)
            score = -math.log(u) / egress["weight"]
            candidate = (score, egress["name"], egress["mark"])
            if best is None or candidate < best:
                best = candidate
        result.append(best[2] if best else FAIL_MARK)
    return result


def nft_transaction(rules):
    subprocess.run(["nft", "-c", "-f", "-"], input=rules, text=True, check=True, timeout=12)
    subprocess.run(["nft", "-f", "-"], input=rules, text=True, check=True, timeout=12)


def quarantine_mark_set(quarantined):
    return RETIRED_MARKS | {item["mark"] for item in EGRESSES if item["name"] in quarantined}


def validate_policy(marks, qmarks):
    expected = {"bucket_marks": list(marks), "quarantined_marks": sorted(qmarks)}
    fd, expected_path = tempfile.mkstemp(prefix="balance-expected.", dir=RUNTIME)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(expected, stream, sort_keys=True)
            stream.write("\n")
        snapshot = run(["nft", "-j", "list", "table", "inet", "amnezia_lb_balance_v3"], timeout=12)
        subprocess.run(
            [str(BASE / "host/balance-check.py"), "--expected-state", expected_path],
            input=snapshot.stdout, text=True, check=True, timeout=12,
        )
    finally:
        if os.path.exists(expected_path):
            os.unlink(expected_path)


def set_policy(marks, quarantined):
    exists = subprocess.run(
        ["nft", "list", "set", "inet", "amnezia_lb_balance_v3", "quarantined_marks"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0
    if not exists:
        helper(str(BASE / "host/balance-load.sh"), timeout=20)
    lines = ["flush chain inet amnezia_lb_balance_v3 select", "flush set inet amnezia_lb_balance_v3 quarantined_marks"]
    qmarks = sorted(quarantine_mark_set(quarantined))
    if qmarks:
        lines.append("add element inet amnezia_lb_balance_v3 quarantined_marks { " + ", ".join(f"0x{mark:08x}" for mark in qmarks) + " }")
    names = {item["mark"]: item["name"] for item in EGRESSES}
    for mark in sorted(names):
        buckets = [f"0.0.0.{index}" for index, assigned in enumerate(marks) if assigned == mark]
        if buckets:
            lines.append(
                "add rule inet amnezia_lb_balance_v3 select "
                f"ip daddr & 0.0.0.255 {{ {', '.join(buckets)} }} "
                f"meta mark set 0x{mark:08x} return comment \"v3 buckets {names[mark]}\""
            )
    lines.append("add rule inet amnezia_lb_balance_v3 select meta mark set 0x000002ff comment \"v3 select fail\"")
    nft_transaction("\n".join(lines) + "\n")
    validate_policy(marks, set(qmarks))


def drain_mode(name):
    path = DRAIN_DIR / name
    if not path.exists():
        return None
    try:
        value = path.read_text().strip().lower()
    except OSError:
        return "force"
    return value if value in {"soft", "force"} else "force"


def lifecycle_authorized(name, action):
    if name not in RECOVERY_ALLOWED:
        return False
    if action == "stop" and not RECOVERY_ALLOW_CRASHLOOP_CONTAINMENT:
        return False
    return action in {"start", "restart", "stop"}


def evaluate_recovery_budget(record, now):
    """Prune the rolling window and return (decision, remaining, changed)."""
    previous_attempts = list(record.get("attempts", []))
    attempts = [stamp for stamp in previous_attempts if now - stamp <= RECOVERY_WINDOW]
    record["attempts"] = attempts
    changed = attempts != previous_attempts
    if record.get("recovery_exhausted"):
        return "exhausted", 0, changed
    if len(attempts) >= RECOVERY_MAX_RESTARTS:
        record["recovery_exhausted"] = True
        return "exhausted", 0, True
    if attempts and now - attempts[-1] < RECOVERY_COOLDOWN:
        return "cooldown", RECOVERY_COOLDOWN - (now - attempts[-1]), changed
    return "ready", 0, changed


def update_engine_history(journal, egress, identity, now):
    record = journal["egresses"][egress["name"]]
    current = identity.get("restart_count", 0) if identity else 0
    previous = record.get("last_restart_count")
    changed = False
    if previous is None or current < previous:
        record["last_restart_count"] = current
        changed = True
    elif current > previous:
        record.setdefault("engine_restart_events", []).extend([now] * min(current - previous, 10))
        record["last_restart_count"] = current
        changed = True
    events = [stamp for stamp in record.get("engine_restart_events", []) if now - stamp <= 300]
    if events != record.get("engine_restart_events", []):
        record["engine_restart_events"] = events
        changed = True
    return len(events) >= 3, changed


def recovery_action(context):
    egress = context["egress"]
    data = container_inspect(egress["container"])
    if not data:
        raise RuntimeError("container disappeared before lifecycle action")
    check_container_labels(egress, data)
    current = identity_from_inspect(data)
    if context["action"] != "start" and identity_key(current) != tuple(context["pre_identity"]):
        raise RuntimeError("container identity changed before lifecycle action")
    if context["action"] == "stop":
        result = run(["docker", "stop", "--timeout", "10", egress["container"]], timeout=30)
    elif context["action"] == "start":
        result = run(["docker", "start", egress["container"]], timeout=30)
    else:
        result = run(["docker", "restart", "--timeout", "10", egress["container"]], timeout=35)
    after = identity_from_inspect(container_inspect(egress["container"]))
    return {"stdout": result.stdout.strip(), "after_identity": identity_key(after)}


def reconcile_pending_action(journal, pending):
    target = next(item for item in EGRESSES if item["name"] == pending["egress"])
    current = identity_from_inspect(container_inspect(target["container"]))
    current_key = identity_key(current)
    pre_key = tuple(pending["pre_identity"]) if pending.get("pre_identity") else None
    action = pending["action"]
    completed = (
        (action == "stop" and current_key is None)
        or (action == "start" and pre_key is None and current_key is not None)
        or (action == "restart" and current_key is not None and current_key != pre_key)
    )
    now = int(time.time())
    pending["reconciled_at"] = now
    pending["reconciled_identity"] = current_key
    # Startup observations cannot prove that a previous Docker RPC caused an
    # identity change.  Preserve the durable global fence for manual review.
    pending["status"] = "outcome_unknown"
    pending["effect_observed"] = completed
    journal["egresses"][target["name"]]["last_outcome"] = {
        "time": now, "status": "outcome_unknown", "action_id": pending["action_id"],
        "observed_identity": current_key, "effect_observed": completed,
    }
    save_recovery_journal(journal)
    recovery_log(
        "startup_pending_fenced", action_id=pending["action_id"],
        egress=target["name"], action=action, effect_observed=completed,
        observed_identity=current_key,
    )


def stop_handler(_signum, _frame):
    global stopping
    stopping = True


def wait_until(deadline):
    """Wait interruptibly without ever passing a negative delay to sleep()."""
    while not stopping:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(0.5, remaining))


def main():
    global stopping
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    RUNTIME.mkdir(mode=0o755, parents=True, exist_ok=True)
    STATE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    DRAIN_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    RECOVERY_LOCK.touch(mode=0o600, exist_ok=True)
    journal, journal_valid, journal_error = load_recovery_journal()
    states = {
        item["name"]: {
            "healthy": False, "eligible": False, "successes": 0, "failures": 0,
            "recoverable_failures": 0, "recoverable_reason": None,
            "error": "starting", "reason": "starting", "reason_scope": "local",
            "bps_ewma": 0.0, "last_bytes": None, "last_sample": None,
            "last_sample_id": None, "identity_key": None, "quarantine_latched": False,
        }
        for item in EGRESSES
    }
    recovery_executor = ThreadPoolExecutor(max_workers=RECOVERY_MAX_PARALLEL, thread_name_prefix="egress-recovery")
    recovery_future = None
    recovery_context = None
    last_policy = None
    last_log = None
    last_cooldown_log = {}

    pending = journal.get("pending") if journal_valid else None
    if pending:
        reconcile_pending_action(journal, pending)

    try:
        set_policy([FAIL_MARK] * 256, {item["name"] for item in EGRESSES})
        close_admission()
        while not stopping:
            loop_started = time.monotonic()
            now = int(time.time())
            maintenance = MAINTENANCE.exists()
            common_valid = False
            common_error = None
            ingress_identity = None
            repaired = False
            try:
                run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=8)
                ingress_identity = identity_from_inspect(container_inspect(ENV["INGRESS_CONTAINER"]))
                if not ingress_identity:
                    raise RuntimeError("ingress has no active namespace")
                check_ingress(ingress_identity)
                repaired = ensure_infrastructure()
                current_ingress = identity_from_inspect(container_inspect(ENV["INGRESS_CONTAINER"]))
                if identity_key(current_ingress) != identity_key(ingress_identity):
                    raise RuntimeError("ingress namespace changed during reconciliation")
                common_valid = True
            except Exception as exc:
                common_error = str(exc)
                close_admission()

            identities = {}
            for egress in EGRESSES:
                try:
                    identities[egress["name"]] = identity_from_inspect(container_inspect(egress["container"]))
                except Exception as exc:
                    identities[egress["name"]] = None
                    states[egress["name"]]["error"] = str(exc)

            probe_results = {}
            if common_valid:
                with ThreadPoolExecutor(max_workers=len(EGRESSES)) as executor:
                    pending_probes = {executor.submit(probe_one, egress, identities[egress["name"]]): egress for egress in EGRESSES}
                    for future in as_completed(pending_probes):
                        egress = pending_probes[future]
                        try:
                            result, final_identity = future.result()
                        except Exception as exc:
                            result = {"healthy": False, "reason": "probe_exception", "reason_scope": "collector", "detail": str(exc)[-300:]}
                            final_identity = identities[egress["name"]]
                        probe_results[egress["name"]] = result
                        identities[egress["name"]] = final_identity

            any_probe_success = any(item.get("healthy") for item in probe_results.values())
            journal_changed = False
            for egress in EGRESSES:
                name = egress["name"]
                state = states[name]
                identity = identities[name]
                current_key = identity_key(identity)
                if current_key != state["identity_key"]:
                    state.update({
                        "healthy": False, "eligible": False, "successes": 0, "failures": 0,
                        "recoverable_failures": 0, "recoverable_reason": None,
                        "last_bytes": None, "last_sample": None, "last_sample_id": None,
                        "identity_key": current_key,
                    })
                crashloop, changed = update_engine_history(journal, egress, identity, now)
                journal_changed = journal_changed or changed
                record = journal["egresses"][name]
                state["engine_restart_count"] = identity.get("restart_count", 0) if identity else None
                state["engine_crashloop"] = crashloop
                state["engine_crashloop_suspended"] = record.get("engine_crashloop_suspended", False)
                if crashloop or state["engine_crashloop_suspended"]:
                    state["quarantine_latched"] = True

                if not common_valid:
                    state["eligible"] = False
                    state["error"] = f"infrastructure: {common_error}"
                    state["recoverable_failures"] = 0
                    state["recoverable_reason"] = None
                    continue
                result = probe_results[name]
                sample_id = result.get("sample_id")
                reason = result.get("reason", "unknown")
                scope = result.get("reason_scope", "collector")
                state["probe_version"] = result.get("probe_version", "none")
                state["probe_instance"] = result.get("instance_id")
                state["probe_generation"] = result.get("config_generation")
                state["reason"] = reason
                state["reason_scope"] = scope
                state["error"] = None if result.get("healthy") else reason
                if reason in {"probe_busy", "identity_changed"} or (sample_id and sample_id == state["last_sample_id"]):
                    if state["last_sample"] is None or time.time() - state["last_sample"] > MAX_SAMPLE_AGE:
                        state["healthy"] = False
                        state["eligible"] = False
                        state["reason"] = "collector_stale"
                        state["reason_scope"] = "collector"
                        state["error"] = "collector_stale"
                    else:
                        state["eligible"] = state["healthy"]
                    continue
                if reason == "starting":
                    state["healthy"] = False
                    state["eligible"] = False
                    state["recoverable_failures"] = 0
                    state["recoverable_reason"] = None
                    continue
                if result.get("healthy"):
                    total_bytes = int(result.get("rx_bytes", 0)) + int(result.get("tx_bytes", 0))
                    if state["last_bytes"] is not None and total_bytes >= state["last_bytes"]:
                        elapsed = max(0.001, time.time() - state["last_sample"])
                        instant = (total_bytes - state["last_bytes"]) / elapsed
                        state["bps_ewma"] = ALPHA * instant + (1.0 - ALPHA) * state["bps_ewma"]
                    state["last_bytes"] = total_bytes
                    state["last_sample"] = time.time()
                    state["last_sample_id"] = sample_id
                    state["successes"] += 1
                    state["failures"] = 0
                    state["recoverable_failures"] = 0
                    state["recoverable_reason"] = None
                    state["exit_ip"] = result.get("exit_ip")
                    state["handshake_age"] = result.get("handshake_age")
                    state["observer"] = result.get("observer")
                    if state["successes"] >= SUCCESS_THRESHOLD:
                        state["healthy"] = True
                        if not record.get("engine_crashloop_suspended"):
                            state["quarantine_latched"] = False
                else:
                    state["successes"] = 0
                    state["failures"] += 1
                    update_recoverable_streak(state, result, any_probe_success)
                    if reason in HARD_REASONS or state["failures"] >= FAIL_THRESHOLD:
                        state["healthy"] = False
                    if reason in HARD_REASONS:
                        state["quarantine_latched"] = True
                state["eligible"] = state["healthy"]

            drains = {item["name"]: drain_mode(item["name"]) for item in EGRESSES}
            for egress in EGRESSES:
                state = states[egress["name"]]
                state["drain"] = drains[egress["name"]]
                if drains[egress["name"]]:
                    state["eligible"] = False
                if drains[egress["name"]] == "force":
                    state["quarantine_latched"] = True

            recoverable = []
            for egress in EGRESSES:
                state = states[egress["name"]]
                reason = state.get("reason")
                network_confirmed = reason != "https_unavailable" or any_probe_success
                if (
                    common_valid and not maintenance and not drains[egress["name"]]
                    and reason in RECOVERABLE_REASONS and network_confirmed
                    and (
                        state["recoverable_failures"] >= RECOVERY_FAILURE_THRESHOLD
                        or reason == "container_stopped"
                    )
                ):
                    state["quarantine_latched"] = True
                    recoverable.append(egress)

            eligible = []
            quarantined = set()
            for egress in EGRESSES:
                state = states[egress["name"]]
                record = journal["egresses"][egress["name"]]
                if state["quarantine_latched"] or record.get("engine_crashloop_suspended"):
                    quarantined.add(egress["name"])
                    state["eligible"] = False
                egress["weight"] = max(WEIGHT_FLOOR, 1.0 / (1.0 + state["bps_ewma"] / REFERENCE_BPS))
                state["weight"] = round(egress["weight"], 6)
                if state["eligible"]:
                    eligible.append(egress)

            if not common_valid or maintenance or not eligible:
                marks = [FAIL_MARK] * 256
                effective_quarantine = {item["name"] for item in EGRESSES}
            else:
                marks = rendezvous_map(eligible)
                effective_quarantine = quarantined

            policy_key = (tuple(marks), tuple(sorted(effective_quarantine)))
            try:
                if policy_key != last_policy or repaired:
                    set_policy(marks, effective_quarantine)
                    last_policy = policy_key
                else:
                    validate_policy(marks, quarantine_mark_set(effective_quarantine))
            except Exception as exc:
                common_valid = False
                common_error = f"selector: {exc}"
                eligible = []
                marks = [FAIL_MARK] * 256
                effective_quarantine = {item["name"] for item in EGRESSES}
                last_policy = None
                try:
                    set_policy(marks, effective_quarantine)
                except Exception as fail_exc:
                    common_error += f"; fail-policy: {fail_exc}"
                close_admission()

            admission_open = False
            if eligible and common_valid and not maintenance:
                helper(str(Path(ENV["V2_DIR"]) / "host/policy-up.sh"), timeout=25)
                mode = "balanced" if len(eligible) == len(EGRESSES) else "degraded"
                admission_open = True
            else:
                close_admission()
                mode = "reconciling" if maintenance else "fail-closed"

            counts = {item["name"]: marks.count(item["mark"]) for item in EGRESSES}
            counts["fail"] = marks.count(FAIL_MARK)
            generation = hashlib.sha256(json.dumps({
                "marks": marks,
                "quarantine_marks": sorted(quarantine_mark_set(effective_quarantine)),
            }, separators=(",", ":")).encode()).hexdigest()

            if recovery_future is not None and recovery_future.done():
                target_name = recovery_context["egress"]["name"]
                try:
                    outcome = recovery_future.result()
                    journal["egresses"][target_name]["last_outcome"] = {"time": now, "status": "completed", **outcome}
                    journal["pending"] = None
                    recovery_log(
                        "completed", action_id=recovery_context["action_id"],
                        egress=target_name, action=recovery_context["action"],
                        after_identity=outcome.get("after_identity"),
                    )
                except Exception as exc:
                    journal["egresses"][target_name]["last_outcome"] = {
                        "time": now, "status": "outcome_unknown",
                        "action_id": recovery_context["action_id"], "error": str(exc)[-500:],
                    }
                    journal["pending"]["status"] = "outcome_unknown"
                    journal["pending"]["error"] = str(exc)[-500:]
                    recovery_log(
                        "outcome_unknown", action_id=recovery_context["action_id"],
                        egress=target_name, action=recovery_context["action"],
                        error=str(exc)[-500:],
                    )
                save_recovery_journal(journal)
                recovery_future = None
                recovery_context = None

            if (
                journal_valid and RECOVERY_ENABLED and recovery_future is None
                and journal.get("pending") is None and not maintenance and common_valid
            ):
                candidate = None
                action = None
                for egress in EGRESSES:
                    record = journal["egresses"][egress["name"]]
                    state = states[egress["name"]]
                    if (
                        state.get("engine_crashloop")
                        and not record.get("engine_crashloop_suspended")
                        and lifecycle_authorized(egress["name"], "stop")
                    ):
                        candidate, action = egress, "stop"
                        record["engine_crashloop_suspended"] = True
                        state["quarantine_latched"] = True
                        journal_changed = True
                        break
                if candidate is None:
                    for egress in recoverable:
                        record = journal["egresses"][egress["name"]]
                        was_exhausted = record.get("recovery_exhausted", False)
                        budget, remaining, budget_changed = evaluate_recovery_budget(record, now)
                        journal_changed = journal_changed or budget_changed
                        if budget == "exhausted":
                            if not was_exhausted:
                                recovery_log(
                                    "budget_exhausted", egress=egress["name"],
                                    attempts=len(record["attempts"]), window_seconds=RECOVERY_WINDOW,
                                )
                            continue
                        if budget == "cooldown":
                            last_attempt = record["attempts"][-1]
                            if last_cooldown_log.get(egress["name"]) != last_attempt:
                                recovery_log(
                                    "cooldown", egress=egress["name"],
                                    last_attempt=last_attempt, remaining_seconds=remaining,
                                )
                                last_cooldown_log[egress["name"]] = last_attempt
                            continue
                        candidate = egress
                        action = "restart" if identities[egress["name"]] else "start"
                        if not lifecycle_authorized(egress["name"], action):
                            candidate = None
                            action = None
                            continue
                        record["attempts"].append(now)
                        journal_changed = True
                        break

                if candidate is not None:
                    if not lifecycle_authorized(candidate["name"], action):
                        raise RuntimeError("lifecycle action is outside the active authorization scope")
                    candidate_state = states[candidate["name"]]
                    recovery_log(
                        "candidate", egress=candidate["name"], action=action,
                        reason=candidate_state.get("reason"),
                        reason_scope=candidate_state.get("reason_scope"),
                        recoverable_failures=candidate_state.get("recoverable_failures"),
                        probe_instance=candidate_state.get("probe_instance"),
                        probe_generation=candidate_state.get("probe_generation"),
                    )
                    lock_stream = RECOVERY_LOCK.open("r+")
                    try:
                        fcntl.flock(lock_stream, fcntl.LOCK_EX)
                        current_data = container_inspect(candidate["container"])
                        check_container_labels(candidate, current_data)
                        current_identity = identity_from_inspect(current_data)
                        context = {
                            "action_id": f"{now}-{candidate['name']}-{action}", "time": now,
                            "egress": candidate, "action": action, "pre_identity": identity_key(current_identity),
                            "reason": candidate_state.get("reason"),
                            "reason_scope": candidate_state.get("reason_scope"),
                            "probe_instance": candidate_state.get("probe_instance"),
                            "probe_generation": candidate_state.get("probe_generation"),
                        }
                        journal["pending"] = {
                            "action_id": context["action_id"], "time": now, "egress": candidate["name"],
                            "action": action, "pre_identity": context["pre_identity"],
                            "status": "intent_recorded",
                        }
                        save_recovery_journal(journal)
                        recovery_log(
                            "intent_recorded", action_id=context["action_id"],
                            egress=candidate["name"], action=action,
                            reason=context["reason"], reason_scope=context["reason_scope"],
                            probe_instance=context["probe_instance"],
                            probe_generation=context["probe_generation"],
                            pre_identity=context["pre_identity"],
                        )
                        journal["pending"]["status"] = "rpc_dispatched"
                        save_recovery_journal(journal)
                        recovery_log(
                            "rpc_dispatched", action_id=context["action_id"],
                            egress=candidate["name"], action=action,
                        )
                        recovery_context = context
                        recovery_future = recovery_executor.submit(recovery_action, context)
                        journal_changed = False
                    finally:
                        fcntl.flock(lock_stream, fcntl.LOCK_UN)
                        lock_stream.close()

            if journal_valid and journal_changed and journal.get("pending") is None:
                save_recovery_journal(journal)

            operational = {
                "time": now, "release": RELEASE_ID, "mode": mode,
                "healthy": [item["name"] for item in EGRESSES if states[item["name"]]["healthy"]],
                "eligible": [item["name"] for item in eligible],
                "quarantined": sorted(effective_quarantine), "bucket_counts": counts,
                "generation": generation, "ingress_identity": ingress_identity,
                "egress_identities": identities, "infra_valid": common_valid,
                "infra_error": common_error, "maintenance": maintenance,
                "admission_open": admission_open, "recovery_enabled": RECOVERY_ENABLED,
                "recovery_allowed_egresses": sorted(RECOVERY_ALLOWED),
                "recovery_allow_crashloop_containment": RECOVERY_ALLOW_CRASHLOOP_CONTAINMENT,
                "recovery_journal_valid": journal_valid, "recovery_journal_error": journal_error,
                "recovery_pending": journal.get("pending") if journal_valid else None,
                "retired_quarantined_marks": sorted(RETIRED_MARKS),
                "egresses": states,
            }
            atomic_json(STATE, operational, mode=0o644)
            summary = (
                mode, tuple(operational["eligible"]), tuple(operational["quarantined"]),
                tuple(
                    (
                        name, states[name].get("reason"), states[name].get("failures"),
                        states[name].get("recoverable_failures"),
                    )
                    for name in sorted(states)
                ),
                tuple(sorted(counts.items())), common_error,
                json.dumps(operational["recovery_pending"], sort_keys=True),
            )
            if summary != last_log:
                print(
                    f"mode={mode} eligible={','.join(operational['eligible']) or '-'} "
                    f"quarantine={','.join(operational['quarantined']) or '-'} buckets={counts} "
                    f"recovery_pending={operational['recovery_pending']}", flush=True,
                )
                last_log = summary

            wait_until(loop_started + INTERVAL)
    except Exception as exc:
        print(f"controller fatal: {exc}", file=sys.stderr, flush=True)
        try:
            set_policy([FAIL_MARK] * 256, {item["name"] for item in EGRESSES})
        except Exception as close_exc:
            print(f"fail-closed policy error: {close_exc}", file=sys.stderr, flush=True)
        close_admission()
        return 1
    finally:
        stopping = True
        try:
            set_policy([FAIL_MARK] * 256, {item["name"] for item in EGRESSES})
        except Exception as exc:
            print(f"shutdown fail-closed error: {exc}", file=sys.stderr, flush=True)
        close_admission()
        recovery_executor.shutdown(wait=True, cancel_futures=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
