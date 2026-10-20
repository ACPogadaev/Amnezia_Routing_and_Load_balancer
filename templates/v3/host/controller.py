#!/usr/bin/env python3
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
from pathlib import Path

BASE = Path(os.environ.get("AMNEZIA_LB_MULTI_DIR", "/etc/amnezia-lb-multi-v3"))


def read_env(path):
    result = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key] = value
    return result


ENV = read_env(BASE / "multi.env")
EGRESSES = json.loads((BASE / "egresses.json").read_text())
RUNTIME = Path(ENV["RUNTIME_DIR"])
STATE = RUNTIME / "state.json"
STATE_ROOT = Path(ENV["STATE_ROOT"])
MAINTENANCE = Path(ENV["MAINTENANCE_FILE"])
MODE_FILE = Path(ENV["MODE_FILE"])
RELEASE_ID = ENV["RELEASE_ID"]
FAIL_MARK = int(ENV["FAIL_MARK"], 0)
INTERVAL = int(ENV["HEALTH_INTERVAL_SECONDS"])
TIMEOUT = int(ENV["HEALTH_TIMEOUT_SECONDS"])
FAIL_THRESHOLD = int(ENV["HEALTH_FAILURE_THRESHOLD"])
SUCCESS_THRESHOLD = int(ENV["HEALTH_SUCCESS_THRESHOLD"])
MAX_HANDSHAKE_AGE = int(ENV["HEALTH_MAX_HANDSHAKE_AGE_SECONDS"])
ALPHA = float(ENV["LOAD_EWMA_ALPHA"])
REFERENCE_BPS = float(ENV["LOAD_REFERENCE_BPS"])
WEIGHT_FLOOR = float(ENV["LOAD_WEIGHT_FLOOR"])
stopping = False


def run(args, *, timeout=15, check=True, text=True):
    return subprocess.run(args, check=check, capture_output=True, text=text, timeout=timeout)


def helper(path, *args):
    run([path, *args], timeout=20)


def docker_exec(container, args, timeout=15):
    return run(["docker", "exec", container, *args], timeout=timeout).stdout


def enable_forwarding(egress):
    if egress["name"] == "main":
        helper(egress["forward_helper"])
    else:
        helper(egress["forward_helper"], egress["container"], egress["ready_file"])


def read_bytes(egress):
    out = docker_exec(
        egress["container"],
        ["sh", "-c", f"cat /sys/class/net/{egress['awg_if']}/statistics/rx_bytes; "
                       f"cat /sys/class/net/{egress['awg_if']}/statistics/tx_bytes"],
        timeout=5,
    )
    values = [int(x) for x in out.split()]
    if len(values) != 2:
        raise RuntimeError("invalid byte counters")
    return sum(values)


def probe(egress):
    running = run(
        ["docker", "inspect", "-f", "{{.State.Running}}", egress["container"]],
        timeout=5,
    ).stdout.strip()
    if running != "true":
        raise RuntimeError("container is not running")
    docker_exec(egress["container"], ["test", "-s", egress["ready_file"]], timeout=5)
    enable_forwarding(egress)

    observed = ""
    observer = ""
    observer_errors = []
    for name, url in (
        ("primary", ENV["HEALTH_URL"]),
        ("secondary", ENV["HEALTH_URL_SECONDARY"]),
    ):
        try:
            trace = docker_exec(
                egress["container"],
                ["curl", "--silent", "--show-error", "--fail", "--ipv4",
                 "--max-time", str(TIMEOUT), "--interface", egress["awg_ip"], url],
                timeout=TIMEOUT + 3,
            )
            candidate = next(
                (line[3:].strip() for line in trace.splitlines() if line.startswith("ip=")),
                trace.strip().splitlines()[0] if trace.strip() else "",
            )
            if candidate == egress["expected_exit_ip"]:
                observed = candidate
                observer = name
                break
            observer_errors.append(f"{name}: exit IP {candidate or 'missing'}")
        except Exception as exc:
            observer_errors.append(f"{name}: {exc}")
    if not observed:
        raise RuntimeError("; ".join(observer_errors))

    banner_result = subprocess.run(
        ["docker", "exec", egress["container"], "curl", "--silent", "--ipv4",
         "--max-time", "3", "--interface", egress["awg_ip"],
         f"telnet://{ENV['TARGET_IP']}:{ENV['TARGET_TCP_PORT']}"],
        capture_output=True, text=True, timeout=6,
    )
    banner_ok = "SSH-2.0-" in banner_result.stdout

    handshakes = docker_exec(
        egress["container"], ["awg", "show", egress["awg_if"], "latest-handshakes"], timeout=5
    )
    timestamps = []
    for line in handshakes.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            timestamps.append(int(parts[1]))
    latest = max(timestamps, default=0)
    age = int(time.time()) - latest
    if latest <= 0 or age < 0 or age > MAX_HANDSHAKE_AGE:
        raise RuntimeError(f"handshake age {age}")
    return read_bytes(egress), observed, age, observer, banner_ok


def rendezvous_map(healthy):
    result = []
    for bucket in range(256):
        best = None
        for egress in healthy:
            digest = hashlib.sha256(f"amnezia-v3:{bucket}:{egress['name']}".encode()).digest()
            u = (int.from_bytes(digest, "big") + 1) / ((1 << 256) + 1)
            score = -math.log(u) / egress["weight"]
            candidate = (score, egress["name"], egress["mark"])
            if best is None or candidate < best:
                best = candidate
        result.append(best[2] if best else FAIL_MARK)
    return result


def nft_transaction(rules):
    subprocess.run(["nft", "-c", "-f", "-"], input=rules, text=True, check=True, timeout=10)
    subprocess.run(["nft", "-f", "-"], input=rules, text=True, check=True, timeout=10)


def set_map(marks):
    lines = ["flush chain inet amnezia_lb_balance_v3 select"]
    names = {e["mark"]: e["name"] for e in EGRESSES}
    for mark in sorted(names):
        buckets = [f"0.0.0.{i}" for i, assigned in enumerate(marks) if assigned == mark]
        if buckets:
            lines.append(
                "add rule inet amnezia_lb_balance_v3 select "
                f"ip daddr & 0.0.0.255 {{ {', '.join(buckets)} }} "
                f"meta mark set 0x{mark:08x} return "
                f"comment \"v3 buckets {names[mark]}\""
            )
    lines.append(
        "add rule inet amnezia_lb_balance_v3 select "
        "meta mark set 0x000002ff comment \"v3 select fail\""
    )
    nft_transaction("\n".join(lines) + "\n")
    helper(str(BASE / "host/balance-check.sh"))


def namespace_identity(container):
    raw = run(
        ["docker", "inspect", "-f", "{{.Id}}|{{.State.StartedAt}}|{{.State.Pid}}", container],
        timeout=5,
    ).stdout.strip()
    container_id, started_at, raw_pid = raw.split("|", 2)
    pid = int(raw_pid)
    if pid <= 0:
        raise RuntimeError(f"{container} has no network namespace")
    return {
        "container_id": container_id,
        "started_at": started_at,
        "pid": pid,
        "netns_inode": os.stat(f"/proc/{pid}/ns/net").st_ino,
    }


def namespace_identities():
    names = [ENV["INGRESS_CONTAINER"]] + [item["container"] for item in EGRESSES]
    return {name: namespace_identity(name) for name in names}


def check_ingress(identity):
    ready = Path("/run/amnezia-lb-v2/ingress.ready")
    if not ready.is_file() or ready.read_text().strip() != str(identity["pid"]):
        raise RuntimeError("ingress readiness does not match current namespace")
    run([str(Path(ENV["V2_DIR"]) / "host/ingress-check.sh"), str(identity["pid"])], timeout=20)
    run([str(Path(ENV["V2_DIR"]) / "host/ingress-targets-check.sh")], timeout=20)


def close_admission():
    run([str(Path(ENV["V2_DIR"]) / "host/policy-down.sh")], timeout=20)


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
        if subprocess.run(check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            close_admission()
            run(repair, timeout=30)
            run(check, timeout=20)
            repaired = True
    return repaired


def atomic_state(payload):
    RUNTIME.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="state.", dir=RUNTIME)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(payload, stream, sort_keys=True, indent=2)
            stream.write("\n")
        os.replace(name, STATE)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def fail_closed(states, reason):
    try:
        set_map([FAIL_MARK] * 256)
    except Exception as exc:
        reason = f"{reason}; fail-map error: {exc}"
    subprocess.run([str(Path(ENV["V2_DIR"]) / "host/policy-down.sh")], check=False)
    atomic_state({
        "time": int(time.time()), "release": RELEASE_ID, "mode": "fail-closed",
        "reason": reason, "infra_valid": False, "maintenance": MAINTENANCE.exists(),
        "admission_open": False, "egresses": states,
    })


def stop_handler(_signum, _frame):
    global stopping
    stopping = True


def main():
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    RUNTIME.mkdir(mode=0o755, parents=True, exist_ok=True)
    states = {
        e["name"]: {
            "healthy": False, "successes": 0, "failures": 0, "error": "starting",
            "bps_ewma": 0.0, "last_bytes": None, "last_sample": None,
        } for e in EGRESSES
    }
    last_marks = None
    generation = None
    try:
        fail_closed(states, "warming up")
        while not stopping:
            loop_started = time.monotonic()
            now_wall = time.time()
            infra_valid = False
            infra_error = None
            identities = {}
            repaired = False
            try:
                identities = namespace_identities()
                check_ingress(identities[ENV["INGRESS_CONTAINER"]])
                repaired = ensure_infrastructure()
                current_identities = namespace_identities()
                if current_identities != identities:
                    raise RuntimeError("container namespace changed during reconciliation")
                identities = current_identities
                if repaired:
                    last_marks = None
                infra_valid = True
            except Exception as exc:
                infra_error = str(exc)
                close_admission()

            probe_results = {}
            if infra_valid:
                with ThreadPoolExecutor(max_workers=len(EGRESSES)) as executor:
                    pending = {executor.submit(probe, egress): egress for egress in EGRESSES}
                    for future in as_completed(pending):
                        egress = pending[future]
                        try:
                            probe_results[egress["name"]] = (future.result(), None)
                        except Exception as exc:
                            probe_results[egress["name"]] = (None, exc)

            for egress in EGRESSES:
                state = states[egress["name"]]
                if not infra_valid:
                    state["healthy"] = False
                    state["successes"] = 0
                    state["failures"] += 1
                    state["error"] = f"infrastructure: {infra_error}"
                    continue
                result, probe_error = probe_results[egress["name"]]
                try:
                    if probe_error is not None:
                        raise probe_error
                    total_bytes, observed, handshake_age, observer, banner_ok = result
                    if state["last_bytes"] is not None and total_bytes >= state["last_bytes"]:
                        elapsed = max(0.001, now_wall - state["last_sample"])
                        instant = (total_bytes - state["last_bytes"]) / elapsed
                        state["bps_ewma"] = ALPHA * instant + (1.0 - ALPHA) * state["bps_ewma"]
                    state["last_bytes"] = total_bytes
                    state["last_sample"] = now_wall
                    state["successes"] += 1
                    state["failures"] = 0
                    state["error"] = None
                    state["exit_ip"] = observed
                    state["handshake_age"] = handshake_age
                    state["observer"] = observer
                    state["ssh_diagnostic"] = "ok" if banner_ok else "unavailable"
                    if not state["healthy"] and state["successes"] >= SUCCESS_THRESHOLD:
                        state["healthy"] = True
                except Exception as exc:
                    state["failures"] += 1
                    state["successes"] = 0
                    state["error"] = str(exc)
                    if state["healthy"] and state["failures"] >= FAIL_THRESHOLD:
                        state["healthy"] = False

            healthy = []
            for egress in EGRESSES:
                state = states[egress["name"]]
                egress["weight"] = max(
                    WEIGHT_FLOOR, 1.0 / (1.0 + state["bps_ewma"] / REFERENCE_BPS)
                )
                state["weight"] = round(egress["weight"], 6)
                if state["healthy"]:
                    healthy.append(egress)

            marks = rendezvous_map(healthy)
            try:
                if marks != last_marks:
                    set_map(marks)
                    last_marks = marks
                elif infra_valid:
                    helper(str(BASE / "host/balance-check.sh"))
            except Exception as exc:
                infra_valid = False
                infra_error = f"selector: {exc}"
                healthy = []
                marks = [FAIL_MARK] * 256
                last_marks = None
                try:
                    set_map(marks)
                except Exception as fail_exc:
                    infra_error += f"; fail-map: {fail_exc}"
                close_admission()

            generation = hashlib.sha256(
                json.dumps(marks, separators=(",", ":")).encode("ascii")
            ).hexdigest()

            maintenance = MAINTENANCE.exists()
            admission_open = False
            if healthy and infra_valid and not maintenance:
                helper(str(Path(ENV["V2_DIR"]) / "host/policy-up.sh"))
                mode = "balanced" if len(healthy) == len(EGRESSES) else "degraded"
                admission_open = True
            else:
                helper(str(Path(ENV["V2_DIR"]) / "host/policy-down.sh"))
                mode = "reconciling" if maintenance or infra_valid else "fail-closed"

            counts = {e["name"]: marks.count(e["mark"]) for e in EGRESSES}
            counts["fail"] = marks.count(FAIL_MARK)
            atomic_state({
                "time": int(time.time()), "release": RELEASE_ID, "mode": mode,
                "healthy": [e["name"] for e in healthy],
                "bucket_counts": counts, "generation": generation,
                "namespaces": identities, "last_reconcile": int(time.time()),
                "infra_valid": infra_valid, "infra_error": infra_error,
                "maintenance": maintenance, "admission_open": admission_open,
                "egresses": states,
            })
            print(
                f"mode={mode} infra_valid={infra_valid} admission={admission_open} "
                f"healthy={','.join(e['name'] for e in healthy) or '-'} buckets={counts}",
                flush=True,
            )

            delay = max(0.0, INTERVAL - (time.monotonic() - loop_started))
            end = time.monotonic() + delay
            while not stopping and time.monotonic() < end:
                time.sleep(min(0.5, end - time.monotonic()))
    except Exception as exc:
        print(f"controller fatal: {exc}", file=sys.stderr, flush=True)
        try:
            fail_closed(states, f"controller fatal: {exc}")
        except Exception as close_exc:
            print(f"fail-closed reporting error: {close_exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        if stopping:
            try:
                fail_closed(states, "controller stopped")
            except Exception as close_exc:
                print(f"shutdown fail-closed error: {close_exc}", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
