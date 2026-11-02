#!/usr/bin/env python3
"""Ingress reconciliation with a persistent, batched read-only validator."""
import os
from pathlib import Path
import signal
import subprocess
import time

from runtime_checks import RuntimeChecks


def main():
    base = Path(os.environ.get("AMNEZIA_LB_DIR", "/etc/amnezia-lb-v2"))
    runtime = Path("/run/amnezia-lb-v2")
    runtime.mkdir(parents=True, exist_ok=True)
    ready = runtime / "ingress.ready"
    checks = RuntimeChecks(base)
    stopping = False
    last_identity = None

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    def helper(name):
        subprocess.run([str(base / "host" / name)], check=True, timeout=60)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while not stopping:
            checks.begin_cycle()
            try:
                identity = checks.identity(checks.inspect())
            except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                identity = None
            if identity is None:
                ready.unlink(missing_ok=True)
                last_identity = None
            else:
                try:
                    if identity != last_identity or not ready.is_file() or ready.read_text().strip() != str(identity[2]):
                        raise ValueError("new ingress identity or missing readiness")
                    helper("transit-host-check.sh")
                    checks.check_docker_user(2)
                    checks.check_ingress(identity[2])
                except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                    ready.unlink(missing_ok=True)
                    helper("policy-down.sh")
                    print(f"ingress reconciliation: {error}", flush=True)
                    helper("network-ensure.sh")
                    helper("transit-host-up.sh")
                    helper("ingress-configure.sh")
                    helper("docker-user-install.sh")
                    checks.invalidate()
                    # Never publish readiness using the PID from before repair.
                    identity = checks.identity(checks.inspect())
                    checks.check_docker_user(2)
                    checks.check_ingress(identity[2])
                    temporary = ready.with_suffix(".tmp")
                    temporary.write_text(str(identity[2]) + "\n", encoding="utf-8")
                    temporary.replace(ready)
                    last_identity = identity
            # Preserve the existing manager's interval after work, without
            # a process spawn for sleep and without delaying service signals.
            deadline = time.monotonic() + int(checks.env["INGRESS_CHECK_INTERVAL_SECONDS"])
            while not stopping and time.monotonic() < deadline:
                time.sleep(min(0.5, max(0, deadline - time.monotonic())))
    finally:
        ready.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
