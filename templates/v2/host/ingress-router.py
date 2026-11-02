#!/usr/bin/env python3
"""Ingress reconciliation with a persistent, batched read-only validator."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading

from runtime_checks import RuntimeChecks


CHECK_ERRORS = (OSError, ValueError, KeyError, subprocess.SubprocessError)


class StopRequested(Exception):
    pass


class IngressRouter:
    MAX_CONSECUTIVE_REPAIRS = 3

    def __init__(self, base, runtime, *, checks=None, runner=None, stop_event=None):
        self.base = Path(base)
        self.runtime = Path(runtime)
        self.runtime.mkdir(parents=True, exist_ok=True)
        self.ready = self.runtime / "ingress.ready"
        self.temporary = self.runtime / "ingress.ready.tmp"
        self.checks = checks if checks is not None else RuntimeChecks(self.base)
        self.runner = runner if runner is not None else subprocess.run
        self.stopped = stop_event if stop_event is not None else threading.Event()
        self.last_identity = None
        self.repairs = 0

    def request_stop(self, _signum=None, _frame=None):
        self.stopped.set()
        self.ready.unlink(missing_ok=True)

    def require_running(self):
        if self.stopped.is_set():
            raise StopRequested()

    def helper(self, name):
        self.require_running()
        self.runner([str(self.base / "host" / name)], check=True, timeout=60)
        self.require_running()

    def close_admission(self):
        # Also runs during shutdown, when ordinary helpers are prohibited.
        self.ready.unlink(missing_ok=True)
        self.runner([str(self.base / "host/policy-down.sh")], check=True, timeout=60)

    def current_identity(self):
        return self.checks.identity(self.checks.inspect())

    def validate(self, identity):
        self.helper("transit-host-check.sh")
        self.checks.check_docker_user(2)
        self.checks.check_ingress(identity[2])
        self.checks.assert_config_current()
        if self.current_identity() != identity:
            raise ValueError("ingress identity changed before readiness publication")
        self.require_running()

    def tick(self):
        self.require_running()
        self.checks.begin_cycle()
        try:
            identity = self.current_identity()
        except CHECK_ERRORS:
            self.close_admission()
            self.last_identity = None
            return "unavailable"
        if identity != self.last_identity:
            self.ready.unlink(missing_ok=True)
        try:
            # A service restart may adopt an already configured namespace only
            # after full validation; missing readiness alone does not force repair.
            self.validate(identity)
        except CHECK_ERRORS as error:
            self.close_admission()
            if self.repairs >= self.MAX_CONSECUTIVE_REPAIRS:
                raise RuntimeError("ingress repair did not reach a stable cycle; manual inspection required") from error
            self.repairs += 1
            print(f"ingress reconciliation attempt={self.repairs}: {error}", flush=True)
            for name in ("network-ensure.sh", "transit-host-up.sh", "ingress-configure.sh", "docker-user-install.sh"):
                self.helper(name)
            self.checks.invalidate()
            identity = self.current_identity()
            # A failed repair/readback exits the service; it never publishes a
            # ready PID or starts another repair inside the same tick.
            self.validate(identity)
        else:
            self.repairs = 0
        self.require_running()
        self.temporary.write_text(str(identity[2]) + "\n", encoding="utf-8")
        self.require_running()
        self.temporary.replace(self.ready)
        # SIGTERM can arrive between the check above and os.replace().
        if self.stopped.is_set():
            self.ready.unlink(missing_ok=True)
            raise StopRequested()
        self.last_identity = identity
        return "ready"

    def run(self, *, handle_signals=True):
        previous = {}
        if handle_signals:
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous[signum] = signal.signal(signum, self.request_stop)
        try:
            while not self.stopped.is_set():
                self.tick()
                interval = int(self.checks.env["INGRESS_CHECK_INTERVAL_SECONDS"])
                if interval <= 0:
                    raise ValueError("ingress check interval must be positive")
                self.stopped.wait(interval)
            return 0
        except StopRequested:
            return 0
        except Exception as error:
            print(f"ingress manager failed: {error}", file=sys.stderr, flush=True)
            return 1
        finally:
            self.ready.unlink(missing_ok=True)
            self.temporary.unlink(missing_ok=True)
            try:
                self.close_admission()
            except Exception as error:
                print(f"ingress admission close failed: {error}", file=sys.stderr, flush=True)
            for signum, handler in previous.items():
                signal.signal(signum, handler)


def main():
    import fcntl
    base = Path(os.environ.get("AMNEZIA_LB_DIR", "/etc/amnezia-lb-v2"))
    runtime = Path("/run/amnezia-lb-v2")
    runtime.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(runtime / "ingress-manager.lock", os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, "r+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("another ingress manager already holds the lock")
        (runtime / "ingress.ready").unlink(missing_ok=True)
        return IngressRouter(base, runtime).run()


if __name__ == "__main__":
    raise SystemExit(main())
