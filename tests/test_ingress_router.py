import contextlib
import importlib.util
import io
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock

from runtime_fixtures import ROOT

sys.path.insert(0, str(ROOT / "templates/v2/host"))
spec = importlib.util.spec_from_file_location("ingress_router", ROOT / "templates/v2/host/ingress-router.py")
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)


class IngressRouterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / "work")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.identity = ("container", "started", 42, 123)
        self.inspect_results = []
        self.fail_check = False
        self.fail_helper = None
        self.configured_by_repair = True
        self.calls = []
        self.check_hook = None
        self.checks = types.SimpleNamespace(
            env={"INGRESS_CHECK_INTERVAL_SECONDS": "10"}, begin_cycle=Mock(),
            inspect=self.inspect, identity=lambda data: data, check_docker_user=Mock(),
            check_ingress=self.check_ingress, assert_config_current=Mock(), invalidate=Mock(),
        )
        self.router = manager.IngressRouter(self.root / "v2", self.root / "run", checks=self.checks, runner=self.helper)

    def inspect(self):
        value = self.inspect_results.pop(0) if self.inspect_results else self.identity
        if isinstance(value, Exception):
            raise value
        return value

    def helper(self, args, **_kwargs):
        name = Path(args[0]).name
        self.calls.append((name, self.router.ready.exists()))
        if name == self.fail_helper:
            raise subprocess.CalledProcessError(1, args)
        if name == "ingress-configure.sh" and self.configured_by_repair:
            self.fail_check = False

    def check_ingress(self, pid):
        self.calls.append(("validate", pid))
        if self.check_hook is not None:
            self.check_hook()
        if self.fail_check:
            raise ValueError("broken ingress rules")

    def tick(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return self.router.tick()

    def test_restart_adopts_running_valid_ingress_without_unnecessary_repair(self):
        self.router.ready.write_text("42\n")
        self.assertEqual(self.tick(), "ready")
        self.assertEqual(self.router.ready.read_text(), "42\n")
        self.assertEqual(self.router.last_identity, self.identity)
        self.assertNotIn("network-ensure.sh", [name for name, _ in self.calls])
        self.assertEqual(self.tick(), "ready")

    def test_changed_pid_and_reused_pid_with_new_namespace_replace_readiness(self):
        self.tick()
        for identity in (("container", "new-start", 43, 124), ("container", "next-start", 43, 125)):
            with self.subTest(identity=identity):
                self.identity = identity
                self.check_hook = lambda: self.assertFalse(self.router.ready.exists())
                self.assertEqual(self.tick(), "ready")
                self.assertEqual(self.router.last_identity, identity)
                self.assertEqual(self.router.ready.read_text().strip(), str(identity[2]))

    def test_error_removes_readiness_and_closes_admission_before_repair(self):
        self.tick()
        self.calls.clear()
        self.fail_check = True
        self.assertEqual(self.tick(), "ready")
        names = [name for name, _ in self.calls]
        self.assertLess(names.index("policy-down.sh"), names.index("network-ensure.sh"))
        for name, ready_exists in self.calls:
            if name in {"policy-down.sh", "network-ensure.sh", "transit-host-up.sh", "ingress-configure.sh", "docker-user-install.sh"}:
                self.assertFalse(ready_exists, name)
        self.checks.invalidate.assert_called_once()

    def test_failed_repair_exits_without_republishing_or_retrying(self):
        self.router.ready.write_text("42\n")
        self.fail_check = True
        self.fail_helper = "ingress-configure.sh"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.router.run(handle_signals=False), 1)
        self.assertFalse(self.router.ready.exists())
        self.assertEqual([name for name, _ in self.calls].count("network-ensure.sh"), 1)
        self.assertNotIn("docker-user-install.sh", [name for name, _ in self.calls])

    def test_failed_readback_never_publishes_readiness(self):
        self.fail_check = True
        self.configured_by_repair = False
        with self.assertRaisesRegex(ValueError, "broken ingress"):
            self.tick()
        self.assertFalse(self.router.ready.exists())
        self.assertEqual([name for name, _ in self.calls].count("network-ensure.sh"), 1)

    def test_failed_policy_down_prevents_all_repair_writes(self):
        self.fail_check = True
        self.fail_helper = "policy-down.sh"
        with self.assertRaises(subprocess.CalledProcessError):
            self.tick()
        self.assertFalse(self.router.ready.exists())
        self.assertNotIn("network-ensure.sh", [name for name, _ in self.calls])

    def test_sigterm_cannot_publish_readiness_after_validation(self):
        previous = signal.getsignal(signal.SIGTERM)
        self.check_hook = lambda: signal.raise_signal(signal.SIGTERM)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.router.run(), 0)
        self.assertIs(signal.getsignal(signal.SIGTERM), previous)
        self.assertFalse(self.router.ready.exists())
        self.assertFalse(self.router.temporary.exists())
        self.assertIn("policy-down.sh", [name for name, _ in self.calls])
        self.assertNotIn("network-ensure.sh", [name for name, _ in self.calls])

    def test_docker_restart_clears_readiness_then_adopts_new_identity(self):
        self.tick()
        self.inspect_results = [subprocess.CalledProcessError(1, ["docker", "inspect"])]
        self.assertEqual(self.tick(), "unavailable")
        self.assertFalse(self.router.ready.exists())
        self.assertIsNone(self.router.last_identity)
        self.identity = ("container", "docker-restarted", 55, 200)
        self.assertEqual(self.tick(), "ready")
        self.assertEqual(self.router.ready.read_text(), "55\n")

    def test_identity_changing_during_repair_readback_is_rejected(self):
        changed = ("container", "other-start", 66, 300)
        self.fail_check = True
        self.inspect_results = [self.identity, self.identity, changed]
        with self.assertRaisesRegex(ValueError, "identity changed"):
            self.tick()
        self.assertFalse(self.router.ready.exists())

    def test_repeated_repairs_without_stable_cycle_are_bounded(self):
        for _ in range(self.router.MAX_CONSECUTIVE_REPAIRS):
            self.fail_check = True
            self.assertEqual(self.tick(), "ready")
        self.fail_check = True
        with self.assertRaisesRegex(RuntimeError, "stable cycle"):
            self.tick()
        self.assertFalse(self.router.ready.exists())
        self.assertEqual([name for name, _ in self.calls].count("network-ensure.sh"), 3)

    def test_shutdown_interrupts_idle_wait_and_closes_admission(self):
        # Use a real Event so this test also verifies the wait path without a
        # timed sleep: the injected wait requests a stop after one valid tick.
        self.router.stopped.wait = lambda _interval: self.router.request_stop()
        self.assertEqual(self.router.run(handle_signals=False), 0)
        self.assertFalse(self.router.ready.exists())


if __name__ == "__main__":
    unittest.main()
