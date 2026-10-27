#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "work"
WORK.mkdir(exist_ok=True)
TEMP = tempfile.TemporaryDirectory(dir=WORK)
BASE = Path(TEMP.name)
(BASE / "multi.env").write_text(
    "\n".join(
        (
            f"V2_DIR={BASE / 'v2'}",
            f"RUNTIME_DIR={BASE / 'run'}",
            "RELEASE_ID=test-release",
            f"STATE_ROOT={BASE / 'state'}",
            f"LOCK_FILE={BASE / 'state.lock'}",
            f"MAINTENANCE_FILE={BASE / 'maintenance'}",
            f"MODE_FILE={BASE / 'mode'}",
            "INGRESS_CONTAINER=ingress",
            "FAIL_MARK=0x2ff",
            "RETIRED_MARKS=0x203",
            "HEALTH_INTERVAL_SECONDS=10",
            "HEALTH_FAILURE_THRESHOLD=3",
            "HEALTH_SUCCESS_THRESHOLD=3",
            "HEALTH_MAX_HANDSHAKE_AGE_SECONDS=300",
            "HEALTH_MAX_SAMPLE_AGE_SECONDS=45",
            "ALLOW_LEGACY_PROBE=0",
            "LOAD_EWMA_ALPHA=0.35",
            "LOAD_REFERENCE_BPS=1048576",
            "LOAD_WEIGHT_FLOOR=0.25",
            "HEALTH_PROBE_TIMEOUT_SECONDS=15",
            "HEALTH_URL=https://example.invalid/trace",
            "HEALTH_URL_SECONDARY=https://example.invalid/ip.json",
            "RECOVERY_ENABLED=1",
            "RECOVERY_ALLOWED_EGRESSES=pgdl",
            "RECOVERY_ALLOW_CRASHLOOP_CONTAINMENT=0",
            "RECOVERY_FAILURE_THRESHOLD=6",
            "RECOVERY_COOLDOWN_SECONDS=300",
            "RECOVERY_WINDOW_SECONDS=1800",
            "RECOVERY_MAX_RESTARTS=3",
            "RECOVERY_MAX_PARALLEL=1",
            "RECOVERY_STARTUP_GRACE_SECONDS=90",
            f"RECOVERY_STATE_FILE={BASE / 'state/recovery.json'}",
            f"RECOVERY_LOCK_FILE={BASE / 'state/recovery.lock'}",
            f"DRAIN_DIR={BASE / 'state/drain'}",
        )
    )
    + "\n",
    encoding="utf-8",
)
(BASE / "egresses.json").write_text(
    json.dumps(
        [
            {
                "name": "main", "container": "main", "awg_if": "awg-main",
                "awg_ip": "10.9.0.2", "expected_exit_ip": "192.0.2.10", "mark": 0x201,
                "compose_project": "egress", "compose_service": "egress-main",
                "compose_file": "/etc/example/main.yaml", "ready_file": "/run/main",
                "forward_helper": "/bin/true",
            },
            {
                "name": "pgdl", "container": "pgdl", "awg_if": "awg-pgdl",
                "awg_ip": "10.9.0.3", "expected_exit_ip": "192.0.2.20", "mark": 0x202,
                "compose_project": "egress", "compose_service": "egress-pgdl",
                "compose_file": "/etc/example/pgdl.yaml", "ready_file": "/run/pgdl",
                "forward_helper": "/bin/true",
            },
        ]
    ),
    encoding="utf-8",
)
OLD_BASE = os.environ.get("AMNEZIA_LB_MULTI_DIR")
os.environ["AMNEZIA_LB_MULTI_DIR"] = str(BASE)
sys.modules.setdefault("fcntl", types.SimpleNamespace(LOCK_EX=2, LOCK_UN=8, flock=lambda *_args: None))
SPEC = importlib.util.spec_from_file_location("controller_recovery_test", ROOT / "templates/v3/host/controller.py")
controller = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(controller)
if OLD_BASE is None:
    os.environ.pop("AMNEZIA_LB_MULTI_DIR", None)
else:
    os.environ["AMNEZIA_LB_MULTI_DIR"] = OLD_BASE


class ControllerRecoveryTests(unittest.TestCase):
    def test_wait_until_never_sleeps_negative(self):
        old_monotonic, old_sleep, old_stopping = controller.time.monotonic, controller.time.sleep, controller.stopping
        sleeps = []
        readings = iter([9.999, 10.001])
        try:
            controller.stopping = False
            controller.time.monotonic = lambda: next(readings)
            controller.time.sleep = lambda delay: sleeps.append(delay) if delay >= 0 else self.fail("negative sleep")
            controller.wait_until(10.0)
            self.assertEqual(len(sleeps), 1)
            self.assertGreater(sleeps[0], 0)
        finally:
            controller.time.monotonic, controller.time.sleep, controller.stopping = old_monotonic, old_sleep, old_stopping

    def test_lifecycle_scope_and_recoverable_counter(self):
        self.assertTrue(controller.lifecycle_authorized("pgdl", "restart"))
        self.assertFalse(controller.lifecycle_authorized("main", "restart"))
        self.assertFalse(controller.lifecycle_authorized("pgdl", "stop"))
        state = {"recoverable_failures": 0, "recoverable_reason": None}
        collector = {"healthy": False, "reason": "probe_output_invalid", "reason_scope": "collector"}
        local = {"healthy": False, "reason": "interface_down", "reason_scope": "local"}
        controller.update_recoverable_streak(state, collector, True)
        self.assertEqual(state["recoverable_failures"], 0)
        controller.update_recoverable_streak(state, local, True)
        self.assertEqual(state["recoverable_failures"], 1)

    def test_budget_is_durable_and_exhausts(self):
        now = 10_000
        record = {"attempts": [now - 10], "recovery_exhausted": False}
        decision, remaining, _ = controller.evaluate_recovery_budget(record, now)
        self.assertEqual(decision, "cooldown")
        self.assertEqual(remaining, controller.RECOVERY_COOLDOWN - 10)
        record = {"attempts": [now - 900, now - 600, now - 300], "recovery_exhausted": False}
        decision, _, changed = controller.evaluate_recovery_budget(record, now)
        self.assertEqual(decision, "exhausted")
        self.assertTrue(changed)
        self.assertTrue(record["recovery_exhausted"])

    def test_changed_identity_remains_outcome_unknown(self):
        before = {"container_id": "id", "started_at": "before", "pid": 42, "netns_inode": 123, "restart_count": 0}
        after = {"container_id": "id", "started_at": "after", "pid": 43, "netns_inode": 124, "restart_count": 0}
        pending = {
            "action_id": "old-restart", "time": 100, "egress": "main", "action": "restart",
            "pre_identity": list(controller.identity_key(before)), "status": "rpc_dispatched",
        }
        journal = controller.fresh_recovery_journal()
        journal["pending"] = pending
        saved = []
        old_inspect, old_identity = controller.container_inspect, controller.identity_from_inspect
        old_save, old_log = controller.save_recovery_journal, controller.recovery_log
        try:
            controller.container_inspect = lambda _name: {"state": "mock"}
            controller.identity_from_inspect = lambda _data: after
            controller.save_recovery_journal = lambda data: saved.append(copy.deepcopy(data))
            controller.recovery_log = lambda *_args, **_kwargs: None
            controller.reconcile_pending_action(journal, pending)
        finally:
            controller.container_inspect, controller.identity_from_inspect = old_inspect, old_identity
            controller.save_recovery_journal, controller.recovery_log = old_save, old_log
        self.assertEqual(journal["pending"]["status"], "outcome_unknown")
        self.assertTrue(journal["pending"]["effect_observed"])
        self.assertTrue(saved and saved[-1]["pending"] is not None)


if __name__ == "__main__":
    unittest.main()
