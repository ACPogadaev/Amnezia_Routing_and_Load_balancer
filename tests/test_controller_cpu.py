import copy
from pathlib import Path
import types
import unittest
from unittest.mock import patch

from test_controller_recovery import controller as c, BASE


class ControllerCpuTests(unittest.TestCase):
    def setUp(self):
        self.identity = {"container_id": "id", "started_at": "2026-11-02T00:00:00Z", "pid": 42, "netns_inode": 123, "restart_count": 0}
        self.egress = c.EGRESSES[0]
        c.forwarding_ready.clear()

    def test_forwarding_setup_only_for_new_identity_and_live_sysctl_drift(self):
        healthy = {"healthy": True, "reason": "ok"}
        disabled = {"healthy": False, "reason": "forwarding_disabled"}
        with patch.object(c, "docker_exec", return_value=types.SimpleNamespace(returncode=0, stdout="instance")), \
             patch.object(c, "enable_forwarding") as enable, \
             patch.object(c, "functional_probe", side_effect=[healthy, healthy, disabled, healthy]), \
             patch.object(c, "container_inspect", return_value={}), \
             patch.object(c, "identity_from_inspect", return_value=self.identity):
            c.probe_one(self.egress, self.identity)
            c.probe_one(self.egress, self.identity)
            self.assertEqual(enable.call_count, 1)
            c.probe_one(self.egress, self.identity)
            self.assertEqual(enable.call_count, 2)

    def test_instance_change_requires_forwarding_validation_again(self):
        with patch.object(c, "docker_exec", side_effect=[types.SimpleNamespace(returncode=0, stdout="first"), types.SimpleNamespace(returncode=0, stdout="second")]), \
             patch.object(c, "enable_forwarding") as enable, \
             patch.object(c, "functional_probe", return_value={"healthy": True}), \
             patch.object(c, "container_inspect", return_value={}), \
             patch.object(c, "identity_from_inspect", return_value=self.identity):
            c.probe_one(self.egress, self.identity)
            c.probe_one(self.egress, self.identity)
            self.assertEqual(enable.call_count, 2)

    def test_same_failed_sample_does_not_advance_failure_threshold(self):
        snapshots = []
        cycle = [0]
        fake_checks = types.SimpleNamespace(begin_cycle=lambda: None, assert_config_current=lambda: None)
        def probe(egress, identity):
            failed = egress["name"] == "pgdl" and cycle[0] >= 3
            sample = "failure" if failed else f"ok-{cycle[0]}"
            return {"healthy": not failed, "reason": "https_unavailable" if failed else "ok",
                    "reason_scope": "network" if failed else "none", "sample_id": sample,
                    "rx_bytes": 100, "tx_bytes": 100}, identity
        def record(path, payload, **_kwargs):
            if path == c.STATE:
                snapshots.append(copy.deepcopy(payload))
        def wait(_deadline):
            cycle[0] += 1
            c.stopping = cycle[0] >= 6
        with patch.multiple(c, stopping=False, RECOVERY_ENABLED=False,
            run=lambda *_a, **_k: types.SimpleNamespace(returncode=0, stdout="", stderr=""),
            helper=lambda *_a, **_k: None, close_admission=lambda: None,
            get_runtime_checks=lambda: fake_checks,
            container_inspect=lambda *_a: {}, identity_from_inspect=lambda *_a: self.identity,
            check_ingress=lambda *_a: None, ensure_infrastructure=lambda: False,
            load_recovery_journal=lambda: (c.fresh_recovery_journal(), True, None),
            update_engine_history=lambda *_a: (False, False), save_recovery_journal=lambda *_a: None,
            set_policy=lambda *_a: None, validate_policy=lambda *_a: None,
            atomic_json=record, probe_one=probe, wait_until=wait):
            self.assertEqual(c.main(), 0)
        failed = [s["egresses"]["pgdl"]["failures"] for s in snapshots[3:]]
        self.assertEqual(failed, [1, 1, 1])
        self.assertTrue(snapshots[-1]["egresses"]["pgdl"]["healthy"])


if __name__ == "__main__":
    unittest.main()
