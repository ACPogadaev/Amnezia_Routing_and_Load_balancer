import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("verify_state", ROOT / "templates/v3/host/verify-state.py")
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class VerifyStateTests(unittest.TestCase):
    def setUp(self):
        self.inventory = [{"name": name, "mark": mark, "expected_exit_ip": address}
                          for name, mark, address in (("main", 513, "192.0.2.10"), ("pgdl", 514, "192.0.2.20"), ("ae", 515, "192.0.2.30"))]
        self.env = {"RECOVERY_ENABLED": "0", "RECOVERY_ALLOWED_EGRESSES": "", "RECOVERY_ALLOW_CRASHLOOP_CONTAINMENT": "0"}
        self.state = {
            "time": 1000, "release": "test", "infra_valid": True, "maintenance": True,
            "admission_open": False, "mode": "reconciling", "healthy": ["main", "pgdl", "ae"],
            "eligible": ["main", "pgdl", "ae"], "recovery_enabled": False,
            "recovery_allowed_egresses": [], "recovery_allow_crashloop_containment": False,
            "recovery_journal_valid": True, "recovery_journal_error": None, "recovery_pending": None,
            "retired_quarantined_marks": [], "bucket_counts": {"main": 0, "pgdl": 0, "ae": 0, "fail": 256},
            "egresses": {item["name"]: {"healthy": True, "eligible": True, "reason": "ok", "failures": 0, "exit_ip": item["expected_exit_ip"]} for item in self.inventory},
        }

    def validate(self, maintenance=True):
        return verify.validate_state(self.state, self.env, self.inventory, "test", maintenance=maintenance, now=1001)

    def test_maintenance_verifies_health_while_all_marks_remain_quarantined(self):
        expected = self.validate()
        self.assertEqual(expected, {513, 514, 515})
        verify.validate_quarantine({"nftables": [{"set": {"name": "quarantined_marks", "elem": [513, 514, 515]}}]}, expected)

    def test_regular_verify_requires_admission_and_active_buckets(self):
        with self.assertRaises(ValueError):
            self.validate(maintenance=False)
        self.state.update(maintenance=False, admission_open=True, mode="balanced", bucket_counts={"main": 85, "pgdl": 85, "ae": 86, "fail": 0})
        self.assertEqual(self.validate(maintenance=False), set())

    def test_maintenance_rejects_open_admission_or_assigned_buckets(self):
        for changes in ({"admission_open": True}, {"bucket_counts": {"main": 1, "pgdl": 0, "ae": 0, "fail": 255}}):
            original = copy.deepcopy(self.state)
            self.state.update(changes)
            with self.assertRaises(ValueError):
                self.validate()
            self.state = original

    def test_maintenance_rejects_enabled_recovery_stale_state_and_pending_actions(self):
        for changes in ({"time": 900}, {"time": 1002}, {"recovery_pending": {"status": "outcome_unknown"}},
                        {"infra_valid": False}, {"healthy": ["main", "pgdl"]}):
            original = copy.deepcopy(self.state)
            self.state.update(changes)
            with self.assertRaises(ValueError):
                self.validate()
            self.state = original
        self.env["RECOVERY_ENABLED"] = "1"
        self.state["recovery_enabled"] = True
        with self.assertRaisesRegex(ValueError, "requires recovery disabled"):
            self.validate()

    def test_missing_quarantine_mark_and_wrong_exit_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "quarantine readback"):
            verify.validate_quarantine({"nftables": [{"set": {"name": "quarantined_marks", "elem": [513, 514]}}]}, self.validate())
        self.state["egresses"]["ae"]["exit_ip"] = "192.0.2.99"
        with self.assertRaisesRegex(ValueError, "wrong exit IP"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
