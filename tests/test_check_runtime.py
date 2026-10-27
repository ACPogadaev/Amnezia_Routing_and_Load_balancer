#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECK = ROOT / "tools" / "check-runtime.py"


class RuntimeCheckTests(unittest.TestCase):
    def run_check(self, state: dict):
        scratch = ROOT / "work"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            directory = pathlib.Path(temporary)
            state_path = directory / "state.json"
            egress_path = directory / "egresses.json"
            state_path.write_text(json.dumps(state), encoding="utf-8")
            egress_path.write_text(json.dumps([{"name": "main"}, {"name": "pgdl"}]), encoding="utf-8")
            return subprocess.run(
                [
                    sys.executable,
                    str(CHECK),
                    "--state",
                    str(state_path),
                    "--egresses",
                    str(egress_path),
                    "--now",
                    "1000",
                ],
                text=True,
                capture_output=True,
            )

    @staticmethod
    def baseline():
        return {
            "time": 995,
            "release": "test",
            "mode": "balanced",
            "healthy": ["main", "pgdl"],
            "eligible": ["main", "pgdl"],
            "bucket_counts": {"main": 128, "pgdl": 128, "fail": 0},
            "infra_valid": True,
            "maintenance": False,
            "admission_open": True,
            "recovery_journal_valid": True,
            "recovery_journal_error": None,
            "recovery_pending": None,
        }

    def test_balanced_is_ok(self):
        result = self.run_check(self.baseline())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "OK")

    def test_degraded_is_warning(self):
        state = self.baseline()
        state.update(mode="degraded", healthy=["main"], eligible=["main"])
        state["bucket_counts"] = {"main": 256, "pgdl": 0, "fail": 0}
        result = self.run_check(state)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_stale_and_unknown_recovery_are_critical(self):
        stale = self.baseline()
        stale["time"] = 900
        self.assertEqual(self.run_check(stale).returncode, 2)
        unknown = self.baseline()
        unknown["recovery_pending"] = {"status": "outcome_unknown"}
        self.assertEqual(self.run_check(unknown).returncode, 2)


if __name__ == "__main__":
    unittest.main()
