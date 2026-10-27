#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.modules.setdefault("fcntl", types.SimpleNamespace(LOCK_EX=2, LOCK_UN=8, flock=lambda *_args: None))
spec = importlib.util.spec_from_file_location(
    "recovery_resolver", ROOT / "templates/v3/host/recovery-resolve.py"
)
resolver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resolver)


def fixture():
    return {
        "schema_version": 2,
        "pending": {
            "action_id": "123-pgdl-restart",
            "time": 100,
            "egress": "pgdl",
            "action": "restart",
            "pre_identity": None,
            "status": "outcome_unknown",
        },
        "egresses": {
            "main": {"last_outcome": None, "attempts": []},
            "pgdl": {"last_outcome": None, "attempts": [100]},
        },
    }


class RecoveryResolverTests(unittest.TestCase):
    def test_resolution_preserves_budget_and_clears_only_matching_fence(self):
        journal = fixture()
        resolved = resolver.resolve_document(
            journal,
            "123-pgdl-restart",
            "completed",
            {"evidence_sha256": "abc", "evidence_file": "/evidence", "operator_summary": "checked"},
            {"main", "pgdl"},
            "release",
            200,
        )
        self.assertIsNone(resolved["pending"])
        self.assertEqual(resolved["egresses"]["pgdl"]["attempts"], [100])
        self.assertEqual(resolved["egresses"]["pgdl"]["last_outcome"]["action_id"], "123-pgdl-restart")
        self.assertEqual(resolved["manual_resolutions"][-1]["status"], "manually_resolved_completed")

    def test_wrong_action_or_non_unknown_is_rejected(self):
        for mutation, action_id in ((None, "wrong"), ("rpc_dispatched", "123-pgdl-restart")):
            journal = fixture()
            if mutation:
                journal["pending"]["status"] = mutation
            with self.assertRaises(ValueError):
                resolver.resolve_document(
                    copy.deepcopy(journal),
                    action_id,
                    "not-executed",
                    {},
                    {"main", "pgdl"},
                    "release",
                    200,
                )


if __name__ == "__main__":
    unittest.main()
