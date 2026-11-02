import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from runtime_fixtures import ROOT, environment

spec = importlib.util.spec_from_file_location("prepare_cpu_upgrade", ROOT / "tools/prepare-cpu-upgrade.py")
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


class PrepareCpuUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / "work")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = environment(self.root)
        self.release = self.root / "release"
        for version in ("v2", "v3"):
            shutil.copytree(ROOT / "templates" / version, self.release / version,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"))
        entries = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(self.release).as_posix()}\n"
                   for path in sorted(self.release.rglob("*")) if path.is_file()]
        (self.release / "SHA256SUMS").write_text("".join(entries), encoding="utf-8")
        self.inventory = [
            {"name": name, "mark": mark, "container": "existing-" + name,
             "awg_ip": "10.9.0." + str(index), "expected_exit_ip": "192.0.2." + str(index),
             "compose_project": "existing-project", "compose_service": "existing-service-" + name}
            for name, mark, index in (("main", 513, 2), ("pgdl", 514, 3), ("ae", 515, 4))
        ]
        (self.root / "v3/egresses.json").write_text(json.dumps(self.inventory), encoding="utf-8")
        (self.root / "v2/active-target-v4.txt").write_bytes((self.root / "targets.txt").read_bytes())
        self.composes = {}
        for version, names in (("v2", {"main"}), ("v3", {"pgdl", "ae"})):
            document = {"name": "existing-project", "services": {
                item["compose_service"]: {"container_name": item["container"], "image": "existing-image",
                    "environment": {"EGRESS_AWG_IF": "existing-" + item["name"]},
                    "volumes": ["/private/profile-" + item["name"] + ":/existing/profile:ro"]}
                for item in self.inventory if item["name"] in names}, "networks": {"existing-net": {"external": True}}}
            self.composes[version] = document
            (self.root / (version + "-compose.json")).write_text(json.dumps(document), encoding="utf-8")
            (self.root / version / "egress").mkdir()
            (self.root / version / "egress/compose.yaml").write_text("local original compose")
            (self.root / version / "host").mkdir()
            (self.root / version / "host/guard-load.sh").write_text("local loader paired with local guard hashes")
            (self.root / version / "host/guard.create.nft").write_text("local endpoint ports and routes")
        self.output = self.root / "staged"

    def prepare(self):
        return upgrade.prepare(self.release, self.root / "v2", self.root / "v3", self.root / "v2-compose.json", self.root / "v3-compose.json", self.output)

    def test_stages_complete_payload_preserving_local_network_configuration(self):
        report = self.prepare()
        self.assertEqual(report["egresses"], ["main", "pgdl", "ae"])
        for version, envfile in (("v2", "pilot.env"), ("v3", "multi.env")):
            self.assertEqual((self.output / version / envfile).read_bytes(), (self.root / version / envfile).read_bytes())
            for path in ("host/guard-load.sh", "host/guard.create.nft"):
                self.assertEqual((self.output / version / path).read_bytes(), (self.root / version / path).read_bytes())
            staged_compose = json.loads((self.output / version / "egress/compose.yaml").read_text())
            expected = copy.deepcopy(self.composes[version])
            for service in expected["services"].values():
                service["environment"]["HEALTH_INTERVAL_SECONDS"] = "10"
            self.assertEqual(staged_compose, expected)
            for line in (self.output / version / "installed-manifest.sha256").read_text().splitlines():
                sha, live = line.split("  ", 1)
                relative = live.removeprefix(upgrade.LIVE[version] + "/")
                self.assertEqual(sha, upgrade.digest(self.output / version / relative))
        for relative in ("host/runtime_checks.py", "host/runtime-collect.py", "host/ingress-router.py", "host/rpdb-check.py"):
            self.assertEqual((self.output / "v2" / relative).read_bytes(), (self.release / "v2" / relative).read_bytes())
        for relative in ("host/controller.py", "host/verify-state.py", "host/verify.sh", "egress/egress-healthcheck.sh"):
            self.assertTrue((self.output / "v3" / relative).is_file())
        self.assertEqual((self.output / "v3/egresses.json").read_bytes(), (self.root / "v3/egresses.json").read_bytes())
        self.assertTrue((self.output / "units" / upgrade.UNIT).is_file())

    def test_two_egress_baseline_is_rejected_before_any_staging(self):
        (self.root / "v3/egresses.json").write_text(json.dumps(self.inventory[:2]), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "main\\+pgdl\\+ae"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_corrupted_release_is_rejected_before_staging(self):
        (self.release / "v2/host/runtime_checks.py").write_text("changed after review")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_retired_active_mark_is_not_silently_reused(self):
        path = self.root / "v3/multi.env"
        path.write_text(path.read_text().replace("RETIRED_MARKS=", "RETIRED_MARKS=0x203"), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "still retired"):
            self.prepare()

    def test_does_not_overwrite_or_recursively_copy_into_inputs(self):
        self.output.mkdir()
        (self.output / "keep").write_text("untouched")
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.prepare()
        self.assertEqual((self.output / "keep").read_text(), "untouched")
        self.output = self.root / "v2/nested"
        with self.assertRaisesRegex(ValueError, "separate from"):
            self.prepare()


if __name__ == "__main__":
    unittest.main()
