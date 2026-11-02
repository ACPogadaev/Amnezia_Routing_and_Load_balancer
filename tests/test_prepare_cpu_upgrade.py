import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

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
        for version, files in upgrade.PAYLOAD.items():
            for relative in files:
                target = self.release / version / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / "templates" / version / relative, target)
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
            (self.root / version / "host/policy-down.sh").write_text("checked local policy-down helper")
            (self.root / version / "host/docker-user-install.sh").write_text("checked local Docker rules helper")
        self.output = self.root / "staged"
        self.write_baseline_manifests()

    def write_baseline_manifests(self):
        self.baseline_hashes = {}
        for version in ("v2", "v3"):
            base = self.root / version
            hashes = {path.relative_to(base).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in sorted(base.rglob("*")) if path.is_file() and path.name != "installed-manifest.sha256"}
            (base / "installed-manifest.sha256").write_text(
                "".join(f"{sha}  {upgrade.LIVE[version]}/{relative}\n" for relative, sha in hashes.items()), encoding="utf-8")
            self.baseline_hashes[version] = hashes

    def prepare(self, review=None):
        return upgrade.prepare(self.release, self.root / "v2", self.root / "v3", self.root / "v2-compose.json", self.root / "v3-compose.json", self.output,
                               baseline_review=review)

    def write_review(self, changes):
        document = {"schema": 1, "reviewed_by": "test-reviewer", "reviewed_at": "2026-11-02T12:00:00+00:00",
                    "reference": "test:reviewed-local-change", "baseline_manifests": {
                        version: upgrade.digest(self.root / version / "installed-manifest.sha256") for version in ("v2", "v3")},
                    "changes": changes}
        path = self.root / "baseline-review.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def reviewed_change(self, version="v2", relative="host/guard-load.sh"):
        return {"baseline": version, "path": relative, "expected_sha256": self.baseline_hashes[version][relative],
                "reviewed_sha256": upgrade.digest(self.root / version / relative), "reason": "Separately inspected local adaptation"}

    def test_stages_complete_payload_preserving_local_network_configuration(self):
        report = self.prepare()
        self.assertEqual(report["egresses"], ["main", "pgdl", "ae"])
        self.assertIsNone(report["baseline_review"])
        for version, envfile in (("v2", "pilot.env"), ("v3", "multi.env")):
            self.assertEqual(report["baseline_manifests"][version]["sha256"], upgrade.digest(self.root / version / "installed-manifest.sha256"))
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
        self.write_baseline_manifests()
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
        self.write_baseline_manifests()
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

    def test_missing_baseline_manifest_is_rejected_before_staging(self):
        for version in ("v2", "v3"):
            path = self.root / version / "installed-manifest.sha256"
            original = path.read_bytes()
            path.unlink()
            try:
                with self.subTest(version=version), self.assertRaisesRegex(ValueError, "missing .* baseline"):
                    self.prepare()
                self.assertFalse(self.output.exists())
            finally:
                path.write_bytes(original)

    def test_modified_preserved_helpers_in_either_baseline_are_not_resealed(self):
        for version in ("v2", "v3"):
            for relative in ("host/guard-load.sh", "host/policy-down.sh", "host/docker-user-install.sh"):
                path = self.root / version / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\nunreviewed change\n")
                try:
                    with self.subTest(version=version, relative=relative), self.assertRaisesRegex(ValueError, "baseline checksum mismatch"):
                        self.prepare()
                    self.assertFalse(self.output.exists())
                finally:
                    path.write_bytes(original)

    def test_manifest_missing_file_and_duplicate_entries_are_rejected(self):
        for version in ("v2", "v3"):
            path = self.root / version / "host/policy-down.sh"
            original = path.read_bytes()
            path.unlink()
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "missing/non-regular"):
                self.prepare()
            self.assertFalse(self.output.exists())
            path.write_bytes(original)
            manifest = self.root / version / "installed-manifest.sha256"
            original_manifest = manifest.read_bytes()
            manifest.write_bytes(original_manifest + original_manifest.splitlines(keepends=True)[0])
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "duplicate .* manifest path"):
                self.prepare()
            self.assertFalse(self.output.exists())
            manifest.write_bytes(original_manifest)

    def test_outside_relative_and_noncanonical_manifest_paths_are_rejected(self):
        path = self.root / "v2/installed-manifest.sha256"
        original = path.read_bytes()
        for absolute in ("/etc/amnezia-lb-v20/host/policy-down.sh", "/etc/amnezia-lb-multi-v3/host/policy-down.sh",
                         "/etc/amnezia-lb-v2/../outside", "/etc/amnezia-lb-v2/host/../../outside",
                         "/etc/amnezia-lb-v2/host/./policy-down.sh", "/etc/amnezia-lb-v2//host/policy-down.sh",
                         "/etc/amnezia-lb-v2/host\\policy-down.sh", "host/policy-down.sh", "C:/etc/amnezia-lb-v2/host/policy-down.sh",
                         "/etc/amnezia-lb-v2/installed-manifest.sha256"):
            path.write_bytes(original + f"{'0' * 64}  {absolute}\n".encode())
            with self.subTest(path=absolute), self.assertRaises(ValueError):
                self.prepare()
            self.assertFalse(self.output.exists())
        path.write_bytes(original)

    def test_unlisted_preserved_file_cannot_enter_the_new_manifest(self):
        extra = self.root / "v3/host/unreviewed-helper.py"
        extra.write_text("unreviewed helper")
        with self.assertRaisesRegex(ValueError, "unlisted v3 baseline files"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_empty_or_malformed_baseline_manifest_is_rejected(self):
        manifest = self.root / "v3/installed-manifest.sha256"
        for content in ("", "not-a-checksum  /etc/amnezia-lb-multi-v3/host/policy-down.sh\n",
                        "0" * 64 + " /etc/amnezia-lb-multi-v3/host/policy-down.sh\n"):
            manifest.write_text(content, encoding="utf-8")
            with self.subTest(content=content), self.assertRaises(ValueError):
                self.prepare()
            self.assertFalse(self.output.exists())

    def test_symlink_to_outside_baseline_is_rejected(self):
        path = self.root / "v2/host/policy-down.sh"
        outside = self.root / "outside-policy-down.sh"
        outside.write_bytes(path.read_bytes())
        path.unlink()
        try:
            path.symlink_to(outside)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        with self.assertRaisesRegex(ValueError, "symlinks/junctions"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_explicit_review_is_bound_to_original_manifests_and_reported(self):
        path = self.root / "v2/host/guard-load.sh"
        path.write_text("separately reviewed local loader")
        other = self.root / "v3/host/policy-down.sh"
        other.write_text("separately reviewed local policy-down")
        review = self.write_review([self.reviewed_change(), self.reviewed_change("v3", "host/policy-down.sh")])
        report = self.prepare(review)
        self.assertEqual((self.output / "v2/host/guard-load.sh").read_bytes(), path.read_bytes())
        self.assertEqual((self.output / "v3/host/policy-down.sh").read_bytes(), other.read_bytes())
        self.assertEqual(report["baseline_review"]["sha256"], upgrade.digest(review))
        self.assertEqual(report["baseline_review"]["changes"][0]["reviewed_sha256"], upgrade.digest(path))

    def test_wrong_or_stale_review_cannot_authorize_another_change(self):
        path = self.root / "v2/host/guard-load.sh"
        original = path.read_bytes()
        path.write_text("reviewed local loader")
        change = self.reviewed_change()
        review = self.write_review([change])
        document = json.loads(review.read_text())
        invalid = []
        for mutate in (lambda doc: doc["baseline_manifests"].update(v3="0" * 64),
                       lambda doc: doc["changes"][0].update(expected_sha256="0" * 64),
                       lambda doc: doc["changes"][0].update(reviewed_sha256="0" * 64),
                       lambda doc: doc["changes"][0].update(path="../guard-load.sh"),
                       lambda doc: doc["changes"][0].update(reason=""),
                       lambda doc: doc.update(reviewed_by=""),
                       lambda doc: doc.update(reviewed_at="2026-11-02T12:00:00"),
                       lambda doc: doc.update(schema=True),
                       lambda doc: doc["baseline_manifests"].pop("v3"),
                       lambda doc: doc["changes"].append(copy.deepcopy(doc["changes"][0]))):
            variant = copy.deepcopy(document)
            mutate(variant)
            invalid.append(variant)
        for variant in invalid:
            review.write_text(json.dumps(variant), encoding="utf-8")
            with self.assertRaises(ValueError):
                self.prepare(review)
            self.assertFalse(self.output.exists())
        review.write_text(json.dumps(document), encoding="utf-8")
        path.write_bytes(original)
        with self.assertRaisesRegex(ValueError, "unused/stale"):
            self.prepare(review)
        self.assertFalse(self.output.exists())

    def test_changed_copy_is_rejected_before_any_new_manifest_is_created(self):
        original_copytree = shutil.copytree
        def copytree(source, destination, *args, **kwargs):
            result = original_copytree(source, destination, *args, **kwargs)
            if Path(source) == self.root / "v3":
                (Path(destination) / "host/policy-down.sh").write_text("changed during copy")
            return result
        with patch.object(upgrade.shutil, "copytree", side_effect=copytree), patch.object(upgrade, "make_manifest") as writer:
            with self.assertRaisesRegex(ValueError, "changed while copying"):
                self.prepare()
            writer.assert_not_called()
        self.assertEqual((self.output / "v2/installed-manifest.sha256").read_bytes(), (self.root / "v2/installed-manifest.sha256").read_bytes())


if __name__ == "__main__":
    unittest.main()
