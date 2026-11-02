import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get("BASH_TEST_BINARY") or shutil.which("bash")


@unittest.skipUnless(BASH, "Bash is needed for shell cache tests")
class HealthCacheTests(unittest.TestCase):
    def run_cache(self, version, **changes):
        (ROOT / "work").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "work") as directory:
            root = Path(directory)
            cache = root / "health"
            cache.mkdir()
            ready = root / "ready"
            ready.write_text("instance\n")
            sample = {"schema_version": 1, "sample_id": "existing", "sample_epoch": int(time.time()),
                      "instance_id": "instance", "config_generation": "generation", "healthy": True}
            sample.update(changes)
            (cache / "result.json").write_text(json.dumps(sample, separators=(",", ":")))
            script = (ROOT / f"templates/{version}/egress/egress-healthcheck.sh").read_text()
            # Exercise the production entrypoint/cache path. Stop at the first
            # collector operation, so a cache miss cannot touch real networking.
            prefix = script.split('exec 9>"$LOCK"', 1)[0]
            prefix = prefix.replace("RUN_DIR=/run/amnezia-lb-health", f"RUN_DIR='{cache.as_posix()}'")
            path = root / "cache-test.sh"
            path.write_text(prefix + "exit 42\n", encoding="utf-8", newline="\n")
            env = {**os.environ, "EGRESS_AWG_IF": "awg-test", "EGRESS_AWG_IP": "10.9.0.2", "EGRESS_POLICY_TABLE": "201",
                   "INGRESS_TRANSIT_IP": "172.30.250.10", "EGRESS_READY_FILE": ready.as_posix(),
                   "EGRESS_EXPECTED_EXIT_IP": "192.0.2.1", "HEALTH_URL": "https://example.invalid/", "HEALTH_URL_SECONDARY": "https://example.invalid/",
                   "HEALTH_CONFIG_GENERATION": "generation", "HEALTH_MAX_HANDSHAKE_AGE_SECONDS": "300", "HEALTH_MAX_SAMPLE_AGE_SECONDS": "45", "HEALTH_INTERVAL_SECONDS": "10"}
            if os.name == "nt":
                env["PATH"] = str(Path(BASH).parent) + os.pathsep + env["PATH"]
            return subprocess.run([BASH, str(path), "--docker"], env=env, capture_output=True, text=True, timeout=10)

    def test_recent_success_and_failure_reused_without_collecting(self):
        for version in ("v2", "v3"):
            for healthy, status in ((True, 0), (False, 1)):
                with self.subTest(version=version, healthy=healthy):
                    result = self.run_cache(version, healthy=healthy)
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertEqual(json.loads(result.stdout)["sample_id"], "existing")

    def test_stale_future_wrong_generation_and_wrong_instance_force_collection(self):
        for fields in ({"sample_epoch": int(time.time()) - 20}, {"sample_epoch": int(time.time()) + 30},
                       {"config_generation": "old"}, {"instance_id": "other"}):
            with self.subTest(fields=fields):
                result = self.run_cache("v3", **fields)
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
