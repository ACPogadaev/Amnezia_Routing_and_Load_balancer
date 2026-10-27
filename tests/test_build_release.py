#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class BuildReleaseTests(unittest.TestCase):
    def test_release_renders_without_secrets_or_unresolved_tokens(self):
        example = (ROOT / "config" / "deployment.env.example").read_text(encoding="utf-8")
        replacements = {
            "CHANGE_ME_BALANCER_PUBLIC_IPV4": "192.0.2.1",
            "CHANGE_ME_INGRESS_UDP_PORT": "46777",
            "CHANGE_ME_INGRESS_OUTER_IPV4": "172.29.172.2",
            "CHANGE_ME_INGRESS_OUTER_GATEWAY": "172.29.172.1",
            "CHANGE_ME_INGRESS_DNS_IPV4": "172.29.172.2",
            "CHANGE_ME_INGRESS_DNS_GATEWAY": "172.29.172.1",
            "CHANGE_ME_INGRESS_AUX_IPV4": "172.17.0.2",
            "CHANGE_ME_HEALTH_TARGET_IPV4": "198.51.100.10",
            "CHANGE_ME_IP_FROM_YOUR_ROUTE_LIST": "93.184.216.34",
            "CHANGE_ME_MAIN_AWG_CLIENT_IPV4": "10.9.0.2",
            "CHANGE_ME_MAIN_AWG_ENDPOINT_IPV4": "192.0.2.10",
            "CHANGE_ME_MAIN_AWG_ENDPOINT_UDP_PORT": "31001",
            "CHANGE_ME_MAIN_PUBLIC_EXIT_IPV4": "192.0.2.10",
            "CHANGE_ME_EGRESS2_AWG_CLIENT_IPV4": "10.9.0.3",
            "CHANGE_ME_EGRESS2_AWG_ENDPOINT_IPV4": "192.0.2.20",
            "CHANGE_ME_EGRESS2_AWG_ENDPOINT_UDP_PORT": "31002",
            "CHANGE_ME_EGRESS2_PUBLIC_EXIT_IPV4": "192.0.2.20",
            "CHANGE_ME_EGRESS3_AWG_CLIENT_IPV4": "10.9.0.4",
            "CHANGE_ME_EGRESS3_AWG_ENDPOINT_IPV4": "192.0.2.30",
            "CHANGE_ME_EGRESS3_AWG_ENDPOINT_UDP_PORT": "31003",
            "CHANGE_ME_EGRESS3_PUBLIC_EXIT_IPV4": "192.0.2.30",
        }
        for before, after in replacements.items():
            example = example.replace(before, after)
        scratch = ROOT / "work"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = pathlib.Path(temporary)
            config = root / "deployment.env"
            routes = root / "routes.txt"
            output = root / "release"
            config.write_text(example, encoding="utf-8")
            routes.write_text("93.184.216.34/32\n10.0.0.0/8\n", encoding="utf-8")
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools" / "build-release.py"),
                    "--config",
                    str(config),
                    "--routes",
                    str(routes),
                    "--iana-csv",
                    str(ROOT / "tests" / "data" / "iana-ipv4-special-registry.csv"),
                    "--output",
                    str(output),
                ],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )
            all_text = "\n".join(
                path.read_text(encoding="utf-8", errors="ignore")
                for path in output.rglob("*")
                if path.is_file()
            )
            self.assertNotIn("@@", all_text)
            routed_text = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (
                    output / "v2" / "config" / "active-target-v4.txt",
                    output / "v2" / "host" / "guard.create.nft",
                    output / "v2" / "host" / "ingress-targets.create.nft",
                )
            )
            self.assertNotIn("10.0.0.0/8", routed_text)
            self.assertIn("93.184.216.34/32", all_text)
            self.assertTrue((output / "SHA256SUMS").is_file())
            self.assertTrue((output / "v2" / "egress" / "egress-healthcheck.sh").is_file())
            self.assertTrue((output / "v3" / "egress" / "egress-healthcheck.sh").is_file())
            runtime = root / "runtime-v3"
            shutil.copytree(output / "v3", runtime)
            shutil.copy2(runtime / "config" / "multi.env", runtime / "multi.env")
            shutil.copy2(runtime / "config" / "egresses.json", runtime / "egresses.json")
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    """
import importlib.util, os, pathlib, sys, types
base=pathlib.Path(sys.argv[1])
os.environ['AMNEZIA_LB_MULTI_DIR']=str(base)
sys.modules.setdefault('fcntl', types.SimpleNamespace(LOCK_EX=2, LOCK_UN=8, flock=lambda *_args: None))
spec=importlib.util.spec_from_file_location('built_controller', base/'host/controller.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert module.RECOVERY_ENABLED is False
assert module.RECOVERY_ALLOWED == set()
assert module.RECOVERY_MAX_PARALLEL == 1
assert {item['name'] for item in module.EGRESSES} == {'main','pgdl','ae'}
assert all(item.get('compose_file') and item.get('compose_service') for item in module.EGRESSES)
old_monotonic, old_sleep, old_stopping = module.time.monotonic, module.time.sleep, module.stopping
readings=iter([9.999, 10.001])
sleeps=[]
try:
    module.stopping=False
    module.time.monotonic=lambda: next(readings)
    module.time.sleep=lambda delay: sleeps.append(delay) if delay >= 0 else (_ for _ in ()).throw(AssertionError(delay))
    module.wait_until(10.0)
    assert len(sleeps) == 1 and 0 < sleeps[0] <= 0.5
finally:
    module.time.monotonic, module.time.sleep, module.stopping = old_monotonic, old_sleep, old_stopping
""",
                    str(runtime),
                ],
                check=True,
            )


if __name__ == "__main__":
    unittest.main()
