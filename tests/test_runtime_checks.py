import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from runtime_fixtures import ROOT, HOST_SAVE, INGRESS_SAVE, V6_SAVE, environment, target_document, ingress_snapshot

sys.path.insert(0, str(ROOT / "templates/v2/host"))
from runtime_checks import (Rules, RuntimeChecks, TargetVerifier, canonical_rule, fingerprint,
                            validate_host_v2, validate_host_v3, validate_ingress_rules, validate_dnat)


class RuntimeCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "work")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = environment(self.root)

    def test_realistic_save_preserves_all_rules_and_order(self):
        rules = Rules(HOST_SAVE.format_map(self.env))
        validate_host_v2(rules, self.env)
        validate_host_v3(rules, self.env)
        validate_dnat(rules, self.env)
        validate_ingress_rules(Rules(INGRESS_SAVE.format_map(self.env)), Rules(V6_SAVE.format_map(self.env)),
                               self.env, ["outer", "aux", "direct", "transit"])

    def test_changed_ports_negation_extra_matches_and_parent_order_fail_closed(self):
        original = HOST_SAVE.format_map(self.env)
        mutations = [
            original.replace("--dport 31002", "--dport 31009"),
            original.replace("-s 172.30.251.11/32", "! -s 172.30.251.11/32"),
            original.replace("-A DOCKER-USER -j AMNEZIA_LB_V2", "-A DOCKER-USER -j ACCEPT\n-A DOCKER-USER -j AMNEZIA_LB_V2"),
            original.replace("-A AMNEZIA_LB_MULTI_V3 -j RETURN", "-A AMNEZIA_LB_MULTI_V3 -m mark --mark 1 -j RETURN"),
            original.replace("-A PREROUTING -j AMNEZIA_LB_MULTI_V3_RAW", "-A PREROUTING -j AMNEZIA_LB_MULTI_V3_RAW\n-A PREROUTING -j AMNEZIA_LB_MULTI_V3_RAW"),
        ]
        for snapshot in mutations:
            with self.subTest(snapshot=snapshot[-100:]), self.assertRaises(ValueError):
                validate_host_v3(Rules(snapshot), self.env)

    def test_missing_ipv6_block_and_incomplete_snapshot_rejected(self):
        v4 = Rules(INGRESS_SAVE.format_map(self.env))
        with self.assertRaises(ValueError):
            validate_ingress_rules(v4, Rules(V6_SAVE.format_map(self.env).replace("-j REJECT", "-j ACCEPT")), self.env, ["outer", "aux", "direct", "transit"])
        with self.assertRaises(ValueError):
            Rules("*filter\n:FORWARD ACCEPT [0:0]\n")

    def test_cidr_cache_invalidates_by_content_even_if_mtime_unchanged(self):
        verifier = TargetVerifier()
        path = self.root / "targets.txt"
        document = target_document()
        verifier.verify(document, path, "amnezia_lb_v2_targets")
        expected = verifier.expected
        verifier.verify(document, path, "amnezia_lb_v2_targets")
        self.assertIs(verifier.expected, expected)
        stamp = path.stat().st_mtime_ns
        path.write_text("93.184.216.35/32\n", encoding="utf-8")
        os.utime(path, ns=(stamp, stamp))
        with self.assertRaises(ValueError):
            verifier.verify(document, path, "amnezia_lb_v2_targets")

    def test_observed_set_changes_are_not_hidden_by_expected_cache(self):
        verifier = TargetVerifier()
        doc = target_document()
        verifier.verify(doc, self.root / "targets.txt", "amnezia_lb_v2_targets")
        doc["nftables"][1]["set"]["elem"] = ["93.184.216.35"]
        with self.assertRaises(ValueError):
            verifier.verify(doc, self.root / "targets.txt", "amnezia_lb_v2_targets")

    def test_host_snapshot_shared_only_within_cycle_and_invalidated_after_repair(self):
        calls = []
        def run(args, **_kwargs):
            calls.append(args)
            out = "0\n0\n0\n0\n" if args[0] == "sysctl" else HOST_SAVE.format_map(self.env)
            return types.SimpleNamespace(stdout=out)
        checks = RuntimeChecks(self.root / "v2", self.root / "v3", runner=run)
        checks.check_docker_user(2)
        checks.check_docker_user(3)
        self.assertEqual(calls.count(["iptables-save"]), 1)
        checks.invalidate()
        checks.check_docker_user(2)
        checks.begin_cycle()
        checks.check_docker_user(2)
        self.assertEqual(calls.count(["iptables-save"]), 3)

    def test_configuration_generation_is_fenced_during_collection(self):
        checks = RuntimeChecks(self.root / "v2")
        path = self.root / "v2/pilot.env"
        path.write_text(path.read_text() + "\nPUBLIC_IF=other\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "configuration changed"):
            checks.assert_config_current()

    def make_checks(self):
        host = self.root / "v2/host"
        host.mkdir()
        for name in ("default-route-check.py", "rpdb-check.py"):
            shutil.copy2(ROOT / "templates/v2/host" / name, host / name)
        document = target_document()
        (self.root / "ingress-targets.42.sha256").write_text(fingerprint(document))
        self.calls = []
        self.snapshot = ingress_snapshot(self.env)
        self.inspects = 0
        def run(args, **_kwargs):
            self.calls.append(args)
            if args[:2] == ["docker", "inspect"]:
                self.inspects += 1
                out = json.dumps([{"Id": "container", "State": {"Running": True, "Pid": 42, "StartedAt": str(self.inspects)},
                                   "NetworkSettings": {"Networks": {self.env[n]: {"IPAddress": self.env[k]} for n, k in
                                    (("INGRESS_OUTER_NETWORK", "INGRESS_OUTER_IP"), ("INGRESS_DNS_NETWORK", "INGRESS_DNS_IP"),
                                     ("INGRESS_AUX_NETWORK", "INGRESS_AUX_IP"), ("DIRECT_NETWORK", "INGRESS_DIRECT_IP"), ("TRANSIT_NETWORK", "INGRESS_TRANSIT_IP"))}}}])
            elif args[0] == "nsenter":
                out = json.dumps(self.snapshot)
            elif args[0] == "iptables-save":
                out = HOST_SAVE.format_map(self.env)
            else:
                out = self.env["INGRESS_AWG_PORT"] + "\n"
            return types.SimpleNamespace(stdout=out)
        return RuntimeChecks(self.root / "v2", runtime_dir=self.root, runner=run)

    def test_batched_ingress_checks_namespace_and_terminal_rules(self):
        checks = self.make_checks()
        with patch.object(checks, "identity", return_value=("container", "start", 42, 1)):
            checks.check_ingress(42)
        self.assertEqual(sum(args[0] == "nsenter" for args in self.calls), 1)
        self.assertEqual(len(self.calls), 5)
        rules = json.loads(self.snapshot["rules"])
        rules[1]["action"] = "blackhole"
        self.snapshot["rules"] = json.dumps(rules)
        with patch.object(checks, "identity", return_value=("container", "start", 42, 1)), self.assertRaises(ValueError):
            checks.check_ingress(42)

    def test_recreated_namespace_during_snapshot_is_rejected(self):
        checks = self.make_checks()
        with patch.object(checks, "identity", side_effect=[("id", "before", 42, 1), ("id", "after", 42, 2)]), self.assertRaisesRegex(ValueError, "identity changed"):
            checks.check_ingress(42)


if __name__ == "__main__":
    unittest.main()
