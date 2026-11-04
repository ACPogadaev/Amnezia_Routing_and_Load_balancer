from __future__ import annotations

import base64
import contextlib
import copy
import io
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import subprocess
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from amnezia_router import cli, render
from amnezia_router.balance import FAIL_MARK, Health, bucket_map, pinned_mark, route_mark
from amnezia_router.config import ConfigError, choose_networks, load_routes, make_config, read_profile, validate_runtime
from amnezia_router.runtime import Runtime, fingerprint, validate_policy_rule, verify_chain


KEY = base64.b64encode(bytes(range(32))).decode()
INGRESS = {"container": "amnezia-awg2", "interface": "awg0", "client_subnet": "10.8.1.0/24", "port": 46777,
           "outer_interface": "eth0", "outer_gateway": "172.20.0.1", "public_if": "eth0", "image": "sha256:" + "a" * 64,
           "attachments": [{"name": "existing", "bridge": "amn0", "address": "172.20.0.2"}]}
WORK = Path(__file__).resolve().parents[2] / "work"
WORK.mkdir(exist_ok=True)


def profile_text(index=1):
    return f"""[Interface]
PrivateKey = {KEY}
Address = 10.9.0.2/32
DNS = 1.1.1.1
PostUp = echo should-never-execute
PreDown = false
SaveConfig = true
Table = 999
Jc = 7
H1 = 12345

[Peer]
PublicKey = {KEY}
Endpoint = 192.0.2.{index}:3100{index}
AllowedIPs = 0.0.0.0/0, ::/0
"""


def config(count=3, pinned=True):
    with tempfile.TemporaryDirectory(dir=WORK) as temporary:
        root = Path(temporary)
        profiles = []
        for index in range(1, count + 1):
            path = root / f"{index}.conf"
            path.write_text(profile_text(index), encoding="utf-8")
            profiles.append(read_profile(path))
        return make_config(profiles, ["93.184.216.0/24"], ["93.184.216.34/32"] if pinned else [],
                           count if pinned else None, copy.deepcopy(INGRESS), ["172.20.0.0/16"])


def sample(index, healthy=True, reason=None):
    return {"sample_id": str(index), "healthy": healthy, "reason": reason or ("ok" if healthy else "https_unavailable"),
            "rx_bytes": index * 100, "tx_bytes": index * 100}


class ConfigTests(unittest.TestCase):
    def test_profile_sanitizes_hooks_and_normalizes_without_requiring_psk(self):
        with tempfile.TemporaryDirectory(dir=WORK) as temporary:
            path = Path(temporary) / "input.conf"
            path.write_text(profile_text())
            profile = read_profile(path)
        self.assertEqual(profile.endpoint_port, 31001)
        self.assertIn("Jc = 7", profile.contents)
        self.assertIn("H1 = 12345", profile.contents)
        self.assertIn("PersistentKeepalive = 25", profile.contents)
        self.assertIn("Table = off", profile.contents)
        for removed in ("PostUp", "PreDown", "DNS", "::/0", "999", "SaveConfig = true"):
            self.assertNotIn(removed, profile.contents)
        self.assertNotIn(KEY, repr(profile))

    def test_profile_rejects_ambiguous_or_invalid_inputs_without_echoing_keys(self):
        cases = [profile_text() + "\n[Peer]\n", profile_text().replace("192.0.2.1:31001", "example.org:443"),
                 profile_text().replace("PrivateKey = " + KEY, "PrivateKey = SECRET_NOT_BASE64"),
                 profile_text().replace("Address = 10.9.0.2/32", "Address = 10.9.0.2/32, 10.9.0.3/32"),
                 profile_text().replace("Address = 10.9.0.2/32", "Address = 2001:db8::1/64"),
                 profile_text().replace("0.0.0.0/0, ::/0", "10.0.0.0/8"),
                 profile_text().replace("Jc = 7", "Jc = 7\njc = 8")]
        with tempfile.TemporaryDirectory(dir=WORK) as temporary:
            path = Path(temporary) / "bad.conf"
            for text in cases:
                with self.subTest(text=text[:12]):
                    path.write_text(text)
                    with self.assertRaises(ConfigError) as raised:
                        read_profile(path)
                    self.assertNotIn("SECRET_NOT_BASE64", str(raised.exception))
                    self.assertNotIn(KEY, str(raised.exception))

    def test_awg3_header_protection_and_keepalive_range_are_preserved(self):
        from amnezia_router.config import parse_profile
        text = profile_text().replace("Jc = 7", f"Jc = 7\nHeaderProtectionKey = {KEY}") + "PersistentKeepalive = 25-35\n"
        profile = parse_profile(text)
        self.assertIn("PersistentKeepalive = 25-35", profile.contents)
        self.assertIn("HeaderProtectionKey = " + KEY, profile.contents)
        for value in ("35-25", "0-65536", "abc", "1-2-3"):
            with self.assertRaises(ConfigError):
                parse_profile(text.replace("25-35", value))

    def test_one_two_three_profiles_and_same_internal_addresses_are_supported(self):
        for count in (1, 2, 3):
            c = config(count)
            self.assertEqual(len(c["egresses"]), count)
            self.assertEqual(len({e["address"] for e in c["egresses"]}), 1)
            self.assertEqual(len({e["network"]["subnet"] for e in c["egresses"]}), count)
            self.assertEqual(c["pin_egress"], count)
            validate_runtime(c)

    def test_missing_pin_owner_empty_targets_and_bad_float_are_rejected(self):
        c = config()
        for key, value in (("pin_egress", 4), ("reference_bps", 0), ("reference_bps", float("inf")),
                           ("alpha", float("nan")), ("weight_floor", -1), ("alpha", 1.1), ("interval", 0)):
            with self.subTest(key=key, value=value):
                broken = copy.deepcopy(c)
                broken[key] = value
                with self.assertRaises(ConfigError):
                    validate_runtime(broken)

    def test_normalization_filters_special_ranges_and_rejects_ipv6(self):
        with tempfile.TemporaryDirectory(dir=WORK) as temporary:
            path = Path(temporary) / "routes.txt"
            path.write_text("# comment\n93.184.216.34/24\n93.184.216.0/24\n10.0.0.0/8\n127.0.0.0/8\n224.0.0.0/4\n")
            self.assertEqual(load_routes(path), ["93.184.216.0/24"])
            path.write_text("2001:db8::/32\n")
            with self.assertRaises(ConfigError):
                load_routes(path)
            path.write_text("# optional empty list\n")
            self.assertEqual(load_routes(path), [])

    def test_subnet_allocator_avoids_broad_existing_routes_and_exhaustion(self):
        result = choose_networks(["172.16.0.0/12", "10.250.0.0/24"], 5)
        self.assertEqual(result[0], "10.250.1.0/24")
        with self.assertRaises(ConfigError):
            choose_networks(["172.16.0.0/12", "10.0.0.0/8"], 5)


class PolicyTests(unittest.TestCase):
    def healthy(self, c):
        return {e["id"]: Health(healthy=True, identity=(e["id"],)) for e in c["egresses"]}

    def test_pinned_precedence_and_no_fallback_when_its_owner_fails(self):
        for count in (1, 2, 3):
            c = config(count)
            health = self.healthy(c)
            marks = bucket_map(c["egresses"], health, c)
            fixed = pinned_mark(c, health)
            self.assertEqual(route_mark("93.184.216.34", c, marks, fixed), c["egresses"][-1]["mark"])
            self.assertIsNone(route_mark("8.8.8.8", c, marks, fixed))
            health[count].healthy = False
            marks, fixed = bucket_map(c["egresses"], health, c), pinned_mark(c, health)
            self.assertEqual(route_mark("93.184.216.34", c, marks, fixed), FAIL_MARK)
            if count > 1:
                self.assertNotEqual(route_mark("93.184.216.35", c, marks, fixed), FAIL_MARK)

    def test_all_failed_returns_fail_marks_and_single_egress_gets_all_buckets(self):
        for count in (1, 2, 3):
            c = config(count)
            states = {e["id"]: Health() for e in c["egresses"]}
            self.assertEqual(bucket_map(c["egresses"], states, c), [FAIL_MARK] * 256)
            states[1].healthy = True
            self.assertEqual(bucket_map(c["egresses"], states, c), [c["egresses"][0]["mark"]] * 256)

    def test_stable_map_and_busy_exit_gets_fewer_new_buckets(self):
        c = config()
        states = self.healthy(c)
        before = bucket_map(c["egresses"], states, c)
        self.assertEqual(before, bucket_map(c["egresses"], states, c))
        states[1].bps = 100 * c["reference_bps"]
        after = bucket_map(c["egresses"], states, c)
        self.assertLess(after.count(c["egresses"][0]["mark"]), before.count(c["egresses"][0]["mark"]))

    def test_failures_and_recovery_use_thresholds_and_deduplicate_samples(self):
        c = config()
        state = Health()
        for n in range(1, 4):
            state.update(sample(n), n, c, (1,))
        self.assertTrue(state.healthy)
        for n in range(4, 7):
            state.update(sample(n, False), n, c, (1,))
            state.update(sample(n, False), n + 0.1, c, (1,))
        self.assertEqual(state.failures, 3)
        self.assertFalse(state.healthy)
        for n in range(7, 10):
            state.update(sample(n), n, c, (1,))
        self.assertTrue(state.healthy)
        state.update(sample(10, False, "wrong_exit_ip"), 10, c, (1,))
        self.assertFalse(state.healthy)
        state.update(sample(11), 11, c, (2,))
        self.assertFalse(state.healthy)
        self.assertEqual(state.successes, 1)

    def test_busy_collector_cannot_keep_an_old_success_alive_forever(self):
        c = config()
        state = Health()
        for n in range(1, 4):
            state.update(sample(n), n, c, (1,))
        state.update({"healthy": False, "reason": "probe_busy"}, 60, c, (1,))
        self.assertFalse(state.healthy)

    def test_quarantine_is_applied_at_health_failure_threshold(self):
        c = config(2)
        runtime = Runtime(c)
        runtime.ingress_identity = ("ingress", "start", 42, 1)
        runtime.interfaces = ("direct", "transit", "outer")
        runtime.health = self.healthy(c)
        state = runtime.health[2]
        for n in range(1, 4):
            state.update(sample(n, False), n, c, (2,))
        statements = []
        runtime.nft_apply = statements.append
        runtime.nft_snapshot = lambda: {"nftables": []}
        runtime.ns = lambda *_a, **_k: types.SimpleNamespace(stdout="[]")
        result = runtime.apply_policy()
        self.assertIn(c["egresses"][1]["mark"], result["quarantined_marks"])
        self.assertFalse(result["pinned_available"])
        self.assertEqual(result["mode"], "degraded")
        self.assertIn(f"ip daddr @pinned_v4 meta mark set {FAIL_MARK} return", statements[0])


class RenderTests(unittest.TestCase):
    def test_complete_dynamic_compose_matches_profiles_for_every_count(self):
        for count in (1, 2, 3):
            c = config(count)
            compose = render.compose(c)
            self.assertEqual(compose["name"], "amnezia-router")
            self.assertEqual(len(compose["services"]), count)
            for e in c["egresses"]:
                service = compose["services"][e["name"]]
                self.assertIn(f":/etc/amnezia/amneziawg/{e['interface']}.conf:ro", " ".join(service["volumes"]))
                self.assertEqual(service["environment"]["EGRESS_AWG_ENDPOINT_PORT"], str(e["endpoint_port"]))
                self.assertEqual(service["sysctls"]["net.ipv4.ip_forward"], "0")
                self.assertNotIn(KEY, json.dumps(compose))

    def test_all_endpoint_ports_are_rendered_and_no_legacy_values_survive(self):
        c = config()
        for replace in (True, False):
            text = render.host_nft(c, replace=replace)
            for e in c["egresses"]:
                self.assertIn(f"ip daddr {e['endpoint_ip']} udp dport {e['endpoint_port']}", text)
            for legacy in ("35367", "33592", "43999", "amnezia_lb", "@@"):
                self.assertNotIn(legacy, text)

    def test_pinned_rule_precedes_buckets_and_fail_is_explicit(self):
        c = config()
        statements = render.selector(c, [c["egresses"][0]["mark"]] * 256, FAIL_MARK, {c["egresses"][2]["mark"]})
        self.assertLess(statements.index("@pinned_v4"), statements.index("@balanced_v4"))
        self.assertIn(f"@pinned_v4 meta mark set {FAIL_MARK} return", statements)
        host = render.host_nft(c)
        self.assertIn("quarantine ct mark @quarantined counter drop", host)

    def test_boot_dependency_and_every_unit_are_packaged(self):
        units = render.units()
        self.assertIn("Before=docker.service", units["amnezia-router-guard.service"])
        self.assertIn("Requires=amnezia-router-guard.service", units["docker-dropin.conf"])
        for path in ("routerctl.py", "egress-start.sh", "egress-healthcheck.sh", "data/iana-ipv4-special-registry.csv", "install.sh"):
            self.assertTrue((Path(__file__).resolve().parents[1] / path).is_file())


class RuntimeRegressionTests(unittest.TestCase):
    def test_absent_fib_table_partial_json_is_empty_but_other_failures_are_rejected(self):
        from amnezia_router.system import route_table_entries
        missing = types.SimpleNamespace(returncode=2, stdout="[", stderr="Error: ipv4: FIB table does not exist.\nDump terminated\n")
        self.assertEqual(route_table_entries(missing, allow_missing=True), [])
        with self.assertRaises(ConfigError):
            route_table_entries(missing)
        with self.assertRaises(ConfigError):
            route_table_entries(types.SimpleNamespace(returncode=1, stdout="[", stderr="Permission denied"), allow_missing=True)

    def test_policy_json_accepts_omitted_mask_and_rejects_changed_or_extra_selectors(self):
        rule = {"priority": 31000, "src": "all", "fwmark": "0xa01", "table": 41001, "protocol": "99"}
        expected = {"fwmark": 0xA01, "fwmask": 0xFFFFFFFF, "table": 41001}
        validate_policy_rule([rule], 31000, expected)
        for changes in ({"fwmask": "0xff"}, {"dst": "1.1.1.1"}, {"iif": "lo"}, {"protocol": "static"}):
            with self.assertRaises(ConfigError):
                validate_policy_rule([{**rule, **changes}], 31000, expected)
        terminal = {"priority": 31001, "src": "all", "fwmark": "0xa01", "action": 7, "protocol": "99"}
        validate_policy_rule([terminal], 31001, {"fwmark": 0xA01, "fwmask": 0xFFFFFFFF, "action": "unreachable"})

    def test_conditional_duplicate_and_reordered_jumps_are_rejected(self):
        expected = ["-s 10.0.0.1/32 -j ACCEPT", "-j RETURN"]
        text = "-A DOCKER-USER -j AMR_FORWARD\n-A AMR_FORWARD -s 10.0.0.1/32 -j ACCEPT\n-A AMR_FORWARD -j RETURN\n"
        verify_chain(text, "DOCKER-USER", "AMR_FORWARD", expected)
        for parent in ("-A DOCKER-USER -p tcp -j AMR_FORWARD\n", "-A DOCKER-USER -j RETURN\n-A DOCKER-USER -j AMR_FORWARD\n", "-A DOCKER-USER -j AMR_FORWARD\n-A DOCKER-USER -j AMR_FORWARD\n"):
            with self.assertRaises(ConfigError):
                verify_chain(parent + "\n".join(text.splitlines()[1:]), "DOCKER-USER", "AMR_FORWARD", expected)

    def test_fingerprint_ignores_counters_but_not_policy(self):
        first = {"nftables": [{"metainfo": {"version": 1}}, {"rule": {"chain": "guard", "handle": 3, "expr": [{"counter": {"packets": 3, "bytes": 10}}, {"drop": None}]}}]}
        second = copy.deepcopy(first)
        second["nftables"][1]["rule"]["expr"][0]["counter"]["packets"] = 100
        self.assertEqual(fingerprint(first), fingerprint(second))
        second["nftables"][1]["rule"]["expr"][1] = {"accept": None}
        self.assertNotEqual(fingerprint(first), fingerprint(second))

    def test_foreign_same_named_builtin_in_another_table_does_not_break_validation(self):
        snapshot = "*mangle\n:FORWARD ACCEPT [0:0]\n-A FORWARD -p tcp -j ACCEPT\nCOMMIT\n*filter\n:FORWARD ACCEPT [0:0]\n:AMR_INGRESS - [0:0]\n-A FORWARD -j AMR_INGRESS\n-A AMR_INGRESS -j RETURN\nCOMMIT\n"
        verify_chain(snapshot, "FORWARD", "AMR_INGRESS", ["-j RETURN"], "filter")
        with self.assertRaises(ConfigError):
            verify_chain(snapshot, "FORWARD", "AMR_INGRESS", ["-j RETURN"], "mangle")

    def test_compose_teardown_has_explicit_unique_scope_and_no_remove_orphans(self):
        runner = types.SimpleNamespace(docker=lambda *args, **kwargs: (args, kwargs))
        result = Runtime(config(), runner).compose("down")
        self.assertEqual(result[0][result[0].index("--project-name") + 1], "amnezia-router")
        self.assertNotIn("--remove-orphans", result[0])
        self.assertIn("/etc/amnezia-router/compose.json", result[0])

    def test_uninstall_refuses_foreign_containers_before_stopping_any_service(self):
        calls = []
        runner = types.SimpleNamespace(docker=lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=json.dumps([{"Config": {"Labels": {"com.docker.compose.project": "foreign"}}}])),
                                       run=lambda *a, **k: calls.append(a))
        with patch.object(cli, "load_config", return_value=config()), patch.object(cli, "operation_lock", contextlib.nullcontext), \
             patch.object(cli.sys, "platform", "linux"), patch.object(cli.os, "geteuid", return_value=0, create=True):
            with self.assertRaises(ConfigError):
                cli.uninstall(runner)
        self.assertEqual(calls, [])

    def test_check_only_does_not_create_installation_or_call_services(self):
        with tempfile.TemporaryDirectory(dir=WORK) as temporary:
            root = Path(temporary)
            profile = root / "profile.conf"
            routes = root / "routes.txt"
            profile.write_text(profile_text())
            routes.write_text("93.184.216.34/32\n")
            args = cli.arguments().parse_args(["install", "--egress", str(profile), "--balanced-routes", str(routes), "--check-only"])
            with patch.object(cli, "CONFIG", root / "new-config/config.json"), patch.object(cli.render, "LIB", str(root / "new-lib")), \
                 patch.object(cli, "LAUNCHER", root / "new-launcher"), patch.object(cli, "UNITS", root / "units"), patch.object(cli, "DROPIN", root / "dropin"), \
                 patch.object(cli, "platform_checks", return_value={}), patch.object(cli, "resource_checks"), \
                 patch.object(cli, "discovery", return_value=(copy.deepcopy(INGRESS), [])), patch.object(cli, "identity", return_value=("id", "started", 42, 1)), contextlib.redirect_stdout(io.StringIO()):
                commands = []
                runner = types.SimpleNamespace(run=lambda a, **k: commands.append(a), docker=lambda *a, **k: commands.append(a),
                                               ns=lambda *a, **k: commands.append(a), inspect=lambda *_: {})
                self.assertEqual(cli.install(args, runner), 0)
                self.assertTrue(all("-c" in a or "--quiet" in a for a in commands))
            self.assertFalse((root / "new-config").exists())
            self.assertFalse((root / "new-lib").exists())


class DeliveryTests(unittest.TestCase):
    def test_offline_cli_plan_for_one_two_three_profiles_contains_no_keys(self):
        universal = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir=WORK) as temporary:
            root = Path(temporary)
            for count in (1, 2, 3):
                command = [sys.executable, str(universal / "routerctl.py"), "plan", "--balanced-routes", str(universal / "examples/balanced.txt"),
                           "--pinned-routes", str(universal / "examples/pinned.txt"), "--pin-egress", str(count),
                           "--ingress-info", str(universal / "examples/ingress.json"), "--output", str(root / f"plan-{count}")]
                for n in range(1, count + 1):
                    profile = root / f"{n}.conf"
                    profile.write_text(profile_text(n))
                    command += ["--egress", str(profile)]
                result = subprocess.run(command, check=True, capture_output=True, text=True)
                summary = json.loads(result.stdout)
                self.assertEqual(len(summary["egresses"]), count)
                self.assertEqual(summary["pinned_egress"], count)
                self.assertNotIn(KEY, result.stdout)
                for p in (root / f"plan-{count}").iterdir():
                    self.assertNotIn(KEY, p.read_text())

    def test_archive_is_deterministic_complete_and_manifest_verifies(self):
        universal = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location("universal_package_test", universal / "tools/package.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(dir=WORK) as temporary:
            root = Path(temporary)
            one, two = root / "one.tar.gz", root / "two.tar.gz"
            self.assertEqual(module.package(one), module.package(two))
            with tarfile.open(one) as archive:
                files = {m.name: archive.extractfile(m).read() for m in archive.getmembers() if m.isfile()}
                self.assertIn("amnezia-router/install.sh", files)
                self.assertIn("amnezia-router/amnezia_router/runtime.py", files)
                self.assertFalse(any(n.endswith((".conf", ".key", ".pem", ".pyc")) for n in files))
                manifest = files["amnezia-router/SHA256SUMS"].decode().splitlines()
                for line in manifest:
                    digest, name = line.split("  ", 1)
                    self.assertEqual(hashlib.sha256(files["amnezia-router/" + name]).hexdigest(), digest)
                self.assertEqual(archive.getmember("amnezia-router/install.sh").mode, 0o755)


if __name__ == "__main__":
    unittest.main()
