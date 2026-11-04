"""Regressions for image preflight and verified firewall teardown."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from test_universal import WORK, config, profile_text
from amnezia_router import cli, render, system
from amnezia_router.config import ConfigError


def result(stdout="", code=0):
    return subprocess.CompletedProcess([], code, stdout, "permission denied" if code else "")


class DiscoveryRunner:
    """A compatible running ingress does not imply a compatible image."""
    ingress_image = "sha256:" + "a" * 64
    custom_image = "sha256:" + "b" * 64

    def __init__(self, probe_code=0):
        self.probe_code = probe_code
        self.calls = []

    def inspect(self, container):
        return {"Id": "ingress", "Image": self.ingress_image,
                "State": {"Running": True, "Pid": 42, "StartedAt": "start"},
                "HostConfig": {"NetworkMode": "bridge"},
                "NetworkSettings": {"Networks": {"existing": {"IPAddress": "172.20.0.2"}}}}

    def run(self, args, **kwargs):
        self.calls.append(("host", tuple(args), kwargs))
        if args == ["ip", "-j", "-4", "route", "show", "default"]:
            return result('[{"dev":"eth0","gateway":"192.0.2.254"}]')
        if args == ["ip", "-j", "-4", "route", "show", "table", "all"]:
            return result("[]")
        if args == ["nft", "-c", "-f", "-"]:
            return result()
        raise AssertionError("Unexpected host operation: " + str(args))

    def json(self, args):
        return json.loads(self.run(args).stdout)

    def ns(self, pid, *args, **kwargs):
        self.calls.append(("namespace", args, kwargs))
        if args == ("ip", "-j", "-4", "addr", "show"):
            return result(json.dumps([
                {"ifname": "awg0", "addr_info": [{"family": "inet", "local": "10.8.1.254", "prefixlen": 24}]},
                {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "172.20.0.2", "prefixlen": 16}]}]))
        if args == ("ip", "-j", "-4", "route", "show", "default"):
            return result('[{"dev":"eth0","gateway":"172.20.0.1"}]')
        if args == ("nft", "-c", "-f", "-"):
            return result()
        raise AssertionError("Unexpected namespace operation: " + str(args))

    def docker(self, *args, **kwargs):
        self.calls.append(("docker", args, kwargs))
        if args[:2] == ("exec", "amnezia-awg2"):
            if args[2:] == ("awg", "show", "interfaces"):
                return result("awg0\n")
            if args[2:] == ("awg", "show", "awg0", "listen-port"):
                return result("46777\n")
        if args[:2] == ("image", "inspect"):
            return result(json.dumps([{"Id": self.ingress_image if args[2] == self.ingress_image else self.custom_image}]))
        if args == ("network", "inspect", "existing"):
            return result(json.dumps([{"Id": "c" * 64, "Driver": "bridge", "Options": {"com.docker.network.bridge.name": "amn0"}}]))
        if args == ("network", "ls", "-q"):
            return result()
        if args[0] == "run":
            return result(code=self.probe_code)
        if args[:2] == ("compose", "--project-name") and args[-2:] == ("config", "--quiet"):
            return result()
        raise AssertionError("Unexpected Docker operation: " + str(args))


class ImagePreflightTests(unittest.TestCase):
    def test_default_and_override_probe_the_selected_image_id_without_network(self):
        for image in (None, "custom:mutable-tag"):
            with self.subTest(image=image), patch.object(system, "identity", return_value=("ingress", "start", 42, 1)):
                runner = DiscoveryRunner()
                ingress, _ = system.discovery(runner, "amnezia-awg2", egress_image=image)
            selected = runner.custom_image if image else runner.ingress_image
            self.assertEqual(ingress["egress_image"], selected)
            probes = [args for scope, args, _ in runner.calls if scope == "docker" and args[0] == "run"]
            self.assertEqual(len(probes), 1)
            probe = probes[0]
            self.assertEqual(probe[probe.index("--network") + 1], "none")
            self.assertEqual(probe[probe.index("--pull") + 1], "never")
            self.assertEqual(probe[probe.index("--entrypoint") + 1], "/bin/sh")
            self.assertEqual(probe[probe.index("-c") - 1], selected)
            self.assertIn("--rm", probe)
            self.assertIn("--no-healthcheck", probe)
            self.assertNotIn("--privileged", probe)
            self.assertNotIn("--mount", probe)
            self.assertNotIn("--volume", probe)
            self.assertFalse(any(scope == "docker" and args[:1] == ("exec",) and "-c" in args
                                 for scope, args, _ in runner.calls))

    def test_check_only_rejects_an_incompatible_image_before_any_installation(self):
        with tempfile.TemporaryDirectory(dir=WORK) as temporary:
            root = Path(temporary)
            profile, routes = root / "profile.conf", root / "routes.txt"
            profile.write_text(profile_text())
            routes.write_text("93.184.216.34/32\n")
            for image in (None, "missing-tools:local"):
                for code in (1, 125, 127):  # absent tools, failed create, absent shell
                    with self.subTest(image=image, code=code):
                        argv = ["install", "--egress", str(profile), "--balanced-routes", str(routes), "--check-only"]
                        if image:
                            argv += ["--egress-image", image]
                        args = cli.arguments().parse_args(argv)
                        with patch.object(cli, "CONFIG", root / "installation/config.json"), \
                             patch.object(cli.render, "LIB", str(root / "library")), \
                             patch.object(cli, "LAUNCHER", root / "launcher"), patch.object(cli, "UNITS", root / "units"), \
                             patch.object(cli, "DROPIN", root / "dropin"), patch.object(cli, "platform_checks", return_value={}), \
                             patch.object(system, "identity", return_value=("ingress", "start", 42, 1)), \
                             patch.object(cli, "resource_checks") as resources, patch.object(cli, "operation_lock") as lock:
                            runner = DiscoveryRunner(probe_code=code)
                            with self.assertRaisesRegex(ConfigError, "Selected egress image"):
                                cli.install(args, runner)
                            resources.assert_not_called()
                            lock.assert_not_called()
                        self.assertEqual(sorted(p.name for p in root.iterdir()), ["profile.conf", "routes.txt"])


class VerifiedRemovalTests(unittest.TestCase):
    present = json.dumps({"nftables": [{"table": {"family": "inet", "name": render.TABLE}}]})
    absent = json.dumps({"nftables": [{"table": {"family": "ip", "name": render.TABLE}},
                                      {"table": {"family": "inet", "name": "foreign"}}]})

    def test_removal_verifies_absence_and_accepts_an_already_absent_table(self):
        for existing in (False, True):
            for namespace in (False, True):
                with self.subTest(existing=existing, namespace=namespace):
                    responses = [result(self.present), result(), result(self.absent)] if existing else [result(self.absent), result(self.absent)]
                    runner = system.Runner()
                    runtime = types.SimpleNamespace(ns=lambda *a, **k: runner.ns(42, *a, **k)) if namespace else None
                    with patch.object(system.subprocess, "run", side_effect=responses) as commands:
                        cli.remove_nft_table(runner, runtime)
                    nft_commands = [c.args[0][c.args[0].index("nft"):] for c in commands.call_args_list]
                    self.assertEqual(nft_commands[0], ["nft", "-j", "list", "tables"])
                    self.assertEqual(nft_commands[-1], ["nft", "-j", "list", "tables"])
                    self.assertEqual(sum(c[1:2] == ["delete"] for c in nft_commands), int(existing))

    def test_deletion_and_inventory_errors_are_never_treated_as_absence(self):
        cases = [
            ([result(code=1)], RuntimeError),
            ([result(self.present), result(code=1)], RuntimeError),
            ([result(self.present), result(), result(code=1)], RuntimeError),
            ([result(self.present), result(), result(self.present)], ConfigError),
            ([result('{}')], ConfigError),
            ([result('{"nftables":[{"table":null}]}')], ConfigError),
        ]
        for responses, error in cases:
            with self.subTest(responses=responses), patch.object(system.subprocess, "run", side_effect=responses):
                with self.assertRaises(error):
                    cli.remove_nft_table(system.Runner())

    def test_uninstall_preserves_recovery_files_and_reports_failure_if_guard_remains(self):
        for outcome in ("already_absent", "removed", "delete_failed", "readback_failed", "still_present"):
            success = outcome in {"already_absent", "removed"}
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory(dir=WORK) as temporary:
                root = Path(temporary)
                conf, lib, units = root / "installation", root / "library", root / "units"
                for directory in (conf, lib, units):
                    directory.mkdir()
                paths = [conf / "config.json", lib / "routerctl.py", units / "amnezia-router.service",
                         units / "amnezia-router-guard.service", root / "launcher", root / "baseline.json", root / "dropin"]
                for path in paths:
                    path.write_text("preserve for retry")
                snapshot = self.absent if outcome == "already_absent" else self.present
                deleted = False
                def run(args, **kwargs):
                    nonlocal snapshot, deleted
                    if args[:3] == ["systemctl", "is-active", "--quiet"]:
                        return result(code=3)
                    if args == ["nft", "-j", "list", "tables"]:
                        if deleted and outcome == "readback_failed":
                            raise RuntimeError("Cannot verify table removal")
                        return result(snapshot)
                    if args == ["nft", "delete", "table", "inet", render.TABLE]:
                        if outcome == "delete_failed":
                            raise RuntimeError("nft delete denied")
                        deleted = True
                        if outcome != "still_present":
                            snapshot = self.absent
                    return result()
                runner = types.SimpleNamespace(run=run, docker=lambda *a, **k: result(code=1))
                runtime = Mock()
                runtime.baseline = {}
                runtime.owned_networks.return_value = []
                output, errors = io.StringIO(), io.StringIO()
                with patch.object(cli, "Runner", return_value=runner), patch.object(cli, "Runtime", return_value=runtime), \
                     patch.object(cli, "load_config", return_value=config(1)), patch.object(cli, "operation_lock", contextlib.nullcontext), \
                     patch.object(cli.sys, "platform", "linux"), patch.object(cli.os, "geteuid", return_value=0, create=True), \
                     patch.object(cli, "CONFIG", conf / "config.json"), patch.object(cli.render, "LIB", str(lib)), \
                     patch.object(cli, "UNITS", units), patch.object(cli, "LAUNCHER", root / "launcher"), \
                     patch.object(cli, "BACKUP", root / "baseline.json"), patch.object(cli, "DROPIN", root / "dropin"), \
                     patch.object(cli, "remove_chains"), patch.object(cli, "remove_policy"), \
                     contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    code = cli.main(["uninstall", "--restore-direct"])
                self.assertEqual(code, 0 if success else 2)
                self.assertEqual("Исходный прямой путь восстановлен" in output.getvalue(), success)
                for path in paths[:-1]:
                    self.assertEqual(path.exists(), not success, str(path))
                if success:
                    self.assertTrue(list(root.glob("installation.uninstalled-*/config.json")))
                else:
                    self.assertTrue(errors.getvalue())
