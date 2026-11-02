"""Opt-in kernel integration in an isolated namespace, never a live VPN."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
import uuid

from runtime_fixtures import ROOT, HOST_SAVE, INGRESS_SAVE, V6_SAVE, environment
sys.path.insert(0, str(ROOT / "templates/v2/host"))
from runtime_checks import RuntimeChecks, fingerprint


@unittest.skipUnless(sys.platform == "linux" and os.environ.get("AMNEZIA_LB_INTEGRATION") == "1", "requires opt-in isolated Linux namespace")
class LinuxRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "work")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = environment(self.root)
        self.namespace = "aml-test-" + uuid.uuid4().hex[:10]
        subprocess.run(["ip", "netns", "add", self.namespace], check=True)
        self.addCleanup(lambda: subprocess.run(["ip", "netns", "delete", self.namespace], check=True))
        self.process = subprocess.Popen(["ip", "netns", "exec", self.namespace, "sleep", "180"])
        self.addCleanup(self.process.wait)
        self.addCleanup(self.process.terminate)
        host = self.root / "v2/host"
        host.mkdir()
        for name in ("runtime-collect.py", "default-route-check.py", "rpdb-check.py"):
            shutil.copy2(ROOT / "templates/v2/host" / name, host / name)
        for name, key, prefix in (("outer", "INGRESS_OUTER_IP", 24), ("aux", "INGRESS_AUX_IP", 16),
                                  ("direct", "INGRESS_DIRECT_IP", 24), ("transit", "INGRESS_TRANSIT_IP", 24)):
            self.ns("ip", "link", "add", name, "type", "dummy")
            self.ns("ip", "link", "set", name, "up")
            self.ns("ip", "addr", "add", self.env[key] + "/" + str(prefix), "dev", name)
        self.ns("ip", "link", "add", self.env["INGRESS_AWG_IF"], "type", "dummy")
        self.ns("iptables-restore", input=INGRESS_SAVE.format_map(self.env))
        self.ns("ip6tables-restore", input=V6_SAVE.format_map(self.env))
        for chain in ("ufw-before-forward", "f2b-sshd", "DOCKER-FORWARD"):
            self.ns("iptables", "-N", chain)
            self.ns("iptables", "-A", chain, "-p", "tcp", "--tcp-flags", "FIN,SYN,RST,ACK", "SYN", "-j", "RETURN")
        for table, gateway, device, source in (("main", self.env["INGRESS_OUTER_GATEWAY"], "outer", self.env["INGRESS_OUTER_IP"]),
                                              (self.env["OUTER_ROUTE_TABLE"], self.env["INGRESS_OUTER_GATEWAY"], "outer", self.env["INGRESS_OUTER_IP"]),
                                              (self.env["DIRECT_ROUTE_TABLE"], self.env["DIRECT_GATEWAY"], "direct", self.env["INGRESS_DIRECT_IP"])):
            self.ns("ip", "route", "add", "default", "via", gateway, "dev", device, "src", source, "table", table)
        for prefix, interface in (("OUTER", "lo"), ("TARGET", self.env["INGRESS_AWG_IF"]), ("DIRECT", self.env["INGRESS_AWG_IF"])):
            selectors = ["iif", interface]
            if prefix == "OUTER":
                selectors += ["ipproto", "udp", "sport", self.env["INGRESS_AWG_PORT"]]
            if prefix == "TARGET":
                selectors += ["fwmark", "0x101/0xffffffff"]
            self.ns("ip", "rule", "add", "priority", self.env[prefix + "_LOOKUP_PRIORITY"], "protocol", "99", *selectors, "lookup", self.env[prefix + "_ROUTE_TABLE"])
            self.ns("ip", "rule", "add", "priority", self.env[prefix + "_UNREACHABLE_PRIORITY"], "protocol", "99", *selectors, "unreachable")
        template = (ROOT / "templates/v2/host/ingress-targets.create.nft.in").read_text()
        for key, value in {**self.env, "TARGET_ELEMENTS": "93.184.216.34/32"}.items():
            template = template.replace(f"@@{key}@@", value)
        self.ns("nft", "-f", "-", input=template)
        document = json.loads(self.ns("nft", "-j", "list", "table", "inet", "amnezia_lb_v2_targets").stdout)
        (self.root / f"ingress-targets.{self.process.pid}.sha256").write_text(fingerprint(document))
        for name in ("all", "outer", "aux", "direct", "transit", self.env["INGRESS_AWG_IF"]):
            self.ns("sysctl", "-q", "-w", f"net.ipv4.conf.{name}.rp_filter=2")

    def ns(self, *args, **kwargs):
        return subprocess.run(["ip", "netns", "exec", self.namespace, *args], check=True, capture_output=True, text=True, **kwargs)

    def runner(self, args, **kwargs):
        if args[:2] == ["docker", "inspect"]:
            e = self.env
            networks = {e[n]: {"IPAddress": e[k]} for n, k in (("INGRESS_OUTER_NETWORK", "INGRESS_OUTER_IP"),
                        ("INGRESS_DNS_NETWORK", "INGRESS_DNS_IP"), ("INGRESS_AUX_NETWORK", "INGRESS_AUX_IP"),
                        ("DIRECT_NETWORK", "INGRESS_DIRECT_IP"), ("TRANSIT_NETWORK", "INGRESS_TRANSIT_IP"))}
            data = [{"Id": "test", "State": {"Running": True, "Pid": self.process.pid, "StartedAt": "test"}, "NetworkSettings": {"Networks": networks}}]
            return types.SimpleNamespace(stdout=json.dumps(data))
        if args[:2] == ["docker", "exec"]:
            return types.SimpleNamespace(stdout=self.env["INGRESS_AWG_PORT"] + "\n")
        if args == ["iptables-save"]:
            return types.SimpleNamespace(stdout=HOST_SAVE.format_map(self.env))
        return subprocess.run(args, **kwargs)

    def test_real_kernel_snapshots_and_missing_terminal_rule(self):
        checks = RuntimeChecks(self.root / "v2", runtime_dir=self.root, runner=self.runner)
        checks.check_ingress(self.process.pid)
        self.ns("ip", "rule", "delete", "priority", self.env["TARGET_UNREACHABLE_PRIORITY"])
        with self.assertRaisesRegex(ValueError, "occurs 0 times"):
            checks.check_ingress(self.process.pid)
