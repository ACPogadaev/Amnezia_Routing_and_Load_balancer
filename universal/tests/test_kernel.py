"""Opt-in packet tests in disposable namespaces; never touches a live VPN."""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import subprocess
import sys
import types
import unittest
import uuid

from test_universal import config
from amnezia_router import cli, render
from amnezia_router.balance import FAIL_MARK, Health, bucket_map, pinned_mark
from amnezia_router.runtime import Runtime, validate_policy_rule
from amnezia_router.system import Runner


@unittest.skipUnless(sys.platform == "linux" and os.environ.get("AMNEZIA_ROUTER_INTEGRATION") == "1",
                     "requires opt-in isolated Linux namespaces")
class PacketRoutingTests(unittest.TestCase):
    def test_nft_table_removal_verifies_absence_and_preserves_foreign_tables(self):
        namespace = self.namespace("remove")
        call = lambda *a, **k: self.ns(namespace, *a, **k)
        call("nft", "add", "table", "inet", "foreign")
        call("nft", "add", "table", "ip", render.TABLE)
        runner = types.SimpleNamespace(run=lambda a, **k: call(*a, **k))
        for runtime in (None, types.SimpleNamespace(ns=call)):
            call("nft", "add", "table", "inet", render.TABLE)
            cli.remove_nft_table(runner, runtime)
            cli.remove_nft_table(runner, runtime)
            tables = json.loads(call("nft", "-j", "list", "tables").stdout)["nftables"]
            actual = {(t["table"]["family"], t["table"]["name"]) for t in tables if "table" in t}
            self.assertEqual(actual, {("inet", "foreign"), ("ip", render.TABLE)})

    def command(self, *args, **kwargs):
        return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs)

    def ns(self, name, *args, **kwargs):
        return self.command("ip", "netns", "exec", name, *args, **kwargs)

    def namespace(self, suffix):
        name = "amr-test-" + uuid.uuid4().hex[:8] + "-" + suffix
        self.command("ip", "netns", "add", name)
        self.addCleanup(lambda: self.command("ip", "netns", "delete", name))
        self.ns(name, "ip", "link", "set", "lo", "up")
        return name

    def link(self, host, peer, net):
        bridge = net["bridge"]
        self.ns(host, "ip", "link", "add", bridge, "type", "veth", "peer", "name", "peer0")
        self.ns(host, "ip", "link", "set", "peer0", "netns", peer)
        self.ns(host, "ip", "addr", "add", net["gateway"] + "/24", "dev", bridge)
        self.ns(host, "ip", "link", "set", bridge, "up")
        self.ns(peer, "ip", "addr", "add", net["address"] + "/24", "dev", "peer0")
        self.ns(peer, "ip", "link", "set", "peer0", "up")
        self.ns(peer, "ip", "route", "add", "default", "via", net["gateway"])
        for namespace, interface in ((host, bridge), (peer, "peer0")):
            self.ns(namespace, "sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=0", f"net.ipv4.conf.{interface}.rp_filter=0")

    def receiver(self, namespace):
        code = "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('93.184.216.34',19000)); print('ready',flush=True)\nwhile True: print(s.recvfrom(128)[0].decode(),flush=True)"
        process = subprocess.Popen(["ip", "netns", "exec", namespace, sys.executable, "-u", "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def close():
            process.terminate()
            process.communicate(timeout=5)
        self.addCleanup(close)
        self.assertTrue(select.select([process.stdout], [], [], 5)[0], "receiver did not start")
        self.assertEqual(process.stdout.readline().strip(), "ready")
        return process

    def send(self, namespace):
        self.ns(namespace, sys.executable, "-c", "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('',23456)); s.sendto(b'routed',('93.184.216.34',19000))")

    def test_pinned_packets_and_existing_flow_quarantine_for_one_two_three_exits(self):
        for count in (1, 2, 3):
            with self.subTest(egresses=count):
                c = config(count)
                host, ingress = self.namespace("host"), self.namespace("in")
                self.link(host, ingress, c["transit"])
                for name in (c["ingress"]["public_if"], c["direct"]["bridge"], c["ingress"]["attachments"][0]["bridge"]):
                    self.ns(host, "ip", "link", "add", name, "type", "dummy")
                    self.ns(host, "ip", "link", "set", name, "up")
                self.ns(host, "ip", "addr", "add", "198.51.100.1/24", "dev", c["ingress"]["public_if"])
                self.ns(host, "ip", "route", "add", "default", "via", "198.51.100.254")
                self.ns(host, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
                receivers = []
                for egress in c["egresses"]:
                    peer = self.namespace("e" + str(egress["id"]))
                    self.link(host, peer, egress["network"])
                    self.ns(peer, "ip", "addr", "add", "93.184.216.34/32", "dev", "lo")
                    receivers.append(self.receiver(peer))
                test = self
                class NamespaceRunner(Runner):
                    def run(self, args, **kwargs):
                        return super().run(["ip", "netns", "exec", host, *args], **kwargs)
                runtime = Runtime(c, NamespaceRunner())
                runtime.boot_guard()
                runtime.host_routing()
                health = {e["id"]: Health(healthy=True) for e in c["egresses"]}
                runtime.nft_apply(render.selector(c, bucket_map(c["egresses"], health, c), pinned_mark(c, health), set()))
                self.send(ingress)
                owner = receivers[-1]
                self.assertTrue(select.select([owner.stdout], [], [], 3)[0], "pinned packet did not reach its selected egress")
                self.assertEqual(owner.stdout.readline().strip(), "routed")
                self.assertFalse(select.select([p.stdout for p in receivers[:-1]], [], [], 0.1)[0])
                # Same UDP tuple retains its original ct mark. Quarantine must
                # block it even while other balanced egresses remain available.
                health[count].healthy = False
                runtime.nft_apply(render.selector(c, bucket_map(c["egresses"], health, c), pinned_mark(c, health), {c["egresses"][-1]["mark"]}))
                self.send(ingress)
                self.assertFalse(select.select([p.stdout for p in receivers], [], [], 0.3)[0], "quarantined flow reached an egress")
                table = json.loads(runtime.nft_snapshot())
                counters = [expr["counter"]["packets"] for entry in table["nftables"] if "rule" in entry and entry["rule"].get("chain") == "quarantine"
                            for expr in entry["rule"].get("expr", []) if "counter" in expr]
                self.assertGreater(sum(counters), 0)
                # Empty egress table must end in unreachable instead of main.
                first = c["egresses"][0]
                self.ns(host, "ip", "route", "flush", "table", str(first["table"]))
                result = subprocess.run(["ip", "netns", "exec", host, "ip", "route", "get", "93.184.216.35", "mark", str(first["mark"])], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, "missing egress route fell through to main")
                rules = json.loads(self.ns(host, "ip", "-N", "-j", "rule", "show").stdout)
                validate_policy_rule(rules, 31001, {"fwmark": first["mark"], "fwmask": 0xFFFFFFFF, "action": "unreachable"})


if __name__ == "__main__":
    unittest.main()
