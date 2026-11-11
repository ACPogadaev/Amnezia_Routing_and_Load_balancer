from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shlex
import signal
import tempfile
import threading
import time

from .balance import FAIL_MARK, Health, bucket_map, pinned_mark
from .config import ConfigError, require, validate_runtime
from . import render
from .system import Runner, identity, route_table_entries

CONFIG = Path(render.BASE) / "config.json"
STATE = Path("/run/amnezia-router/state.json")
BACKUP = Path("/var/lib/amnezia-router/baseline.json")


def atomic_json(path, document, mode=0o600):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def load_config(path=CONFIG):
    return validate_runtime(json.loads(Path(path).read_text(encoding="utf-8")))


def fingerprint(snapshot):
    def strip_runtime_fields(node):
        for field in ("handle", "index", "packets", "bytes", "expires", "last"):
            node.pop(field, None)
        return node

    document = json.loads(snapshot, object_hook=strip_runtime_fields)
    document = [entry for entry in document["nftables"] if "metainfo" not in entry]
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def canonical(tokens):
    if isinstance(tokens, str):
        tokens = shlex.split(tokens)
    result = []
    index = 0
    while index < len(tokens):
        negative = tokens[index] == "!"
        index += int(negative)
        require(index < len(tokens) and tokens[index].startswith("-"), "Unexpected rule grammar")
        name = tokens[index]
        index += 1
        value = ""
        if index < len(tokens) and tokens[index] != "!" and not tokens[index].startswith("-"):
            value = tokens[index]
            index += 1
        if name in {"-s", "-d"}:
            value = str(ipaddress.ip_network(value, strict=False))
        if name in {"--dscp", "--set-dscp"}:
            value = str(int(value, 0))
        if name == "--ctstate":
            value = ",".join(sorted(value.split(",")))
        result.append((name, value, negative))
    protocol = next((v for k, v, n in result if k == "-p" and not n), None)
    reject = ("-j", "REJECT", False) in result
    return sorted(item for item in result if item != ("-m", protocol, False)
                  and not (reject and item[0] == "--reject-with" and item[1] in {"icmp-port-unreachable", "icmp6-port-unreachable"} and not item[2]))


def chain_rules(text, chain):
    return [shlex.split(line)[2:] for line in text.splitlines() if line.startswith(f"-A {chain} ")]


def verify_chain(snapshot, parent, chain, expected, table=None):
    if table is not None:
        current, selected = None, []
        for line in snapshot.splitlines():
            if line.startswith("*"):
                current = line[1:]
            elif line == "COMMIT":
                current = None
            elif current == table:
                selected.append(line)
        snapshot = "\n".join(selected)
    actual = chain_rules(snapshot, chain)
    require([canonical(r) for r in actual] == [canonical(r) for r in expected], "Owned firewall chain differs: " + chain)
    parents = chain_rules(snapshot, parent)
    positions = [index for index, rule in enumerate(parents) if chain in rule]
    require(positions == [0] and parents[0] == ["-j", chain], "Owned firewall jump is missing, duplicated or conditional: " + chain)


def numeric(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def validate_policy_rule(document, priority, expected):
    matches = [r for r in document if int(r["priority"]) == priority]
    require(len(matches) == 1, "Missing or duplicate policy fence")
    rule = dict(matches[0])
    require(str(rule.get("protocol")) in {"99", "openr"}, "Policy ownership changed")
    # iproute2 omits the all-ones mask and can render unreachable as numeric 7.
    if "fwmark" in rule:
        rule.setdefault("fwmask", 0xFFFFFFFF)
    if str(rule.get("action")) == "7":
        rule["action"] = "unreachable"
    for key in ("src", "dst"):
        raw = rule.get(key, "all")
        embedded = ipaddress.IPv4Network("0.0.0.0/0" if raw == "all" else raw, strict=False)
        length = int(rule.get(key + "len", embedded.prefixlen))
        actual = ipaddress.IPv4Network(f"{embedded.network_address}/{length}", strict=False)
        wanted = ipaddress.IPv4Network(expected.get(key, "0.0.0.0/0"), strict=False)
        require(actual == wanted, "Unexpected policy source/destination selector")
    for key, value in expected.items():
        if key in {"src", "dst"}:
            continue
        observed = rule.get(key)
        if key in {"fwmark", "fwmask", "table"}:
            require(observed is not None and numeric(observed) == value, "Policy selector/lookup drift")
        else:
            require(observed == value, "Policy selector drift")
    allowed = {"priority", "protocol", "src", "srclen", "dst", "dstlen", *expected}
    require(not (set(rule) - allowed), "Unexpected policy selectors")


class Runtime:
    def __init__(self, config, runner=None):
        self.config = validate_runtime(config)
        self.runner = runner or Runner()
        self.host_fingerprint = None
        self.ingress_fingerprint = None
        self.ingress_identity = None
        self.interfaces = None
        self.stopped = threading.Event()
        self.health = {e["id"]: Health() for e in config["egresses"]}
        self.baseline = json.loads(BACKUP.read_text()) if BACKUP.exists() else {"schema": 1, "host_sysctls": {}, "ingress_sysctls": {}, "ingress_identity": None}
        self.last_policy = None

    def ns(self, *args, **kwargs):
        require(self.ingress_identity is not None, "Ingress namespace is unavailable")
        return self.runner.ns(self.ingress_identity[2], *args, **kwargs)

    def nft_snapshot(self, ingress=False):
        args = ["nft", "-j", "list", "table", "inet", render.TABLE]
        return (self.ns(*args) if ingress else self.runner.run(args)).stdout

    def nft_apply(self, text, ingress=False):
        call = self.ns if ingress else self.runner.run
        if ingress:
            call("nft", "-c", "-f", "-", input=text)
            call("nft", "-f", "-", input=text)
        else:
            call(["nft", "-c", "-f", "-"], input=text)
            call(["nft", "-f", "-"], input=text)

    def block(self):
        """Close target admission without relying on health, forwarding or Compose."""
        result = self.runner.docker("inspect", self.config["ingress"]["container"], check=False)
        if not result.returncode:
            data = json.loads(result.stdout)[0]
            if data.get("State", {}).get("Running") and int(data["State"].get("Pid", 0)) > 0:
                pid = data["State"]["Pid"]
                rules = json.loads(self.runner.ns(pid, "ip", "-N", "-j", "-4", "rule", "show").stdout)
                fences = [r for r in rules if int(r["priority"]) == 31099]
                if fences:
                    validate_policy_rule(rules, 31099, {"iif": self.config["ingress"]["interface"], "fwmark": render.TARGET_MARK,
                                                       "fwmask": 0xFFFFFFFF, "action": "unreachable"})
                else:
                    self.runner.ns(pid, "ip", "rule", "add", "priority", "31099", "protocol", "99", "iif", self.config["ingress"]["interface"],
                                   "fwmark", f"{render.TARGET_MARK}/0xffffffff", "unreachable")
                self.runner.ns(pid, "ip", "route", "flush", "table", str(render.TRANSIT_TABLE), "proto", "99", check=False)

    def boot_guard(self):
        exists = self.runner.run(["nft", "list", "table", "inet", render.TABLE], check=False).returncode == 0
        self.nft_apply(render.host_nft(self.config, replace=exists))
        self.host_fingerprint = fingerprint(self.nft_snapshot())
        self.last_policy = None

    def compose(self, *args, check=True):
        return self.runner.docker("compose", "--project-name", render.PROJECT, "--project-directory", render.BASE,
                                  "-f", render.BASE + "/compose.json", *args, check=check, timeout=120)

    def owned_networks(self):
        return [self.config["direct"], self.config["transit"], *(e["network"] for e in self.config["egresses"])]

    def ensure_networks(self):
        for net in self.owned_networks():
            result = self.runner.docker("network", "inspect", net["name"], check=False)
            if result.returncode:
                self.runner.docker("network", "create", "--driver", "bridge", "--subnet", net["subnet"],
                    "--gateway", net["gateway"], "--opt", "com.docker.network.bridge.name=" + net["bridge"],
                    "--label", "org.amnezia-router.managed=1", net["name"])
                result = self.runner.docker("network", "inspect", net["name"])
            data = json.loads(result.stdout)[0]
            require((data.get("Labels") or {}).get("org.amnezia-router.managed") == "1", "Refusing a foreign Docker network")
            require(data.get("Driver") == "bridge" and data.get("Options", {}).get("com.docker.network.bridge.name") == net["bridge"], "Managed Docker bridge drift")
            ipam = data.get("IPAM", {}).get("Config", [])
            require(len(ipam) == 1 and ipam[0].get("Subnet") == net["subnet"] and ipam[0].get("Gateway") == net["gateway"]
                    and not ipam[0].get("IPRange") and not ipam[0].get("AuxiliaryAddresses"), "Managed Docker IPAM drift")
        container = self.config["ingress"]["container"]
        for net in [self.config["direct"], self.config["transit"]]:
            data = self.runner.inspect(container)
            attachments = data["NetworkSettings"]["Networks"]
            if net["name"] not in attachments:
                self.runner.docker("network", "connect", "--gw-priority", "-1", "--ip", net["address"], net["name"], container)
                data = self.runner.inspect(container)
            require(data["NetworkSettings"]["Networks"][net["name"]]["IPAddress"] == net["address"], "Managed ingress attachment has a different IP")

    def save_baseline(self):
        atomic_json(BACKUP, self.baseline)

    def host_sysctls(self):
        own = {net["bridge"] for net in self.owned_networks()}
        interfaces = [x["ifname"] for x in self.runner.json(["ip", "-j", "link", "show"])]
        old = self.baseline["host_sysctls"]
        # Record originals durably before the first write; preserve the original
        # all-interface RPF policy on existing non-project interfaces.
        for interface in ["all", *interfaces]:
            key = f"net.ipv4.conf.{interface}.rp_filter"
            if key not in old and interface not in own:
                old[key] = int(self.runner.run(["sysctl", "-n", key]).stdout.strip())
        self.save_baseline()
        all_value = old["net.ipv4.conf.all.rp_filter"]
        for interface in interfaces:
            key = f"net.ipv4.conf.{interface}.rp_filter"
            value = 0 if interface in own else max(all_value, old[key])
            self.runner.run(["sysctl", "-q", "-w", f"{key}={value}"])
        self.runner.run(["sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=0"])

    def put_chains(self, chains, ingress=False, ipv6=False):
        binary = "ip6tables" if ipv6 else "iptables"
        for table, parent, chain, rules in chains:
            batch = f"*{table}\n:{chain} - [0:0]\n-F {chain}\n" + "".join(f"-A {chain} {rule}\n" for rule in rules) + "COMMIT\n"
            if ingress:
                self.ns(binary + "-restore", "--wait", "5", "--noflush", input=batch)
                call = lambda *a, **k: self.ns(binary, "-w", "5", "-t", table, *a, **k)
            else:
                self.runner.run([binary + "-restore", "--wait", "5", "--noflush"], input=batch)
                call = lambda *a, **k: self.runner.run([binary, "-w", "5", "-t", table, *a], **k)
            # Only remove our own exact jump; refuse foreign conditional jumps.
            snapshot = call("-S", parent).stdout
            refs = [r for r in chain_rules(snapshot, parent) if chain in r]
            require(all(r == ["-j", chain] for r in refs), "Conditional reference to a managed chain")
            for _ in refs:
                call("-D", parent, "-j", chain)
            call("-I", parent, "1", "-j", chain)

    def replace_rule(self, priority, args, ingress=False):
        call = self.ns if ingress else lambda *a, **k: self.runner.run(list(a), **k)
        rules = json.loads(call("ip", "-N", "-j", "-4", "rule", "show").stdout)
        matching = [r for r in rules if int(r["priority"]) == priority]
        require(all(str(r.get("protocol")) in {"99", "openr"} for r in matching), "A foreign policy rule occupies a managed priority")
        for _ in matching:
            call("ip", "rule", "del", "priority", str(priority), "protocol", "99")
        call("ip", "rule", "add", "priority", str(priority), "protocol", "99", *args)

    def host_routing(self):
        for egress in self.config["egresses"]:
            priority = 31000 + (egress["id"] - 1) * 2
            # The terminal fence is in place before a lookup can be admitted.
            self.replace_rule(priority + 1, ["fwmark", f"{egress['mark']}/0xffffffff", "unreachable"])
            self.runner.run(["ip", "route", "replace", "default", "via", egress["network"]["address"],
                "dev", egress["network"]["bridge"], "onlink", "table", str(egress["table"]), "proto", "99"])
            self.replace_rule(priority, ["fwmark", f"{egress['mark']}/0xffffffff", "lookup", str(egress["table"])])
        self.replace_rule(31006, ["fwmark", f"{FAIL_MARK}/0xffffffff", "unreachable"])
        self.replace_rule(31007, ["iif", self.config["transit"]["bridge"], "from", self.config["transit"]["address"] + "/32", "unreachable"])

    def interface_for(self, address):
        addresses = json.loads(self.ns("ip", "-j", "-4", "addr", "show").stdout)
        found = [item["ifname"] for item in addresses for a in item.get("addr_info", []) if a.get("local") == address]
        require(len(found) == 1, "Cannot uniquely resolve a managed ingress interface")
        return found[0]

    def configure_ingress(self):
        self.block()
        self.ingress_identity = identity(self.runner.inspect(self.config["ingress"]["container"]))
        c = self.config
        direct_if, transit_if = self.interface_for(c["direct"]["address"]), self.interface_for(c["transit"]["address"])
        # Re-resolve after Docker restarts: interface names need not remain stable.
        outer_ip = self.outer_address()
        outer_if = self.interface_for(outer_ip)
        self.interfaces = direct_if, transit_if, outer_if
        old = self.baseline["ingress_sysctls"]
        current_key = list(self.ingress_identity)
        if self.baseline.get("ingress_identity") != current_key:
            old.clear()
            self.baseline["ingress_identity"] = current_key
        for interface in ["all", "default", direct_if, transit_if, outer_if, c["ingress"]["interface"]]:
            key = f"net.ipv4.conf.{interface}.rp_filter"
            if key not in old:
                old[key] = int(self.ns("sysctl", "-n", key).stdout.strip())
        self.save_baseline()
        for key in old:
            self.ns("sysctl", "-q", "-w", key + "=2")
        for priority, args in (
            (31101, ["iif", c["ingress"]["interface"], "fwmark", f"{render.TARGET_MARK}/0xffffffff", "unreachable"]),
            (31103, ["iif", c["ingress"]["interface"], "unreachable"]),
            (31100, ["iif", c["ingress"]["interface"], "fwmark", f"{render.TARGET_MARK}/0xffffffff", "lookup", str(render.TRANSIT_TABLE)]),
            (31102, ["iif", c["ingress"]["interface"], "lookup", str(render.DIRECT_TABLE)])):
            self.replace_rule(priority, args, ingress=True)
        self.ns("ip", "route", "replace", "default", "via", c["direct"]["gateway"], "dev", direct_if,
                "src", c["direct"]["address"], "table", str(render.DIRECT_TABLE), "proto", "99")
        exists = self.ns("nft", "list", "table", "inet", render.TABLE, check=False).returncode == 0
        self.nft_apply(render.ingress_nft(c, replace=exists), ingress=True)
        self.put_chains(render.ingress_chains(c, direct_if, transit_if, outer_if), ingress=True)
        self.put_chains([("filter", "FORWARD", "AMR_IPV6", [f"-i {c['ingress']['interface']} -j REJECT", "-j RETURN"])], ingress=True, ipv6=True)
        require(identity(self.runner.inspect(c["ingress"]["container"])) == self.ingress_identity, "Ingress changed during configuration")
        self.ingress_fingerprint = fingerprint(self.nft_snapshot(ingress=True))

    def outer_address(self):
        addresses = json.loads(self.ns("ip", "-j", "-4", "addr", "show").stdout)
        routes = json.loads(self.ns("ip", "-j", "-4", "route", "show", "default").stdout)
        require(len(routes) == 1 and routes[0].get("gateway") == self.config["ingress"]["outer_gateway"], "Original ingress default route changed")
        found = {a["local"] for item in addresses if item["ifname"] == routes[0]["dev"] for a in item.get("addr_info", [])}
        return next(a["address"] for a in self.config["ingress"]["attachments"] if a["address"] in found)

    def validate_infrastructure(self):
        data = self.runner.inspect(self.config["ingress"]["container"])
        require(identity(data) == self.ingress_identity, "Ingress identity changed")
        expected_attachments = {a["name"]: a["address"] for a in self.config["ingress"]["attachments"]}
        expected_attachments.update({n["name"]: n["address"] for n in (self.config["direct"], self.config["transit"])})
        actual_attachments = {name: item["IPAddress"] for name, item in data["NetworkSettings"]["Networks"].items() if item.get("IPAddress")}
        require(actual_attachments == expected_attachments, "Ingress Docker attachments changed")
        require(fingerprint(self.nft_snapshot()) == self.host_fingerprint, "Host nftables drift")
        require(fingerprint(self.nft_snapshot(ingress=True)) == self.ingress_fingerprint, "Ingress classifier drift")
        host_save = self.runner.run(["iptables-save"]).stdout
        for table, parent, chain, expected in render.host_chains(self.config):
            verify_chain(host_save, parent, chain, expected, table)
        ingress_save = self.ns("iptables-save").stdout
        for table, parent, chain, expected in render.ingress_chains(self.config, *self.interfaces):
            verify_chain(ingress_save, parent, chain, expected, table)
        verify_chain(self.ns("ip6tables-save").stdout, "FORWARD", "AMR_IPV6", [f"-i {self.config['ingress']['interface']} -j REJECT", "-j RETURN"], "filter")
        self.validate_routes()
        keys = ["net.ipv4.conf.all.rp_filter"] + [f"net.ipv4.conf.{n['bridge']}.rp_filter" for n in self.owned_networks()]
        require(self.runner.run(["sysctl", "-n", *keys]).stdout.split() == ["0"] * len(keys), "Host RPF drift")
        require(self.ns("sysctl", "-n", "net.ipv4.conf.all.rp_filter").stdout.strip() == "2", "Ingress RPF drift")
        require(self.outer_address(), "Ingress outer route unavailable")
        require(identity(self.runner.inspect(self.config["ingress"]["container"])) == self.ingress_identity, "Ingress changed during validation")

    def validate_routes(self):
        rules = self.runner.json(["ip", "-N", "-j", "-4", "rule", "show"])
        check_rule = validate_policy_rule
        owned = {31006, 31007} | {31000 + n for n in range(len(self.config["egresses"]) * 2)}
        require(all(not (0 < int(r["priority"]) < 32766) or int(r["priority"]) in owned for r in rules), "Unexpected host policy priority")
        for egress in self.config["egresses"]:
            priority = 31000 + 2 * (egress["id"] - 1)
            selectors = {"fwmark": egress["mark"], "fwmask": 0xFFFFFFFF}
            check_rule(rules, priority, {**selectors, "table": egress["table"]})
            check_rule(rules, priority + 1, {**selectors, "action": "unreachable"})
            routes = self.runner.json(["ip", "-j", "-4", "route", "show", "table", str(egress["table"])])
            require(len(routes) == 1 and routes[0].get("dst") == "default" and routes[0].get("gateway") == egress["network"]["address"]
                    and routes[0].get("dev") == egress["network"]["bridge"] and "onlink" in routes[0].get("flags", [])
                    and str(routes[0].get("protocol")) in {"99", "openr"}, "Host egress default drift")
        check_rule(rules, 31006, {"fwmark": FAIL_MARK, "fwmask": 0xFFFFFFFF, "action": "unreachable"})
        check_rule(rules, 31007, {"iif": self.config["transit"]["bridge"], "src": self.config["transit"]["address"] + "/32", "action": "unreachable"})
        ingress_rules = json.loads(self.ns("ip", "-N", "-j", "-4", "rule", "show").stdout)
        require(all(not (0 < int(r["priority"]) < 32766) or int(r["priority"]) in range(31099, 31104) for r in ingress_rules), "Unexpected ingress policy priority")
        if any(int(r["priority"]) == 31099 for r in ingress_rules):
            check_rule(ingress_rules, 31099, {"iif": self.config["ingress"]["interface"], "fwmark": render.TARGET_MARK,
                                           "fwmask": 0xFFFFFFFF, "action": "unreachable"})
        for priority, expected in ((31100, {"iif": self.config["ingress"]["interface"], "fwmark": render.TARGET_MARK, "fwmask": 0xFFFFFFFF, "table": render.TRANSIT_TABLE}),
            (31101, {"iif": self.config["ingress"]["interface"], "fwmark": render.TARGET_MARK, "fwmask": 0xFFFFFFFF, "action": "unreachable"}),
            (31102, {"iif": self.config["ingress"]["interface"], "table": render.DIRECT_TABLE}),
            (31103, {"iif": self.config["ingress"]["interface"], "action": "unreachable"})):
            check_rule(ingress_rules, priority, expected)
        direct = json.loads(self.ns("ip", "-j", "-4", "route", "show", "table", str(render.DIRECT_TABLE)).stdout)
        require(len(direct) == 1 and direct[0].get("gateway") == self.config["direct"]["gateway"] and direct[0].get("dev") == self.interfaces[0], "Ingress direct default drift")
        transit = route_table_entries(self.ns("ip", "-j", "-4", "route", "show", "table", str(render.TRANSIT_TABLE), check=False), allow_missing=True)
        require(not transit or (len(transit) == 1 and transit[0].get("gateway") == self.config["transit"]["gateway"]
                and transit[0].get("dev") == self.interfaces[1]), "Ingress target default drift")

    def setup(self):
        self.block()
        self.boot_guard()
        self.ensure_networks()
        self.host_sysctls()
        self.host_routing()
        self.put_chains(render.host_chains(self.config))
        self.configure_ingress()
        self.validate_infrastructure()
        # The explicit project and complete service set make lifecycle scope independent of directory names.
        self.compose("up", "-d", "--no-build")

    def probe(self, egress):
        container = egress["container"]
        try:
            data = self.runner.inspect(container)
            current = identity(data)
        except Exception:
            return {"healthy": False, "reason": "container_stopped"}, None
        labels = data.get("Config", {}).get("Labels") or {}
        require(labels.get("com.docker.compose.project") == render.PROJECT and labels.get("com.docker.compose.service") == egress["name"]
                and labels.get("org.amnezia-router.managed") == "1", "Refusing an unmanaged egress container")
        ready = self.runner.docker("exec", container, "cat", "/run/amnezia-router/ready", check=False)
        instance = ready.stdout.strip()
        if ready.returncode or not instance:
            return {"healthy": False, "reason": "starting"}, current
        pid = current[2]
        forwarding = self.runner.ns(pid, "sysctl", "-n", "net.ipv4.ip_forward").stdout.strip()
        if forwarding == "0":
            # Host infrastructure was checked before any worker enables forwarding.
            require(identity(self.runner.inspect(container)) == current, "Egress changed before forwarding enable")
            self.runner.ns(pid, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
        elif forwarding != "1":
            raise ConfigError("Invalid egress forwarding state")
        result = self.runner.docker("exec", container, "timeout", "16", "/run/amnezia-router/egress-healthcheck.sh", "--json", check=False, timeout=25)
        try:
            sample = json.loads(result.stdout.strip().splitlines()[-1])
            now = time.time()
            require(type(sample.get("schema_version")) is int and sample["schema_version"] == 1, "Invalid health schema")
            require(sample.get("instance_id") == instance and sample.get("config_generation") == render.generation(self.config), "Stale health identity/generation")
            epoch = sample.get("sample_epoch")
            require(type(epoch) is int and 0 <= now - epoch <= max(45, self.config["interval"] * 3), "Stale health sample")
            require(type(sample.get("healthy")) is bool and isinstance(sample.get("sample_id"), str) and sample["sample_id"], "Invalid health sample")
            if sample["healthy"]:
                require(sample.get("exit_ip") == egress["expected_exit_ip"], "Unexpected exit IP")
                require(all(type(sample.get(k)) is int and sample[k] >= 0 for k in ("rx_bytes", "tx_bytes")), "Invalid health counters")
            require(identity(self.runner.inspect(container)) == current, "Egress changed during health sample")
            return sample, (*current, instance)
        except (ValueError, KeyError, IndexError, TypeError):
            return {"healthy": False, "reason": "invalid_sample"}, (*current, instance)

    def collect_health(self):
        def delayed_probe(egress, delay):
            if not self.stopped.wait(delay):
                return self.probe(egress)
            return None

        egresses = self.config["egresses"]
        with ThreadPoolExecutor(max_workers=len(egresses)) as pool:
            futures = [pool.submit(delayed_probe, egress, index) for index, egress in enumerate(egresses)]
            for egress, future in zip(egresses, futures):
                try:
                    result = future.result()
                except Exception:
                    result = ({"healthy": False, "reason": "invalid_sample"}, None)
                if self.stopped.is_set():
                    return
                sample, current = result
                self.health[egress["id"]].update(sample, time.monotonic(), self.config, current)

    def apply_policy(self):
        marks = bucket_map(self.config["egresses"], self.health, self.config)
        fixed = pinned_mark(self.config, self.health)
        # Quarantine tracks eligibility, independently of lifecycle recovery or a second threshold.
        quarantined = {e["mark"] for e in self.config["egresses"] if not self.health[e["id"]].healthy}
        policy = (tuple(marks), fixed, tuple(sorted(quarantined)))
        if self.last_policy != policy:
            self.nft_apply(render.selector(self.config, marks, fixed, quarantined))
            self.host_fingerprint = fingerprint(self.nft_snapshot())
            self.last_policy = policy
        usable = any(h.healthy for h in self.health.values())
        if usable:
            self.ns("ip", "route", "replace", "default", "via", self.config["transit"]["gateway"], "dev", self.interfaces[1],
                    "src", self.config["transit"]["address"], "table", str(render.TRANSIT_TABLE), "proto", "99")
            rules = json.loads(self.ns("ip", "-N", "-j", "-4", "rule", "show").stdout)
            if any(int(r["priority"]) == 31099 for r in rules):
                validate_policy_rule(rules, 31099, {"iif": self.config["ingress"]["interface"], "fwmark": render.TARGET_MARK,
                                                   "fwmask": 0xFFFFFFFF, "action": "unreachable"})
                self.ns("ip", "rule", "del", "priority", "31099", "protocol", "99")
        else:
            self.block()
        healthy = [e["id"] for e in self.config["egresses"] if self.health[e["id"]].healthy]
        return {"time": int(time.time()), "version": 1, "mode": "balanced" if len(healthy) == len(self.health) else "degraded" if healthy else "blocked",
                "healthy": healthy, "admission_open": usable, "pinned_egress": self.config["pin_egress"], "pinned_available": fixed != FAIL_MARK,
                "quarantined_marks": sorted(quarantined), "bucket_counts": {str(e["id"]): marks.count(e["mark"]) for e in self.config["egresses"]},
                "fail_buckets": marks.count(FAIL_MARK), "generation": render.generation(self.config),
                "host_fingerprint": self.host_fingerprint, "ingress_fingerprint": self.ingress_fingerprint,
                "egresses": {str(e["id"]): {"healthy": self.health[e["id"]].healthy, "reason": self.health[e["id"]].reason,
                    "failures": self.health[e["id"]].failures, "successes": self.health[e["id"]].successes,
                    "bytes_per_second": round(self.health[e["id"]].bps, 1)} for e in self.config["egresses"]}}

    def daemon(self):
        import fcntl
        STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock = (STATE.parent / "daemon.lock").open("a+")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        def stop(*_):
            self.stopped.set()
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        config_digest = hashlib.sha256(CONFIG.read_bytes()).digest()
        configured = False
        try:
            while not self.stopped.is_set():
                start = time.monotonic()
                try:
                    require(hashlib.sha256(CONFIG.read_bytes()).digest() == config_digest, "Configuration changed; restart the service")
                    if not configured:
                        self.setup()
                        configured = True
                    self.validate_infrastructure()
                    self.collect_health()
                    if self.stopped.is_set():
                        break
                    # Recheck live infrastructure after possibly slow probes, before opening admission.
                    self.validate_infrastructure()
                    if self.stopped.is_set():
                        break
                    state = self.apply_policy()
                except Exception as error:
                    self.block()
                    try:
                        self.boot_guard()
                    except Exception:
                        pass
                    configured = False
                    self.health = {e["id"]: Health() for e in self.config["egresses"]}
                    state = {"time": int(time.time()), "mode": "blocked", "admission_open": False, "error": str(error), "generation": render.generation(self.config)}
                    print(json.dumps(state), flush=True)
                atomic_json(STATE, state)
                self.stopped.wait(max(0, start + self.config["interval"] - time.monotonic()))
        finally:
            try:
                self.block()
                self.boot_guard()
            finally:
                lock.close()
