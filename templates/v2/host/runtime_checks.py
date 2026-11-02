#!/usr/bin/env python3
"""Batched read-only validators shared by the daemons and diagnostic CLIs.

Only expected CIDR models survive a cycle. Observed kernel state is collected
again on every cycle and after a repair; no persistent 'firewall is OK' cache.
"""
from __future__ import annotations

import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import shlex
import subprocess
import time


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse_env(text):
    return dict(line.split("=", 1) for raw in text.splitlines()
                if (line := raw.strip()) and not line.startswith("#") and "=" in line)


def scrub(value):
    if isinstance(value, dict):
        return {key: scrub(item) for key, item in value.items()
                if key not in {"handle", "index", "packets", "bytes", "last", "expires"}}
    if isinstance(value, list):
        return [scrub(item) for item in value]
    return value


def fingerprint(document):
    objects = [item for item in document["nftables"] if "metainfo" not in item]
    return hashlib.sha256(json.dumps(scrub(objects), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def canonical_rule(tokens):
    """Compare full rules, including negation; tolerate iptables formatting only."""
    if isinstance(tokens, str):
        tokens = shlex.split(tokens)
    options = []
    index = 0
    while index < len(tokens):
        negated = tokens[index] == "!"
        index += int(negated)
        require(index < len(tokens) and tokens[index].startswith("-"), "invalid rule option")
        key = tokens[index]
        index += 1
        value = ""
        if index < len(tokens) and not tokens[index].startswith("-") and tokens[index] != "!":
            value = tokens[index]
            index += 1
        if key in {"-s", "-d"}:
            value = str(ipaddress.ip_network(value, strict=False))
        elif key == "--ctstate":
            value = ",".join(sorted(value.split(",")))
        elif key in {"--dscp", "--set-dscp"}:
            value = str(int(value, 0))
        options.append((key, value, negated))
    protocol = next((value for key, value, neg in options if key == "-p" and not neg), None)
    # iptables-save writes the implicit default REJECT type explicitly.
    default_reject = ("-j", "REJECT", False) in options
    return tuple(sorted(item for item in options if item != ("-m", protocol, False)
                        and not (default_reject and item[0] == "--reject-with"
                                 and item[1] in {"icmp-port-unreachable", "icmp6-port-unreachable"}
                                 and not item[2])))


def option_values(tokens, names):
    """Inspect named switches without interpreting opaque extension arguments."""
    return [(tokens[index + 1], index > 0 and tokens[index - 1] == "!")
            for index, token in enumerate(tokens[:-1]) if token in names]


class Rules:
    def __init__(self, text):
        self.chains = {}
        table = None
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("*"):
                require(table is None, "nested iptables table")
                table = line[1:]
            elif line == "COMMIT":
                require(table is not None, "unexpected COMMIT")
                table = None
            elif line.startswith(":"):
                require(table is not None, "chain outside table")
                key = (table, line.split()[0][1:])
                require(key not in self.chains, "duplicate iptables chain")
                self.chains[key] = []
            elif line.startswith("-A "):
                tokens = shlex.split(line)
                require(len(tokens) >= 3, "incomplete iptables rule")
                key = (table, tokens[1])
                require(key in self.chains, f"undeclared chain {key}")
                # Foreign chains can contain arbitrary multi-argument match
                # extensions. Preserve tokens; only exact() parses owned rules.
                self.chains[key].append(tuple(tokens[2:]))
            else:
                raise ValueError(f"unsupported iptables-save line: {line[:80]}")
        require(table is None, "incomplete iptables snapshot")

    def chain(self, table, chain):
        require((table, chain) in self.chains, f"missing {table}/{chain}")
        return self.chains[table, chain]

    def exact(self, table, chain, expected):
        require(chain.startswith("AMNEZIA_LB_"), "exact validation is restricted to project chains")
        require([canonical_rule(rule) for rule in self.chain(table, chain)] == [canonical_rule(rule) for rule in expected],
                f"rules/order differ in {table}/{chain}")

    def jump(self, table, parent, target, position=0):
        rules = self.chain(table, parent)
        references = [i for i, rule in enumerate(rules)
                      if any(value == target for value, _ in option_values(rule, {"-j", "--jump", "-g", "--goto"}))]
        require(references == [position] and rules[position] in {("-j", target), ("--jump", target)},
                f"{target} must have one unconditional jump at {parent}[{position}]")


def host_v2_rules(e):
    return [
        f"-i {e['INGRESS_OUTER_BRIDGE']} -o {e['PUBLIC_IF']} -s {e['INGRESS_OUTER_IP']}/32 -p udp --sport {e['INGRESS_AWG_PORT']} -m dscp --dscp {e['OUTER_TRANSPORT_DSCP']} -j ACCEPT",
        f"-i {e['INGRESS_OUTER_BRIDGE']} -o {e['PUBLIC_IF']} -s {e['INGRESS_OUTER_IP']}/32 -j DROP",
        f"-i {e['INGRESS_AUX_BRIDGE']} -o {e['PUBLIC_IF']} -s {e['INGRESS_AUX_IP']}/32 -j DROP",
        f"-i {e['DIRECT_BRIDGE']} -o {e['PUBLIC_IF']} -s {e['INGRESS_DIRECT_IP']}/32 -j ACCEPT",
        f"-i {e['PUBLIC_IF']} -o {e['DIRECT_BRIDGE']} -d {e['INGRESS_DIRECT_IP']}/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        f"-i {e['TRANSIT_BRIDGE']} -o {e['TRANSIT_BRIDGE']} -s {e['INGRESS_TRANSIT_IP']}/32 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT",
        f"-i {e['TRANSIT_BRIDGE']} -o {e['TRANSIT_BRIDGE']} -d {e['INGRESS_TRANSIT_IP']}/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        f"-i {e['TRANSIT_BRIDGE']} -o {e['TRANSIT_BRIDGE']} -j DROP",
        f"-i {e['TRANSIT_BRIDGE']} -o {e['PUBLIC_IF']} -s {e['EGRESS_CONTAINER_IP']}/32 -d {e['EGRESS_AWG_ENDPOINT_IP']}/32 -p udp --dport {e['EGRESS_AWG_ENDPOINT_PORT']} -j ACCEPT",
        f"-i {e['PUBLIC_IF']} -o {e['TRANSIT_BRIDGE']} -d {e['EGRESS_CONTAINER_IP']}/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        f"-i {e['TRANSIT_BRIDGE']} -o {e['PUBLIC_IF']} -j DROP", "-j RETURN",
    ]


def validate_host_v2(rules, env):
    rules.jump("filter", "DOCKER-USER", "AMNEZIA_LB_V2")
    rules.exact("filter", "AMNEZIA_LB_V2", host_v2_rules(env))


def host_v3_rules(e):
    result = []
    for prefix in ("PGDL", "AE"):
        bridge = e[prefix + "_BRIDGE"]
        result.extend([
            f"-i {e['INGRESS_TRANSIT_BRIDGE']} -o {bridge} -s {e['INGRESS_TRANSIT_IP']}/32 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT",
            f"-i {bridge} -o {e['INGRESS_TRANSIT_BRIDGE']} -d {e['INGRESS_TRANSIT_IP']}/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            f"-i {e['INGRESS_TRANSIT_BRIDGE']} -o {bridge} -j DROP",
            f"-i {bridge} -o {e['INGRESS_TRANSIT_BRIDGE']} -j DROP",
        ])
    for prefix in ("PGDL", "AE"):
        result.extend([
            f"-i {e[prefix + '_BRIDGE']} -o {e['PUBLIC_IF']} -s {e[prefix + '_CONTAINER_IP']}/32 -d {e[prefix + '_ENDPOINT_IP']}/32 -p udp --dport {e[prefix + '_ENDPOINT_PORT']} -j ACCEPT",
            f"-i {e['PUBLIC_IF']} -o {e[prefix + '_BRIDGE']} -d {e[prefix + '_CONTAINER_IP']}/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            f"-i {e[prefix + '_BRIDGE']} -o {e['PUBLIC_IF']} -j DROP",
        ])
    return result + ["-j RETURN"]


def validate_host_v3(rules, e):
    rules.jump("filter", "DOCKER-USER", "AMNEZIA_LB_V2")
    rules.jump("filter", "DOCKER-USER", "AMNEZIA_LB_MULTI_V3", 1)
    rules.exact("filter", "AMNEZIA_LB_MULTI_V3", host_v3_rules(e))
    for table, parent, chain, expected in (
        ("raw", "PREROUTING", "AMNEZIA_LB_MULTI_V3_RAW", [
            f"-i {e['PGDL_BRIDGE']} -d {e['INGRESS_TRANSIT_IP']}/32 -j ACCEPT",
            f"-i {e['AE_BRIDGE']} -d {e['INGRESS_TRANSIT_IP']}/32 -j ACCEPT", "-j RETURN"]),
        ("nat", "POSTROUTING", "AMNEZIA_LB_MULTI_V3_NAT", [
            f"-s {e['INGRESS_TRANSIT_IP']}/32 -o {e['PGDL_BRIDGE']} -j ACCEPT",
            f"-s {e['INGRESS_TRANSIT_IP']}/32 -o {e['AE_BRIDGE']} -j ACCEPT", "-j RETURN"]),
    ):
        rules.jump(table, parent, chain)
        rules.exact(table, chain, expected)


def validate_dnat(rules, e):
    port = e["INGRESS_AWG_PORT"]
    matches = [rule for rule in rules.chain("nat", "DOCKER")
               if any(value == port for value, _ in option_values(rule, {"--dport", "--destination-port"}))
               and ("DNAT", False) in option_values(rule, {"-j", "--jump"})]
    require(len(matches) == 1, "expected one ingress Docker DNAT")
    require(option_values(matches[0], {"-p", "--protocol"}) == [("udp", False)] and
            option_values(matches[0], {"--dport", "--destination-port"}) == [(port, False)] and
            option_values(matches[0], {"--to-destination"}) == [(f"{e['INGRESS_OUTER_IP']}:{port}", False)],
            "wrong ingress Docker DNAT")


def ingress_rules(e, interfaces):
    outer, _aux, direct, transit = interfaces
    awg = e["INGRESS_AWG_IF"]
    subnet = e["INGRESS_CLIENT_SUBNET"]
    return {
        ("mangle", "AMNEZIA_LB_V2_OUTER"): [
            f"-o {outer} -p udp --sport {e['INGRESS_AWG_PORT']} -j DSCP --set-dscp {e['OUTER_TRANSPORT_DSCP']}", "-j RETURN"],
        ("nat", "AMNEZIA_LB_V2_NAT"): [
            f"-s {subnet} -o {transit} -j SNAT --to-source {e['INGRESS_TRANSIT_IP']}",
            f"-s {subnet} -o {direct} -j SNAT --to-source {e['INGRESS_DIRECT_IP']}", "-j RETURN"],
        ("filter", "AMNEZIA_LB_V2_FORWARD"): [
            "-j AMNEZIA_LB_V2_TEST",
            f"-i {transit} -o {awg} -d {subnet} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            f"-i {direct} -o {awg} -d {subnet} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            f"-i {awg} -o {transit} -s {subnet} -j ACCEPT",
            f"-i {awg} -o {direct} -s {subnet} -j ACCEPT",
            f"-i {awg} -s {subnet} -j REJECT", "-j RETURN"],
    }


def validate_ingress_rules(v4, v6, env, interfaces):
    require(("mangle", "AMNEZIA_LB_V2_CLASSIFY") not in v4.chains, "legacy classifier remains")
    for (table, chain), expected in ingress_rules(env, interfaces).items():
        v4.exact(table, chain, expected)
    for table, parent, target in (("mangle", "OUTPUT", "AMNEZIA_LB_V2_OUTER"),
                                  ("nat", "POSTROUTING", "AMNEZIA_LB_V2_NAT"),
                                  ("filter", "FORWARD", "AMNEZIA_LB_V2_FORWARD")):
        v4.jump(table, parent, target)
    test = v4.chain("filter", "AMNEZIA_LB_V2_TEST")
    require(test and canonical_rule(test[-1]) == canonical_rule("-j RETURN"), "self-test chain must end in RETURN")
    v6.jump("filter", "FORWARD", "AMNEZIA_LB_V2_IPV6")
    v6.exact("filter", "AMNEZIA_LB_V2_IPV6", [f"-i {env['INGRESS_AWG_IF']} -j REJECT", "-j RETURN"])


class TargetVerifier:
    def __init__(self):
        self.expected_digest = None
        self.expected = None
        self.actual_cache = {}

    @staticmethod
    def networks(value):
        if isinstance(value, str):
            yield ipaddress.IPv4Network(value, strict=False)
        elif isinstance(value, dict) and "prefix" in value:
            prefix = value["prefix"]
            yield ipaddress.IPv4Network(f"{prefix['addr']}/{prefix['len']}", strict=False)
        elif isinstance(value, dict) and "range" in value:
            first, last = value["range"]
            if isinstance(first, dict):
                first = first.get("addr", first.get("val"))
            if isinstance(last, dict):
                last = last.get("addr", last.get("val"))
            yield from ipaddress.summarize_address_range(ipaddress.IPv4Address(first), ipaddress.IPv4Address(last))
        elif isinstance(value, dict) and "elem" in value:
            inner = value["elem"]
            yield from TargetVerifier.networks(inner.get("val", inner) if isinstance(inner, dict) else inner)
        else:
            raise ValueError("unsupported nft target element")

    def verify(self, document, path, table):
        content = Path(path).read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        if digest != self.expected_digest:
            expected = [ipaddress.IPv4Network(line.strip(), strict=True)
                        for line in content.decode("utf-8").splitlines() if line.strip()]
            require(expected, "empty expected target list")
            self.expected = list(ipaddress.collapse_addresses(expected))
            self.expected_digest = digest
            self.actual_cache.clear()
        sets = [entry["set"] for entry in document["nftables"] if "set" in entry
                and entry["set"].get("family") == "inet" and entry["set"].get("table") == table
                and entry["set"].get("name") == "target_v4"]
        require(len(sets) == 1, "expected one target_v4 set")
        item = sets[0]
        require(item.get("type") == "ipv4_addr" and "interval" in item.get("flags", []), "wrong target set type/flags")
        elements = list(item.get("elem", []))
        for entry in document["nftables"]:
            extra = entry.get("element", {})
            if extra.get("table") == table and extra.get("name") == "target_v4":
                elements.extend(extra.get("elem", []))
        actual_digest = hashlib.sha256(json.dumps(elements, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if actual_digest not in self.actual_cache:
            actual = list(ipaddress.collapse_addresses(network for value in elements for network in self.networks(value)))
            require(actual == self.expected, "target set differs from active list")
            if len(self.actual_cache) >= 4:
                self.actual_cache.clear()
            self.actual_cache[actual_digest] = True


class RuntimeChecks:
    def __init__(self, v2_dir, multi_dir=None, *, runtime_dir="/run/amnezia-lb-v2", runner=None):
        self.base = Path(v2_dir)
        self.multi = Path(multi_dir) if multi_dir else None
        self.runtime = Path(runtime_dir)
        self.runner = runner or subprocess.run
        self.targets = TargetVerifier()
        self.validators = {}
        self.begin_cycle()

    def begin_cycle(self):
        self.host_snapshot = None
        self.nft_snapshots = {}
        paths = [self.base / "pilot.env"] + ([self.multi / "multi.env"] if self.multi else [])
        contents = [path.read_bytes() for path in paths]
        self.config_digests = {path: hashlib.sha256(content).digest() for path, content in zip(paths, contents)}
        self.env = parse_env(contents[0].decode("utf-8"))
        self.multi_env = parse_env(contents[1].decode("utf-8")) if self.multi else None
        self.commands = 0

    def assert_config_current(self):
        require(all(hashlib.sha256(path.read_bytes()).digest() == digest for path, digest in self.config_digests.items()),
                "configuration changed during collection")
        if self.targets.expected_digest is not None:
            require(hashlib.sha256(Path(self.env["ACTIVE_TARGETS_FILE"]).read_bytes()).hexdigest() == self.targets.expected_digest,
                    "target list changed during collection")

    def command(self, args, **kwargs):
        self.commands += 1
        return self.runner(args, check=True, capture_output=True, text=True, timeout=25, **kwargs).stdout

    def host_rules(self):
        if self.host_snapshot is None:
            self.host_snapshot = Rules(self.command(["iptables-save"]))
        return self.host_snapshot

    def invalidate(self):
        self.host_snapshot = None
        self.nft_snapshots.clear()

    def nft(self, table):
        if table not in self.nft_snapshots:
            self.nft_snapshots[table] = json.loads(self.command(["nft", "-j", "list", "table", "inet", table]))
        return self.nft_snapshots[table]

    def validator(self, name):
        if name not in self.validators:
            spec = importlib.util.spec_from_file_location(name.replace("-", "_"), self.base / "host" / (name + ".py"))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.validators[name] = module.validate
        return self.validators[name]

    def check_docker_user(self, version):
        if version == 2:
            validate_host_v2(self.host_rules(), self.env)
        else:
            e = self.multi_env
            keys = ["net.ipv4.conf.all.rp_filter"] + [f"net.ipv4.conf.{e[key]}.rp_filter"
                    for key in ("INGRESS_TRANSIT_BRIDGE", "PGDL_BRIDGE", "AE_BRIDGE")]
            require(self.command(["sysctl", "-n", *keys]).split() == ["0"] * len(keys), "wrong host rp_filter")
            validate_host_v3(self.host_rules(), e)

    def check_guard(self, version):
        table = "amnezia_lb_v2" if version == 2 else "amnezia_lb_multi_v3"
        runtime = self.runtime if version == 2 else Path(self.multi_env["RUNTIME_DIR"])
        document = self.nft(table)
        require(fingerprint(document) == (runtime / "guard.sha256").read_text().strip(), f"{table} fingerprint mismatch")
        if version == 2:
            self.targets.verify(document, self.env["ACTIVE_TARGETS_FILE"], table)
            self.check_chain(document, "forward_guard", "forward", -5, 8)

    @staticmethod
    def check_chain(document, name, hook, priority, count):
        chains = [entry["chain"] for entry in document["nftables"] if "chain" in entry and entry["chain"].get("name") == name]
        require(len(chains) == 1, f"expected one {name} chain")
        chain = chains[0]
        require(chain.get("hook") == hook and chain.get("prio") == priority and chain.get("policy") == "accept", f"wrong {name} hook")
        rules = [entry["rule"] for entry in document["nftables"] if "rule" in entry and entry["rule"].get("chain") == name]
        comments = [rule.get("comment") for rule in rules]
        require(len(rules) == count and len(set(comments)) == count and None not in comments, f"wrong {name} rules")
        return comments

    def check_targets(self, document, pid):
        expected = (self.runtime / f"ingress-targets.{pid}.sha256").read_text().strip()
        require(fingerprint(document) == expected, "ingress classifier fingerprint mismatch")
        self.targets.verify(document, self.env["ACTIVE_TARGETS_FILE"], "amnezia_lb_v2_targets")
        comments = self.check_chain(document, "classify", "prerouting", -151, 2)
        require(comments == ["v2 reset client DSCP", "v2 classify active targets"], "wrong classifier order")

    def inspect(self):
        data = json.loads(self.command(["docker", "inspect", self.env["INGRESS_CONTAINER"]]))
        require(isinstance(data, list) and len(data) == 1, "missing ingress inspect")
        return data[0]

    @staticmethod
    def identity(data):
        state = data["State"]
        require(state["Running"] and int(state["Pid"]) > 0, "ingress stopped")
        pid = int(state["Pid"])
        return data["Id"], state["StartedAt"], pid, os.stat(f"/proc/{pid}/ns/net").st_ino

    def check_ingress(self, expected_pid=None):
        started = time.monotonic()
        data = self.inspect()
        identity = self.identity(data)
        pid = identity[2]
        require(expected_pid is None or pid == int(expected_pid), "ingress PID changed")
        e = self.env
        for network, key in (("INGRESS_OUTER_NETWORK", "INGRESS_OUTER_IP"), ("INGRESS_DNS_NETWORK", "INGRESS_DNS_IP"),
                             ("INGRESS_AUX_NETWORK", "INGRESS_AUX_IP"), ("DIRECT_NETWORK", "INGRESS_DIRECT_IP"),
                             ("TRANSIT_NETWORK", "INGRESS_TRANSIT_IP")):
            require(data["NetworkSettings"]["Networks"][e[network]]["IPAddress"] == e[key], "wrong ingress Docker address")
        specs = {
            "addresses": ["ip", "-j", "-4", "addr", "show"],
            "routes": ["ip", "-j", "-4", "route", "show", "table", "all"],
            "rules": ["ip", "-N", "-j", "rule", "show"],
            "v4": ["iptables-save"], "v6": ["ip6tables-save"],
            "targets": ["nft", "-j", "list", "table", "inet", "amnezia_lb_v2_targets"],
            "sysctl": ["sysctl", "-a", "--pattern", "^net.ipv4.conf.*.rp_filter$"],
        }
        raw = json.loads(self.command(["nsenter", "-t", str(pid), "-n", "--", "python3",
                                      str(self.base / "host/runtime-collect.py")], input=json.dumps(specs)))
        addresses = json.loads(raw["addresses"])
        interfaces = []
        for key, prefix in (("INGRESS_OUTER_IP", 24), ("INGRESS_AUX_IP", 16), ("INGRESS_DIRECT_IP", 24), ("INGRESS_TRANSIT_IP", 24)):
            matches = [item["ifname"] for item in addresses for addr in item.get("addr_info", [])
                       if addr.get("local") == e[key] and addr.get("prefixlen") == prefix]
            require(len(matches) == 1, f"missing or ambiguous interface {key}")
            interfaces.append(matches[0])
        routes = json.loads(raw["routes"])
        for key, interface, gateway, source in (
            ("main", interfaces[0], e["INGRESS_OUTER_GATEWAY"], e["INGRESS_OUTER_IP"]),
            (e["OUTER_ROUTE_TABLE"], interfaces[0], e["INGRESS_OUTER_GATEWAY"], e["INGRESS_OUTER_IP"]),
            (e["DIRECT_ROUTE_TABLE"], interfaces[2], e["DIRECT_GATEWAY"], e["INGRESS_DIRECT_IP"]),
        ):
            table_routes = [item for item in routes if str(item.get("table", "main")) == key or (key == "main" and str(item.get("table")) == "254")]
            if key == "main":
                table_routes = [item for item in table_routes if item.get("dst") == "default"]
            self.validator("default-route-check")(table_routes, gateway, interface, source)
        self.validator("rpdb-check")(json.loads(raw["rules"]), e)
        validate_ingress_rules(Rules(raw["v4"]), Rules(raw["v6"]), e, interfaces)
        self.check_targets(json.loads(raw["targets"]), pid)
        values = dict(line.split(" = ", 1) for line in raw["sysctl"].splitlines() if " = " in line)
        for interface in ["all", *interfaces, e["INGRESS_AWG_IF"]]:
            require(values.get(f"net.ipv4.conf.{interface}.rp_filter") == "2", "wrong ingress rp_filter")
        port = self.command(["docker", "exec", e["INGRESS_CONTAINER"], "awg", "show", e["INGRESS_AWG_IF"], "listen-port"])
        require(port.strip() == e["INGRESS_AWG_PORT"], "wrong ingress AWG port")
        validate_dnat(self.host_rules(), e)
        require(self.identity(self.inspect()) == identity, "ingress identity changed during collection")
        self.assert_config_current()
        require(time.monotonic() - started <= 25, "ingress snapshot expired during collection")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("check", choices=("ingress", "targets", "guard-v2", "guard-v3", "docker-v2", "docker-v3"))
    parser.add_argument("pid", nargs="?", type=int)
    args = parser.parse_args()
    v2 = os.environ.get("AMNEZIA_LB_DIR", "/etc/amnezia-lb-v2")
    multi = os.environ.get("AMNEZIA_LB_MULTI_DIR", "/etc/amnezia-lb-multi-v3") if args.check.endswith("v3") else None
    checks = RuntimeChecks(v2, multi)
    try:
        if args.check == "ingress":
            checks.check_ingress(args.pid)
        elif args.check == "targets":
            data = checks.inspect()
            identity = checks.identity(data)
            pid = identity[2]
            require(args.pid is None or args.pid == pid, "ingress PID changed")
            document = json.loads(checks.command(["nsenter", "-t", str(pid), "-n", "--", "nft", "-j", "list", "table", "inet", "amnezia_lb_v2_targets"]))
            checks.check_targets(document, pid)
            require(checks.identity(checks.inspect()) == identity, "ingress identity changed")
        elif args.check.startswith("guard"):
            checks.check_guard(int(args.check[-1]))
        else:
            checks.check_docker_user(int(args.check[-1]))
        checks.assert_config_current()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"{args.check}: {error}\n")


if __name__ == "__main__":
    main()
