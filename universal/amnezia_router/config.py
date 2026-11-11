from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import ipaddress
import math
from pathlib import Path
import re


DEFAULT_INTERVAL = 15


class ConfigError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ConfigError(message)


def ipv4(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError as error:
        raise ConfigError(f"Expected an IPv4 address: {value}") from error


def identifier(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", value), "Invalid container/interface name")
    return value


@dataclass(repr=False)
class Profile:
    address: str
    endpoint_ip: str
    endpoint_port: int
    peer: str
    contents: str = field(repr=False)

    def __repr__(self):
        return f"Profile(address={self.address!r}, endpoint={self.endpoint_ip}:{self.endpoint_port}, keys=<redacted>)"


def key(value, name):
    try:
        require(len(base64.b64decode(value, validate=True)) == 32, f"{name} must be a 32-byte base64 key")
    except (ValueError, TypeError) as error:
        raise ConfigError(f"Invalid {name}; key value is redacted") from error


def read_profile(path):
    return parse_profile(Path(path).read_text(encoding="utf-8-sig"))


def parse_profile(text):
    # No ConfigParser interpolation, shell sourcing or execution of quick hooks.
    require(len(text) <= 65536, "AWG profile is too large")
    sections = {}
    current = None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            require(line in {"[Interface]", "[Peer]"} and line not in sections,
                    f"Profile line {number}: exactly one Interface and one Peer are supported")
            current = sections[line] = {}
        else:
            require(current is not None and "=" in line, f"Invalid profile line {number}; contents redacted")
            name, value = (part.strip() for part in line.split("=", 1))
            require(re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", name) and value and not any(ord(c) < 32 for c in value),
                    f"Invalid profile option at line {number}; contents redacted")
            require(name.lower() not in {n.lower() for n in current}, f"Duplicate profile option {name}")
            current[name] = value
    require(set(sections) == {"[Interface]", "[Peer]"}, "Profile requires one Interface and one Peer")
    interface, peer = sections["[Interface]"], sections["[Peer]"]
    # Preserve AWG obfuscation extensions while normalizing the standard keys.
    def find(options, name, default=None):
        return next((v for k, v in options.items() if k.lower() == name.lower()), default)
    private, public = find(interface, "PrivateKey"), find(peer, "PublicKey")
    key(private, "PrivateKey")
    key(public, "PublicKey")
    if find(peer, "PresharedKey") is not None:
        key(find(peer, "PresharedKey"), "PresharedKey")
    if find(interface, "HeaderProtectionKey") is not None:
        key(find(interface, "HeaderProtectionKey"), "HeaderProtectionKey")
    try:
        address = ipaddress.IPv4Interface(find(interface, "Address", ""))
    except ValueError as error:
        raise ConfigError("Profile Address must contain a single IPv4 address") from error
    require(not (address.ip.is_unspecified or address.ip.is_multicast or address.ip.is_loopback), "Invalid AWG address")
    endpoint = find(peer, "Endpoint", "")
    require(re.fullmatch(r"[0-9.]+:[0-9]+", endpoint), "Endpoint must be numeric IPv4:port; hostnames require explicit resolution")
    endpoint_ip, port = endpoint.split(":")
    endpoint_ip, port = ipv4(endpoint_ip), int(port)
    require(1 <= port <= 65535, "Endpoint UDP port must be 1..65535")
    allowed = find(peer, "AllowedIPs", "").replace(" ", "").split(",")
    require("0.0.0.0/0" in allowed, "Each egress profile must allow 0.0.0.0/0")
    removed = {"address", "privatekey", "dns", "mtu", "table", "saveconfig", "preup", "postup", "predown", "postdown", "listenport", "fwmark"}
    contents = ["[Interface]", f"PrivateKey = {private}", f"Address = {address.ip}/32", "MTU = 1280", "Table = off", "SaveConfig = false"]
    contents.extend(f"{k} = {v}" for k, v in interface.items() if k.lower() not in removed)
    contents += ["", "[Peer]", f"PublicKey = {public}"]
    if find(peer, "PresharedKey"):
        contents.append(f"PresharedKey = {find(peer, 'PresharedKey')}")
    keepalive = find(peer, "PersistentKeepalive", "25")
    require(re.fullmatch(r"[0-9]+(?:-[0-9]+)?", keepalive), "Invalid PersistentKeepalive")
    bounds = [int(value) for value in keepalive.split("-")]
    require(all(0 <= value <= 65535 for value in bounds) and bounds[0] <= bounds[-1], "Invalid PersistentKeepalive range")
    contents += ["AllowedIPs = 0.0.0.0/0", f"Endpoint = {endpoint_ip}:{port}", f"PersistentKeepalive = {keepalive}"]
    # Reject unknown peer keys instead of silently changing their meaning.
    require(all(k.lower() in {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"} for k in peer), "Unsupported Peer option")
    return Profile(str(address.ip), endpoint_ip, port, public, "\n".join(contents) + "\n")


def load_routes(path):
    if path is None:
        return []
    from .targets import load_input, load_registry, filter_networks
    text = Path(path).read_text(encoding="utf-8-sig")
    if not any(line.split("#", 1)[0].strip() for line in text.splitlines()):
        return []
    try:
        networks, _ = load_input(Path(path))
        registry = load_registry(Path(__file__).parent.parent / "data/iana-ipv4-special-registry.csv")
        normalized, _ = filter_networks(networks, registry)
    except SystemExit as error:
        raise ConfigError(str(error)) from error
    require(normalized, "Route file contains no globally routable IPv4 destinations after filtering")
    return [str(n) for n in normalized]


def target_union(balanced, pinned):
    return [str(n) for n in ipaddress.collapse_addresses(ipaddress.IPv4Network(x) for x in balanced + pinned)]


def choose_networks(used, count):
    occupied = [ipaddress.IPv4Network(value, strict=False) for value in used if value != "default" and value != "0.0.0.0/0"]
    candidates = [f"172.{a}.{b}.0/24" for a in (30, 31, 29, 28) for b in range(240, 256)]
    candidates += [f"10.250.{b}.0/24" for b in range(256)]
    result = []
    for candidate in candidates:
        network = ipaddress.IPv4Network(candidate)
        if any(network.overlaps(other) for other in occupied):
            continue
        result.append(str(network))
        occupied.append(network)
        if len(result) == count:
            return result
    raise ConfigError("No collision-free private subnets found for Docker bridges")


def network(name, subnet):
    net = ipaddress.IPv4Network(subnet)
    return {"name": "amnezia-router-" + name, "bridge": "amr-" + name,
            "subnet": str(net), "gateway": str(net.network_address + 1), "address": str(net.network_address + 10)}


def make_config(profiles, balanced, pinned, pin_egress, ingress, used, expected=None, interval=DEFAULT_INTERVAL):
    require(1 <= len(profiles) <= 3, "Supply one to three --egress profiles")
    require(bool(balanced or pinned), "At least one route list must be non-empty")
    require(not pinned or pin_egress is not None, "--pinned-routes requires --pin-egress")
    require(pin_egress is None or 1 <= pin_egress <= len(profiles), "--pin-egress must select a supplied profile, numbered from 1")
    require(isinstance(interval, int) and 3 <= interval <= 300, "--interval must be 3..300 seconds")
    require(len({(p.endpoint_ip, p.endpoint_port) for p in profiles}) == len(profiles), "Egress endpoint IP:port pairs must be distinct")
    expected = expected or {}
    require(set(expected) <= set(range(1, len(profiles) + 1)), "--expected-exit references a missing egress")
    used = list(used) + [ingress["client_subnet"]] + [p.address + "/32" for p in profiles]
    subnets = choose_networks(used, len(profiles) + 2)
    egresses = []
    for index, (profile, subnet) in enumerate(zip(profiles, subnets[2:]), 1):
        egresses.append({"id": index, "name": f"egress{index}", "container": f"amnezia-router-egress{index}",
            "interface": f"amr{index}", "address": profile.address, "endpoint_ip": profile.endpoint_ip,
            "endpoint_port": profile.endpoint_port, "expected_exit_ip": ipv4(expected.get(index, profile.endpoint_ip)),
            "mark": 0xA00 + index, "table": 41000 + index, "network": network(f"e{index}", subnet),
            "profile_sha256": hashlib.sha256(profile.contents.encode()).hexdigest()})
    return {"schema": 1, "project": "amnezia-router", "ingress": ingress,
            "direct": network("direct", subnets[0]), "transit": network("transit", subnets[1]),
            "egresses": egresses, "balanced_routes": balanced, "pinned_routes": pinned,
            "pin_egress": pin_egress, "targets": target_union(balanced, pinned), "interval": interval,
            "failure_threshold": 3, "success_threshold": 3, "reference_bps": 1048576.0, "alpha": 0.35, "weight_floor": 0.25}


def validate_runtime(config):
    require(config.get("schema") == 1 and config.get("project") == "amnezia-router", "Unsupported configuration schema")
    egresses = config["egresses"]
    require(1 <= len(egresses) <= 3 and [e["id"] for e in egresses] == list(range(1, len(egresses) + 1)), "Invalid egress inventory")
    require(config["targets"] == target_union(config["balanced_routes"], config["pinned_routes"]), "Target union mismatch")
    require(config["targets"], "Empty targets")
    require(not config["pinned_routes"] or config["pin_egress"] in [e["id"] for e in egresses], "Pinned owner is absent")
    for name in ("reference_bps", "alpha", "weight_floor"):
        require(isinstance(config[name], (int, float)) and math.isfinite(config[name]) and config[name] > 0, f"Invalid {name}")
    require(config["alpha"] <= 1 and config["weight_floor"] <= 1, "alpha and weight_floor must be <= 1")
    require(3 <= config["interval"] <= 300, "Invalid health interval")
    return config
