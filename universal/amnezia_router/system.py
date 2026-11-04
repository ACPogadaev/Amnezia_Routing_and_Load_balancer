from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys

from .config import ConfigError, identifier, ipv4, require

DOCKER_HOST = "unix:///var/run/docker.sock"


def route_table_entries(result, allow_missing=False):
    if result.returncode:
        if allow_missing and "FIB table does not exist" in result.stderr:
            return []
        raise ConfigError("Cannot read policy routing table: " + result.stderr.strip())
    entries = json.loads(result.stdout)
    require(isinstance(entries, list), "Unexpected route table response")
    return entries


class Runner:
    def run(self, args, *, input=None, check=True, timeout=30):
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("COMPOSE_", "DOCKER_")) and key not in {"BASH_ENV", "ENV"}}
        env.update({"LC_ALL": "C", "LANG": "C"})
        result = subprocess.run([str(a) for a in args], input=input, capture_output=True, text=True,
                                check=False, timeout=timeout, env=env)
        if check and result.returncode:
            # Never include command input, profile contents or arbitrary tool stdout.
            label = " ".join(str(a) for a in args[:4])
            detail = re.sub(r"(?i)(PrivateKey|PresharedKey)\s*=\s*\S+", r"\1=<redacted>", result.stderr[-1500:])
            detail = re.sub(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/])", "<redacted-key>", detail).strip()
            raise RuntimeError(f"Command failed ({result.returncode}): {label}" + (": " + detail if detail else ""))
        return result

    def json(self, args):
        return json.loads(self.run(args).stdout)

    def docker(self, *args, **kwargs):
        return self.run(["docker", "--host", DOCKER_HOST, *args], **kwargs)

    def inspect(self, container):
        data = json.loads(self.docker("inspect", container).stdout)
        require(len(data) == 1, "Expected one Docker container")
        return data[0]

    def ns(self, pid, *args, **kwargs):
        return self.run(["nsenter", "-t", str(pid), "-n", "--", *args], **kwargs)


def platform_checks(runner):
    require(sys.platform == "linux", "Installation requires Linux with systemd (Ubuntu 22.04/24.04 or Debian 12/13)")
    require(os.geteuid() == 0, "Run install/check/uninstall using sudo")
    require(sys.version_info >= (3, 10), "Python 3.10+ is required")
    missing = [name for name in ("docker", "ip", "iptables", "ip6tables", "iptables-save", "ip6tables-save", "iptables-restore", "ip6tables-restore", "nft", "nsenter", "systemctl", "systemd-analyze", "sysctl", "bash", "curl") if not shutil.which(name)]
    require(not missing, "Missing programs: " + ", ".join(missing) + ". Install Docker Engine + Compose plugin and: apt-get install python3 iproute2 iptables nftables util-linux bash curl")
    require(Path("/run/systemd/system").is_dir(), "A running systemd instance is required")
    require(Path("/dev/net/tun").exists() and stat.S_ISCHR(Path("/dev/net/tun").stat().st_mode), "Character device /dev/net/tun is required")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    distro, version = release.get("ID", "").strip('"'), release.get("VERSION_ID", "").strip('"')
    require((distro == "ubuntu" and version in {"22.04", "24.04"}) or (distro == "debian" and version in {"12", "13"}),
            "Supported installation targets: Ubuntu 22.04/24.04, Debian 12/13")
    require("nf_tables" in runner.run(["iptables", "--version"]).stdout, "iptables-nft backend is required")
    runner.docker("info", timeout=15)
    require("--gw-priority" in runner.docker("network", "connect", "--help").stdout,
            "Docker must support network connect --gw-priority (Engine 28+); update Docker before installing")
    compose_version = runner.docker("compose", "version", "--short").stdout.strip().lstrip("v")
    require(compose_version.split(".")[0].isdigit() and int(compose_version.split(".")[0]) >= 2, "Docker Compose v2+ is required")
    runner.run(["iptables", "-S", "DOCKER-USER"])
    require(runner.run(["sysctl", "-n", "net.ipv4.ip_forward"]).stdout.strip() == "1", "Host IPv4 forwarding must already be enabled for Docker")
    existing_tables = runner.run(["nft", "list", "tables"]).stdout
    require(not any(name in existing_tables for name in ("amnezia_lb_v2", "amnezia_lb_balance_v3", "amnezia_lb_multi_v3")),
            "Legacy Amnezia LB rules are active. Migrate/restore them separately before installing this version")
    return {"platform": distro + " " + version, "compose": compose_version}


def identity(data):
    state = data.get("State", {})
    require(state.get("Running") is True and int(state.get("Pid", 0)) > 0, "Container is not running")
    pid = int(state["Pid"])
    return data["Id"], state["StartedAt"], pid, os.stat(f"/proc/{pid}/ns/net").st_ino


def discovery(runner, container, awg_if=None, client_subnet=None, egress_image=None):
    identifier(container)
    data = runner.inspect(container)
    current = identity(data)
    require(data.get("HostConfig", {}).get("NetworkMode") != "host", "Ingress must use Docker bridge networks")
    interfaces = runner.docker("exec", container, "awg", "show", "interfaces").stdout.split()
    require(awg_if is not None or len(interfaces) == 1, "Use --ingress-interface when the container has multiple AWG interfaces")
    awg_if = identifier(awg_if or interfaces[0])
    require(awg_if in interfaces and len(awg_if) <= 15, "Ingress AWG interface is absent/invalid")
    addresses = json.loads(runner.ns(current[2], "ip", "-j", "-4", "addr", "show").stdout)
    awg_addresses = [a for item in addresses if item["ifname"] == awg_if for a in item.get("addr_info", []) if a.get("family") == "inet"]
    require(len(awg_addresses) == 1, "Ingress must have exactly one IPv4 subnet; use a separate instance for multi-subnet ingress")
    auto_subnet = str(ipaddress.IPv4Network(f"{awg_addresses[0]['local']}/{awg_addresses[0]['prefixlen']}", strict=False))
    subnet = str(ipaddress.IPv4Network(client_subnet, strict=True)) if client_subnet else auto_subnet
    require(ipaddress.IPv4Address(awg_addresses[0]["local"]) in ipaddress.IPv4Network(subnet), "Ingress subnet override does not contain its AWG address")
    require(ipaddress.IPv4Network(subnet).prefixlen <= 30, "Use --client-subnet when ingress Address has /32")
    routes = json.loads(runner.ns(current[2], "ip", "-j", "-4", "route", "show", "default").stdout)
    require(len(routes) == 1 and routes[0].get("gateway"), "Ingress requires a single existing default route")
    outer_if = identifier(routes[0]["dev"])
    outer_addresses = {a["local"] for item in addresses if item["ifname"] == outer_if for a in item.get("addr_info", []) if a.get("family") == "inet"}
    attachments = []
    for name, attachment in data["NetworkSettings"]["Networks"].items():
        if not attachment.get("IPAddress"):
            continue
        net = json.loads(runner.docker("network", "inspect", name).stdout)[0]
        require(net.get("Driver") == "bridge", "All ingress IPv4 attachments must be Docker bridge networks")
        bridge = (net.get("Options") or {}).get("com.docker.network.bridge.name") or ("docker0" if name == "bridge" else "br-" + net["Id"][:12])
        attachments.append({"name": name, "bridge": identifier(bridge), "address": ipv4(attachment["IPAddress"])})
    require(any(a["address"] in outer_addresses for a in attachments), "Cannot match ingress default route to a Docker attachment")
    public_routes = runner.json(["ip", "-j", "-4", "route", "show", "default"])
    require(len(public_routes) == 1, "Host requires a single default route")
    public_if = identifier(public_routes[0]["dev"])
    port = int(runner.docker("exec", container, "awg", "show", awg_if, "listen-port").stdout.strip())
    require(1 <= port <= 65535, "Invalid ingress listen port")
    # Probe the immutable image, rather than a running container's writable layer.
    selected_image = json.loads(runner.docker("image", "inspect", egress_image or data["Image"]).stdout)[0]["Id"]
    tools = runner.docker("run", "--rm", "--pull", "never", "--network", "none", "--no-healthcheck", "--read-only", "--cap-drop", "ALL",
                          "--security-opt", "no-new-privileges", "--entrypoint", "/bin/sh", selected_image, "-c",
                          "for tool in awg awg-quick amneziawg-go dumb-init bash curl ip iptables ip6tables flock sysctl timeout awk sed grep cat date mkdir chmod mv rm dirname sleep; do command -v \"$tool\" >/dev/null || exit 1; done",
                          check=False)
    require(tools.returncode == 0, "Selected egress image cannot run the required AWG/startup/healthcheck utilities. Prepare a compatible local image and select --egress-image")
    require(identity(runner.inspect(container)) == current, "Ingress restarted during discovery; retry")
    ingress = {"container": container, "interface": awg_if, "client_subnet": subnet,
               "port": port, "outer_interface": outer_if, "outer_gateway": ipv4(routes[0]["gateway"]),
               "public_if": public_if, "image": data["Image"], "egress_image": selected_image, "attachments": attachments}
    used = [route["dst"] for route in runner.json(["ip", "-j", "-4", "route", "show", "table", "all"]) if route.get("dst") not in {None, "default"}]
    network_ids = runner.docker("network", "ls", "-q").stdout.split()
    if network_ids:
        for net in json.loads(runner.docker("network", "inspect", *network_ids).stdout):
            used.extend(c["Subnet"] for c in (net.get("IPAM", {}).get("Config") or []) if c.get("Subnet") and ":" not in c["Subnet"])
    return ingress, used


def resource_checks(runner, config):
    from .render import DIRECT_TABLE, TRANSIT_TABLE
    for name, rules in (("Host", runner.json(["ip", "-j", "-4", "rule", "show"])),
                        ("Ingress", json.loads(runner.docker("exec", config["ingress"]["container"], "ip", "-j", "-4", "rule", "show").stdout))):
        require(not any(0 < int(rule["priority"]) < 32766 for rule in rules), f"{name} has custom policy rules; automatic installation cannot safely infer their ordering")
    for table in [e["table"] for e in config["egresses"]]:
        result = runner.run(["ip", "-j", "-4", "route", "show", "table", str(table)], check=False)
        require(route_table_entries(result, allow_missing=True) == [], f"Host table {table} is occupied")
    pid = identity(runner.inspect(config["ingress"]["container"]))[2]
    for table in (DIRECT_TABLE, TRANSIT_TABLE):
        result = runner.ns(pid, "ip", "-j", "-4", "route", "show", "table", str(table), check=False)
        require(route_table_entries(result, allow_missing=True) == [], f"Ingress table {table} is occupied")
    for net in [config["direct"], config["transit"], *(e["network"] for e in config["egresses"])]:
        require(runner.docker("network", "inspect", net["name"], check=False).returncode != 0, "Managed network name is already occupied: " + net["name"])
        require(runner.run(["ip", "link", "show", net["bridge"]], check=False).returncode != 0, "Bridge name is already occupied: " + net["bridge"])
    for egress in config["egresses"]:
        require(runner.docker("inspect", egress["container"], check=False).returncode != 0, "Managed container name is already occupied")
    require(runner.run(["nft", "list", "table", "inet", "amnezia_router"], check=False).returncode != 0, "Managed nft table already exists")
    require(not any(n in runner.run(["iptables-save"]).stdout for n in (":AMR_FORWARD ", ":AMR_NAT ", ":AMR_RAW ")), "Managed iptables chains already exist")
