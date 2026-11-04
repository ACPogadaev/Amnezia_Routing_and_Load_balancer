from __future__ import annotations

import hashlib
import json

from .balance import FAIL_MARK

TABLE = "amnezia_router"
TARGET_MARK = 0xA10
TRANSIT_TABLE = 41010
DIRECT_TABLE = 41011
BASE = "/etc/amnezia-router"
LIB = "/usr/local/lib/amnezia-router"
PROJECT = "amnezia-router"


def elements(values):
    return ", ".join(str(value) for value in values)


def nft_set(name, values, kind="ipv4_addr", interval=False):
    lines = [f"add set inet {TABLE} {name} {{ type {kind};" + (" flags interval;" if interval else "") + " }"]
    if values:
        lines.append(f"add element inet {TABLE} {name} {{ {elements(values)} }}")
    return lines


def selector(config, marks, fixed, quarantined):
    lines = [f"flush chain inet {TABLE} select", f"flush set inet {TABLE} quarantined"]
    if quarantined:
        lines.append(f"add element inet {TABLE} quarantined {{ {elements(sorted(quarantined))} }}")
    # Pinned routes are always evaluated first, even when their owner is down.
    lines.append(f"add rule inet {TABLE} select ip daddr @pinned_v4 meta mark set {fixed} return")
    for egress in config["egresses"]:
        buckets = [f"0.0.0.{bucket}" for bucket, mark in enumerate(marks) if mark == egress["mark"]]
        if buckets:
            lines.append(f"add rule inet {TABLE} select ip daddr @balanced_v4 ip daddr & 0.0.0.255 {{ {elements(buckets)} }} meta mark set {egress['mark']} return")
    lines.append(f"add rule inet {TABLE} select meta mark set {FAIL_MARK}")
    return "\n".join(lines) + "\n"


def host_nft(config, replace=False):
    ingress, transit, direct = config["ingress"], config["transit"], config["direct"]
    public = ingress["public_if"]
    lines = ([f"delete table inet {TABLE}"] if replace else []) + [f"add table inet {TABLE}"]
    for name, values in (("targets_v4", config["targets"]), ("balanced_v4", config["balanced_routes"]), ("pinned_v4", config["pinned_routes"])):
        lines += nft_set(name, values, interval=True)
    lines += nft_set("quarantined", [], "mark")
    lines += [f"add chain inet {TABLE} classify {{ type filter hook prerouting priority -5; policy accept; }}",
              f"add chain inet {TABLE} quarantine {{ type filter hook forward priority -20; policy accept; }}",
              f"add chain inet {TABLE} guard {{ type filter hook forward priority -10; policy accept; }}",
              f"add chain inet {TABLE} select",
              f"add rule inet {TABLE} quarantine ct mark @quarantined counter drop"]
    valid_marks = elements([e["mark"] for e in config["egresses"]] + [FAIL_MARK])
    prefix = f'add rule inet {TABLE} classify iifname "{transit["bridge"]}" ip saddr {transit["address"]}'
    lines += [f"{prefix} ct mark {{ {valid_marks} }} meta mark set ct mark return",
              f"{prefix} ct mark 0 jump select", f"{prefix} ct mark 0 ct mark set meta mark"]
    # Only locally generated, tagged ingress AWG transport can use an original bridge.
    for attachment in ingress["attachments"]:
        stem = f'add rule inet {TABLE} guard iifname "{attachment["bridge"]}" oifname "{public}" ip saddr {attachment["address"]}'
        lines += [f"{stem} udp sport {ingress['port']} ip dscp 46 counter accept", f"{stem} counter drop"]
        lines.append(f'add rule inet {TABLE} guard iifname "{attachment["bridge"]}" oifname "{public}" ip daddr @targets_v4 counter drop')
    lines += [f'add rule inet {TABLE} guard iifname "{direct["bridge"]}" oifname "{public}" ip daddr @targets_v4 counter drop',
              f'add rule inet {TABLE} guard iifname "{transit["bridge"]}" oifname "{public}" counter drop']
    for egress in config["egresses"]:
        net = egress["network"]
        stem = f'add rule inet {TABLE} guard iifname "{net["bridge"]}" oifname "{public}"'
        lines += [f"{stem} ip saddr {net['address']} ip daddr {egress['endpoint_ip']} udp dport {egress['endpoint_port']} counter accept", f"{stem} counter drop"]
    lines.append(selector(config, [FAIL_MARK] * 256, FAIL_MARK, {e["mark"] for e in config["egresses"]}))
    return "\n".join(lines) + "\n"


def ingress_nft(config, replace=False):
    lines = ([f"delete table inet {TABLE}"] if replace else []) + [f"add table inet {TABLE}"]
    lines += nft_set("targets_v4", config["targets"], interval=True)
    lines += [f"add chain inet {TABLE} classify {{ type filter hook prerouting priority -151; policy accept; }}"]
    awg = config["ingress"]["interface"]
    lines += [f'add rule inet {TABLE} classify iifname "{awg}" ip dscp set 0',
              f'add rule inet {TABLE} classify iifname "{awg}" meta mark set 0',
              f'add rule inet {TABLE} classify iifname "{awg}" ip daddr @targets_v4 meta mark set {TARGET_MARK}']
    return "\n".join(lines) + "\n"


def host_chains(config):
    ingress, direct, transit = config["ingress"], config["direct"], config["transit"]
    public = ingress["public_if"]
    forward, nat, raw = [], [], []
    for attachment in ingress["attachments"]:
        stem = f"-i {attachment['bridge']} -o {public} -s {attachment['address']}/32"
        forward += [f"{stem} -p udp --sport {ingress['port']} -m dscp --dscp 46 -j ACCEPT", f"{stem} -j DROP"]
    forward += [f"-i {direct['bridge']} -o {public} -s {direct['address']}/32 -j ACCEPT",
                f"-i {public} -o {direct['bridge']} -d {direct['address']}/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"]
    for egress in config["egresses"]:
        net = egress["network"]
        forward += [f"-i {transit['bridge']} -o {net['bridge']} -s {transit['address']}/32 -j ACCEPT",
                    f"-i {net['bridge']} -o {transit['bridge']} -d {transit['address']}/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                    f"-i {net['bridge']} -o {public} -s {net['address']}/32 -d {egress['endpoint_ip']}/32 -p udp --dport {egress['endpoint_port']} -j ACCEPT",
                    f"-i {public} -o {net['bridge']} -d {net['address']}/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"]
        nat += [f"-s {transit['address']}/32 -o {net['bridge']} -j ACCEPT"]
        raw += [f"-i {net['bridge']} -d {transit['address']}/32 -j ACCEPT"]
    for net in [direct, transit, *(e["network"] for e in config["egresses"])]:
        forward += [f"-i {net['bridge']} -j DROP", f"-o {net['bridge']} -j DROP"]
    return [("filter", "DOCKER-USER", "AMR_FORWARD", forward + ["-j RETURN"]),
            ("nat", "POSTROUTING", "AMR_NAT", nat + ["-j RETURN"]),
            ("raw", "PREROUTING", "AMR_RAW", raw + ["-j RETURN"])]


def ingress_chains(config, direct_if, transit_if, outer_if):
    ingress, direct, transit = config["ingress"], config["direct"], config["transit"]
    awg, subnet = ingress["interface"], ingress["client_subnet"]
    return [
        ("mangle", "OUTPUT", "AMR_OUTER", [f"-o {outer_if} -p udp --sport {ingress['port']} -j DSCP --set-dscp 46", "-j RETURN"]),
        ("nat", "POSTROUTING", "AMR_INGRESS_NAT", [f"-s {subnet} -o {transit_if} -j SNAT --to-source {transit['address']}",
            f"-s {subnet} -o {direct_if} -j SNAT --to-source {direct['address']}", "-j RETURN"]),
        ("filter", "FORWARD", "AMR_INGRESS", [
            f"-i {transit_if} -o {awg} -d {subnet} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            f"-i {direct_if} -o {awg} -d {subnet} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            f"-i {awg} -o {transit_if} -s {subnet} -j ACCEPT", f"-i {awg} -o {direct_if} -s {subnet} -j ACCEPT",
            f"-i {awg} -j REJECT", "-j RETURN"]),
    ]


def generation(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def compose(config):
    services, networks = {}, {}
    for egress in config["egresses"]:
        name, net = egress["name"], egress["network"]
        services[name] = {"image": config["ingress"].get("egress_image", config["ingress"]["image"]), "container_name": egress["container"],
            "entrypoint": ["dumb-init", "/bin/bash", "/run/amnezia-router/egress-start.sh"],
            "restart": "unless-stopped", "cap_add": ["NET_ADMIN"], "devices": ["/dev/net/tun:/dev/net/tun"],
            "sysctls": {"net.ipv4.ip_forward": "0", "net.ipv4.conf.all.rp_filter": "2", "net.ipv4.conf.default.rp_filter": "2"},
            "environment": {"EGRESS_AWG_IF": egress["interface"], "EGRESS_AWG_IP": egress["address"],
                "EGRESS_AWG_ENDPOINT_IP": egress["endpoint_ip"], "EGRESS_AWG_ENDPOINT_PORT": str(egress["endpoint_port"]),
                "TRANSIT_GATEWAY": net["gateway"], "EGRESS_POLICY_TABLE": "201", "INGRESS_TRANSIT_IP": config["transit"]["address"],
                "EGRESS_READY_FILE": "/run/amnezia-router/ready", "EGRESS_EXPECTED_EXIT_IP": egress["expected_exit_ip"],
                "HEALTH_URL": "https://1.1.1.1/cdn-cgi/trace", "HEALTH_URL_SECONDARY": "https://1.0.0.1/cdn-cgi/trace",
                "HEALTH_MAX_HANDSHAKE_AGE_SECONDS": "300", "HEALTH_PROBE_TIMEOUT_SECONDS": "15", "HEALTH_CONNECT_TIMEOUT_SECONDS": "3",
                "HEALTH_HTTP_TIMEOUT_SECONDS": "6", "HEALTH_CONFIG_GENERATION": generation(config),
                "HEALTH_MAX_SAMPLE_AGE_SECONDS": str(max(45, config["interval"] * 3)), "HEALTH_INTERVAL_SECONDS": str(config["interval"])},
            "healthcheck": {"test": ["CMD", "timeout", "16", "/run/amnezia-router/egress-healthcheck.sh", "--docker"],
                "interval": "30s", "timeout": "20s", "retries": 3, "start_period": "60s"},
            "volumes": [f"{BASE}/secrets/{name}.conf:/etc/amnezia/amneziawg/{egress['interface']}.conf:ro",
                f"{LIB}/egress-start.sh:/run/amnezia-router/egress-start.sh:ro",
                f"{LIB}/egress-healthcheck.sh:/run/amnezia-router/egress-healthcheck.sh:ro"],
            "networks": {name: {"ipv4_address": net["address"]}}, "labels": {"org.amnezia-router.managed": "1"}}
        networks[name] = {"external": True, "name": net["name"]}
    return {"name": PROJECT, "services": services, "networks": networks}


def units():
    return {
        "amnezia-router-guard.service": f"""[Unit]
Description=Amnezia Router boot guard
DefaultDependencies=no
After=local-fs.target
Before=docker.service
RequiresMountsFor={BASE} {LIB}

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {LIB}/routerctl.py boot-guard
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
""",
        "amnezia-router.service": f"""[Unit]
Description=Amnezia Router for 1 to 3 AWG exits
Requires=docker.service amnezia-router-guard.service
After=docker.service amnezia-router-guard.service
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
UMask=0077
ExecStart=/usr/bin/python3 {LIB}/routerctl.py daemon
ExecStopPost=/usr/bin/python3 {LIB}/routerctl.py block
Restart=on-failure
RestartSec=5
TimeoutStopSec=90

[Install]
WantedBy=multi-user.target
""",
        "docker-dropin.conf": "[Unit]\nRequires=amnezia-router-guard.service\nAfter=amnezia-router-guard.service\n",
    }
