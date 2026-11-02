"""Synthetic Docker/network snapshots. No live server inventory or keys."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
(ROOT / "work").mkdir(exist_ok=True)

INGRESS_SAVE = """*mangle
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:AMNEZIA_LB_V2_OUTER - [0:0]
-A OUTPUT -j AMNEZIA_LB_V2_OUTER
-A AMNEZIA_LB_V2_OUTER -o outer -p udp -m udp --sport {INGRESS_AWG_PORT} -j DSCP --set-dscp 0x2e
-A AMNEZIA_LB_V2_OUTER -j RETURN
COMMIT
*nat
:POSTROUTING ACCEPT [0:0]
:AMNEZIA_LB_V2_NAT - [0:0]
-A POSTROUTING -j AMNEZIA_LB_V2_NAT
-A AMNEZIA_LB_V2_NAT -s {INGRESS_CLIENT_SUBNET} -o transit -j SNAT --to-source {INGRESS_TRANSIT_IP}
-A AMNEZIA_LB_V2_NAT -s {INGRESS_CLIENT_SUBNET} -o direct -j SNAT --to-source {INGRESS_DIRECT_IP}
-A AMNEZIA_LB_V2_NAT -j RETURN
COMMIT
*filter
:FORWARD ACCEPT [0:0]
:AMNEZIA_LB_V2_FORWARD - [0:0]
:AMNEZIA_LB_V2_TEST - [0:0]
-A FORWARD -j AMNEZIA_LB_V2_FORWARD
-A AMNEZIA_LB_V2_TEST -j RETURN
-A AMNEZIA_LB_V2_FORWARD -j AMNEZIA_LB_V2_TEST
-A AMNEZIA_LB_V2_FORWARD -d {INGRESS_CLIENT_SUBNET} -i transit -o {INGRESS_AWG_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A AMNEZIA_LB_V2_FORWARD -d {INGRESS_CLIENT_SUBNET} -i direct -o {INGRESS_AWG_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A AMNEZIA_LB_V2_FORWARD -s {INGRESS_CLIENT_SUBNET} -i {INGRESS_AWG_IF} -o transit -j ACCEPT
-A AMNEZIA_LB_V2_FORWARD -s {INGRESS_CLIENT_SUBNET} -i {INGRESS_AWG_IF} -o direct -j ACCEPT
-A AMNEZIA_LB_V2_FORWARD -s {INGRESS_CLIENT_SUBNET} -i {INGRESS_AWG_IF} -j REJECT --reject-with icmp-port-unreachable
-A AMNEZIA_LB_V2_FORWARD -j RETURN
COMMIT
"""

V6_SAVE = """*filter
:FORWARD ACCEPT [0:0]
:AMNEZIA_LB_V2_IPV6 - [0:0]
-A FORWARD -j AMNEZIA_LB_V2_IPV6
-A AMNEZIA_LB_V2_IPV6 -i {INGRESS_AWG_IF} -j REJECT --reject-with icmp6-port-unreachable
-A AMNEZIA_LB_V2_IPV6 -j RETURN
COMMIT
"""

HOST_SAVE = """*filter
:DOCKER-USER - [0:0]
:AMNEZIA_LB_V2 - [0:0]
:AMNEZIA_LB_MULTI_V3 - [0:0]
-A DOCKER-USER -j AMNEZIA_LB_V2
-A DOCKER-USER -j AMNEZIA_LB_MULTI_V3
-A AMNEZIA_LB_V2 -s {INGRESS_OUTER_IP}/32 -i {INGRESS_OUTER_BRIDGE} -o {PUBLIC_IF} -p udp -m udp --sport {INGRESS_AWG_PORT} -m dscp --dscp 0x2e -j ACCEPT
-A AMNEZIA_LB_V2 -s {INGRESS_OUTER_IP}/32 -i {INGRESS_OUTER_BRIDGE} -o {PUBLIC_IF} -j DROP
-A AMNEZIA_LB_V2 -s {INGRESS_AUX_IP}/32 -i {INGRESS_AUX_BRIDGE} -o {PUBLIC_IF} -j DROP
-A AMNEZIA_LB_V2 -s {INGRESS_DIRECT_IP}/32 -i {DIRECT_BRIDGE} -o {PUBLIC_IF} -j ACCEPT
-A AMNEZIA_LB_V2 -d {INGRESS_DIRECT_IP}/32 -i {PUBLIC_IF} -o {DIRECT_BRIDGE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A AMNEZIA_LB_V2 -s {INGRESS_TRANSIT_IP}/32 -i {TRANSIT_BRIDGE} -o {TRANSIT_BRIDGE} -m conntrack --ctstate RELATED,NEW,ESTABLISHED -j ACCEPT
-A AMNEZIA_LB_V2 -d {INGRESS_TRANSIT_IP}/32 -i {TRANSIT_BRIDGE} -o {TRANSIT_BRIDGE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A AMNEZIA_LB_V2 -i {TRANSIT_BRIDGE} -o {TRANSIT_BRIDGE} -j DROP
-A AMNEZIA_LB_V2 -s {EGRESS_CONTAINER_IP}/32 -d {EGRESS_AWG_ENDPOINT_IP}/32 -i {TRANSIT_BRIDGE} -o {PUBLIC_IF} -p udp -m udp --dport {EGRESS_AWG_ENDPOINT_PORT} -j ACCEPT
-A AMNEZIA_LB_V2 -d {EGRESS_CONTAINER_IP}/32 -i {PUBLIC_IF} -o {TRANSIT_BRIDGE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A AMNEZIA_LB_V2 -i {TRANSIT_BRIDGE} -o {PUBLIC_IF} -j DROP
-A AMNEZIA_LB_V2 -j RETURN
-A AMNEZIA_LB_MULTI_V3 -s {INGRESS_TRANSIT_IP}/32 -i {INGRESS_TRANSIT_BRIDGE} -o {PGDL_BRIDGE} -m conntrack --ctstate RELATED,NEW,ESTABLISHED -j ACCEPT
-A AMNEZIA_LB_MULTI_V3 -d {INGRESS_TRANSIT_IP}/32 -i {PGDL_BRIDGE} -o {INGRESS_TRANSIT_BRIDGE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A AMNEZIA_LB_MULTI_V3 -i {INGRESS_TRANSIT_BRIDGE} -o {PGDL_BRIDGE} -j DROP
-A AMNEZIA_LB_MULTI_V3 -i {PGDL_BRIDGE} -o {INGRESS_TRANSIT_BRIDGE} -j DROP
-A AMNEZIA_LB_MULTI_V3 -s {INGRESS_TRANSIT_IP}/32 -i {INGRESS_TRANSIT_BRIDGE} -o {AE_BRIDGE} -m conntrack --ctstate RELATED,NEW,ESTABLISHED -j ACCEPT
-A AMNEZIA_LB_MULTI_V3 -d {INGRESS_TRANSIT_IP}/32 -i {AE_BRIDGE} -o {INGRESS_TRANSIT_BRIDGE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A AMNEZIA_LB_MULTI_V3 -i {INGRESS_TRANSIT_BRIDGE} -o {AE_BRIDGE} -j DROP
-A AMNEZIA_LB_MULTI_V3 -i {AE_BRIDGE} -o {INGRESS_TRANSIT_BRIDGE} -j DROP
-A AMNEZIA_LB_MULTI_V3 -s {PGDL_CONTAINER_IP}/32 -d {PGDL_ENDPOINT_IP}/32 -i {PGDL_BRIDGE} -o {PUBLIC_IF} -p udp -m udp --dport {PGDL_ENDPOINT_PORT} -j ACCEPT
-A AMNEZIA_LB_MULTI_V3 -d {PGDL_CONTAINER_IP}/32 -i {PUBLIC_IF} -o {PGDL_BRIDGE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A AMNEZIA_LB_MULTI_V3 -i {PGDL_BRIDGE} -o {PUBLIC_IF} -j DROP
-A AMNEZIA_LB_MULTI_V3 -s {AE_CONTAINER_IP}/32 -d {AE_ENDPOINT_IP}/32 -i {AE_BRIDGE} -o {PUBLIC_IF} -p udp -m udp --dport {AE_ENDPOINT_PORT} -j ACCEPT
-A AMNEZIA_LB_MULTI_V3 -d {AE_CONTAINER_IP}/32 -i {PUBLIC_IF} -o {AE_BRIDGE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A AMNEZIA_LB_MULTI_V3 -i {AE_BRIDGE} -o {PUBLIC_IF} -j DROP
-A AMNEZIA_LB_MULTI_V3 -j RETURN
COMMIT
*raw
:PREROUTING ACCEPT [0:0]
:AMNEZIA_LB_MULTI_V3_RAW - [0:0]
-A PREROUTING -j AMNEZIA_LB_MULTI_V3_RAW
-A AMNEZIA_LB_MULTI_V3_RAW -d {INGRESS_TRANSIT_IP}/32 -i {PGDL_BRIDGE} -j ACCEPT
-A AMNEZIA_LB_MULTI_V3_RAW -d {INGRESS_TRANSIT_IP}/32 -i {AE_BRIDGE} -j ACCEPT
-A AMNEZIA_LB_MULTI_V3_RAW -j RETURN
COMMIT
*nat
:DOCKER - [0:0]
:POSTROUTING ACCEPT [0:0]
:AMNEZIA_LB_MULTI_V3_NAT - [0:0]
-A DOCKER -p udp -m udp --dport {INGRESS_AWG_PORT} -j DNAT --to-destination {INGRESS_OUTER_IP}:{INGRESS_AWG_PORT}
-A POSTROUTING -j AMNEZIA_LB_MULTI_V3_NAT
-A AMNEZIA_LB_MULTI_V3_NAT -s {INGRESS_TRANSIT_IP}/32 -o {PGDL_BRIDGE} -j ACCEPT
-A AMNEZIA_LB_MULTI_V3_NAT -s {INGRESS_TRANSIT_IP}/32 -o {AE_BRIDGE} -j ACCEPT
-A AMNEZIA_LB_MULTI_V3_NAT -j RETURN
COMMIT
"""


def environment(root):
    values = {}
    for raw in (ROOT / "config/deployment.env.example").read_text().splitlines():
        if raw and not raw.startswith("#"):
            key, value = raw.split("=", 1)
            values[key] = value
    values.update({
        "BALANCER_PUBLIC_IP": "192.0.2.1", "INGRESS_AWG_PORT": "31000",
        "INGRESS_OUTER_IP": "172.29.172.2", "INGRESS_OUTER_GATEWAY": "172.29.172.1",
        "INGRESS_DNS_IP": "172.29.172.2", "INGRESS_DNS_GATEWAY": "172.29.172.1", "INGRESS_AUX_IP": "172.17.0.2",
        "HEALTH_TARGET_IP": "198.51.100.1", "ACTIVE_TEST_IP": "93.184.216.34",
        "MAIN_AWG_IP": "10.9.0.2", "MAIN_ENDPOINT_IP": "192.0.2.10", "MAIN_ENDPOINT_PORT": "31001", "MAIN_EXPECTED_EXIT_IP": "192.0.2.10",
        "EGRESS2_AWG_IP": "10.9.0.3", "EGRESS2_ENDPOINT_IP": "192.0.2.20", "EGRESS2_ENDPOINT_PORT": "31002", "EGRESS2_EXPECTED_EXIT_IP": "192.0.2.20",
        "EGRESS3_AWG_IP": "10.9.0.4", "EGRESS3_ENDPOINT_IP": "192.0.2.30", "EGRESS3_ENDPOINT_PORT": "31003", "EGRESS3_EXPECTED_EXIT_IP": "192.0.2.30",
        "ACTIVE_TARGETS_COUNT": "1",
    })
    for version, name in (("v2", "pilot"), ("v3", "multi")):
        text = (ROOT / f"templates/{version}/config/{name}.env.in").read_text()
        for key, value in values.items():
            text = text.replace(f"@@{key}@@", value)
        directory = root / version
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{name}.env").write_text(text, encoding="utf-8")
    env = {}
    for version, name in (("v2", "pilot"), ("v3", "multi")):
        env.update(dict(line.split("=", 1) for line in (root / version / f"{name}.env").read_text().splitlines() if line and not line.startswith("#")))
    env["ACTIVE_TARGETS_FILE"] = str(root / "targets.txt")
    (root / "targets.txt").write_text("93.184.216.34/32\n", encoding="utf-8")
    for version, name in (("v2", "pilot"), ("v3", "multi")):
        text = (root / version / f"{name}.env").read_text()
        if version == "v2":
            text = "\n".join(f"ACTIVE_TARGETS_FILE={env['ACTIVE_TARGETS_FILE']}" if line.startswith("ACTIVE_TARGETS_FILE=") else line for line in text.splitlines()) + "\n"
        (root / version / f"{name}.env").write_text(text, encoding="utf-8")
    return env


def target_document():
    return {"nftables": [
        {"table": {"family": "inet", "name": "amnezia_lb_v2_targets"}},
        {"set": {"family": "inet", "table": "amnezia_lb_v2_targets", "name": "target_v4", "type": "ipv4_addr", "flags": ["interval"], "elem": ["93.184.216.34"]}},
        {"chain": {"family": "inet", "table": "amnezia_lb_v2_targets", "name": "classify", "hook": "prerouting", "prio": -151, "policy": "accept"}},
        {"rule": {"chain": "classify", "comment": "v2 reset client DSCP"}},
        {"rule": {"chain": "classify", "comment": "v2 classify active targets"}},
    ]}


def ingress_snapshot(e):
    addresses = []
    for name, key, prefix in (("outer", "INGRESS_OUTER_IP", 24), ("aux", "INGRESS_AUX_IP", 16), ("direct", "INGRESS_DIRECT_IP", 24), ("transit", "INGRESS_TRANSIT_IP", 24)):
        addresses.append({"ifname": name, "addr_info": [{"local": e[key], "prefixlen": prefix}]})
    routes = [{"dst": "default", "gateway": e["INGRESS_OUTER_GATEWAY"], "dev": "outer", "prefsrc": e["INGRESS_OUTER_IP"], "table": "main"}]
    routes.append({**routes[0], "table": int(e["OUTER_ROUTE_TABLE"])})
    routes.append({"dst": "default", "gateway": e["DIRECT_GATEWAY"], "dev": "direct", "prefsrc": e["INGRESS_DIRECT_IP"], "table": int(e["DIRECT_ROUTE_TABLE"])})
    rules = []
    for prefix, interface in (("OUTER", "lo"), ("TARGET", e["INGRESS_AWG_IF"]), ("DIRECT", e["INGRESS_AWG_IF"])):
        common = {"protocol": 99, "src": "all", "iif": interface}
        if prefix == "OUTER":
            common.update(ipproto="udp", sport=int(e["INGRESS_AWG_PORT"]))
        if prefix == "TARGET":
            common.update(fwmark="0x101", fwmask="0xffffffff")
        rules.extend([{**common, "priority": int(e[prefix + "_LOOKUP_PRIORITY"]), "table": int(e[prefix + "_ROUTE_TABLE"])},
                      {**common, "priority": int(e[prefix + "_UNREACHABLE_PRIORITY"]), "action": "unreachable"}])
    return {"addresses": json.dumps(addresses), "routes": json.dumps(routes), "rules": json.dumps(rules),
            "v4": INGRESS_SAVE.format_map(e), "v6": V6_SAVE.format_map(e), "targets": json.dumps(target_document()),
            "sysctl": "\n".join(f"net.ipv4.conf.{name}.rp_filter = 2" for name in ("all", "outer", "aux", "direct", "transit", e["INGRESS_AWG_IF"]))}
