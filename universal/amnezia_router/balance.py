from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import math

FAIL_MARK = 0xAFF
HARD_FAILURES = {"wrong_exit_ip", "missing_interface", "interface_down", "wrong_interface_address",
                 "forwarding_disabled", "missing_policy_default", "missing_forward_lookup", "missing_forward_unreachable",
                 "missing_health_lookup", "missing_health_unreachable", "missing_forward_out", "missing_forward_return",
                 "missing_snat", "missing_output_guard", "container_stopped", "identity_changed", "invalid_sample"}


@dataclass
class Health:
    healthy: bool = False
    successes: int = 0
    failures: int = 0
    last_sample: str | None = None
    last_good: float | None = None
    last_bytes: int | None = None
    bps: float = 0.0
    reason: str = "starting"
    identity: tuple | None = None

    def update(self, sample, now, config, identity):
        if identity != self.identity:
            self.healthy, self.successes, self.failures = False, 0, 0
            self.last_sample = self.last_good = self.last_bytes = None
            self.bps = 0.0
            self.identity = identity
        sample_id = sample.get("sample_id")
        self.reason = sample.get("reason", "invalid_sample")
        if self.reason == "probe_busy" or (sample_id and sample_id == self.last_sample):
            if self.last_good is None or now - self.last_good > max(45, config["interval"] * 3):
                self.healthy = False
                self.reason = "collector_stale"
            return
        self.last_sample = sample_id
        if sample.get("healthy") is True:
            total = sample["rx_bytes"] + sample["tx_bytes"]
            if self.last_good is not None and total >= self.last_bytes:
                instantaneous = (total - self.last_bytes) / max(0.001, now - self.last_good)
                self.bps = config["alpha"] * instantaneous + (1 - config["alpha"]) * self.bps
            self.last_bytes, self.last_good = total, now
            self.successes += 1
            self.failures = 0
            if self.successes >= config["success_threshold"]:
                self.healthy = True
        else:
            self.successes = 0
            self.failures += 1
            if self.reason in HARD_FAILURES or self.failures >= config["failure_threshold"]:
                self.healthy = False


def bucket_map(egresses, health, config):
    eligible = [e for e in egresses if health[e["id"]].healthy]
    result = []
    for bucket in range(256):
        candidates = []
        for egress in eligible:
            weight = max(config["weight_floor"], 1 / (1 + health[egress["id"]].bps / config["reference_bps"]))
            digest = hashlib.sha256(f"amnezia-router-v1:{bucket}:{egress['id']}".encode()).digest()
            # Use 53 bits, with strictly 0 < u < 1, avoiding float rounding to zero.
            u = ((int.from_bytes(digest[:8], "big") >> 11) + 1) / ((1 << 53) + 2)
            candidates.append((-math.log(u) / weight, egress["id"], egress["mark"]))
        result.append(min(candidates)[2] if candidates else FAIL_MARK)
    return result


def pinned_mark(config, health):
    owner = config["pin_egress"]
    return next((e["mark"] for e in config["egresses"] if e["id"] == owner and health[owner].healthy), FAIL_MARK)


def route_mark(address, config, marks, fixed):
    """Reference policy, also used for the plan/explain CLI and regression tests."""
    address = ipaddress.IPv4Address(address)
    if any(address in ipaddress.IPv4Network(n) for n in config["pinned_routes"]):
        return fixed
    if any(address in ipaddress.IPv4Network(n) for n in config["balanced_routes"]):
        return marks[int(address) & 255]
    return None  # Direct ingress path.
