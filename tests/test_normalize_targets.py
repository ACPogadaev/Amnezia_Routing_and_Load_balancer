#!/usr/bin/env python3
import importlib.util
import ipaddress
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
(ROOT.parent / "work").mkdir(exist_ok=True)
SPEC = importlib.util.spec_from_file_location(
    "normalize_targets", ROOT.parent / "tools" / "normalize-targets.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
REGISTRY = MODULE.load_registry(ROOT / "data" / "iana-ipv4-special-registry.csv")


class NormalizeTargetsTests(unittest.TestCase):
    def filtered(self, *values):
        source = [ipaddress.ip_network(value, strict=False) for value in values]
        networks, excluded = MODULE.filter_networks(
            list(ipaddress.collapse_addresses(source)), REGISTRY
        )
        return [str(network) for network in networks], excluded

    def test_private_loopback_multicast_and_reserved_are_removed(self):
        result, excluded = self.filtered(
            "10.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4"
        )
        self.assertEqual(result, [])
        self.assertEqual(excluded["IPv4 Multicast (224.0.0.0/4)"], 1 << 28)

    def test_most_specific_global_exceptions_survive(self):
        result, _ = self.filtered("192.0.0.0/24")
        self.assertEqual(result, ["192.0.0.9/32", "192.0.0.10/32"])

    def test_loopback_is_cut_from_broad_prefix(self):
        result, _ = self.filtered("126.0.0.0/7")
        self.assertEqual(result, ["126.0.0.0/8"])

    def test_duplicates_and_nested_networks_collapse(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent / "work") as temporary:
            path = pathlib.Path(temporary) / "input.txt"
            path.write_text(
                "1.1.0.0/16\n1.1.0.0/16\n1.1.1.0/24\n",
                encoding="utf-8",
            )
            networks, stats = MODULE.load_input(path)
        self.assertEqual([str(network) for network in networks], ["1.1.0.0/16"])
        self.assertEqual(stats["duplicate_entries"], 1)
        self.assertEqual(stats["collapsed_input_entries"], 1)

    def test_host_bits_are_canonicalized_and_reported(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            path = pathlib.Path(temporary) / "input.txt"
            path.write_text("1.2.3.4/24\n", encoding="utf-8")
            networks, stats = MODULE.load_input(path)
        self.assertEqual([str(network) for network in networks], ["1.2.3.0/24"])
        self.assertEqual(stats["canonicalized_entries"], 1)

    def test_invalid_or_ipv6_input_fails_closed(self):
        for value in ("not-a-network\n", "2001:db8::/32\n", "1.1.1.0/24 extra\n"):
            with self.subTest(value=value), tempfile.TemporaryDirectory(dir=ROOT.parent / "work") as temporary:
                path = pathlib.Path(temporary) / "input.txt"
                path.write_text(value, encoding="utf-8")
                with self.assertRaises(SystemExit):
                    MODULE.load_input(path)


if __name__ == "__main__":
    unittest.main()
