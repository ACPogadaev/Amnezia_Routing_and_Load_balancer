import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_universal import WORK


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")
RULES = [
    "20100: from 172.30.241.10 iif eth0 lookup 201 proto 99",
    "20101: from 172.30.241.10 iif eth0 7 proto 99",
    "20110: from 10.8.1.7 lookup 201 proto 99",
    "20111: from 10.8.1.7 7 proto 99",
]
REASONS = ["missing_forward_lookup", "missing_forward_unreachable",
           "missing_health_lookup", "missing_health_unreachable"]


@unittest.skipUnless(BASH and os.name == "posix", "requires Bash and POSIX test commands")
class HealthRuleTests(unittest.TestCase):
    def run_health(self, rules, dump_status=0):
        with tempfile.TemporaryDirectory(dir=WORK) as directory:
            root = Path(directory)
            tools = root / "bin"
            tools.mkdir()
            scripts = {
                "ip": """#!/bin/sh
printf '%s\n' "$*" >> "$TEST_CALLS"
case "$*" in
    'link show dev awg-test') exit 0 ;;
    '-o link show dev awg-test') echo '4: awg-test: <POINTOPOINT,UP,LOWER_UP>' ;;
    '-o -4 addr show dev awg-test') echo '4: awg-test inet 10.8.1.7/32 scope global awg-test' ;;
    '-4 route show table 201') echo 'default dev awg-test' ;;
    '-N -o -4 rule show') cat "$TEST_RULES"; exit "$TEST_DUMP_STATUS" ;;
    *) echo "unexpected ip call" >&2; exit 9 ;;
esac
""",
                "sysctl": "#!/bin/sh\necho 1\n",
                "awg": "#!/bin/sh\nexit 99\n",
                "iptables": "#!/bin/sh\nexit 99\n",
                "curl": "#!/bin/sh\nexit 99\n",
            }
            for name, contents in scripts.items():
                target = tools / name
                target.write_text(contents)
                target.chmod(0o755)
            for name, contents in (("ready", "instance\n"), ("profile", "test\n"),
                                   ("rules", "\n".join(rules) + "\n")):
                (root / name).write_text(contents)
            source = (ROOT / "egress-healthcheck.sh").read_text()
            source = source.split("\niptables -C FORWARD", 1)[0]
            source = source.replace("RUN_DIR=/run/amnezia-router-health", 'RUN_DIR="$TEST_RUN_DIR"')
            source = source.replace("CONF=/etc/amnezia/amneziawg/${EGRESS_AWG_IF}.conf", 'CONF="$TEST_CONF"')
            path = root / "health.sh"
            path.write_text(source + "\nprintf 'policy-ok\\n'\n", newline="\n")
            env = {
                **os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                "TEST_CALLS": str(root / "calls"), "TEST_RULES": str(root / "rules"),
                "TEST_DUMP_STATUS": str(dump_status), "TEST_RUN_DIR": str(root / "run"),
                "TEST_CONF": str(root / "profile"), "EGRESS_READY_FILE": str(root / "ready"),
                "EGRESS_AWG_IF": "awg-test", "EGRESS_AWG_IP": "10.8.1.7",
                "EGRESS_POLICY_TABLE": "201", "INGRESS_TRANSIT_IP": "172.30.241.10",
                "EGRESS_EXPECTED_EXIT_IP": "192.0.2.1", "HEALTH_URL": "https://example.invalid/",
                "HEALTH_URL_SECONDARY": "https://example.invalid/",
                "HEALTH_MAX_HANDSHAKE_AGE_SECONDS": "300", "HEALTH_MAX_SAMPLE_AGE_SECONDS": "45",
            }
            result = subprocess.run([BASH, str(path), "--json"], env=env, capture_output=True,
                                    text=True, timeout=10)
            calls = (root / "calls").read_text().splitlines()
            self.assertEqual(calls.count("-N -o -4 rule show"), 1)
            self.assertFalse(any("priority" in entry for entry in calls))
            return result

    def test_complete_snapshot_accepts_host_prefixes_and_protocol_metadata(self):
        for rules in (RULES, [line.replace(".10 ", ".10/32 ").replace(".7 ", ".7/32 ")
                             .replace("proto 99", "protocol openr").replace(" 7 ", " unreachable ")
                             for line in RULES]):
            with self.subTest(rules=rules):
                result = self.run_health(rules)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "policy-ok\n")

    def test_missing_rule_reports_its_existing_failure_reason(self):
        for index, reason in enumerate(REASONS):
            with self.subTest(reason=reason):
                result = self.run_health(RULES[:index] + RULES[index + 1:])
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(json.loads(result.stdout)["reason"], reason)

    def test_partial_failed_duplicate_and_changed_rules_are_rejected(self):
        changed = [
            [RULES[0].replace("172.30.241.10", "172.30.241.100"), *RULES[1:]],
            [RULES[0].replace("from ", "not from "), *RULES[1:]],
            [RULES[0] + " fwmark 1", *RULES[1:]],
            [RULES[0].replace("eth0", "eth9"), *RULES[1:]],
            [RULES[0].replace("lookup 201 ", "lookup 2010 "), *RULES[1:]],
            [RULES[0], *RULES],
            [RULES[0].replace(" iif eth0", ""),
             RULES[0].replace("172.30.241.10", "172.30.241.100"), *RULES[1:]],
        ]
        for rules in changed:
            with self.subTest(rules=rules):
                result = self.run_health(rules)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(json.loads(result.stdout)["reason"], "missing_forward_lookup")
        result = self.run_health(RULES, dump_status=1)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["reason"], "missing_forward_lookup")
