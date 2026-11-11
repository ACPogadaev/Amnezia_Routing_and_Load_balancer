import unittest
from unittest.mock import Mock, call, patch

from test_universal import config, sample
from amnezia_router import cli, render
from amnezia_router.config import validate_runtime
from amnezia_router.runtime import Runtime


class HealthCollectionTests(unittest.TestCase):
    def test_probe_stagger_for_one_two_three_exits(self):
        for count in (1, 2, 3):
            with self.subTest(count=count):
                runtime = Runtime(config(count))
                runtime.stopped = Mock()
                runtime.stopped.wait.return_value = False
                runtime.stopped.is_set.return_value = False
                runtime.probe = Mock(side_effect=lambda egress: (sample(egress["id"]), (egress["id"],)))
                runtime.collect_health()
                self.assertCountEqual(runtime.stopped.wait.call_args_list, [call(delay) for delay in range(count)])
                self.assertCountEqual(runtime.probe.call_args_list,
                                      [call(egress) for egress in runtime.config["egresses"]])
                self.assertTrue(all(health.successes == 1 for health in runtime.health.values()))

    def test_shutdown_cancels_delayed_probes(self):
        runtime = Runtime(config())
        runtime.stopped.set()
        with patch.object(runtime, "probe") as probe:
            runtime.collect_health()
        probe.assert_not_called()
        self.assertTrue(all(health.successes == 0 for health in runtime.health.values()))

    def test_probe_exception_marks_only_its_exit_unhealthy(self):
        runtime = Runtime(config())
        runtime.stopped = Mock()
        runtime.stopped.wait.return_value = False
        runtime.stopped.is_set.return_value = False
        runtime.health[2].healthy = True
        runtime.health[2].identity = (2,)

        def probe(egress):
            if egress["id"] == 2:
                raise RuntimeError("failed probe")
            return sample(egress["id"]), (egress["id"],)

        with patch.object(runtime, "probe", side_effect=probe):
            runtime.collect_health()
        self.assertEqual(runtime.health[1].successes, 1)
        self.assertEqual(runtime.health[3].successes, 1)
        self.assertFalse(runtime.health[2].healthy)
        self.assertEqual(runtime.health[2].reason, "invalid_sample")

    def test_default_and_existing_interval_reach_health_environment(self):
        c = config()
        self.assertEqual(c["interval"], 15)
        args = cli.arguments().parse_args(["install", "--egress", "peer.conf", "--balanced-routes", "routes"])
        self.assertEqual(args.interval, 15)
        args = cli.arguments().parse_args(["install", "--egress", "peer.conf", "--balanced-routes", "routes",
                                          "--interval", "10"])
        self.assertEqual(args.interval, 10)
        for interval in (10, 15):
            c["interval"] = interval
            validate_runtime(c)
            for service in render.compose(c)["services"].values():
                self.assertEqual(service["environment"]["HEALTH_INTERVAL_SECONDS"], str(interval))
