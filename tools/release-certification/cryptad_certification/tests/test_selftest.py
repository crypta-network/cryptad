"""Coverage and failure semantics for deterministic certification test sharding."""

import io
import unittest
from unittest.mock import patch

from cryptad_certification import cli, selftest


def case(name, fail=False):
    class SyntheticCase(unittest.TestCase):
        def id(self):
            return name

        def runTest(self):
            if fail:
                self.fail("synthetic failure")

    return SyntheticCase()


class SelfTestShardingTest(unittest.TestCase):
    def test_shards_partition_all_tests_once_and_balance_counts(self):
        tests = [case(f"test-{index:03}") for index in range(29)]
        suite = unittest.TestSuite([unittest.TestSuite(tests[:11]), unittest.TestSuite(tests[11:])])
        shards = [list(selftest.shard_suite(suite, index, 6)) for index in range(6)]
        selected = [test.id() for shard in shards for test in shard]
        self.assertCountEqual(selected, [test.id() for test in tests])
        self.assertEqual(len(selected), len(set(selected)))
        self.assertLessEqual(max(map(len, shards)) - min(map(len, shards)), 1)

    def test_input_order_does_not_change_shard_membership(self):
        tests = [case(f"test-{index}") for index in range(12)]
        for index in range(3):
            forward = selftest.shard_suite(unittest.TestSuite(tests), index, 3)
            reverse = selftest.shard_suite(unittest.TestSuite(reversed(tests)), index, 3)
            self.assertEqual([test.id() for test in forward], [test.id() for test in reverse])

    def test_invalid_or_empty_shards_are_rejected(self):
        for index, count in [(-1, 2), (2, 2), (0, 0), (0, -1), (0, 3)]:
            with self.subTest(index=index, count=count), self.assertRaises(ValueError):
                selftest.shard_suite(unittest.TestSuite([case("a"), case("b")]), index, count)

    def test_unsharded_run_keeps_every_test(self):
        suite = unittest.TestSuite([case("b"), case("a")])
        self.assertEqual([test.id() for test in selftest.shard_suite(suite, 0, 1)], ["a", "b"])

    def test_failed_selected_test_keeps_nonzero_exit_status(self):
        runner = unittest.TextTestRunner(stream=io.StringIO())
        with patch.dict(selftest.SUITE_MODULES, {"synthetic": ["synthetic.module"]}), patch.object(
            unittest.defaultTestLoader, "loadTestsFromName",
            return_value=unittest.TestSuite([case("a", fail=True), case("b")]),
        ), patch.object(unittest, "TextTestRunner", return_value=runner):
            self.assertEqual(selftest.run("synthetic", shard_index=0, shard_count=2), 1)

    def test_cli_forwards_shard_selection(self):
        with patch.object(selftest, "run", return_value=0) as run:
            self.assertEqual(cli.main(["self-test", "core", "--shard-index", "2", "--shard-count", "6"]), 0)
            run.assert_called_once_with("core", shard_index=2, shard_count=6)
