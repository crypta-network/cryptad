"""Offline orchestration regression tests; they do not execute installed acceptance."""
from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import installation
import pr315_workload_runner as runner


class RunnerTests(unittest.TestCase):
    def test_predeclared_groups_partition_exact_historical_inventory(self):
        groups = runner.groups()
        self.assertEqual([8, 26, 11], [len(names) for _, names in groups])
        names = [name for _, group in groups for name in group]
        self.assertEqual(45, len(set(names)))
        self.assertEqual(set(runner.acceptance.CASES), set(names))

    def test_test_kit_entries_cannot_export_to_production(self):
        for name in ('fixtures', 'guest', 'runner', 'evidence'):
            self.assertFalse(installation.production_member(Path(
                'tools/release-certification/restricted/pr315_workload_' + name + '.py')))

    def test_memory_admission_accounts_for_guest_overhead_and_host_reserve(self):
        args = SimpleNamespace(memory_budget_bytes=runner.GUEST_MEMORY + runner.HOST_OVERHEAD,
                               min_host_memory_bytes=1024**3)
        required = runner.GUEST_MEMORY + runner.HOST_OVERHEAD + args.min_host_memory_bytes
        self.assertIsNone(runner.memory_reason(args, {'effectiveAvailableBytes': required}))
        self.assertEqual('host-memory-reserve-unavailable',
            runner.memory_reason(args, {'effectiveAvailableBytes': required - 1}))
        args.memory_budget_bytes -= 1
        self.assertEqual('memory-budget-insufficient',
            runner.memory_reason(args, {'effectiveAvailableBytes': required}))

    def test_positive_requires_exact_identity_owned_stop_and_successful_cleanup_result(self):
        identity = {'bundleIdentity': 'a' * 64, 'helperSourceCommit': 'b' * 40}
        report = {'hostVerifiedIdentity': identity, 'mode': 'workload-positive',
                  'guestStopped': True, 'status': 'guest-report-retained', 'guestExitCode': 0}
        result = {'identity': {'bundleIdentity': 'a' * 64, 'sourceCommit': 'b' * 40},
            'contentRetrieval': 'observed', 'newEpoch': True, 'profile': runner.acceptance.PROFILE,
            'topologyRoles': 4, 'signedAppWorkers': 2, 'protectedExecutionEnabled': False,
            'workloadAcceptance': 'incomplete-hostile-contract-not-executed'}
        self.assertTrue(runner.positive_executed(report, result))
        for field, value in (('guestStopped', False), ('guestExitCode', 1), ('hostVerifiedIdentity', {}),
                             ('workloadPurpose', 'startup-measurement')):
            changed = copy.deepcopy(report)
            changed[field] = value
            self.assertFalse(runner.positive_executed(changed, result))
        report['hostVerifiedIdentity'] = {}
        result['identity'] = {}
        self.assertFalse(runner.positive_executed(report, result))

    def test_public_result_never_promotes_positive_aggregate_to_case_acceptance(self):
        result = runner.public_result('implementation-incomplete', True)
        self.assertTrue(result['installedPositiveExecuted'])
        self.assertFalse(result['installedWorkloadAcceptanceSatisfied'])
        self.assertFalse(result['finiteNativeAcceptance'])
        self.assertFalse(result['phaseComplete'])
        self.assertEqual({'not-executed'}, {row['status'] for row in result['cases']})

    def test_workload_reference_projection_omits_private_guest_and_source_fields(self):
        report = runner.reference.public_report({'mode': 'workload-positive', 'executed': True,
            'status': 'guest-report-retained', 'guestStopped': True,
            'guestSummary': {'secret': 'private-token'}, 'productDigest': 'private-product',
            'preparedImageDigest': 'private-image', 'helperSourceCommit': 'private-commit'})
        self.assertNotIn('private-', json.dumps(report))
        self.assertFalse(report['installedWorkloadAcceptanceSatisfied'])

    def test_missing_inputs_return_78_without_reference_allocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            source = Path(__file__).resolve().parents[3]
            args = SimpleNamespace(source=source, output=root / 'suite', storage_root=root,
                prepared_fixtures=root / 'absent-fixtures', qemu_root=root / 'absent-qemu',
                prepared_image=root / 'absent-image', seed=root / 'absent-seed',
                ssh_key=root / 'absent-key', known_hosts=root / 'absent-pin',
                storage_budget_bytes=40 * 1024**3, min_free_bytes=8 * 1024**3,
                memory_budget_bytes=7 * 1024**3, min_host_memory_bytes=1024**3,
                profile='tcg-single')
            with patch.object(runner.os, 'geteuid', return_value=os.getuid()), \
                    patch.object(runner, 'memory_snapshot', return_value={'effectiveAvailableBytes': 9 * 1024**3}), \
                    patch.object(runner.reference, 'run') as launch, redirect_stdout(io.StringIO()):
                self.assertEqual(78, runner.run(args))
            launch.assert_not_called()
            value = json.loads((args.output / 'assessment.json').read_text())
            self.assertEqual('setup-blocked', value['status'])
            self.assertEqual(45, len(value['cases']))
            self.assertFalse((args.output / 'attempt-01').exists())


if __name__ == '__main__':
    unittest.main()
