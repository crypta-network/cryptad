"""Offline execution-lane contracts. No QEMU or guest acceptance is implied."""
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import pr313_acceptance as acceptance
import pr313_acceptance_runner as runner
from test_pr313_acceptance import synthetic_identity, synthetic_observation


class AcceptanceRunnerTest(unittest.TestCase):
    def test_fixed_groups_cover_each_required_case_once(self):
        rows = [name for _group, _case, names in runner.groups() for name in names]
        self.assertEqual(set(acceptance.CASES), set(rows))
        self.assertEqual(len(rows), len(set(rows)))

    def test_root_rejected_before_any_creation_or_guest(self):
        with patch.object(runner.os, 'geteuid', return_value=0), patch.object(runner.Path, 'mkdir') as mkdir, \
                patch.object(runner.reference, 'run') as launch:
            with self.assertRaisesRegex(ValueError, 'unprivileged-host'):
                runner.run(SimpleNamespace())
            mkdir.assert_not_called()
            launch.assert_not_called()

    def test_strict_private_input_rejects_symlink_duplicate_keys_and_public_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.write_text('{"one":1,"one":2}')
            source.chmod(0o600)
            with self.assertRaises(ValueError):
                runner.private_json(source)
            source.write_text('{}')
            link = root / 'link'
            link.symlink_to(source)
            with self.assertRaises(OSError):
                runner.private_json(link)
            source.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'private-record-invalid'):
                runner.private_json(source)

    def test_missing_observer_is_not_executed_even_when_transport_succeeded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner._save(root / 'attempt.private.json', dict(hostVerifiedIdentity=synthetic_identity(),
                                                             guestStopped=True, guestExitCode=0, status='guest-report-retained'))
            result = runner.collect_attempt(root, ['package-api'])
            self.assertEqual([dict(caseId='package-api', status='not-executed')], result['observations'])

    def test_guest_booleans_and_dimension_labels_cannot_become_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner._save(root / 'attempt.private.json', dict(hostVerifiedIdentity=synthetic_identity(), guestStopped=True, guestExitCode=0, status='guest-report-retained'))
            runner._save(root / 'pr313-observation.private.json',
                         dict(installedKeylessNativeAcceptanceSatisfied=True, dimensions=['package-api']))
            with self.assertRaisesRegex(ValueError, 'group-observation-invalid'):
                runner.collect_attempt(root, ['package-api'])

    def test_owned_private_causal_record_is_retained_for_fixed_verifier(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = synthetic_identity()
            runner._save(root / 'attempt.private.json', dict(hostVerifiedIdentity=identity, guestStopped=True, guestExitCode=0, status='guest-report-retained'))
            record = synthetic_observation('input-inode', identity)
            runner._save(root / 'pr313-observation.private.json', record)
            result = runner.collect_attempt(root, ['input-inode'])
            self.assertEqual('passed', acceptance.observation_status(result['observations'][0], identity))

    def test_terminal_reference_failure_is_not_completed_even_with_retained_evidence(self):
        for status, code in (('failed', 0), ('guest-operation-failed', 2),
                             ('guest-report-retained', 2), ('guest-report-retained', False)):
            with self.subTest(status=status, code=code), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                runner._save(root / 'attempt.private.json', dict(hostVerifiedIdentity=synthetic_identity(),
                             guestStopped=True, guestExitCode=code, status=status))
                runner._save(root / 'pr313-observation.private.json',
                             synthetic_observation('input-inode', synthetic_identity()))
                result = runner.collect_attempt(root, ['input-inode'])
                self.assertFalse(result['attemptCompleted'])
                self.assertTrue(result['guestStopped'])

    def test_reached_fault_without_complete_record_is_inconclusive(self):
        report = {'guestSummary': {'failedStage': 'installed-pr313-fault'}}
        self.assertEqual('inconclusive', runner.missing_status(report, ['input-inode'], 'input-inode'))
        report['guestSummary']['failedStage'] = 'production-bootstrap-readiness'
        self.assertEqual('setup-failed', runner.missing_status(report, ['input-inode'], 'input-inode'))
        report['guestSummary']['failedStage'] = 'PRIVATE-CANARY'
        self.assertEqual('not-executed', runner.missing_status(report, ['input-inode'], 'input-inode'))

    def test_group_failure_does_not_claim_later_cases_executed(self):
        cases = ['package-api', 'signed-app', 'cms-five-member-context']
        report = {'guestSummary': {'failedStage': 'installed-package-api-owner-validation'}}
        self.assertEqual(['inconclusive', 'not-executed', 'not-executed'],
                         [runner.missing_status(report, cases, name) for name in cases])
        report['guestSummary']['failedStage'] = 'installation'
        self.assertEqual(['setup-failed'] * 3,
                         [runner.missing_status(report, cases, name) for name in cases])

    def test_capacity_exhaustion_preserves_originals_and_prevents_all_remaining_guests(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            original = parent / 'failed-original.qcow2'
            original.write_bytes(b'failed-original-immutable')
            output = parent / 'suite'
            selected_groups = [('fault', 'input-inode', ['input-inode']),
                               ('fault', 'output-inode', ['output-inode'])]
            with patch.object(runner.os, 'geteuid', return_value=os.geteuid() or 1000), \
                    patch.object(runner, 'groups', return_value=selected_groups), \
                    patch.object(runner, 'required_attempt_bytes', return_value=100), \
                    patch.object(runner.shutil, 'disk_usage', return_value=SimpleNamespace(free=99)), \
                    patch.object(runner.reference, 'run') as launch, patch('builtins.print'):
                self.assertEqual(2, runner.run(SimpleNamespace(output=output)))
            launch.assert_not_called()
            self.assertEqual(b'failed-original-immutable', original.read_bytes())
            self.assertFalse((output / 'attempt-01').exists())
            result = json.loads((output / 'assessment.json').read_bytes())
            self.assertEqual(2, len(result['attemptHistory']))
            self.assertTrue(all(row['reason'] == 'external-capacity-unavailable'
                                for row in result['attemptHistory']))
            self.assertEqual(len(acceptance.CASES), len(result['cases']))

    def test_capacity_estimate_binds_prepared_copy_source_products_and_guest_headroom(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('prepared', 'seed'):
                (root / name).write_bytes(b'x' * 10)
            args = SimpleNamespace(source=root, prepared_image=root / 'prepared', seed=root / 'seed',
                                   qemu_root=root / 'qemu', prepared_fixtures=root / 'fixtures')
            with patch.object(runner.reference, 'command', return_value=SimpleNamespace(
                    stdout=b'100644 blob abc 30\tfile\0')), \
                    patch.object(runner, '_tree_bytes', return_value=20):
                required = runner.required_attempt_bytes(args)
            # Git + 3 products + fixture copies, tracked source, QEMU, disk and seed.
            self.assertEqual(runner.GUEST_WRITE_RESERVE + runner.REPORT_RESERVE + 430, required)

    def test_failed_attempt_has_closed_public_matrix_and_no_upload_or_private_canary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'suite'
            args = SimpleNamespace(output=root)
            original_uid = os.geteuid()
            with patch.object(runner.os, 'geteuid', return_value=original_uid or 1000), \
                    patch.object(runner, 'groups', return_value=[('positive', None, list(acceptance.CASES))]), \
                    patch.object(runner.reference, 'run', side_effect=ValueError('PRIVATE-CANARY')), \
                    patch.object(runner, 'required_attempt_bytes', return_value=1), \
                    patch('builtins.print'):
                self.assertEqual(2, runner.run(args))
            result = json.loads((root / 'assessment.json').read_text())
            self.assertFalse(result['installedKeylessNativeAcceptanceSatisfied'])
            self.assertEqual(len(acceptance.CASES), len(result['cases']))
            self.assertNotIn('PRIVATE-CANARY', json.dumps(result))
            self.assertEqual({'plan.private.json', 'history-01.private.json', 'assessment.json', 'observations.private.json'},
                             {path.name for path in root.iterdir()})
            self.assertFalse(any('upload' in path.name for path in root.iterdir()))


if __name__ == '__main__':
    unittest.main()
