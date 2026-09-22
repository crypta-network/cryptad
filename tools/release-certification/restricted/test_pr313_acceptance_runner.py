"""Offline execution-lane contracts. No QEMU or guest acceptance is implied."""
import copy
import hashlib
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
    def test_storage_inventory_includes_old_attempts_but_not_link_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'task'
            old = root / 'old-failed-attempt'
            old.mkdir(parents=True)
            disk = old / 'guest.qcow2'
            disk.write_bytes(b'x' * 8192)
            outside = Path(temporary) / 'outside'
            outside.mkdir()
            (root / 'link').symlink_to(outside, target_is_directory=True)
            before = runner.allocated_bytes(root)
            (outside / 'unrelated').write_bytes(b'x' * 16384)
            self.assertEqual(before, runner.allocated_bytes(root))
            self.assertGreaterEqual(before, disk.stat().st_blocks * 512)

    def test_budget_and_free_space_reserve_are_independent_admission_requirements(self):
        args = SimpleNamespace(storage_budget_bytes=1000, min_free_bytes=200)
        with patch.object(runner, 'allocated_bytes', return_value=800), \
                patch.object(runner.shutil, 'disk_usage', return_value=SimpleNamespace(free=400)):
            self.assertIsNone(runner.capacity_reason(args, Path('/unused'), 200))
            self.assertEqual('suite-storage-budget-exhausted',
                             runner.capacity_reason(args, Path('/unused'), 201))
        with patch.object(runner, 'allocated_bytes', return_value=0), \
                patch.object(runner.shutil, 'disk_usage', return_value=SimpleNamespace(free=399)):
            self.assertEqual('external-capacity-unavailable',
                             runner.capacity_reason(args, Path('/unused'), 200))

    def test_retained_failed_attempt_blocks_next_guest_even_with_free_host_space(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / 'suite'
            args = SimpleNamespace(source=Path(__file__).resolve().parents[3], output=output,
                storage_root=root, storage_budget_bytes=1000, min_free_bytes=200)
            groups = [('fault', 'input-inode', ['input-inode']),
                      ('fault', 'output-inode', ['output-inode'])]
            def failed_guest(selected):
                selected.attempt.mkdir()
                (selected.attempt / 'guest.qcow2').write_bytes(b'failed-original')
                raise ValueError('failed-attempt')
            with patch.object(runner.os, 'geteuid', return_value=1000), \
                    patch.object(runner, 'groups', return_value=groups), \
                    patch.object(runner, 'required_attempt_bytes', return_value=200), \
                    patch.object(runner, 'allocated_bytes', side_effect=[0, 900]), \
                    patch.object(runner.shutil, 'disk_usage', return_value=SimpleNamespace(free=10000)), \
                    patch.object(runner.reference, 'run', side_effect=failed_guest) as launch, \
                    patch('builtins.print'):
                self.assertEqual(2, runner.run(args))
            self.assertEqual(1, launch.call_count)
            self.assertEqual(b'failed-original', (output / 'attempt-01/guest.qcow2').read_bytes())
            self.assertFalse((output / 'attempt-02').exists())
            result = json.loads((output / 'assessment.json').read_text())
            self.assertEqual('suite-storage-budget-exhausted', result['attemptHistory'][1]['reason'])
            self.assertEqual(len(acceptance.CASES), len(result['cases']))

    def test_storage_root_must_contain_suite_and_limits_must_be_positive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = SimpleNamespace(storage_root=root, storage_budget_bytes=1000, min_free_bytes=100)
            self.assertEqual(root.resolve(), runner.storage_policy(args, root / 'suite'))
            with self.assertRaisesRegex(ValueError, 'storage-policy-invalid'):
                runner.storage_policy(args, root.parent / 'elsewhere')
            for field in ('storage_budget_bytes', 'min_free_bytes'):
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'storage-policy-invalid'):
                    runner.storage_policy(SimpleNamespace(**{**vars(args), field: 0}), root / 'suite')

    def test_fixed_groups_cover_each_required_case_once(self):
        rows = [name for _group, _case, names in runner.groups() for name in names]
        self.assertEqual(set(acceptance.CASES), set(rows))
        self.assertEqual(len(rows), len(set(rows)))

    def test_fixed_plan_keeps_all_recovery_guests_after_independent_reclaimable_cases(self):
        groups = runner.groups()
        first = next(index for index, row in enumerate(groups) if row[1] in runner.RECOVERY_CASES)
        self.assertTrue(all(row[1] in runner.RECOVERY_CASES for row in groups[first:]))
        self.assertEqual(runner.RECOVERY_CASES, {row[1] for row in groups[first:]})

    def test_root_rejected_before_any_creation_or_guest(self):
        with patch.object(runner.os, 'geteuid', return_value=0), patch.object(runner.Path, 'mkdir') as mkdir, \
                patch.object(runner.reference, 'run') as launch:
            with self.assertRaisesRegex(ValueError, 'unprivileged-host'):
                runner.run(SimpleNamespace())
            mkdir.assert_not_called()
            launch.assert_not_called()

    def test_every_executing_grouping_or_verdict_module_must_match_selected_source(self):
        modules = (runner, runner.reference, acceptance, runner.faults, runner.worker_faults, runner.public_faults)
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            directory = source / 'tools/release-certification/restricted'
            directory.mkdir(parents=True)
            for module in modules:
                actual = Path(module.__file__)
                runner.shutil.copyfile(actual, directory / actual.name)
            runner.verify_executing_source(source)
            for module in modules:
                target = directory / Path(module.__file__).name
                original = target.read_bytes()
                target.write_bytes(original + b'\n# source drift\n')
                with self.subTest(module=target.name), self.assertRaisesRegex(ValueError, 'executing-acceptance-source-mismatch'):
                    runner.verify_executing_source(source)
                target.write_bytes(original)

    def test_source_mismatch_rejected_before_suite_creation_or_guest_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'suite'
            with patch.object(runner.os, 'geteuid', return_value=os.geteuid() or 1000), \
                    patch.object(runner, 'verify_executing_source', side_effect=ValueError('executing-acceptance-source-mismatch')), \
                    patch.object(runner.reference, 'run') as launch:
                with self.assertRaisesRegex(ValueError, 'executing-acceptance-source-mismatch'):
                    runner.run(SimpleNamespace(source=Path(temporary), output=output))
                launch.assert_not_called()
                self.assertFalse(output.exists())

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

    def disposable_fixture(self, root):
        suite = root / 'suite'
        suite.mkdir(mode=0o700)
        attempt = suite / 'attempt-01'
        attempt.mkdir(mode=0o700)
        for name in runner.DISPOSABLE_FILES:
            (attempt / name).write_bytes(('generated-' + name).encode())
        for name in runner.DISPOSABLE_DIRECTORIES:
            (attempt / name).mkdir()
            (attempt / name / 'generated').write_bytes(b'generated source')
        for name in ('seed.iso', 'known_hosts', 'diagnostics.private.log', 'pr313-observation.private.json'):
            (attempt / name).write_bytes(b'preserved private material')
        identity = synthetic_identity()
        identity['preparedImageDigest'] = hashlib.sha256((attempt / 'prepared.qcow2').read_bytes()).hexdigest()
        runner._save(attempt / 'attempt.private.json', {
            'sourceArchiveDigest': hashlib.sha256((attempt / 'source.tar.gz').read_bytes()).hexdigest()})
        record = dict(contract=acceptance.CONTRACT, identity=identity, declaredCases=['input-inode'],
                      observations=[synthetic_observation('input-inode', identity)],
                      guestStopped=True, attemptCompleted=True)
        return suite, attempt, identity, record

    def test_only_completed_exact_owned_generated_objects_are_disposed_with_prior_hash_audit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite, attempt, identity, record = self.disposable_fixture(root)
            original = root / 'failed-original.qcow2'
            original.write_bytes(b'failed original')
            (attempt / 'arbitrary.qcow2').write_bytes(b'not an allowed generated name')
            self.assertEqual('disposed', runner.dispose_successful_attempt(suite, attempt, record, identity))
            self.assertTrue(all(not (attempt / name).exists() for name in
                                (*runner.DISPOSABLE_FILES, *runner.DISPOSABLE_DIRECTORIES)))
            for name in ('seed.iso', 'known_hosts', 'diagnostics.private.log', 'pr313-observation.private.json',
                         'attempt.private.json', 'arbitrary.qcow2'):
                self.assertTrue((attempt / name).is_file())
            self.assertEqual(b'failed original', original.read_bytes())
            audit = json.loads((attempt / 'disposal.private.json').read_bytes())
            self.assertEqual(set(runner.DISPOSABLE_FILES), {row['name'] for row in audit['files']})
            for row in audit['files']:
                self.assertEqual(hashlib.sha256(('generated-' + row['name']).encode()).hexdigest(), row['sha256'])
            self.assertEqual('complete', json.loads((attempt / 'disposal-complete.private.json').read_bytes())['status'])

    def test_missing_failed_inconclusive_unstopped_or_unverified_record_prevents_disposal(self):
        mutations = [lambda row: row.update(observations=[]),
            lambda row: row.update(observations=[{'caseId': 'input-inode', 'status': 'failed'}]),
            lambda row: row.update(observations=[{'caseId': 'input-inode', 'status': 'inconclusive'}]),
            lambda row: row.update(guestStopped=False), lambda row: row.update(attemptCompleted=False),
            lambda row: row['identity'].update(productDigest='e' * 64)]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as temporary:
                suite, attempt, identity, record = self.disposable_fixture(Path(temporary))
                record = copy.deepcopy(record)
                mutate(record)
                self.assertEqual('retained', runner.dispose_successful_attempt(suite, attempt, record, identity))
                self.assertTrue(all((attempt / name).is_file() for name in runner.DISPOSABLE_FILES))
                self.assertFalse((attempt / 'disposal.private.json').exists())

    def test_recovery_and_symlinked_generated_objects_always_retained(self):
        for variant in ('recovery', 'disk-link', 'directory-link', 'outside-suite'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                suite, attempt, identity, record = self.disposable_fixture(root)
                outside = root / 'outside'
                outside.mkdir()
                (outside / 'valuable').write_bytes(b'unchanged')
                if variant == 'recovery':
                    record['declaredCases'] = ['death-active']
                    record['observations'] = [synthetic_observation('death-active', identity)]
                elif variant == 'disk-link':
                    (attempt / 'guest.qcow2').unlink()
                    (attempt / 'guest.qcow2').symlink_to(outside / 'valuable')
                elif variant == 'directory-link':
                    runner.shutil.rmtree(attempt / 'cryptad')
                    (attempt / 'cryptad').symlink_to(outside, target_is_directory=True)
                else:
                    suite = outside
                self.assertEqual('retained', runner.dispose_successful_attempt(suite, attempt, record, identity))
                self.assertTrue((attempt / 'prepared.qcow2').is_file())
                self.assertEqual(b'unchanged', (outside / 'valuable').read_bytes())
                self.assertFalse((attempt / 'disposal.private.json').exists())

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
                self.assertEqual(2, runner.run(SimpleNamespace(output=output, source=Path(__file__).resolve().parents[3],
                    storage_root=parent, storage_budget_bytes=10**9, min_free_bytes=1)))
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
            args = SimpleNamespace(output=root, source=Path(__file__).resolve().parents[3],
                storage_root=root.parent, storage_budget_bytes=10**9, min_free_bytes=1)
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
