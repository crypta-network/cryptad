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
                                                             guestStopped=True, guestExitCode=0))
            result = runner.collect_attempt(root, ['package-api'])
            self.assertEqual([dict(caseId='package-api', status='not-executed')], result['observations'])

    def test_guest_booleans_and_dimension_labels_cannot_become_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner._save(root / 'attempt.private.json', dict(hostVerifiedIdentity=synthetic_identity(), guestStopped=True))
            runner._save(root / 'pr313-observation.private.json',
                         dict(installedKeylessNativeAcceptanceSatisfied=True, dimensions=['package-api']))
            with self.assertRaisesRegex(ValueError, 'group-observation-invalid'):
                runner.collect_attempt(root, ['package-api'])

    def test_owned_private_causal_record_is_retained_for_fixed_verifier(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = synthetic_identity()
            runner._save(root / 'attempt.private.json', dict(hostVerifiedIdentity=identity, guestStopped=True))
            record = synthetic_observation('input-inode', identity)
            runner._save(root / 'pr313-observation.private.json', record)
            result = runner.collect_attempt(root, ['input-inode'])
            self.assertEqual('passed', acceptance.observation_status(result['observations'][0], identity))

    def test_failed_attempt_has_closed_public_matrix_and_no_upload_or_private_canary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'suite'
            args = SimpleNamespace(output=root)
            original_uid = os.geteuid()
            with patch.object(runner.os, 'geteuid', return_value=original_uid or 1000), \
                    patch.object(runner, 'groups', return_value=[('positive', None, list(acceptance.CASES))]), \
                    patch.object(runner.reference, 'run', side_effect=ValueError('PRIVATE-CANARY')), \
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
