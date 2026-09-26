"""Offline host receipt authentication tests; no installed acceptance credit."""
import copy
from pathlib import Path
import tempfile
import unittest

import pr315_campaign_seal as seal


SOURCE = 'a' * 40


def fixture_plan(root):
    identity = {key: (SOURCE if key.endswith(('Commit', 'Tree')) else 'a' * 64)
                for key in seal.acceptance.IDENTITY_FIELDS}
    fingerprint = seal.prepare_key(root)
    return seal.plan(identity, 'b' * 64, 'pve-tcg-swap-admission-v1',
                     'c' * 64, 'd' * 64, fingerprint), fingerprint


class CampaignSealTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pr315-seal-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.plan, self.fingerprint = fixture_plan(self.root)

    def receipt(self):
        return seal.attempt_receipt(self.plan, 'output-symlink',
            'suite-201', SOURCE, 'completed', True,
            {'output-symlink': '1' * 64}, '2' * 64,
            '3' * 64, '4' * 64, '5' * 64)

    def sign(self, receipt):
        return seal.sign(self.root, self.plan, receipt,
            pinned_source_commit=SOURCE,
            pinned_fingerprint=self.fingerprint)

    def verify(self, envelope):
        return seal.verify(self.root, self.plan, envelope,
            pinned_source_commit=SOURCE,
            pinned_fingerprint=self.fingerprint)

    def test_real_ed25519_round_trip_and_independent_source_pin(self):
        receipt = self.receipt()
        envelope = self.sign(receipt)
        self.assertEqual(receipt, self.verify(envelope))
        self.assertNotIn('PRIVATE KEY', envelope['signature'])
        with self.assertRaisesRegex(ValueError, 'pinned-identity-changed'):
            seal.verify(self.root, self.plan, envelope,
                pinned_source_commit='e' * 40,
                pinned_fingerprint=self.fingerprint)

    def test_changed_case_stop_monitor_or_campaign_is_rejected(self):
        envelope = self.sign(self.receipt())
        for edit in (
                lambda row: row['receipt']['caseDigests'].update(
                    {'output-symlink': 'f' * 64}),
                lambda row: row['receipt'].update(stopDigest='f' * 64),
                lambda row: row['receipt'].update(monitorDigest='f' * 64),
                lambda row: row['receipt'].update(campaignNonce='f' * 64),
                lambda row: row.update(signature=row['signature'][:-80] + 'x' * 80)):
            changed = copy.deepcopy(envelope)
            edit(changed)
            with self.assertRaises(ValueError):
                self.verify(changed)

    def test_incomplete_completion_and_phase_confusion_fail_closed(self):
        for cases, stop, monitor, archive in (
                ({}, '3' * 64, '4' * 64, '5' * 64),
                ({'output-symlink': '1' * 64}, None, '4' * 64, '5' * 64),
                ({'output-symlink': '1' * 64}, '3' * 64, None, '5' * 64),
                ({'output-symlink': '1' * 64}, '3' * 64, '4' * 64, None)):
            with self.assertRaisesRegex(ValueError, 'completion-incomplete'):
                seal.attempt_receipt(self.plan, 'output-symlink',
                    'suite-201', SOURCE, 'completed', True, cases,
                    '2' * 64, stop, monitor, archive)
        with self.assertRaisesRegex(ValueError, 'setup-phase-invalid'):
            seal.attempt_receipt(self.plan, 'output-symlink',
                'suite-201', SOURCE, 'setup-failed', True, {},
                None, None, None, None)
        with self.assertRaisesRegex(ValueError, 'failure-phase-invalid'):
            seal.attempt_receipt(self.plan, 'output-symlink',
                'suite-201', SOURCE, 'failed', False, {},
                None, None, None, None)

    def test_private_directory_and_existing_key_are_required(self):
        with self.assertRaisesRegex(ValueError, 'key-already-exists'):
            seal.prepare_key(self.root)
        self.root.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'private-directory-required'):
            self.sign(self.receipt())
        self.root.chmod(0o700)
        (self.root / seal.KEY_NAME).chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'key-invalid'):
            self.sign(self.receipt())

    def test_public_key_replacement_cannot_sign_for_frozen_campaign(self):
        with tempfile.TemporaryDirectory(prefix='pr315-other-key-') as directory:
            alternate = Path(directory)
            alternate.chmod(0o700)
            seal.prepare_key(alternate)
            (self.root / (seal.KEY_NAME + '.pub')).write_bytes(
                (alternate / (seal.KEY_NAME + '.pub')).read_bytes())
        with self.assertRaisesRegex(ValueError, 'public-key-changed'):
            self.sign(self.receipt())


if __name__ == '__main__':
    unittest.main()
