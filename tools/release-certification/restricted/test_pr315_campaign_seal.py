"""Offline host receipt authentication tests; no installed acceptance credit."""
import copy
import hashlib
import json
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

    def test_retired_authority_handoff_is_signed_without_raw_handle(self):
        provenance = {'schemaVersion': 1,
            'kind': 'pr315-retired-authority-host-provenance',
            'sourceCommit': SOURCE,
            'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            'campaignGeneration': '1' * 64,
            'senderHandleDigest': hashlib.sha256(
                ('e' * 64).encode()).hexdigest(),
            'inputDigest': '3' * 64,
            'guestStopped': True}
        handoff = seal.authority_handoff(self.plan, 'suite-201-preparation',
            provenance, '4' * 64, '5' * 64)
        signed = seal.sign_authority_handoff(self.root, self.plan, handoff)
        public = (self.root / (seal.KEY_NAME + '.pub')).read_bytes()
        self.assertEqual(handoff, seal.verify_authority_handoff(
            self.plan, signed, public))
        self.assertNotIn('e' * 64, json.dumps(signed))
        for field in ('privateInputDigest', 'retiredBootId',
                      'stopDigest', 'archiveDigest', 'planDigest'):
            changed = copy.deepcopy(signed)
            changed['handoff'][field] = 'f' * 64
            with self.assertRaises(ValueError):
                seal.verify_authority_handoff(self.plan, changed, public)
        changed = copy.deepcopy(signed)
        changed['signature'] = changed['signature'].replace(
            'SSH SIGNATURE', 'SSH SIGNAFURE')
        with self.assertRaises(ValueError):
            seal.verify_authority_handoff(self.plan, changed, public)

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
        with self.assertRaisesRegex(ValueError, 'case-ownership-invalid'):
            seal.attempt_receipt(self.plan, 'output-symlink',
                'suite-201', SOURCE, 'failed', True,
                {'installed-ready': '1' * 64},
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

    def test_append_only_history_selects_first_valid_attempt_after_setup_failure(self):
        common = {'pinned_source_commit': SOURCE,
                  'pinned_fingerprint': self.fingerprint,
                  'group_id': 'output-symlink'}
        first = seal.append_verified_attempt(self.root, self.plan,
            **common, attempt_id='suite-201', status='setup-failed',
            probe_started=False, case_digests={}, evidence_digest='2' * 64,
            stop_digest='3' * 64, monitor_digest='4' * 64,
            archive_digest='5' * 64)
        second = seal.append_verified_attempt(self.root, self.plan,
            **common, attempt_id='suite-202', status='completed',
            probe_started=True, case_digests={'output-symlink': '1' * 64},
            evidence_digest='2' * 64, stop_digest='3' * 64,
            monitor_digest='4' * 64, archive_digest='5' * 64)
        self.assertEqual(1, first['sequence'])
        self.assertEqual(2, second['sequence'])
        self.assertEqual([first, second], seal.load_verified_history(
            self.root, self.plan, pinned_source_commit=SOURCE,
            pinned_fingerprint=self.fingerprint))
        with self.assertRaisesRegex(ValueError, 'post-probe-retry'):
            seal.append_verified_attempt(self.root, self.plan,
                **common, attempt_id='suite-203', status='completed',
                probe_started=True, case_digests={'output-symlink': '1' * 64},
                evidence_digest='2' * 64, stop_digest='3' * 64,
                monitor_digest='4' * 64, archive_digest='5' * 64)

    def test_retired_authority_preparation_consumes_one_attempt(self):
        common = {'pinned_source_commit': SOURCE,
                  'pinned_fingerprint': self.fingerprint,
                  'group_id': 'authority', 'probe_started': False,
                  'case_digests': {}, 'evidence_digest': '2' * 64,
                  'stop_digest': '3' * 64, 'monitor_digest': '4' * 64,
                  'archive_digest': '5' * 64}
        first = seal.append_verified_attempt(self.root, self.plan,
            **common, attempt_id='suite-201', status='preparation-completed')
        self.assertEqual(1, first['sequence'])
        self.assertEqual('preparation-completed',
            seal.load_verified_history(self.root, self.plan,
                pinned_source_commit=SOURCE,
                pinned_fingerprint=self.fingerprint)[0]['status'])
        with self.assertRaisesRegex(ValueError,
                                     'retired-preparation-duplicate'):
            seal.append_verified_attempt(self.root, self.plan,
                **common, attempt_id='suite-202',
                status='preparation-completed')

    def test_unknown_probe_phase_cannot_be_retried_as_setup(self):
        with self.assertRaisesRegex(ValueError, 'setup-phase-invalid'):
            seal.attempt_receipt(self.plan, 'output-symlink',
                'suite-201', SOURCE, 'setup-failed', None, {},
                None, None, None, None)
        receipt = seal.append_verified_attempt(self.root, self.plan,
            pinned_source_commit=SOURCE,
            pinned_fingerprint=self.fingerprint,
            group_id='output-symlink', attempt_id='suite-201',
            status='failed', probe_started=None, case_digests={},
            evidence_digest='2' * 64, stop_digest='3' * 64,
            monitor_digest='4' * 64, archive_digest='5' * 64)
        self.assertIsNone(receipt['probeStarted'])
        with self.assertRaisesRegex(ValueError, 'post-probe-retry'):
            seal.append_verified_attempt(self.root, self.plan,
                pinned_source_commit=SOURCE,
                pinned_fingerprint=self.fingerprint,
                group_id='output-symlink', attempt_id='suite-202',
                status='completed', probe_started=True,
                case_digests={'output-symlink': '1' * 64},
                evidence_digest='2' * 64, stop_digest='3' * 64,
                monitor_digest='4' * 64, archive_digest='5' * 64)

    def test_deleted_or_modified_ledger_history_is_rejected(self):
        common = {'pinned_source_commit': SOURCE,
                  'pinned_fingerprint': self.fingerprint,
                  'group_id': 'output-symlink', 'probe_started': False,
                  'case_digests': {}, 'evidence_digest': None,
                  'stop_digest': None, 'monitor_digest': None,
                  'archive_digest': None, 'status': 'setup-failed'}
        seal.append_verified_attempt(self.root, self.plan,
            **common, attempt_id='suite-201')
        seal.append_verified_attempt(self.root, self.plan,
            **common, attempt_id='suite-202')
        path = self.root / seal.LEDGER_NAME
        original = path.read_bytes()
        changed = json.loads(original)
        changed['envelopes'].pop(0)
        path.write_bytes(seal._canonical(changed))
        with self.assertRaisesRegex(ValueError, 'ledger-chain-invalid'):
            seal.load_verified_history(self.root, self.plan,
                pinned_source_commit=SOURCE,
                pinned_fingerprint=self.fingerprint)
        path.write_bytes(original)
        changed = json.loads(original)
        changed['envelopes'][0]['receipt']['status'] = 'completed'
        path.write_bytes(seal._canonical(changed))
        with self.assertRaises(ValueError):
            seal.load_verified_history(self.root, self.plan,
                pinned_source_commit=SOURCE,
                pinned_fingerprint=self.fingerprint)
        path.write_bytes(original.replace(b'"status":"setup-failed"',
            b'"status":"completed","status":"setup-failed"', 1))
        with self.assertRaisesRegex(ValueError, 'ledger-bytes-changed'):
            seal.load_verified_history(self.root, self.plan,
                pinned_source_commit=SOURCE,
                pinned_fingerprint=self.fingerprint)


if __name__ == '__main__':
    unittest.main()
