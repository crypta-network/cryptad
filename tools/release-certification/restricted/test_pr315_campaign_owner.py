"""Mac archive integrity tests; synthetic records cannot grant installed acceptance."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import pr315_campaign_owner as owner
import pr315_campaign_seal as seal


class PrivateArchiveTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pr315-owner-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)

    def write(self, name, raw=b'{}'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.parent.chmod(0o700)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
        return path

    def test_missing_mac_sealed_cleanup_cannot_satisfy_selected_group(self):
        self.assertFalse(owner.verify_completed_cleanup_receipts(
            self.root, self.root, {'planDigest': 'a' * 64},
            {'attemptId': 'suite-201'}))

    def test_cleanup_verifier_binds_sealed_attempt_and_pve_bytes(self):
        source = Path(__file__).resolve().parents[3]
        identity = {key: ('a' * 40 if key.endswith(('Commit', 'Tree'))
                          else 'a' * 64)
                    for key in seal.acceptance.IDENTITY_FIELDS}
        fingerprint = seal.prepare_key(self.root)
        campaign = seal.plan(identity, 'b' * 64,
            'pve-tcg-swap-admission-v1', 'c' * 64,
            'd' * 64, fingerprint)
        attempt = seal.attempt_receipt(campaign, 'output-symlink',
            'suite-201', 'a' * 40, 'completed', True,
            {'output-symlink': '1' * 64}, '2' * 64,
            '3' * 64, '4' * 64, '5' * 64)
        full = '6' * 64
        file_digests = {'guest.qcow2': '7' * 64,
            'prepared.qcow2': '8' * 64,
            'source.tar.gz': '9' * 64}
        staged = {'files': {'attempt-01/' + name: {'sha256': digest}
                             for name, digest in file_digests.items()}}
        release_plan = {'schemaVersion': 1,
            'kind': 'pr315-host-success-copy-release-plan-v1',
            'suite': 'suite-201', 'sourceCommit': 'a' * 40,
            'campaignPlanDigest': campaign['planDigest'],
            'sealedReceiptDigest': seal._digest(attempt),
            'macFullArchiveDigest': full,
            'fileDigests': file_digests}
        checked = {'schemaVersion': 1,
            'kind': 'pr315-pve-success-copy-release-check-v1',
            'suite': 'suite-201', 'sourceCommit': 'a' * 40,
            'campaignPlanDigest': campaign['planDigest'],
            'sealedReceiptDigest': seal._digest(attempt),
            'macFullArchiveDigest': full,
            'files': {name: {'sha256': digest}
                      for name, digest in file_digests.items()},
            'directories': {name: {} for name in (
                'cryptad', 'expected-bundle', 'boot-runtime', 'tools')},
            'taskQemuPids': [], 'openUserPids': [],
            'externalBackingDependents': [], 'qcowMetadataScanned': 2}
        check = {**checked, 'checkDigest': seal._digest(checked)}
        complete = {**checked, 'checkDigest': check['checkDigest'],
            'release': 'completed-remote-success-duplicates-only'}
        tool_root = source / 'tools/release-certification/restricted'
        inventory_digest = hashlib.sha256((tool_root /
            'pr315_pve_attempt_inventory.py').read_bytes()).hexdigest()
        cleanup_digest = hashlib.sha256((tool_root /
            'pr315_pve_attempt_cleanup.py').read_bytes()).hexdigest()
        cleanup = seal.cleanup_receipt(campaign, attempt, full,
            check['checkDigest'], seal._digest(complete),
            seal._digest(release_plan), inventory_digest, cleanup_digest)
        signed = seal.sign_cleanup(self.root, campaign, attempt, cleanup)
        for suffix, value in (('plan', release_plan), ('check', check),
                              ('complete', complete), ('seal', signed)):
            self.write('host-release/suite-201.' + suffix + '.private.json',
                       seal._canonical(value))
        with patch('pr315_workload_coordinator.verify_full_staging_copy',
                   return_value=(self.root, staged, full)):
            self.assertTrue(owner.verify_completed_cleanup_receipts(
                self.root, source, campaign, attempt))
            changed = dict(complete, release='not-completed')
            (self.root / 'host-release/suite-201.complete.private.json').write_bytes(
                seal._canonical(changed))
            with self.assertRaises(ValueError):
                owner.verify_completed_cleanup_receipts(
                    self.root, source, campaign, attempt)

    def test_checksum_copy_and_manifest_reject_changed_or_extra_bytes(self):
        for name in owner._MANDATORY:
            self.write(name)
        campaign = {'planDigest': 'a' * 64,
            'campaignNonce': 'b' * 64,
            'identity': {'helperSourceCommit': 'c' * 40}}
        digest = owner.create_archive_manifest(self.root, campaign,
            'positive', 'suite-201', SimpleNamespace(returncode=0,
                stdout=b'', stderr=b''))
        receipt = {'archiveDigest': digest, 'groupId': 'positive',
            'attemptId': 'suite-201', 'sourceCommit': 'c' * 40}
        self.assertEqual(7, len(owner._archive_manifest(
            self.root, campaign, receipt)['files']))
        (self.root / 'assessment.json').write_text('{"status":"changed"}')
        with self.assertRaisesRegex(ValueError, 'digest-changed'):
            owner._archive_manifest(self.root, campaign, receipt)

    def test_extra_file_and_unverified_rsync_cannot_enter_sealed_archive(self):
        for name in owner._MANDATORY:
            self.write(name)
        campaign = {'planDigest': 'a' * 64,
            'campaignNonce': 'b' * 64,
            'identity': {'helperSourceCommit': 'c' * 40}}
        with self.assertRaisesRegex(ValueError, 'copy-unverified'):
            owner.create_archive_manifest(self.root, campaign,
                'positive', 'suite-202', SimpleNamespace(returncode=0,
                    stdout=b'>f changed', stderr=b''))
        digest = owner.create_archive_manifest(self.root, campaign,
            'positive', 'suite-202', SimpleNamespace(returncode=0,
                stdout=b'', stderr=b''))
        self.write('unexpected.private.json')
        with self.assertRaisesRegex(ValueError, 'file-set-changed'):
            owner._archive_manifest(self.root, campaign,
                {'archiveDigest': digest, 'groupId': 'positive',
                 'attemptId': 'suite-202', 'sourceCommit': 'c' * 40})

    def test_development_startup_cannot_be_recovered_as_final_acceptance(self):
        source = self.root / 'source'
        source.mkdir(mode=0o700)
        (source / 'file').write_text('frozen fixture\n')
        for arguments in (['init', '--quiet'], ['add', 'file'],
                ['-c', 'user.name=Fixture',
                 '-c', 'user.email=fixture@example.invalid',
                 'commit', '--quiet', '-m', 'fixture']):
            subprocess.run(['git', *arguments], cwd=source,
                           check=True, capture_output=True)
        commit = subprocess.check_output(['git', '-C', str(source),
            'rev-parse', 'HEAD'], text=True).strip()
        tree = subprocess.check_output(['git', '-C', str(source),
            'rev-parse', 'HEAD^{tree}'], text=True).strip()
        identity = {key: (commit if key.endswith(('Commit', 'Tree'))
                          else 'a' * 64)
                    for key in seal.acceptance.IDENTITY_FIELDS}
        identity['helperSourceTree'] = tree
        fingerprint = seal.prepare_key(self.root)
        campaign = seal.plan(identity, 'b' * 64,
            'pve-tcg-swap-admission-v1', 'c' * 64,
            'd' * 64, fingerprint)
        self.write('campaign-plan.private.json', seal._canonical(campaign))
        self.write('remote-known-hosts.private', b'pinned-fixture-host\n')
        self.write('start.private.json', seal._canonical({
            'schemaVersion': 1, 'kind': 'pr315-development-campaign-start',
            'planDigest': campaign['planDigest'],
            'sourceCommit': commit,
            'sourceTree': tree,
            'trackedByteDigest': owner.tracked_byte_digest(source),
            'hostKeyFingerprint': fingerprint,
            'fixtureManifestDigest': identity['fixtureManifestDigest'],
            'productSelectionDigest': identity['productSelectionDigest'],
            'hostAdmissionPolicy': 'pve-tcg-swap-admission-v1',
            'remoteKnownHostsDigest': hashlib.sha256(
                b'pinned-fixture-host\n').hexdigest(),
            'groupCount': 21}))
        with self.assertRaisesRegex(ValueError,
                                    'frozen-source-or-startup-pin-changed'):
            owner.recovered_campaign_verdict(self.root, source,
                expected_plan_digest=campaign['planDigest'],
                expected_key_fingerprint=fingerprint)
        start = seal.frozen_start(campaign, tree,
            owner.tracked_byte_digest(source),
            hashlib.sha256(b'pinned-fixture-host\n').hexdigest(),
            201, 225 * 1024**3)
        (self.root / 'start.private.json').write_bytes(seal._canonical(start))
        with self.assertRaises(FileNotFoundError):
            owner.recovered_campaign_verdict(self.root, source,
                expected_plan_digest=campaign['planDigest'],
                expected_key_fingerprint=fingerprint)
        signed = seal.sign_start(self.root, campaign, start)
        self.write('start-seal.private.json', seal._canonical(signed))
        result = owner.recovered_campaign_verdict(self.root, source,
            expected_plan_digest=campaign['planDigest'],
            expected_key_fingerprint=fingerprint)
        self.assertFalse(result['installedWorkloadAcceptanceSatisfied'])
        development = seal.frozen_start(campaign, tree,
            owner.tracked_byte_digest(source),
            hashlib.sha256(b'pinned-fixture-host\n').hexdigest(),
            201, 225 * 1024**3, development_group='authority')
        development_seal = seal.sign_start(self.root, campaign, development,
                                           development_group='authority')
        (self.root / 'start.private.json').write_bytes(seal._canonical(development))
        (self.root / 'start-seal.private.json').write_bytes(seal._canonical(development_seal))
        with self.assertRaisesRegex(ValueError, 'startup-pin-changed'):
            owner.recovered_campaign_verdict(self.root, source,
                expected_plan_digest=campaign['planDigest'],
                expected_key_fingerprint=fingerprint)
        observed = owner.recovered_development_verdict(self.root, source,
            development_group='authority', expected_plan_digest=campaign['planDigest'],
            expected_key_fingerprint=fingerprint)
        self.assertFalse(observed['groupSatisfied'])
        self.assertFalse(observed['installedWorkloadAcceptanceSatisfied'])
        self.assertEqual({'authority:missing-or-excess-attempts',
                          'emitter-registry-incomplete'}, set(observed['reasons']))
        with self.assertRaises(ValueError):
            owner.recovered_development_verdict(self.root, source,
                development_group='network-app', expected_plan_digest=campaign['planDigest'],
                expected_key_fingerprint=fingerprint)
        (self.root / 'start.private.json').write_bytes(seal._canonical(start))
        signed['signature'] = signed['signature'].replace(
            'SSH SIGNATURE', 'SSH SIGNAFURE')
        (self.root / 'start-seal.private.json').write_bytes(
            seal._canonical(signed))
        with self.assertRaises(ValueError):
            owner.recovered_campaign_verdict(self.root, source,
                expected_plan_digest=campaign['planDigest'],
                expected_key_fingerprint=fingerprint)


if __name__ == '__main__':
    unittest.main()
