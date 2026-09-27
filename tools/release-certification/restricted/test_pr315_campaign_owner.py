"""Mac archive integrity tests; synthetic records cannot grant installed acceptance."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

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
        identity = {key: (commit if key.endswith(('Commit', 'Tree'))
                          else 'a' * 64)
                    for key in seal.acceptance.IDENTITY_FIELDS}
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
            'sourceTree': commit,
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


if __name__ == '__main__':
    unittest.main()
