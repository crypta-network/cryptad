"""Real private retention/public projection; external artifact providers remain synthetic."""
import copy
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import cross_version_supervisor_authority as supervisor
import pr320_supervisor_projection as projection
from cryptad_certification.tests.test_cross_version_evidence import fixture_plan


def report():
    plan = fixture_plan()
    return dict(schemaVersion=1, kind='cryptad-cross-version-supervisor', operation='authorize',
        experimentId=plan['experimentId'], planDigest=supervisor.digest(plan), producer=plan['producer'],
        job=dict(sourceCommit='a'*40, runId=9, runAttempt=2), purpose='nonrelease-observed-experiment',
        releaseEligible=False, selectionDigest='sha256:'+'b'*64, approvedBounds={}, plan=plan,
        serviceDigest='sha256:'+'c'*64)


class BudgetSupervisorProjectionTest(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'isolated root fixture invocation required')
    def test_private_report_retained_and_exact_public_receipt_reopens(self):
        private = report()
        with tempfile.TemporaryDirectory(dir='/root') as temporary, \
             patch.object(projection, 'ROOT', Path(temporary)/'originals'), \
             patch.object(projection, '__file__', '/opt/cryptad-cross-version/current/private.py'):
            public = projection.retain(private)
            raw = json.dumps(public)
            for private_field in ('plan', 'producer', 'selectionDigest', 'approvedBounds', 'serviceDigest'):
                self.assertNotIn(private_field, public)
            for private_digest in (private['selectionDigest'], private['planDigest'], private['serviceDigest']):
                self.assertNotIn(private_digest, raw)
            self.assertEqual(private, projection.reopen(public))
            altered = copy.deepcopy(public)
            altered['job']['runAttempt'] = 3
            with self.assertRaisesRegex(ValueError, 'substituted'):
                projection.reopen(altered)
            with patch.object(projection.os, 'geteuid', return_value=62001), self.assertRaisesRegex(ValueError, 'owner-required'):
                projection.reopen(public)

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'isolated root fixture invocation required')
    def test_original_member_job_and_attestation_are_checked_before_private_reopening(self):
        private = report()
        coordinates = dict(sourceFamily='cross-version-supervisor', sourceCommit='a'*40,
            runId=9, runAttempt=2, artifactName='cross-version-supervisor-9-2')
        with tempfile.TemporaryDirectory(dir='/root') as temporary, \
             patch.object(projection, 'ROOT', Path(temporary)/'originals'), \
             patch.object(projection, '__file__', '/opt/cryptad-cross-version/current/private.py'):
            public = projection.retain(private)
            content = io.BytesIO()
            with zipfile.ZipFile(content, 'w') as archive:
                archive.writestr('cross-version-supervisor.json', json.dumps(public))
            original = SimpleNamespace(content=content.getvalue(), coordinates=coordinates)
            invocation = 'https://github.com/crypta-network/cryptad/actions/runs/9/attempts/2'
            verified = [{'verificationResult': {'signature': {'certificate': {'runInvocationURI': invocation}}}}]
            with patch.object(supervisor, 'authenticate_original', return_value=original), \
                 patch.object(supervisor, '_environment', return_value={}), \
                 patch.object(supervisor, '_gh', return_value=verified) as attest:
                observed, _ = supervisor.authenticate_report(coordinates, Path(temporary))
                self.assertEqual(private, observed)
                attest.return_value = []
                with patch.object(projection, 'reopen') as reopen, self.assertRaisesRegex(ValueError, 'attested-attempt'):
                    supervisor.authenticate_report(coordinates, Path(temporary))
                reopen.assert_not_called()

    def test_public_shape_rejects_extra_private_fields_and_boolean_versions(self):
        public = dict(schemaVersion=9, kind='cryptad-cross-version-supervisor', operation='authorize',
            job=dict(sourceCommit='a'*40,runId=1,runAttempt=1), purpose='nonrelease-observed-experiment',
            releaseEligible=False, privateOriginalReceipt=dict(schemaVersion=1,
                kind='pr320-private-supervisor-original', receiptId='b'*32))
        projection.validate(public)
        for changed in (dict(public, planDigest='sha256:'+'c'*64), dict(public, schemaVersion=True),
                        dict(public, job=dict(public['job'], privateSelection='payload'))):
            with self.assertRaises(ValueError): projection.validate(changed)


if __name__ == '__main__':
    unittest.main()
