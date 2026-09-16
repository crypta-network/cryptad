"""Offline validation of the separate signed-app fixture; no installed acceptance claim."""
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import pr312_app_projection as fixture
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protected'))
import original_artifact_authentication as original
import restricted_native as native


class AppProjectionFixtureTest(unittest.TestCase):
    def test_repository_import_cannot_claim_installed_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'new'
            with self.assertRaisesRegex(ValueError, 'requires-installed-guest'):
                fixture.run(target, Path('/opt/absent'), 'a' * 64, Path('/root/jdk'))
            self.assertFalse(target.exists())

    def test_installed_module_must_match_exact_canonical_bundle(self):
        root = Path('/opt/cryptad-cross-version/bundles/' + 'a' * 64)
        exact = root / 'tools/release-certification/protected/restricted_native.py'
        with patch.object(native, '__file__', str(exact)):
            self.assertTrue(fixture._installed_module(native, root))
            self.assertFalse(fixture._installed_module(native, root.parent / ('b' * 64)))
            self.assertFalse(fixture._installed_module(native, Path('/opt/cryptad-restricted')))
        with patch.object(native, '__file__', str(exact)), patch.object(Path, 'is_symlink', return_value=True):
            self.assertFalse(fixture._installed_module(native, root))

    def test_synthetic_artifact_preserves_exact_closed_signed_roster(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = ('external.properties', 'external.signature', 'external-app.zip', 'submission.zip')
            for name in files:
                (root / name).write_bytes(name.encode())
            artifact, names = fixture._artifact(original, root)
            self.assertEqual({'catalog', 'catalogSignature', 'bundle', 'submission'}, set(names))
            self.assertEqual('sha256:' + hashlib.sha256(artifact.content).hexdigest(), artifact.coordinates['artifactDigest'])
            self.assertEqual('synthetic-pr312-signed-app', artifact.coordinates['artifactName'])
            with zipfile.ZipFile(io.BytesIO(artifact.content)) as archive:
                self.assertEqual(b'external-app.zip', archive.read('bundle'))
                self.assertEqual(set(names), set(archive.namelist()))

    def test_returned_owner_observation_cannot_claim_production_eligibility(self):
        result = {'declaration': {'appId': 'external-app'}, 'producerAttestation': 'not-observed',
                  'releaseEligibility': 'blocked'}
        fixture._validate_result(result)
        for key, value in (('producerAttestation', 'verified'), ('releaseEligibility', 'eligible')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                fixture._validate_result({**result, key: value})
        with self.assertRaises(ValueError):
            fixture._validate_result({**result, 'declaration': {'appId': 'wrong-app'}})

    def test_retained_active_invocation_prevents_quiescence_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'active.json').write_text('{}')
            with patch.object(native, 'ROOT', root), patch.object(native, '_manager',
                    return_value={'ActiveState': 'inactive', 'ControlGroup': ''}):
                with self.assertRaisesRegex(ValueError, 'quiescence-unavailable'):
                    fixture._quiescent(native)


if __name__ == '__main__':
    unittest.main()
