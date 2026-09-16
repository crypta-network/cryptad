"""Semantic fixture checks; no installed execution claim."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import pr313_public_faults as faults
from pr312_app_projection import _artifact

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protected'))
import app_subject_projection as projection
import original_artifact_authentication as original
import bounded_process


class PublicPayloadTest(unittest.TestCase):
    def test_actual_owner_rejects_each_payload_at_intended_semantic_stage(self):
        for case in faults.CASES:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture = root / 'fixture'
                fixture.mkdir()
                for name in ('external.properties', 'external.signature', 'external-app.zip', 'submission.zip'):
                    (fixture / name).write_bytes(b'public-synthetic-selected-input')
                artifact, names = _artifact(original, fixture)
                payload = faults.adversarial_payload(case, projection, 'private-canary')
                exporter = root / 'exporter'
                exporter.write_bytes(b'local-fixture-placeholder')
                # Explicit offline transport fixture; production owner parsing is unchanged.
                def output(arguments, **kwargs):
                    Path(arguments[arguments.index('--output') + 1]).write_bytes(payload)
                expected = ('app-subject-exported-member-mismatch' if case == 'public-wrong-subject'
                            else 'app-subject-java-verification-failed')
                with patch.object(bounded_process, 'run', side_effect=output):
                    with self.assertRaisesRegex(projection.ProjectionFailure, expected):
                        projection.produce(artifact, names, exporter=exporter,
                            exporter_digest='sha256:' + hashlib.sha256(exporter.read_bytes()).hexdigest(),
                            app_id='expected-app', catalog_key_id='synthetic', catalog_keys=root / 'keys',
                            publisher_keys=root / 'keys', reviewer_keys=None, private_root=root)


if __name__ == '__main__':
    unittest.main()
