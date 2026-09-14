"""Real CMS/exact-retention integration with the existing synthetic publication fixture.

This checks provider intake only. Arbitrary private JSON members are not native admission evidence;
no producer authentication, authorization, key provisioning or public operation is performed here.
"""
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch

import maintenance_runtime_companion as companion
from maintenance_runtime_transfer import copy_frozen_tree
import test_maintenance_runtime_companion as transport_owner
from cryptad_certification.tests import test_stable_maintenance_publication as fixture_owner


@unittest.skipUnless(sys.platform == 'linux', 'maintenance CMS uses the fixed Linux resource limiter')
class SealedPublicationRetentionTest(unittest.TestCase):
    def setUp(self):
        transport = transport_owner.CompanionTransportTest()
        transport.setUp()
        self.addCleanup(transport.doCleanups)
        self.transport = transport
        self.root = transport.root / 'publication'
        original_write = fixture_owner.write_json
        def write(path, value):
            if path.name == 'maintenance-candidate-freeze.json':
                value['schemaVersion'] = 3
                value['predecessorObservation']['sourceCommit'] = 'c' * 40
                value['checksumsDigest'] = companion._digest(b'exact-public-checksums\n')
                self.original = transport.root / 'original-freeze'
                self.original.mkdir()
                value['runtimeMetadata'] = companion.seal(transport.source, self.original / 'runtime', value)
                original_write(self.original / 'stable-1.0-maintenance-candidate-freeze.json', value)
                (self.original / 'checksums.txt').write_bytes(b'exact-public-checksums\n')
                assets = self.original / 'assets'
                assets.mkdir()
                for row in value['assets']:
                    shutil.copyfile(self.root / 'component/artifacts/legacy' / row['fileName'], assets / row['fileName'])
            original_write(path, value)
        with patch.object(fixture_owner, 'write_json', side_effect=write):
            self.fixture = fixture_owner.BundleFixture(self.root)
        copy_frozen_tree(self.fixture.candidate_freeze, self.original, self.root / 'freeze')

    def test_real_cms_exact_frozen_tree_reaches_existing_publication_intake(self):
        with patch.object(companion, 'open_companion', side_effect=AssertionError('provider must not open')):
            bundle = self.fixture.load()
        self.assertEqual(bundle.root, self.root)
        original = self.original / 'runtime/runtime-companion.cms'
        retained = self.root / 'freeze/runtime/runtime-companion.cms'
        self.assertEqual(original.read_bytes(), retained.read_bytes())
        self.assertFalse(any(row['fileName'].startswith('runtime-companion') for row in bundle.plan['assets']))

    def test_missing_and_mutated_committed_ciphertext_block_provider(self):
        ciphertext = self.root / 'freeze/runtime/runtime-companion.cms'
        raw = ciphertext.read_bytes()
        for content in (None, raw[:-1] + bytes([raw[-1] ^ 1])):
            with self.subTest(missing=content is None):
                if content is None:
                    ciphertext.unlink()
                else:
                    ciphertext.write_bytes(content)
                with self.assertRaisesRegex(fixture_owner.publication.AdapterError, 'maintenance-runtime-sealed-handoff-invalid'):
                    self.fixture.load()


if __name__ == '__main__':
    unittest.main()
