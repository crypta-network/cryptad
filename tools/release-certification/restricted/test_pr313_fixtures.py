"""Closed immutable-input contract tests; these do not imply installed native acceptance."""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import pr313_fixtures as fixtures


class FixtureInputsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(__file__).resolve().parents[3]
        import sys
        sys.path.insert(0, str(cls.source / 'tools/release-certification/protected'))
        import app_subject_projection as projection
        cls.projection = projection
        cls.commit = subprocess.run(['git', '-C', str(cls.source), 'rev-parse', 'HEAD'],
            check=True, capture_output=True, text=True, timeout=10).stdout.strip()

    def input_tree(self, root):
        for name in ('signed', 'federated', 'app-products'):
            (root / name).mkdir()
            (root / name / 'input').write_bytes(b'synthetic-input')
        (root / 'previous-api.jar').write_bytes(b'synthetic-variant')
        value = {'schemaVersion': 1, 'kind': 'pr313-synthetic-inputs', 'productionEligible': False,
            'sourceCommit': self.commit, 'productSourceCommit': self.commit,
            'jdkIdentity': 'sha256:' + 'a' * 64, 'toolIdentity': 'sha256:' + 'b' * 64,
            'producerSources': [{'path': name, 'sha256': fixtures.digest(self.source / name)}
                for name in fixtures.PRODUCERS], 'members': fixtures.inventory(root)}
        self.write_manifest(root, value)
        return value

    def write_manifest(self, root, value):
        (root / 'manifest.private.json').write_text(json.dumps(value))

    def verify(self, root):
        with patch.object(self.projection, 'tree_digest', return_value='sha256:' + 'b' * 64):
            return fixtures.verify(root, fixtures.digest(root / 'manifest.private.json'),
                self.source, self.commit)

    def test_exact_manifest_is_consumable_and_changes_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.input_tree(root)
            self.assertEqual(root, self.verify(root))
            (root / 'signed/input').write_bytes(b'substitution')
            with self.assertRaisesRegex(ValueError, 'identity-mismatch'):
                self.verify(root)

    def test_private_key_payloads_links_and_unlisted_roots_are_rejected(self):
        for name in ('signed/producer-env.json', 'signed/review-private.der', 'unexpected'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.input_tree(root)
                (root / name).write_bytes(b'private-canary')
                with self.assertRaisesRegex(ValueError, 'member-invalid'):
                    fixtures.inventory(root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.input_tree(root)
            (root / 'signed/link').symlink_to(root / 'signed/input')
            with self.assertRaisesRegex(ValueError, 'member-invalid'):
                fixtures.inventory(root)

    def test_missing_roster_bound_and_substituted_producer_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = self.input_tree(root)
            with patch.object(fixtures, 'MAX_BYTES', 1), self.assertRaisesRegex(ValueError, 'bound-exceeded'):
                fixtures.inventory(root)
            value['producerSources'][0]['sha256'] = '0' * 64
            self.write_manifest(root, value)
            with self.assertRaisesRegex(ValueError, 'producer-source-mismatch'):
                self.verify(root)
            (root / 'previous-api.jar').unlink()
            with self.assertRaisesRegex(ValueError, 'roster-incomplete'):
                fixtures.inventory(root)

    def test_caller_authored_authority_and_duplicate_json_cannot_enter_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = self.input_tree(root)
            value['productionEligible'] = True
            self.write_manifest(root, value)
            with self.assertRaisesRegex(ValueError, 'identity-mismatch'):
                self.verify(root)
            path = root / 'manifest.private.json'
            path.write_text('{"schemaVersion":1,"schemaVersion":1}')
            with self.assertRaises(Exception):
                self.verify(root)

    def test_diagnostics_classify_without_retaining_private_payload(self):
        observed = fixtures.classify_diagnostic(
            b'private-canary SIGILL C1 jdk.internal.classfile.impl.SplitConstantPool.entryByIndex')
        self.assertEqual('jvm-sigill', observed['failureClass'])
        self.assertEqual('split-constant-pool-entry', observed['fatalFrame'])
        self.assertNotIn('private-canary', str(observed))
        record = fixtures.command_record(['/usr/bin/true', 'private-canary'],
            {'PATH': '/usr/bin', 'SECRET': 'private-canary'}, 60, 'java-producers')
        self.assertNotIn('private-canary', str(record))
        self.assertEqual(fixtures.digest(Path('/usr/bin/true')), record['executableSha256'])

    def test_ambient_jvm_options_fail_before_preparation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'inputs'
            with patch.dict(os.environ, {'JAVA_TOOL_OPTIONS': '-Xint'}):
                with self.assertRaisesRegex(ValueError, 'ambient-jvm-options-forbidden'):
                    fixtures.prepare(self.source, root, self.commit)
            self.assertFalse(root.exists())
