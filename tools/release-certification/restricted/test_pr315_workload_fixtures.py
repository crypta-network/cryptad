"""Offline fixture admission tests; no daemon launch or installed acceptance."""
import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import pr315_workload_fixtures as fixtures


def products():
    return {name: {'sourceCommit': marker * 40, 'artifactDigest': 'sha256:' + marker * 64,
        'artifactSize': 100, 'daemonDigest': 'sha256:' + marker * 64, 'packageTarget': 'linux-x64',
        'contractVersion': 26, 'classification': 'historical-source-build' if name == 'previous' else 'source-build'}
        for name, marker in (('candidate', 'a'), ('previous', 'b'))}


class AdmissionTests(unittest.TestCase):
    def test_distinct_labels_and_archives_cannot_repackage_one_daemon(self):
        value = products()
        fixtures.validate_roster(value)
        value['previous']['daemonDigest'] = value['candidate']['daemonDigest']
        with self.assertRaisesRegex(ValueError, 'previous-not-distinct'):
            fixtures.validate_roster(value)

    def test_source_lane_never_claims_original_product(self):
        value = products()
        value['previous']['classification'] = 'originally-published'
        with self.assertRaisesRegex(ValueError, 'products-invalid'):
            fixtures.validate_roster(value)

    def test_embedded_jar_marker_is_checked_by_real_runtime_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'lib').mkdir()
            with zipfile.ZipFile(root / 'lib/cryptad.jar', 'w') as jar:
                jar.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\nImplementation-Version: 315 aaaaaaa\n\n')
            expected = 'sha256:' + hashlib.sha256((root / 'lib/cryptad.jar').read_bytes()).hexdigest()
            self.assertEqual(expected, fixtures.runtime.packaged_daemon_identity(root, 'a' * 40))
            with self.assertRaisesRegex(fixtures.runtime.RuntimeFailure, 'embedded-source-mismatch'):
                fixtures.runtime.packaged_daemon_identity(root, 'b' * 40)

    def test_invalid_budget_fails_before_output_allocation(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'inputs'
            for value in (True, 29, 3601):
                args = SimpleNamespace(max_seconds=value, max_operations=100, candidate_commit='a' * 40,
                                       previous_commit='b' * 40, output=output)
                with self.assertRaisesRegex(ValueError, 'selection-invalid'):
                    fixtures.prepare(args)
                self.assertFalse(output.exists())


class FileTests(unittest.TestCase):
    def test_exact_copy_is_private_and_inventory_detects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / 'source', root / 'target'
            source.write_bytes(b'exact portable input')
            fixtures.copy_input(source, target, 100)
            self.assertEqual(source.read_bytes(), target.read_bytes())
            self.assertEqual(0o600, target.stat().st_mode & 0o777)
            before = fixtures.inventory(root)
            target.write_bytes(b'changed')
            self.assertNotEqual(before, fixtures.inventory(root))

    def test_copy_rejects_symlinks_hardlinks_fifo_and_oversize(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / 'regular'
            regular.write_bytes(b'bytes')
            link = root / 'link'
            link.symlink_to(regular)
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            hard = root / 'hard'
            os.link(regular, hard)
            for source in (regular, link, fifo, hard):
                with self.subTest(source=source.name), self.assertRaises(ValueError):
                    fixtures.copy_input(source, root / 'output', 2)
                self.assertFalse((root / 'output').exists())

    def test_parent_symlink_is_not_an_allowed_copy_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / 'actual'
            actual.mkdir()
            (actual / 'file').write_bytes(b'bytes')
            (root / 'alias').symlink_to(actual, target_is_directory=True)
            with self.assertRaises(ValueError):
                fixtures.copy_input(root / 'alias/file', root / 'output', 10)

    def test_digest_rejects_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / 'fifo'
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                fixtures.digest(fifo)

    def test_inventory_rejects_directory_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'alias').symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'link-invalid'):
                fixtures.inventory(root)


class SelectionTests(unittest.TestCase):
    def test_guest_materialization_binds_fresh_installed_identity_and_fixed_roster(self):
        selected = {'products': products(), 'runtimeDigest': 'sha256:' + 'c' * 64,
            'mailDigest': 'sha256:' + 'd' * 64, 'trustDigest': 'sha256:' + 'e' * 64,
            'maxSeconds': 900, 'maxOperations': 1000}
        producer = {'sourceCommit': 'f' * 40, 'runnerDigest': 'sha256:' + '1' * 64,
                    'adapterDigest': 'sha256:' + '2' * 64}
        with patch.object(fixtures, 'verify', return_value=selected) as verify, \
                patch.object(fixtures.os, 'geteuid', return_value=0), \
                patch.object(fixtures.runtime, 'runner_identity', return_value=producer), \
                patch.object(fixtures.preparation, 'configuration_identity',
                             side_effect=lambda role, trust: 'sha256:' + hashlib.sha256(role.encode()).hexdigest()):
            value = fixtures.materialize_selection(fixtures.FIXED_GUEST_ROOT, Path('/root/cryptad'), '9' * 64, 'a' * 40)
        verify.assert_called_once_with(fixtures.FIXED_GUEST_ROOT, '9' * 64, Path('/root/cryptad'), 'a' * 40)
        self.assertEqual(producer, value['plan']['producer'])
        self.assertEqual(list(fixtures.ROLES), [row['role'] for row in value['plan']['nodes']])
        for role, row in value['private']['nodes'].items():
            self.assertEqual((19400, 19401, 19402), (row['fnpPort'], row['fcpPort'], row['httpPort']))
            self.assertEqual(1 if role.startswith('candidate-') else 0, len(row['apps']))
        self.assertEqual(fixtures.runtime.canonical_digest(value['plan']), value['authorization']['planDigest'])
        self.assertEqual(900, value['authorization']['maxSeconds'])

    def test_guest_requires_expected_binding_and_fixed_path(self):
        with patch.object(fixtures.os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(ValueError, 'fixed-guest-root'):
                fixtures.materialize_selection(Path('/tmp/arbitrary'), Path('/root/cryptad'))
            with self.assertRaisesRegex(ValueError, 'expected-binding'):
                fixtures.materialize_selection(fixtures.FIXED_GUEST_ROOT, Path('/root/cryptad'))


if __name__ == '__main__':
    unittest.main()
