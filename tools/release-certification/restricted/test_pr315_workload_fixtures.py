"""Offline fixture admission tests; no daemon launch or installed acceptance."""
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import pr315_workload_fixtures as fixtures


def products():
    return {name: {'sourceCommit': marker * 40, 'artifactDigest': 'sha256:' + marker * 64,
        'artifactSize': 100, 'daemonDigest': 'sha256:' + marker * 64, 'packageTarget': 'linux-x64',
        'daemonImplementationDigest': 'sha256:' + marker * 64,
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


class ImplementationIdentityTests(unittest.TestCase):
    def jar(self, path, revision, implementation=b'\xca\xfe\xba\xbe implementation-a', *, reverse=False):
        rows = [('META-INF/MANIFEST.MF', ('Implementation-Version: ' + revision).encode()),
                (fixtures.GENERATED_VERSION, b'\xca\xfe\xba\xbe revision-' + revision.encode()),
                ('network/crypta/node/Node.class', implementation)]
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED if reverse else zipfile.ZIP_STORED) as jar:
            jar.comment = revision.encode()
            for name, raw in reversed(rows) if reverse else rows:
                entry = zipfile.ZipInfo(name, (2026 if reverse else 2025, 1, 1, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_DEFLATED if reverse else zipfile.ZIP_STORED
                jar.writestr(entry, raw)

    def test_marker_and_archive_metadata_only_difference_cannot_prove_two_products(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate, previous = Path(directory) / 'candidate.jar', Path(directory) / 'previous.jar'
            self.jar(candidate, 'candidate')
            self.jar(previous, 'previous', reverse=True)
            self.assertNotEqual(candidate.read_bytes(), previous.read_bytes())
            rows = products()
            for name, path in (('candidate', candidate), ('previous', previous)):
                rows[name]['daemonDigest'] = 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
                rows[name]['daemonImplementationDigest'] = fixtures.daemon_implementation_identity(path)
            self.assertEqual(rows['candidate']['daemonImplementationDigest'], rows['previous']['daemonImplementationDigest'])
            with self.assertRaisesRegex(ValueError, 'previous-not-distinct'):
                fixtures.validate_roster(rows)

    def test_substantive_class_bytes_distinguish_products(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate, previous = Path(directory) / 'candidate.jar', Path(directory) / 'previous.jar'
            self.jar(candidate, 'candidate')
            self.jar(previous, 'previous', b'\xca\xfe\xba\xbe implementation-b')
            rows = products()
            for name, path in (('candidate', candidate), ('previous', previous)):
                rows[name]['daemonImplementationDigest'] = fixtures.daemon_implementation_identity(path)
            self.assertNotEqual(rows['candidate']['daemonImplementationDigest'], rows['previous']['daemonImplementationDigest'])
            fixtures.validate_roster(rows)

    def test_portable_identity_is_recomputed_from_actual_daemon_member(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jar = root / 'daemon.jar'
            self.jar(jar, 'candidate')
            portable = root / 'product.tar.gz'
            with tarfile.open(portable, 'w:gz') as archive:
                archive.add(jar, arcname='cryptad/lib/cryptad.jar')
            self.assertEqual(fixtures.daemon_implementation_identity(jar),
                             fixtures.portable_implementation_identity(portable))
            measured = fixtures.portable_daemon_identities(portable,
                expected_digest='sha256:' + hashlib.sha256(portable.read_bytes()).hexdigest(),
                expected_size=portable.stat().st_size)
            self.assertEqual('sha256:' + hashlib.sha256(jar.read_bytes()).hexdigest(), measured['daemonDigest'])

    def test_verify_rejects_forged_raw_jar_digest_even_with_correct_portable_and_classes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / 'inputs'
            inputs.mkdir()
            selected = products()
            for name in ('candidate', 'previous'):
                jar = root / (name + '.jar')
                self.jar(jar, name, b'\xca\xfe\xba\xbe ' + name.encode())
                portable = inputs / (name + '.tar.gz')
                with tarfile.open(portable, 'w:gz') as archive:
                    archive.add(jar, arcname='cryptad/lib/cryptad.jar')
                selected[name].update(artifactDigest='sha256:' + hashlib.sha256(portable.read_bytes()).hexdigest(),
                    artifactSize=portable.stat().st_size,
                    **fixtures.portable_daemon_identities(portable))
            selected['candidate']['daemonDigest'] = 'sha256:' + 'f' * 64
            value = {'schemaVersion': 2, 'kind': 'pr315-workload-fixtures',
                'classification': fixtures.CLASSIFICATION, 'sourceCommit': 'a' * 40,
                'products': selected, 'roles': list(fixtures.ROLES),
                'runtimeDigest': 'sha256:' + '1' * 64, 'jdkClosureDigest': 'sha256:' + '2' * 64,
                'mailDigest': 'sha256:' + '3' * 64, 'trustDigest': 'sha256:' + '4' * 64,
                'verifierDigest': 'sha256:' + '5' * 64, 'maxSeconds': 900, 'maxOperations': 1000,
                'members': fixtures.inventory(inputs)}
            (inputs / fixtures.MANIFEST).write_text(json.dumps(value))
            with patch.object(fixtures.subprocess, 'check_output', return_value='a' * 40), \
                    self.assertRaisesRegex(ValueError, 'daemon-identity-mismatch'):
                fixtures.verify(inputs, fixtures.digest(inputs / fixtures.MANIFEST), root, 'a' * 40)

    def test_archive_replacement_between_hash_and_parse_is_rejected_without_following_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jar = root / 'daemon.jar'
            self.jar(jar, 'candidate')
            portable = root / 'portable.tar.gz'
            with tarfile.open(portable, 'w:gz') as archive:
                archive.add(jar, arcname='cryptad/lib/cryptad.jar')
            expected = 'sha256:' + hashlib.sha256(portable.read_bytes()).hexdigest()
            original = fixtures._portable_daemon_identities
            def replace_then_parse(stream, deadline):
                portable.unlink()
                os.mkfifo(portable)
                return original(stream, deadline)
            with patch.object(fixtures, '_portable_daemon_identities', side_effect=replace_then_parse), \
                    self.assertRaises(ValueError):
                fixtures.portable_daemon_identities(portable, expected_digest=expected)

    def test_archive_fifo_is_rejected_before_open_for_read(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / 'portable.tar.gz'
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, 'archive-file-invalid'):
                fixtures.portable_daemon_identities(fifo)

    def test_wrong_portable_digest_rejected_before_archive_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'portable.tar.gz'
            archive.write_bytes(b'not an archive')
            with patch.object(fixtures, '_portable_daemon_identities') as parse, \
                    self.assertRaisesRegex(ValueError, 'product-mismatch'):
                fixtures.portable_daemon_identities(archive, expected_digest='sha256:' + '0' * 64)
            parse.assert_not_called()

    def test_marker_only_jar_has_no_implementation(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as jar:
            jar.writestr(fixtures.GENERATED_VERSION, b'marker')
        stream.seek(0)
        with self.assertRaisesRegex(ValueError, 'implementation-empty'):
            fixtures._implementation_identity(stream)

    def test_duplicate_class_is_rejected_instead_of_selecting_one(self):
        import warnings
        stream = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(stream, 'w') as jar:
                jar.writestr('Node.class', b'first')
                jar.writestr('Node.class', b'second')
        stream.seek(0)
        with self.assertRaisesRegex(ValueError, 'entry-invalid'):
            fixtures._implementation_identity(stream)

    def test_legacy_product_roster_cannot_omit_implementation_binding(self):
        value = products()
        del value['previous']['daemonImplementationDigest']
        with self.assertRaisesRegex(ValueError, 'products-invalid'):
            fixtures.validate_roster(value)


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
