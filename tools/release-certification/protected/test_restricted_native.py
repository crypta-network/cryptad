"""Offline native boundary contract checks; these do not claim multi-UID isolation."""
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

import restricted_native as native


@unittest.skipUnless(sys.platform == 'linux', 'native execution boundary requires Linux')
class RestrictedNativeTest(unittest.TestCase):
    def test_unsupported_platform_import_does_not_load_unix_account_modules(self):
        import importlib.util
        import builtins
        original_import = builtins.__import__
        def without_unix(name, *args, **kwargs):
            if name in ('fcntl', 'grp', 'pwd'):
                raise AssertionError('unsupported platform imported Unix-only module')
            return original_import(name, *args, **kwargs)
        spec = importlib.util.spec_from_file_location('unsupported_native_boundary', native.__file__)
        module = importlib.util.module_from_spec(spec)
        with patch.object(sys, 'platform', 'win32'), patch('builtins.__import__', side_effect=without_unix):
            spec.loader.exec_module(module)
            with self.assertRaises(module.NativeBoundaryError):
                with module.owning_boundary():
                    self.fail('unsupported platform entered owning boundary')

    def test_installed_execution_cannot_fall_back_without_owning_context(self):
        with patch.object(native, '__file__', '/opt/cryptad-cross-version/current/protected/restricted_native.py'):
            with self.assertRaisesRegex(native.NativeBoundaryError, 'boundary-rejected'):
                native.run(['/usr/bin/true'], environment={})

    @unittest.skipIf(getattr(os, 'geteuid', lambda: 1)() == 0, 'requires the actual non-root test principal')
    def test_unprivileged_process_cannot_enter_owning_context(self):
        with self.assertRaisesRegex(native.NativeBoundaryError, 'boundary-rejected'):
            with native.owning_boundary():
                self.fail('non-root owner admitted')

    def test_native_input_copy_has_no_writable_alias_to_resolver_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.mkdir()
            (source / 'selection').write_bytes(b'scoped-selection')
            target = root / 'target'
            native._copy(source, target, os.geteuid(), os.getegid(), [0, 0])
            (target / 'selection').chmod(0o600)
            (target / 'selection').write_bytes(b'candidate-replacement')
            self.assertEqual(b'scoped-selection', (source / 'selection').read_bytes())
            self.assertNotEqual((source / 'selection').stat().st_ino,
                                (target / 'selection').stat().st_ino)

    def test_materialized_jdk_internal_link_preserves_approved_tree_through_copy(self):
        import maintenance_runtime_metadata as metadata
        import app_subject_projection as projection
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / 'jdk-installed'
            legal = original / 'legal'
            legal.mkdir(parents=True)
            (legal / 'notice').write_bytes(b'approved-jdk-notice')
            (legal / 'duplicate').write_bytes(b'approved-jdk-notice')
            expected = projection.tree_digest(original)
            (legal / 'duplicate').unlink()
            (legal / 'duplicate').symlink_to('notice')
            staged = metadata.stage_jdk(original, root / 'jdk-approved', expected)
            native._copy(staged, root / 'jdk-native', os.geteuid(), os.getegid(), [0, 0])
            self.assertEqual(expected, projection.tree_digest(root / 'jdk-native'))
            self.assertFalse((root / 'jdk-native/legal/duplicate').is_symlink())

    def test_unmaterialized_jdk_link_cannot_bypass_original_owner_identity(self):
        import app_subject_projection as projection
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jdk = root / 'jdk'
            jdk.mkdir()
            (root / 'external-cacerts').write_bytes(b'not-in-approved-closure')
            (jdk / 'cacerts').symlink_to(root / 'external-cacerts')
            with self.assertRaises(projection.ProjectionFailure):
                projection.tree_digest(jdk)
            with self.assertRaises(native.NativeBoundaryError):
                native._copy(jdk, root / 'native', os.geteuid(), os.getegid(), [0, 0])

    def test_input_symlink_and_hardlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.write_bytes(b'private-canary')
            link = root / 'link'
            link.symlink_to(source)
            with self.assertRaises(native.NativeBoundaryError):
                native._copy(link, root / 'target', os.geteuid(), os.getegid(), [0, 0])
            link.unlink()
            os.link(source, link)
            with self.assertRaises(native.NativeBoundaryError):
                native._copy(source, root / 'target', os.geteuid(), os.getegid(), [0, 0])

    def test_output_collection_rejects_link_oversize_and_existing_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / 'source', root / 'target'
            source.symlink_to(target)
            with self.assertRaises(OSError):
                native._collect(source, target)
            source.unlink()
            source.write_bytes(b'x' * 32769)
            with self.assertRaises(native.NativeBoundaryError):
                native._collect(source, target)
            source.write_bytes(b'{"untrusted":"private-canary"}')
            target.write_bytes(b'owning-record')
            with self.assertRaises(FileExistsError):
                native._collect(source, target)
            self.assertEqual(b'owning-record', target.read_bytes())

    def test_output_collection_preserves_exact_bytes_for_owning_semantic_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / 'source', root / 'projection.json'
            raw = b'{"untrusted":"not-an-admission-capability"}'
            source.write_bytes(raw)
            native._collect(source, target)
            self.assertEqual(raw, target.read_bytes())
            self.assertEqual(0o600, target.stat().st_mode & 0o777)


if __name__ == '__main__':
    unittest.main()
