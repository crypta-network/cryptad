"""Real deterministic source races; local checks do not establish installed VM acceptance."""
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import restricted_native as native


@unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'O_PATH'),
                     'the installed input copier requires Linux O_PATH')
class NativeInputRaceTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='native-input-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.leaf = self.source / 'input'
        self.leaf.write_bytes(b'original')
        self.output = self.root / 'copied'

    def copy(self, **kwargs):
        native._copy(self.source, self.output, os.getuid(), os.getgid(), [0, 0], **kwargs)

    def test_regular_tree_copies_exact_bytes(self):
        self.copy()
        self.assertEqual((self.output / 'input').read_bytes(), b'original')

    def swap_at_destination_creation(self, mutation):
        original = os.chown
        changed = False
        def chown(path, uid, gid):
            nonlocal changed
            original(path, uid, gid)
            if not changed:
                changed = True
                mutation()
        return patch.object(native.os, 'chown', side_effect=chown)

    def test_source_replaced_with_symlink_never_stages_substituted_bytes(self):
        alternate = self.root / 'alternate'
        alternate.mkdir()
        (alternate / 'input').write_bytes(b'substituted')
        def replace():
            self.source.rename(self.root / 'old')
            self.source.symlink_to(alternate, target_is_directory=True)
        with self.swap_at_destination_creation(replace), self.assertRaises(native.NativeBoundaryError):
            self.copy()
        self.assertEqual((self.output / 'input').read_bytes(), b'original')

    def test_ancestor_replaced_while_original_leaf_remains_is_rejected(self):
        parent = self.root / 'parent'
        parent.mkdir()
        self.source.rename(parent / 'source')
        self.source = parent / 'source'
        def replace():
            parent.rename(self.root / 'old-parent')
            parent.symlink_to(self.root / 'old-parent', target_is_directory=True)
        with self.swap_at_destination_creation(replace), self.assertRaises(native.NativeBoundaryError):
            self.copy()

    def test_directory_members_added_during_copy_are_rejected(self):
        with self.swap_at_destination_creation(lambda: (self.source / 'added').write_bytes(b'x')):
            with self.assertRaises(native.NativeBoundaryError):
                self.copy()

    def test_replaced_leaf_larger_than_remaining_budget_is_rejected_before_read(self):
        self.leaf.write_bytes(b'123456789')
        with patch.object(native.os, 'read', side_effect=AssertionError('must not read')):
            with self.assertRaises(native.NativeBoundaryError):
                native._copy(self.leaf, self.output, os.getuid(), os.getgid(), [4 * 1024**3 - 8, 0])

    def test_symlink_and_hardlink_sources_rejected_before_read(self):
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind):
                link = self.source / kind
                if kind == 'symlink':
                    link.symlink_to(self.leaf)
                else:
                    os.link(self.leaf, link)
                with patch.object(native.os, 'read', side_effect=AssertionError('must not read')):
                    with self.assertRaises(native.NativeBoundaryError):
                        native._copy(link, self.output, os.getuid(), os.getgid(), [0, 0])
                link.unlink()

    def test_same_size_rewrite_during_read_rejected(self):
        original = os.read
        changed = False
        def read(fd, size):
            nonlocal changed
            raw = original(fd, size)
            if not changed:
                changed = True
                before = self.leaf.stat()
                self.leaf.write_bytes(b'replaced')
                os.utime(self.leaf, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000))
            return raw
        with patch.object(native.os, 'read', side_effect=read), self.assertRaises(native.NativeBoundaryError):
            self.copy()

    def test_trusted_source_rejects_group_writable_member(self):
        self.leaf.chmod(0o660)
        with self.assertRaises(native.NativeBoundaryError):
            self.copy(trusted_source=True)

    @unittest.skipIf(os.geteuid() == 0, 'requires actual nonroot source owner')
    def test_actual_nonroot_source_is_denied_before_any_read(self):
        with patch.object(native.os, 'read', side_effect=AssertionError('must not read')):
            with self.assertRaises(native.NativeBoundaryError):
                self.copy(trusted_source=True)

    @unittest.skipUnless(os.geteuid() == 0, 'root-owned fixture requires root')
    def test_root_owned_sticky_ancestor_with_private_child_is_allowed(self):
        self.assertTrue(Path('/tmp').stat().st_mode & 0o1000)
        self.copy(trusted_source=True)
        self.assertEqual((self.output / 'input').read_bytes(), b'original')

    @unittest.skipUnless(os.geteuid() == 0, 'root-owned fixture requires root')
    def test_writable_nonsticky_ancestor_is_denied(self):
        self.root.chmod(0o777)
        with self.assertRaises(native.NativeBoundaryError):
            self.copy(trusted_source=True)

    @unittest.skipUnless(os.geteuid() == 0, 'ownership fixture requires root')
    def test_nonroot_owned_member_is_denied(self):
        os.chown(self.leaf, 65534, 65534)
        with self.assertRaises(native.NativeBoundaryError):
            self.copy(trusted_source=True)


if __name__ == '__main__':
    unittest.main()
