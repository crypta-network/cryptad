"""Exercise actual descriptor copies and malicious filesystem inputs."""
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest import mock

import restricted_workload_storage as storage


@unittest.skipUnless(os.geteuid() == 0, 'root-owned immutable staging requires root')
class WorkloadStorageTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cryptad-storage-test-', dir='/var/lib')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir(mode=0o700)
        self.destination = self.root / 'destination'
        self.deadline = time.monotonic() + 20

    def copy(self, **kwargs):
        return storage.copy_tree(self.source, self.destination, self.deadline, **kwargs)

    def test_copies_private_inputs_with_read_only_executable_modes(self):
        (self.source / 'nested').mkdir()
        (self.source / 'nested' / 'data').write_bytes(b'abc')
        executable = self.source / 'launcher'
        executable.write_bytes(b'fixed')
        executable.chmod(0o700)
        self.assertEqual({'bytes': 8, 'entries': 3}, self.copy())
        self.assertEqual(b'abc', (self.destination / 'nested' / 'data').read_bytes())
        self.assertEqual(0o444, stat.S_IMODE((self.destination / 'nested' / 'data').stat().st_mode))
        self.assertEqual(0o555, stat.S_IMODE((self.destination / 'launcher').stat().st_mode))
        self.assertEqual(0o755, stat.S_IMODE(self.destination.stat().st_mode))
        self.assertEqual(0, self.destination.stat().st_uid)
        self.assertEqual(0o700, stat.S_IMODE(self.source.stat().st_mode))

    def test_rejects_symlink_fifo_and_hardlink_without_opening_them(self):
        for kind in ('symlink', 'fifo', 'hardlink'):
            with self.subTest(kind=kind):
                path = self.source / kind
                if kind == 'symlink':
                    path.symlink_to('/etc/passwd')
                elif kind == 'fifo':
                    os.mkfifo(path)
                else:
                    original = self.root / 'original'
                    original.write_bytes(b'private')
                    os.link(original, path)
                self.destination = self.root / ('destination-' + kind)
                with self.assertRaises(storage.StorageError):
                    self.copy()
                self.assertTrue(self.destination.is_dir())
                self.assertFalse((self.destination / kind).exists())
                path.unlink()

    def test_rejects_writable_ancestor_before_mutation(self):
        self.root.chmod(0o777)
        with self.assertRaises(storage.StorageError):
            self.copy()
        self.assertFalse(self.destination.exists())
        self.root.chmod(0o700)

    def test_rejects_non_root_file_owner(self):
        path = self.source / 'candidate'
        path.write_bytes(b'attack')
        os.chown(path, 65534, 65534)
        with self.assertRaises(storage.StorageError):
            self.copy()
        self.assertTrue(self.destination.is_dir())

    def test_rejects_symlink_ancestor(self):
        linked = self.root / 'linked'
        linked.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(storage.StorageError):
            storage.copy_tree(linked, self.destination, self.deadline)
        self.assertFalse(self.destination.exists())

    def test_byte_and_entry_limits_retain_failed_destination(self):
        (self.source / 'data').write_bytes(b'1234')
        with self.assertRaisesRegex(storage.StorageError, 'byte-budget'):
            self.copy(max_bytes=3)
        self.assertTrue(self.destination.is_dir())
        self.destination = self.root / 'second-destination'
        (self.source / 'other').write_bytes(b'a')
        with self.assertRaisesRegex(storage.StorageError, 'entry-budget'):
            self.copy(max_files=1)
        self.assertTrue(self.destination.is_dir())

    def test_existing_destination_never_overwritten(self):
        self.destination.mkdir()
        marker = self.destination / 'marker'
        marker.write_bytes(b'retained')
        with self.assertRaises(storage.StorageError):
            self.copy()
        self.assertEqual(b'retained', marker.read_bytes())

    def test_expired_deadline_does_not_allocate(self):
        self.deadline = time.monotonic() - 1
        with self.assertRaisesRegex(storage.StorageError, 'deadline'):
            self.copy()
        self.assertFalse(self.destination.exists())

    def test_modified_input_is_not_credited(self):
        path = self.source / 'data'
        path.write_bytes(b'abcd')
        real_read = os.read
        changed = False

        def read_and_replace(fd, size):
            nonlocal changed
            result = real_read(fd, size)
            if result and not changed:
                changed = True
                path.unlink()
                path.write_bytes(b'fake')
            return result

        with mock.patch.object(storage.os, 'read', side_effect=read_and_replace):
            with self.assertRaises(storage.StorageError):
                self.copy()
        self.assertTrue(changed)
        self.assertTrue(self.destination.exists())

    def test_replaced_destination_is_rejected_and_both_trees_retained(self):
        (self.source / 'data').write_bytes(b'abcd')
        real_read = os.read
        changed = False
        retained = self.root / 'retained'

        def read_and_replace(fd, size):
            nonlocal changed
            result = real_read(fd, size)
            if result and not changed:
                changed = True
                self.destination.rename(retained)
                self.destination.mkdir()
            return result

        with mock.patch.object(storage.os, 'read', side_effect=read_and_replace):
            with self.assertRaisesRegex(storage.StorageError, 'destination-replaced'):
                self.copy()
        self.assertEqual(b'abcd', (retained / 'data').read_bytes())
        self.assertTrue(self.destination.is_dir())

    def test_writable_input_file_is_rejected(self):
        path = self.source / 'data'
        path.write_bytes(b'untrusted')
        path.chmod(0o666)
        with self.assertRaisesRegex(storage.StorageError, 'input-not-trusted'):
            self.copy()
        self.assertFalse((self.destination / 'data').exists())

    def test_depth_budget_retains_partial_copy(self):
        current = self.source
        for _ in range(storage.MAX_DEPTH + 1):
            current /= 'd'
            current.mkdir()
        with self.assertRaisesRegex(storage.StorageError, 'depth-exceeded'):
            self.copy()
        self.assertTrue(self.destination.exists())

    def test_destination_inside_source_is_rejected(self):
        self.destination = self.source / 'recursive'
        with self.assertRaisesRegex(storage.StorageError, 'path-invalid'):
            self.copy()
        self.assertFalse(self.destination.exists())

    def test_invalid_budgets_rejected_before_mutation(self):
        for value in (0, True, storage.MAX_BYTES + 1):
            with self.subTest(value=value), self.assertRaises(storage.StorageError):
                self.copy(max_bytes=value)
        self.assertFalse(self.destination.exists())


@unittest.skipUnless(os.geteuid() == 0, 'candidate snapshot verification requires root')
class InstalledAppSnapshotTest(unittest.TestCase):
    def setUp(self):
        from restricted_native_launcher import tree_identity
        self.temporary = tempfile.TemporaryDirectory(prefix='cryptad-app-snapshot-test-', dir='/var/lib')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'installed'
        self.source.mkdir()
        (self.source / 'run').write_bytes(b'signed-original')
        (self.source / 'run').chmod(0o755)
        self.expected = tree_identity(self.source)
        # The source now really belongs to an untrusted workload identity.
        os.chown(self.source / 'run', 65534, 65534)
        os.chown(self.source, 65534, 65534)
        self.scratch = self.root / 'verification'

    def verify(self):
        return storage.verify_installed_app(self.source, self.expected, self.scratch,
                                            time.monotonic() + 10)

    def test_exact_untrusted_installed_bytes_match_and_only_snapshot_removed(self):
        self.assertEqual(self.expected, self.verify())
        self.assertFalse(self.scratch.exists())
        self.assertEqual(b'signed-original', (self.source / 'run').read_bytes())
        self.assertEqual(65534, self.source.stat().st_uid)

    def test_changed_bytes_retain_exclusive_failure_and_prevent_retry(self):
        (self.source / 'run').write_bytes(b'candidate-forged')
        with self.assertRaisesRegex(storage.StorageError, 'identity-mismatch'):
            self.verify()
        self.assertTrue((self.scratch / 'tree').is_dir())
        with self.assertRaises(storage.StorageError):
            self.verify()
        self.assertEqual(b'candidate-forged', (self.source / 'run').read_bytes())

    def test_fifo_symlink_and_hardlink_fail_without_deleting_candidate_state(self):
        from restricted_native import NativeBoundaryError
        for kind in ('fifo', 'symlink', 'hardlink'):
            with self.subTest(kind=kind):
                hostile = self.source / 'hostile'
                if kind == 'fifo':
                    os.mkfifo(hostile)
                elif kind == 'symlink':
                    hostile.symlink_to('/etc/passwd')
                else:
                    os.link(self.source / 'run', hostile)
                self.scratch = self.root / ('verification-' + kind)
                with self.assertRaises((storage.StorageError, NativeBoundaryError)):
                    self.verify()
                self.assertTrue(self.scratch.is_dir())
                self.assertTrue(hostile.exists() or hostile.is_symlink())
                hostile.unlink()

    def test_oversized_sparse_output_is_rejected_before_copying(self):
        from restricted_native import NativeBoundaryError
        with (self.source / 'oversize').open('wb') as stream:
            stream.truncate(storage.APP_MAX_BYTES + 1)
        with self.assertRaises((storage.StorageError, NativeBoundaryError)):
            self.verify()
        self.assertTrue(self.scratch.is_dir())
        self.assertFalse((self.scratch / 'tree/oversize').exists())

    def test_existing_scratch_does_not_inspect_or_replace_source(self):
        self.scratch.mkdir()
        (self.scratch / 'retained').write_bytes(b'failure')
        with self.assertRaises(storage.StorageError):
            self.verify()
        self.assertEqual(b'failure', (self.scratch / 'retained').read_bytes())

    def test_untrusted_scratch_ancestor_is_rejected_before_reservation(self):
        self.root.chmod(0o777)
        with self.assertRaises(storage.StorageError):
            self.verify()
        self.assertFalse(self.scratch.exists())
        self.root.chmod(0o700)


class StorageRootPolicyTest(unittest.TestCase):
    def test_nonroot_cannot_stage(self):
        with mock.patch.object(storage.os, 'geteuid', return_value=65534):
            with self.assertRaisesRegex(storage.StorageError, 'root-required'):
                storage.copy_tree('/missing', '/missing-copy', time.monotonic() + 1)


if __name__ == '__main__':
    unittest.main()
