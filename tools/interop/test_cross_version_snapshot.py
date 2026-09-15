"""Hostile output acquisition checks; these are not installed UID isolation acceptance."""
import hashlib
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

import runtime_snapshot as snapshot
import federated_catalog_runtime as catalog


@unittest.skipUnless(hasattr(os, 'O_PATH') and Path('/proc/self/fd').is_dir(),
                     'requires Linux O_PATH and procfs reference profile')
class WorkloadSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_catalog_content_commitment_is_unchanged_for_regular_tree(self):
        (self.root / 'static').mkdir()
        (self.root / 'static/page.html').write_bytes(b'synthetic app')
        (self.root / 'manifest.json').write_bytes(b'{}')
        rows = [[name, 'sha256:' + hashlib.sha256(data).hexdigest()] for name, data in
                [('manifest.json', b'{}'), ('static/page.html', b'synthetic app')]]
        self.assertEqual(rows, snapshot.content_tree(self.root))
        self.assertEqual(catalog.digest(rows), catalog.installed_content_tree(self.root))

    def test_links_fifo_socket_and_linked_ancestors_are_rejected(self):
        import socket
        with tempfile.TemporaryDirectory() as separate:
            other = Path(separate)
            (other / 'private').write_bytes(b'PRIVATE-CANARY')
            candidate = self.root / 'entry'
            candidate.symlink_to(other / 'private')
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.content_tree(self.root)
            candidate.unlink()
            os.link(other / 'private', candidate)
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.read_file(self.root, 'entry')
            candidate.unlink()
            os.mkfifo(candidate)
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.read_file(self.root, 'entry')
            candidate.unlink()
            with socket.socket(socket.AF_UNIX) as endpoint:
                endpoint.bind(str(candidate))
                with self.assertRaises(snapshot.SnapshotError):
                    snapshot.content_tree(self.root)
            candidate.unlink()
            candidate.symlink_to(other, target_is_directory=True)
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.read_file(candidate, 'private')

    def test_limits_prevent_partial_tree_acceptance(self):
        (self.root / 'a').write_bytes(b'1234')
        (self.root / 'b').write_bytes(b'5678')
        for limits in ({'maximum_entries': 1}, {'maximum_bytes': 7, 'maximum_file_bytes': 7},
                       {'maximum_file_bytes': 3}):
            with self.subTest(limits=limits), self.assertRaises(snapshot.SnapshotError):
                snapshot.content_tree(self.root, **limits)
        with self.assertRaises(snapshot.SnapshotError):
            snapshot.read_file(self.root, 'a', maximum=3)
        self.assertEqual(b'1234', snapshot.read_file(self.root, 'a', maximum=4))

    def test_replacement_during_read_rejects_result_and_does_not_follow_target(self):
        selected = self.root / 'output'
        selected.write_bytes(b'admitted observation')
        real_read = os.read
        replaced = False
        def replace_after_read(descriptor, count):
            nonlocal replaced
            value = real_read(descriptor, count)
            if not replaced:
                replaced = True
                selected.rename(self.root / 'old')
                selected.symlink_to('/etc/passwd')
            return value
        with patch.object(snapshot.os, 'read', side_effect=replace_after_read), \
                self.assertRaises(snapshot.SnapshotError):
            snapshot.read_file(self.root, 'output')

    def test_in_place_change_and_deadline_reject_observation(self):
        selected = self.root / 'output'
        selected.write_bytes(b'original')
        real_read = os.read
        replaced = False
        def mutate_after_read(descriptor, count):
            nonlocal replaced
            value = real_read(descriptor, count)
            if not replaced:
                replaced = True
                selected.write_bytes(b'mutation')
            return value
        with patch.object(snapshot.os, 'read', side_effect=mutate_after_read), \
                self.assertRaises(snapshot.SnapshotError):
            snapshot.read_file(self.root, 'output')
        with patch.object(snapshot.time, 'monotonic', side_effect=[0, 31]), \
                self.assertRaisesRegex(snapshot.SnapshotError, 'deadline'):
            snapshot.read_file(self.root, 'output')

    def test_directory_replacement_during_walk_rejects_complete_result(self):
        selected = self.root / 'app'
        selected.mkdir()
        (selected / 'data').write_bytes(b'synthetic')
        real_read = os.read
        replaced = False
        def replace_root(descriptor, count):
            nonlocal replaced
            value = real_read(descriptor, count)
            if not replaced:
                replaced = True
                selected.rename(self.root / 'prior')
                selected.mkdir()
                (selected / 'data').write_bytes(b'replacement')
            return value
        with patch.object(snapshot.os, 'read', side_effect=replace_root), \
                self.assertRaises(snapshot.SnapshotError):
            snapshot.content_tree(selected)

    def test_change_to_earlier_file_while_reading_later_file_is_rejected(self):
        first, second = self.root / 'a', self.root / 'b'
        first.write_bytes(b'first')
        second.write_bytes(b'second')
        real_file = snapshot._file
        def change_earlier_file(parent, name, *args, **kwargs):
            result = real_file(parent, name, *args, **kwargs)
            if name == 'b':
                first.write_bytes(b'changed')
            return result
        with patch.object(snapshot, '_file', side_effect=change_earlier_file), \
                self.assertRaisesRegex(snapshot.SnapshotError, 'changed'):
            snapshot.content_tree(self.root)

    def test_special_file_is_pinned_but_never_opened_for_io(self):
        selected = self.root / 'fifo'
        os.mkfifo(selected)
        real_open = os.open
        flags = []
        def observe_open(path, mode, *args, **kwargs):
            if path == 'fifo':
                flags.append(mode)
            if isinstance(path, str) and path.startswith('/proc/self/fd/'):
                self.fail('special file was reopened for I/O')
            return real_open(path, mode, *args, **kwargs)
        with patch.object(snapshot.os, 'open', side_effect=observe_open), \
                self.assertRaises(snapshot.SnapshotError):
            snapshot.read_file(self.root, 'fifo')
        self.assertEqual([os.O_PATH | os.O_NOFOLLOW], flags)

    def test_native_output_is_bounded_before_json_admission_and_stderr_stays_private(self):
        environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
        def execute(script):
            return catalog.native_json([sys.executable, '-I', '-S', '-c', script], environment,
                timeout=5, output_limit=128, error='catalog-owned-scope-bootstrap-failed')
        self.assertEqual({'synthetic': True}, execute('print(\'{"synthetic":true}\')'))
        for script in ('import os; os.write(1,b"x"*129)',
                       'import os; os.write(2,b"PRIVATE-CANARY"*128)',
                       'print("[]")', 'print("not-json")'):
            with self.subTest(script=script), self.assertRaises(catalog.LifecycleFailure) as error:
                execute(script)
            self.assertEqual('catalog-owned-scope-bootstrap-failed', str(error.exception))


class NativeFailurePrivacyTest(unittest.TestCase):
    def test_cleanup_timeout_does_not_expose_selected_arguments(self):
        failure = subprocess.TimeoutExpired(['PRIVATE-SELECTED-EXECUTABLE'], 10,
                                            stderr=b'PRIVATE-CHILD-CANARY')
        with patch.object(catalog, 'bounded_run', side_effect=failure), \
                self.assertRaises(catalog.LifecycleFailure) as error:
            catalog.native_json(['PRIVATE-SELECTED-EXECUTABLE'], {}, timeout=1,
                                output_limit=128, error='catalog-owned-scope-bootstrap-failed')
        self.assertEqual('catalog-owned-scope-bootstrap-failed', str(error.exception))
        self.assertTrue(error.exception.__suppress_context__)


if __name__ == '__main__':
    unittest.main()
