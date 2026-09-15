"""Deterministic local races against real files; these do not establish VM acceptance."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import restricted_native as native


@unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'O_PATH'),
                     'the installed descriptor collector requires Linux O_PATH')
class NativeOutputRaceTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='native-output-race-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.parent = self.root / 'output'
        self.parent.mkdir()
        self.source = self.parent / 'projection.json'
        self.payload = b'{"subject":"original"}\n'
        self.source.write_bytes(self.payload)

    def mutate_after_first_read(self, mutation, *, chunk_size=None):
        """Read the actual pinned descriptor, then interleave exactly one filesystem mutation."""
        original = os.read
        chunks = []
        mutated = False
        def read(descriptor, maximum):
            nonlocal mutated
            raw = original(descriptor, min(maximum, chunk_size) if chunk_size else maximum)
            chunks.append(raw)
            if not mutated:
                mutated = True
                mutation()
            return raw
        return patch.object(native.os, 'read', side_effect=read), chunks

    def test_same_size_rewrite_is_rejected_after_original_bytes_were_read(self):
        replacement = b'{"subject":"replaced"}\n'
        self.assertEqual(len(self.payload), len(replacement))
        before = self.source.stat()
        def rewrite():
            self.source.write_bytes(replacement)
            # Force an observable timestamp change without depending on clock resolution/sleeps.
            os.utime(self.source, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
        interception, chunks = self.mutate_after_first_read(rewrite)
        with interception, self.assertRaises(native.NativeBoundaryError):
            native._read_output(self.source, 32768)
        self.assertEqual(self.payload, b''.join(chunks))
        self.assertEqual(before.st_size, self.source.stat().st_size)
        self.assertEqual(replacement, self.source.read_bytes())

    def test_same_bytes_and_timestamp_on_replacement_inode_are_still_rejected(self):
        before = self.source.stat()
        replacement = self.parent / 'replacement'
        replacement.write_bytes(self.payload)
        os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertNotEqual(before.st_ino, replacement.stat().st_ino)
        interception, chunks = self.mutate_after_first_read(lambda: os.replace(replacement, self.source))
        with interception, self.assertRaises(native.NativeBoundaryError):
            native._read_output(self.source, 32768)
        self.assertEqual(self.payload, b''.join(chunks))
        self.assertEqual(self.payload, self.source.read_bytes())
        self.assertEqual(before.st_mtime_ns, self.source.stat().st_mtime_ns)
        self.assertNotEqual(before.st_ino, self.source.stat().st_ino)

    def test_ancestor_replaced_by_symlink_to_same_file_is_rejected(self):
        before = self.source.stat()
        relocated = self.root / 'relocated-output'
        def substitute_ancestor():
            self.parent.rename(relocated)
            self.parent.symlink_to(relocated, target_is_directory=True)
        interception, chunks = self.mutate_after_first_read(substitute_ancestor)
        with interception, self.assertRaises(native.NativeBoundaryError):
            native._read_output(self.source, 32768)
        # The leaf object and bytes stayed identical: the ancestor boundary itself changed.
        self.assertEqual(before.st_ino, self.source.stat().st_ino)
        self.assertEqual(self.payload, b''.join(chunks))
        self.assertTrue(self.parent.is_symlink())

    def test_symlink_substitution_does_not_read_its_target_or_return_pinned_old_bytes(self):
        private = self.root / 'private-selection'
        private.write_bytes(b'synthetic-private-target-canary')
        def replace_with_link():
            self.source.unlink()
            self.source.symlink_to(private)
        interception, chunks = self.mutate_after_first_read(replace_with_link)
        with interception, self.assertRaises(native.NativeBoundaryError):
            native._read_output(self.source, 32768)
        self.assertEqual(self.payload, b''.join(chunks))
        self.assertNotIn(b'synthetic-private-target-canary', b''.join(chunks))
        self.assertEqual(b'synthetic-private-target-canary', private.read_bytes())

    def test_hardlink_added_during_collection_invalidates_the_pinned_output(self):
        alias = self.root / 'outside-output-roster'
        interception, chunks = self.mutate_after_first_read(lambda: os.link(self.source, alias))
        with interception, self.assertRaises(native.NativeBoundaryError):
            native._read_output(self.source, 32768)
        self.assertEqual(2, self.source.stat().st_nlink)
        self.assertEqual(self.source.stat().st_ino, alias.stat().st_ino)
        self.assertEqual(self.payload, b''.join(chunks))

    def test_preexisting_hardlink_is_rejected_without_reading_file_content(self):
        os.link(self.source, self.root / 'alias')
        with patch.object(native.os, 'read') as read, self.assertRaises(native.NativeBoundaryError):
            native._read_output(self.source, 32768)
        read.assert_not_called()

    def test_actual_truncation_after_a_partial_read_is_rejected(self):
        interception, chunks = self.mutate_after_first_read(lambda: os.truncate(self.source, 4), chunk_size=4)
        with interception, self.assertRaises(native.NativeBoundaryError):
            native._read_output(self.source, 32768)
        self.assertEqual(self.payload[:4], b''.join(chunks))
        self.assertEqual(4, self.source.stat().st_size)
        self.assertEqual(b'', chunks[-1])

    def test_short_reads_of_an_unchanged_file_are_collected_completely(self):
        original = os.read
        requests = []
        def read(descriptor, maximum):
            requests.append(maximum)
            return original(descriptor, min(maximum, 3))
        with patch.object(native.os, 'read', side_effect=read):
            actual = native._read_output(self.source, 32768)
        self.assertEqual(self.payload, actual)
        self.assertGreater(len(requests), 2)

    def test_growth_during_collection_is_rejected_with_bounded_reads(self):
        maximum = len(self.payload) + 4
        def grow():
            with self.source.open('ab') as stream:
                stream.write(b'x' * 65536)
        interception, chunks = self.mutate_after_first_read(grow)
        with interception, self.assertRaises(native.NativeBoundaryError):
            native._read_output(self.source, maximum)
        self.assertGreater(self.source.stat().st_size, maximum)
        self.assertLessEqual(sum(map(len, chunks)), maximum + 1)


if __name__ == '__main__':
    unittest.main()
