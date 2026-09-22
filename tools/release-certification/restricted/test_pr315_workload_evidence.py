"""Real local descriptor-reader tests; these are not installed acceptance observations."""
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'interop'))
import pr315_workload_evidence as evidence


class VolatileEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'authority').mkdir()
        self.state = self.root / 'state/candidate-sender'
        self.state.mkdir(parents=True)
        self.raw = b'0123456789abcdef0123456789abcdef'
        self.assertEqual(32, len(self.raw))
        self.expected = 'sha256:' + hashlib.sha256(self.raw).hexdigest()
        self.path = self.state / evidence.SENTINEL
        self.path.write_bytes(self.raw)
        (self.root / 'campaign.json').write_text(json.dumps({'state': 'prepared',
            'deadlineMonotonicNs': 123, 'handles': {'candidate-sender': 'must-not-copy'}}))
        for role in evidence.ROLES:
            (self.root / 'authority' / (role + '.json')).write_text(json.dumps({
                'state': 'quiescent', 'managerInvocation': 'a' * 32, 'cgroupIdentity': [1, 2],
                'handle': 'must-not-copy'}))

    def test_capture_matches_exact_subject_and_filters_authority(self):
        result = evidence._capture(self.root, self.expected, True)
        self.assertEqual('matched', result['sentinel']['status'])
        self.assertFalse(result['quiescenceIndependentlyEstablished'])
        self.assertEqual(5, len(result['controllerRecords']))
        self.assertNotIn('must-not-copy', json.dumps(result))
        self.assertLess(len(json.dumps(result)), evidence.MAX_OUTPUT)

    def test_no_read_without_literal_completed_cleanup(self):
        with patch.object(evidence.snapshot, 'read_file', side_effect=AssertionError('must not read')):
            for cleanup in (False, None, 1, 'true'):
                result = evidence._capture(self.root, self.expected, cleanup)
                self.assertEqual('not-captured-cleanup-unverified', result['sentinel']['status'])

    def test_changed_sentinel_is_not_matched(self):
        self.path.write_bytes(b'x' * 32)
        self.assertEqual('changed', evidence._capture(self.root, self.expected, True)['sentinel']['status'])

    def test_missing_sentinel_retains_controller_diagnostics(self):
        self.path.unlink()
        result = evidence._capture(self.root, self.expected, True)
        self.assertEqual('unavailable-or-unsafe', result['sentinel']['status'])
        self.assertEqual('captured', result['controllerRecords']['campaign']['status'])

    def test_special_and_multiply_linked_sentinel_rejected_without_blocking(self):
        for kind in ('symlink', 'fifo', 'hardlink', 'socket', 'oversized'):
            with self.subTest(kind=kind):
                self.path.unlink(missing_ok=True)
                target = self.state / 'other'
                target.unlink(missing_ok=True)
                connection = None
                if kind == 'symlink':
                    target.write_bytes(self.raw)
                    self.path.symlink_to(target)
                elif kind == 'fifo':
                    os.mkfifo(self.path)
                elif kind == 'hardlink':
                    target.write_bytes(self.raw)
                    os.link(target, self.path)
                elif kind == 'socket':
                    connection = socket.socket(socket.AF_UNIX)
                    connection.bind(str(self.path))
                else:
                    self.path.write_bytes(b'x' * 33)
                try:
                    self.assertEqual('unavailable-or-unsafe',
                        evidence._capture(self.root, self.expected, True)['sentinel']['status'])
                finally:
                    if connection is not None:
                        connection.close()

    def test_unsafe_authority_does_not_prevent_safe_sentinel_capture(self):
        path = self.root / 'campaign.json'
        path.unlink()
        os.mkfifo(path)
        result = evidence._capture(self.root, self.expected, True)
        self.assertEqual('unavailable-or-unsafe', result['controllerRecords']['campaign']['status'])
        self.assertEqual('matched', result['sentinel']['status'])

    def test_fixed_leaf_creation_is_exclusive(self):
        with evidence.snapshot._directory(self.state) as parent:
            with self.assertRaises(FileExistsError):
                evidence._create(parent, b'x' * 32)
        self.assertEqual(self.raw, self.path.read_bytes())

    def test_capture_does_not_treat_missing_records_as_quiescence(self):
        for path in (self.root / 'authority').iterdir():
            path.unlink()
        result = evidence._capture(self.root, self.expected, True)
        self.assertFalse(result['quiescenceIndependentlyEstablished'])
        self.assertTrue(all(result['controllerRecords'][role]['status'] == 'unavailable-or-unsafe'
                            for role in evidence.ROLES))

    def test_same_bytes_replaced_during_read_are_rejected(self):
        original = os.read
        replaced = False
        def replacing_read(fd, maximum):
            nonlocal replaced
            raw = original(fd, maximum)
            if raw == self.raw and not replaced:
                replacement = self.state / 'replacement'
                replacement.write_bytes(self.raw)
                os.replace(replacement, self.path)
                replaced = True
            return raw
        with patch.object(evidence.snapshot.os, 'read', side_effect=replacing_read):
            result = evidence._capture(self.root, self.expected, True)
        self.assertTrue(replaced)
        self.assertEqual('unavailable-or-unsafe', result['sentinel']['status'])

    def test_parent_symlink_does_not_export_sentinel(self):
        original = self.root / 'state/original'
        self.state.rename(original)
        self.state.symlink_to(original, target_is_directory=True)
        result = evidence._capture(self.root, self.expected, True)
        self.assertEqual('unavailable-or-unsafe', result['sentinel']['status'])


if __name__ == '__main__':
    unittest.main()
