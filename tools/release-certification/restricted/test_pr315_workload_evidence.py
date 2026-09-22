"""Real local descriptor-reader tests; these are not installed acceptance observations."""
import base64
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
        self.assertEqual(6, len(result['controllerRecords']))
        self.assertNotIn('must-not-copy', json.dumps(result))
        self.assertLess(len(json.dumps(result)), evidence.MAX_OUTPUT)

    def test_partial_preparation_captures_authority_without_inventing_a_sentinel(self):
        self.path.unlink()
        (self.root / 'authority/network.json').write_text(json.dumps({
            'version': 1, 'phase': 'retained', 'pending': None,
            'namespaces': {'private-topology-not-exported': [1, 2]}}))
        result = evidence._capture(self.root, None, True)
        self.assertEqual({'status': 'not-prepared'}, result['sentinel'])
        self.assertEqual('captured', result['controllerRecords']['campaign']['status'])
        self.assertEqual({'version': 1, 'phase': 'retained', 'pending': None},
                         result['controllerRecords']['network']['record'])
        self.assertFalse(result['quiescenceIndependentlyEstablished'])
        self.assertGreaterEqual(result['finishedMonotonicNs'], result['startedMonotonicNs'])
        self.assertNotIn('private-topology-not-exported', json.dumps(result))

    def test_no_read_without_literal_completed_cleanup(self):
        with patch.object(evidence.snapshot, 'read_file', side_effect=AssertionError('must not read')):
            for cleanup in (False, None, 1, 'true'):
                result = evidence._capture(self.root, self.expected, cleanup)
                self.assertEqual('not-captured-cleanup-unverified', result['sentinel']['status'])
                self.assertTrue(all(row == {'status': 'not-captured-cleanup-unverified'}
                                    for row in result['wrapperLogs'].values()))

    def wrapper(self, role='candidate-sender'):
        logs = self.root / 'state' / role / 'logs'
        logs.mkdir(parents=True, exist_ok=True)
        return logs / 'wrapper.log'

    def test_wrapper_logs_capture_only_fixed_private_tail_after_authority_and_sentinel(self):
        raw = b'not-in-retained-tail' + bytes(range(256)) * 32
        for role in evidence.ROLES:
            self.wrapper(role).write_bytes(raw)
        original = evidence.snapshot.read_file
        names = []
        def read(root, name, **kwargs):
            names.append(name)
            return original(root, name, **kwargs)
        with patch.object(evidence.snapshot, 'read_file', side_effect=read):
            result = evidence._capture(self.root, self.expected, True)
        self.assertEqual([*(['wrapper.log'] * 4)], names[-4:])
        self.assertLess(names.index(evidence.SENTINEL), names.index('wrapper.log'))
        for log in result['wrapperLogs'].values():
            self.assertEqual('candidate-origin-private-diagnostic-not-acceptance', log['classification'])
            self.assertEqual(len(raw), log['sizeBytes'])
            self.assertEqual(4096, log['tailBytes'])
            self.assertTrue(log['truncated'])
            self.assertEqual(raw[-4096:], base64.b64decode(log['tailBase64']))
        self.assertEqual(64 * 1024, evidence.MAX_OUTPUT)
        self.assertLessEqual(len(json.dumps(result).encode()), evidence.MAX_OUTPUT)

    def test_short_and_missing_wrapper_logs_are_reported_without_invented_bytes(self):
        self.wrapper().write_bytes(b'daemon startup failure\n')
        result = evidence._capture(self.root, self.expected, True)
        log = result['wrapperLogs']['candidate-sender']
        self.assertFalse(log['truncated'])
        self.assertEqual(log['sizeBytes'], log['tailBytes'])
        self.assertEqual({'status': 'unavailable-or-unsafe'}, result['wrapperLogs']['previous'])

    def test_wrapper_log_special_hardlinked_and_oversized_files_are_rejected(self):
        path = self.wrapper()
        other = path.with_name('unselected-file')
        for kind in ('symlink', 'fifo', 'hardlink', 'oversized'):
            with self.subTest(kind=kind):
                path.unlink(missing_ok=True)
                other.unlink(missing_ok=True)
                if kind == 'symlink':
                    other.write_bytes(b'private')
                    path.symlink_to(other)
                elif kind == 'fifo':
                    os.mkfifo(path)
                elif kind == 'hardlink':
                    other.write_bytes(b'private')
                    os.link(other, path)
                else:
                    with path.open('wb') as stream:
                        stream.truncate(evidence.MAX_WRAPPER_LOG + 1)
                result = evidence._capture(self.root, self.expected, True)
                self.assertEqual({'status': 'unavailable-or-unsafe'}, result['wrapperLogs']['candidate-sender'])
                self.assertEqual('matched', result['sentinel']['status'])

    def test_wrapper_replacement_during_descriptor_read_is_not_exported(self):
        path = self.wrapper()
        path.write_bytes(b'fixed wrapper output')
        original = os.read
        replaced = False
        def replace(fd, maximum):
            nonlocal replaced
            value = original(fd, maximum)
            if value == b'fixed wrapper output' and not replaced:
                replacement = path.with_name('replacement')
                replacement.write_bytes(value)
                os.replace(replacement, path)
                replaced = True
            return value
        with patch.object(evidence.snapshot.os, 'read', side_effect=replace):
            result = evidence._capture(self.root, self.expected, True)
        self.assertTrue(replaced)
        self.assertEqual({'status': 'unavailable-or-unsafe'}, result['wrapperLogs']['candidate-sender'])

    def test_remaining_global_deadline_prevents_additional_log_reads(self):
        with patch.object(evidence.time, 'monotonic', return_value=10), \
                patch.object(evidence.snapshot, 'read_file') as read:
            self.assertEqual({'status': 'capture-deadline'}, evidence._wrapper_log(self.root, 'previous', 9))
            read.assert_not_called()
            read.return_value = b'x'
            evidence._wrapper_log(self.root, 'previous', 10.25)
            self.assertEqual(.25, read.call_args.kwargs['timeout'])
            self.assertEqual(2 * 1024 * 1024, read.call_args.kwargs['maximum'])

    def test_output_budget_omits_logs_without_discarding_prior_observations(self):
        self.wrapper().write_bytes(b'x' * 8192)
        with patch.object(evidence, 'MAX_OUTPUT', 4096):
            result = evidence._capture(self.root, self.expected, True)
        self.assertEqual('matched', result['sentinel']['status'])
        self.assertEqual('captured', result['controllerRecords']['campaign']['status'])
        self.assertEqual({'status': 'not-captured-output-budget'}, result['wrapperLogs']['candidate-sender'])
        self.assertLess(len(json.dumps(result)), 4096)

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
