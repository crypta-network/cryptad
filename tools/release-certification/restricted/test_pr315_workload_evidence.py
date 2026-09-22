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

    def test_stop_receipts_preserve_current_and_previous_epoch_with_fixed_projection(self):
        role = 'candidate-sender'
        authority = self.root / 'authority'
        record = json.loads((authority / (role + '.json')).read_text())
        record['previousStopGeneration'] = 'b' * 64
        (authority / (role + '.json')).write_text(json.dumps(record))
        for suffix, generation in (('-stop.json', 'c' * 64), ('-stop-' + 'b' * 64 + '.json', 'b' * 64)):
            (authority / (role + suffix)).write_text(json.dumps({
                'generation': generation, 'membership': 'only-stop-helper', 'helperPid': 123,
                'privateExtra': 'must-not-copy'}))
        result = evidence._capture(self.root, self.expected, True)
        receipts = result['stopReceipts'][role]
        self.assertEqual('c' * 64, receipts['current']['record']['generation'])
        self.assertEqual('b' * 64, receipts['previous']['record']['generation'])
        self.assertNotIn('must-not-copy', json.dumps(result))
        self.assertFalse(result['quiescenceIndependentlyEstablished'])
        record['previousStopGeneration'] = '../../arbitrary'
        (authority / (role + '.json')).write_text(json.dumps(record))
        self.assertNotIn('previous', evidence._capture(self.root, self.expected, True)['stopReceipts'][role])

    def test_no_read_without_literal_completed_cleanup(self):
        with patch.object(evidence.snapshot, 'read_file', side_effect=AssertionError('must not read')):
            for cleanup in (False, None, 1, 'true'):
                result = evidence._capture(self.root, self.expected, cleanup)
                self.assertEqual('not-captured-cleanup-unverified', result['sentinel']['status'])
                self.assertTrue(all(row == {'status': 'not-captured-cleanup-unverified'}
                                    for row in result['wrapperLogs'].values()))

    def test_fatal_sections_stop_at_nonhex_and_exclude_adjacent_private_sections(self):
        raw = (b'Instructions: (pc=0x123)\n0x123: 0f 0b 90\n'
               b'Registers: secret-registers\n0x456: 11 22\n'
               b'CPU: total 4 avx sse2\nCPU Features: avx2\n'
               b'Environment Variables: SECRET=value\n')
        result = evidence._fatal_sections(raw, float('inf'))
        self.assertEqual(b'Instructions:\n0x123: 0f 0b 90\n',
                         base64.b64decode(result['instructions']['contentBase64']))
        self.assertEqual(b'CPU: total 4 avx sse2\nCPU Features: avx2\n',
                         base64.b64decode(result['cpu']['contentBase64']))
        self.assertFalse(any(row['truncated'] for row in result.values()))

    def test_fatal_sections_have_independent_caps_and_explicit_missing(self):
        raw = b'Instructions:\n' + b'0x123: 90 90\n' * 300 + b'CPU: ' + b'x' * 2000 + b'\n'
        result = evidence._fatal_sections(raw, float('inf'))
        for name, limit in (('instructions', 2048), ('cpu', 1024)):
            self.assertEqual(limit, result[name]['sizeBytes'])
            self.assertTrue(result[name]['truncated'])
        missing = evidence._fatal_sections(b'Environment Variables: secret\n', float('inf'))
        self.assertTrue(all(row['status'] == 'not-found' and row['sizeBytes'] == 0
                            for row in missing.values()))

    def test_fatal_snapshot_selects_sections_beyond_retained_header(self):
        directory = self.fatal_directory()
        raw = b'H' * 5000 + b'\nInstructions: (pc=0x123)\n0x123: 0f 0b\n\nCPU: synthetic\n'
        (directory / 'hs_err_pid1.log').write_bytes(raw)
        result = evidence._capture(self.root, self.expected, True)
        row = result['fatalLogs']['candidate-sender']['files'][0]
        self.assertEqual(b'H' * 4096, base64.b64decode(row['headBase64']))
        self.assertIn(b'0f 0b', base64.b64decode(row['sections']['instructions']['contentBase64']))
        self.assertLessEqual(len(json.dumps(result, sort_keys=True, allow_nan=False).encode()),
                             evidence.MAX_OUTPUT)

    def test_fatal_sections_deadline_does_not_select_later_bytes(self):
        with patch.object(evidence.time, 'monotonic', return_value=2):
            result = evidence._fatal_sections(b'CPU: hidden\n', 1)
        self.assertTrue(all(row['status'] == 'capture-deadline' and row['sizeBytes'] == 0
                            for row in result.values()))

    def fatal_directory(self):
        directory = self.state / 'tmp'
        directory.mkdir(exist_ok=True)
        return directory

    def test_fatal_selection_is_fixed_bounded_and_retains_header(self):
        directory = self.fatal_directory()
        for name in ('hs_err_pid3.log', 'hs_err_pid1.log', 'hs_err_pid2.log'):
            (directory / name).write_bytes(b'H' * 5000 + b'TAIL')
        (directory / 'credentials').write_bytes(b'must-not-read')
        result = evidence._capture(self.root, self.expected, True)
        logs = result['fatalLogs']['candidate-sender']
        self.assertEqual('too-many-matching-files', logs['status'])
        self.assertEqual(3, logs['matchedFiles'])
        self.assertEqual(['hs_err_pid1.log', 'hs_err_pid2.log'],
                         [row['name'] for row in logs['files']])
        self.assertFalse(logs['locationProven'])
        for row in logs['files']:
            self.assertEqual(b'H' * 4096, base64.b64decode(row['headBase64']))
            self.assertEqual(5004, row['sizeBytes'])
            self.assertTrue(row['truncated'])
        self.assertNotIn('must-not-read', json.dumps(result))

    def test_fatal_empty_and_flooded_directory_are_distinct(self):
        directory = self.fatal_directory()
        self.assertEqual('none', evidence._fatal_logs(self.root, 'candidate-sender', float('inf'))['status'])
        for number in range(65):
            (directory / str(number)).touch()
        with patch.object(evidence.snapshot, 'read_file', side_effect=AssertionError('no reads')):
            self.assertEqual('too-many-directory-entries',
                evidence._fatal_logs(self.root, 'candidate-sender', float('inf'))['status'])

    def test_fatal_special_files_and_oversize_are_rejected(self):
        directory = self.fatal_directory()
        path = directory / 'hs_err_pid1.log'
        for kind in ('symlink', 'fifo', 'hardlink', 'oversize'):
            with self.subTest(kind=kind):
                if kind == 'symlink':
                    path.symlink_to(self.path)
                elif kind == 'fifo':
                    os.mkfifo(path)
                elif kind == 'hardlink':
                    os.link(self.path, path)
                else:
                    with path.open('wb') as stream:
                        stream.truncate(evidence.MAX_WRAPPER_LOG + 1)
                row = evidence._fatal_logs(self.root, 'candidate-sender', float('inf'))['files'][0]
                self.assertEqual('unavailable-or-unsafe', row['status'])
                path.unlink()
        directory.rmdir()
        directory.symlink_to(self.root, target_is_directory=True)
        self.assertEqual('unavailable-or-unsafe',
            evidence._fatal_logs(self.root, 'candidate-sender', float('inf'))['status'])

    def test_fatal_reader_uses_remaining_deadline_and_rejects_directory_replacement(self):
        directory = self.fatal_directory()
        (directory / 'hs_err_pid1.log').write_bytes(b'header')
        with patch.object(evidence.time, 'monotonic', return_value=9.75), \
                patch.object(evidence.snapshot, 'read_file', return_value=b'header') as reader:
            result = evidence._fatal_logs(self.root, 'candidate-sender', 10)
        self.assertEqual('captured', result['files'][0]['status'])
        self.assertEqual(.25, reader.call_args.kwargs['timeout'])
        self.assertEqual(2 * 1024 * 1024, reader.call_args.kwargs['maximum'])
        original = evidence.snapshot.read_file
        def replace(*args, **kwargs):
            raw = original(*args, **kwargs)
            directory.rename(self.state / 'replaced-tmp')
            directory.mkdir()
            return raw
        with patch.object(evidence.snapshot, 'read_file', side_effect=replace):
            result = evidence._fatal_logs(self.root, 'candidate-sender', float('inf'))
        self.assertEqual({'status': 'unavailable-or-unsafe'}, result)

    def test_fatal_deadline_and_output_budget_preserve_higher_priority_records(self):
        directory = self.fatal_directory()
        (directory / 'hs_err_pid1.log').write_bytes(b'H' * 4096)
        with patch.object(evidence.snapshot, 'read_file', side_effect=AssertionError('no reads')):
            self.assertEqual('capture-deadline',
                evidence._fatal_logs(self.root, 'candidate-sender', 0)['status'])
        with patch.object(evidence, 'MAX_OUTPUT', 4096):
            result = evidence._capture(self.root, self.expected, True)
        self.assertEqual('not-captured-output-budget', result['fatalLogs']['candidate-sender']['status'])
        self.assertEqual('matched', result['sentinel']['status'])
        with patch.object(evidence.snapshot, '_directory', side_effect=AssertionError('no enumeration')):
            result = evidence._capture(self.root, self.expected, False)
        self.assertTrue(all(row['status'] == 'not-captured-cleanup-unverified'
                            for row in result['fatalLogs'].values()))

    def test_wrapper_excerpt_finds_buried_error_without_command_lines(self):
        command = b'INFO | wrapper | 2026 | Command[1] : private-command-value\n'
        error = b'ERROR | wrapper | 2026 | Bootstrap failed\n'
        jvm = b'INFO | jvm 4 | 2026 | private-jvm-output\n'
        raw = command * 1000 + error + jvm + command * 1000
        self.wrapper().write_bytes(raw)
        with patch.object(evidence.snapshot, 'read_file', wraps=evidence.snapshot.read_file) as reader:
            log = evidence._wrapper_log(self.root, 'candidate-sender', float('inf'))
        self.assertEqual(1, reader.call_count)
        excerpt = log['excerpt']
        self.assertEqual(error + jvm, base64.b64decode(excerpt['contentBase64']))
        self.assertIn('private-diagnostic-not-acceptance', excerpt['classification'])
        self.assertNotIn(error, base64.b64decode(log['tailBase64']))
        self.assertFalse(excerpt['truncated'])

    def test_wrapper_excerpt_yields_output_budget_to_existing_tail(self):
        self.wrapper().write_bytes(b'ERROR | wrapper | failure ' + b'x' * 10000)
        with patch.object(evidence, 'MAX_OUTPUT', 10000):
            result = evidence._capture(self.root, self.expected, True)
        log = result['wrapperLogs']['candidate-sender']
        self.assertEqual('captured', log['status'])
        self.assertEqual(4096, log['tailBytes'])
        self.assertEqual({'status': 'not-captured-output-budget'}, log['excerpt'])
        self.assertEqual('matched', result['sentinel']['status'])
        self.assertLess(len(json.dumps(result)), 10000)

    def test_wrapper_excerpt_bounds_adversarial_text_and_deadline(self):
        line = b'FATAL | wrapper | spoofed-severity-is-not-proof ' + b'x' * 20000
        excerpt = evidence._wrapper_excerpt(line, float('inf'))
        self.assertEqual(line[:8192], base64.b64decode(excerpt['contentBase64']))
        self.assertEqual(8192, excerpt['sizeBytes'])
        self.assertTrue(excerpt['truncated'])
        excluded = (b'ERROR text | wrapper | invalid\n'
                    b'INFO | jvm evil | invalid\n'
                    b'WARN | wrapper | Command[1] : hidden\n')
        self.assertEqual('', evidence._wrapper_excerpt(excluded, float('inf'))['contentBase64'])
        with patch.object(evidence.time, 'monotonic', side_effect=[0, 2]):
            excerpt = evidence._wrapper_excerpt(b'WARN | wrapper | first\nINFO | jvm 1 | second\n', 1)
        self.assertEqual('capture-deadline', excerpt['status'])
        self.assertEqual(b'WARN | wrapper | first\n', base64.b64decode(excerpt['contentBase64']))
        self.assertTrue(excerpt['truncated'])

    def observer(self):
        root = self.root / 'observer'
        root.mkdir(exist_ok=True)
        return root

    def test_observer_logs_capture_exact_leaves_and_tails_before_candidate_logs(self):
        observer = self.observer()
        raw = b'private FCP transcript\n' * 200
        for role in evidence.ROLES:
            (observer / ('fcp-' + role + '.log')).write_bytes(raw)
        (observer / 'not-selected.log').write_text('must-not-copy')
        (observer / 'nested').mkdir()
        (observer / 'nested/fcp-previous.log').write_text('must-not-copy')
        reads = []
        original = evidence.snapshot.read_file
        def read(root, name, **kwargs):
            reads.append((root, name))
            return original(root, name, **kwargs)
        with patch.object(evidence.snapshot, 'read_file', side_effect=read):
            result = evidence._capture(self.root, self.expected, True, observer_root=observer)
        self.assertEqual(['fcp-' + role + '.log' for role in evidence.ROLES],
                         [name for root, name in reads if root == observer])
        names = [name for _root, name in reads]
        self.assertLess(names.index(evidence.SENTINEL), names.index('fcp-candidate-sender.log'))
        self.assertLess(names.index('fcp-relay-no-apps.log'), names.index('wrapper.log'))
        for row in result['observerFcpLogs'].values():
            self.assertEqual('captured', row['status'])
            self.assertEqual('observer-origin-private-diagnostic-not-acceptance', row['classification'])
            self.assertEqual(raw[-2048:], base64.b64decode(row['tailBase64']))
            self.assertEqual(len(raw), row['sizeBytes'])
            self.assertEqual(2048, row['tailBytes'])
            self.assertTrue(row['truncated'])
        self.assertLessEqual(len(json.dumps(result, sort_keys=True, allow_nan=False).encode()), evidence.MAX_OUTPUT)

    def test_observer_root_omission_and_nonliteral_cleanup_never_read_transcripts(self):
        with patch.object(evidence, '_observer_fcp_log') as read:
            result = evidence._capture(self.root, self.expected, True)
            self.assertEqual({}, result['observerFcpLogs'])
            read.assert_not_called()
        for cleanup in (False, None, 1, 'true'):
            with self.subTest(cleanup=cleanup), patch.object(evidence.snapshot, 'read_file') as read:
                result = evidence._capture(self.root, self.expected, cleanup, observer_root=self.observer())
                self.assertTrue(all(row == {'status': 'not-captured-cleanup-unverified'}
                                    for row in result['observerFcpLogs'].values()))
                read.assert_not_called()

    def test_observer_log_missing_special_hardlinked_and_oversized_files_are_unavailable(self):
        observer = self.observer()
        path = observer / 'fcp-candidate-sender.log'
        other = observer / 'other'
        other.write_bytes(b'private')
        for kind in ('missing', 'symlink', 'fifo', 'hardlink', 'oversized'):
            with self.subTest(kind=kind):
                if kind == 'symlink':
                    path.symlink_to(other)
                elif kind == 'fifo':
                    os.mkfifo(path)
                elif kind == 'hardlink':
                    os.link(other, path)
                elif kind == 'oversized':
                    with path.open('wb') as stream:
                        stream.truncate(evidence.MAX_OBSERVER_FCP_LOG + 1)
                self.assertEqual({'status': 'unavailable-or-unsafe'},
                    evidence._observer_fcp_log(observer, 'candidate-sender', float('inf')))
                if kind != 'missing':
                    path.unlink()

    def test_observer_transcript_replacement_or_growth_during_read_is_not_exported(self):
        observer = self.observer()
        path = observer / 'fcp-candidate-sender.log'
        original = os.read
        for attack in ('replacement', 'growth'):
            with self.subTest(attack=attack):
                path.write_bytes(b'fixed FCP output')
                changed = []
                def mutate(fd, maximum):
                    value = original(fd, maximum)
                    if value == b'fixed FCP output' and not changed:
                        changed.append(True)
                        if attack == 'replacement':
                            replacement = observer / 'replacement'
                            replacement.write_bytes(value)
                            os.replace(replacement, path)
                        else:
                            with path.open('ab') as stream:
                                stream.write(b'growth')
                    return value
                with patch.object(evidence.snapshot.os, 'read', side_effect=mutate):
                    result = evidence._observer_fcp_log(observer, 'candidate-sender', float('inf'))
                self.assertTrue(changed)
                self.assertEqual({'status': 'unavailable-or-unsafe'}, result)

    def test_observer_transcript_read_shares_global_deadline_and_fixed_input_cap(self):
        observer = self.observer()
        with patch.object(evidence.time, 'monotonic', return_value=10), \
                patch.object(evidence.snapshot, 'read_file', return_value=b'x') as read:
            self.assertEqual({'status': 'capture-deadline'},
                             evidence._observer_fcp_log(observer, 'previous', 9))
            read.assert_not_called()
            row = evidence._observer_fcp_log(observer, 'previous', 10.25)
            read.assert_called_once_with(observer, 'fcp-previous.log', maximum=16 * 1024 * 1024, timeout=.25)
            self.assertEqual(b'x', base64.b64decode(row['tailBase64']))
            self.assertFalse(row['truncated'])
            evidence._observer_fcp_log(observer, 'previous', 20)
            self.assertEqual(2, read.call_args.kwargs['timeout'])

    def test_observer_output_budget_keeps_higher_priority_controller_and_sentinel(self):
        observer = self.observer()
        for role in evidence.ROLES:
            (observer / ('fcp-' + role + '.log')).write_bytes(b'x' * 4096)
        baseline = evidence._capture(self.root, self.expected, True)
        cap = len(json.dumps(baseline, sort_keys=True, allow_nan=False).encode()) + 1500
        with patch.object(evidence, 'MAX_OUTPUT', cap):
            result = evidence._capture(self.root, self.expected, True, observer_root=observer)
        self.assertEqual('matched', result['sentinel']['status'])
        self.assertEqual('captured', result['controllerRecords']['campaign']['status'])
        self.assertTrue(all(row == {'status': 'not-captured-output-budget'}
                            for row in result['observerFcpLogs'].values()))
        self.assertLessEqual(len(json.dumps(result, sort_keys=True, allow_nan=False).encode()), cap)

    def test_public_observer_selection_only_accepts_direct_experiment_child(self):
        allowed = evidence.OBSERVER_EXPERIMENTS / 'fixed-experiment'
        with patch.object(evidence, '_installed'), patch.object(evidence, '_capture', return_value={}) as capture:
            evidence.capture(object(), None, True, observer_root=allowed)
            capture.assert_called_once_with(evidence.ROOT, None, True, observer_root=allowed)
            capture.reset_mock()
            for root in (Path('/tmp/other'), evidence.OBSERVER_EXPERIMENTS,
                         evidence.OBSERVER_EXPERIMENTS / '..', allowed / 'nested',
                         Path('relative/experiment')):
                with self.subTest(root=root), self.assertRaisesRegex(ValueError, 'observer-root-invalid'):
                    evidence.capture(object(), None, True, observer_root=root)
            capture.assert_not_called()

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
