"""Local fixed actor checks; no unit result grants installed workload acceptance."""
import http.server
import json
import os
import stat
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'interop'))
import pr315_role_probe as probe
import runtime_snapshot as snapshot


class RoleProbeTest(unittest.TestCase):
    def test_role_boundary_mode_runs_only_its_five_fixed_operations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready = root / 'ready.json'
            trigger = root / 'trigger.json'
            result = root / 'result.json'
            trigger.write_text(json.dumps({'caseId': 'role-boundary', 'nonce': 'a' * 64}))
            fixed = {'sibling-data', 'package-expectation', 'cgroup-migration'}

            def access(case_id, *_args):
                self.assertIn(case_id, fixed)
                return {'operation': case_id}

            with patch.object(probe, 'ROLE_BOUNDARY_READY', ready), \
                    patch.object(probe, 'ROLE_BOUNDARY_TRIGGER', trigger), \
                    patch.object(probe, 'ROLE_BOUNDARY_OUTPUT', result), \
                    patch.object(probe.sys, 'argv', ['probe.py', 'a' * 64,
                                                      'role-boundary']), \
                    patch.object(probe.sys, 'flags', SimpleNamespace(isolated=1,
                                                                       no_site=1)), \
                    patch.object(probe, 'attempt_read', return_value={
                        'caseId': 'observer-private-read'}), \
                    patch.object(probe, 'attempt_write', return_value={
                        'operation': 'observer-private-write'}), \
                    patch.object(probe, 'attempt_fixed_access', side_effect=access) as operations, \
                    patch.object(probe, 'fixed_false_claims') as claims, \
                    patch.object(probe, 'publish_network_result') as network, \
                    patch.object(probe.time, 'sleep', side_effect=StopIteration):
                with self.assertRaises(StopIteration):
                    probe.main()
            self.assertTrue(ready.exists())
            record = json.loads(result.read_text())
            self.assertEqual({'caseId', 'writeAttempt', 'siblingRead',
                              'packageWrite', 'cgroupMigration'}, set(record))
            self.assertEqual(3, operations.call_count)
            claims.assert_not_called()
            network.assert_not_called()

    def test_authority_mode_emits_only_fixed_claims_resolver_and_origin_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready = root / 'ready.json'
            trigger = root / 'trigger.json'
            result = root / 'result.json'
            trigger.write_text(json.dumps({'caseId': 'authority', 'nonce': 'a' * 64}))
            claims = ({'claimedHostPid': 1}, {'claimedTasksCurrent': 0})
            with patch.object(probe, 'AUTHORITY_READY', ready), \
                    patch.object(probe, 'AUTHORITY_TRIGGER', trigger), \
                    patch.object(probe, 'AUTHORITY_OUTPUT', result), \
                    patch.object(probe.sys, 'argv', ['probe.py', 'a' * 64,
                                                      'authority']), \
                    patch.object(probe.sys, 'flags', SimpleNamespace(isolated=1,
                                                                       no_site=1)), \
                    patch.object(probe, 'fixed_false_claims', return_value=claims), \
                    patch.object(probe, 'attempt_fixed_access', return_value={
                        'operation': 'resolver-authority'}) as access, \
                    patch.object(probe, 'attempt_hostile_origin', return_value={
                        'caseId': 'hostile-app-origin'}) as hostile, \
                    patch.object(probe, 'attempt_read') as read, \
                    patch.object(probe, 'publish_network_result') as network, \
                    patch.object(probe.time, 'sleep', side_effect=StopIteration):
                with self.assertRaises(StopIteration):
                    probe.main()
            record = json.loads(result.read_text())
            self.assertEqual({'schemaVersion', 'kind', 'caseId', 'nonce', 'pid',
                              'uid', 'gid', 'startedMonotonicNs',
                              'finishedMonotonicNs', 'identityClaim',
                              'counterClaim', 'resolverRead', 'hostileOrigin'}, set(record))
            access.assert_called_once_with('resolver-authority', probe.RESOLVER_TARGET)
            hostile.assert_called_once_with('a' * 64)
            read.assert_not_called()
            network.assert_not_called()

    def test_hostile_origin_uses_valid_session_without_emitting_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / 'hostile-input.json'
            token = 'private-browser-session-token'
            input_path.write_text(json.dumps({'caseId': 'hostile-app-origin',
                'nonce': 'a' * 64, 'session': token,
                'expectedOrigin': 'http://127.0.0.1:12345'}))
            input_path.chmod(0o600)
            origins = []

            class Connection:
                def request(self, method, path, headers):
                    self.origin = headers['Origin']
                    origins.append(self.origin)
                    self_headers = headers
                    if method != 'GET' or path != probe.HOSTILE_ORIGIN_ENDPOINT \
                            or self_headers['X-Crypta-App-Session'] != token:
                        raise AssertionError('unexpected fixed request')

                def getresponse(self):
                    hostile = self.origin == probe.HOSTILE_ORIGIN
                    body = (b'{"error":{"code":"origin_mismatch"}}' if hostile
                            else b'{"status":{"appId":"mail-prototype",'
                                 b'"storeAvailable":true}}')
                    return SimpleNamespace(status=403 if hostile else 200,
                                           read=lambda limit: body)

                def close(self):
                    pass

            with patch.object(probe, 'HOSTILE_ORIGIN_INPUT', input_path), \
                    patch.object(probe.http.client, 'HTTPConnection', return_value=Connection()):
                result = probe.attempt_hostile_origin('a' * 64)
            self.assertEqual(['http://127.0.0.1:12345', probe.HOSTILE_ORIGIN,
                              'http://127.0.0.1:12345'], origins)
            self.assertEqual((200, 403, 200), tuple(result[key]['status'] for key in
                ('before', 'attack', 'after')))
            self.assertEqual('origin_mismatch', result['attack']['errorCode'])
            self.assertNotIn(token, json.dumps(result))

    def test_hostile_origin_emits_real_good_bad_good_http_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / 'hostile-input.json'
            token = 'private-browser-session-token'
            input_path.write_text(json.dumps({'caseId': 'hostile-app-origin',
                'nonce': 'a' * 64, 'session': token,
                'expectedOrigin': 'http://127.0.0.1:12345'}))
            input_path.chmod(0o600)
            requests = []

            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    requests.append((self.path, self.headers.get('Origin'),
                                     self.headers.get('X-Crypta-App-Session')))
                    hostile = self.headers.get('Origin') == probe.HOSTILE_ORIGIN
                    body = (b'{"error":{"code":"origin_mismatch"}}' if hostile
                            else b'{"status":{"appId":"mail-prototype",'
                                 b'"storeAvailable":true}}')
                    self.send_response(403 if hostile else 200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, _format, *_args):
                    pass

            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                with patch.object(probe, 'HOSTILE_ORIGIN_INPUT', input_path), \
                        patch.object(probe, 'HOSTILE_ORIGIN_PORT', server.server_address[1]):
                    result = probe.attempt_hostile_origin('a' * 64)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual([('http://127.0.0.1:12345', token),
                              (probe.HOSTILE_ORIGIN, token),
                              ('http://127.0.0.1:12345', token)],
                             [(origin, session) for path, origin, session in requests
                              if path == probe.HOSTILE_ORIGIN_ENDPOINT])
            self.assertEqual(3, len(requests))
            self.assertEqual('origin_mismatch', result['attack']['errorCode'])
            self.assertNotIn(token, json.dumps(result))

    def test_network_app_mode_runs_only_fixed_sibling_connections(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / 'ready.json'
            with patch.object(probe, 'NETWORK_APP_READY', ready), \
                    patch.object(probe.sys, 'argv', ['probe.py', 'a' * 64,
                                                      'network-app']), \
                    patch.object(probe.sys, 'flags', SimpleNamespace(isolated=1,
                                                                       no_site=1)), \
                    patch.object(probe, 'publish_network_result') as network, \
                    patch.object(probe, 'attempt_read') as read, \
                    patch.object(probe, 'fixed_false_claims') as claims, \
                    patch.object(probe.time, 'sleep', side_effect=StopIteration):
                with self.assertRaises(StopIteration):
                    probe.main()
            self.assertTrue(ready.exists())
            self.assertEqual([call('sibling-fcp', 'a' * 64),
                              call('sibling-http', 'a' * 64)], network.call_args_list)
            read.assert_not_called()
            claims.assert_not_called()

    @unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0
                         and Path('/node/tmp').is_dir(),
                         'requires disposable Linux root and isolated /node/tmp')
    def test_real_double_fork_child_keeps_cgroup_after_setsid(self):
        nonce = 'a' * 64
        ready = Path('/node/tmp/pr315-setsid-double-fork-child.json')
        self.assertFalse(ready.exists())
        child_pid = None
        with tempfile.TemporaryDirectory(dir='/node/tmp') as directory:
            root = Path(directory)
            trigger = root / 'trigger.json'
            result = root / 'result.json'
            trigger.write_text(json.dumps({'caseId': 'setsid-double-fork',
                                            'nonce': nonce}))
            with patch.object(probe, 'SETSID_TRIGGER', trigger), \
                    patch.object(probe, 'SETSID_RESULT', result):
                probe.publish_setsid_double_fork(nonce)
            until = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < until:
                time.sleep(.01)
            self.assertTrue(ready.exists())
            child_pid = json.loads(ready.read_text())['pid']
            expected_tail = (b'-I\0-S\0-B\0'
                        + os.fsencode(probe.__file__) + b'\0'
                        + nonce.encode() + b'\0setsid-child\0')
            proc = Path('/proc') / str(child_pid)
            try:
                command = proc.joinpath('cmdline').read_bytes()
                self.assertIn(b'/usr/bin/python3\0', command)
                self.assertTrue(command.endswith(expected_tail))
                self.assertNotEqual(os.getsid(0), os.getsid(child_pid))
                self.assertEqual(Path('/proc/self/cgroup').read_bytes(),
                                 proc.joinpath('cgroup').read_bytes())
                self.assertEqual('setsid-double-fork',
                                 json.loads(result.read_text())['caseId'])
            finally:
                if (proc.joinpath('cmdline').exists() and
                        proc.joinpath('cmdline').read_bytes().endswith(expected_tail)):
                    os.kill(child_pid, 15)
                    until = time.monotonic() + 5
                    while proc.exists() and time.monotonic() < until:
                        time.sleep(.02)
                    if (proc.exists() and
                            proc.joinpath('cmdline').read_bytes().endswith(expected_tail)):
                        os.kill(child_pid, 9)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux O_PATH reader required')
    def test_fixed_output_fifo_is_real_and_collector_rejects_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canary = root / 'canary'
            artifact = root / 'artifact'
            trigger = root / 'trigger.json'
            result = root / 'result.json'
            canary.write_bytes(b'x' * 32)
            trigger.write_text(json.dumps({'caseId': 'output-fifo', 'nonce': 'a' * 64}))
            with patch.object(probe, 'OUTPUT_CANARY', canary), \
                    patch.object(probe, 'OUTPUT_FIFO', artifact), \
                    patch.object(probe, 'OUTPUT_FIFO_TRIGGER', trigger), \
                    patch.object(probe, 'OUTPUT_FIFO_RESULT', result):
                probe.publish_output_fifo('a' * 64)
            self.assertTrue(stat.S_ISFIFO(artifact.lstat().st_mode))
            with self.assertRaisesRegex(snapshot.SnapshotError, 'file-invalid'):
                snapshot.read_file(root, artifact.name, maximum=64, timeout=2)
            self.assertEqual(b'x' * 32, snapshot.read_file(
                root, canary.name, maximum=64, timeout=2))
            self.assertEqual('output-fifo', json.loads(result.read_text())['caseId'])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux O_PATH reader required')
    def test_fixed_output_hardlink_preserves_canary_and_collector_rejects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canary = root / 'canary'
            artifact = root / 'artifact'
            trigger = root / 'trigger.json'
            result = root / 'result.json'
            canary.write_bytes(b'x' * 32)
            trigger.write_text(json.dumps({'caseId': 'output-hardlink', 'nonce': 'a' * 64}))
            with patch.object(probe, 'OUTPUT_CANARY', canary), \
                    patch.object(probe, 'OUTPUT_HARDLINK', artifact), \
                    patch.object(probe, 'OUTPUT_HARDLINK_TRIGGER', trigger), \
                    patch.object(probe, 'OUTPUT_HARDLINK_RESULT', result):
                probe.publish_output_hardlink('a' * 64)
            self.assertTrue(stat.S_ISREG(artifact.lstat().st_mode))
            self.assertEqual(2, artifact.stat().st_nlink)
            self.assertEqual((canary.stat().st_dev, canary.stat().st_ino),
                             (artifact.stat().st_dev, artifact.stat().st_ino))
            with self.assertRaisesRegex(snapshot.SnapshotError, 'file-invalid'):
                snapshot.read_file(root, artifact.name, maximum=64, timeout=2)
            self.assertEqual(b'x' * 32, canary.read_bytes())
            self.assertEqual('output-hardlink', json.loads(result.read_text())['caseId'])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux O_PATH reader required')
    def test_fixed_output_flood_exceeds_collector_cap_by_one_byte(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canary = root / 'canary'
            artifact = root / 'artifact'
            trigger = root / 'trigger.json'
            result = root / 'result.json'
            canary.write_bytes(b'x' * 32)
            trigger.write_text(json.dumps({'caseId': 'output-flood', 'nonce': 'a' * 64}))
            with patch.object(probe, 'OUTPUT_CANARY', canary), \
                    patch.object(probe, 'OUTPUT_FLOOD', artifact), \
                    patch.object(probe, 'OUTPUT_FLOOD_TRIGGER', trigger), \
                    patch.object(probe, 'OUTPUT_FLOOD_RESULT', result):
                probe.publish_output_flood('a' * 64)
            self.assertEqual(65537, artifact.stat().st_size)
            self.assertEqual(b'F' * 65537, artifact.read_bytes())
            with self.assertRaisesRegex(snapshot.SnapshotError, 'file-invalid'):
                snapshot.read_file(root, artifact.name, maximum=65536, timeout=2)
            self.assertEqual(b'x' * 32, snapshot.read_file(
                root, canary.name, maximum=64, timeout=2))
            self.assertEqual(65537, json.loads(result.read_text())['writtenBytes'])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux descriptor pinning required')
    def test_fixed_output_replacement_waits_for_second_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canary = root / 'canary'
            artifact = root / 'artifact'
            trigger = root / 'trigger.json'
            result = root / 'result.json'
            swap_trigger = root / 'swap-trigger.json'
            swap_result = root / 'swap-result.json'
            next_file = root / 'next'
            canary.write_bytes(b'x' * 32)
            trigger.write_text(json.dumps({'caseId': 'output-replacement',
                                            'nonce': 'a' * 64}))
            failures = []

            def run():
                try:
                    probe.publish_output_replacement('a' * 64)
                except Exception as error:
                    failures.append(error)

            with patch.object(probe, 'OUTPUT_CANARY', canary), \
                    patch.object(probe, 'OUTPUT_REPLACEMENT', artifact), \
                    patch.object(probe, 'OUTPUT_REPLACEMENT_TRIGGER', trigger), \
                    patch.object(probe, 'OUTPUT_REPLACEMENT_RESULT', result), \
                    patch.object(probe, 'OUTPUT_REPLACEMENT_SWAP_TRIGGER', swap_trigger), \
                    patch.object(probe, 'OUTPUT_REPLACEMENT_SWAP_RESULT', swap_result), \
                    patch.object(probe, 'OUTPUT_REPLACEMENT_NEXT', next_file):
                worker = threading.Thread(target=run, daemon=True)
                worker.start()
                until = time.monotonic() + 2
                while not result.exists() and time.monotonic() < until:
                    time.sleep(.01)
                self.assertTrue(result.exists())
                self.assertEqual(b'A' * 32, artifact.read_bytes())
                first = artifact.stat().st_ino
                swap_trigger.write_text(json.dumps({'caseId': 'output-replacement',
                                                    'nonce': 'a' * 64}))
                worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
            self.assertFalse(failures)
            self.assertNotEqual(first, artifact.stat().st_ino)
            self.assertEqual(b'B' * 32, artifact.read_bytes())
            self.assertEqual('output-replacement', json.loads(swap_result.read_text())['caseId'])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux O_PATH reader required')
    def test_fixed_output_symlink_is_real_and_descriptor_collector_rejects_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canary = root / 'canary'
            artifact = root / 'artifact'
            trigger = root / 'trigger.json'
            result = root / 'result.json'
            canary.write_bytes(b'x' * 32)
            trigger.write_text(json.dumps({'caseId': 'output-symlink', 'nonce': 'a' * 64}))
            with patch.object(probe, 'OUTPUT_CANARY', canary), \
                    patch.object(probe, 'OUTPUT_SYMLINK', artifact), \
                    patch.object(probe, 'OUTPUT_SYMLINK_TRIGGER', trigger), \
                    patch.object(probe, 'OUTPUT_SYMLINK_RESULT', result):
                probe.publish_output_symlink('a' * 64)
            self.assertTrue(artifact.is_symlink())
            self.assertEqual(str(canary), os.readlink(artifact))
            with self.assertRaisesRegex(snapshot.SnapshotError, 'file-invalid'):
                snapshot.read_file(root, artifact.name, maximum=64, timeout=2)
            self.assertEqual(b'x' * 32, snapshot.read_file(
                root, canary.name, maximum=64, timeout=2))
            self.assertEqual('output-symlink', json.loads(result.read_text())['caseId'])

    def test_sibling_probe_sends_only_fixed_recipient_syn_and_records_real_timeout(self):
        channel = MagicMock()
        channel.__enter__.return_value = channel
        channel.connect.side_effect = TimeoutError('fixed test timeout')
        with patch.object(probe.socket, 'socket', return_value=channel) as created:
            result = probe.attempt_network('sibling-fcp', 'a' * 64)
        created.assert_called_once_with(probe.socket.AF_INET, probe.socket.SOCK_STREAM)
        channel.connect.assert_called_once_with(('10.231.0.2', 19401))
        self.assertEqual({'connected': False, 'errno': 'ETIMEDOUT'}, result['outcome'])
        self.assertLess(result['startedMonotonicNs'], result['finishedMonotonicNs'])
        self.assertEqual('sibling-fcp', result['caseId'])
        with self.assertRaisesRegex(ValueError, 'network-case-invalid'):
            probe.attempt_network('sibling-app', 'a' * 64)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux proc namespaces required')
    def test_composed_role_record_fits_fixed_guest_capture_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(probe, 'TARGET', root / 'missing-observer'), \
                    patch.object(probe, 'SIBLING', root / 'missing-sibling'), \
                    patch.object(probe, 'PACKAGE', root / 'missing-package'), \
                    patch.object(probe, 'CGROUP_TARGET', root / 'missing-cgroup'), \
                    patch.object(probe, 'RESOLVER_TARGET', root / 'missing-resolver'):
                record = probe.attempt_read('a' * 64)
                record['writeAttempt'] = probe.attempt_write()
                record['identityClaim'], record['counterClaim'] = probe.fixed_false_claims()
                record['siblingRead'] = probe.attempt_fixed_access(
                    'sibling-data', probe.SIBLING)
                record['packageWrite'] = probe.attempt_fixed_access(
                    'package-expectation', probe.PACKAGE, b'pr315!')
                record['cgroupMigration'] = probe.attempt_fixed_access(
                    'cgroup-migration', probe.CGROUP_TARGET, b'2')
                record['resolverRead'] = probe.attempt_fixed_access(
                    'resolver-authority', probe.RESOLVER_TARGET)
            self.assertLessEqual(len(json.dumps(record).encode()), 4096)

    def test_fixed_role_access_rejects_arbitrary_target_and_reports_kernel_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'sibling-canary'
            target.write_bytes(b'x' * 32)
            target.chmod(0o000)
            try:
                with patch.object(probe, 'SIBLING', target):
                    denied = probe.attempt_fixed_access('sibling-data', target)
            finally:
                target.chmod(0o600)
            self.assertEqual({'opened': False, 'errno': 'EACCES'}, denied['outcome'])
            self.assertEqual(0, denied['writtenBytes'])
            self.assertEqual(b'x' * 32, target.read_bytes())
            with self.assertRaisesRegex(ValueError, 'operation-invalid'):
                probe.attempt_fixed_access('sibling-data', target.parent / 'other')

    def test_unexpected_package_write_is_bounded_and_detectable(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'cryptad.jar'
            target.write_bytes(b'x' * 32)
            with patch.object(probe, 'PACKAGE', target):
                value = probe.attempt_fixed_access('package-expectation', target, b'pr315!')
            self.assertEqual({'opened': True, 'errno': None}, value['outcome'])
            self.assertEqual(6, value['writtenBytes'])
            self.assertEqual(b'pr315!', target.read_bytes()[:6])

    def test_false_identity_and_counter_claims_are_finite(self):
        identity, counters = probe.fixed_false_claims()
        self.assertNotEqual(os.getpid(), identity['claimedHostPid'])
        self.assertEqual(0, counters['claimedMemoryCurrentBytes'])
        self.assertEqual(0, counters['claimedTasksCurrent'])
        self.assertLess(identity['startedMonotonicNs'], counters['finishedMonotonicNs'])

    def test_write_attempt_reports_real_denial_and_preserves_canary(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'observer-canary'
            raw = b'x' * 32
            target.write_bytes(raw)
            target.chmod(0o000)
            try:
                with patch.object(probe, 'TARGET', target):
                    denied = probe.attempt_write()
            finally:
                target.chmod(0o600)
            self.assertEqual({'opened': False, 'errno': 'EACCES'}, denied['outcome'])
            self.assertEqual(0, denied['writtenBytes'])
            self.assertEqual(raw, target.read_bytes())

    def test_unexpected_write_access_is_observable_with_finite_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'observer-canary'
            target.write_bytes(b'x' * 32)
            with patch.object(probe, 'TARGET', target):
                opened = probe.attempt_write()
            self.assertEqual({'opened': True, 'errno': None}, opened['outcome'])
            self.assertEqual(len(b'pr315!'), opened['writtenBytes'])
            self.assertEqual(b'pr315!', target.read_bytes()[:len(b'pr315!')])


if __name__ == '__main__':
    unittest.main()
