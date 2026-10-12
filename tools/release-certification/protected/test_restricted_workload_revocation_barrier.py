"""Fixed reply-barrier checks; these are not installed acceptance records."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import socket
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import restricted_workload as workload
import restricted_workload_revocation_barrier as barrier


class RevocationReplyBarrierTest(unittest.TestCase):
    def test_normal_request_has_no_barrier_or_peer_read(self):
        with tempfile.TemporaryDirectory() as directory:
            connection = Mock()
            with patch.object(workload, 'ROOT', Path(directory)):
                self.assertIsNone(barrier.prepare(connection, 1000))
            connection.getsockopt.assert_not_called()
        barrier.refused(None, ValueError('unrelated request failure'))

    @unittest.skipUnless(os.name == 'posix', 'requires filesystem permissions')
    def test_public_request_record_is_rejected_before_kernel_peer_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'authority').mkdir()
            request = root / 'authority' / barrier.REQUEST_NAME
            request.write_text('{}')
            request.chmod(0o644)
            connection = Mock()
            with patch.object(workload, 'ROOT', root):
                with self.assertRaisesRegex(ValueError, 'private-record-invalid'):
                    barrier.prepare(connection, 1000)
            connection.getsockopt.assert_not_called()

    @unittest.skipUnless(os.name == 'posix' and Path('/proc/self/stat').exists()
                         and os.geteuid() == 0, 'requires disposable Linux root')
    def test_actual_uid_peer_is_bound_and_wrong_peer_or_denial_cannot_release(self):
        account = pwd.getpwnam('nobody')
        with tempfile.TemporaryDirectory(dir='/node/tmp') as private_directory, \
                tempfile.TemporaryDirectory() as directory:
            public = Path(directory)
            public.chmod(0o755)
            root = Path(private_directory)
            authority = root / 'authority'
            authority.mkdir(mode=0o700)
            address = public / 'control.sock'
            marker = b'x' * 32
            nonce = 'a' * 64
            source_digest = hashlib.sha256(Path(barrier.__file__).read_bytes()).hexdigest()
            generation = 'c' * 64
            with patch.object(workload, 'ROOT', root), socket.socket(
                    socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                workload.write(root / 'campaign.json', {'generation': generation,
                    'deadlineMonotonicNs': time.monotonic_ns() + 20_000_000_000})
                listener.bind(str(address))
                address.chmod(0o666)
                listener.listen(1)
                pid = os.fork()
                if pid == 0:
                    try:
                        listener.close()
                        os.setgroups([])
                        os.setgid(account.pw_gid)
                        os.setuid(account.pw_uid)
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                            client.settimeout(5)
                            client.connect(str(address))
                            client.sendall(b'R')
                            client.recv(1)
                        os._exit(0)
                    except BaseException:
                        os._exit(1)
                try:
                    listener.settimeout(5)
                    with listener.accept()[0] as connection:
                        self.assertEqual(b'R', connection.recv(1))
                        selected = {'schemaVersion': 1, 'policy': barrier.POLICY,
                            'caseId': 'revocation-running',
                            'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
                            'campaign': generation, 'bootId': workload.boot(),
                            'controllerPid': os.getpid(),
                            'controllerStartTicks': int(Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19]),
                            'observerPid': pid,
                            'observerStartTicks': int((Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()[19]),
                            'markerDigest': hashlib.sha256(marker).hexdigest(), 'sourceDigest': source_digest}
                        workload.write(authority / barrier.REQUEST_NAME, selected)
                        token = barrier.prepare(connection, account.pw_uid)
                        self.assertEqual(pid, token['observerPid'])
                        for key, value in (
                                ('observerStartTicks', selected['observerStartTicks'] + 1),
                                ('controllerPid', selected['controllerPid'] + 1),
                                ('bootId', 'wrong-boot'), ('campaign', 'e' * 64),
                                ('sourceDigest', 'f' * 64), ('schemaVersion', True)):
                            with self.subTest(key=key):
                                workload.write(authority / barrier.REQUEST_NAME, {**selected, key: value})
                                with self.assertRaisesRegex(ValueError, 'instance-invalid'):
                                    barrier.prepare(connection, account.pw_uid)
                        (root / 'revoked').write_bytes(marker)
                        (root / 'revoked').chmod(0o600)
                        token['requestDigest'] = 'd' * 64
                        with self.assertRaisesRegex(ValueError, 'request-changed'):
                            barrier.refused(token, workload.WorkloadError(
                                'restricted-workload-authority-expired-or-revoked'))
                        workload.write(authority / barrier.REQUEST_NAME, selected)
                        with self.assertRaisesRegex(ValueError, 'wrong-denial'):
                            barrier.refused(token, ValueError('different failure'))
                        self.assertFalse((authority / barrier.PHASE_NAME).exists())
                        workload.write(authority / barrier.RELEASE_NAME,
                            {'schemaVersion': 1, 'policy': barrier.POLICY, 'nonce': 'b' * 64})
                        with self.assertRaisesRegex(ValueError, 'release-invalid'):
                            barrier.refused(token, workload.WorkloadError(
                                'restricted-workload-authority-expired-or-revoked'))
                        proof = workload.read(authority / barrier.PHASE_NAME)
                        self.assertEqual(pid, proof['observerPid'])
                        self.assertEqual('authority-expired-or-revoked', proof['errorCode'])
                        (authority / barrier.PHASE_NAME).unlink()
                        (authority / barrier.RELEASE_NAME).unlink()
                        token['campaignDeadlineNs'] = time.monotonic_ns() - 1
                        with self.assertRaisesRegex(ValueError, 'release-timeout'):
                            barrier.refused(token, workload.WorkloadError(
                                'restricted-workload-authority-expired-or-revoked'))
                        connection.sendall(b'G')
                finally:
                    waited, status = os.waitpid(pid, 0)
                    self.assertEqual(pid, waited)
                    self.assertEqual(0, status)

    @unittest.skipUnless(Path('/proc/self/stat').exists() and os.geteuid() == 0,
                         'requires disposable Linux root')
    def test_real_handler_refuses_revoked_start_and_waits_for_root_release(self):
        import restricted_workload_controller as controller
        with tempfile.TemporaryDirectory(dir='/node/tmp') as private_directory:
            root = Path(private_directory)
            authority = root / 'authority'
            authority.mkdir(mode=0o700)
            nonce, handle = 'a' * 64, 'b' * 64
            marker = b'x' * 32
            deadline_ns = time.monotonic_ns() + 20_000_000_000
            server, client = socket.socketpair()
            with patch.object(workload, 'ROOT', root):
                campaign = {'generation': 'c' * 64, 'bootId': workload.boot(),
                    'state': 'prepared', 'deadlineMonotonicNs': deadline_ns,
                    'handles': {'candidate-sender': handle}}
                workload.write(root / 'campaign.json', campaign)
                workload.write(authority / 'candidate-sender.json', {
                    'handle': handle, 'campaign': campaign['generation']})
                ticks = int(Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19])
                workload.write(authority / barrier.REQUEST_NAME, {
                    'schemaVersion': 1, 'policy': barrier.POLICY, 'caseId': 'revocation-running',
                    'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
                    'campaign': campaign['generation'], 'bootId': workload.boot(),
                    'controllerPid': os.getpid(), 'controllerStartTicks': ticks,
                    'observerPid': os.getpid(), 'observerStartTicks': ticks,
                    'markerDigest': hashlib.sha256(marker).hexdigest(),
                    'sourceDigest': hashlib.sha256(Path(barrier.__file__).read_bytes()).hexdigest()})
                pid = os.fork()
                if pid == 0:
                    try:
                        server.close()
                        client.settimeout(5)
                        client.sendall(b'P')
                        if client.recv(1) != b'R':
                            os._exit(2)
                        (root / 'revoked').write_bytes(marker)
                        (root / 'revoked').chmod(0o600)
                        client.sendall((json.dumps({'method': 'start', 'handle': handle},
                            separators=(',', ':')) + '\n').encode())
                        if client.recv(256) != b'{"error":"restricted-workload-request-failed"}\n':
                            os._exit(3)
                        until = time.monotonic() + 3
                        while not (authority / barrier.PHASE_NAME).exists():
                            if time.monotonic() >= until:
                                os._exit(4)
                            time.sleep(.01)
                        proof = workload.read(authority / barrier.PHASE_NAME)
                        if proof['errorCode'] != 'authority-expired-or-revoked':
                            os._exit(5)
                        workload.write(authority / barrier.RELEASE_NAME,
                            {'schemaVersion': 1, 'policy': barrier.POLICY, 'nonce': nonce})
                        os._exit(0)
                    except BaseException:
                        os._exit(1)
                client.close()
                try:
                    # This disposable test has no systemd unit. Only its unit snapshot is
                    # replaced; parsing, current-authority rejection and reply barrier run.
                    with server, patch.object(controller, '_controller_process', return_value={}):
                        self.assertFalse(controller.handle_request(server, 0))
                    proof = workload.read(authority / barrier.PHASE_NAME)
                    self.assertGreater(proof['replyEnqueuedMonotonicNs'], proof['acceptedMonotonicNs'])
                    self.assertEqual('authority-expired-or-revoked', proof['errorCode'])
                    self.assertTrue((authority / barrier.RELEASE_NAME).exists())
                finally:
                    waited, status = os.waitpid(pid, 0)
                    self.assertEqual(pid, waited)
                    self.assertEqual(0, status)


if __name__ == '__main__':
    unittest.main()
