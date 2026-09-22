"""Bounded protocol, invocation, and current scoped-process mapping regressions."""
import array
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

import cross_version_workload as workload

HANDLE = 'a' * 64
JDK = 'sha256:' + 'b' * 64
EPOCH = {'handle': HANDLE, 'generation': 'c' * 64, 'managerInvocation': 'd' * 32,
         'bootId': '12345678-1234-1234-1234-123456789abc'}


def sample():
    def row(pid, parent, namespaces, digest):
        return {'hostPid': pid, 'hostParentPid': parent, 'namespacePids': namespaces,
                'startTicks': pid + 100, 'executableDigest': digest,
                'noNewPrivileges': True, 'effectiveCapabilities': 0}
    return {**EPOCH, 'state': 'running', 'provenance': 'controller-kernel-sample', 'processes': [
        row(100, 1, [100, 1], 'sha256:' + '0' * 64),
        row(101, 100, [101, 2], JDK),
        row(102, 101, [102, 3], 'sha256:' + '1' * 64),
        row(103, 102, [103, 4, 1], JDK)]}


class ScopedWorkerTests(unittest.TestCase):
    def test_real_scoped_inner_java_is_bound_to_wrapper_hint(self):
        result = workload.bind_worker(sample(), 3, JDK)
        self.assertEqual(102, result['hostPid'])
        self.assertEqual(103, result['javaHostPid'])
        self.assertEqual(EPOCH['managerInvocation'], result['managerInvocation'])

    def test_api_host_pid_is_not_namespace_pid(self):
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'outside-role'):
            workload.bind_worker(sample(), 102, JDK)

    def test_unrelated_matching_jvm_does_not_authenticate_app(self):
        value = sample()
        value['processes'][-1]['hostParentPid'] = 100
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'descendant-not-observed'):
            workload.bind_worker(value, 3, JDK)

    def test_no_nested_pid_namespace_cannot_credit_sandbox(self):
        value = sample()
        value['processes'][-1]['namespacePids'] = [103, 4]
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'descendant-not-observed'):
            workload.bind_worker(value, 3, JDK)

    def test_wrong_executable_or_candidate_provenance_rejected(self):
        with self.assertRaises(workload.runtime.RuntimeFailure):
            workload.bind_worker(sample(), 3, 'sha256:' + '9' * 64)
        value = sample()
        value['provenance'] = 'candidate-api'
        with self.assertRaises(workload.runtime.RuntimeFailure):
            workload.bind_worker(value, 3, JDK)

    def test_duplicate_or_ambiguous_pids_rejected(self):
        value = sample()
        value['processes'].append(copy.deepcopy(value['processes'][-1]))
        with self.assertRaises(workload.runtime.RuntimeFailure):
            workload.bind_worker(value, 3, JDK)
        value = sample()
        value['processes'][-1]['namespacePids'][1] = 3
        with self.assertRaises(workload.runtime.RuntimeFailure):
            workload.bind_worker(value, 3, JDK)


class ObserverPolicyTests(unittest.TestCase):
    def test_every_session_refresh_uses_controller_even_with_candidate_origin(self):
        supervisor = types.SimpleNamespace(
            private={'nodes': {'candidate-sender': {'httpPort': 19402}}},
            handles={'candidate-sender': HANDLE}, next_operation=mock.Mock(),
            observe=mock.Mock(), control=types.SimpleNamespace(request=mock.Mock()))
        app = workload.InstalledAppHandle(supervisor, 'candidate-sender')
        forged = {'uiOrigin': 'http://127.0.0.1:23456', 'browserSessionToken': 'forged'}
        with mock.patch.object(app, 'request', return_value=(200, forged)) as ordinary:
            for token in ('initial-session', 'restarted-session'):
                supervisor.control.request.return_value = {
                    'uiOrigin': 'http://127.0.0.1:23457', 'browserSessionToken': token,
                    'browserSessionExpiresAt': 123456}
                self.assertIs(app, app.refresh_session())
                self.assertEqual(token, app.session)
                self.assertEqual('http://127.0.0.1:23457', app.origin)
            ordinary.assert_not_called()
        self.assertEqual([mock.call('bootstrap-mail', HANDLE)] * 2,
                         supervisor.control.request.call_args_list)
        self.assertEqual(4, supervisor.observe.call_count)

    def test_failed_controller_refresh_discards_previous_session(self):
        supervisor = types.SimpleNamespace(private={'nodes': {'candidate-sender': {'httpPort': 19402}}})
        app = workload.InstalledAppHandle(supervisor, 'candidate-sender')
        app.origin, app.session, app.session_expires_at = 'http://127.0.0.1:23457', 'old', 123
        with mock.patch.object(app, 'isolated_bootstrap', side_effect=workload.runtime.RuntimeFailure('denied')):
            with self.assertRaises(workload.runtime.RuntimeFailure):
                app.refresh_session()
        self.assertIsNone(app.session)
        self.assertIsNone(app.origin)
        self.assertIsNone(app.session_expires_at)

    def test_changed_manager_epoch_rejected(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.handles = {'candidate-sender': HANDLE}
        adapter.nodes = {'candidate-sender': dict(EPOCH)}
        self.assertEqual(EPOCH, adapter._bound('candidate-sender', dict(EPOCH)))
        for key in workload.EPOCH:
            with self.subTest(key=key), self.assertRaises(workload.runtime.RuntimeFailure):
                adapter._bound('candidate-sender', {**EPOCH, key: 'reused'})

    def test_disallowed_routes_never_open_connection(self):
        supervisor = types.SimpleNamespace(private={'nodes': {'candidate-sender': {'httpPort': 19402}}})
        app = workload.InstalledAppHandle(supervisor, 'candidate-sender')
        with mock.patch.object(app.opener, 'open') as opened:
            for path in ('/etc/passwd', '/api/v1/apps/other/start', '/api/v1/apps?escape=true', '/api/v1/app-data/../secret'):
                with self.subTest(path=path), self.assertRaises(workload.runtime.RuntimeFailure):
                    app.request('GET', path)
            opened.assert_not_called()

    def test_dynamic_target_cannot_use_management_opener(self):
        opener = workload._RoleHttp(object(), 'candidate-sender')
        for target in ('http://127.0.0.1:19403/', 'http://example.invalid/', 'http://127.0.0.1:19402/#fragment'):
            with self.subTest(target=target), self.assertRaises(workload.runtime.RuntimeFailure):
                opener.open(workload.runtime.urllib.request.Request(target))

    def test_historical_mail_client_is_not_a_fallback(self):
        supervisor = types.SimpleNamespace(private={'nodes': {'candidate-sender': {'httpPort': 19402}}})
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'consumer-adapter-unsupported'):
            workload.InstalledAppHandle(supervisor, 'candidate-sender').mail_client()

    def test_restart_preserves_deadline_and_rejects_reused_invocation(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.nodes = {'candidate-sender': dict(EPOCH)}
        adapter.apps = {}
        adapter.deadline = 12345
        adapter.stop = mock.Mock()
        adapter.start = mock.Mock(return_value={**EPOCH, 'generation': 'e' * 64, 'managerInvocation': 'f' * 32})
        result = adapter.restart('candidate-sender')
        self.assertEqual('e' * 64, result['generation'])
        self.assertEqual(12345, adapter.deadline)
        adapter.start.return_value = {**EPOCH, 'generation': 'e' * 64}
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'restart-epoch-invalid'):
            adapter.restart('candidate-sender')

    def test_unstarted_role_cleanup_does_not_forge_node_epoch_event(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.handles = {'candidate-sender': HANDLE}
        adapter._journal_started_roles = set()
        adapter.control = types.SimpleNamespace(request=mock.Mock(return_value={'state': 'quiescent', 'handle': HANDLE}))
        adapter.emit = mock.Mock()
        adapter.stop('candidate-sender')
        adapter.emit.assert_not_called()
        adapter._journal_started_roles.add('candidate-sender')
        adapter.stop('candidate-sender')
        adapter.emit.assert_called_once_with('node-stop', role='candidate-sender')
        self.assertFalse(adapter._journal_started_roles)

    def test_request_shape_rejected_before_socket_allocation(self):
        with mock.patch.object(workload.socket, 'socket') as factory:
            for method, handle in (('exec', HANDLE), ('observe', '/proc/1'), ('connect-19403', HANDLE)):
                with self.assertRaises(workload.runtime.RuntimeFailure):
                    workload.WorkloadClient().request(method, handle)
            factory.assert_not_called()


class ReadinessDeadlineTests(unittest.TestCase):
    def adapter(self, seconds):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.handles = {'candidate-sender': HANDLE}
        adapter.nodes = {}
        adapter.control = types.SimpleNamespace(request=mock.Mock(return_value={**EPOCH, 'state': 'running'}))
        adapter.deadline = time.monotonic() + seconds
        adapter.emit = mock.Mock()
        adapter._journal_started_roles = set()
        return adapter

    def test_retry_success_preserves_original_budget_and_one_manager_start(self):
        adapter = self.adapter(2)
        original_deadline = adapter.deadline
        attempts, closed = [], []
        @contextmanager
        def client(role):
            attempts.append(role)
            if len(attempts) == 1:
                raise ConnectionRefusedError('not listening yet')
            try:
                yield object()
            finally:
                closed.append(role)
        adapter.client = client
        reference = {'identity': 'synthetic-node-identity'}
        with mock.patch.object(workload.runtime.interop, 'get_node_reference', return_value=reference):
            result = adapter.start('candidate-sender')
        self.assertEqual(reference, result['reference'])
        self.assertEqual(original_deadline, adapter.deadline)
        self.assertEqual(['candidate-sender'] * 2, attempts)
        self.assertEqual(['candidate-sender'], closed)
        adapter.control.request.assert_called_once_with('start', HANDLE)
        adapter.emit.assert_called_once()
        self.assertEqual({'candidate-sender'}, adapter._journal_started_roles)

    def test_blocked_real_fcp_reference_cannot_exceed_original_readiness_deadline(self):
        adapter = self.adapter(.1)
        original_deadline = adapter.deadline
        observer, daemon = socket.socketpair()
        daemon.sendall(b'NodeHello\nVersion=test\nEndMessage\n')
        stop = threading.Event()
        def close_after_outer_bound():
            stop.wait(.6)
            daemon.close()
        thread = threading.Thread(target=close_after_outer_bound)
        thread.start()
        with tempfile.TemporaryDirectory() as directory:
            @contextmanager
            def client(_role):
                selected = workload.ConnectedFcpClient(observer, 'readiness-test', Path(directory) / 'fcp.log', lambda: None)
                try:
                    yield selected
                finally:
                    selected.close()
            adapter.client = client
            started = time.monotonic()
            try:
                with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'workload-daemon-readiness-timeout') as raised:
                    adapter.start('candidate-sender')
                self.assertLess(time.monotonic() - started, .4)
                self.assertIsInstance(raised.exception.__cause__, workload.runtime.RuntimeFailure)
                self.assertEqual('operation-deadline-exceeded', str(raised.exception.__cause__))
                self.assertEqual(original_deadline, adapter.deadline)
                adapter.emit.assert_not_called()
                self.assertFalse(adapter._journal_started_roles)
                self.assertEqual(-1, observer.fileno())
            finally:
                stop.set()
                thread.join(2)
                observer.close()
                self.assertFalse(thread.is_alive())


@unittest.skipUnless(os.geteuid() == 0, 'actual UNIX controller peer must be root')
class TransportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='workload-client-')
        self.addCleanup(self.temporary.cleanup)
        self.path = str(Path(self.temporary.name) / 'control.sock')
        patch = mock.patch.object(workload, 'SOCKET', self.path)
        patch.start()
        self.addCleanup(patch.stop)

    def exchange(self, payload, method='observe', passed=None):
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(self.path)
        listener.listen(1)
        listener.settimeout(5)
        seen = []
        errors = []

        def serve():
            try:
                with listener.accept()[0] as channel:
                    channel.settimeout(5)
                    request = bytearray()
                    while not request.endswith(b'\n'):
                        request.extend(channel.recv(4096))
                    seen.append(json.loads(request))
                    ancillary = [] if passed is None else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [passed.fileno()]))]
                    channel.sendmsg([payload], ancillary)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            result = workload.WorkloadClient().request(method, HANDLE)
            self.assertEqual([{'method': method, 'handle': HANDLE}], seen)
            return result
        finally:
            thread.join(5)
            listener.close()
            self.assertFalse(thread.is_alive())
            if errors:
                raise errors[0]

    def test_actual_root_peer_and_bounded_json_roundtrip(self):
        self.assertEqual(EPOCH, self.exchange(json.dumps(EPOCH).encode() + b'\n'))

    def test_duplicate_fields_rejected(self):
        with self.assertRaises(workload.runtime.RuntimeFailure):
            self.exchange(b'{"state":"running","state":"quiescent"}\n')

    def test_missing_newline_is_not_a_response(self):
        with self.assertRaises(workload.runtime.RuntimeFailure):
            self.exchange(b'{}')

    def test_error_response_rejected(self):
        with self.assertRaises(workload.runtime.RuntimeFailure):
            self.exchange(b'{"error":"restricted-workload-request-failed"}\n')

    def test_actual_tcp_descriptor_handoff(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            with socket.create_connection(server.getsockname()) as passed, server.accept()[0] as peer:
                value, connected = self.exchange(b'{"status":"connected"}\n', 'connect-fcp', passed)
                with connected:
                    connected.sendall(b'fixed-endpoint')
                    self.assertEqual(b'fixed-endpoint', peer.recv(32))
                    self.assertFalse(os.get_inheritable(connected.fileno()))
                self.assertEqual({'status': 'connected'}, value)

    def test_unexpected_descriptor_on_observation_is_rejected(self):
        left, right = socket.socketpair()
        try:
            with self.assertRaises(workload.runtime.RuntimeFailure):
                self.exchange(b'{}\n', passed=left)
        finally:
            left.close()
            right.close()

    def test_unix_socket_is_not_accepted_as_role_tcp_connection(self):
        left, right = socket.socketpair()
        try:
            with self.assertRaises(workload.runtime.RuntimeFailure):
                self.exchange(b'{"status":"connected"}\n', 'connect-http', left)
        finally:
            left.close()
            right.close()

    def test_connection_method_requires_descriptor(self):
        with self.assertRaises(workload.runtime.RuntimeFailure):
            self.exchange(b'{"status":"connected"}\n', 'connect-http')


class FcpParserTests(unittest.TestCase):
    def test_handshake_uses_existing_fcp_parser_on_supplied_socket(self):
        observer, daemon = socket.socketpair()
        with tempfile.TemporaryDirectory() as temporary:
            daemon.sendall(b'NodeHello\nVersion=test\nEndMessage\n')
            charges = []
            client = workload.ConnectedFcpClient(observer, 'fixed-client', Path(temporary) / 'fcp.log', lambda: charges.append(1))
            try:
                sent = daemon.recv(4096)
                self.assertIn(b'ClientHello\n', sent)
                self.assertIn(b'Name=fixed-client\n', sent)
                self.assertEqual('NodeHello', client.hello.name)
                self.assertEqual([1], charges)
            finally:
                client.close()
                daemon.close()


if __name__ == '__main__':
    unittest.main()
