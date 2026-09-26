"""Bounded protocol, invocation, and current scoped-process mapping regressions."""
import array
from contextlib import contextmanager, nullcontext
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
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
                'networkNamespaceIdentity': [1, 42],
                'noNewPrivileges': True, 'effectiveCapabilities': 0}
    return {**EPOCH, 'state': 'running', 'provenance': 'controller-kernel-sample',
            'cgroupIdentity': [1, 99], 'networkNamespaceIdentity': [1, 42], 'processes': [
        row(100, 1, [100, 1], 'sha256:' + '0' * 64),
        row(101, 100, [101, 2], JDK),
        row(102, 101, [102, 3], 'sha256:' + '1' * 64),
        row(103, 102, [103, 4, 1], JDK)]}


class ScopedWorkerTests(unittest.TestCase):
    def test_real_scoped_inner_java_is_bound_to_wrapper_hint(self):
        result = workload.bind_worker(sample(), 3, JDK)
        self.assertEqual(102, result['hostPid'])
        self.assertEqual(3, result['namespacePid'])
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


class ScopedDaemonTests(unittest.TestCase):
    def test_outer_java_epoch_is_bound_to_controller_kernel_sample(self):
        identity = workload.bind_daemon(sample(), JDK)
        self.assertEqual(101, identity['hostPid'])
        self.assertEqual(201, identity['startTicks'])
        self.assertEqual(EPOCH['managerInvocation'], identity['managerInvocation'])
        self.assertEqual((1, 42), identity['networkNamespaceIdentity'])

    def test_nested_app_java_or_ambiguous_outer_java_cannot_replace_daemon(self):
        value = sample()
        value['processes'][1]['namespacePids'] = [101, 2, 1]
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'daemon-process-not-unique'):
            workload.bind_daemon(value, JDK)
        value = sample()
        value['processes'].append({**value['processes'][1], 'hostPid': 104,
                                   'namespacePids': [104, 5], 'startTicks': 204})
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'daemon-process-not-unique'):
            workload.bind_daemon(value, JDK)

    def test_candidate_claim_and_unscoped_java_are_rejected(self):
        value = sample()
        value['provenance'] = 'candidate-api'
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'daemon-process-sample-invalid'):
            workload.bind_daemon(value, JDK)
        value = sample()
        value['processes'][1]['noNewPrivileges'] = False
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'daemon-process-sample-invalid'):
            workload.bind_daemon(value, JDK)
        value = sample()
        value['processes'][1]['networkNamespaceIdentity'] = [1, 43]
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'daemon-process-sample-invalid'):
            workload.bind_daemon(value, JDK)


class KernelRosterTests(unittest.TestCase):
    def test_signed_probe_pid_hint_requires_nested_kernel_process_without_capabilities(self):
        leader = {'hostPid': 123, 'namespacePids': [123, 22, 1],
                   'startTicks': 456, 'noNewPrivileges': True,
                   'effectiveCapabilities': 0, 'executableDigest': 'sha256:' + 'a' * 64,
                   'pidNamespace': 'pid:[46]', 'mountNamespaceIdentity': [1, 45],
                   'userNamespaceIdentity': [1, 47], 'networkNamespaceIdentity': [1, 43]}
        child = dict(leader, hostPid=124, hostParentPid=123,
                     namespacePids=[124, 23, 2], startTicks=457,
                     executableDigest='sha256:' + 'd' * 64)
        daemon = {'hostPid': 100, 'namespacePids': [100, 2],
                  'executableDigest': JDK, 'mountNamespaceIdentity': [1, 44]}
        observation = {'provenance': 'controller-kernel-sample',
                       'managerInvocation': 'b' * 32,
                       'cgroupIdentity': [1, 42], 'networkNamespaceIdentity': [1, 43],
                       'stateDigest': 'c' * 64, 'observedMonotonicNs': 1000,
                       'processes': [daemon, leader, child]}
        with mock.patch.object(workload.runtime, 'digest_file', return_value=child['executableDigest']):
            bound = workload.bind_probe_worker(observation, 22, JDK)
            self.assertEqual(124, bound['hostPid'])
            self.assertEqual([124, 23, 2], bound['namespacePids'])
            self.assertEqual(123, bound['sandboxLeader']['hostPid'])
            self.assertEqual([123, 22, 1], bound['sandboxLeader']['namespacePids'])
            self.assertEqual([1, 45], bound['mountNamespaceIdentity'])
            self.assertEqual([1, 44], bound['outerMountNamespaceIdentity'])
            self.assertEqual('controller-kernel-sample', bound['provenance'])
            shallow = dict(leader, namespacePids=[123, 22])
            with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'outside-role'):
                workload.bind_probe_worker(dict(observation, processes=[daemon, shallow, child]), 22, JDK)
            privileged = dict(leader, effectiveCapabilities=1)
            with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'kernel-boundary-invalid'):
                workload.bind_probe_worker(dict(observation, processes=[daemon, privileged, child]), 22, JDK)
            with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'python-child-unavailable'):
                workload.bind_probe_worker(dict(observation, processes=[daemon, leader,
                    dict(child, executableDigest='sha256:' + 'e' * 64)]), 22, JDK)

    def samples(self):
        result = {}
        for index, role in enumerate(workload.runtime.ROLES):
            value = copy.deepcopy(sample())
            value['managerInvocation'] = format(index + 1, '032x')
            value['cgroupIdentity'] = [1, 99 + index]
            value['networkNamespaceIdentity'] = [1, 42 + index]
            daemon = value['processes'][1]
            daemon['hostPid'] = 101 + index * 10
            daemon['startTicks'] = 201 + index * 10
            daemon['namespacePids'] = [daemon['hostPid'], 2 + index]
            daemon['networkNamespaceIdentity'] = [1, 42 + index]
            result[role] = value
        return result

    def test_final_controller_samples_project_distinct_fixed_role_principals(self):
        accounts = {'vmadmin': (1000, 1000)}
        accounts.update({'cryptad-wl-' + role: (1001 + index, 2001 + index)
                         for index, role in enumerate(workload.runtime.ROLES)})
        def account(name):
            uid, gid = accounts[name]
            return types.SimpleNamespace(pw_uid=uid, pw_gid=gid)
        with mock.patch.object(workload.pwd, 'getpwnam', side_effect=account), \
                mock.patch.object(workload.os, 'geteuid', return_value=987):
            roster = workload.kernel_roster(self.samples(),
                {role: JDK for role in workload.runtime.ROLES})
        self.assertEqual({'observerUid', 'runnerUid', 'roles'}, set(roster))
        self.assertEqual(987, roster['observerUid'])
        self.assertEqual(1000, roster['runnerUid'])
        self.assertEqual(set(workload.runtime.ROLES), {row['role'] for row in roster['roles']})
        self.assertEqual({42, 43, 44, 45}, {row['networkNamespace'] for row in roster['roles']})
        self.assertEqual({201, 211, 221, 231}, {row['processEpoch'] for row in roster['roles']})
        self.assertTrue(all(set(row) == {'role', 'uid', 'gid', 'invocationId', 'processEpoch',
                                         'bootId', 'cgroupDigest', 'networkNamespace'}
                            for row in roster['roles']))

    def test_missing_role_or_swapped_daemon_network_cannot_make_roster(self):
        values = self.samples()
        values.pop('previous')
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'kernel-roster-incomplete'):
            workload.kernel_roster(values, {role: JDK for role in workload.runtime.ROLES})
        values = self.samples()
        values['previous']['processes'][1]['networkNamespaceIdentity'] = [1, 42]
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'daemon-process-sample-invalid'):
            workload.kernel_roster(values, {role: JDK for role in workload.runtime.ROLES})


class ObserverPolicyTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(socket, 'SO_PEERCRED') and Path('/proc/self/stat').is_file(),
                         'Linux peer credentials and process epoch required')
    def test_fixed_observer_control_denial_checkpoint_excludes_handle(self):
        class FakeChannel:
            def __init__(self):
                self.response = b'R{"error":"restricted-workload-request-failed"}\n'
                self.request = None
                self.sent = []

            def __enter__(self):
                return self

            def __exit__(self, *_arguments):
                return False

            def settimeout(self, value):
                self.timeout = value

            def connect(self, address):
                self.address = address

            def getsockopt(self, *_arguments):
                return struct.pack('3i', 1, 0, 0)

            def sendall(self, value):
                self.request = value
                self.sent.append(value)

            def recv(self, length):
                value, self.response = self.response[:length], self.response[length:]
                return value

        with tempfile.TemporaryDirectory() as temporary:
            adapter = object.__new__(workload.InstalledWorkloadAdapter)
            adapter.root = Path(temporary)
            adapter.private = {'nodes': {'candidate-sender': {'apps': [
                {'appId': 'mail-prototype'}, {'appId': 'pr315-probe'}]}}}
            adapter.handles = {'candidate-sender': HANDLE}
            adapter.initial_role_roster = {'observerUid': 1001, 'roles': []}
            adapter.initial_role_window = {'startedMonotonicNs': 10,
                                           'finishedMonotonicNs': 20}
            adapter.initial_sender_state = 'c' * 64
            adapter.remaining = lambda maximum: maximum
            channel = FakeChannel()
            with mock.patch.object(workload.socket, 'socket', return_value=channel):
                adapter.probe_observer_control()
            path = adapter.root / 'pr315-observer-control.private.json'
            value = json.loads(path.read_text())
            self.assertEqual(workload.SOCKET, channel.address)
            self.assertEqual(b'P', channel.sent[0])
            self.assertEqual(hashlib.sha256(channel.request).hexdigest(), value['requestDigest'])
            self.assertEqual(hashlib.sha256(b'{"error":"restricted-workload-request-failed"}\n').hexdigest(),
                             value['responseDigest'])
            self.assertNotIn(HANDLE, path.read_text())
            self.assertEqual(0o600, path.stat().st_mode & 0o777)

    @unittest.skipUnless(hasattr(socket, 'SO_PEERCRED') and Path('/proc/self/stat').is_file(),
                         'Linux peer credentials and process epoch required')
    def test_arbitrary_endpoint_checkpoint_uses_real_observer_socket_without_leaking_handle(self):
        with tempfile.TemporaryDirectory() as temporary:
            adapter = object.__new__(workload.InstalledWorkloadAdapter)
            adapter.root = Path(temporary)
            adapter.private = {'nodes': {'candidate-sender': {'apps': [
                {'appId': 'mail-prototype'}, {'appId': 'pr315-probe'}]}}}
            adapter.handles = {'candidate-sender': HANDLE}
            adapter.initial_role_roster = {'observerUid': 1001, 'roles': []}
            adapter.initial_role_window = {'startedMonotonicNs': 10,
                                           'finishedMonotonicNs': 20}
            adapter.remaining = lambda maximum: maximum
            self.assertFalse(hasattr(adapter, 'initial_recipient_state'))
            response = b'{"error":"restricted-workload-request-failed"}\n'
            channel = mock.MagicMock()
            channel.__enter__.return_value = channel
            channel.getsockopt.return_value = struct.pack('3i', 1, 0, 0)
            channel.recv.side_effect = [b'R', response]
            with mock.patch.object(workload.socket, 'socket', return_value=channel):
                adapter.probe_arbitrary_endpoint()
            path = adapter.root / 'pr315-arbitrary-endpoint.private.json'
            value = json.loads(path.read_text())
            request = channel.sendall.call_args_list[1].args[0]
            self.assertEqual('arbitrary-endpoint', value['caseId'])
            self.assertEqual(hashlib.sha256(request).hexdigest(), value['requestDigest'])
            self.assertEqual(hashlib.sha256(response).hexdigest(), value['responseDigest'])
            self.assertNotIn(HANDLE, path.read_text())
            self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_probe_cohort_captures_four_active_roles_before_app_launch(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.private = {'nodes': {'candidate-sender': {'apps': [
            {'appId': 'mail-prototype'}, {'appId': 'pr315-probe'}]}}}
        adapter.expected_jdk_digests = {role: JDK for role in workload.runtime.ROLES}
        adapter.observe = mock.Mock(side_effect=lambda role: {'role': role,
            'stateDigest': 'a' * 64 if role == 'candidate-sender' else None})
        expected = {'observerUid': 1001, 'roles': []}
        with mock.patch.object(workload, 'kernel_roster', return_value=expected) as roster:
            adapter.capture_probe_target_roster()
        self.assertEqual(expected, adapter.initial_role_roster)
        self.assertEqual('a' * 64, adapter.initial_sender_state)
        self.assertEqual(4, adapter.observe.call_count)
        self.assertLess(adapter.initial_role_window['startedMonotonicNs'],
                        adapter.initial_role_window['finishedMonotonicNs'])
        roster.assert_called_once()

    def test_probe_checkpoint_durably_binds_fixed_signed_child_before_later_faults(self):
        with tempfile.TemporaryDirectory() as temporary:
            adapter = object.__new__(workload.InstalledWorkloadAdapter)
            adapter.root = Path(temporary)
            adapter.initial_role_roster = {'observerUid': 1001, 'roles': []}
            adapter.initial_role_window = {'startedMonotonicNs': 10,
                                           'finishedMonotonicNs': 20}
            adapter.initial_sender_state = 'a' * 64
            worker = {'hostPid': 123, 'observedMonotonicNs': 30}
            selected = {'appId': 'pr315-probe', 'bundleDigest': 'sha256:' + 'b' * 64}
            administrator = {'phase': 'probe', 'recordDigest': 'c' * 64}
            adapter.retain_probe_checkpoint(selected, worker, administrator)
            path = adapter.root / 'pr315-probe-kernel.private.json'
            value = json.loads(path.read_text())
            self.assertEqual(worker, value['probeWorker'])
            self.assertEqual(selected['bundleDigest'], value['bundleDigest'])
            self.assertEqual(administrator['recordDigest'], value['administratorRecordDigest'])
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            with self.assertRaises(FileExistsError):
                adapter.retain_probe_checkpoint(selected, worker, administrator)

    def stop_adapter(self, response, started=False):
        adapter = workload.InstalledWorkloadAdapter.__new__(workload.InstalledWorkloadAdapter)
        adapter.handles = {'candidate-sender': HANDLE}
        adapter.nodes = {'candidate-sender': dict(EPOCH)} if started else {}
        adapter.daemon_epochs = {}
        adapter._journal_started_roles = set()
        adapter.control = types.SimpleNamespace(request=mock.Mock(return_value=response))
        adapter.emit = mock.Mock()
        return adapter

    def test_partial_cleanup_preserves_explicit_never_launched_state(self):
        response = {**EPOCH, 'state': 'prepared', 'generation': None, 'managerInvocation': None}
        adapter = self.stop_adapter(response)
        self.assertEqual(response, adapter.stop('candidate-sender'))
        adapter.emit.assert_not_called()
        for changed in ({'generation': 'e' * 64}, {'managerInvocation': 'e' * 32}, {'handle': 'e' * 64}):
            adapter.control.request.return_value = {**response, **changed}
            with self.subTest(changed=changed), self.assertRaises(workload.runtime.RuntimeFailure):
                adapter.stop('candidate-sender')
        with self.assertRaises(workload.runtime.RuntimeFailure):
            self.stop_adapter(response, started=True).stop('candidate-sender')

    def test_stopped_reply_must_match_observed_launch_epoch(self):
        adapter = self.stop_adapter({**EPOCH, 'state': 'quiescent'}, started=True)
        adapter.stop('candidate-sender')
        adapter.control.request.return_value = {**EPOCH, 'state': 'quiescent', 'generation': 'e' * 64}
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'role-invocation-changed'):
            adapter.stop('candidate-sender')

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

    def test_same_manager_invocation_cannot_hide_jvm_replacement(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.handles = {'candidate-sender': HANDLE}
        adapter.nodes = {'candidate-sender': dict(EPOCH)}
        adapter.expected_jdk_digests = {'candidate-sender': JDK}
        adapter.daemon_epochs = {'candidate-sender': workload.bind_daemon(sample(), JDK)}
        adapter.deadline = time.monotonic() + 10
        replaced = sample()
        replaced['processes'][1]['startTicks'] += 1
        adapter.control = types.SimpleNamespace(request=mock.Mock(return_value=replaced))
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'role-daemon-epoch-changed'):
            adapter.observe('candidate-sender')

    def test_installed_chk_selection_is_public_and_charged_once(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.plan = {'producer': {'sourceCommit': 'a' * 40}}
        adapter.next_operation = mock.Mock(return_value='op-' + 'b' * 32)
        with mock.patch.object(workload.runtime.Supervisor, 'content') as content:
            adapter.content_chk()
        adapter.next_operation.assert_called_once_with()
        self.assertEqual('op-' + 'b' * 32, content.call_args.kwargs['operation'])
        self.assertEqual(workload.runtime.fixed_pr315_payload('a' * 40, 'op-' + 'b' * 32),
                         content.call_args.kwargs['payload'])

    def test_fnp_probe_uses_only_administrator_sampler_and_fixed_phase(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.handles = {'candidate-recipient': HANDLE}
        adapter.nodes = {'candidate-recipient': dict(EPOCH)}
        value = {'phase': 'before', 'managerInvocation': EPOCH['managerInvocation'],
                 'snapshot': {'observedMonotonicNs': 10}}
        adapter.control = types.SimpleNamespace(request=mock.Mock())
        self.assertIsNone(adapter._fnp_sample('before'))
        self.assertEqual('administrator-sampler-unavailable',
                         adapter.fnp_sample_failure['failureClass'])
        adapter.counter_sampler = mock.Mock(return_value=value)
        self.assertEqual(value, adapter._fnp_sample('before'))
        adapter.counter_sampler.assert_called_once_with('before')
        adapter.control.request.assert_not_called()
        self.assertIsNone(adapter._fnp_sample('after'))
        self.assertEqual({'phase': 'after', 'failureClass': 'response-binding-rejected'},
                         adapter.fnp_sample_failure)
        adapter.counter_sampler.side_effect = workload.runtime.RuntimeFailure('private detail')
        self.assertIsNone(adapter._fnp_sample('before'))
        self.assertEqual({'phase': 'before', 'failureClass': 'RuntimeFailure'},
                         adapter.fnp_sample_failure)
        self.assertNotIn('private detail', str(adapter.fnp_sample_failure))
        adapter.control.request.assert_not_called()

    def test_restarted_sender_peer_checks_both_current_endpoints(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.nodes = {
            'candidate-sender': {'reference': {'identity': 'new-sender'}},
            'relay-no-apps': {'reference': {'identity': 'relay'}}}
        sender, relay = object(), object()
        adapter.remaining = mock.Mock(return_value=170)
        adapter.client = mock.Mock(side_effect=lambda role: nullcontext({
            'candidate-sender': sender, 'relay-no-apps': relay}[role]))
        with (mock.patch.object(workload.runtime, 'absolute_deadline', return_value=nullcontext()) as bound,
              mock.patch.object(workload.runtime.interop, 'wait_for_peer_connection') as connected):
            adapter.wait_restarted_sender_peer()
        adapter.client.assert_has_calls([mock.call('candidate-sender'), mock.call('relay-no-apps')])
        bound.assert_called_once_with(170)
        connected.assert_called_once_with(sender, relay, 'new-sender', 'relay', 150)

    def test_positive_result_requires_final_sample_of_each_running_daemon(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.nodes = {'candidate-sender': dict(EPOCH)}
        adapter.apps = {('candidate-sender', 'mail-prototype'): types.SimpleNamespace(
            observe_worker=mock.Mock(return_value={'hostPid': 102, 'namespacePid': 3,
                'startTicks': 202, 'managerInvocation': EPOCH['managerInvocation'],
                'javaHostPid': 103, 'javaStartTicks': 203,
                'provenance': 'controller-kernel-sample'}))}
        adapter.outcomes = {'network-chk': 'observed'}
        adapter.start = mock.Mock()
        adapter.connect = mock.Mock()
        adapter.capture_probe_target_roster = mock.Mock()
        adapter.probe_observer_control = mock.Mock()
        adapter.probe_arbitrary_endpoint = mock.Mock()
        adapter.provision_apps = mock.Mock()
        adapter.restart_with_witness = mock.Mock(return_value={**EPOCH, 'generation': 'e' * 64,
                                                               'managerInvocation': 'f' * 32})
        adapter.wait_restarted_sender_peer = mock.Mock()
        adapter.content_chk = mock.Mock()
        adapter._fnp_sample = mock.Mock(return_value=None)
        adapter.cleanup = mock.Mock(return_value='complete')
        def observe(role):
            if role == 'previous':
                raise workload.runtime.RuntimeFailure('role-daemon-epoch-changed')
        adapter.observe = mock.Mock(side_effect=observe)
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'role-daemon-epoch-changed'):
            adapter.run_positive()
        self.assertEqual(2, adapter.content_chk.call_count)
        self.assertEqual([mock.call('candidate-sender'), mock.call('candidate-recipient'),
                          mock.call('previous')], adapter.observe.call_args_list)
        adapter.cleanup.assert_called_once_with()

    def test_successful_positive_sequence_leaves_roles_only_for_administrator_teardown(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.nodes = {'candidate-sender': {'generation': 'old',
            'managerInvocation': 'a' * 32, 'bootId': 'boot'}}
        adapter.apps = {('candidate-sender', 'mail-prototype'): types.SimpleNamespace(
            observe_worker=mock.Mock(return_value={'hostPid': 102, 'namespacePid': 3,
                'startTicks': 202, 'managerInvocation': 'a' * 32,
                'javaHostPid': 103, 'javaStartTicks': 203,
                'provenance': 'controller-kernel-sample'}))}
        adapter.outcomes = {'network-chk': 'observed'}
        adapter.control_exchanges = {}
        adapter.expected_jdk_digests = {}
        adapter.restart_context = adapter.restart_window = None
        adapter.start = mock.Mock()
        adapter.connect = mock.Mock()
        adapter.capture_probe_target_roster = mock.Mock()
        adapter.probe_observer_control = mock.Mock()
        adapter.probe_arbitrary_endpoint = mock.Mock()
        adapter.provision_apps = mock.Mock()
        adapter.restart_with_witness = mock.Mock(return_value={
            'generation': 'new', 'managerInvocation': 'b' * 32, 'bootId': 'boot'})
        adapter.wait_restarted_sender_peer = mock.Mock()
        adapter.content_chk = mock.Mock()
        ordering = mock.Mock()
        ordering.attach_mock(adapter.content_chk, 'content')
        ordering.attach_mock(adapter.wait_restarted_sender_peer, 'peer')
        adapter._fnp_sample = mock.Mock(return_value=None)
        adapter.observe = mock.Mock(return_value={'state': 'running'})
        adapter.cleanup = mock.Mock(return_value='complete')
        with mock.patch.object(workload, 'kernel_roster', return_value={'roles': []}):
            result = adapter.run_positive(leave_running_for_administrator=True)
        self.assertTrue(result['newEpoch'])
        self.assertEqual('observed', result['contentRetrieval'])
        self.assertEqual([mock.call.content(), mock.call.peer(), mock.call.content()],
                         ordering.mock_calls)
        adapter.cleanup.assert_not_called()

    def test_missing_restarted_sender_peer_blocks_second_chk(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.nodes = {'candidate-sender': {'generation': 'old',
            'managerInvocation': 'a' * 32, 'bootId': 'boot'}}
        adapter.start = mock.Mock()
        adapter.connect = mock.Mock()
        adapter.capture_probe_target_roster = mock.Mock()
        adapter.probe_observer_control = mock.Mock()
        adapter.probe_arbitrary_endpoint = mock.Mock()
        adapter.provision_apps = mock.Mock()
        adapter.restart_with_witness = mock.Mock(return_value={
            'generation': 'new', 'managerInvocation': 'b' * 32, 'bootId': 'boot'})
        adapter.wait_restarted_sender_peer = mock.Mock(side_effect=workload.runtime.RuntimeFailure(
            'restarted-sender-peer-unconnected'))
        adapter.content_chk = mock.Mock()
        adapter.cleanup = mock.Mock(return_value='complete')
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure,
                                    'restarted-sender-peer-unconnected'):
            adapter.run_positive()
        adapter.content_chk.assert_called_once_with()
        adapter.cleanup.assert_called_once_with()

    def test_failed_role_readiness_is_diagnosed_before_cleanup(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        order = []

        def fail_start(role):
            adapter.active_start_role = role
            adapter.active_start_stage = 'fcp-get-node'
            order.append('start')
            raise workload.runtime.RuntimeFailure('workload-daemon-readiness-timeout')

        def diagnose(role, stage):
            order.append('diagnose-' + role + '-' + stage)
            raise ValueError('diagnostic-unavailable')

        adapter.start = fail_start
        adapter.cleanup = mock.Mock(side_effect=lambda: order.append('cleanup') or 'complete')
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure,
                                    'workload-daemon-readiness-timeout'):
            adapter.run_positive(on_start_failure=diagnose)
        self.assertEqual(['start', 'diagnose-candidate-sender-fcp-get-node', 'cleanup'], order)

    def test_output_group_preparation_starts_real_roles_without_positive_traffic(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.nodes = {}
        adapter.expected_jdk_digests = {role: JDK for role in workload.runtime.ROLES}

        def start(role):
            adapter.nodes[role] = {'role': role}

        adapter.start = mock.Mock(side_effect=start)
        adapter.observe = mock.Mock(return_value={'state': 'running'})
        adapter.connect = mock.Mock()
        adapter.provision_apps = mock.Mock()
        adapter.content_chk = mock.Mock()
        adapter.cleanup = mock.Mock(return_value='complete')
        with mock.patch.object(workload, 'kernel_roster', return_value={'roles': []}):
            result = adapter.run_group_preparation('output-symlink',
                leave_running_for_administrator=True)
        self.assertEqual([mock.call(role) for role in workload.runtime.ROLES],
                         adapter.start.call_args_list)
        self.assertEqual(4, adapter.observe.call_count)
        self.assertEqual('output-symlink', result['groupPreparation'])
        self.assertEqual('not-executed-group', result['contentRetrieval'])
        self.assertFalse(result['newEpoch'])
        adapter.connect.assert_not_called()
        adapter.provision_apps.assert_not_called()
        adapter.content_chk.assert_not_called()
        adapter.cleanup.assert_not_called()

    def test_partial_launch_preparation_keeps_unstarted_roles_absent(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.nodes = {}
        adapter.expected_jdk_digests = {role: JDK for role in workload.runtime.ROLES}
        adapter.daemon_epochs = {}

        def start(role):
            adapter.nodes[role] = {'role': role}
            adapter.daemon_epochs[role] = {'hostPid': 100 + len(adapter.nodes)}

        adapter.start = mock.Mock(side_effect=start)
        adapter.observe = mock.Mock(return_value={'state': 'running'})
        adapter.cleanup = mock.Mock(return_value='complete')
        with mock.patch.object(workload, 'principal_row',
                               side_effect=lambda role, *_: {'role': role}):
            result = adapter.run_group_preparation('partial-launch',
                leave_running_for_administrator=True)
        self.assertEqual([mock.call(role) for role in workload.runtime.ROLES[:2]],
                         adapter.start.call_args_list)
        self.assertEqual(2, adapter.observe.call_count)
        self.assertEqual(2, result['topologyRoles'])
        self.assertEqual([{'role': role} for role in workload.runtime.ROLES[:2]],
                         result['partialRoleRoster'])
        self.assertNotIn('roleKernelRoster', result)
        adapter.cleanup.assert_not_called()

    def test_lost_start_barrier_binds_first_invocation_before_retry(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.handles = {'candidate-sender': HANDLE}
        adapter.nodes = {}
        adapter.expected_jdk_digests = {role: JDK for role in workload.runtime.ROLES}
        generation, invocation = 'c' * 64, 'd' * 32
        before = {'phase': 'lost-start-before', 'role': 'candidate-sender',
                  'observedMonotonicNs': 10}
        intent = {'phase': 'lost-start-intent', 'role': 'candidate-sender',
                  'generation': generation, 'managerInvocation': invocation,
                  'observedMonotonicNs': 40}
        dropped = {'requestDigest': 'e' * 64, 'sendStartedNs': 20,
                   'sendFinishedNs': 30}
        adapter.lost_start_sampler = mock.Mock(side_effect=[before, intent])
        adapter.control = types.SimpleNamespace(drop_start_response=mock.Mock(
            return_value=dropped))
        adapter.remaining = mock.Mock(return_value=180)
        adapter.start = mock.Mock(side_effect=lambda role: adapter.nodes.update({
            role: {'generation': generation, 'managerInvocation': invocation}}))
        adapter.observe = mock.Mock(return_value={'state': 'running'})
        adapter.cleanup = mock.Mock(return_value='complete')
        order = mock.Mock()
        order.attach_mock(adapter.lost_start_sampler, 'barrier')
        order.attach_mock(adapter.control.drop_start_response, 'drop')
        order.attach_mock(adapter.start, 'start')
        with mock.patch.object(workload, 'kernel_roster', return_value={'roles': []}):
            result = adapter.run_group_preparation('lost-start-response',
                leave_running_for_administrator=True)
        self.assertEqual([mock.call.barrier('before'), mock.call.drop(HANDLE),
                          mock.call.barrier('intent'),
                          *(mock.call.start(role) for role in workload.runtime.ROLES)],
                         order.mock_calls)
        self.assertEqual({'administratorBefore': before, 'droppedRequest': dropped,
                          'administratorBarrier': intent}, result['lostStartResponse'])
        adapter.cleanup.assert_not_called()
        intent['managerInvocation'] = 'f' * 32
        adapter.lost_start_sampler = mock.Mock(side_effect=[before, intent])
        with mock.patch.object(workload, 'kernel_roster', return_value={'roles': []}), \
                self.assertRaisesRegex(workload.runtime.RuntimeFailure,
                                            'lost-start-duplicate-invocation'):
            adapter.run_group_preparation('lost-start-response')
        adapter.cleanup.assert_called_once()

    def test_authority_preparation_binds_signed_app_session_for_role_origin_probe(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.nodes = {}
        adapter.apps = {}
        adapter.expected_jdk_digests = {role: JDK for role in workload.runtime.ROLES}
        adapter.start = mock.Mock(side_effect=lambda role: adapter.nodes.update({role: {}}))
        adapter.observe = mock.Mock(return_value={'state': 'running'})
        adapter.capture_probe_target_roster = mock.Mock()
        adapter.probe_observer_control = mock.Mock()
        adapter.probe_arbitrary_endpoint = mock.Mock()
        def provision():
            adapter.apps = {('candidate-sender', 'mail-prototype'):
                types.SimpleNamespace(session='private-session',
                    origin='http://127.0.0.1:12345',
                    observe_worker=lambda: {'hostPid': 101}),
                ('candidate-recipient', 'mail-prototype'): object(),
                ('candidate-sender', 'pr315-probe'):
                    types.SimpleNamespace(observe_worker=lambda: {
                        'provenance': 'controller-kernel-sample'})}
        adapter.provision_apps = mock.Mock(side_effect=provision)
        adapter.remaining = mock.Mock(return_value=180)
        adapter.origin_handoff = mock.Mock(return_value={
            'phase': 'hostile-origin-handoff',
            'sessionDigest': hashlib.sha256(b'private-session').hexdigest(),
            'originDigest': hashlib.sha256(b'http://127.0.0.1:12345').hexdigest()})
        adapter.content_chk = mock.Mock()
        adapter.cleanup = mock.Mock(return_value='complete')
        order = mock.Mock()
        order.attach_mock(adapter.capture_probe_target_roster, 'roster')
        order.attach_mock(adapter.probe_observer_control, 'observer')
        order.attach_mock(adapter.probe_arbitrary_endpoint, 'endpoint')
        order.attach_mock(adapter.provision_apps, 'apps')
        with mock.patch.object(workload, 'kernel_roster', return_value={'roles': []}):
            result = adapter.run_group_preparation('authority',
                leave_running_for_administrator=True)
        self.assertEqual('authority', result['groupPreparation'])
        self.assertEqual([mock.call.roster(), mock.call.observer(),
                          mock.call.endpoint(), mock.call.apps()],
                         order.mock_calls)
        self.assertEqual(3, result['signedAppWorkers'])
        self.assertEqual(hashlib.sha256(b'private-session').hexdigest(),
                         result['hostileOriginSessionDigest'])
        self.assertNotIn('private-session', json.dumps(result))
        adapter.origin_handoff.assert_called_once_with(
            'private-session', 'http://127.0.0.1:12345')
        self.assertEqual('controller-kernel-sample',
                         result['probeAppKernelProcess']['provenance'])
        adapter.provision_apps.assert_called_once_with()
        adapter.content_chk.assert_not_called()
        adapter.cleanup.assert_not_called()

    def test_network_app_preparation_starts_normal_signed_probe_without_chk(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.nodes = {}
        adapter.apps = {}
        adapter.expected_jdk_digests = {role: JDK for role in workload.runtime.ROLES}
        adapter.start = mock.Mock(side_effect=lambda role: adapter.nodes.update({role: {}}))
        adapter.observe = mock.Mock(return_value={'state': 'running'})
        adapter.capture_probe_target_roster = mock.Mock()

        def provision():
            adapter.apps = {('candidate-sender', 'mail-prototype'): object(),
                ('candidate-recipient', 'mail-prototype'):
                    types.SimpleNamespace(origin='http://127.0.0.1:12345',
                        observe_worker=lambda: {
                        'provenance': 'controller-kernel-sample'}),
                ('candidate-sender', 'pr315-probe'): types.SimpleNamespace(
                    observe_worker=lambda: {'provenance': 'controller-kernel-sample'})}

        adapter.provision_apps = mock.Mock(side_effect=provision)
        adapter.content_chk = mock.Mock()
        adapter.cleanup = mock.Mock(return_value='complete')
        with mock.patch.object(workload, 'kernel_roster', return_value={'roles': []}):
            result = adapter.run_group_preparation('network-app',
                leave_running_for_administrator=True)
        self.assertEqual('network-app', result['groupPreparation'])
        self.assertEqual(3, result['signedAppWorkers'])
        self.assertEqual('controller-kernel-sample',
                         result['probeAppKernelProcess']['provenance'])
        self.assertEqual('controller-kernel-sample',
                         result['recipientMailAppKernelProcess']['provenance'])
        self.assertEqual(hashlib.sha256(b'http://127.0.0.1:12345').hexdigest(),
                         result['recipientMailUiOriginDigest'])
        adapter.capture_probe_target_roster.assert_called_once_with()
        adapter.provision_apps.assert_called_once_with()
        adapter.content_chk.assert_not_called()
        adapter.cleanup.assert_not_called()

    def test_resource_group_prepares_signed_app_without_running_positive_chk(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.nodes = {}
        adapter.apps = {}
        adapter.expected_jdk_digests = {role: JDK for role in workload.runtime.ROLES}
        adapter.start = mock.Mock(side_effect=lambda role: adapter.nodes.update({role: {}}))
        adapter.observe = mock.Mock(return_value={'state': 'running'})
        adapter.capture_probe_target_roster = mock.Mock()

        def provision():
            adapter.apps = {('candidate-sender', 'mail-prototype'): object(),
                ('candidate-recipient', 'mail-prototype'): object(),
                ('candidate-sender', 'pr315-probe'): types.SimpleNamespace(
                    observe_worker=lambda: {'provenance': 'controller-kernel-sample'})}

        adapter.provision_apps = mock.Mock(side_effect=provision)
        adapter.content_chk = mock.Mock()
        adapter.cleanup = mock.Mock(return_value='complete')
        with mock.patch.object(workload, 'kernel_roster', return_value={'roles': []}):
            result = adapter.run_group_preparation('resource-exhaustion',
                leave_running_for_administrator=True)
        self.assertEqual('resource-exhaustion', result['groupPreparation'])
        self.assertEqual(3, result['signedAppWorkers'])
        self.assertEqual('controller-kernel-sample',
                         result['probeAppKernelProcess']['provenance'])
        adapter.capture_probe_target_roster.assert_called_once_with()
        adapter.provision_apps.assert_called_once_with()
        adapter.content_chk.assert_not_called()
        adapter.cleanup.assert_not_called()

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
        adapter.daemon_epochs = {'candidate-sender': {'startTicks': 201}}
        adapter.deadline = 12345
        adapter.stop = mock.Mock()
        def start(_role):
            adapter.daemon_epochs['candidate-sender'] = {'startTicks': 301}
            return {**EPOCH, 'generation': 'e' * 64, 'managerInvocation': 'f' * 32}
        adapter.start = mock.Mock(side_effect=start)
        result = adapter.restart('candidate-sender')
        self.assertEqual('e' * 64, result['generation'])
        self.assertEqual(12345, adapter.deadline)
        adapter.start.side_effect = lambda _role: {**EPOCH, 'generation': 'e' * 64}
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'restart-epoch-invalid'):
            adapter.restart('candidate-sender')
        adapter.daemon_epochs['candidate-sender'] = {'startTicks': 301}
        def reused_daemon(_role):
            adapter.daemon_epochs['candidate-sender'] = {'startTicks': 301}
            return {**EPOCH, 'generation': 'e' * 64, 'managerInvocation': 'f' * 32}
        adapter.start.side_effect = reused_daemon
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'restart-epoch-invalid'):
            adapter.restart('candidate-sender')

    def test_restart_retains_exact_two_signed_apps_and_restarts_probe_worker(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.nodes = {'candidate-sender': dict(EPOCH)}
        adapter.private = {'nodes': {'candidate-sender': {'apps': [
            {'appId': 'mail-prototype'}, {'appId': 'pr315-probe'}]}}}
        adapter.daemon_epochs = {'candidate-sender': {'startTicks': 201}}
        adapter.stop = mock.Mock()
        def start(_role):
            adapter.daemon_epochs['candidate-sender'] = {'startTicks': 301}
            return {**EPOCH, 'generation': 'e' * 64, 'managerInvocation': 'f' * 32}
        adapter.start = mock.Mock(side_effect=start)
        def mail_request(method, path, *args):
            if path == '/api/v1/apps':
                return 200, {'apps': [{'appId': 'mail-prototype'}, {'appId': 'pr315-probe'}]}
            return 200, {'runtime': {'running': True}}
        mail = types.SimpleNamespace(password='stale', host_bootstrap=mock.Mock(),
            request=mock.Mock(side_effect=mail_request), observe_worker=mock.Mock(),
            refresh_session=mock.Mock())
        mail.host_bootstrap.side_effect = lambda: setattr(mail, 'password', 'current')
        probe = types.SimpleNamespace(password='stale', request=mock.Mock(), observe_worker=mock.Mock())
        def probe_request(method, _path):
            if method == 'GET':
                return 200, {'runtime': {'running': False}}
            return (201, {}) if probe.password == 'current' else (403, {})
        probe.request.side_effect = probe_request
        adapter.apps = {('candidate-sender', 'mail-prototype'): mail,
                        ('candidate-sender', 'pr315-probe'): probe}
        adapter.restart('candidate-sender')
        probe.request.assert_has_calls([
            mock.call('GET', '/api/v1/apps/pr315-probe/runtime'),
            mock.call('POST', '/api/v1/apps/pr315-probe/start')])
        probe.observe_worker.assert_called_once_with()
        self.assertEqual('current', probe.password)
        adapter.daemon_epochs['candidate-sender'] = {'startTicks': 201}
        mail.request.side_effect = lambda method, path, *args: (
            (200, {'apps': [{'appId': 'mail-prototype'}]}) if path == '/api/v1/apps'
            else (200, {'runtime': {'running': True}}))
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'installed-app-not-retained'):
            adapter.restart('candidate-sender')
        adapter.daemon_epochs['candidate-sender'] = {'startTicks': 201}
        mail.request.side_effect = mail_request
        probe.request.side_effect = [(200, {'runtime': {'running': False}}), (409, {'private': 'must-not-copy'})]
        with self.assertRaisesRegex(workload.runtime.RuntimeFailure, 'restart-probe-start-http-409') as raised:
            adapter.restart('candidate-sender')
        self.assertNotIn('must-not-copy', str(raised.exception))

    def test_restart_context_uses_real_before_after_controller_epochs(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        before = sample()
        after = copy.deepcopy(before)
        after['managerInvocation'] = 'e' * 32
        after['cgroupIdentity'] = [1, 100]
        after['processes'][1]['startTicks'] = 301
        after['stateDigest'] = before['stateDigest'] = 'b' * 64
        after['deadlineMonotonicNs'] = before['deadlineMonotonicNs'] = 1000
        before['observedMonotonicNs'], after['observedMonotonicNs'] = 10, 20
        adapter.expected_jdk_digests = {'candidate-sender': JDK}
        adapter.daemon_epochs = {'candidate-sender': workload.bind_daemon(before, JDK)}
        adapter.observe = mock.Mock(side_effect=[before, after])
        def restarted(role):
            self.assertEqual('candidate-sender', role)
            adapter.daemon_epochs[role] = workload.bind_daemon(after, JDK)
            return {'state': 'running'}
        adapter.restart = mock.Mock(side_effect=restarted)
        with mock.patch.object(workload.pwd, 'getpwnam', return_value=types.SimpleNamespace(
                pw_uid=2000, pw_gid=2000)):
            self.assertEqual({'state': 'running'}, adapter.restart_with_witness('candidate-sender'))
        context = adapter.restart_context
        self.assertEqual((10, 20), (context['before']['observedMonotonicNs'],
                                    context['after']['observedMonotonicNs']))
        self.assertEqual('b' * 64, context['after']['stateDigest'])
        self.assertNotEqual(context['before']['roleIdentity']['cgroupDigest'],
                            context['after']['roleIdentity']['cgroupDigest'])
        self.assertLess(adapter.restart_window['startedMonotonicNs'],
                        adapter.restart_window['finishedMonotonicNs'])

    def test_unstarted_role_cleanup_does_not_forge_node_epoch_event(self):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.handles = {'candidate-sender': HANDLE}
        adapter.nodes = {}
        adapter.daemon_epochs = {}
        adapter._journal_started_roles = set()
        adapter.control = types.SimpleNamespace(request=mock.Mock(return_value={**EPOCH, 'state': 'quiescent'}))
        adapter.emit = mock.Mock()
        adapter.stop('candidate-sender')
        adapter.emit.assert_not_called()
        adapter.nodes['candidate-sender'] = dict(EPOCH)
        adapter._journal_started_roles.add('candidate-sender')
        adapter.stop('candidate-sender')
        adapter.emit.assert_called_once_with('node-stop', role='candidate-sender')
        self.assertFalse(adapter._journal_started_roles)

    def test_request_shape_rejected_before_socket_allocation(self):
        with mock.patch.object(workload.socket, 'socket') as factory:
            for method, handle in (('exec', HANDLE), ('observe', '/proc/1'), ('connect-19403', HANDLE)):
                with self.assertRaises(workload.runtime.RuntimeFailure):
                    workload.WorkloadClient().request(method, handle)
            with self.assertRaises(workload.runtime.RuntimeFailure):
                workload.WorkloadClient().drop_start_response('/proc/1')
            factory.assert_not_called()

    def test_denied_observe_retains_exact_controller_exchange_digest(self):
        denied = b'{"error":"restricted-workload-request-failed"}\n'
        sent = []
        channel = mock.Mock()
        channel.getsockopt.return_value = struct.pack('3i', 123, 0, 0)
        channel.recvmsg.return_value = (denied, [], 0, None)
        channel.sendall.side_effect = sent.append
        client = workload.WorkloadClient()
        with mock.patch.object(workload.socket, 'SO_PEERCRED', 17, create=True), \
                mock.patch.object(workload.socket, 'MSG_CMSG_CLOEXEC', 0,
                                  create=True), \
                mock.patch.object(workload.socket, 'socket', return_value=channel):
            with self.assertRaisesRegex(workload.runtime.RuntimeFailure,
                                        'controller-request-rejected'):
                client.request('observe', HANDLE)
        self.assertEqual(1, len(sent))
        self.assertEqual({'method': 'observe',
            'requestDigest': hashlib.sha256(sent[0]).hexdigest(),
            'responseDigest': hashlib.sha256(denied).hexdigest()},
            client.last_exchange)


class ReadinessDeadlineTests(unittest.TestCase):
    def test_late_observer_uses_original_deadline_not_a_fresh_budget(self):
        with mock.patch.object(workload.time, 'monotonic_ns', return_value=10 * 10**9):
            self.assertEqual(20, workload.retained_deadline({'deadlineMonotonicNs': 20 * 10**9}, 30))
        with mock.patch.object(workload.time, 'monotonic_ns', return_value=19 * 10**9):
            self.assertEqual(20, workload.retained_deadline({'deadlineMonotonicNs': 20 * 10**9}, 30))

    def test_missing_expired_extended_or_noninteger_deadline_rejects(self):
        with mock.patch.object(workload.time, 'monotonic_ns', return_value=10 * 10**9):
            for value in (None, True, 20e9, 0, 10 * 10**9, 40 * 10**9 + 1):
                with self.subTest(deadline=value), self.assertRaisesRegex(
                        workload.runtime.RuntimeFailure, 'retained-deadline'):
                    workload.retained_deadline({'deadlineMonotonicNs': value}, 30)

    def adapter(self, seconds):
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.handles = {'candidate-sender': HANDLE}
        adapter.nodes = {}
        adapter.daemon_epochs = {}
        adapter.expected_jdk_digests = {'candidate-sender': JDK}
        def request(method, _handle):
            return {**EPOCH, 'state': 'running'} if method == 'start' else sample()
        adapter.control = types.SimpleNamespace(request=mock.Mock(side_effect=request))
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
        self.assertEqual([mock.call('start', HANDLE), mock.call('observe', HANDLE)],
                         adapter.control.request.call_args_list)
        self.assertEqual(201, adapter.daemon_epochs['candidate-sender']['startTicks'])
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


class PeerConnectionTests(unittest.TestCase):
    def adapter(self, relay_connected=True):
        frame = workload.runtime.interop.FcpFrame
        endpoints = {}
        for role in workload.runtime.ROLES:
            endpoint = mock.Mock(name=role)
            endpoint.references = {}
            endpoint.frames = []

            def add(name, fields, expected, selected=endpoint):
                self.assertEqual('AddPeer', name)
                self.assertEqual({'Peer'}, expected)
                selected.references[fields['identity']] = dict(fields)
                return frame('Peer', dict(fields))

            def send(name, fields, selected=endpoint, selected_role=role):
                self.assertEqual('ListPeers', name)
                self.assertEqual('true', fields['WithVolatile'])
                status = 'CONNECTED' if relay_connected or selected_role != 'relay-no-apps' else 'CONNECTING'
                selected.frames = [frame('Peer', {'identity': identity, 'volatile.status': status})
                                   for identity in selected.references]
                selected.frames.append(frame('EndListPeers', {}))

            endpoint.read_until_after_send.side_effect = add
            endpoint.send.side_effect = send
            endpoint.read_message.side_effect = lambda _timeout, selected=endpoint: selected.frames.pop(0)
            endpoints[role] = endpoint
        adapter = object.__new__(workload.InstalledWorkloadAdapter)
        adapter.nodes = {role: {'reference': {'identity': role}} for role in workload.runtime.ROLES}
        adapter.deadline = time.monotonic() + 180

        @contextmanager
        def client(role):
            yield endpoints[role]

        adapter.client = client
        return adapter, endpoints

    def test_real_peer_helper_checks_both_endpoints_of_each_fixed_link(self):
        adapter, endpoints = self.adapter()
        original_deadline = adapter.deadline
        adapter.connect()
        self.assertEqual(original_deadline, adapter.deadline)
        self.assertEqual(3, endpoints['relay-no-apps'].send.call_count)
        for role in workload.runtime.ROLES[:-1]:
            endpoints[role].send.assert_called_once()
            self.assertEqual({'relay-no-apps'}, set(endpoints[role].references))
        self.assertEqual(set(workload.runtime.ROLES[:-1]), set(endpoints['relay-no-apps'].references))

    def test_one_sided_connected_status_is_not_peer_connection_success(self):
        adapter, endpoints = self.adapter(relay_connected=False)
        now = [0]
        clock = types.SimpleNamespace(monotonic=lambda: now[0], sleep=lambda _: now.__setitem__(0, 150))
        with mock.patch.object(workload.runtime.interop, 'time', clock), \
                self.assertRaisesRegex(workload.runtime.interop.InteropFailure, 'CONNECTED on both nodes'):
            adapter.connect()
        endpoints['candidate-sender'].send.assert_called_once()
        endpoints['relay-no-apps'].send.assert_called_once()
        endpoints['candidate-recipient'].send.assert_not_called()


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

    def test_lost_start_sends_only_fixed_request_and_closes_before_response(self):
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(self.path)
        listener.listen(1)
        listener.settimeout(5)
        received, failures = [], []

        def serve():
            try:
                with listener.accept()[0] as channel:
                    channel.settimeout(5)
                    raw = bytearray()
                    while not raw.endswith(b'\n'):
                        raw.extend(channel.recv(4096))
                    received.append(bytes(raw))
                    received.append(channel.recv(1))
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            result = workload.WorkloadClient().drop_start_response(HANDLE)
        finally:
            thread.join(5)
            listener.close()
        self.assertFalse(thread.is_alive())
        self.assertEqual([], failures)
        request = b'{"method":"start","handle":"' + HANDLE.encode() + b'"}\n'
        self.assertEqual([request, b''], received)
        self.assertEqual(hashlib.sha256(request).hexdigest(), result['requestDigest'])
        self.assertLess(result['sendStartedNs'], result['sendFinishedNs'])

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
