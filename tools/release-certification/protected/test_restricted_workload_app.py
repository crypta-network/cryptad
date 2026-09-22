"""Scoped-process and listener-binding tests; synthetic proc data is not installed acceptance."""
import copy
import os
from pathlib import Path
import socket
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import restricted_workload_app as app

JAVA = 'sha256:' + 'a' * 64
OTHER = 'sha256:' + 'b' * 64
ROLE = 'candidate-sender'
RUNTIME = {'running': True, 'pid': 8, 'sandbox': {'provider': 'bubblewrap', 'active': True}}


def process(pid, parent, namespace_pids, namespace, java=False):
    return {'hostPid': pid, 'hostParentPid': parent, 'startTicks': pid * 100,
            'pidNamespace': namespace, 'namespacePids': namespace_pids,
            'executableDigest': JAVA if java else OTHER,
            'noNewPrivileges': True, 'effectiveCapabilities': 0}


class AppBindingTests(unittest.TestCase):
    def setUp(self):
        self.processes = {
            100: process(100, 90, [100, 4], 'pid:[5000]', java=True),
            110: process(110, 100, [110, 8], 'pid:[5000]'),
            120: process(120, 110, [120, 9, 1], 'pid:[5001]'),
            130: process(130, 120, [130, 10, 2], 'pid:[5001]', java=True),
        }
        self.called = []
        for owner, name, replacement in (
            (app, '_members', lambda role, deadline: sorted(self.processes)),
            (app, '_listener', lambda daemon, port, deadline: 9001),
            (app.workload, 'read', lambda path: {'javaDigest': JAVA}),
            (app.workload, 'account', lambda role: SimpleNamespace(pw_uid=60001)),
            (app.workload, '_process', self.observe),
        ):
            holder = patch.object(owner, name, replacement)
            holder.start()
            self.addCleanup(holder.stop)

    def observe(self, pid, role, uid):
        self.assertEqual(role, ROLE)
        self.assertEqual(uid, 60001)
        self.assertIn(pid, self.processes)
        self.called.append(pid)
        return copy.deepcopy(self.processes[pid])

    def test_namespace_pid_hint_resolves_scoped_worker_and_deeper_java(self):
        result = app.require_app_listener(ROLE, RUNTIME, 22000)
        self.assertEqual(result['daemon']['hostPid'], 100)
        self.assertEqual(result['worker']['hostPid'], 110)
        self.assertEqual(result['appJvm']['hostPid'], 130)
        self.assertEqual(result['listenerInode'], 9001)
        self.assertEqual(set(self.called), set(self.processes))
        for pid in self.processes:
            self.assertEqual(self.called.count(pid), 2)
        self.assertNotIn('executableDigest', result['appJvm'])

    def test_reported_host_pid_is_not_accepted_as_namespace_pid(self):
        runtime = {**RUNTIME, 'pid': 110}
        with self.assertRaises(app.workload.WorkloadError):
            app.require_app_listener(ROLE, runtime, 22000)
        self.assertNotIn(8, self.called)

    def test_exited_unrelated_helper_is_skipped_in_roster(self):
        self.processes[140] = process(140, 100, [140, 11], 'pid:[5000]')
        def sampled(pid, role, uid):
            if pid == 140:
                raise app.workload.ProcessExitedDuringSample()
            return self.observe(pid, role, uid)
        with patch.object(app.workload, '_process', sampled):
            result = app.require_app_listener(ROLE, RUNTIME, 22000)
        self.assertEqual(130, result['appJvm']['hostPid'])

    def test_required_process_exit_rejects_initial_and_final_binding(self):
        for required in (100, 110, 120, 130):
            for final in (False, True):
                self.called.clear()
                def sampled(pid, role, uid):
                    if pid == required and (not final or pid in self.called):
                        raise app.workload.ProcessExitedDuringSample()
                    return self.observe(pid, role, uid)
                with self.subTest(pid=required, final=final), \
                        patch.object(app.workload, '_process', sampled), \
                        self.assertRaises(app.workload.WorkloadError):
                    app.require_app_listener(ROLE, RUNTIME, 22000)

    def test_ownership_failure_in_roster_is_not_skipped(self):
        with patch.object(app.workload, '_process', side_effect=app.workload.WorkloadError('process-scope-changed')):
            with self.assertRaises(app.workload.WorkloadError):
                app.require_app_listener(ROLE, RUNTIME, 22000)

    def test_unsandboxed_or_nonrunning_report_is_denied_before_proc_scan(self):
        for runtime in ({**RUNTIME, 'running': False},
                        {**RUNTIME, 'sandbox': {'provider': 'none', 'active': True}},
                        {**RUNTIME, 'sandbox': {'provider': 'bubblewrap', 'active': False}},
                        {**RUNTIME, 'pid': True}):
            with self.subTest(runtime=runtime), self.assertRaises(app.workload.WorkloadError):
                app.require_app_listener(ROLE, runtime, 22000)
        self.assertEqual(self.called, [])

    def test_same_namespace_java_does_not_satisfy_app_sandbox(self):
        self.processes[130]['namespacePids'] = [130, 10]
        self.processes[130]['pidNamespace'] = 'pid:[5000]'
        with self.assertRaises(app.workload.WorkloadError):
            app.require_app_listener(ROLE, RUNTIME, 22000)

    def test_unrelated_nested_java_does_not_satisfy_worker_descendant(self):
        self.processes[130]['hostParentPid'] = 100
        with self.assertRaises(app.workload.WorkloadError):
            app.require_app_listener(ROLE, RUNTIME, 22000)

    def test_interpreter_descendant_hint_resolves_nested_init_or_java(self):
        for namespace_pid, host_pid in ((9, 120), (10, 130)):
            self.called.clear()
            with self.subTest(pid=namespace_pid):
                result = app.require_app_listener(ROLE, {**RUNTIME, 'pid': namespace_pid}, 22000)
                self.assertEqual(result['worker']['hostPid'], host_pid)
                self.assertEqual(result['appJvm']['hostPid'], 130)
                for pid in self.processes:
                    self.assertEqual(self.called.count(pid), 2)

    def test_nested_hint_cannot_bind_unrelated_java_or_outer_namespace(self):
        for field, value in (('hostParentPid', 90), ('pidNamespace', 'pid:[5000]')):
            original = self.processes[130][field]
            self.processes[130][field] = value
            with self.subTest(field=field), self.assertRaises(app.workload.WorkloadError):
                app.require_app_listener(ROLE, {**RUNTIME, 'pid': 10}, 22000)
            self.processes[130][field] = original

    def test_missing_deeper_java_rejects_reported_bubblewrap_success(self):
        del self.processes[130]
        with self.assertRaises(app.workload.WorkloadError):
            app.require_app_listener(ROLE, RUNTIME, 22000)

    def test_capabilities_or_missing_no_new_privileges_reject_kernel_child(self):
        for field, value in (('effectiveCapabilities', 1), ('noNewPrivileges', False)):
            original = self.processes[130][field]
            self.processes[130][field] = value
            with self.subTest(field=field), self.assertRaises(app.workload.WorkloadError):
                app.require_app_listener(ROLE, RUNTIME, 22000)
            self.processes[130][field] = original

    def test_pid_reuse_during_binding_is_rejected(self):
        def changed(pid, role, uid):
            value = self.observe(pid, role, uid)
            if self.called.count(pid) > 1 and pid == 130:
                value['startTicks'] += 1
            return value
        with patch.object(app.workload, '_process', changed), self.assertRaises(app.workload.WorkloadError):
            app.require_app_listener(ROLE, RUNTIME, 22000)

    def test_ancestor_reparent_during_binding_is_rejected(self):
        def changed(pid, role, uid):
            value = self.observe(pid, role, uid)
            if self.called.count(pid) > 1 and pid == 120:
                value['hostParentPid'] = 100
            return value
        with patch.object(app.workload, '_process', changed), self.assertRaises(app.workload.WorkloadError):
            app.require_app_listener(ROLE, RUNTIME, 22000)

    def test_listener_replacement_during_binding_is_rejected(self):
        with patch.object(app, '_listener', side_effect=[9001, 9002]), self.assertRaises(app.workload.WorkloadError):
            app.require_app_listener(ROLE, RUNTIME, 22000)

    def test_missing_trusted_java_identity_is_rejected(self):
        with patch.object(app.workload, 'read', return_value={}), self.assertRaises(app.workload.WorkloadError):
            app.require_app_listener(ROLE, RUNTIME, 22000)
        self.assertEqual(self.called, [])


class ProcListenerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.daemon = self.root / '100'
        (self.daemon / 'net').mkdir(parents=True)
        (self.daemon / 'fd').mkdir()
        holder = patch.object(app, 'PROC', self.root)
        holder.start()
        self.addCleanup(holder.stop)
        self.write_table('0100007F:55F0', '0A', '9001')
        (self.daemon / 'fd/7').symlink_to('socket:[9001]')

    def write_table(self, local, state, inode):
        # Relevant fields follow Linux /proc/net/tcp's actual column order.
        (self.daemon / 'net/tcp').write_text(
            'sl local_address rem_address st tx_queue rx_queue tr tm_when retrnsmt uid timeout inode\n'
            f'0: {local} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000 60001 0 {inode}\n')

    def test_real_bounded_reader_binds_table_inode_to_daemon_fd(self):
        self.assertEqual(app._listener({'hostPid': 100}, 22000, float('inf')), 9001)

    def test_jdk_ipv4_mapped_ipv6_socket_preserves_loopback_binding(self):
        self.write_table('0000000000000000FFFF00000100007F:55F0', '0A', '9001')
        (self.daemon / 'net/tcp').rename(self.daemon / 'net/tcp6')
        (self.daemon / 'net/tcp').write_text('header\n')
        self.assertEqual(app._listener({'hostPid': 100}, 22000, float('inf')), 9001)

    def test_ipv6_wildcard_is_not_an_approved_loopback_listener(self):
        self.write_table('00000000000000000000000000000000:55F0', '0A', '9001')
        (self.daemon / 'net/tcp').rename(self.daemon / 'net/tcp6')
        (self.daemon / 'net/tcp').write_text('header\n')
        with self.assertRaises(app.workload.WorkloadError):
            app._listener({'hostPid': 100}, 22000, float('inf'))

    def test_active_listener_owned_by_another_process_is_denied(self):
        (self.daemon / 'fd/7').unlink()
        unrelated = self.root / '110/fd'
        unrelated.mkdir(parents=True)
        (unrelated / '8').symlink_to('socket:[9001]')
        with self.assertRaises(app.workload.WorkloadError):
            app._listener({'hostPid': 100}, 22000, float('inf'))

    def test_wrong_bind_address_and_nonlistener_state_are_denied(self):
        for local, state in (('00000000:55F0', '0A'), ('0100007F:55F0', '01'), ('0100007F:55F1', '0A')):
            self.write_table(local, state, '9001')
            with self.subTest(local=local, state=state), self.assertRaises(app.workload.WorkloadError):
                app._listener({'hostPid': 100}, 22000, float('inf'))

    def test_ambiguous_reuseport_listener_is_denied(self):
        target = self.daemon / 'net/tcp'
        with target.open('a') as stream:
            stream.write(target.read_text().splitlines()[1] + '\n')
        with self.assertRaises(app.workload.WorkloadError):
            app._listener({'hostPid': 100}, 22000, float('inf'))

    def test_proc_table_over_budget_is_rejected_without_unbounded_read(self):
        (self.daemon / 'net/tcp').write_bytes(b'x' * (app.MAX_TCP_BYTES + 1))
        with self.assertRaises(app.workload.WorkloadError):
            app._listener({'hostPid': 100}, 22000, float('inf'))

    def test_fd_enumeration_limit_is_enforced_even_after_matching_inode(self):
        with patch.object(app, 'MAX_FDS', 1):
            (self.daemon / 'fd/8').symlink_to('socket:[9002]')
            with self.assertRaises(app.workload.WorkloadError):
                app._listener({'hostPid': 100}, 22000, float('inf'))

    def test_expired_absolute_deadline_prevents_proc_read(self):
        with patch.object(app.os, 'open') as opened, self.assertRaises(app.workload.WorkloadError):
            app._listener({'hostPid': 100}, 22000, -1)
        opened.assert_not_called()

    def test_cgroup_scope_rejects_nested_group(self):
        group = self.root / 'group'
        group.mkdir()
        (group / 'cgroup.procs').write_text('100\n110\n')
        (group / 'nested').mkdir()
        with patch.object(app.workload, 'group', return_value=group), self.assertRaises(app.workload.WorkloadError):
            app._members(ROLE, float('inf'))


class LocalKernelListenerTests(unittest.TestCase):
    @unittest.skipUnless(Path('/proc/self/net/tcp').exists(), 'Linux proc interface required')
    def test_actual_own_loopback_listener_matches_current_process_socket_inode(self):
        # Same-UID socket ownership only; this does not exercise installed role isolation.
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            expected = int(os.readlink('/proc/self/fd/' + str(listener.fileno()))[8:-1])
            actual = app._listener({'hostPid': os.getpid()}, listener.getsockname()[1],
                                   time.monotonic() + 5)
            self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
