"""Local cleanup ordering and retention tests; no installed systemd execution."""
from contextlib import contextmanager, ExitStack
import fcntl
import hashlib
import json
import os
import socket
import time
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import pr314_workload_driver as driver


class ObserverFailureTest(unittest.TestCase):
    def test_immediate_cause_survives_private_child_response(self):
        error = ValueError('workload-daemon-readiness-timeout')
        error.__cause__ = RuntimeError('controller-request-rejected')
        result = driver.observer_failure(error)
        self.assertEqual('controller-request-rejected', result['immediateCause']['privateDetail'])
        self.assertEqual('workload-daemon-readiness-timeout', result['privateDetail'])

    def test_unicode_and_cycles_cannot_overrun_retained_child_transcript(self):
        error = ValueError('😀' * 10000)
        error.__cause__ = RuntimeError('😀' * 10000)
        self.assertLess(len(json.dumps(driver.observer_failure(error)).encode()), 4096)
        error.__cause__ = error
        self.assertNotIn('immediateCause', driver.observer_failure(error))

    def test_deadline_diagnostic_retains_bounded_code_locations_without_locals_or_paths(self):
        namespace = {}
        exec(compile('def connect(depth):\n'
                     ' private_token = "never-export-this-token"\n'
                     ' if depth: return connect(depth - 1)\n'
                     ' raise RuntimeError("operation-deadline-exceeded")\n',
                     '/private-location/cross_version_workload.py', 'exec'), namespace)
        try:
            namespace['connect'](40)
        except RuntimeError as error:
            result = driver.observer_failure(error)
        self.assertEqual(8, len(result['privateCodeLocations']))
        self.assertTrue(all(value.startswith('cross_version_workload.py:connect:')
                            for value in result['privateCodeLocations']))
        encoded = json.dumps(result)
        self.assertNotIn('private-location', encoded)
        self.assertNotIn('never-export-this-token', encoded)
        self.assertLess(len(encoded.encode()), 4096)


class CleanupTest(unittest.TestCase):
    def test_startup_measurement_has_fixed_ceiling_and_cannot_extend_campaign(self):
        self.assertEqual(190, driver.readiness_deadline(999 * 10**9, 100))
        self.assertEqual(220, driver.readiness_deadline(999 * 10**9, 100, True))
        self.assertEqual(115, driver.readiness_deadline(115 * 10**9, 100, True))
        self.assertEqual(90, driver.readiness_deadline(90 * 10**9, 100, True))

    def test_startup_measurement_never_constructs_workload_or_claims_positive(self):
        # None is deliberately unusable as a workload selection: diagnostic completion
        # must not open a journal, construct an adapter, or start any role.
        with patch.object(driver, 'controller_ready') as ready, \
                patch.object(driver.time, 'monotonic', return_value=146):
            value = driver.observer_sequence(None, None, None, 999 * 10**9, 100, True)
        ready.assert_called_once_with(220)
        self.assertEqual(46, value['startupElapsedSeconds'])
        self.assertFalse(value['installedPositiveExecuted'])
        self.assertNotIn('contentRetrieval', value)
        self.assertEqual('startup-measurement-not-workload-acceptance', value['classification'])

    def test_startup_capture_uses_only_fixed_private_record(self):
        workload = SimpleNamespace(read=Mock(return_value={'stage': 'entry'}))
        value = driver.controller_startup_snapshot(workload)
        workload.read.assert_called_once_with(Path('/run/cryptad-workload/startup.json'))
        self.assertEqual('captured', value['status'])
        self.assertEqual({'stage': 'entry'}, value['record'])
        self.assertEqual('private-startup-diagnostic-not-acceptance', value['classification'])

    def test_startup_capture_failure_does_not_prevent_cleanup(self):
        for error in (FileNotFoundError(), ValueError('untrusted record')):
            with self.subTest(error=type(error).__name__):
                workload = SimpleNamespace(read=Mock(side_effect=error))
                self.assertEqual({'status': 'unavailable-not-quiescence-proof'},
                                 driver.controller_startup_snapshot(workload))

    def test_terminal_fence_waits_for_owner_transaction_before_controller_stop(self):
        events = []
        with tempfile.TemporaryDirectory() as directory:
            lease = Path(directory) / 'lease'
            with lease.open('w') as controller:
                fcntl.flock(controller, fcntl.LOCK_EX | fcntl.LOCK_NB)

                @contextmanager
                def locked():
                    with lease.open('r') as observer:
                        fcntl.flock(observer, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        yield

                # Reproduce the exact busy-lease failure of the previous first step.
                with self.assertRaises(BlockingIOError), locked():
                    pass

                def stop(command, **kwargs):
                    self.assertEqual(['/usr/bin/systemctl', 'stop',
                                      'cryptad-workload-controller.service'], command)
                    self.assertTrue(kwargs['check'])
                    self.assertGreater(kwargs['timeout'], 0)
                    self.assertLessEqual(kwargs['timeout'], 110)
                    events.append('controller-stop')
                    fcntl.flock(controller, fcntl.LOCK_UN)

                def reconcile():
                    with locked():
                        events.append('reconcile')

                calls = 0
                def fence():
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        raise BlockingIOError('owner transaction in progress')
                    fcntl.flock(controller, fcntl.LOCK_UN)
                    events.append('owner-request-completed')
                    with locked():
                        events.append('fence')

                workload = SimpleNamespace(ROLES=('sender', 'recipient'), locked=locked,
                    fence_campaign=fence, reconcile=reconcile, quiescent=lambda role: events.append(role) or True)
                network = SimpleNamespace(teardown=lambda: events.append('teardown'))
                with patch.object(driver.subprocess, 'run', side_effect=stop), \
                        patch.dict('sys.modules', {'restricted_workload_network': network}):
                    driver.cleanup(workload)
        self.assertEqual(['owner-request-completed', 'fence', 'controller-stop', 'reconcile',
                          'sender', 'recipient', 'teardown'], events)

    def test_uncertain_shutdown_retains_network_and_state(self):
        from contextlib import nullcontext
        for failure in ('fence', 'stop', 'reconcile', 'quiescence'):
            workload = SimpleNamespace(ROLES=('sender',), locked=nullcontext,
                fence_campaign=Mock(), reconcile=Mock(), quiescent=Mock(return_value=failure != 'quiescence'))
            network = SimpleNamespace(teardown=Mock())
            if failure == 'fence':
                workload.fence_campaign.side_effect = ValueError('fence failed')
            if failure == 'reconcile':
                workload.reconcile.side_effect = BlockingIOError('lease still busy')
            with self.subTest(failure=failure), \
                    patch.object(driver.subprocess, 'run', side_effect=(
                        subprocess.TimeoutExpired('systemctl', 110) if failure == 'stop' else None)), \
                    patch.dict('sys.modules', {'restricted_workload_network': network}):
                with self.assertRaises((subprocess.TimeoutExpired, BlockingIOError, ValueError)):
                    driver.cleanup(workload)
                network.teardown.assert_not_called()
                if failure in {'fence', 'stop'}:
                    workload.reconcile.assert_not_called()


@unittest.skipUnless(hasattr(os, 'fork'), 'requires real fork/waitpid')
class ObserverProcessTest(unittest.TestCase):
    def child(self, action):
        parent, child = socket.socketpair()
        pid = os.fork()
        if pid == 0:
            parent.close()
            try:
                action(child)
            finally:
                os._exit(0)
        child.close()
        return parent, pid

    def test_eof_does_not_disable_exit_deadline(self):
        def action(channel):
            channel.close()
            time.sleep(10)
        parent, pid = self.child(action)
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(ValueError, 'exit-timeout'):
                driver.collect_child(parent, pid, started + .1)
            self.assertLess(time.monotonic() - started, 2)
        finally:
            parent.close()
            driver.stop_child(pid)
        with self.assertRaises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)

    def test_complete_output_still_waits_for_actual_process_exit(self):
        def action(channel):
            channel.sendall(b'{"complete":true}')
            channel.close()
            time.sleep(.1)
        parent, pid = self.child(action)
        try:
            raw, status = driver.collect_child(parent, pid, time.monotonic() + 2)
            self.assertEqual(b'{"complete":true}', raw)
            self.assertEqual(0, status)
            with self.assertRaises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)
        finally:
            parent.close()

    def test_flooded_output_is_bounded_and_child_is_terminated(self):
        def action(channel):
            channel.sendall(b'x' * 65537)
            time.sleep(10)
        parent, pid = self.child(action)
        try:
            with self.assertRaisesRegex(ValueError, 'output-limit'):
                driver.collect_child(parent, pid, time.monotonic() + 2)
        finally:
            parent.close()
            driver.stop_child(pid)

    def test_missing_eof_cannot_extend_collection(self):
        parent, pid = self.child(lambda channel: time.sleep(10))
        try:
            with self.assertRaisesRegex(ValueError, 'observer-timeout'):
                driver.collect_child(parent, pid, time.monotonic() + .1)
        finally:
            parent.close()
            driver.stop_child(pid)


class ControllerReadinessTest(unittest.TestCase):
    def test_existing_socket_requires_root_peer_and_served_protocol(self):
        import struct
        for uid, response, error in ((1, b'', 'peer-not-root'),
                (0, b'{"status":"ok"}\n', 'response-invalid'),
                (0, b'{"error":"restricted-workload-request-failed"}\n', None)):
            channel = Mock()
            channel.__enter__ = Mock(return_value=channel)
            channel.__exit__ = Mock(return_value=False)
            channel.getsockopt.return_value = struct.pack('3i', 42, uid, uid)
            channel.recv.return_value = response
            with self.subTest(uid=uid, response=response), \
                    patch.object(driver.socket, 'socket', return_value=channel):
                if error:
                    with self.assertRaisesRegex(ValueError, error):
                        driver.controller_ready(time.monotonic() + 1)
                else:
                    driver.controller_ready(time.monotonic() + 1)
                    channel.sendall.assert_called_once_with(b'{}\n')


class TerminalPublicationTest(unittest.TestCase):
    def exercise(self, failure):
        events = []
        repository = Path(driver.__file__).resolve().parents[3]
        relative = 'tools/release-certification/restricted/pr314_workload_driver.py'
        identity = {'sourceCommit': 'test-source'}
        selection = {'plan': {}, 'private': {
            'root': '/var/lib/cryptad-cross-version/experiments/pr315-test-never-created'},
            'authorization': {'maxSeconds': 30}}
        kit = {**identity, 'files': {relative: hashlib.sha256(Path(driver.__file__).read_bytes()).hexdigest()}}
        installation = SimpleNamespace(verify_execution=lambda: identity,
            read_json=lambda path: kit, secured=lambda path: path)
        campaign_deadline = time.monotonic_ns() + 30 * 10**9
        workload = SimpleNamespace(ROOT=Path('/var/lib/cryptad-restricted-workload'),
            read=lambda path: selection if path == driver.SELECTION else
                {'deadlineMonotonicNs': campaign_deadline},
            write=lambda path, *args, **kwargs: events.append(
                'terminal-report' if path == driver.REPORT else
                'volatile-diagnostics' if path == driver.VOLATILE else 'private-diagnostics'))
        def prepare(*args):
            events.append('prepare')
            if failure == 'prepare':
                raise ValueError('setup-failure')
            return {'deadlineMonotonicNs': campaign_deadline + (1 if failure == 'handoff' else 0)}
        def cleanup(_workload):
            events.append('cleanup')
            if failure == 'cleanup':
                raise ValueError('cleanup-failure')
        def capture(*args, observer_root):
            self.assertEqual(Path(selection['private']['root']), observer_root)
            return {'sentinel': {'status': 'matched'}}
        modules = {'installation': installation, 'restricted_workload': workload,
            'pr315_workload_evidence': SimpleNamespace(prepare_sentinel=lambda _: 'sha256:' + 'a' * 64,
                capture=capture),
            'workload_installation': SimpleNamespace(install=lambda: None),
            'restricted_workload_prepare': SimpleNamespace(prepare=prepare),
            'restricted_workload_launcher': SimpleNamespace(launcher_policy=lambda: {'revision': 'offline-test'}),
            'cross_version_workload': SimpleNamespace(InstalledWorkloadAdapter=Mock()),
            'cryptad_certification.cross_version_evidence': SimpleNamespace(Journal=Mock())}
        with ExitStack() as stack:
            stack.enter_context(patch.dict('sys.modules', modules))
            stack.enter_context(patch.object(driver, 'TEST_KIT', repository))
            stack.enter_context(patch.object(driver, 'prerequisites', return_value=[]))
            stack.enter_context(patch.object(driver.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=123, pw_gid=123)))
            stack.enter_context(patch.object(Path, 'mkdir'))
            stack.enter_context(patch.object(driver.os, 'chown'))
            stack.enter_context(patch.object(driver.os, 'fork', return_value=12345))
            stack.enter_context(patch.object(driver.socket, 'socketpair', return_value=(Mock(), Mock())))
            stack.enter_context(patch.object(driver.subprocess, 'run', side_effect=(
                subprocess.TimeoutExpired('systemctl', 30) if failure == 'controller' else None)))
            stack.enter_context(patch.object(driver, 'collect_child',
                return_value=(b'{"contentRetrieval":"observed","newEpoch":true}', 0)))
            stack.enter_context(patch.object(driver, 'cleanup', side_effect=cleanup))
            if failure:
                with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                    driver.execute()
            else:
                self.assertEqual('incomplete', driver.execute()['workloadAcceptance'])
        return events

    def test_partial_preparation_and_controller_start_failure_reconcile(self):
        for failure in ('prepare', 'controller', 'handoff'):
            with self.subTest(failure=failure):
                expected = ['prepare', 'cleanup', 'private-diagnostics', 'volatile-diagnostics']
                self.assertEqual(expected, self.exercise(failure))

    def test_cleanup_failure_prevents_terminal_report(self):
        self.assertEqual(['prepare', 'cleanup', 'private-diagnostics', 'volatile-diagnostics'], self.exercise('cleanup'))

    def test_terminal_report_follows_completed_cleanup(self):
        self.assertEqual(['prepare', 'cleanup', 'private-diagnostics', 'volatile-diagnostics', 'terminal-report'], self.exercise(None))


class MemoryDiagnosticsTest(unittest.TestCase):
    def test_sampled_peaks_preserve_observed_demand_after_cgroup_disappears(self):
        diagnostics = {}
        samples = [
            {'guest': {'status': 'observed', 'MemAvailableBytes': available},
             'services': {'role': {'status': 'observed', 'memory.current': memory, 'pids.current': tasks}}}
            for available, memory, tasks in ((100, 20, 3), (50, 40, 2))]
        samples.append({'guest': {'status': 'unavailable'}, 'services': {
            'role': {'status': 'absent-or-removed-not-quiescence-proof'}}})
        with patch.object(driver, 'memory_snapshot', side_effect=samples):
            for _ in samples:
                driver.sample_memory(diagnostics)
        observed = diagnostics['during']
        self.assertEqual(3, observed['sampleCount'])
        self.assertEqual(50, observed['minimumObservedGuestAvailableBytes'])
        self.assertEqual(40, observed['services']['role']['maximumObservedMemoryBytes'])
        self.assertEqual(3, observed['services']['role']['maximumObservedTasks'])
        self.assertEqual(2, observed['services']['role']['sampleCount'])

    def test_absent_cgroups_do_not_become_zero_or_quiescence(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(driver, 'CGROUP_ROOT', Path(directory)):
            snapshot = driver.memory_snapshot()
        self.assertEqual('observed', snapshot['guest']['status'])
        self.assertGreater(snapshot['guest']['MemTotalBytes'], 0)
        self.assertEqual(5, len(snapshot['services']))
        for service in snapshot['services'].values():
            self.assertEqual({'status': 'absent-or-removed-not-quiescence-proof'}, service)

    def test_fixed_cgroup_limits_and_events_are_observed_without_reinterpreting_oom(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(driver, 'CGROUP_ROOT', Path(directory)):
            group = Path(directory) / 'cryptad-workload@candidate-sender.service'
            group.mkdir()
            for name, value in {'memory.current': '123', 'memory.max': '1073741824',
                    'memory.swap.max': '0', 'pids.current': '8', 'pids.max': '512',
                    'memory.events': 'oom 1\noom_kill 1\n', 'cgroup.events': 'populated 1\n',
                    'cpu.stat': 'usage_usec 15\nthrottled_usec 4\n', 'cpu.max': '50000 100000'}.items():
                (group / name).write_text(value)
            snapshot = driver.memory_snapshot()['services'][group.name]
        self.assertEqual('observed', snapshot['status'])
        self.assertEqual(123, snapshot['memory.current'])
        self.assertEqual(0, snapshot['memory.swap.max'])
        self.assertEqual({'oom': 1, 'oom_kill': 1}, snapshot['memory.events'])
        self.assertEqual({'populated': 1}, snapshot['cgroup.events'])
        self.assertEqual({'usage_usec': 15, 'throttled_usec': 4}, snapshot['cpu.stat'])
        self.assertEqual({'quota': 50000, 'period': 100000}, snapshot['cpu.max'])

    def test_symlink_metric_is_unavailable_not_zero(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(driver, 'CGROUP_ROOT', Path(directory)):
            group = Path(directory) / 'cryptad-workload@candidate-sender.service'
            group.mkdir()
            (group / 'memory.current').symlink_to('/proc/meminfo')
            snapshot = driver.memory_snapshot()['services'][group.name]
        self.assertEqual({'status': 'unavailable'}, snapshot)


class CpuObservationFailureTests(unittest.TestCase):
    def make_group(self, root):
        group = root / 'cryptad-workload@candidate-sender.service'
        group.mkdir()
        for name, value in {'memory.current': '123', 'memory.max': '1073741824',
                'memory.swap.max': '0', 'pids.current': '8', 'pids.max': '512',
                'memory.events': 'oom 0\n', 'cgroup.events': 'populated 1\n',
                'cpu.stat': 'usage_usec 15\nthrottled_usec 4\n', 'cpu.max': '50000 100000'}.items():
            (group / name).write_text(value)
        return group

    def test_missing_and_malformed_cpu_metrics_never_become_zero(self):
        for kind in ('missing', 'malformed', 'invalid-period'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                group = self.make_group(root)
                if kind == 'missing':
                    (group / 'cpu.stat').unlink()
                elif kind == 'malformed':
                    (group / 'cpu.stat').write_text('usage_usec unknown\n')
                else:
                    (group / 'cpu.max').write_text('50000 0')
                with patch.object(driver, 'CGROUP_ROOT', root):
                    result = driver.memory_snapshot()['services'][group.name]
                self.assertIn(result['status'], ('unavailable', 'absent-or-removed-not-quiescence-proof'))
                self.assertNotIn('cpu.stat', result)
                self.assertNotIn('cpu.max', result)

    def test_replaced_cgroup_during_cpu_read_is_unavailable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            group = self.make_group(root)
            original = driver._kernel_read
            def replace_after_cpu_read(path):
                raw = original(path)
                if path == group / 'cpu.max':
                    group.rename(root / 'retained-original')
                    group.mkdir()
                return raw
            with patch.object(driver, 'CGROUP_ROOT', root), \
                    patch.object(driver, '_kernel_read', side_effect=replace_after_cpu_read):
                result = driver.memory_snapshot()['services'][group.name]
            self.assertEqual({'status': 'unavailable'}, result)


if __name__ == '__main__':
    unittest.main()
