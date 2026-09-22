"""Workload control fault tests with simulated manager state, not installed acceptance."""
from contextlib import ExitStack, nullcontext
import copy
import json
import os
import shlex
import shutil
import socket
import stat
import threading
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import restricted_workload as workload
import restricted_workload_controller as controller
import restricted_workload_launcher as launcher
import restricted_workload_prepare as preparation


class ControllerStartupDiagnosticsTest(unittest.TestCase):
    def test_fixed_runtime_record_is_private_and_excludes_exception_message(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(controller, 'STARTUP', Path(directory) / 'startup.json'), \
                patch.object(workload, 'secured', side_effect=lambda path, **_kwargs: path):
            controller.startup_checkpoint('entry', 123, {}, ValueError('sensitive detail'))
            record = json.loads(controller.STARTUP.read_text())
            self.assertEqual(0o600, stat.S_IMODE(controller.STARTUP.stat().st_mode))
        self.assertEqual('private-runtime-diagnostic-not-acceptance', record['classification'])
        self.assertEqual(os.getpid(), record['pid'])
        self.assertEqual(workload.boot(), record['bootId'])
        self.assertEqual(123, record['startedMonotonicNs'])
        self.assertGreater(record['observedMonotonicNs'], 123)
        self.assertEqual(2, record['schemaVersion'])
        self.assertEqual({'entry': 123}, record['stageMonotonicNs'])
        self.assertEqual('entry', record['stage'])
        self.assertEqual('ValueError', record['exceptionType'])
        self.assertNotIn('sensitive detail', json.dumps(record))

    def test_invalid_stage_and_diagnostic_write_failure_cannot_change_control_behavior(self):
        with patch.object(workload, 'write', side_effect=OSError('disk unavailable')) as write:
            controller.startup_checkpoint('arbitrary-stage', 1, {})
            write.assert_not_called()
            controller.startup_checkpoint('entry', 1, {})
            write.assert_called_once()

    def test_failed_write_and_later_exception_preserve_first_stage_time_in_one_epoch(self):
        reached = {}
        with patch.object(controller.time, 'monotonic_ns', side_effect=[100, 120, 150]), \
                patch.object(workload, 'write', side_effect=[OSError('unavailable'), None, None]) as write:
            controller.startup_checkpoint('entry', 90, reached)
            controller.startup_checkpoint('installation-verified', 90, reached)
            controller.startup_checkpoint('installation-verified', 90, reached, ValueError('private'))
        record = write.call_args.args[1]
        self.assertEqual({'entry': 90, 'installation-verified': 120}, record['stageMonotonicNs'])
        self.assertEqual(150, record['observedMonotonicNs'])
        self.assertEqual('ValueError', record['exceptionType'])
        self.assertEqual({'entry': 90}, write.call_args_list[0].args[1]['stageMonotonicNs'])

    def run_startup(self, verification_error=None):
        records, events = [], []
        def write(path, record, **kwargs):
            self.assertEqual(controller.STARTUP, path)
            self.assertEqual({'mode': 0o600}, kwargs)
            records.append(record)
            events.append(record['stage'])
        def verify():
            events.append('verify-called')
            if verification_error is not None:
                raise verification_error
        endpoint = Mock()
        endpoint.exists.return_value = endpoint.is_symlink.return_value = False
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            stack.enter_context(patch.object(controller.sys, 'argv', ['fixed-controller']))
            stack.enter_context(patch.object(controller.sys, 'flags', SimpleNamespace(isolated=True, no_site=True)))
            stack.enter_context(patch.object(controller.sys, 'path', list(sys.path)))
            stack.enter_context(patch.object(controller.os, 'geteuid', return_value=0))
            stack.enter_context(patch.object(controller.os, 'umask'))
            stack.enter_context(patch.object(controller.os, 'environ', {}))
            stack.enter_context(patch.object(workload, 'secured'))
            stack.enter_context(patch.object(workload, 'ROOT', Path(directory)))
            stack.enter_context(patch.object(workload, 'write', side_effect=write))
            stack.enter_context(patch.object(workload, 'reconcile'))
            stack.enter_context(patch.object(workload, 'fence_campaign'))
            stack.enter_context(patch.object(controller.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1, pw_gid=1)))
            stack.enter_context(patch.object(controller, 'SOCKET', endpoint))
            stack.enter_context(patch.object(controller.socket, 'socket'))
            stack.enter_context(patch.object(controller.os, 'chown'))
            stack.enter_context(patch.object(controller.select, 'select', side_effect=RuntimeError('stop test loop')))
            stack.enter_context(patch.dict(sys.modules, {'installation': SimpleNamespace(verify_execution=verify)}))
            with self.assertRaises((ValueError, RuntimeError)) as raised:
                controller.main()
        return records, events, raised.exception

    def test_entry_precedes_verification_and_failure_retains_original_exception(self):
        failure = ValueError('private verification detail')
        records, events, raised = self.run_startup(failure)
        self.assertIs(failure, raised)
        self.assertEqual(['entry', 'verify-called', 'entry'], events)
        self.assertEqual('ValueError', records[-1]['exceptionType'])
        self.assertEqual(records[0]['startedMonotonicNs'], records[1]['startedMonotonicNs'])
        self.assertNotIn('private verification detail', json.dumps(records))

    def test_successful_startup_records_all_fixed_stages_before_request_loop(self):
        records, events, _raised = self.run_startup()
        self.assertEqual(['entry', 'verify-called', 'installation-verified', 'reconciled', 'listening'], events)
        self.assertEqual(1, len({row['startedMonotonicNs'] for row in records}))
        self.assertEqual(1, len({row['pid'] for row in records}))
        self.assertTrue(all('exceptionType' not in row for row in records))
        for index, record in enumerate(records):
            self.assertEqual(set(events[:index + 2]) - {'verify-called'}, set(record['stageMonotonicNs']))
            self.assertEqual(record['startedMonotonicNs'], record['stageMonotonicNs']['entry'])
            self.assertTrue(all(record['startedMonotonicNs'] <= timestamp <= record['observedMonotonicNs']
                                for timestamp in record['stageMonotonicNs'].values()))
        self.assertEqual(set(controller.STARTUP_STAGES), set(records[-1]['stageMonotonicNs']))


class MarkerImportTest(unittest.TestCase):
    def test_rejected_manager_entry_does_not_mutate_installed_module_tree(self):
        source = Path(__file__).parent
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('restricted_workload_mark.py', 'restricted_workload.py',
                         'restricted_native_launcher.py'):
                shutil.copyfile(source / name, root / name)
            result = subprocess.run([sys.executable, '-I', '-S', str(root / 'restricted_workload_mark.py')],
                                    capture_output=True, timeout=10)
            self.assertEqual(1, result.returncode)
            self.assertFalse((root / '__pycache__').exists())


class ProspectiveConfigurationTest(unittest.TestCase):
    def test_fixed_accounts_fit_systemd_strict_names_and_match_role_lookup(self):
        assets = Path(__file__).resolve().parents[1] / 'restricted/systemd'
        rows = [shlex.split(line) for line in (assets / 'cryptad-workload.conf').read_text().splitlines()
                if line and not line.startswith('#')]
        settings = dict(line.split('=', 1) for line in (assets / 'cryptad-workload@.service').read_text().splitlines()
                        if '=' in line and not line.startswith('#'))
        self.assertEqual(len(workload.ROLES), len(rows))
        for role, row in zip(workload.ROLES, rows):
            name = row[1]
            # systemd v257 strict validation reserves one byte in utmpx.ut_user.
            self.assertLessEqual(len(name.encode('ascii')), 31)
            self.assertRegex(name, r'^[A-Za-z_][A-Za-z0-9_-]*$')
            self.assertEqual(name, settings['User'].replace('%i', role))
            self.assertEqual(name, settings['Group'].replace('%i', role))
            user = SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_shell='/usr/sbin/nologin')
            with patch.object(workload.pwd, 'getpwnam', return_value=user) as lookup:
                self.assertIs(user, workload.account(role))
                lookup.assert_called_once_with(name)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux resource limits required')
    def test_service_file_limit_allows_configured_store_and_remains_finite(self):
        unit = Path(__file__).resolve().parents[1] / 'restricted/systemd/cryptad-workload@.service'
        settings = dict(line.split('=', 1) for line in unit.read_text().splitlines()
                        if '=' in line and not line.startswith('#'))
        limit = settings['LimitFSIZE']
        self.assertTrue(limit.endswith('M'))
        limit_bytes = int(limit[:-1]) * 1024**2
        config = dict(line.split('=', 1) for line in preparation.configuration(workload.ROLES[0]).splitlines()
                      if '=' in line)
        # An entire configured store is an upper bound on each CHK backing file.
        store_bytes = int(config['node.storeSize'])
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([sys.executable, '-c', '''
import errno, os, resource, signal, sys
limit, required = map(int, sys.argv[1:3])
resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
with open(sys.argv[3], 'wb') as stream:
    os.ftruncate(stream.fileno(), required)
    assert os.fstat(stream.fileno()).st_size == required
    try:
        os.ftruncate(stream.fileno(), limit + 1)
    except OSError as failure:
        assert failure.errno == errno.EFBIG
    else:
        raise AssertionError('file size limit not enforced')
''', str(limit_bytes), str(store_bytes), str(Path(temporary) / 'store.hd')],
                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_role_configuration_keeps_management_loopback_and_distinct_data_plane(self):
        from restricted_workload_network import address
        identities = set()
        for role in workload.ROLES:
            text = preparation.configuration(role)
            self.assertIn('node.bindTo=' + address(role) + '\n', text)
            self.assertIn('node.ipAddressOverride=' + address(role) + '\n', text)
            self.assertIn('fcp.bindTo=127.0.0.1\n', text)
            self.assertIn('fproxy.bindTo=127.0.0.1\n', text)
            self.assertIn('node.install.cfgDir=/node/config\n', text)
            identities.add(preparation.configuration_identity(role, None))
        self.assertEqual(4, len(identities))

    def test_profile_configuration_binds_public_trust_and_is_reproducible(self):
        role = workload.ROLES[0]
        original = preparation.configuration_identity(role, 'sha256:' + 'a' * 64)
        self.assertEqual(original, preparation.configuration_identity(role, 'sha256:' + 'a' * 64))
        self.assertNotEqual(original, preparation.configuration_identity(role, 'sha256:' + 'b' * 64))

    def test_preconfigured_workload_completes_wizard_and_changes_configuration_pin(self):
        for role in workload.ROLES:
            with self.subTest(role=role):
                text = preparation.configuration(role)
                self.assertEqual(1, text.count('fproxy.hasCompletedWizard=true\n'))
                current = preparation.configuration_identity(role, None)
                with patch.object(preparation, 'configuration', return_value=text.replace(
                        'fproxy.hasCompletedWizard=true\n', '')):
                    self.assertNotEqual(current, preparation.configuration_identity(role, None))

    def test_configuration_identity_changes_with_fixed_launcher_policy(self):
        original = preparation.configuration_identity('previous', None)
        changed = launcher.launcher_policy()
        changed['wrapperStartupTimeoutSeconds']['previous'] = 30
        with patch.object(preparation, 'launcher_policy', return_value=changed):
            self.assertNotEqual(original, preparation.configuration_identity('previous', None))


class BootstrapHttpTest(unittest.TestCase):
    def test_connected_loopback_listener_receives_its_real_host_port(self):
        listener = socket.socket()
        self.addCleanup(listener.close)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        received = []
        def respond():
            connection, _address = listener.accept()
            with connection:
                connection.settimeout(5)
                raw = b''
                while b'\r\n\r\n' not in raw:
                    raw += connection.recv(4096)
                received.append(raw)
                connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}')
        worker = threading.Thread(target=respond, daemon=True)
        worker.start()
        with socket.create_connection(listener.getsockname(), timeout=5) as connection:
            status, _headers, body = controller._http(connection, '/.well-known/cryptad-bootstrap.json', {})
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual((200, b'{}'), (status, body))
        self.assertIn(('Host: 127.0.0.1:' + str(listener.getsockname()[1]) + '\r\n').encode(), received[0])


class CurrentImplementationTest(unittest.TestCase):
    def test_partial_preparation_cannot_authorize_work(self):
        with patch.object(workload, 'execution_record_digest') as identity:
            for state in (None, 'preparing', 'failed'):
                with self.subTest(state=state), self.assertRaisesRegex(
                        workload.WorkloadError, 'preparation-incomplete'):
                    workload.current({'state': state})
            identity.assert_not_called()

    def test_changed_installed_execution_record_cannot_continue_campaign(self):
        selection = {'fixed': 'selection'}
        campaign = {'state': 'prepared', 'bootId': BOOT, 'deadlineMonotonicNs': 10**20,
                    'executionRecordDigest': 'a' * 64,
                    'selectionDigest': workload.hashlib.sha256(json.dumps(selection, sort_keys=True,
                        separators=(',', ':')).encode()).hexdigest()}
        with tempfile.TemporaryDirectory() as directory, patch.object(workload, 'ROOT', Path(directory)), \
                patch.object(workload, 'boot', return_value=BOOT), \
                patch.object(workload, 'read', return_value=selection), \
                patch.object(workload, 'execution_record_digest', return_value='a' * 64) as identity:
            workload.current(campaign)
            identity.return_value = 'b' * 64
            with self.assertRaisesRegex(workload.WorkloadError, 'implementation-changed'):
                workload.current(campaign)


ROLE = 'candidate-sender'
HANDLE = 'a' * 64
BOOT = 'example-current-boot'
INVOCATION = 'b' * 32


def manager_state(active='active', invocation=INVOCATION):
    return dict(InvocationID=invocation, ActiveState=active, SubState='running',
                ControlGroup='/system.slice/' + workload.unit(ROLE), MainPID='123', Result='success')


class ObservationTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.root = root
        (root / 'memory.current').write_text('4096')
        (root / 'pids.current').write_text('0')
        info = root.stat()
        record = dict(handle=HANDLE, state='running', generation='generation', bootId=BOOT,
                      managerInvocation=INVOCATION, cgroupIdentity=[info.st_dev, info.st_ino])
        self.stack.enter_context(patch.object(workload, 'locked', side_effect=nullcontext))
        self.stack.enter_context(patch.object(workload, 'retained', return_value=({}, ROLE, record)))
        self.stack.enter_context(patch.object(workload, 'admit'))
        self.stack.enter_context(patch.object(workload, 'group', return_value=root))
        self.stack.enter_context(patch.object(workload, 'boot', return_value=BOOT))
        self.stack.enter_context(patch.object(workload, 'account', return_value=SimpleNamespace(pw_uid=os.getuid())))
        self.manager = self.stack.enter_context(patch.object(workload, 'manager', return_value=manager_state()))

    def reaped_child(self):
        child = os.fork()
        if child == 0:
            os._exit(0)
        self.assertEqual((child, 0), os.waitpid(child, 0))
        (self.root / 'cgroup.procs').write_text(str(child))

    @unittest.skipUnless(hasattr(os, 'pidfd_open'), 'requires Linux pidfd support')
    def test_reaped_process_is_counted_as_exited_sample(self):
        self.reaped_child()
        result = workload.observe(HANDLE)
        self.assertEqual([], result['processes'])
        self.assertEqual(1, result['exitedDuringSample'])
        self.assertEqual(4096, result['cgroupMemoryBytes'])
        self.assertEqual(2, self.manager.call_count)

    @unittest.skipUnless(hasattr(os, 'pidfd_open'), 'requires Linux pidfd support')
    def test_reaped_process_does_not_skip_final_invocation_check(self):
        self.reaped_child()
        self.manager.side_effect = [manager_state(), manager_state(invocation='replacement')]
        with self.assertRaisesRegex(workload.WorkloadError, 'invocation-changed'):
            workload.observe(HANDLE)

    def test_sampling_permission_failure_is_not_an_exited_process(self):
        (self.root / 'cgroup.procs').write_text('123')
        with patch.object(workload, '_process', side_effect=PermissionError('denied')):
            with self.assertRaises(PermissionError):
                workload.observe(HANDLE)

    @unittest.skipUnless(hasattr(os, 'pidfd_open'), 'requires Linux pidfd support')
    def test_exit_after_sample_is_counted_and_final_invocation_is_checked(self):
        for replaced in (False, True):
            with self.subTest(replaced=replaced), subprocess.Popen(['/usr/bin/sleep', '30']) as child:
                try:
                    (self.root / 'cgroup.procs').write_text(str(child.pid))
                    self.manager.side_effect = [manager_state(), manager_state(
                        invocation='replacement' if replaced else INVOCATION)]
                    def sampled(pid, role, uid):
                        self.assertEqual(child.pid, pid)
                        child.terminate()
                        child.wait(timeout=5)
                        return {'hostPid': pid}
                    # Keep the real pidfd open/readiness/close path; terminate only
                    # after _process has opened it, at the end of the sample.
                    with patch.object(workload, '_process_sample', side_effect=sampled):
                        if replaced:
                            with self.assertRaisesRegex(workload.WorkloadError, 'invocation-changed'):
                                workload.observe(HANDLE)
                        else:
                            result = workload.observe(HANDLE)
                            self.assertEqual([], result['processes'])
                            self.assertEqual(1, result['exitedDuringSample'])
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=5)


class LifecycleTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.record = dict(handle=HANDLE, state='prepared', generation=None, bootId=BOOT,
                           managerInvocation=None, cgroupIdentity=None, stopReason=None, campaign='d' * 64)
        self.campaign = dict(deadlineMonotonicNs=10**20, maxOperations=100)
        self.marker = None
        self.stop_marker = None
        self.writes = []
        self.calls = []
        self.state = manager_state('inactive')
        self.current = self.stack.enter_context(patch.object(workload, 'current'))
        self.stack.enter_context(patch.object(workload, 'locked', side_effect=nullcontext))
        self.stack.enter_context(patch.object(workload, 'retained', side_effect=lambda _handle:
            (self.campaign, ROLE, copy.deepcopy(self.record))))
        self.stack.enter_context(patch.object(workload, 'write', side_effect=self.write))
        self.stack.enter_context(patch.object(workload, 'read', side_effect=self.read))
        self.stack.enter_context(patch.object(workload, 'tree_identity', return_value='exact-input'))
        self.stack.enter_context(patch.object(workload, 'boot', return_value=BOOT))
        self.group = Mock()
        self.group.stat.return_value = SimpleNamespace(st_dev=1, st_ino=99)
        self.stack.enter_context(patch.object(workload, 'group', return_value=self.group))
        self.quiescent = self.stack.enter_context(patch.object(workload, 'quiescent', return_value=True))
        self.manager = self.stack.enter_context(patch.object(workload, 'manager', side_effect=self.operation))

    def read(self, path):
        if path.name.endswith('-stop.json'):
            if self.stop_marker is None:
                raise FileNotFoundError('no-stop-receipt')
            return copy.deepcopy(self.stop_marker)
        if path.name.endswith('-start.json'):
            if self.marker is None:
                raise FileNotFoundError('no-manager-receipt')
            return copy.deepcopy(self.marker)
        return {'inputs': {'package': 'exact-input'}}

    def write(self, path, value):
        if path.name == 'campaign.json':
            self.campaign = copy.deepcopy(value)
            return
        self.record = copy.deepcopy(value)
        self.writes.append(copy.deepcopy(value))

    def operation(self, role, operation):
        self.assertEqual(ROLE, role)
        self.calls.append(operation)
        if operation == 'start':
            self.assertEqual('launching', self.record['state'])
            self.state = manager_state()
            self.marker = dict(generation=self.record['generation'], bootId=BOOT,
                               managerInvocation=INVOCATION, cgroupIdentity=[1, 99])
        elif operation == 'stop':
            self.assertEqual('stopping', self.record['state'])
            self.stop_marker = dict(schemaVersion=1, role=ROLE, campaign=self.record['campaign'],
                generation=self.record['generation'], bootId=BOOT, managerInvocation=INVOCATION,
                cgroupIdentity=[1, 99], helperPid=42, helperStartTimeTicks=3,
                startedMonotonicNs=1, observedMonotonicNs=2,
                membership='only-stop-helper', descendantCgroups=0)
            self.state = manager_state('inactive', invocation='')
            self.state.update(ControlGroup='', MainPID='0', SubState='dead')
        elif operation == 'show':
            return copy.deepcopy(self.state)

    def running(self):
        workload.start(HANDLE)
        self.calls.clear()

    def test_launch_intent_precedes_mutation_and_retry_returns_same_invocation(self):
        first = workload.start(HANDLE)
        second = workload.start(HANDLE)
        self.assertEqual(first, second)
        self.assertEqual(['launching', 'running'], [row['state'] for row in self.writes])
        self.assertEqual(1, self.calls.count('start'))
        self.assertEqual([1, 99], self.record['cgroupIdentity'])

    def test_lost_start_response_retains_intent_and_prevents_duplicate_launch(self):
        def lost(role, operation):
            result = self.operation(role, operation)
            if operation == 'start':
                raise subprocess.TimeoutExpired('fixed-manager-start', 35)
            return result
        self.manager.side_effect = lost
        with self.assertRaises(subprocess.TimeoutExpired):
            workload.start(HANDLE)
        self.assertEqual('launching', self.record['state'])
        self.manager.side_effect = self.operation
        result = workload.start(HANDLE)
        self.assertEqual(1, self.calls.count('start'))
        self.assertEqual('running', result['state'])
        self.assertEqual(INVOCATION, result['managerInvocation'])

    def test_lost_start_without_manager_receipt_retains_uncertainty(self):
        def lost(_role, operation):
            if operation == 'start':
                self.calls.append(operation)
                raise subprocess.TimeoutExpired('fixed-manager-start', 35)
            return copy.deepcopy(self.state)
        self.manager.side_effect = lost
        with self.assertRaises(subprocess.TimeoutExpired):
            workload.start(HANDLE)
        with self.assertRaises(FileNotFoundError):
            workload.start(HANDLE)
        self.assertEqual('launching', self.record['state'])
        self.assertEqual(1, self.calls.count('start'))

    def test_stale_manager_receipt_is_not_adopted(self):
        self.running()
        self.record['state'] = 'launching'
        self.marker['generation'] = 'different-generation'
        with self.assertRaisesRegex(workload.WorkloadError, 'launch-reconciliation-required'):
            workload.start(HANDLE)
        self.assertEqual('launching', self.record['state'])
        self.assertNotIn('start', self.calls)

    def test_exhausted_operation_budget_denies_launch_but_leaves_stop_available(self):
        self.running()
        self.campaign['maxOperations'] = self.campaign['usedOperations']
        with self.assertRaisesRegex(workload.WorkloadError, 'operation-budget-exhausted'):
            workload.start(HANDLE)
        result = workload.stop(HANDLE)
        self.assertEqual('quiescent', result['state'])

    def test_changed_invocation_does_not_stop_unrelated_live_service(self):
        self.running()
        self.state['InvocationID'] = 'c' * 32
        with self.assertRaisesRegex(workload.WorkloadError, 'invocation-changed'):
            workload.stop(HANDLE)
        self.assertNotIn('stop', self.calls)
        self.assertEqual('running', self.record['state'])

    def test_replaced_cgroup_does_not_signal_new_occupant(self):
        self.running()
        self.group.stat.return_value = SimpleNamespace(st_dev=1, st_ino=100)
        with self.assertRaisesRegex(workload.WorkloadError, 'cgroup-changed'):
            workload.stop(HANDLE)
        self.assertNotIn('stop', self.calls)

    def test_changed_boot_does_not_adopt_old_process(self):
        self.running()
        with patch.object(workload, 'boot', return_value='different-boot'):
            with self.assertRaisesRegex(workload.WorkloadError, 'invocation-changed'):
                workload.start(HANDLE)
        self.assertNotIn('start', self.calls)

    def test_stop_remains_available_after_expiry_and_revocation(self):
        self.running()
        self.current.reset_mock()
        self.current.side_effect = workload.WorkloadError('restricted-workload-authority-expired-or-revoked')
        result = workload.stop(HANDLE)
        self.assertEqual('quiescent', result['state'])
        self.assertIn('stop', self.calls)
        self.current.assert_not_called()

    def test_nonempty_cgroup_retains_reconciliation_failure(self):
        self.running()
        self.quiescent.return_value = False
        with self.assertRaisesRegex(workload.WorkloadError, 'descendants-not-quiescent'):
            workload.stop(HANDLE)
        self.assertEqual('reconciliation-required', self.record['state'])
        self.assertEqual(HANDLE, self.record['handle'])
        self.assertEqual(INVOCATION, self.record['managerInvocation'])

    def test_authority_change_after_start_stops_exact_owned_invocation(self):
        self.current.side_effect = [None, None,
            workload.WorkloadError('restricted-workload-authority-expired-or-revoked')]
        with self.assertRaisesRegex(workload.WorkloadError, 'authority-expired-or-revoked'):
            workload.start(HANDLE)
        self.assertEqual('quiescent', self.record['state'])
        self.assertEqual('authority-changed', self.record['stopReason'])
        self.assertEqual(1, self.calls.count('stop'))

    def test_input_change_prevents_first_mutation(self):
        with patch.object(workload, 'tree_identity', return_value='changed-input'):
            with self.assertRaisesRegex(workload.WorkloadError, 'input-substituted'):
                workload.start(HANDLE)
        self.assertEqual([], self.writes)
        self.assertNotIn('start', self.calls)

    def test_removed_inactive_group_without_receipt_retains_uncertainty(self):
        self.running()
        self.state = manager_state('inactive', invocation='')
        self.state.update(ControlGroup='', MainPID='0', SubState='dead')
        self.group.stat.side_effect = FileNotFoundError('removed')
        with self.assertRaisesRegex(FileNotFoundError, 'no-stop-receipt'):
            workload.stop(HANDLE)
        self.assertEqual('reconciliation-required', self.record['state'])
        self.assertNotIn('stop', self.calls)

    def test_removed_group_requires_exact_preceding_stop_observation(self):
        self.running()
        workload.stop(HANDLE)
        self.calls.clear()
        self.group.stat.side_effect = FileNotFoundError('removed')
        self.assertEqual('quiescent', workload.stop(HANDLE)['state'])
        self.assertNotIn('stop', self.calls)
        for key, value in (('generation', 'e' * 64), ('managerInvocation', 'f' * 32),
                           ('cgroupIdentity', [1, 100]), ('campaign', 'e' * 64),
                           ('bootId', 'other-boot'), ('helperPid', True),
                           ('observedMonotonicNs', 10**30), ('descendantCgroups', True)):
            original = copy.deepcopy(self.stop_marker)
            with self.subTest(field=key):
                self.stop_marker[key] = value
                with self.assertRaisesRegex(workload.WorkloadError, 'stop-receipt-mismatch'):
                    workload.stop(HANDLE)
                self.assertNotIn('stop', self.calls)
            self.stop_marker = original

    def test_terminal_receipt_cannot_adopt_replacement_cgroup(self):
        self.running()
        workload.stop(HANDLE)
        self.calls.clear()
        self.group.stat.return_value = SimpleNamespace(st_dev=1, st_ino=100)
        with self.assertRaisesRegex(workload.WorkloadError, 'cgroup-changed'):
            workload.stop(HANDLE)
        self.assertNotIn('stop', self.calls)

    def test_manager_changes_during_terminal_observation_fail_closed(self):
        self.running()
        workload.stop(HANDLE)
        self.manager.side_effect = [copy.deepcopy(self.state), manager_state(invocation='c' * 32)]
        with self.assertRaisesRegex(workload.WorkloadError, 'terminal-observation-changed'):
            workload.stop(HANDLE)
        self.assertEqual('reconciliation-required', self.record['state'])

    def test_restart_archives_old_epoch_before_new_intent_without_new_deadline(self):
        self.running()
        workload.stop(HANDLE)
        old_generation = self.record['generation']
        deadline = self.campaign['deadlineMonotonicNs']
        def archived(role, record):
            self.assertEqual(ROLE, role)
            self.assertEqual(old_generation, record['generation'])
            self.assertEqual('quiescent', self.record['state'])
        with patch.object(workload, 'archive_stop', side_effect=archived) as archive:
            workload.start(HANDLE)
        archive.assert_called_once()
        self.assertNotEqual(old_generation, self.record['generation'])
        self.assertEqual(old_generation, self.record['previousStopGeneration'])
        self.assertEqual(deadline, self.campaign['deadlineMonotonicNs'])


class TerminalCampaignTest(unittest.TestCase):
    def test_terminal_fence_keeps_generation_deadline_and_rejects_admission(self):
        campaign = dict(state='prepared', generation='a' * 64, bootId=BOOT,
                        deadlineMonotonicNs=123456789)
        with patch.object(workload, 'locked', side_effect=nullcontext), \
                patch.object(workload, 'boot', return_value=BOOT), \
                patch.object(workload, 'read', return_value=campaign), \
                patch.object(workload, 'write') as write:
            workload.fence_campaign()
            self.assertEqual('terminalizing', campaign['state'])
            self.assertEqual(123456789, campaign['deadlineMonotonicNs'])
            self.assertEqual('a' * 64, campaign['generation'])
            with self.assertRaisesRegex(workload.WorkloadError, 'preparation-incomplete'):
                workload.current(campaign)
            workload.fence_campaign()
            self.assertEqual(1, write.call_count)

    def test_controller_recovery_fences_prior_launch_but_not_initial_preparation(self):
        for launched in (False, True):
            campaign = dict(state='prepared', generation='a' * 64, bootId=BOOT,
                            handles={role: HANDLE for role in workload.ROLES})
            record = {'state': 'prepared', 'generation': None}
            if launched:
                record.update(state='launching', generation='b' * 64)
            with self.subTest(launched=launched), \
                    patch.object(workload, 'locked', side_effect=nullcontext), \
                    patch.object(workload, 'boot', return_value=BOOT), \
                    patch.object(workload, 'read', return_value=campaign), \
                    patch.object(workload, 'retained', return_value=(campaign, ROLE, record)), \
                    patch.object(workload, 'write'), patch.object(workload, 'reconcile') as reconcile:
                workload.recover_controller()
                self.assertEqual('terminalizing' if launched else 'prepared', campaign['state'])
                reconcile.assert_called_once_with()


class FakeConnection:
    def __init__(self, raw, uid=1000):
        self.raw, self.uid = raw, uid
        self.sent = []

    def getsockopt(self, level, option, size):
        assert (level, option, size) == (socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
        return struct.pack('3i', 123, self.uid, 1000)

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, length):
        value, self.raw = self.raw[:length], self.raw[length:]
        return value

    def sendall(self, value):
        self.sent.append(value)


class ControllerRequestTest(unittest.TestCase):
    def setUp(self):
        # These tests use FakeConnection, not the host's peer-credential ABI.
        # Supply only the missing option name on non-Linux hosts so protocol and
        # adversarial HTTP/JSON tests still execute there. Production stays Linux-only.
        option = patch.object(controller.socket, 'SO_PEERCRED',
                              getattr(socket, 'SO_PEERCRED', 17), create=True)
        option.start()
        self.addCleanup(option.stop)

    def test_non_object_runtime_json_fails_only_bootstrap_request_in_both_passes(self):
        import restricted_workload_app as app
        import restricted_workload_network as network
        import restricted_workload_storage as storage
        valid_runtime = {'runtime': {'running': True, 'sandbox': {'provider': 'bubblewrap', 'active': True}}}
        for body in ([], None, 'text', 7, {'runtime': []}, {'runtime': {'sandbox': []}}):
            for final in (False, True):
                with self.subTest(body=body, final=final), ExitStack() as stack:
                    stack.enter_context(patch.object(workload, 'locked', side_effect=nullcontext))
                    stack.enter_context(patch.object(workload, 'retained', return_value=(
                        {'deadlineMonotonicNs': 10**20}, ROLE, {})))
                    for name in ('admit', 'exact', 'manager', 'current'):
                        stack.enter_context(patch.object(workload, name))
                    stack.enter_context(patch.object(workload, 'read', return_value={'mailIdentity': {}}))
                    stack.enter_context(patch.object(storage, 'verify_installed_app'))
                    stack.enter_context(patch.object(network, 'connect'))
                    stack.enter_context(patch.object(network, '_connect_port'))
                    stack.enter_context(patch.object(app, 'require_app_listener', return_value={'bound': True}))
                    responses = [(302, {'Location': 'http://127.0.0.1:23456/#cryptadBootstrapNonce=' + 'a'*16}, b'')]
                    if final:
                        responses.extend([(200, {}, json.dumps(valid_runtime).encode()), (200, {}, json.dumps({
                            'uiOrigin': 'http://127.0.0.1:23456', 'browserSessionToken': 'session'}).encode())])
                    responses.append((200, {}, json.dumps(body).encode()))
                    stack.enter_context(patch.object(controller, '_http', side_effect=responses))
                    reconcile = stack.enter_context(patch.object(workload, 'reconcile'))
                    failed = FakeConnection(json.dumps({'method': 'bootstrap-mail', 'handle': HANDLE}).encode() + b'\n')
                    self.assertFalse(controller.handle_request(failed, 1000))
                    healthy = FakeConnection(self.raw() + b'\n')
                    with patch.object(workload, 'start', return_value={'state': 'running'}):
                        self.assertTrue(controller.handle_request(healthy, 1000))
                    reconcile.assert_not_called()
                    self.assertEqual([b'{"error":"restricted-workload-request-failed"}\n'], failed.sent)

    def test_malformed_role_http_fails_only_request_and_next_request_succeeds(self):
        for response in (b'not-http\r\n', b'HTTP/1.1 200 OK\r\nX: ' + b'a' * 65537 + b'\r\n\r\n'):
            with self.subTest(response_length=len(response)), socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                errors = []
                def reply():
                    try:
                        with listener.accept()[0] as peer:
                            peer.settimeout(5)
                            raw = b''
                            while b'\r\n\r\n' not in raw:
                                raw += peer.recv(4096)
                            peer.sendall(response)
                    except Exception as error:
                        errors.append(error)
                worker = threading.Thread(target=reply, daemon=True)
                worker.start()
                def bootstrap(_handle):
                    with socket.create_connection(listener.getsockname(), timeout=5) as stream:
                        return controller._http(stream, '/', {})
                failed = FakeConnection(json.dumps({'method': 'bootstrap-mail', 'handle': HANDLE}).encode() + b'\n')
                with patch.object(controller, 'bootstrap', side_effect=bootstrap), \
                        patch.object(workload, 'reconcile') as reconcile:
                    self.assertFalse(controller.handle_request(failed, 1000))
                    healthy = FakeConnection(self.raw() + b'\n')
                    with patch.object(workload, 'start', return_value={'state': 'running'}):
                        self.assertTrue(controller.handle_request(healthy, 1000))
                    reconcile.assert_not_called()
                worker.join(5)
                self.assertFalse(worker.is_alive())
                self.assertEqual([], errors)
                self.assertEqual([b'{"error":"restricted-workload-request-failed"}\n'], failed.sent)
                self.assertEqual([b'{"state":"running"}\n'], healthy.sent)

    def raw(self, **values):
        return json.dumps(dict(method='start', handle=HANDLE, **values)).encode()

    def test_fixed_handle_request_dispatches_without_environment_or_paths(self):
        connection = FakeConnection(self.raw() + b'\n')
        with patch.object(workload, 'start', return_value={'state': 'running'}) as start:
            self.assertEqual('start', controller.serve(connection, 1000))
            start.assert_called_once_with(HANDLE)
        self.assertEqual([b'{"state":"running"}\n'], connection.sent)

    def test_duplicate_fields_are_rejected(self):
        raw = ('{"method":"start","method":"stop","handle":"' + HANDLE + '"}').encode()
        with self.assertRaisesRegex(workload.WorkloadError, 'duplicate-request-field'):
            controller.request(raw)

    def test_client_cannot_add_pid_namespace_command_or_environment(self):
        for key, value in (('pid', 1), ('namespace', '/proc/1/ns/net'), ('command', '/bin/sh'),
                           ('environment', {'LD_PRELOAD': '/tmp/evil'}), ('port', 22),
                           ('unit', 'unrelated.service')):
            with self.subTest(key=key), self.assertRaises(workload.WorkloadError):
                controller.request(self.raw(**{key: value}))

    def test_invalid_method_handle_and_size_are_rejected(self):
        for raw in (b'', b' ' * 257, b'[]', b'{"method":"shell","handle":"' + HANDLE.encode() + b'"}',
                    b'{"method":"start","handle":"../other"}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                controller.request(raw)

    def test_wrong_peer_cannot_invoke_manager(self):
        with patch.object(workload, 'start') as start:
            with self.assertRaisesRegex(workload.WorkloadError, 'peer-denied'):
                controller.serve(FakeConnection(self.raw() + b'\n', uid=2000), 1000)
            start.assert_not_called()

    def test_multiple_or_trailing_requests_are_not_dispatched(self):
        for raw in (self.raw() + b'\n{}\n', self.raw() + b'\ntrailing', self.raw()):
            with patch.object(workload, 'start') as start:
                with self.assertRaises(workload.WorkloadError):
                    controller.serve(FakeConnection(raw), 1000)
                start.assert_not_called()


class LauncherTest(unittest.TestCase):
    def test_reserved_logging_option_never_overwrites_or_skips_product_options(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'conf').mkdir()
            config = root / 'conf/wrapper.conf'
            original = ''.join('wrapper.java.additional.' + str(i) + '=-Dtest.option=' + str(i) + '\n'
                               for i in range(1, 10))
            config.write_text(original)
            launcher.verify_wrapper_options(root)
            self.assertEqual(original, config.read_text())
            for changed in (original + 'wrapper.java.additional.10=-Dproduct.required=true\n',
                            original.replace('wrapper.java.additional.9=', 'wrapper.java.additional.11='),
                            original + 'wrapper.java.additional.1=-Dduplicate=true\n',
                            original + '#include other.conf\n',
                            original + 'wrapper.java.additional.9.scope=app_only\n'):
                with self.subTest(configuration=changed):
                    config.write_text(changed)
                    with self.assertRaisesRegex(ValueError, 'workload-wrapper-options-unsupported'):
                        launcher.verify_wrapper_options(root)


    def test_wrapper_logging_is_fixed_bounded_and_inside_role_state(self):
        for role in workload.ROLES:
            command, _environment = launcher.command(role)
            properties = dict(item.split('=', 1) for item in command[command.index('--') + 2:])
            self.assertEqual('/node/logs/wrapper.log', properties['wrapper.logfile'])
            self.assertEqual('2M', properties['wrapper.logfile.maxsize'])
            self.assertEqual('3', properties['wrapper.logfile.maxfiles'])
            self.assertEqual('256', properties['wrapper.java.maxmemory'])
            self.assertEqual('-Dcrypta.log.dir=/node/logs', properties['wrapper.java.additional.10'])
            self.assertEqual('--config-file', properties['wrapper.app.parameter.1'])
            self.assertEqual('/node/config/cryptad.ini', properties['wrapper.app.parameter.2'])

    def test_only_historical_role_gets_prospective_startup_allowance(self):
        for role in workload.ROLES:
            command, _environment = launcher.command(role)
            properties = dict(item.split('=', 1) for item in command[command.index('--') + 2:])
            self.assertEqual('60' if role == 'previous' else '30', properties['wrapper.startup.timeout'])
        changed = launcher.launcher_policy()
        changed['wrapperStartupTimeoutSeconds']['previous'] = 600
        self.assertEqual(60, launcher.launcher_policy()['wrapperStartupTimeoutSeconds']['previous'])

    def test_only_role_state_and_exact_inputs_are_mounted(self):
        for role in workload.ROLES:
            with self.subTest(role=role):
                command, environment = launcher.command(role)
                mounted = []
                for index, token in enumerate(command):
                    if token in ('--bind', '--ro-bind'):
                        mounted.append((token, command[index+1], command[index+2]))
                inputs = launcher.ROOT / 'roles' / role
                state = launcher.ROOT / 'state' / role
                self.assertEqual([
                    ('--ro-bind', '/usr', '/usr'),
                    ('--ro-bind', str(inputs / 'package'), '/package'),
                    ('--ro-bind', str(inputs / 'jdk'), '/jdk'),
                    ('--ro-bind', str(inputs / 'apps'), '/inputs/apps'),
                    ('--ro-bind', str(inputs / 'public'), '/inputs/public'),
                    ('--bind', str(state), '/node'), ('--bind', str(state / 'tmp'), '/tmp')], mounted)
                self.assertEqual('/package/bin/cryptad', command[command.index('--')+1])
                self.assertEqual('bubblewrap', environment['CRYPTAD_APPHOST_SANDBOX_PROVIDER'])
                self.assertNotIn('GITHUB_TOKEN', environment)
                self.assertNotIn('LD_PRELOAD', environment)

    def test_daemon_profile_permits_nested_apphost_namespace_creation(self):
        command, _environment = launcher.command(ROLE)
        self.assertIn('--unshare-user', command)
        self.assertIn('--unshare-pid', command)
        self.assertNotIn('--disable-userns', command)
        self.assertNotIn('--assert-userns-disabled', command)
        self.assertEqual('ALL', command[command.index('--cap-drop')+1])

    def test_invalid_role_never_becomes_path_or_command(self):
        for role in ('../authority', 'candidate-sender;id', 'previous/../../', None):
            with self.subTest(role=role), self.assertRaises(ValueError):
                launcher.command(role)


class PreparationTest(unittest.TestCase):
    @unittest.skipUnless(os.geteuid() == 0, 'preparation fixture drops to a distinct role UID')
    def test_restrictive_umask_preserves_role_access_and_private_authority(self):
        # Exercise the real preparation writes and UID-dropped initialization. Product
        # admission, systemd and tmpfs mounting are fixtures, not installed acceptance.
        preparation.sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'interop'))
        preparation.sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import cross_version_runtime as runtime
        import restricted_workload_network as network
        with tempfile.TemporaryDirectory(prefix='workload-umask-', dir='/var/lib') as directory, ExitStack() as stack:
            root = Path(directory)
            root.chmod(0o711)
            stack.enter_context(patch.object(workload, 'ROOT', root))
            stack.enter_context(patch.object(workload, 'locked', side_effect=nullcontext))
            users = {role: SimpleNamespace(pw_uid=61000 + index, pw_gid=61000 + index)
                     for index, role in enumerate(workload.ROLES)}
            stack.enter_context(patch.object(workload, 'account', side_effect=users.__getitem__))
            stack.enter_context(patch.object(workload, 'manager', return_value={'ActiveState': 'inactive'}))
            stack.enter_context(patch.object(workload, 'quiescent', return_value=True))
            stack.enter_context(patch.object(workload, 'execution_record_digest', return_value='fixed'))
            stack.enter_context(patch.object(preparation.os, 'statvfs', return_value=SimpleNamespace(
                f_bavail=20 * 1024**3, f_frsize=1)))
            stack.enter_context(patch.object(network, 'setup'))
            stack.enter_context(patch.dict('sys.modules', {'workload_installation': SimpleNamespace(
                verify=lambda: {'sourceCommit': 'source'})}))
            from cryptad_certification import cross_version_evidence
            stack.enter_context(patch.object(cross_version_evidence, 'validate_plan'))
            stack.enter_context(patch.object(runtime, 'runner_identity', return_value={'sourceCommit': 'source'}))
            stack.enter_context(patch.object(preparation, 'configuration_identity', return_value='config'))
            stack.enter_context(patch.object(preparation, 'configuration', return_value='fixed-config'))
            stack.enter_context(patch.object(preparation, 'tree_identity', return_value={'sizeBytes': 0, 'fileCount': 0}))
            stack.enter_context(patch.object(runtime, 'tree_digest', return_value='jdk'))
            stack.enter_context(patch.object(runtime, 'require_native_target'))
            stack.enter_context(patch.object(runtime, 'packaged_daemon_identity', side_effect=lambda _p, source: source))
            stack.enter_context(patch.object(runtime, 'digest_file', return_value='java'))
            archive = root / 'fixture.tar'
            with preparation.tarfile.open(archive, 'w'):
                pass
            jdk = root / 'jdk'
            jdk.mkdir()
            trust = root / 'trust'
            trust.write_bytes(b'')
            def extract(_source, destination, *_args):
                destination.mkdir()
                return destination
            stack.enter_context(patch.object(runtime, 'extract_package', side_effect=extract))
            stack.enter_context(patch.object(runtime, 'extract_app_bundle', side_effect=extract))
            def mount(arguments, **_kwargs):
                # Emulate only tmpfs root ownership; no mount or host unit is changed.
                node = Path(arguments[-1])
                user = users[node.name]
                os.chown(node, user.pw_uid, user.pw_gid)
                node.chmod(0o700)
            stack.enter_context(patch.object(preparation.subprocess, 'run', side_effect=mount))
            plan = dict(provenanceClass='source-build-comparison', experimentId='synthetic',
                        producer={'sourceCommit': 'source'}, nodes=[])
            private = dict(root='/private', nodes={})
            for role in workload.ROLES:
                apps = [] if role in ('previous', 'relay-no-apps') else [dict(
                    appId='mail-prototype', bundleDigest='app', bundlePath=str(archive))]
                plan['nodes'].append(dict(role=role, product='cryptad', appDigests=['app'] if apps else [],
                    configDigest='config', artifactDigest='fixture', artifactSize=0,
                    sourceCommit=role, packageTarget='fixture', runtimeDigest='jdk'))
                private['nodes'][role] = dict(archivePath=str(archive), javaHome=str(jdk),
                    fnpPort=network.FNP_PORT, fcpPort=network.FCP_PORT, httpPort=network.HTTP_PORT,
                    apps=apps, trustedKeysPath=str(trust),
                    trustedKeysDigest='sha256:' + preparation.hashlib.sha256(b'').hexdigest())
            authorization = dict(syntheticContent=True, planDigest=runtime.canonical_digest(plan),
                                 experimentId='synthetic', maxSeconds=60, maxOperations=10)
            previous_umask = os.umask(0o077)
            try:
                preparation.prepare(plan, private, authorization)
            finally:
                os.umask(previous_umask)
            for name in ('authority', 'staging'):
                self.assertEqual(0o700, stat.S_IMODE((root / name).stat().st_mode))
            for name in ('roles', 'state'):
                self.assertEqual(0o711, stat.S_IMODE((root / name).stat().st_mode))
            for role, user in users.items():
                inputs = root / 'roles' / role
                self.assertEqual(0o750, stat.S_IMODE(inputs.stat().st_mode))
                self.assertEqual(0o444, stat.S_IMODE((inputs / 'launch.json').stat().st_mode))
                child = os.fork()
                if child == 0:
                    try:
                        os.setgroups([])
                        os.setgid(user.pw_gid)
                        os.setuid(user.pw_uid)
                        json.loads((inputs / 'launch.json').read_text())
                        self.assertEqual('fixed-config', (root / 'state' / role / 'config/cryptad.ini').read_text())
                        self.assertFalse(os.access(root / 'authority', os.X_OK))
                        self.assertFalse(os.access(root / 'campaign.json', os.R_OK))
                        os._exit(0)
                    except BaseException:
                        os._exit(1)
                self.assertEqual(0, os.waitpid(child, 0)[1])

    def selection(self):
        return (dict(provenanceClass='source-build-comparison', experimentId='synthetic',
                     nodes=[{'role': role} for role in workload.ROLES]),
                dict(root='/private', nodes={role: {} for role in workload.ROLES}),
                dict(syntheticContent=True, planDigest='exact', experimentId='synthetic',
                     maxSeconds=60, maxOperations=10))

    def test_unadapted_workloads_and_invalid_budgets_fail_before_lock_or_mutation(self):
        runtime = SimpleNamespace(canonical_digest=lambda _plan: 'exact')
        for section, key, value in (('plan', 'workloadInputs', {'catalog': True}),
                                   ('plan', 'nodes', [{'role': '../private-selection'}]
                                    + [{'role': role} for role in workload.ROLES[1:]]),
                                   ('plan', 'nodes', [{'role': role} for role in reversed(workload.ROLES)]),
                                   ('plan', 'provenanceClass', 'original-release'),
                                   ('authorization', 'maxSeconds', 3601),
                                   ('authorization', 'maxOperations', 0),
                                   ('authorization', 'syntheticContent', False)):
            with self.subTest(key=key):
                plan, private, authorization = self.selection()
                (plan if section == 'plan' else authorization)[key] = value
                with patch.dict('sys.modules', {'cross_version_runtime': runtime}), \
                        patch.object(workload, 'locked') as locked, patch.object(workload, 'write') as write:
                    with self.assertRaisesRegex(workload.WorkloadError, 'profile-selection-unsupported'):
                        preparation.prepare(plan, private, authorization)
                    locked.assert_not_called()
                    write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
