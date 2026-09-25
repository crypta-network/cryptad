"""Local cleanup ordering and retention tests; no installed systemd execution."""
from contextlib import contextmanager, ExitStack, nullcontext
import fcntl
import hashlib
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'interop'))
import pr314_workload_driver as driver


class VolatilePublicationTest(unittest.TestCase):
    def test_large_private_snapshot_is_atomic_exclusive_and_keeps_generic_cap(self):
        raw = b'x' * 70000  # Above restricted_workload.write's 64-KiB record limit.
        self.assertLess(len(raw), driver.VOLATILE_MAX)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'pr315-workload-volatile.private.json'
            driver._write_volatile_bytes(target, raw)
            self.assertEqual(raw, target.read_bytes())
            self.assertEqual(0o600, target.stat().st_mode & 0o777)
            self.assertEqual(1, target.stat().st_nlink)
            with self.assertRaises(FileExistsError):
                driver._write_volatile_bytes(target, b'replacement')
            self.assertEqual(raw, target.read_bytes())
            self.assertEqual([target], list(Path(directory).iterdir()))


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


@unittest.skipUnless(sys.platform.startswith('linux') and os.getuid() > 0,
                     'Linux actor /proc epoch required')
class RunnerControlProbeTest(unittest.TestCase):
    def test_vmadmin_policy_denial_is_bound_to_actor_epoch_and_unchanged_unit(self):
        now = time.monotonic_ns()
        before = {'invocationId': 'a' * 32, 'cgroupIdentity': [1, 25],
                  'bootId': 'boot', 'mainPid': 200, 'mainStartTicks': 300,
                  'observedMonotonicNs': now - 500}
        after = dict(before, observedMonotonicNs=now + 10**9)
        sender = {'state': 'running', 'stateDigest': 'd' * 64,
                  'managerInvocation': 'b' * 32, 'cgroupIdentity': [1, 99],
                  'bootId': 'boot'}
        result = {'roleKernelRoster': {'runnerUid': os.getuid()},
                  'roleKernelRosterWindow': {'startedMonotonicNs': now - 1000,
                                             'finishedMonotonicNs': now - 900}}
        workload = Mock(ROOT=Path('/private-task-root'))
        workload.observe.return_value = sender
        denied = b'Failed to stop fixed unit: Interactive authentication required.\n'
        process = Mock(pid=os.getpid(), returncode=1)
        process.poll.return_value = 1
        user = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        handoff = {'handles': {'candidate-sender': 'a' * 64}}
        with patch.object(driver.pwd, 'getpwnam', return_value=user), \
                patch.object(driver, 'controller_unit_identity', side_effect=[before, after]), \
                patch.object(driver, 'bounded_runner_control_output', return_value=(b'', denied)), \
                patch.object(driver.subprocess, 'Popen', return_value=process) as launched:
            self.assertEqual({'status': 'captured'},
                             driver.probe_runner_control(workload, handoff, result))
        self.assertEqual('/usr/bin/systemctl', launched.call_args.args[0][0])
        self.assertEqual('stop', launched.call_args.args[0][2])
        audit = workload.write.call_args.args[1]
        self.assertEqual(os.getuid(), audit['actor']['uid'])
        self.assertEqual(os.getpid(), audit['actor']['pid'])
        self.assertEqual(hashlib.sha256(denied).hexdigest(), audit['responseDigest'])
        self.assertEqual(sender['stateDigest'], audit['senderStateAfter'])

        process.returncode = 0
        workload.write.reset_mock()
        with patch.object(driver.pwd, 'getpwnam', return_value=user), \
                patch.object(driver, 'controller_unit_identity', return_value=before), \
                patch.object(driver, 'bounded_runner_control_output', return_value=(b'', denied)), \
                patch.object(driver.subprocess, 'Popen', return_value=process):
            with self.assertRaisesRegex(RuntimeError, 'forbidden-unit-stop-admitted'):
                driver.probe_runner_control(workload, handoff, result)
        workload.write.assert_not_called()

        process.returncode = 1
        changed = dict(after, invocationId='c' * 32)
        with patch.object(driver.pwd, 'getpwnam', return_value=user), \
                patch.object(driver, 'controller_unit_identity', side_effect=[before, changed]), \
                patch.object(driver, 'bounded_runner_control_output', return_value=(b'', denied)), \
                patch.object(driver.subprocess, 'Popen', return_value=process):
            with self.assertRaisesRegex(RuntimeError, 'runner-control-target-changed'):
                driver.probe_runner_control(workload, handoff, result)
        workload.write.assert_not_called()

    def test_fixed_systemctl_output_reader_reaps_oversized_child(self):
        process = subprocess.Popen([sys.executable, '-c',
            'import sys; sys.stderr.write("x" * 4096)'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with self.assertRaisesRegex(ValueError, 'runner-control-output-limit'):
            driver.bounded_runner_control_output(process)
        self.assertIsNotNone(process.returncode)


class AdministratorFnpSamplerTest(unittest.TestCase):
    def test_probe_root_record_requires_current_kernel_child_and_verified_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'authority').mkdir()
            result = {'pid': 2, 'uid': 986, 'gid': 986,
                      'namespaceInodes': {'mnt': 5, 'pid': 44, 'net': 7, 'user': 8},
                      'mountEscape': {'operation': 'unshare-mount', 'returnCode': -1,
                                      'errno': 'EPERM'}}
            worker = {'hostPid': 300, 'namespacePids': [300, 20, 2],
                      'hostParentPid': 299, 'startTicks': 20,
                      'mountNamespaceIdentity': [1, 5], 'userNamespaceIdentity': [1, 8],
                      'networkNamespaceIdentity': [1, 7], 'pidNamespace': 'pid:[44]',
                      'noNewPrivileges': True, 'effectiveCapabilities': 0,
                      'executableDigest': 'sha256:' + 'a' * 64}
            leader = dict(worker, hostPid=299, hostParentPid=100, startTicks=10,
                          namespacePids=[299, 19, 1],
                          executableDigest='sha256:' + 'e' * 64)
            outer = {'hostPid': 100, 'namespacePids': [100, 10],
                     'mountNamespaceIdentity': [1, 6],
                     'executableDigest': 'sha256:' + 'b' * 64}
            mail_worker = dict(worker, hostPid=301, namespacePids=[301, 21, 2],
                               pidNamespace='pid:[45]', mountNamespaceIdentity=[1, 15])
            sample = {'state': 'running', 'provenance': 'controller-kernel-sample',
                      'managerInvocation': 'c' * 32, 'bootId': 'boot',
                      'cgroupIdentity': [1, 99], 'stateDigest': 'd' * 64,
                      'networkNamespaceIdentity': [1, 7],
                      'observedMonotonicNs': 100,
                      'processes': [worker, leader, mail_worker, outer]}
            calls = []
            def write(path, value, **options):
                calls.append((path, value, options))
            workload = SimpleNamespace(ROOT=root, locked=nullcontext,
                observe=Mock(side_effect=[sample, dict(sample, observedMonotonicNs=200)]),
                retained=lambda handle: ({'deadlineMonotonicNs': time.monotonic_ns() + 10**10},
                                         'candidate-sender', {}),
                admit=lambda campaign: None, exact=lambda *arguments: None,
                manager=lambda *arguments: {},
                read=lambda path: {'probeIdentity': {'digest': 'sha256:' + 'e' * 64,
                    'fileCount': 3, 'sizeBytes': 100}},
                account=lambda role: SimpleNamespace(pw_uid=986, pw_gid=986), write=write)
            sampler = driver.AdministratorFnpSampler(workload, 'recipient', {},
                sender_handle='sender', probe_digest='sha256:' + 'f' * 64,
                sender_jdk_digest=outer['executableDigest'])
            snapshot = SimpleNamespace(read_file=Mock(return_value=json.dumps(result,
                sort_keys=True, separators=(',', ':')).encode()))
            storage = SimpleNamespace(verify_installed_app=Mock(return_value={
                'digest': 'sha256:' + 'e' * 64, 'fileCount': 3, 'sizeBytes': 100}))
            with patch.dict('sys.modules', {'runtime_snapshot': snapshot,
                                            'restricted_workload_storage': storage}), patch(
                                                'cross_version_runtime.digest_file',
                                                return_value=worker['executableDigest']):
                response = sampler.probe()
                self.assertEqual('probe', response['phase'])
                self.assertEqual(1, len(calls))
                self.assertEqual(worker, calls[0][1]['worker'])
                self.assertEqual(leader, calls[0][1]['sandboxLeader'])
                self.assertTrue(calls[0][2]['create'])
                storage.verify_installed_app.assert_called_once()
                workload.observe = Mock(side_effect=[sample, dict(sample,
                    observedMonotonicNs=200,
                    processes=[dict(worker, namespacePids=[300, 20, 3]),
                               leader, mail_worker, outer])])
                with self.assertRaisesRegex(ValueError, 'actor-ambiguous'):
                    sampler.probe()

    def test_root_only_fixed_recipient_pair_is_written_before_observer_reply(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'authority').mkdir()
            calls = []
            record = {'managerInvocation': 'a' * 32}
            def write(path, value, **options):
                if options.get('create') and path.exists():
                    raise FileExistsError(path)
                path.write_text(json.dumps(value))
            workload = SimpleNamespace(ROOT=root, locked=nullcontext,
                retained=lambda handle: ({}, 'candidate-recipient', record),
                admit=lambda campaign: calls.append('admit'),
                manager=lambda role, operation: {},
                exact=lambda role, retained, state: calls.append('exact'),
                current=lambda campaign: None,
                write=write, read=lambda path: json.loads(path.read_text()))
            def sample(moment):
                return {'schemaVersion': 1, 'kind': 'pr315-fixed-fnp-counters',
                    'policyDigest': 'b' * 64, 'bootId': 'boot',
                    'switchNamespaceIdentity': [1, 42], 'observedMonotonicNs': moment,
                    'counters': {'fixed': {'packets': moment, 'bytes': moment * 10}}}
            network = SimpleNamespace(read_fnp_counters=Mock(side_effect=[sample(10), sample(20)]))
            sampler = driver.AdministratorFnpSampler(workload, 'fixed-recipient-handle', {})
            with patch.dict('sys.modules', {'restricted_workload_network': network}):
                before = sampler.sample('before')
                after = sampler.sample('after')
                with self.assertRaisesRegex(ValueError, 'phase-invalid'):
                    sampler.sample('after')
            pair = json.loads((root / 'authority/fnp-content-probe.json').read_text())
        self.assertEqual('pr315-administrator-fnp-counter-pair', pair['kind'])
        self.assertEqual((sample(10), sample(20)), (pair['before'], pair['after']))
        self.assertEqual(('before', 'after'), (before['phase'], after['phase']))
        self.assertEqual(4, calls.count('exact'))
        self.assertEqual(2, calls.count('admit'))
        self.assertEqual(2, network.read_fnp_counters.call_count)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux AF_UNIX seqpacket required')
    def test_socket_accepts_only_fixed_counter_and_probe_packets(self):
        sampler = driver.AdministratorFnpSampler(SimpleNamespace(), 'fixed', {})
        sampler.sample = Mock(return_value={'phase': 'before', 'managerInvocation': 'a' * 32,
                                             'snapshot': {'observedMonotonicNs': 10}})
        with ExitStack() as stack:
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            stack.enter_context(parent)
            stack.enter_context(child)
            child.sendall(b'B')
            self.assertTrue(sampler.serve(parent))
            self.assertEqual('before', json.loads(child.recv(8192))['phase'])
            sampler.sample.assert_called_once_with('before')
            child.sendall(b'X')
            self.assertTrue(sampler.serve(parent))
            self.assertEqual({'error': 'pr315-admin-fnp-sample-failed'},
                             json.loads(child.recv(8192)))
            sampler.sample.assert_called_once()
            sampler.probe = Mock(return_value={'phase': 'probe', 'recordDigest': 'b' * 64})
            child.sendall(b'P')
            self.assertTrue(sampler.serve(parent))
            self.assertEqual('probe', json.loads(child.recv(8192))['phase'])
            sampler.probe.assert_called_once_with()
            sampler.probe = Mock(side_effect=ValueError('private-actor-input'))
            child.sendall(b'P')
            self.assertTrue(sampler.serve(parent))
            self.assertEqual({'error': 'pr315-admin-probe-sample-failed'},
                             json.loads(child.recv(8192)))
            self.assertEqual({'phase': 'probe', 'exceptionType': 'ValueError'},
                             sampler.diagnostics['probeAdminFailure'])
        self.assertEqual('ValueError', sampler.diagnostics['fnpAdminFailure']['exceptionType'])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux AF_UNIX seqpacket required')
    def test_observer_receives_only_administrator_fixed_sample(self):
        sampler = driver.AdministratorFnpSampler(SimpleNamespace(), 'fixed', {})
        expected = {'phase': 'before', 'managerInvocation': 'a' * 32,
                    'snapshot': {'observedMonotonicNs': 10}}
        sampler.sample = Mock(return_value=expected)
        with ExitStack() as stack:
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            stack.enter_context(parent)
            stack.enter_context(child)
            worker = threading.Thread(target=sampler.serve, args=(parent,), daemon=True)
            worker.start()
            self.assertEqual(expected, driver.request_administrator_fnp(
                child, 'before', time.monotonic_ns() + 5 * 10**9))
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
        sampler.sample.assert_called_once_with('before')

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux AF_UNIX seqpacket required')
    def test_parent_collects_child_result_while_serving_fixed_counter_request(self):
        sampler = driver.AdministratorFnpSampler(SimpleNamespace(), 'fixed', {})
        expected = {'phase': 'before', 'managerInvocation': 'a' * 32,
                    'snapshot': {'observedMonotonicNs': 10}}
        sampler.sample = Mock(return_value=expected)
        with ExitStack() as stack:
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            admin_parent, admin_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            for channel in (parent, child, admin_parent, admin_child):
                stack.enter_context(channel)
            def observer():
                value = driver.request_administrator_fnp(
                    admin_child, 'before', time.monotonic_ns() + 5 * 10**9)
                child.sendall(json.dumps(value).encode())
                child.close()
                admin_child.close()
            worker = threading.Thread(target=observer, daemon=True)
            worker.start()
            with patch.object(driver, 'wait_child', return_value=0):
                raw, status = driver.collect_child(parent, 12345, time.monotonic() + 5,
                    admin_channel=admin_parent, admin_sampler=sampler)
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
        self.assertEqual(expected, json.loads(raw))
        self.assertEqual(0, status)
        sampler.sample.assert_called_once_with('before')


class CancellationObservationTest(unittest.TestCase):
    def test_active_role_trigger_requires_exact_receipts_after_administrator_stop(self):
        from cross_version_runtime import canonical_digest
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'authority').mkdir()
            (root / 'cgroups').mkdir()
            deadline = time.monotonic_ns() + 10 * 10**9
            campaign = {'generation': 'c' * 64, 'deadlineMonotonicNs': deadline}
            boot = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            handles = {}
            records = {}
            receipts = {}
            rows = []
            for index, role in enumerate(driver.ROLE_NAMES):
                handles[role] = format(index + 1, '064x')
                records[role] = {'managerInvocation': format(index + 1, '032x'),
                                 'bootId': boot, 'cgroupIdentity': [1, 99 + index]}
                receipts[role] = {'role': role, **records[role]}
                group = root / 'cgroups' / role
                group.mkdir()
                (group / 'cgroup.events').write_text('populated 1\n')
                rows.append({'role': role, 'invocationId': records[role]['managerInvocation'],
                             'bootId': 'a' * 32, 'cgroupDigest': canonical_digest({
                                 'role': role, 'identity': records[role]['cgroupIdentity']})[7:]})
            terminal = [False]
            def read(path):
                if path.name == 'campaign.json':
                    return campaign
                return receipts[path.name.removesuffix('-stop.json')]
            def retained(handle):
                role = next(role for role, value in handles.items() if value == handle)
                return campaign, role, records[role]
            def manager(role, operation):
                return {'ActiveState': 'inactive' if terminal[0] else 'active',
                        'SubState': 'dead' if terminal[0] else 'running',
                        'MainPID': '0' if terminal[0] else str(1000 + driver.ROLE_NAMES.index(role))}
            workload = SimpleNamespace(ROOT=root, locked=nullcontext, read=read,
                current=Mock(), retained=retained, manager=manager, exact=Mock(),
                group=lambda role: root / 'cgroups' / role,
                quiescent=lambda role: terminal[0])
            before = driver.begin_cancellation(workload, {'handles': handles},
                                               {'roleKernelRoster': {'roles': rows}})
            self.assertEqual(len(driver.ROLE_NAMES), len(before['preRoles']))
            self.assertEqual(64, len(before['triggerEventDigest']))
            forged = [dict(row) for row in rows]
            forged[0]['cgroupDigest'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'roster-mismatch'):
                driver.begin_cancellation(workload, {'handles': handles},
                                          {'roleKernelRoster': {'roles': forged}})
            terminal[0] = True
            after = driver.complete_cancellation(workload, before)
            self.assertGreater(after['terminalObservedNs'], before['triggerStartedNs'])
            self.assertEqual([], after['populatedCgroups'])
            receipts['previous']['cgroupIdentity'] = [1, 1000]
            with self.assertRaisesRegex(ValueError, 'terminal-mismatch'):
                driver.complete_cancellation(workload, before)


class ControllerRestartObservationTest(unittest.TestCase):
    def test_waits_for_all_bound_roles_and_exact_stop_receipts_before_new_start(self):
        rows = [{'role': role, 'managerInvocation': format(index + 1, '032x'),
                 'bootId': 'boot', 'cgroupIdentity': [1, index + 1], 'mainPid': 1000 + index}
                for index, role in enumerate(driver.ROLE_NAMES)]
        records = {row['role']: dict(row) for row in rows}
        workload = SimpleNamespace(ROOT=Path('/fixed-private-root'),
            manager=lambda role, operation: {'ActiveState': 'inactive', 'SubState': 'dead',
                                              'MainPID': '0'},
            read=lambda path: records[path.name.removesuffix('.json')],
            stop_receipt=lambda role, record: {'observedMonotonicNs': 123},
            quiescent=lambda role: True)
        selected = driver.wait_bound_roles_stopped(workload, {
            'preRoles': rows, 'campaignDeadlineNs': time.monotonic_ns() + 5 * 10**9})
        self.assertEqual(set(driver.ROLE_NAMES), {row['role'] for row in selected})
        self.assertTrue(all(row['mainPid'] == 0 for row in selected))

    def test_fixed_restart_requires_a_distinct_real_manager_invocation(self):
        active = {'triggerStartedNs': 10, 'campaignDeadlineNs': time.monotonic_ns() + 10**10,
                  'preRoles': [{'role': role, 'managerInvocation': format(index + 1, '032x'),
                                'bootId': 'boot', 'cgroupIdentity': [1, index + 1],
                                'mainPid': 1000 + index}
                               for index, role in enumerate(driver.ROLE_NAMES)]}
        before = {'InvocationID': 'a' * 32, 'ActiveState': 'active',
                  'SubState': 'running', 'MainPID': '100', 'Result': 'success'}
        after = dict(before, InvocationID='b' * 32, MainPID='200')
        with patch.object(driver, 'begin_cancellation', return_value=active), \
                patch.object(driver, 'controller_unit_state', side_effect=[before, after]) as observed, \
                patch.object(driver, 'wait_bound_roles_stopped', return_value=[
                    {'role': row['role'], 'activeState': 'inactive', 'subState': 'dead',
                     'mainPid': 0, 'receiptObservedMonotonicNs': 20} for row in active['preRoles']]), \
                patch.object(driver.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run:
            intent = driver.begin_controller_restart(SimpleNamespace(), {}, {})
            result = driver.trigger_controller_restart(SimpleNamespace(), intent)
        self.assertEqual('pr315-administrator-controller-restart', result['kind'])
        self.assertEqual('b' * 32, result['afterController']['InvocationID'])
        self.assertEqual(2, observed.call_count)
        self.assertEqual(['/usr/bin/systemctl', 'kill', '--kill-who=main', '--signal=SIGKILL',
                          'cryptad-workload-controller.service'], run.call_args_list[0].args[0])
        self.assertEqual(['/usr/bin/systemctl', 'start',
                          'cryptad-workload-controller.service'], run.call_args_list[1].args[0])
        with patch.object(driver, 'controller_unit_state', return_value=before), \
                patch.object(driver, 'wait_bound_roles_stopped', return_value=[]), \
                patch.object(driver.subprocess, 'run', return_value=SimpleNamespace(returncode=0)):
            with self.assertRaisesRegex(ValueError, 'invocation-unchanged'):
                driver.trigger_controller_restart(SimpleNamespace(), intent)

    def test_terminal_reconciliation_requires_all_four_exact_stop_reasons(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'authority').mkdir()
            rows = [{'role': role, 'managerInvocation': format(index + 1, '032x'),
                     'bootId': 'boot', 'cgroupIdentity': [1, index + 1],
                     'mainPid': 1000 + index}
                    for index, role in enumerate(driver.ROLE_NAMES)]
            records = {row['role']: {'stopReason': 'controller-reconciliation'} for row in rows}
            def read(path):
                role = path.name.split('.')[0].removesuffix('-stop')
                return next(row for row in rows if row['role'] == role) if path.name.endswith('-stop.json') else records[role]
            workload = SimpleNamespace(ROOT=root, locked=nullcontext, read=read,
                manager=lambda role, operation: {'ActiveState': 'inactive', 'SubState': 'dead',
                                                  'MainPID': '0'}, quiescent=lambda role: True)
            context = {'triggerStartedNs': time.monotonic_ns() - 100, 'preRoles': rows}
            completed = driver.complete_controller_restart(workload, context)
            self.assertEqual([], completed['populatedCgroups'])
            self.assertEqual(0, completed['remainingDescendants'])
            records['relay-no-apps']['stopReason'] = 'requested'
            with self.assertRaisesRegex(ValueError, 'terminal-mismatch'):
                driver.complete_controller_restart(workload, context)


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
                'terminal-report' if path == driver.REPORT else 'private-diagnostics'))
        def prepare(*args):
            events.append('prepare')
            if failure == 'prepare':
                raise ValueError('setup-failure')
            return {'deadlineMonotonicNs': campaign_deadline + (1 if failure == 'handoff' else 0),
                    'handles': {'candidate-recipient': 'a' * 64}}
        def cleanup(_workload):
            events.append('cleanup')
            if failure == 'cleanup':
                raise ValueError('cleanup-failure')
        def capture(*args, observer_root):
            self.assertEqual(Path(selection['private']['root']), observer_root)
            return {'sentinel': {'status': 'matched'}}
        modules = {'installation': installation, 'restricted_workload': workload,
            'pr315_workload_evidence': SimpleNamespace(MAX_OUTPUT=driver.VOLATILE_MAX,
                prepare_sentinel=lambda _: 'sha256:' + 'a' * 64,
                capture=capture),
            'workload_installation': SimpleNamespace(install=lambda: None),
            'restricted_workload_prepare': SimpleNamespace(prepare=prepare),
            'restricted_workload_launcher': SimpleNamespace(launcher_policy=lambda: {
                'revision': 'offline-test', 'privateVolatileMaxBytes': driver.VOLATILE_MAX}),
            'cross_version_workload': SimpleNamespace(InstalledWorkloadAdapter=Mock()),
            'cryptad_certification.cross_version_evidence': SimpleNamespace(Journal=Mock())}
        with ExitStack() as stack:
            stack.enter_context(patch.dict('sys.modules', modules))
            stack.enter_context(patch.object(driver, 'TEST_KIT', repository))
            stack.enter_context(patch.object(driver, 'stage_role_probe', return_value='f' * 64))
            stack.enter_context(patch.object(driver, 'prepare_sibling_canary', return_value='d' * 64))
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
            stack.enter_context(patch.object(driver, 'retain_volatile',
                side_effect=lambda *_: events.append('volatile-diagnostics')))
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


class MeasuredRoleProbeStagingTest(unittest.TestCase):
    def test_recipient_canary_is_owned_and_created_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recipient = root / 'state/candidate-recipient'
            recipient.mkdir(parents=True)
            user = SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())
            workload = SimpleNamespace(ROOT=root, account=lambda role: user)
            digest = driver.prepare_sibling_canary(workload)
            target = recipient / driver.SIBLING_CANARY
            self.assertEqual(32, target.stat().st_size)
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), digest)
            self.assertEqual(user.pw_uid, target.stat().st_uid)
            with self.assertRaises(FileExistsError):
                driver.prepare_sibling_canary(workload)

    def test_only_the_exact_test_kit_script_can_be_staged(self):
        source = Path(driver.__file__).resolve().parents[3]
        relative = 'tools/release-certification/restricted/pr315_role_probe.py'
        expected = hashlib.sha256((source / relative).read_bytes()).hexdigest()
        fake_installation = SimpleNamespace(secured=lambda path: path)
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict('sys.modules', {'installation': fake_installation}), \
                patch.object(driver, 'TEST_KIT', source):
            workload = SimpleNamespace(ROOT=Path(directory))
            with self.assertRaisesRegex(ValueError, 'test-kit-mismatch'):
                driver.stage_role_probe(workload, {'files': {relative: '0' * 64}})
            self.assertFalse((workload.ROOT / 'probe-source').exists())
            self.assertEqual(expected, driver.stage_role_probe(
                workload, {'files': {relative: expected}}))
            copied = workload.ROOT / 'probe-source/pr315_role_probe.py'
            self.assertEqual((source / relative).read_bytes(), copied.read_bytes())
            self.assertEqual(0, copied.stat().st_mode & 0o222)


class ReadinessJcmdDiagnosticTest(unittest.TestCase):
    def test_latest_active_role_jvm_must_have_one_exact_staged_executable(self):
        digest = 'sha256:' + 'a' * 64
        handles = {role: role for role in driver.ROLE_NAMES}
        handoff = {'handles': handles, 'expectedJdkDigests': {
            role: digest for role in driver.ROLE_NAMES}}
        workload = SimpleNamespace(
            manager=lambda role, operation: {'ActiveState': 'active' if role in
                {'candidate-sender', 'candidate-recipient'} else 'inactive',
                'SubState': 'running' if role in
                {'candidate-sender', 'candidate-recipient'} else 'dead'},
            observe=lambda handle: {'managerInvocation': 'b' * 32,
                'processes': [{'hostPid': 123, 'startTicks': 45,
                               'executableDigest': digest}]})
        role, invocation, process = driver._readiness_java_process(workload, handoff)
        self.assertEqual('candidate-recipient', role)
        self.assertEqual('b' * 32, invocation)
        self.assertEqual(123, process['hostPid'])
        workload.observe = lambda handle: {'managerInvocation': 'b' * 32,
            'processes': [{'executableDigest': digest}, {'executableDigest': digest}]}
        with self.assertRaisesRegex(ValueError, 'ambiguous-or-absent'):
            driver._readiness_java_process(workload, handoff)

    def test_jcmd_is_bounded_private_and_does_not_change_failure_class(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jcmd = root / 'roles/candidate-recipient/jdk/bin/jcmd'
            jcmd.parent.mkdir(parents=True)
            jcmd.write_bytes(b'fixed-jcmd')
            workload = SimpleNamespace(ROOT=root)
            selected = ('candidate-recipient', 'b' * 32,
                        {'hostPid': 123, 'startTicks': 45,
                         'executableDigest': 'sha256:' + 'a' * 64})
            called = []
            def run(arguments, *, environment, timeout, output_limit, diagnostic_sink):
                called.append((arguments[-2:], timeout, output_limit))
                diagnostic_sink(b'private-thread-details', b'')
                return b'private-thread-details'
            with patch.object(driver, '_readiness_java_process', return_value=selected), \
                    patch.object(driver, 'READINESS_JCMD', root / 'readiness.json'), \
                    patch.dict('sys.modules', {'bounded_process': SimpleNamespace(run=run)}):
                summary = driver.capture_readiness_jcmd(workload, {})
            self.assertEqual('retained', summary['status'])
            self.assertNotIn('private-thread-details', json.dumps(summary))
            self.assertEqual([(['123', 'VM.command_line'], 5, 4096),
                              (['Thread.print', '-l'], 8, 131072)], called)
            retained = json.loads((root / 'readiness.json').read_bytes())
            self.assertEqual('private-diagnostic-not-acceptance', retained['classification'])
            self.assertEqual(0, (root / 'readiness.json').stat().st_mode & 0o077)


class RoleProbeFinalBindingTest(unittest.TestCase):
    def test_result_keeps_actor_target_and_denial_failures_distinct(self):
        actor = {'hostPid': 123, 'startTicks': 45, 'namespacePids': [123, 2],
                 'networkNamespaceIdentity': [1, 200], 'mountNamespaceIdentity': [1, 300],
                 'userNamespaceIdentity': [1, 400], 'executableDigest': 'sha256:' + 'a' * 64,
                 'noNewPrivileges': True, 'effectiveCapabilities': 0}
        ready = {'startedMonotonicNs': 10}
        before = {'managerInvocation': 'b' * 32, 'cgroupIdentity': [1, 99],
                  'cgroupMemoryBytes': 200, 'cgroupTasks': 3}
        after = {'managerInvocation': 'b' * 32, 'observedMonotonicNs': 100,
                 'cgroupIdentity': [1, 99], 'cgroupMemoryBytes': 210, 'cgroupTasks': 3}
        result = {'nonce': 'c' * 64, 'caseId': 'observer-private-read', 'pid': 2,
                  'outcome': {'opened': False, 'errno': 'ENOENT'},
                  'startedMonotonicNs': 30, 'finishedMonotonicNs': 40}
        args = (ready, before, actor, after, actor, result, 'd' * 64, 'd' * 64, 'c' * 64, 20)
        self.assertIsNone(driver._validate_role_probe_result(*args))
        changed_actor = dict(actor, startTicks=46)
        with self.assertRaisesRegex(driver.RoleProbeDiagnosticError, 'actor-changed'):
            driver._validate_role_probe_result(
                ready, before, actor, after, changed_actor, result, 'd' * 64, 'd' * 64, 'c' * 64, 20)
        denied = dict(result, outcome={'opened': False, 'errno': 'EACCES'})
        with self.assertRaisesRegex(driver.RoleProbeDiagnosticError, 'outcome-mismatch') as caught:
            driver._validate_role_probe_result(
                ready, before, actor, after, actor, denied, 'd' * 64, 'd' * 64, 'c' * 64, 20)
        self.assertEqual({'opened': False, 'errno': 'EACCES'}, caught.exception.observed_outcome)
        with self.assertRaisesRegex(driver.RoleProbeDiagnosticError, 'timeline-invalid'):
            driver._validate_role_probe_result(ready, before, actor, after, actor,
                dict(result, finishedMonotonicNs=30), 'd' * 64, 'd' * 64, 'c' * 64, 20)
        with self.assertRaisesRegex(driver.RoleProbeDiagnosticError, 'target-changed'):
            driver._validate_role_probe_result(ready, before, actor, after, actor,
                result, 'd' * 64, 'e' * 64, 'c' * 64, 20)
        write = {'operation': 'observer-private-write', 'startedMonotonicNs': 41,
                 'finishedMonotonicNs': 45, 'writtenBytes': 0,
                 'outcome': {'opened': False, 'errno': 'ENOENT'}}
        self.assertEqual(write, driver._validate_role_probe_write(
            dict(result, writeAttempt=write), after))
        invalid = dict(write, outcome={'opened': False, 'errno': 'EACCES'})
        with self.assertRaisesRegex(driver.RoleProbeDiagnosticError,
                                    'write-outcome-mismatch') as caught:
            driver._validate_role_probe_write(dict(result, writeAttempt=invalid), after)
        self.assertEqual(invalid['outcome'], caught.exception.observed_outcome)
        with self.assertRaisesRegex(driver.RoleProbeDiagnosticError, 'write-timeline-invalid'):
            driver._validate_role_probe_write(dict(result,
                writeAttempt=dict(write, startedMonotonicNs=39)), after)
        identity_claim = {'claimedHostPid': 1, 'claimedHostUid': 0,
                          'startedMonotonicNs': 46, 'finishedMonotonicNs': 47}
        counter_claim = {'claimedMemoryCurrentBytes': 0, 'claimedTasksCurrent': 0,
                         'startedMonotonicNs': 48, 'finishedMonotonicNs': 49}
        claims = dict(result, writeAttempt=write, identityClaim=identity_claim,
                      counterClaim=counter_claim)
        self.assertEqual((identity_claim, counter_claim),
            driver._validate_false_role_claims(claims, before, after, actor, 983))
        with self.assertRaisesRegex(driver.RoleProbeDiagnosticError,
                                    'identity-claim-invalid'):
            driver._validate_false_role_claims(dict(claims,
                identityClaim=dict(identity_claim, claimedHostPid=123)),
                before, after, actor, 983)
        with self.assertRaisesRegex(driver.RoleProbeDiagnosticError,
                                    'counter-target-unavailable'):
            driver._validate_false_role_claims(claims, before,
                dict(after, cgroupMemoryBytes=0), actor, 983)
        def access(operation, path, start, finish, errno_code):
            return {'operation': operation, 'startedMonotonicNs': start,
                    'finishedMonotonicNs': finish, 'writtenBytes': 0,
                    'outcome': {'opened': False, 'errno': errno_code},
                    'targetPathDigest': hashlib.sha256(path.encode()).hexdigest()}
        fixed = dict(claims,
            siblingRead=access('sibling-data', driver.SIBLING_PROBE_PATH, 50, 60, 'ENOENT'),
            packageWrite=access('package-expectation', driver.PACKAGE_PROBE_PATH, 61, 70, 'EACCES'),
            cgroupMigration=access('cgroup-migration', driver.CGROUP_PROBE_PATH, 71, 80, 'ENOENT'))
        self.assertEqual({'sibling-data', 'package-expectation', 'cgroup-migration'},
                         set(driver._validate_fixed_role_accesses(fixed, after)))
        invalid = dict(fixed, packageWrite=dict(fixed['packageWrite'],
            outcome={'opened': False, 'errno': 'ENOENT'}))
        with self.assertRaisesRegex(driver.RoleProbeDiagnosticError,
                                    'package-expectation-invalid'):
            driver._validate_fixed_role_accesses(invalid, after)
        invalid = dict(fixed, cgroupMigration=dict(fixed['cgroupMigration'],
            startedMonotonicNs=69))
        with self.assertRaisesRegex(driver.RoleProbeDiagnosticError,
                                    'fixed-access-timeline-invalid'):
            driver._validate_fixed_role_accesses(invalid, after)

    def test_private_error_code_never_copies_unrecognized_candidate_text(self):
        self.assertEqual('workload-role-probe-ready-timeout',
            driver._private_role_probe_code(ValueError('workload-role-probe-ready-timeout')))
        self.assertIsNone(driver._private_role_probe_code(ValueError(
            '/private/secret/path must not enter diagnostic')))


class MemoryDiagnosticsTest(unittest.TestCase):
    def test_sampled_peaks_preserve_observed_demand_after_cgroup_disappears(self):
        diagnostics = {}
        samples = [
            {'observedMonotonicNs': index * 10 + 1,
             'finishedMonotonicNs': index * 10 + 2,
             'guest': {'status': 'observed', 'MemAvailableBytes': available},
             'services': {'role': {'status': 'observed', 'memory.current': memory, 'pids.current': tasks}}}
            for index, (available, memory, tasks) in enumerate(((100, 20, 3), (50, 40, 2)))]
        samples.append({'observedMonotonicNs': 21, 'finishedMonotonicNs': 22,
                        'guest': {'status': 'unavailable'}, 'services': {
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
        self.assertEqual({'startedMonotonicNs': 11, 'finishedMonotonicNs': 12},
                         observed['services']['role']['lastObservedWindow'])

    def test_absent_cgroups_do_not_become_zero_or_quiescence(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(driver, 'CGROUP_ROOT', Path(directory)):
            snapshot = driver.memory_snapshot()
        self.assertEqual('observed', snapshot['guest']['status'])
        self.assertGreater(snapshot['guest']['MemTotalBytes'], 0)
        self.assertGreater(snapshot['finishedMonotonicNs'], snapshot['observedMonotonicNs'])
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
