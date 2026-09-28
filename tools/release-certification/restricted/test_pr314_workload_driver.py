"""Local cleanup ordering and retention tests; no installed systemd execution."""
import base64
from contextlib import contextmanager, ExitStack, nullcontext
import fcntl
import hashlib
import json
import os
import pwd
import select
import signal
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
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protected'))
import pr314_workload_driver as driver
import restricted_workload_network as network


class VolatilePublicationTest(unittest.TestCase):
    def test_large_private_snapshot_is_atomic_exclusive_and_keeps_generic_cap(self):
        raw = b'x' * 110000  # Above both the old 96-KiB and generic 64-KiB limits.
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


class PositiveObserverEpochTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0,
                         'requires disposable Linux root and pidfd')
    def test_forked_observer_is_bound_after_actual_uid_drop(self):
        reader, writer = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(reader)
            try:
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)
                os.write(writer, b'1')
                time.sleep(10)
            finally:
                os._exit(0)
        os.close(writer)
        try:
            self.assertEqual(b'1', os.read(reader, 1))
            observed = driver._positive_observer_epoch(
                pid, 65534, time.monotonic_ns() + 3 * 10**9)
            self.assertEqual(pid, observed['pid'])
            self.assertEqual(65534, observed['uid'])
            self.assertGreater(observed['startTicks'], 0)
            self.assertEqual({'pid', 'net', 'mnt', 'user'},
                             set(observed['namespaces']))
            self.assertEqual('installed-observer-process', observed['kind'])
            with self.assertRaisesRegex(ValueError, 'uid-unavailable'):
                driver._positive_observer_epoch(
                    pid, 65533, time.monotonic_ns() + 200 * 10**6)
        finally:
            os.close(reader)
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)


class StuckOutputCollectorTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0,
                         'requires disposable Linux root and pidfd')
    def test_actual_collector_times_out_while_fifo_writer_remains_live(self):
        import bounded_process
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / 'held.fifo'
            os.mkfifo(fifo, 0o600)
            pid = os.fork()
            if pid == 0:
                try:
                    descriptor = os.open(fifo, os.O_WRONLY)
                    os.write(descriptor, b'pr315-stuck-output\n')
                    time.sleep(10)
                finally:
                    os._exit(0)
            retained = []
            witness = []
            descriptor = None
            def started(child):
                nonlocal descriptor
                descriptor = os.pidfd_open(child)
                witness.append(driver._stuck_collector_epoch(child))
            try:
                with self.assertRaisesRegex(ValueError, 'deadline_exceeded'):
                    bounded_process.run(['/usr/bin/cat', str(fifo)],
                        environment={'PATH': '/usr/bin:/bin'}, timeout=.3,
                        output_limit=4096,
                        start_observer=started,
                        diagnostic_sink=lambda stdout, stderr:
                            retained.append((stdout, stderr)))
                self.assertEqual([(b'pr315-stuck-output\n', b'')], retained)
                self.assertEqual(0, witness[0]['uid'])
                self.assertEqual(witness[0]['pid'], witness[0]['session'])
                self.assertTrue(select.select([descriptor], [], [], 0)[0])
                os.kill(pid, 0)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)


class SiblingNetworkCounterTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0,
                         'requires disposable Linux root host namespace')
    def test_host_canary_control_proves_active_listener_and_root_epoch(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(2)
            port = listener.getsockname()[1]
            address_rows = json.dumps([{'ifindex': 1, 'ifname': 'lo',
                'addr_info': [{'family': 'inet', 'local': '127.0.0.1'}]}]).encode()
            with patch.object(network, 'HOST_CANARY_ADDRESS', '127.0.0.1'), \
                    patch.object(network, 'HOST_CANARY_PORT', port), \
                    patch.object(driver.subprocess, 'run',
                        return_value=SimpleNamespace(stdout=address_rows)) as address:
                selected = SimpleNamespace(boot=lambda: 'a' * 32)
                first = driver._host_canary_control(listener, selected)
                second = driver._host_canary_control(listener, selected)
                address.return_value = SimpleNamespace(stdout=b'[]')
                with self.assertRaisesRegex(ValueError,
                                            'address-not-assigned'):
                    driver._host_canary_control(listener, selected)
        self.assertEqual(0, first['uid'])
        self.assertEqual(os.getpid(), first['pid'])
        self.assertEqual(first['invocationId'], second['invocationId'])
        self.assertLess(first['observedMonotonicNs'], second['observedMonotonicNs'])
        self.assertEqual(hashlib.sha256(
            b'pr315-host-probe\0pr315-host-ready').hexdigest(),
            first['controlDigest'])

    def test_one_sibling_drop_cannot_be_supplied_by_other_case_or_changed_namespace(self):
        before = {'schemaVersion': 1, 'kind': 'pr315-fixed-sibling-drop-counters',
                  'policyDigest': hashlib.sha256(
                      network.role_rules('candidate-sender').encode()).hexdigest(),
                  'bootId': 'boot', 'roleNamespaceIdentity': [1, 42],
                  'observedMonotonicNs': 10,
                  'counters': {name: {'packets': 0, 'bytes': 0}
                      for name in network.SIBLING_DROP_COUNTERS.values()}}
        after = json.loads(json.dumps(before))
        after['observedMonotonicNs'] = 20
        fcp = network.SIBLING_DROP_COUNTERS['sibling-fcp']
        after['counters'][fcp] = {'packets': 2, 'bytes': 120}
        driver._sibling_counter_pair('sibling-fcp', before, after, [1, 42])
        for mutate in (
                lambda value: value['counters'][fcp].update(packets=0),
                lambda value: value['counters'][network.SIBLING_DROP_COUNTERS[
                    'sibling-http']].update(packets=1, bytes=60),
                lambda value: value.update(roleNamespaceIdentity=[1, 99]),
                lambda value: value.update(policyDigest='0' * 64)):
            changed = json.loads(json.dumps(after))
            mutate(changed)
            with self.assertRaises(ValueError):
                driver._sibling_counter_pair('sibling-fcp', before, changed, [1, 42])


class ObserverFailureTest(unittest.TestCase):
    def test_immediate_cause_survives_private_child_response(self):
        error = ValueError('workload-daemon-readiness-timeout')
        error.__cause__ = RuntimeError('controller-request-rejected')
        result = driver.observer_failure(error)
        self.assertEqual('controller-request-rejected', result['immediateCause']['privateDetail'])
        self.assertEqual('workload-daemon-readiness-timeout', result['privateDetail'])

    def test_transport_diagnostic_has_closed_private_fields(self):
        error = ValueError('workload-controller-transport-failed')
        error.__cause__ = TimeoutError('timed out')
        error.transport_diagnostic = {'method': 'start',
            'phase': 'response-read', 'elapsedNs': 30_000_000_000,
            'causeType': 'TimeoutError', 'errno': None}
        result = driver.observer_failure(error)
        self.assertEqual(error.transport_diagnostic,
                         result['transportDiagnostic'])
        self.assertEqual('TimeoutError', result['immediateCause']['exceptionType'])
        self.assertLess(len(json.dumps(result).encode()), 4096)
        error.transport_diagnostic['privateHandle'] = 'a' * 64
        self.assertNotIn('transportDiagnostic', driver.observer_failure(error))

    def test_readiness_timing_diagnostic_has_closed_private_fields(self):
        error = ValueError('workload-daemon-readiness-timeout')
        error.readiness_diagnostic = {'role': 'candidate-recipient',
            'stage': 'fcp-get-node', 'startRequestNs': 10,
            'startResponseNs': 20, 'readinessDeadlineNs': 200,
            'attemptCount': 2, 'lastAttemptStartedNs': 120,
            'failedAtNs': 210, 'causeType': 'RuntimeFailure'}
        result = driver.observer_failure(error)
        self.assertEqual(error.readiness_diagnostic,
                         result['readinessDiagnostic'])
        self.assertLess(len(json.dumps(result).encode()), 4096)
        error.readiness_diagnostic['privateHandle'] = 'a' * 64
        self.assertNotIn('readinessDiagnostic', driver.observer_failure(error))

    def test_controller_journal_diagnostic_is_fixed_bounded_and_private(self):
        commands = []

        def run(arguments, *, environment, timeout, output_limit, diagnostic_sink):
            commands.append((arguments, environment, timeout, output_limit))
            diagnostic_sink(b'controller-event', b'')
            return b'controller-event'

        with patch.dict('sys.modules', {'bounded_process': SimpleNamespace(run=run)}):
            result = driver.capture_controller_journal_at_failure()
        self.assertEqual('captured', result['status'])
        self.assertEqual(b'controller-event',
                         base64.b64decode(result['stdoutBase64']))
        self.assertEqual('private-diagnostic-not-acceptance',
                         result['classification'])
        self.assertEqual(5, commands[0][2])
        self.assertEqual(8192, commands[0][3])
        self.assertEqual('cryptad-workload-controller.service',
                         commands[0][0][-2].split('=', 1)[1])

    def test_controller_request_checkpoint_is_closed_and_bound_to_fixed_path(self):
        record = {'schemaVersion': 1,
            'kind': 'pr315-controller-request-progress',
            'classification': 'private-runtime-diagnostic-not-acceptance',
            'pid': 12, 'processStartTicks': 42,
            'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            'method': 'observe', 'phase': 'executing',
            'startedMonotonicNs': 100, 'observedMonotonicNs': 101}
        raw = json.dumps(record).encode()
        identity = {'mainPid': 12, 'mainStartTicks': 42,
            'bootId': record['bootId'], 'observedMonotonicNs': 102,
            'invocationId': 'b' * 32, 'cgroupIdentity': [1, 2]}
        with patch('runtime_snapshot.read_file', return_value=raw) as read, \
                patch.object(driver, 'controller_unit_identity',
                             return_value=identity):
            captured = driver.capture_controller_request_at_failure(object())
        self.assertEqual('captured', captured['status'])
        self.assertEqual(record, captured['record'])
        self.assertEqual(identity, captured['kernelController'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         captured['privateDigest'])
        read.assert_called_once_with(driver.CONTROLLER_REQUEST_PROGRESS.parent,
                                     driver.CONTROLLER_REQUEST_PROGRESS.name,
                                     maximum=2048, timeout=2)
        with patch('runtime_snapshot.read_file', return_value=json.dumps(
                {**record, 'handle': 'a' * 64}).encode()), \
                patch.object(driver, 'controller_unit_identity',
                             return_value=identity):
            self.assertEqual({'status': 'unavailable-or-unsafe'},
                             driver.capture_controller_request_at_failure(object()))
        with patch('runtime_snapshot.read_file', return_value=raw), \
                patch.object(driver, 'controller_unit_identity',
                             return_value={**identity, 'mainStartTicks': 43}):
            stale = driver.capture_controller_request_at_failure(object())
        self.assertEqual('unbound', stale['status'])
        self.assertEqual('controller-epoch-mismatch', stale['reason'])
        self.assertNotIn('kernelController', stale)
        with patch('runtime_snapshot.read_file', return_value=raw), \
                patch.object(driver, 'controller_unit_identity',
                             side_effect=TimeoutError('systemd busy')):
            unavailable = driver.capture_controller_request_at_failure(object())
        self.assertEqual('unbound', unavailable['status'])
        self.assertEqual('controller-identity-unavailable', unavailable['reason'])
        self.assertNotIn('systemd busy', json.dumps(unavailable))

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
            captured = driver.probe_runner_control(workload, handoff, result)
            self.assertEqual('captured', captured['status'])
            self.assertEqual('installed-runner-process',
                             captured['actorEpoch']['kind'])
            self.assertEqual(os.getpid(), captured['actorEpoch']['pid'])
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
    def test_lost_start_barrier_observes_original_invocation_before_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'authority').mkdir()
            boot = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            before = {'role': 'candidate-sender', 'state': 'prepared',
                'generation': None, 'managerInvocation': None,
                'cgroupIdentity': None, 'bootId': boot, 'mainPid': 0,
                'observedMonotonicNs': time.monotonic_ns() - 1_000_000_000}
            record = {'state': 'prepared', 'generation': None,
                'managerInvocation': None, 'cgroupIdentity': None,
                'bootId': boot, 'previousStopGeneration': None}
            state = {'ActiveState': 'inactive', 'MainPID': '0'}
            marker = {'generation': 'b' * 64, 'managerInvocation': 'c' * 32,
                      'bootId': boot, 'cgroupIdentity': [1, 99]}
            diagnostics = {'lostStartBefore': before}
            workload = SimpleNamespace(ROOT=root, locked=nullcontext,
                retained=lambda handle: ({'deadlineMonotonicNs':
                    time.monotonic_ns() + 60_000_000_000}, 'candidate-sender', record),
                manager=lambda role, operation: state,
                read=lambda path: marker, admit=Mock(), exact=Mock(), current=Mock())
            handoff = {'handles': {'candidate-sender': 'd' * 64},
                       'deadlineMonotonicNs': time.monotonic_ns() + 60_000_000_000}
            sampler = driver.AdministratorFnpSampler(workload, 'recipient', diagnostics,
                sender_handle='d' * 64, handoff=handoff, lost_start_before=before)
            with patch.object(driver, '_administrator_collector_epoch', return_value={
                    'observedMonotonicNs': time.monotonic_ns()}):
                ready = sampler.lost_start_prepare()
            self.assertEqual('lost-start-before', ready['phase'])
            self.assertEqual(ready['observedMonotonicNs'],
                             diagnostics['probeStart']['startedMonotonicNs'])
            record.update(state='running', generation='b' * 64,
                          managerInvocation='c' * 32, cgroupIdentity=[1, 99])
            state.update(ActiveState='active', MainPID='123')
            first = sampler.lost_start_intent()
            self.assertEqual('c' * 32, first['managerInvocation'])
            self.assertEqual(first['observedMonotonicNs'],
                             diagnostics['lostStartIntent']['first']['observedMonotonicNs'])
            from cross_version_runtime import canonical_digest
            marker_ns = diagnostics['probeStart']['startedMonotonicNs']
            dropped = {'requestDigest': diagnostics['lostStartIntent']['requestDigest'],
                       'sendStartedNs': marker_ns + 1, 'sendFinishedNs': marker_ns + 2}
            result = {'lostStartResponse': {'administratorBefore': ready,
                'droppedRequest': dropped, 'administratorBarrier': first},
                'roleKernelRosterWindow': {
                    'startedMonotonicNs': first['observedMonotonicNs'] + 1,
                    'finishedMonotonicNs': first['observedMonotonicNs'] + 2},
                'roleKernelRoster': {'roles': [{'role': 'candidate-sender',
                    'invocationId': 'c' * 32, 'bootId': 'a' * 32,
                    'cgroupDigest': canonical_digest({
                        'role': 'candidate-sender', 'identity': [1, 99]})[7:]}]}}
            context = driver.complete_lost_start_before_cleanup(
                workload, handoff, result, diagnostics)
            self.assertEqual(first['managerInvocation'], context['retry']['managerInvocation'])
            workload.read = lambda path: dict(marker, generation='f' * 64)
            with self.assertRaisesRegex(ValueError, 'first-invocation-invalid'):
                sampler.lost_start_intent()
            with self.assertRaisesRegex(ValueError, 'duplicate-invocation'):
                driver.complete_lost_start_before_cleanup(
                    workload, handoff, result, diagnostics)

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
            sampler.readiness = Mock(return_value={
                'phase': 'readiness', 'role': 'candidate-recipient',
                'stage': 'fcp-get-node', 'status': 'captured'})
            child.sendall(b'J1F')
            self.assertTrue(sampler.serve(parent))
            self.assertEqual('candidate-recipient', json.loads(child.recv(8192))['role'])
            sampler.readiness.assert_called_once_with('candidate-recipient', 'fcp-get-node')
            sampler.lost_start_prepare = Mock(return_value={
                'phase': 'lost-start-before', 'role': 'candidate-sender',
                'observedMonotonicNs': 10})
            child.sendall(b'Q')
            self.assertTrue(sampler.serve(parent))
            self.assertEqual('lost-start-before', json.loads(child.recv(8192))['phase'])
            sampler.lost_start_prepare.assert_called_once_with()
            sampler.lost_start_intent = Mock(return_value={
                'phase': 'lost-start-intent', 'role': 'candidate-sender',
                'generation': 'b' * 64, 'managerInvocation': 'c' * 32,
                'observedMonotonicNs': 20})
            child.sendall(b'L')
            self.assertTrue(sampler.serve(parent))
            self.assertEqual('lost-start-intent', json.loads(child.recv(8192))['phase'])
            sampler.lost_start_intent.assert_called_once_with()
            sampler.hostile_origin_selected = True
            token = 'private-browser-session'
            child.sendall(b'H' + json.dumps({'session': token,
                'expectedOrigin': 'http://127.0.0.1:12345'}).encode())
            self.assertTrue(sampler.serve(parent))
            self.assertEqual(hashlib.sha256(token.encode()).hexdigest(),
                             json.loads(child.recv(8192))['sessionDigest'])
            self.assertNotIn(token, json.dumps(sampler.diagnostics))
            child.sendall(b'H' + json.dumps({'session': token,
                'expectedOrigin': 'http://127.0.0.1:12345'}).encode())
            self.assertTrue(sampler.serve(parent))
            self.assertEqual({'error': 'pr315-admin-hostile-origin-handoff-failed'},
                             json.loads(child.recv(8192)))
            child.sendall(b'J4F')
            self.assertTrue(sampler.serve(parent))
            self.assertEqual({'error': 'pr315-admin-fnp-sample-failed'},
                             json.loads(child.recv(8192)))
            sampler.readiness.assert_called_once()
        self.assertEqual('ValueError', sampler.diagnostics['fnpAdminFailure']['exceptionType'])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux AF_UNIX seqpacket required')
    def test_browser_credential_handoff_retains_only_root_memory_and_digest_ack(self):
        diagnostics = {}
        sampler = driver.AdministratorFnpSampler(SimpleNamespace(), 'fixed',
            diagnostics, hostile_origin_selected=True)
        token = 'private-browser-session'
        with ExitStack() as stack:
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            stack.enter_context(parent)
            stack.enter_context(child)
            worker = threading.Thread(target=sampler.serve, args=(parent,), daemon=True)
            worker.start()
            reply = driver.request_administrator_hostile_origin(
                child, token, 'http://127.0.0.1:12345',
                time.monotonic_ns() + 5_000_000_000)
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
        self.assertEqual(hashlib.sha256(token.encode()).hexdigest(),
                         reply['sessionDigest'])
        self.assertEqual(token, sampler.hostile_origin_secret['session'])
        self.assertNotIn(token, json.dumps(diagnostics))
        with self.assertRaisesRegex(ValueError, 'hostile-origin-deadline'):
            driver.request_administrator_hostile_origin(
                Mock(), token, 'http://127.0.0.1:12345',
                time.monotonic_ns() - 1)

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
    def test_failed_role_requests_exact_stage_before_cleanup(self):
        sampler = driver.AdministratorFnpSampler(SimpleNamespace(), 'fixed', {})
        expected = {'phase': 'readiness', 'role': 'candidate-recipient',
                    'stage': 'fcp-get-node', 'status': 'captured'}
        sampler.readiness = Mock(return_value=expected)
        with ExitStack() as stack:
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            stack.enter_context(parent)
            stack.enter_context(child)
            worker = threading.Thread(target=sampler.serve, args=(parent,), daemon=True)
            worker.start()
            self.assertEqual(expected, driver.request_administrator_readiness(
                child, 'candidate-recipient', 'fcp-get-node'))
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
        sampler.readiness.assert_called_once_with('candidate-recipient', 'fcp-get-node')
        with self.assertRaisesRegex(ValueError, 'role-invalid'):
            driver.request_administrator_readiness(None, 'candidate-recipient', 'arbitrary-stage')

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


class DeadlineObservationTest(unittest.TestCase):
    def test_waits_original_deadline_and_observes_service_receipts_before_cleanup(self):
        rows = [{'role': role, 'managerInvocation': format(index + 1, '032x'),
                 'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                 'cgroupIdentity': [1, 10 + index], 'mainPid': 1000 + index}
                for index, role in enumerate(driver.ROLE_NAMES)]
        receipts = {row['role']: {**row,
            'startedMonotonicNs': 1010 + index,
            'observedMonotonicNs': 1020 + index,
            'membership': 'only-stop-helper', 'descendantCgroups': 0}
            for index, row in enumerate(rows)}
        with patch.object(driver, 'begin_cancellation', return_value={
                'triggerStartedNs': 900, 'campaignDeadlineNs': 1000,
                'preRoles': rows}):
            armed = driver.begin_deadline(None, None, None)
        workload = SimpleNamespace(ROOT=Path('/fixed-private-root'),
            manager=lambda role, operation: {'ActiveState': 'inactive',
                                              'SubState': 'dead', 'MainPID': '0'},
            quiescent=lambda role: True,
            read=lambda path: receipts[path.name.removesuffix('-stop.json')])
        with patch.object(driver.time, 'monotonic_ns', side_effect=[900, 900, 1000, 1100]), \
                patch.object(driver.time, 'sleep') as slept:
            completed = driver.complete_deadline(workload, armed)
        slept.assert_called_once()
        self.assertEqual(1000, completed['campaignDeadlineNs'])
        self.assertEqual(1100, completed['terminalObservedNs'])
        self.assertEqual(4, len(completed['roleStops']))
        receipts['candidate-sender']['startedMonotonicNs'] = 999
        with self.assertRaisesRegex(ValueError, 'receipt-invalid'):
            driver.complete_deadline(workload, armed)


class RevocationRequestTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0,
                         'requires disposable Linux root for observer UID transition')
    def test_fixed_observer_child_reaches_exact_root_controller_peer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o755)
            path = root / 'control.sock'
            seen = []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                path.chmod(0o666)
                listener.listen(1)
                listener.settimeout(5)

                def serve():
                    with listener.accept()[0] as channel:
                        raw = bytearray()
                        while not raw.endswith(b'\n'):
                            raw.extend(channel.recv(128))
                        seen.append(bytes(raw))
                        channel.sendall(
                            b'{"error":"restricted-workload-request-failed"}\n')

                worker = threading.Thread(target=serve, daemon=True)
                worker.start()
                with patch.object(driver, 'REVOCATION_CONTROL_SOCKET', str(path)):
                    record = driver._revocation_request(
                        pwd.getpwnam('nobody'), 'a' * 64, os.getpid())
                worker.join(timeout=2)
                self.assertFalse(worker.is_alive())
            self.assertEqual([b'{"method":"start","handle":"' +
                              b'a' * 64 + b'"}\n'], seen)
            self.assertEqual(pwd.getpwnam('nobody').pw_uid, record['actor']['uid'])
            self.assertEqual(hashlib.sha256(seen[0]).hexdigest(),
                             record['requestDigest'])

    @unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0
                         and hasattr(os, 'pidfd_open')
                         and hasattr(signal, 'pidfd_send_signal'),
                         'requires disposable Linux root and pidfd')
    def test_real_observer_activity_is_followed_by_exact_pidfd_death(self):
        handle = 'a' * 64
        invocation = 'b' * 32
        response = (json.dumps({'handle': handle, 'state': 'running',
            'managerInvocation': invocation,
            'provenance': 'controller-kernel-sample'},
            separators=(',', ':')).encode() + b'\n')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o755)
            path = root / 'control.sock'
            seen = []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                path.chmod(0o666)
                listener.listen(1)
                listener.settimeout(5)

                def serve():
                    with listener.accept()[0] as channel:
                        raw = bytearray()
                        while not raw.endswith(b'\n'):
                            raw.extend(channel.recv(128))
                        seen.append(bytes(raw))
                        channel.sendall(response)

                worker = threading.Thread(target=serve, daemon=True)
                worker.start()
                with patch.object(driver, 'OBSERVER_DEATH_CONTROL_SOCKET', str(path)):
                    record = driver._observer_death_request(
                        pwd.getpwnam('nobody'), handle, os.getpid(), invocation)
                worker.join(timeout=2)
                self.assertFalse(worker.is_alive())
            self.assertEqual([b'{"method":"observe","handle":"' +
                              handle.encode() + b'"}\n'], seen)
            self.assertTrue(record['pidfdUsed'])
            self.assertEqual(hashlib.sha256(response).hexdigest(),
                             record['responseDigest'])
            self.assertEqual(pwd.getpwnam('nobody').pw_uid, record['actor']['uid'])


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

    def test_bootstrap_failure_snapshot_accepts_only_closed_root_record(self):
        boot = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        record = {'schemaVersion': 1,
            'kind': 'pr315-controller-bootstrap-failure-phase',
            'stage': 'app-runtime', 'role': 'candidate-recipient',
            'exceptionType': 'ValueError',
            'errorCode': 'app-runtime-unavailable',
            'controllerPid': 44, 'bootId': boot,
            'startedMonotonicNs': 1, 'observedMonotonicNs': 2}
        workload = SimpleNamespace(read=Mock(return_value=record),
                                   boot=lambda: boot)
        observed = driver.controller_bootstrap_failure_snapshot(workload)
        self.assertEqual('captured', observed['status'])
        self.assertEqual(record, observed['record'])
        for change in ({'role': 'attacker'},
                       {'bootId': 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'},
                       {'errorCode': 'private-token=value'}):
            workload.read.return_value = {**record, **change}
            self.assertEqual('unavailable-or-unsafe',
                driver.controller_bootstrap_failure_snapshot(workload)['status'])

    def test_absent_bootstrap_failure_receipt_is_not_a_pass(self):
        workload = SimpleNamespace(read=Mock(side_effect=FileNotFoundError()))
        self.assertEqual({'status': 'not-observed'},
                         driver.controller_bootstrap_failure_snapshot(workload))

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
            stack.enter_context(patch.object(driver, 'stage_lifecycle_probe',
                return_value='e' * 64))
            stack.enter_context(patch.object(driver, 'prepare_sibling_canary', return_value='d' * 64))
            stack.enter_context(patch.object(driver, 'prepare_resolver_canary', return_value='e' * 64))
            stack.enter_context(patch.object(driver, '_administrator_collector_epoch',
                return_value={'kind': 'offline-administrator-epoch'}))
            stack.enter_context(patch.object(driver, '_positive_observer_epoch',
                return_value={'kind': 'offline-observer-epoch'}))
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

    @unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0,
                         'requires disposable Linux root test-kit staging')
    def test_lifecycle_role_source_is_staged_separately_and_exactly(self):
        source = Path(driver.__file__).resolve().parents[3]
        regular = 'tools/release-certification/restricted/pr315_role_probe.py'
        lifecycle = 'tools/release-certification/restricted/pr315_lifecycle_role_probe.py'
        digests = {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                   for name in (regular, lifecycle)}
        fake_installation = SimpleNamespace(secured=lambda path: path)
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict('sys.modules', {'installation': fake_installation}), \
                patch.object(driver, 'TEST_KIT', source):
            workload = SimpleNamespace(ROOT=Path(directory))
            driver.stage_role_probe(workload, {'files': digests})
            self.assertEqual(digests[lifecycle],
                driver.stage_lifecycle_probe(workload, {'files': digests}))
            selected = workload.ROOT / 'probe-source/pr315_lifecycle_role_probe.py'
            self.assertEqual((source / lifecycle).read_bytes(), selected.read_bytes())
            self.assertEqual(0, selected.stat().st_mode & 0o222)


class ReadinessJcmdDiagnosticTest(unittest.TestCase):
    def test_root_captures_bounded_selected_role_log_before_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'fcp-candidate-recipient.log'
            log.write_bytes(b'x' * 9000)
            log.chmod(0o600)
            diagnostic = {}
            sampler = driver.AdministratorFnpSampler(SimpleNamespace(), 'fixed', diagnostic,
                handoff={'handles': {}}, observer_root=root)
            with patch.object(driver.pwd, 'getpwnam', return_value=SimpleNamespace(
                    pw_uid=os.geteuid())), \
                    patch.object(driver, 'memory_snapshot', return_value={'guest': {}}), \
                    patch.object(driver, 'capture_readiness_jcmd', return_value={
                        'status': 'unavailable-or-unsafe'}):
                reply = sampler.readiness('candidate-recipient', 'fcp-get-node')
                self.assertEqual('captured', reply['status'])
                self.assertEqual('fcp-get-node', diagnostic['readinessAtFailure']['stage'])
                captured = diagnostic['readinessAtFailure']['fcpLog']
                self.assertEqual(9000, captured['sizeBytes'])
                self.assertEqual(8192, len(base64.b64decode(captured['tailBase64'])))
                log.unlink()
                log.symlink_to(root / 'missing')
                sampler.readiness('candidate-recipient', 'fcp-get-node')
                self.assertEqual('unavailable-or-unsafe',
                    diagnostic['readinessAtFailure']['fcpLog']['status'])

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
        selected_role, _, _ = driver._readiness_java_process(workload, handoff,
                                                              'candidate-sender')
        self.assertEqual('candidate-sender', selected_role)
        with self.assertRaisesRegex(ValueError, 'no-active-role'):
            driver._readiness_java_process(workload, handoff, 'previous')
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
                summary = driver.capture_readiness_jcmd(workload, {
                    'deadlineMonotonicNs': time.monotonic_ns() + 10_000_000_000})
            self.assertEqual('retained', summary['status'])
            self.assertNotIn('private-thread-details', json.dumps(summary))
            self.assertEqual([(['123', 'VM.command_line'], 5, 4096),
                              (['Thread.print', '-l'], 8, 131072)], called)
            retained = json.loads((root / 'readiness.json').read_bytes())
            self.assertEqual('private-diagnostic-not-acceptance', retained['classification'])
            self.assertEqual(0, (root / 'readiness.json').stat().st_mode & 0o077)


    def test_busy_authority_lease_is_retried_before_the_original_deadline(self):
        selected = ('previous', 'a' * 32,
                    {'hostPid': 79, 'startTicks': 42,
                     'executableDigest': 'sha256:' + 'b' * 64})
        handoff = {'deadlineMonotonicNs': time.monotonic_ns() + 1_000_000_000}
        with patch.object(driver, '_readiness_java_process', side_effect=[
                BlockingIOError(), selected]) as observe:
            self.assertEqual(selected, driver._readiness_java_process_retry(
                SimpleNamespace(), handoff, 'previous'))
        self.assertEqual(2, observe.call_count)

    def test_expired_campaign_cannot_extend_jcmd_observation(self):
        handoff = {'deadlineMonotonicNs': time.monotonic_ns() - 1}
        with patch.object(driver, '_readiness_java_process') as observe:
            with self.assertRaisesRegex(ValueError, 'deadline-unavailable'):
                driver._readiness_java_process_retry(SimpleNamespace(), handoff, 'previous')
        observe.assert_not_called()


class HostileOriginValidationTest(unittest.TestCase):
    def test_root_control_binds_current_app_child_and_valid_browser_response(self):
        worker = {'hostPid': 211, 'namespacePid': 3, 'startTicks': 42,
                  'javaHostPid': 212, 'javaStartTicks': 43,
                  'managerInvocation': 'a' * 32,
                  'cgroupIdentity': [1, 99]}
        observed = {'managerInvocation': 'a' * 32,
                    'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                    'cgroupIdentity': [1, 99], 'stateDigest': 'd' * 64,
                    'observedMonotonicNs': 10}
        workload = SimpleNamespace(observe=Mock(side_effect=[observed,
            dict(observed, observedMonotonicNs=20)]),
            connect=Mock(return_value=nullcontext(SimpleNamespace())))
        handoff = {'handles': {'candidate-sender': 'e' * 64},
                   'expectedJdkDigests': {'candidate-sender': 'sha256:' + 'b' * 64}}
        with patch('cross_version_workload.bind_worker', return_value=worker), \
                patch('restricted_workload_controller._http', return_value=(
                    200, {}, b'{"status":{"appId":"mail-prototype",'
                              b'"storeAvailable":true}}')) as request:
            control = driver._mail_browser_control(workload, handoff,
                'private-session', 'http://127.0.0.1:12345', worker)
        self.assertEqual(211, control['workerHostPid'])
        self.assertEqual(20, control['observedMonotonicNs'])
        self.assertEqual('private-session',
                         request.call_args.args[2]['X-Crypta-App-Session'])
        self.assertNotIn('private-session', json.dumps(control))
        workload.observe = Mock(side_effect=[observed,
            dict(observed, observedMonotonicNs=20)])
        with patch('cross_version_workload.bind_worker', return_value=worker), \
                patch('restricted_workload_controller._http', return_value=(
                    403, {}, b'{"error":"origin_mismatch"}')), \
                self.assertRaisesRegex(ValueError, 'valid-target-unavailable'):
            driver._mail_browser_control(workload, handoff,
                'private-session', 'http://127.0.0.1:12345', worker)
        workload.observe = Mock(side_effect=[observed,
            dict(observed, observedMonotonicNs=20)])
        with patch('cross_version_workload.bind_worker', return_value=worker), \
                patch('restricted_workload_controller._http', return_value=(
                    200, {}, b'{"status":{"appId":"other",'
                              b'"storeAvailable":true}}')), \
                self.assertRaisesRegex(ValueError, 'valid-target-unavailable'):
            driver._mail_browser_control(workload, handoff,
                'private-session', 'http://127.0.0.1:12345', worker)

    def test_browser_secret_is_removed_before_retention_and_exchange_is_bounded(self):
        import pr315_role_probe as probe
        secret = {'session': 'private-browser-session',
                  'expectedOrigin': 'http://127.0.0.1:12345'}
        diagnostics = {}
        sampler = driver.AdministratorFnpSampler(SimpleNamespace(), 'recipient',
            diagnostics, hostile_origin_selected=True)
        acknowledged = sampler.hostile_origin_handoff(json.dumps(secret).encode())
        result = {'hostileOriginSessionDigest': acknowledged['sessionDigest'],
                  'mailUiOriginDigest': acknowledged['originDigest'],
                  'safe': 'retained'}
        self.assertEqual(secret, driver._verify_hostile_origin_handoff(
            result, 'authority', sampler, diagnostics))
        self.assertNotIn(secret['session'], json.dumps(result))
        self.assertNotIn(secret['session'], json.dumps(diagnostics))
        self.assertEqual(hashlib.sha256(secret['session'].encode()).hexdigest(),
                         diagnostics['hostileOriginSessionDigest'])
        before = {'role': 'candidate-sender', 'managerInvocation': 'a' * 32,
                  'bootId': 'boot', 'cgroupIdentity': [1, 99],
                  'workerHostPid': 211, 'workerStartTicks': 42,
                  'javaHostPid': 212, 'javaStartTicks': 43,
                  'observedMonotonicNs': 10, 'controlResponseDigest': 'a' * 64}
        after = dict(before, observedMonotonicNs=100,
                     controlResponseDigest='b' * 64)
        good = {'status': 200, 'errorCode': None,
                'responseDigest': 'c' * 64,
                'startedMonotonicNs': 30, 'finishedMonotonicNs': 40}
        attack = {'status': 403, 'errorCode': 'origin_mismatch',
                  'responseDigest': 'd' * 64,
                  'startedMonotonicNs': 50, 'finishedMonotonicNs': 60}
        last = dict(good, startedMonotonicNs=70, finishedMonotonicNs=80)
        witness = {'caseId': 'hostile-app-origin',
            'endpointDigest': hashlib.sha256(
                probe.HOSTILE_ORIGIN_ENDPOINT.encode()).hexdigest(),
            'sessionDigest': diagnostics['hostileOriginSessionDigest'],
            'expectedOriginDigest': hashlib.sha256(
                secret['expectedOrigin'].encode()).hexdigest(),
            'hostileOriginDigest': hashlib.sha256(
                probe.HOSTILE_ORIGIN.encode()).hexdigest(),
            'before': good, 'attack': attack, 'after': last}
        self.assertEqual(witness, driver._validate_hostile_origin(
            witness, secret, before, after, 20))
        for altered in (dict(witness, attack=dict(attack, status=200)),
                        dict(witness, after=dict(last, startedMonotonicNs=59)),
                        dict(witness, sessionDigest='0' * 64)):
            with self.assertRaisesRegex(ValueError, 'hostile-origin'):
                driver._validate_hostile_origin(altered, secret, before, after, 20)
        with self.assertRaisesRegex(ValueError, 'session-unselected'):
            driver._verify_hostile_origin_handoff(
                {}, 'positive', sampler, {})
        injected = {'hostileOriginSecret': secret}
        with self.assertRaisesRegex(ValueError, 'secret-in-result'):
            driver._verify_hostile_origin_handoff(
                injected, 'authority', sampler, {})
        self.assertNotIn('hostileOriginSecret', injected)


class ProviderAuthorityProbeTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0,
                         'requires disposable native Linux root state')
    def test_installed_worker_consumes_synthetic_credential_and_persists_two_results(self):
        from datetime import datetime, timedelta, timezone
        source = Path(__file__).resolve().parents[3]
        sys.path.insert(0, str(source / 'tools/release-certification/protected'))
        import restricted_registration as registration
        import restricted_worker as worker
        with tempfile.TemporaryDirectory(dir='/root',
                                         prefix='pr315-provider-worker-') as directory:
            base = Path(directory) / 'certification'
            state = Path(directory) / 'state'
            for path in (base, state, state / 'operations',
                         state / 'reservations'):
                path.mkdir(mode=0o700)
            credential = base / 'restricted-provider.json'
            token = 'pr315-synthetic-' + 'a' * 64
            raw = worker.encode({'token': token,
                'expiresAt': (datetime.now(timezone.utc) +
                              timedelta(minutes=50)).isoformat()})
            credential.write_bytes(raw)
            credential.chmod(0o600)
            revoked = state / 'revocations.json'
            revoked.write_bytes(b'[]')
            revoked.chmod(0o600)
            identity = {'bundleIdentity': 'b' * 64}
            with patch.object(driver, 'INSTALLED', source), \
                    patch.object(driver, 'PROVIDER_CREDENTIAL_PATH',
                                 str(credential)), \
                    patch.object(driver, 'PROVIDER_CONTEXT_ROOT', base), \
                    patch.object(worker, 'CREDENTIAL', credential), \
                    patch.object(worker, 'STATE', state), \
                    patch.object(worker, 'OPERATIONS', state / 'operations'), \
                    patch.object(registration, 'OPERATIONS',
                                 state / 'operations'), \
                    patch.object(registration, 'RESERVATIONS',
                                 state / 'reservations'), \
                    patch.object(registration, 'installed_verifier',
                                 return_value=(None, identity)), \
                    patch.object(worker.pwd, 'getpwnam',
                                 return_value=SimpleNamespace(pw_uid=62001)):
                first = driver._installed_provider_worker_control(
                    hashlib.sha256(raw).hexdigest(), 1)
                second = driver._installed_provider_worker_control(
                    hashlib.sha256(raw).hexdigest(), 2)
            self.assertNotEqual(first['handleDigest'], second['handleDigest'])
            self.assertEqual(first['credentialDigest'],
                             second['credentialDigest'])
            self.assertNotIn(token, json.dumps([first, second]))
            handles = list((state / 'operations').iterdir())
            self.assertEqual(2, len(handles))
            self.assertTrue(all((path / 'intent.json').is_file()
                                and (path / 'result.json').is_file()
                                for path in handles))

    def test_signed_python_child_is_bound_without_a_fictitious_java_descendant(self):
        worker = {'hostPid': 301, 'namespacePid': 20, 'startTicks': 50,
                  'managerInvocation': 'a' * 32,
                  'cgroupIdentity': [1, 99],
                  'sandboxLeader': {'hostPid': 300}}
        workload = SimpleNamespace(observe=Mock(return_value={'state': 'running'}))
        handoff = {'handles': {'candidate-sender': 'd' * 64},
                   'expectedJdkDigests': {'candidate-sender': 'sha256:' + 'b' * 64}}
        with patch('cross_version_workload.bind_probe_worker', return_value=worker):
            self.assertEqual(worker, driver._provider_app_actor(
                workload, handoff, worker))
            with self.assertRaisesRegex(ValueError, 'worker-changed'):
                driver._provider_app_actor(workload, handoff,
                    dict(worker, startTicks=51))

    @unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0,
                         'requires disposable Linux root for AppHost trigger ownership')
    def test_root_triggers_signed_app_child_and_retains_only_denial_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app_data = root / 'state/candidate-sender/data/node/apps/data/pr315-probe'
            app_data.mkdir(parents=True)
            target = {'role': None, 'managerInvocation': 'e' * 32,
                      'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                      'cgroupIdentity': [3, 5], 'mainPid': 211,
                      'mainStartTicks': 42,
                      'resolverCanaryIdentity': [3, 6],
                      'resolverControlDigest': 'a' * 64,
                      'providerCanaryIdentity': [3, 7],
                      'credentialIdentity': [3, 8],
                      'credentialDigest': 'f' * 64,
                      'controlDigest': 'b' * 64}
            actor = {'hostPid': 301, 'namespacePid': 20,
                     'namespacePids': [301, 20, 2], 'startTicks': 50,
                     'managerInvocation': 'c' * 32,
                     'cgroupIdentity': [1, 99],
                     'sandboxLeader': {'hostPid': 300},
                     'stateDigest': 'd' * 64}
            audits = []
            workload = SimpleNamespace(ROOT=root,
                account=lambda role: SimpleNamespace(pw_uid=0, pw_gid=0),
                write=lambda path, value, **_options: audits.append(value))
            handoff = {'handles': {'candidate-sender': 'f' * 64}}

            def provider_control(*_args):
                return dict(target, observedMonotonicNs=time.monotonic_ns())

            def app_control(*_args):
                return dict(actor, observedMonotonicNs=time.monotonic_ns())

            def read_result(path, uid, until, error):
                self.assertEqual(0, uid)
                self.assertEqual('workload-provider-result-timeout', error)
                trigger = json.loads((app_data / 'pr315-provider-trigger.json').read_text())
                started = time.monotonic_ns()
                return {'schemaVersion': 1,
                    'kind': 'pr315-signed-provider-authority-probe',
                    'caseId': 'provider-authority', 'nonce': trigger['nonce'],
                    'pid': 2, 'uid': 0, 'gid': 0,
                    'startedMonotonicNs': started,
                    'finishedMonotonicNs': time.monotonic_ns() + 1,
                    'targetPathDigest': hashlib.sha256(
                        driver.PROVIDER_CREDENTIAL_PATH.encode()).hexdigest(),
                    'outcome': {'opened': False, 'errno': 'ENOENT'}}

            with patch.object(driver, '_provider_target_control',
                              side_effect=provider_control), \
                    patch.object(driver, '_installed_provider_worker_control',
                        side_effect=lambda digest, ordinal: {
                            'kind': 'pr315-installed-worker-synthetic-provider-control-v2',
                            'ordinal': ordinal, 'credentialDigest': digest,
                            'handleDigest': str(ordinal) * 64,
                            'finishedMonotonicNs': 1 if ordinal == 1 else
                                time.monotonic_ns(),
                            'startedMonotonicNs': 1 if ordinal == 1 else
                                time.monotonic_ns()}) as control, \
                    patch.object(driver, '_provider_app_actor',
                                 side_effect=app_control), \
                    patch.object(driver, '_wait_output_record',
                                 side_effect=read_result):
                digest = driver.probe_provider_authority(workload, handoff,
                    {'providerDigest': 'b' * 64,
                     'credentialDigest': 'f' * 64},
                    'a' * 64, 'sha256:' + '8' * 64, actor,
                    time.monotonic_ns() + 30_000_000_000)
            self.assertEqual(1, len(audits))
            self.assertEqual('provider-authority', audits[0]['caseId'])
            self.assertEqual({'opened': False, 'errno': 'ENOENT'},
                             audits[0]['kernelOpenResult'])
            self.assertEqual(hashlib.sha256(json.dumps(audits[0],
                sort_keys=True, separators=(',', ':')).encode()).hexdigest(), digest)
            self.assertFalse((app_data / 'pr315-provider-trigger.json').exists())

    @unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0,
                         'requires disposable Linux root for provider canary')
    def test_synthetic_provider_canary_is_root_owned_and_bound_to_active_service(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'pr315-provider/pr315-provider-canary'
            resolver = {'role': None, 'managerInvocation': 'c' * 32,
                        'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                        'cgroupIdentity': [1, 22], 'mainPid': 211,
                        'mainStartTicks': 42, 'canaryIdentity': [1, 23],
                        'observedMonotonicNs': 10, 'controlDigest': 'a' * 64}
            with patch.object(driver, 'PROVIDER_PROBE_PATH', str(path)), \
                    patch.object(driver, 'PROVIDER_CREDENTIAL_PATH',
                                 str(Path(directory) / 'restricted-provider.json')), \
                    patch.object(driver, 'prepare_resolver_canary', return_value='a' * 64), \
                    patch.object(driver, '_provider_target_control', return_value={}) as control:
                selected = driver.prepare_provider_canary()
                with self.assertRaises(FileExistsError):
                    driver.prepare_provider_canary()
            self.assertEqual(32, path.stat().st_size)
            self.assertEqual(0, path.stat().st_uid)
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                             selected['providerDigest'])
            control.assert_called_with(selected['providerDigest'], 'a' * 64,
                selected['credentialDigest'])
            with patch.object(driver, 'PROVIDER_PROBE_PATH', str(path)), \
                    patch.object(driver, '_resolver_target_control', return_value=resolver):
                observed = driver._provider_target_control(
                    selected['providerDigest'], selected['resolverDigest'])
            self.assertEqual([path.stat().st_dev, path.stat().st_ino],
                             observed['providerCanaryIdentity'])
            self.assertEqual('c' * 32, observed['managerInvocation'])


class SiblingAppProbeTest(unittest.TestCase):
    def test_recipient_mail_worker_is_bound_to_live_http_control(self):
        worker = {'hostPid': 311, 'namespacePid': 21,
                  'startTicks': 52, 'javaHostPid': 312,
                  'javaStartTicks': 53, 'managerInvocation': 'a' * 32,
                  'cgroupIdentity': [1, 100]}
        observed = {'managerInvocation': 'a' * 32,
                    'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                    'cgroupIdentity': [1, 100], 'stateDigest': 'd' * 64,
                    'observedMonotonicNs': 10}
        workload = SimpleNamespace(observe=Mock(side_effect=[observed,
            dict(observed, observedMonotonicNs=30)]))
        handoff = {'handles': {'candidate-recipient': 'e' * 64},
                   'expectedJdkDigests': {'candidate-recipient': 'sha256:' + 'b' * 64}}
        http = {'role': 'candidate-recipient', 'managerInvocation': 'a' * 32,
                'bootId': observed['bootId'], 'cgroupIdentity': [1, 100],
                'controlObservedNs': 20, 'controlDigest': 'f' * 64}
        with patch('cross_version_workload.bind_worker', return_value=worker), \
                patch('restricted_workload_controller.bootstrap', return_value={
                    'uiOrigin': 'http://127.0.0.1:12345'}), \
                patch.object(driver, '_sibling_target_control', return_value=http):
            controlled = driver._sibling_app_target_control(
                workload, handoff, worker)
        self.assertEqual(311, controlled['workerHostPid'])
        self.assertEqual(20, controlled['controlObservedNs'])
        self.assertEqual(30, controlled['observedMonotonicNs'])
        self.assertEqual(hashlib.sha256(b'http://127.0.0.1:12345').hexdigest(),
                         controlled['appUiOriginDigest'])
        workload.observe = Mock(side_effect=[observed,
            dict(observed, observedMonotonicNs=30)])
        with patch('cross_version_workload.bind_worker', return_value=worker), \
                patch('restricted_workload_controller.bootstrap', return_value={
                    'uiOrigin': 'http://remote.invalid:12345'}), \
                self.assertRaisesRegex(ValueError, 'origin-unavailable'):
            driver._sibling_app_target_control(workload, handoff, worker)

    @unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0,
                         'requires disposable Linux root for AppHost trigger ownership')
    def test_signed_app_syn_requires_own_named_drop_and_active_recipient(self):
        import restricted_workload_network as network
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app_data = root / 'state/candidate-sender/data/node/apps/data/pr315-probe'
            app_data.mkdir(parents=True)
            actor = {'hostPid': 301, 'namespacePid': 20,
                     'namespacePids': [301, 20, 2], 'startTicks': 50,
                     'managerInvocation': 'c' * 32,
                     'cgroupIdentity': [1, 99],
                     'sandboxLeader': {'hostPid': 300},
                     'stateDigest': 'd' * 64,
                     'networkNamespaceIdentity': [1, 200]}
            target = {'role': 'candidate-recipient',
                      'managerInvocation': 'e' * 32,
                      'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                      'cgroupIdentity': [1, 100],
                      'workerHostPid': 311, 'workerStartTicks': 52,
                      'javaHostPid': 312, 'javaStartTicks': 53,
                      'controlDigest': 'f' * 64,
                      'appUiOriginDigest': hashlib.sha256(
                          b'http://127.0.0.1:12345').hexdigest()}
            names = network.SIBLING_DROP_COUNTERS
            policy = hashlib.sha256(network.role_rules(
                'candidate-sender').encode()).hexdigest()
            calls = [0]

            def counter():
                selected = calls[0]
                calls[0] += 1
                counters = {name: {'packets': 0, 'bytes': 0}
                            for name in names.values()}
                if selected:
                    counters[names['sibling-app']] = {'packets': 1, 'bytes': 60}
                return {'schemaVersion': 1,
                    'kind': 'pr315-fixed-sibling-drop-counters',
                    'policyDigest': policy,
                    'bootId': target['bootId'],
                    'roleNamespaceIdentity': [1, 200],
                    'observedMonotonicNs': time.monotonic_ns(),
                    'counters': counters}

            def app_control(*_args):
                return dict(actor, observedMonotonicNs=time.monotonic_ns())

            def target_control(*_args):
                observed_ns = time.monotonic_ns()
                return dict(target, controlObservedNs=observed_ns - 1,
                            observedMonotonicNs=observed_ns)

            def read_result(*_args):
                trigger = json.loads((app_data / 'pr315-sibling-app-trigger.json').read_text())
                started = time.monotonic_ns()
                return {'schemaVersion': 1,
                    'kind': 'pr315-signed-sibling-app-probe',
                    'caseId': 'sibling-app', 'nonce': trigger['nonce'],
                    'pid': 2, 'uid': 0, 'gid': 0,
                    'startedMonotonicNs': started,
                    'finishedMonotonicNs': time.monotonic_ns() + 1,
                    'sourcePort': 19404,
                    'targetEndpointDigest': hashlib.sha256(
                        b'10.231.0.2:19402').hexdigest(),
                    'outcome': {'connected': False, 'phase': 'connect',
                                'errno': 'ETIMEDOUT'}}

            audits = []
            workload = SimpleNamespace(ROOT=root,
                account=lambda role: SimpleNamespace(pw_uid=0, pw_gid=0),
                write=lambda path, value, **_options: audits.append(value))
            handoff = {'handles': {'candidate-sender': 'a' * 64,
                                   'candidate-recipient': 'b' * 64}}
            with patch.object(driver, '_provider_app_actor', side_effect=app_control), \
                    patch.object(driver, '_sibling_app_target_control',
                                 side_effect=target_control), \
                    patch.object(driver, '_wait_output_record', side_effect=read_result), \
                    patch.object(network, 'read_sibling_drop_counters',
                                 side_effect=counter):
                digest = driver.probe_sibling_app(workload, handoff,
                    'sha256:' + '8' * 64, actor, target,
                    time.monotonic_ns() + 30_000_000_000)
            self.assertEqual(1, len(audits))
            self.assertEqual(names['sibling-app'], audits[0]['counterName'])
            self.assertEqual({'connected': False, 'phase': 'connect',
                              'errno': 'ETIMEDOUT'}, audits[0]['kernelConnectResult'])
            self.assertEqual(hashlib.sha256(json.dumps(audits[0],
                sort_keys=True, separators=(',', ':')).encode()).hexdigest(), digest)
            self.assertFalse((app_data / 'pr315-sibling-app-trigger.json').exists())


class OutputHardlinkControlTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux descriptor pinning required')
    def test_canary_remains_byte_checked_after_actor_creates_second_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canary = root / driver.OUTPUT_CANARY
            artifact = root / driver.OUTPUT_HARDLINK
            canary.write_bytes(b'x' * 32)
            canary.chmod(0o600)
            expected = hashlib.sha256(b'x' * 32).hexdigest()
            before = driver._output_canary_control(root, os.geteuid(), expected,
                                                   'output-hardlink')
            os.link(canary, artifact)
            after = driver._output_canary_control(root, os.geteuid(), expected,
                                                  'output-hardlink', expected_links=2)
            self.assertEqual((1, 2), (before['linkCount'], after['linkCount']))
            self.assertEqual(before['fileIdentity'][:4], after['fileIdentity'][:4])
            canary.write_bytes(b'y' * 32)
            with self.assertRaisesRegex(ValueError, 'target-invalid'):
                driver._output_canary_control(root, os.geteuid(), expected,
                                              'output-hardlink', expected_links=2)


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
        authority_claims = {'startedMonotonicNs': 40,
            'identityClaim': identity_claim, 'counterClaim': counter_claim}
        self.assertEqual((identity_claim, counter_claim),
            driver._validate_false_role_claims(authority_claims, before, after,
                                               actor, 983, authority_only=True))
        with self.assertRaisesRegex(driver.RoleProbeDiagnosticError,
                                    'claim-timeline-invalid'):
            driver._validate_false_role_claims(dict(authority_claims,
                startedMonotonicNs=46), before, after, actor, 983,
                authority_only=True)
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
        role_only = {key: fixed[key] for key in ('writeAttempt', 'siblingRead',
                                                  'packageWrite', 'cgroupMigration')}
        self.assertEqual({'sibling-data', 'package-expectation', 'cgroup-migration'},
                         set(driver._validate_fixed_role_accesses(
                             role_only, after, role_boundary=True)))
        early = dict(role_only, siblingRead=dict(role_only['siblingRead'],
                                                 startedMonotonicNs=45))
        with self.assertRaisesRegex(driver.RoleProbeDiagnosticError,
                                    'fixed-access-timeline-invalid'):
            driver._validate_fixed_role_accesses(early, after, role_boundary=True)
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
