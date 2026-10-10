"""Closed campaign selection and preparation accounting without allocating VMs."""
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import patch

import installation
import pr315_workload_coordinator as coordinator


class CoordinatorSelectionTest(unittest.TestCase):
    def test_host_and_fault_helpers_are_test_kit_only(self):
        self.assertFalse(installation.production_member(
            'tools/release-certification/restricted/'
            'pr315_workload_coordinator.py'))
        self.assertFalse(installation.production_member(
            'tools/release-certification/restricted/'
            'pr315_pve_attempt_cleanup.py'))
        self.assertFalse(installation.production_member(
            'tools/release-certification/restricted/'
            'pr315_pve_attempt_inventory.py'))
        for name in ('pr315_installed_case_validators.py',
                     'pr315_workload_fault_probes.py'):
            self.assertFalse(installation.production_member(
                'tools/release-certification/restricted/' + name))

    def test_authority_preparation_uses_one_of_three_group_attempts(self):
        groups = [group for group, _ in coordinator.campaign.GROUPS]
        history = [{'groupId': group, 'status': 'completed'}
                   for group in groups[:2]]
        self.assertEqual({'status': 'ready', 'groupId': 'authority',
            'attemptOrdinal': 1, 'action': 'retired-authority-preparation'},
            coordinator.next_campaign_selection(history))
        history.append({'groupId': 'authority',
                        'status': 'preparation-completed'})
        self.assertEqual({'status': 'ready', 'groupId': 'authority',
            'attemptOrdinal': 2, 'action': 'selected-group'},
            coordinator.next_campaign_selection(history))
        history.append({'groupId': 'authority', 'status': 'setup-failed'})
        self.assertEqual({'status': 'ready', 'groupId': 'authority',
            'attemptOrdinal': 3, 'action': 'selected-group'},
            coordinator.next_campaign_selection(history))
        history.append({'groupId': 'authority', 'status': 'setup-failed'})
        self.assertEqual('failed',
            coordinator.next_campaign_selection(history)['status'])

    def test_development_authority_runs_directly_with_shared_preparation_budget(self):
        selected = coordinator.next_campaign_selection([], development_group='authority')
        self.assertEqual('authority', selected['groupId'])
        self.assertEqual('retired-authority-preparation', selected['action'])
        history = [{'groupId': 'authority', 'status': 'preparation-completed'}]
        self.assertEqual('selected-group', coordinator.next_campaign_selection(
            history, development_group='authority')['action'])
        history.append({'groupId': 'authority', 'status': 'setup-failed'})
        self.assertEqual(3, coordinator.next_campaign_selection(
            history, development_group='authority')['attemptOrdinal'])
        history.append({'groupId': 'authority', 'status': 'failed'})
        self.assertEqual('failed', coordinator.next_campaign_selection(
            history, development_group='authority')['status'])
        with self.assertRaisesRegex(ValueError, 'history-group-changed'):
            coordinator.next_campaign_selection(
                [{'groupId': 'positive', 'status': 'completed'}],
                development_group='authority')

    def test_development_selected_group_reaches_admission_without_positive_groups(self):
        root = Path('/private/campaign')
        source = Path('/source')
        plan = {'planDigest': 'a' * 64, 'hostKeyFingerprint': 'b' * 64}
        config = {'sourceCommit': 'c' * 40, 'hostKeyFingerprint': 'b' * 64}
        verdict = {'installedWorkloadAcceptanceSatisfied': False,
                   'groupSatisfied': False}
        remote = SimpleNamespace(call=unittest.mock.Mock(
            return_value=SimpleNamespace(returncode=0)))
        with patch.object(coordinator, 'frozen_campaign_context', return_value=(
                root, source, plan, {'firstSuiteNumber': 201}, config)), \
                patch.object(coordinator, 'Remote', return_value=remote), \
                patch.object(coordinator, 'source_preflight'), \
                patch.object(coordinator, 'publish_frozen_campaign'), \
                patch.object(coordinator.owner, 'recovered_development_verdict',
                             return_value=verdict), \
                patch.object(coordinator.seal, 'load_verified_history', return_value=[]), \
                patch.object(coordinator, 'prelaunch_admission',
                             return_value=({}, {'admitted': False})), \
                patch.object(coordinator, 'archive_pre_admission_failure') as archive:
            self.assertEqual(verdict, coordinator.run_campaign(
                root, source, development_group='output-symlink'))
            self.assertEqual('output-symlink', archive.call_args.args[5])
            self.assertEqual('suite-201', archive.call_args.args[4])

    def test_retired_preparation_requires_partial_exit_and_exact_status(self):
        observed = {'runnerExitCode': 2, 'assessment': {
            'status': 'retired-authority-preparation-executed'}}
        self.assertTrue(coordinator.retired_preparation_complete(observed))
        for exit_code in (0, 78):
            self.assertFalse(coordinator.retired_preparation_complete(
                {**observed, 'runnerExitCode': exit_code}))
        self.assertFalse(coordinator.retired_preparation_complete({
            **observed, 'assessment': {'status': 'setup-blocked'}}))
        self.assertFalse(coordinator.retired_preparation_complete({
            **observed, 'assessment': None}))

    def test_launch_margin_resets_on_high_psi_and_retains_actual_samples(self):
        values = [(4.0, 1.0), (6.0, 0.0), (4.0, 0.0),
                  (4.0, 1.0), (5.0, 2.0)]
        remote = SimpleNamespace(call=unittest.mock.Mock(side_effect=[
            SimpleNamespace(stdout=json.dumps({'io': io, 'memory': memory,
                'hostTimeNs': index + 1}).encode())
            for index, (io, memory) in enumerate(values)]))
        with tempfile.TemporaryDirectory(prefix='pr315-margin-') as temp, \
                patch.object(coordinator.time, 'sleep') as sleep:
            selected = coordinator.wait_for_launch_margin(
                remote, Path(temp), 'suite-201')
            rows = [json.loads(line) for line in
                (Path(temp) / 'pre-admission-psi.private.jsonl').read_text().splitlines()]
        self.assertEqual(3, selected['consecutiveLowSamples'])
        self.assertEqual([1, 0, 1, 2, 3],
                         [row['consecutiveLowSamples'] for row in rows])
        self.assertEqual(4, sleep.call_count)
        self.assertEqual(5, remote.call.call_count)

    def test_launch_margin_follows_all_input_reads_before_formal_admission(self):
        ordered = []
        def record(name, value=None):
            ordered.append(name)
            return value
        config = {'sourceCommit': 'a' * 40,
                  'sourceSnapshot': coordinator.CT_TASK +
                    '/campaign-frozen/source-test'}
        with patch.object(coordinator, 'task_qemu_inventory',
                          side_effect=lambda remote: record('inventory')), \
                patch.object(coordinator, 'wait_for_launch_margin',
                             side_effect=lambda *args: record('margin')), \
                patch.object(coordinator, 'required_attempt_bytes',
                             side_effect=lambda *args: record('required', 100)), \
                patch.object(coordinator, 'capacity_preflight',
                             side_effect=lambda *args: record('capacity', {'free': 200})), \
                patch.object(coordinator, 'boot_preflight',
                             side_effect=lambda *args: record('boot')), \
                patch.object(coordinator, '_exclusive_json',
                             side_effect=lambda *args: record('persist')), \
                patch.object(coordinator, 'admit_and_watch',
                             side_effect=lambda *args: record('formal',
                                 {'admitted': False})):
            result = coordinator.prelaunch_admission(object(),
                Path('/private/campaign'), config, 'suite-201',
                {'macAvailableAtStartBytes': 1000}, plan={'identity': {}})
        self.assertEqual(({'free': 200}, {'admitted': False}), result)
        self.assertEqual(['inventory', 'required', 'capacity', 'boot',
                          'margin', 'inventory', 'capacity', 'persist', 'formal'], ordered)

    def test_input_verification_pressure_must_settle_before_formal_admission(self):
        pressure = {'io': 0.0}
        def scan(*args):
            pressure['io'] = 13.0
        def settle(*args):
            pressure['io'] = 3.0
        config = {'sourceCommit': 'a' * 40,
                  'sourceSnapshot': coordinator.CT_TASK + '/campaign-frozen/source-test'}
        with patch.object(coordinator, 'task_qemu_inventory'), \
                patch.object(coordinator, 'required_attempt_bytes', return_value=100), \
                patch.object(coordinator, 'capacity_preflight', return_value={'free': 200}), \
                patch.object(coordinator, 'boot_preflight', side_effect=scan), \
                patch.object(coordinator, '_exclusive_json'), \
                patch.object(coordinator, 'wait_for_launch_margin', side_effect=settle), \
                patch.object(coordinator, 'admit_and_watch', side_effect=lambda *args: {
                    'admitted': pressure['io'] <= 10}):
            _capacity, observed = coordinator.prelaunch_admission(object(),
                Path('/private/campaign'), config, 'suite-201',
                {'macAvailableAtStartBytes': 1000}, plan={'identity': {}})
        self.assertTrue(observed['admitted'])

    def test_capacity_change_during_quiet_wait_refuses_formal_admission(self):
        available = {'value': True}
        def capacity(*args):
            if not available['value']:
                raise ValueError('pr315-task-capacity-unavailable')
            return {'free': 200}
        def quiet_wait(*args):
            available['value'] = False
        with patch.object(coordinator, 'task_qemu_inventory'), \
                patch.object(coordinator, 'required_attempt_bytes', return_value=100), \
                patch.object(coordinator, 'capacity_preflight', side_effect=capacity), \
                patch.object(coordinator, 'boot_preflight'), \
                patch.object(coordinator, '_exclusive_json'), \
                patch.object(coordinator, 'wait_for_launch_margin', side_effect=quiet_wait), \
                patch.object(coordinator, 'admit_and_watch') as admit:
            with self.assertRaisesRegex(ValueError, 'task-capacity-unavailable'):
                coordinator.prelaunch_admission(object(), Path('/private'), {},
                    'suite-201', {'macAvailableAtStartBytes': 1000}, plan={})
            admit.assert_not_called()

    def test_boot_dependency_drift_refuses_admission_before_watcher(self):
        with patch.object(coordinator, 'task_qemu_inventory'), \
                patch.object(coordinator, 'wait_for_launch_margin'), \
                patch.object(coordinator, 'required_attempt_bytes', return_value=100), \
                patch.object(coordinator, 'capacity_preflight', return_value={}), \
                patch.object(coordinator, 'measured_boot_closure', return_value={
                    'bootClosureDigest': 'b' * 64, 'fileCount': 204}), \
                patch.object(coordinator, 'admit_and_watch') as admit, \
                patch.object(coordinator, '_exclusive_json') as publish:
            with self.assertRaisesRegex(ValueError, 'frozen-boot-closure-changed'):
                coordinator.prelaunch_admission(object(), Path('/private'), {},
                    'suite-201', {'macAvailableAtStartBytes': 1000},
                    plan={'identity': {'bootClosureDigest': 'a' * 64}})
            admit.assert_not_called()
            publish.assert_not_called()

    def test_runner_streams_survive_missing_assessment_before_error(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o700)
            config = {'sourceCommit': 'a' * 40}
            remote = SimpleNamespace(call=unittest.mock.Mock(side_effect=[
                SimpleNamespace(returncode=2, stdout=b'bounded-failure', stderr=b'diagnostic'),
                SimpleNamespace(returncode=1, stdout=b'', stderr=b'')]))
            with patch.object(coordinator, 'runner_arguments', return_value=['fixed']), \
                    self.assertRaisesRegex(ValueError, 'ct-assessment-unavailable'):
                coordinator.run_selected_attempt(remote, config, 'suite-201',
                    'authority', diagnostic_root=root)
            value = json.loads((root / 'suite-201-ct-outcome.private.json').read_bytes())
            self.assertEqual('a' * 40, value['sourceCommit'])
            self.assertEqual(2, value['exitCode'])
            import base64
            self.assertEqual(b'bounded-failure', base64.b64decode(value['stdoutBase64']))
            self.assertEqual(b'diagnostic', base64.b64decode(value['stderrBase64']))
            self.assertNotIn('passed', value)

    def test_unknown_or_post_probe_failure_cannot_be_retried(self):
        history = [{'groupId': 'positive', 'status': 'failed'}]
        self.assertEqual('failed',
            coordinator.next_campaign_selection(history)['status'])
        history[0]['status'] = 'unknown'
        self.assertEqual('failed',
            coordinator.next_campaign_selection(history)['status'])

    def test_sealed_pre_admission_denial_uses_next_unique_suite_slot(self):
        history = [{'groupId': 'positive', 'status': 'completed'},
                   {'groupId': 'role-boundary', 'status': 'setup-failed'}]
        self.assertEqual({'status': 'ready', 'groupId': 'role-boundary',
                          'attemptOrdinal': 2, 'action': 'selected-group'},
                         coordinator.next_campaign_selection(history))

    def test_no_vm_selected_after_all_groups_complete(self):
        history = [{'groupId': group, 'status': 'completed'}
                   for group, _ in coordinator.campaign.GROUPS]
        self.assertEqual('complete',
            coordinator.next_campaign_selection(history)['status'])

    def test_public_case_count_cannot_bypass_private_group_verification(self):
        owned = set(dict(coordinator.campaign.GROUPS)['positive'])
        plan = {'planDigest': 'a' * 64,
                'campaignNonce': 'b' * 64,
                'hostKeyFingerprint': 'c' * 64}
        result = {'schemaVersion': 2,
            'contract': coordinator.seal.CONTRACT,
            'campaignPlanDigest': plan['planDigest'],
            'campaignNonce': plan['campaignNonce'],
            'hostKeyFingerprint': plan['hostKeyFingerprint'],
            'status': 'partial-execution', 'reasons': [],
            'installedPositiveExecuted': True,
            'installedWorkloadAcceptanceSatisfied': False,
            'cases': coordinator.seal.acceptance.inventory(
                {case: 'passed' for case in owned})}
        self.assertTrue(coordinator.selected_group_complete(
            plan, 'positive', result))
        result['cases'][0]['status'] = 'failed'
        self.assertFalse(coordinator.selected_group_complete(
            plan, 'positive', result))
        result['cases'][0]['status'] = 'passed'
        result['cases'][-1]['status'] = 'passed'
        self.assertFalse(coordinator.selected_group_complete(
            plan, 'positive', result))

    def test_missing_or_wrong_probe_start_never_becomes_setup_retry(self):
        self.assertIsNone(coordinator.explicit_probe_phase('network-app', {}))
        marker = {'schemaVersion': 1,
            'kind': 'pr315-workload-probe-start',
            'caseId': 'network-app', 'startedMonotonicNs': 123}
        self.assertTrue(coordinator.explicit_probe_phase(
            'network-app', {'probeStart': marker}))
        self.assertIsNone(coordinator.explicit_probe_phase(
            'network-app', {'probeStart': dict(marker,
                caseId='authority')}))

    def test_pressure_stop_requires_fixed_action_and_no_remaining_disk_users(self):
        value = {'schemaVersion': 1,
                 'kind': 'pr315-pve-task-qemu-pressure-stopped-v1',
                 'attemptId': 'suite-201', 'sourceCommit': 'a' * 40,
                 'watcherAction': 'pressure-memoryPressure',
                 'watcherReceiptDigest': 'b' * 64,
                 'watcherFinishedMonotonicNs': 10,
                 'observedMonotonicNs': 11,
                 'pveBootId': 'boot', 'taskQemuProcesses': [],
                 'openDiskUserPids': []}
        remote = SimpleNamespace(call=unittest.mock.Mock(
            return_value=SimpleNamespace(stdout=json.dumps(value).encode())))
        self.assertEqual(value, coordinator.pressure_stopped_observation(
            remote, 'suite-201', 'a' * 40, 'pressure-memoryPressure'))
        with self.assertRaisesRegex(ValueError, 'selection-invalid'):
            coordinator.pressure_stopped_observation(
                remote, 'suite-201', 'a' * 40, 'completed')
        remote.call.return_value = SimpleNamespace(stdout=json.dumps(
            dict(value, openDiskUserPids=[500])).encode())
        with self.assertRaisesRegex(ValueError, 'observation-invalid'):
            coordinator.pressure_stopped_observation(
                remote, 'suite-201', 'a' * 40, 'pressure-memoryPressure')

    def test_finished_watcher_never_accepts_an_unlisted_action(self):
        record = {'suite': 'suite-201', 'sourceCommit': 'a' * 40,
                  'action': 'pressure-memoryPressure',
                  'seenTaskQemu': True}
        config = {'sourceCommit': 'a' * 40,
                  'sourceSnapshot': coordinator.CT_TASK +
                    '/campaign-frozen/source-test'}
        remote = SimpleNamespace(call=unittest.mock.Mock(
            return_value=SimpleNamespace(returncode=0,
                stdout=json.dumps(record).encode())))
        self.assertEqual(record, coordinator.finished_watcher(
            remote, config, 'suite-201', {}))
        remote.call.return_value = SimpleNamespace(returncode=0,
            stdout=json.dumps(dict(record, action='untrusted-pass')).encode())
        with patch.object(coordinator.time, 'monotonic', side_effect=[0, 31]), \
                self.assertRaisesRegex(ValueError, 'watcher-incomplete'):
            coordinator.finished_watcher(remote,
                config, 'suite-201', {})

    @unittest.skipUnless(Path('/proc/self/fd').is_dir(),
                         'Linux procfs is required for descriptor ownership')
    def test_pressure_stop_code_rejects_an_open_failed_guest_disk(self):
        with tempfile.TemporaryDirectory(prefix='pr315-pressure-stop-') as temp:
            root = Path(temp)
            monitor = root / 'host-monitor'
            attempt = root / 'suite-201/attempt-01'
            monitor.mkdir()
            attempt.mkdir(parents=True)
            guest = attempt / 'guest.qcow2'
            guest.write_bytes(b'guest-disk')
            (attempt / 'prepared.qcow2').write_bytes(b'prepared-disk')
            watcher = Path(coordinator.__file__).with_name(
                'pr315_pve_pressure_watch.py')
            receipt = monitor / 'suite-201.finished.json'
            receipt.write_text(json.dumps({
                'suite': 'suite-201', 'sourceCommit': 'a' * 40,
                'action': 'pressure-memoryPressure',
                'seenTaskQemu': True,
                'moduleDigest': hashlib.sha256(watcher.read_bytes()).hexdigest(),
                'finishedMonotonicNs': time.monotonic_ns() - 10**9}))
            receipt.chmod(0o444)
            script = coordinator._PVE_PRESSURE_STOP_CODE.replace(
                coordinator.PVE_TASK, str(root)).replace(
                '/root/pr315-workload/source-0fa', str(watcher.parent))
            # The production path's root and mapped-UID gates are exercised
            # on PVE; this unprivileged Linux test exercises the live-FD gate.
            for pinned, fixture in (('os.geteuid()!=0', 'False'),
                                    ('info.st_uid!=0', 'False'),
                                    ('disk.st_uid!=101000', 'False')):
                self.assertEqual(1, script.count(pinned))
                script = script.replace(pinned, fixture)
            command = [sys.executable, '-c', script, 'suite-201',
                       'a' * 40, 'pressure-memoryPressure']
            with guest.open('rb'):
                held = subprocess.run(command, capture_output=True, timeout=10)
            self.assertNotEqual(0, held.returncode)
            stopped = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(0, stopped.returncode,
                             stopped.stderr.decode(errors='replace'))
            self.assertEqual([], json.loads(stopped.stdout)['openDiskUserPids'])

    def test_pressure_terminal_seals_failure_before_any_next_guest(self):
        import pr315_case_registry as registry
        plan = {'hostKeyFingerprint': 'b' * 64, 'planDigest': 'c' * 64}
        config = {'sourceCommit': 'a' * 40,
                  'hostKeyFingerprint': plan['hostKeyFingerprint']}
        remote = SimpleNamespace(call=unittest.mock.Mock(
            return_value=SimpleNamespace(returncode=0)))
        selected = {'status': 'ready', 'groupId': 'positive',
                    'action': 'selected-group'}
        verdict = {'status': 'incomplete',
                   'installedWorkloadAcceptanceSatisfied': False}
        with patch.object(coordinator, 'frozen_campaign_context',
                          return_value=(Path('/private'), Path('/source'), plan,
                                        {'firstSuiteNumber': 201}, config)), \
                patch.object(registry, 'implementation_coverage',
                             return_value='complete'), \
                patch.object(coordinator, 'Remote', return_value=remote), \
                patch.object(coordinator, 'source_preflight'), \
                patch.object(coordinator, 'publish_frozen_campaign'), \
                patch.object(coordinator.owner, 'recovered_campaign_verdict',
                             return_value=verdict), \
                patch.object(coordinator.seal, 'load_verified_history',
                             return_value=[]), \
                patch.object(coordinator, 'next_campaign_selection',
                             return_value=selected), \
                patch.object(coordinator, 'prelaunch_admission',
                             return_value=({}, {'admitted': True})), \
                patch.object(coordinator, 'run_selected_attempt',
                             return_value={'assessment': {
                                 'status': 'monitor-incomplete'}}), \
                patch.object(coordinator, 'finished_watcher',
                             return_value={'action':
                                 'pressure-memoryPressure'}), \
                patch.object(coordinator, 'stage_full_attempt',
                             return_value=('/stage', 'd' * 64)) as stage, \
                patch.object(coordinator, '_seal_failed_attempt') as failed, \
                patch.object(coordinator, '_archive_case_group') as completed:
            self.assertEqual(verdict, coordinator.run_campaign(
                '/private', '/source'))
        stage.assert_called_once_with(remote, config, 'suite-201', Path('/private'),
            pressure_action='pressure-memoryPressure')
        failed.assert_called_once_with(Path('/private'), config, plan,
            'suite-201', 'positive', '/stage', 'd' * 64)
        completed.assert_not_called()

    def test_missing_assessment_archives_real_stopped_attempt_and_seals_failure(self):
        import pr315_case_registry as registry
        plan = {'hostKeyFingerprint': 'b' * 64, 'planDigest': 'c' * 64}
        config = {'sourceCommit': 'a' * 40, 'hostKeyFingerprint': 'b' * 64}
        remote = SimpleNamespace(call=unittest.mock.Mock(
            return_value=SimpleNamespace(returncode=0)))
        verdict = {'installedWorkloadAcceptanceSatisfied': False}
        with patch.object(coordinator, 'frozen_campaign_context', return_value=(
                Path('/private'), Path('/source'), plan,
                {'firstSuiteNumber': 201}, config)), \
                patch.object(registry, 'implementation_coverage', return_value='complete'), \
                patch.object(coordinator, 'Remote', return_value=remote), \
                patch.object(coordinator, 'source_preflight'), \
                patch.object(coordinator, 'publish_frozen_campaign'), \
                patch.object(coordinator.owner, 'recovered_campaign_verdict', return_value=verdict), \
                patch.object(coordinator.seal, 'load_verified_history', return_value=[]), \
                patch.object(coordinator, 'prelaunch_admission', return_value=({}, {'admitted': True})), \
                patch.object(coordinator, 'run_selected_attempt', side_effect=ValueError(
                    'pr315-ct-assessment-unavailable')), \
                patch.object(coordinator, 'finished_watcher', return_value={'action': 'completed'}), \
                patch.object(coordinator, 'stage_full_attempt', return_value=('/stage', 'd' * 64)) as stage, \
                patch.object(coordinator.owner, '_read', return_value=b'real-outcome'), \
                patch.object(coordinator, '_exclusive_json'), \
                patch.object(coordinator, '_seal_failed_attempt') as failed, \
                patch.object(coordinator, '_archive_case_group') as passed:
            self.assertEqual(verdict, coordinator.run_campaign('/private', '/source'))
        stage.assert_called_once_with(remote, config, 'suite-201', Path('/private'),
                                      pressure_action=None)
        self.assertEqual('pr315-ct-assessment-unavailable',
                         failed.call_args.kwargs['host_failure']['reason'])
        self.assertFalse(failed.call_args.kwargs['host_failure'][
            'installedWorkloadAcceptanceSatisfied'])
        passed.assert_not_called()

    def test_default_full_run_rejects_incomplete_emitters_before_remote_access(self):
        import pr315_case_registry as registry
        with patch.object(coordinator, 'frozen_campaign_context',
                          return_value=('/private', '/source', {}, {}, {})), \
                patch.object(registry, 'implementation_coverage',
                             return_value='incomplete'), \
                patch.object(coordinator, 'Remote') as remote:
            with self.assertRaisesRegex(ValueError,
                                        'emitter-coverage-incomplete'):
                coordinator.run_campaign('/private', '/source')
            remote.assert_not_called()

    def test_probe_exits_78_without_remote_or_vm_when_start_is_missing(self):
        with patch.object(coordinator, 'Remote') as remote, \
                redirect_stdout(io.StringIO()) as output:
            status = coordinator.main(['--probe',
                '--campaign-root', '/nonexistent-pr315-campaign',
                '--source', str(Path(__file__).resolve().parents[3])])
        self.assertEqual(78, status)
        self.assertIn('"installedWorkloadAcceptanceSatisfied": false',
                      output.getvalue())
        remote.assert_not_called()

    def test_source_clone_requires_capacity_check_before_git_allocation(self):
        remote = SimpleNamespace(call=unittest.mock.Mock(
            side_effect=[SimpleNamespace(returncode=0),
                         SimpleNamespace(returncode=1)]))
        config = {'sourceSnapshot':
            '/work/pr315-task/campaign-frozen/source-fixture'}
        with self.assertRaisesRegex(ValueError,
                                    'capacity-preflight-required'):
            coordinator.prepare_source_snapshot(remote, config)
        self.assertEqual(['mkdir', '-p', '-m', '700',
                          '/work/pr315-task/campaign-frozen'],
                         remote.call.call_args_list[0].args[1])
        self.assertEqual(2, remote.call.call_count)

    def test_wrong_frozen_guest_port_pin_fails_before_watcher(self):
        task = coordinator.CT_TASK
        config = {'sourceSnapshot': task + '/campaign-frozen/source-test',
                  'fixturePath': task + '/fixture',
                  'qemuRoot': task + '/qemu',
                  'preparedImage': task + '/prepared',
                  'seed': task + '/seed', 'sshKey': task + '/key',
                  'knownHosts': task + '/wrong-port-pin', 'port': 23113}
        remote = SimpleNamespace(call=unittest.mock.Mock(
            return_value=SimpleNamespace(stdout=json.dumps(
                ['known-hosts-port-pin-invalid']).encode())))
        with self.assertRaisesRegex(ValueError,
                                    'runner-prerequisites-invalid'):
            coordinator.remote_runner_prerequisites(remote, config)
        arguments = remote.call.call_args.args[1]
        self.assertEqual('python3', arguments[0])
        self.assertEqual(config['knownHosts'], arguments[-2])
        remote.call.return_value = SimpleNamespace(stdout=b'[]')
        self.assertEqual([], coordinator.remote_runner_prerequisites(
            remote, config))

    def test_separate_campaigns_publish_distinct_immutable_public_keys(self):
        with tempfile.TemporaryDirectory(prefix='pr315-key-path-test-') as temp:
            root = Path(temp)
            root.chmod(0o700)
            remote = SimpleNamespace(call=unittest.mock.Mock())
            base = {'campaignPlanPath': coordinator.CT_TASK +
                    '/campaign-frozen/plan.private.json'}
            with patch.object(coordinator, 'fixed_config'), \
                    patch.object(coordinator, 'source_preflight'), \
                    patch.object(coordinator, '_put_frozen_input',
                                 return_value='d' * 64) as publish:
                for digest in ('a' * 64, 'b' * 64):
                    coordinator.publish_frozen_campaign(remote, root,
                        {**base, 'campaignPlanDigest': digest})
            public_targets = [call.args[2] for call in
                              publish.call_args_list[1::2]]
            self.assertEqual(2, len(set(public_targets)))
            self.assertTrue(all(target.startswith(coordinator.CT_TASK +
                '/campaign-frozen/campaign-') for target in public_targets))
            for digest, target in zip(('a' * 64, 'b' * 64), public_targets):
                self.assertEqual(target,
                    coordinator.remote_campaign_input_paths(
                        {'campaignPlanDigest': digest})[2])

    def test_unlaunched_watcher_refuses_any_allocated_attempt(self):
        remote = SimpleNamespace(call=unittest.mock.Mock(
            return_value=SimpleNamespace(returncode=1)))
        with self.assertRaisesRegex(ValueError,
                                    'unlaunched-attempt-present'):
            coordinator.stop_unlaunched_watcher(remote,
                {'sourceCommit': 'a' * 40}, 'suite-201', {})
        self.assertEqual(1, remote.call.call_count)
        self.assertEqual(coordinator.CT, remote.call.call_args.args[0])

    def test_pve_pressure_denial_returns_before_watcher_launch(self):
        denied = {'policy': coordinator.host_admission.POLICY,
                  'admitted': False,
                  'reason': 'pve-admission-pressure-high'}
        remote = SimpleNamespace(call=unittest.mock.Mock(
            return_value=SimpleNamespace(returncode=78,
                stdout=json.dumps(denied).encode())))
        source = coordinator.CT_TASK + '/campaign-frozen/source-test'
        self.assertEqual(denied, coordinator.admit_and_watch(
            remote, 'suite-201', 'a' * 40, source))
        self.assertEqual(1, remote.call.call_count)
        self.assertEqual(coordinator.PVE, remote.call.call_args.args[0])
        self.assertFalse(remote.call.call_args.kwargs['check'])

    def test_pre_admission_denial_archive_rejects_changed_host_evidence(self):
        with tempfile.TemporaryDirectory(prefix='pr315-pre-admission-test-') as temp:
            root = Path(temp)
            root.chmod(0o700)
            archive = root / 'attempts/suite-201'
            archive.mkdir(parents=True, mode=0o700)
            archive.chmod(0o700)
            capacity = {'pveUsedBytes': 1, 'requiredAttemptBytes': 2}
            saved_capacity = root / 'capacity-suite-201.private.json'
            saved_capacity.write_text(json.dumps(capacity))
            saved_capacity.chmod(0o600)
            observed = {'policy': coordinator.host_admission.POLICY,
                'observedMonotonicNs': 123,
                'hostAvailableBytes': 8 * 1024**3,
                'hostSwapFreeBytes': 8 * 1024**3,
                'memoryFullAvg10Pct': 0.0,
                'ioFullAvg10Pct': 10.33,
                'ctMemoryMaxBytes': 10 * 1024**3,
                'ctMemoryCurrentBytes': 0,
                'ctSwapMaxBytes': 12 * 1024**3,
                'ctSwapCurrentBytes': 0}
            admission = {'schemaVersion': 1,
                'kind': 'pr315-pve-host-admission',
                'policy': coordinator.host_admission.POLICY,
                'suite': 'suite-201', 'sourceCommit': 'b' * 40,
                'moduleDigest': hashlib.sha256(Path(
                    coordinator.host_admission.__file__).read_bytes()).hexdigest(),
                'admitted': False, 'reason': 'pve-admission-pressure-high',
                'observation': observed}
            state = {'schemaVersion': 1,
                'kind': 'pr315-pre-admission-no-vm-observation',
                'suite': 'suite-201', 'sourceCommit': 'b' * 40,
                'taskQemuProcesses': [], 'ctAttemptAbsent': True,
                'pveWatcherAbsent': True}
            files = {}
            for name, value in (
                    ('capacity.private.json', capacity),
                    ('host-admission.private.json', admission),
                    ('host-state.private.json', state)):
                raw = json.dumps(value).encode()
                selected = archive / name
                selected.write_bytes(raw)
                selected.chmod(0o600)
                files[name] = {'sha256': hashlib.sha256(raw).hexdigest(),
                               'sizeBytes': len(raw)}
            plan = {'planDigest': 'a' * 64}
            manifest = {'schemaVersion': 1,
                'kind': 'pr315-pre-admission-rejection-archive-v1',
                'attemptId': 'suite-201', 'sourceCommit': 'b' * 40,
                'planDigest': plan['planDigest'], 'groupId': 'role-boundary',
                'guestAllocated': False, 'phase': 'pre-admission',
                'reason': 'pve-admission-pressure-high', 'files': files}
            selected = archive / 'preparation-archive.private.json'
            selected.write_text(json.dumps(manifest))
            selected.chmod(0o600)
            receipt = {'status': 'setup-failed', 'attemptId': 'suite-201',
                'sourceCommit': 'b' * 40, 'groupId': 'role-boundary',
                'probeStarted': False, 'caseDigests': {},
                'archiveDigest': coordinator.seal._digest(manifest),
                'evidenceDigest': files['host-admission.private.json']['sha256'],
                'monitorDigest': None, 'stopDigest': None}
            self.assertEqual(manifest,
                coordinator.verify_preparation_archive(root, plan, receipt))
            (archive / 'host-admission.private.json').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'byte-changed'):
                coordinator.verify_preparation_archive(root, plan, receipt)

    def test_pre_admission_denial_seals_only_real_no_vm_evidence(self):
        with tempfile.TemporaryDirectory(prefix='pr315-pre-admission-owner-') as temp:
            root = Path(temp)
            root.chmod(0o700)
            (root / 'attempts').mkdir(mode=0o700)
            suite, commit = 'suite-201', 'b' * 40
            capacity = {'pveUsedBytes': 1, 'requiredAttemptBytes': 2}
            coordinator._exclusive_json(
                root / ('capacity-' + suite + '.private.json'), capacity)
            observed = {'policy': coordinator.host_admission.POLICY,
                'observedMonotonicNs': 123,
                'hostAvailableBytes': 8 * 1024**3,
                'hostSwapFreeBytes': 8 * 1024**3,
                'memoryFullAvg10Pct': 0.0, 'ioFullAvg10Pct': 10.33,
                'ctMemoryMaxBytes': 10 * 1024**3,
                'ctMemoryCurrentBytes': 0,
                'ctSwapMaxBytes': 12 * 1024**3,
                'ctSwapCurrentBytes': 0}
            admission = {'schemaVersion': 1,
                'kind': 'pr315-pve-host-admission',
                'policy': coordinator.host_admission.POLICY,
                'suite': suite, 'sourceCommit': commit,
                'moduleDigest': hashlib.sha256(Path(
                    coordinator.host_admission.__file__).read_bytes()).hexdigest(),
                'admitted': False, 'reason': 'pve-admission-pressure-high',
                'observation': observed}
            raw = json.dumps(admission).encode()
            denial = {'policy': coordinator.host_admission.POLICY,
                      'admitted': False,
                      'reason': 'pve-admission-pressure-high'}
            remote = SimpleNamespace(call=unittest.mock.Mock(
                return_value=SimpleNamespace(returncode=0)))

            def copy_admission(_remote, host, source, target):
                self.assertEqual(coordinator.CT, host)
                self.assertEqual(coordinator.CT_TASK +
                    '/host-admission/' + suite + '.json', source)
                target.write_bytes(raw)
                target.chmod(0o600)

            def seal_attempt(_root, _plan, **selected):
                return {'status': selected['status'],
                    'attemptId': selected['attempt_id'],
                    'sourceCommit': selected['pinned_source_commit'],
                    'groupId': selected['group_id'],
                    'probeStarted': selected['probe_started'],
                    'caseDigests': selected['case_digests'],
                    'evidenceDigest': selected['evidence_digest'],
                    'stopDigest': selected['stop_digest'],
                    'monitorDigest': selected['monitor_digest'],
                    'archiveDigest': selected['archive_digest']}

            config = {'sourceCommit': commit,
                      'hostKeyFingerprint': 'c' * 64}
            plan = {'planDigest': 'a' * 64}
            with patch.object(coordinator, '_scp', side_effect=copy_admission), \
                    patch.object(coordinator, 'task_qemu_inventory',
                                 return_value=[]), \
                    patch.object(coordinator.seal, 'append_verified_attempt',
                                 side_effect=seal_attempt):
                receipt = coordinator.archive_pre_admission_failure(
                    remote, root, config, plan, suite, 'role-boundary',
                    capacity, denial)
            self.assertEqual('setup-failed', receipt['status'])
            self.assertIsNone(receipt['monitorDigest'])
            self.assertIsNone(receipt['stopDigest'])
            self.assertEqual({}, receipt['caseDigests'])
            self.assertEqual(6, remote.call.call_count)
            self.assertTrue(all(call.kwargs.get('check') is False
                                for call in remote.call.call_args_list))
            archive = root / 'attempts' / suite
            self.assertFalse((archive / 'attempt-01').exists())
            self.assertEqual('pr315-pre-admission-rejection-archive-v1',
                coordinator.verify_preparation_archive(
                    root, plan, receipt)['kind'])

    def test_no_vm_setup_archive_rejects_tampering_before_retry(self):
        with tempfile.TemporaryDirectory(prefix='pr315-no-vm-archive-test-') as temp:
            root = Path(temp)
            root.chmod(0o700)
            archive = root / 'attempts/suite-201'
            receipts = archive / 'host-receipts'
            receipts.mkdir(parents=True, mode=0o700)
            archive.chmod(0o700)
            receipts.chmod(0o700)
            names = ('assessment.json', 'capacity.private.json',
                'plan.private.json',
                'host-receipts/host-admission.private.json',
                'host-receipts/host-monitor-ready.private.json',
                'host-receipts/host-monitor-finished.private.json',
                'host-receipts/host-monitor-samples.private.jsonl',
                'host-receipts/host-monitor-stop.private')
            files = {}
            for name in names:
                path = archive / name
                path.write_bytes(name.encode())
                path.chmod(0o600)
                files[name] = {'sha256': hashlib.sha256(
                    name.encode()).hexdigest(), 'sizeBytes': len(name)}
            plan = {'planDigest': 'a' * 64}
            manifest = {'schemaVersion': 1,
                'kind': 'pr315-no-vm-preparation-archive-v1',
                'attemptId': 'suite-201', 'sourceCommit': 'b' * 40,
                'planDigest': plan['planDigest'], 'groupId': 'positive',
                'guestAllocated': False, 'files': files}
            selected = archive / 'preparation-archive.private.json'
            selected.write_text(json.dumps(manifest))
            selected.chmod(0o600)
            receipt = {'status': 'setup-failed', 'attemptId': 'suite-201',
                'sourceCommit': 'b' * 40, 'groupId': 'positive',
                'archiveDigest': coordinator.seal._digest(manifest),
                'evidenceDigest': files['assessment.json']['sha256'],
                'monitorDigest': files[
                    'host-receipts/host-monitor-finished.private.json']['sha256'],
                'stopDigest': None}
            self.assertEqual(manifest,
                coordinator.verify_preparation_archive(root, plan, receipt))
            (archive / 'assessment.json').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'byte-changed'):
                coordinator.verify_preparation_archive(root, plan, receipt)

    def test_full_staging_rehash_rejects_changed_or_extra_guest_bytes(self):
        with tempfile.TemporaryDirectory(prefix='pr315-full-stage-test-') as temp:
            root = Path(temp)
            root.chmod(0o700)
            stage = root / 'full-attempt-staging/suite-201'
            stage.mkdir(parents=True, mode=0o700)
            stage.chmod(0o700)
            files = {}
            for relative in ('attempt-01/guest.qcow2',
                             'attempt-01/prepared.qcow2',
                             'attempt-01/source.tar.gz',
                             'host-stop.private.json'):
                path = stage / relative
                path.parent.mkdir(mode=0o700, exist_ok=True)
                path.write_bytes(relative.encode())
                files[relative] = {'sha256': hashlib.sha256(
                    relative.encode()).hexdigest(),
                    'sizeBytes': len(relative)}
            manifest = {'schemaVersion': 1,
                'kind': 'pr315-mac-full-attempt-preservation-v1',
                'attemptId': 'suite-201', 'sourceCommit': 'a' * 40,
                'files': files, 'copyVerified': True,
                'excludedReconstructible': []}
            selected = stage / 'full-stage-manifest.private.json'
            selected.write_text(json.dumps(manifest))
            selected.chmod(0o600)
            _stage, _manifest, digest = (
                coordinator.verify_full_staging_copy(root, 'suite-201',
                    'a' * 40))
            self.assertEqual(coordinator.seal._digest(manifest), digest)
            (stage / 'attempt-01/guest.qcow2').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'file-identity-changed'):
                coordinator.verify_full_staging_copy(root, 'suite-201',
                    'a' * 40)
            (stage / 'attempt-01/guest.qcow2').write_bytes(
                b'attempt-01/guest.qcow2')
            (stage / 'unexpected').write_bytes(b'x')
            with self.assertRaisesRegex(ValueError, 'file-set-changed'):
                coordinator.verify_full_staging_copy(root, 'suite-201',
                    'a' * 40)

    def test_pve_release_refuses_unsealed_attempt_before_remote_access(self):
        with tempfile.TemporaryDirectory(prefix='pr315-release-order-test-') as temp:
            root = Path(temp)
            root.chmod(0o700)
            remote = SimpleNamespace(call=unittest.mock.Mock())
            with self.assertRaisesRegex(ValueError, 'unsealed-attempt'):
                coordinator.release_completed_attempt(remote, root, root,
                    {'identity': {'helperSourceCommit': 'a' * 40}},
                    {'attemptId': 'suite-201', 'sourceCommit': 'a' * 40,
                     'status': 'completed'}, [])
            remote.call.assert_not_called()

    def test_stopped_guest_release_scan_has_separate_bounded_wait(self):
        calls = []

        def read(host, command, *, timeout):
            calls.append((host, command, timeout))
            if timeout < 1200:
                raise AssertionError('stopped guest scan lost its host-only bound')
            return SimpleNamespace(stdout=b'{"status":"checked"}')

        remote = SimpleNamespace(call=read)
        source_commit = 'a' * 40
        common = ['--suite', 'suite-201', '--source-commit', source_commit]
        for script in ('pr315_pve_attempt_inventory.py',
                       'pr315_pve_attempt_cleanup.py'):
            self.assertEqual({'status': 'checked'},
                coordinator._pve_release_audit(remote, source_commit,
                                               script, common))
        self.assertEqual([1200, 1200], [call[2] for call in calls])
        self.assertTrue(all(call[0] == coordinator.PVE for call in calls))
        self.assertEqual([
            'python3',
            '/root/pr315-workload/campaign-' + source_commit[:12] +
                '/pr315_pve_attempt_inventory.py', *common], calls[0][1])
        with self.assertRaisesRegex(ValueError, 'release-script-invalid'):
            coordinator._pve_release_audit(remote, source_commit,
                                           'arbitrary.py', common)
        self.assertEqual(2, len(calls))

    def test_pve_release_transfer_rejects_unpinned_destination(self):
        with tempfile.TemporaryDirectory(prefix='pr315-transfer-test-') as temp:
            source = Path(temp) / 'fixed.py'
            source.write_bytes(b'fixed-source')
            remote = SimpleNamespace(call=unittest.mock.Mock())
            with self.assertRaisesRegex(ValueError, 'file-selection-invalid'):
                coordinator._publish_pve_release_file(remote, source,
                    '/root/unrelated.py', mode=0o400)
            remote.call.assert_not_called()

    def test_full_disk_copy_requires_mac_budget_before_rsync(self):
        with tempfile.TemporaryDirectory(prefix='pr315-mac-capacity-test-') as temp:
            root = Path(temp)
            root.chmod(0o700)
            start = root / 'start.private.json'
            start.write_text(json.dumps({
                'macAvailableAtStartBytes': 225 * 1024**3}))
            start.chmod(0o600)
            suite = 'suite-201'
            remote = SimpleNamespace(call=unittest.mock.Mock(
                return_value=SimpleNamespace(stdout=(str(40 * 1024**3) +
                    ' /work/pr315-task/' + suite + '\n').encode())))
            with patch.object(coordinator.subprocess, 'run') as copied:
                with self.assertRaisesRegex(ValueError,
                                            'mac-capacity-unavailable'):
                    coordinator.stage_full_attempt(remote,
                        {'sourceCommit': 'a' * 40}, suite, root)
                copied.assert_not_called()

    def test_initialize_seals_private_start_without_remote_allocation(self):
        with tempfile.TemporaryDirectory(prefix='pr315-init-test-') as temp:
            root = Path(temp)
            root.chmod(0o700)
            source = root / 'source'
            source.mkdir(mode=0o700)
            (source / 'tracked.txt').write_text('source fixture\n')
            for command in (['init', '--quiet'], ['add', 'tracked.txt'],
                    ['-c', 'user.name=Fixture',
                     '-c', 'user.email=fixture@example.invalid',
                     'commit', '--quiet', '-m', 'fixture']):
                coordinator.subprocess.run(['git', *command], cwd=source,
                    check=True, capture_output=True)
            commit = coordinator.subprocess.run(['git', 'rev-parse', 'HEAD'],
                cwd=source, check=True, capture_output=True,
                text=True).stdout.strip()
            tree = coordinator.subprocess.run(['git', 'rev-parse',
                'HEAD^{tree}'], cwd=source, check=True,
                capture_output=True, text=True).stdout.strip()
            fixture = root / 'fixture.private.json'
            fixture.write_text(json.dumps({'sourceCommit': commit,
                'probeDigest': 'sha256:' + 'd' * 64}))
            fixture.chmod(0o600)
            pin = root / 'known-hosts.private'
            pin.write_bytes(b'fixture ssh-ed25519 AAAA\n')
            pin.chmod(0o600)
            identity = {key: (commit if key.endswith(('Commit', 'Tree'))
                              else 'a' * 64)
                        for key in coordinator.seal.acceptance.IDENTITY_FIELDS}
            identity.update(helperSourceTree=tree,
                fixtureManifestDigest=hashlib.sha256(
                    fixture.read_bytes()).hexdigest(),
                preparedImageDigest='b' * 64,
                productSelectionDigest='a' * 64)
            task = coordinator.CT_TASK
            config = {'sourceCommit': commit, 'sourceTree': tree,
                'trackedByteDigest': coordinator.owner.tracked_byte_digest(source),
                'productSelectionDigest': 'a' * 64,
                'fixtureManifestDigest': identity['fixtureManifestDigest'],
                'preparedImageDigest': 'b' * 64,
                'productSourceCommit': 'f' * 40,
                'sourceSnapshot': task + '/campaign-frozen/source-' + commit[:12],
                'campaignPlanPath': task + '/campaign-frozen/plan.private.json',
                'fixturePath': task + '/fixture', 'qemuRoot': task + '/qemu',
                'preparedImage': task + '/prepared', 'seed': task + '/seed',
                'sshKey': task + '/key', 'knownHosts': task + '/pin',
                'port': 23113, 'localFixtureManifest': str(fixture),
                'probeDigest': 'd' * 64}
            destination = root / 'campaign'
            with patch.object(coordinator.os, 'statvfs', return_value=
                    SimpleNamespace(f_bavail=225 * 1024**3, f_frsize=1)), \
                    patch.object(coordinator, 'Remote') as remote:
                plan = coordinator.initialize_campaign(destination, source,
                    config, identity, pin, 201)
                remote.assert_not_called()
            start = coordinator.owner._json(destination, 'start.private.json')
            sealed = coordinator.owner._json(destination,
                'start-seal.private.json')
            self.assertEqual(start,
                coordinator.seal.verify_start(destination, plan, sealed))
            self.assertEqual(201, start['firstSuiteNumber'])
            self.assertEqual([], list((destination / 'attempts').iterdir()))


class CoordinatorTransportFailureTest(unittest.TestCase):
    """Offline transport faults retain stop gates and produce real signed failures."""

    def setUp(self):
        from test_pr315_campaign_seal import fixture_plan
        temporary = tempfile.TemporaryDirectory(prefix='pr315-transport-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.plan, fingerprint = fixture_plan(self.root)
        self.config = {'sourceCommit': 'a' * 40,
                       'hostKeyFingerprint': fingerprint}
        self.source = Path('/source')
        self.staging = self.root / 'attempts' / 'suite-201'
        for path in (self.staging.parent, self.staging,
                     self.staging / 'attempt-01'):
            path.mkdir(mode=0o700)
        self.report = {'guestStopped': True, 'helperSourceCommit': 'a' * 40}
        self.report_path = self.staging / 'attempt-01/attempt.private.json'
        coordinator._exclusive_json(self.report_path, self.report)
        manifest = {'files': {
            'host-stop.private.json': {'sha256': 'e' * 64},
            'host-receipts/host-monitor-finished.private.json': {'sha256': 'f' * 64}}}
        coordinator._exclusive_json(
            self.staging / 'full-stage-manifest.private.json', manifest)
        self.stage_digest = coordinator.seal._digest(manifest)
        self.outcome_path = self.root / 'suite-201-ct-outcome.private.json'
        self.verdict = {'installedWorkloadAcceptanceSatisfied': False}
        self.remote = SimpleNamespace(call=unittest.mock.Mock())
        self.enterContext(patch.object(coordinator, 'frozen_campaign_context',
            return_value=(self.root, self.source, self.plan,
                          {'firstSuiteNumber': 201}, self.config)))
        self.enterContext(patch.object(coordinator, 'Remote', return_value=self.remote))
        self.enterContext(patch.object(coordinator, 'source_preflight'))
        self.enterContext(patch.object(coordinator, 'publish_frozen_campaign'))
        self.enterContext(patch.object(coordinator.owner, 'recovered_campaign_verdict',
                                      return_value=self.verdict))
        self.admission = self.enterContext(patch.object(coordinator, 'prelaunch_admission',
            return_value=({}, {'admitted': True})))
        self.enterContext(patch.object(coordinator, 'runner_arguments', return_value=['fixed']))
        self.finished = self.enterContext(patch.object(coordinator, 'finished_watcher',
            return_value={'action': 'completed'}))
        self.stage = self.enterContext(patch.object(coordinator, 'stage_full_attempt',
            return_value=(self.staging, self.stage_digest)))

    def history(self):
        return coordinator.seal.load_verified_history(self.root, self.plan,
            pinned_source_commit=self.config['sourceCommit'],
            pinned_fingerprint=self.config['hostKeyFingerprint'])

    def run_transport_failure(self, error):
        self.remote.call.side_effect = [SimpleNamespace(returncode=0), error]
        return coordinator.run_campaign(self.root, self.source, case_group='positive')

    def assert_sealed_transport_failure(self, error):
        self.assertEqual(self.verdict, self.run_transport_failure(error))
        self.finished.assert_called_once()
        self.stage.assert_called_once_with(self.remote, self.config, 'suite-201',
                                          self.root, pressure_action=None)
        raw = coordinator.owner._read(self.root, self.outcome_path.name, 98304)
        outcome = json.loads(raw)
        self.assertEqual('pr315-fixed-ct-runner-unobserved-outcome', outcome['kind'])
        self.assertEqual('suite-201', outcome['suite'])
        self.assertEqual('positive', outcome['groupId'])
        self.assertEqual(self.config['sourceCommit'], outcome['sourceCommit'])
        self.assertEqual(type(error).__name__, outcome['reason'])
        self.assertIsNone(outcome['exitCode'])
        self.assertNotIn(b'private-command', raw)
        self.assertNotIn(b'partial-private-output', raw)
        failure = coordinator.owner._json(self.root, 'suite-201-host-failure.private.json')
        self.assertEqual(type(error).__name__, failure['reason'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), failure['ctOutcomeDigest'])
        receipt, = self.history()
        self.assertEqual('failed', receipt['status'])
        self.assertIsNone(receipt['probeStarted'])
        self.assertEqual({}, receipt['caseDigests'])
        self.assertEqual('e' * 64, receipt['stopDigest'])
        self.assertEqual('f' * 64, receipt['monitorDigest'])
        self.assertEqual(self.stage_digest, receipt['archiveDigest'])
        self.assertEqual(coordinator.seal._digest({
            'fullStageDigest': self.stage_digest,
            'assessmentDigest': coordinator.seal._digest(failure)}), receipt['evidenceDigest'])
        self.assertEqual('failed', coordinator.next_campaign_selection(self.history())['status'])
        # A later invocation observes the terminal failure instead of reusing the suite.
        self.remote.call.reset_mock(side_effect=True)
        self.assertEqual(self.verdict,
            coordinator.run_campaign(self.root, self.source, case_group='positive'))
        self.remote.call.assert_not_called()
        self.admission.assert_called_once()

    def test_timeout_without_runner_outcome_seals_a_terminal_failure(self):
        self.assert_sealed_transport_failure(subprocess.TimeoutExpired(
            ['ssh', 'private-command'], 4500, output=b'partial-private-output'))

    def test_os_error_without_runner_outcome_seals_a_terminal_failure(self):
        self.assert_sealed_transport_failure(OSError('private-command unavailable'))

    def test_unverified_watcher_leaves_failure_unsealed(self):
        self.finished.side_effect = ValueError('pr315-pve-watcher-incomplete')
        with self.assertRaisesRegex(ValueError, 'watcher-incomplete'):
            self.run_transport_failure(OSError('private-command unavailable'))
        self.stage.assert_not_called()
        self.assertFalse(self.outcome_path.exists())
        self.assertEqual([], self.history())

    def test_stop_archive_failure_leaves_failure_unsealed(self):
        self.stage.side_effect = ValueError('pr315-full-stage-stop-invalid')
        with self.assertRaisesRegex(ValueError, 'full-stage-stop-invalid'):
            self.run_transport_failure(OSError('private-command unavailable'))
        self.assertFalse(self.outcome_path.exists())
        self.assertEqual([], self.history())

    def test_unstopped_guest_record_cannot_seal_transport_failure(self):
        self.report_path.write_bytes(coordinator.seal._canonical(
            dict(self.report, guestStopped=False)))
        with self.assertRaisesRegex(ValueError, 'failed-attempt-host-premise-invalid'):
            self.run_transport_failure(OSError('private-command unavailable'))
        self.assertEqual([], self.history())

    def test_unsafe_outcome_is_not_replaced_with_missing_outcome_record(self):
        target = self.root / 'other.private.json'
        coordinator._exclusive_json(target, {'private': 'retained'})
        self.outcome_path.symlink_to(target)
        with self.assertRaises(OSError):
            self.run_transport_failure(OSError('private-command unavailable'))
        self.assertTrue(self.outcome_path.is_symlink())
        self.assertEqual([], self.history())


if __name__ == '__main__':
    unittest.main()
