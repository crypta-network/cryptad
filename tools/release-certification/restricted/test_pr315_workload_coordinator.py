"""Closed campaign selection and preparation accounting without allocating VMs."""
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
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

    def test_fresh_margin_and_capacity_occur_after_history_before_formal_admission(self):
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
                patch.object(coordinator, '_exclusive_json',
                             side_effect=lambda *args: record('persist')), \
                patch.object(coordinator, 'admit_and_watch',
                             side_effect=lambda *args: record('formal',
                                 {'admitted': False})):
            result = coordinator.prelaunch_admission(object(),
                Path('/private/campaign'), config, 'suite-201',
                {'macAvailableAtStartBytes': 1000})
        self.assertEqual(({'free': 200}, {'admitted': False}), result)
        self.assertEqual(['inventory', 'margin', 'inventory', 'required',
                          'capacity', 'persist', 'formal'], ordered)

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


if __name__ == '__main__':
    unittest.main()
