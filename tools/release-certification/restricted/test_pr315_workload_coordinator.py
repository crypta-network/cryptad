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

    def test_unknown_or_post_probe_failure_cannot_be_retried(self):
        history = [{'groupId': 'positive', 'status': 'failed'}]
        self.assertEqual('failed',
            coordinator.next_campaign_selection(history)['status'])
        history[0]['status'] = 'unknown'
        self.assertEqual('failed',
            coordinator.next_campaign_selection(history)['status'])

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


if __name__ == '__main__':
    unittest.main()
