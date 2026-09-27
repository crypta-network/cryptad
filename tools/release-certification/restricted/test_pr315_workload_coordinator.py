"""Closed campaign selection and preparation accounting without allocating VMs."""
import unittest

import installation
import pr315_workload_coordinator as coordinator


class CoordinatorSelectionTest(unittest.TestCase):
    def test_mac_host_coordinator_is_test_kit_only(self):
        self.assertFalse(installation.production_member(
            'tools/release-certification/restricted/'
            'pr315_workload_coordinator.py'))

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


if __name__ == '__main__':
    unittest.main()
