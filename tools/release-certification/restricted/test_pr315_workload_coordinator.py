"""Closed campaign selection and preparation accounting without allocating VMs."""
import unittest

import pr315_workload_coordinator as coordinator


class CoordinatorSelectionTest(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
