"""Offline campaign ledger regressions; synthetic statuses are never acceptance."""
import copy
import unittest

import pr315_workload_campaign as campaign


def fixture_plan():
    identity = {key: ('a' * 40 if key.endswith(('Commit', 'Tree')) else 'a' * 64)
                for key in campaign.acceptance.IDENTITY_FIELDS}
    return campaign.plan(identity, 'b' * 64, 'pve-tcg-swap-admission-v1', 'c' * 64)


def attempt(group, number, status):
    return {'groupId': group, 'declaredCases': list(dict(campaign.GROUPS)[group]),
            'status': status, 'attemptId': f'{group}-{number}'}


class CampaignLedgerTest(unittest.TestCase):
    def test_complete_fixed_inventory_is_partitioned_into_21_groups(self):
        self.assertEqual(21, len(campaign.GROUPS))
        self.assertEqual(set(campaign.acceptance.CASES), set(campaign.CASE_TO_GROUP))
        self.assertEqual(45, sum(len(cases) for _, cases in campaign.GROUPS))

    def test_first_complete_attempt_selected_after_setup_failures_only(self):
        rows = [attempt('positive', 1, 'setup-failed'),
                attempt('positive', 2, 'setup-failed'),
                attempt('positive', 3, 'completed')]
        result = campaign.reduce_attempts(fixture_plan(), rows,
            lambda item: {case: 'passed' for case in item['declaredCases']})
        self.assertEqual({'positive': 'positive-3'}, result['selectedAttemptIds'])
        self.assertEqual(8, sum(row['status'] == 'passed' for row in result['cases']))
        self.assertFalse(result['allCasesStructurallyPassed'])
        self.assertFalse(result['installedWorkloadAcceptanceSatisfied'])

    def test_started_probe_cannot_be_retried_to_hide_failure(self):
        rows = [attempt('positive', 1, 'failed'), attempt('positive', 2, 'completed')]
        with self.assertRaisesRegex(ValueError, 'post-probe-retry'):
            campaign.reduce_attempts(fixture_plan(), rows, lambda _: {})
        rows = [attempt('positive', number, 'setup-failed') for number in range(1, 5)]
        with self.assertRaisesRegex(ValueError, 'retry-limit'):
            campaign.reduce_attempts(fixture_plan(), rows, lambda _: {})

    def test_duplicate_or_changed_plan_is_rejected(self):
        row = attempt('positive', 1, 'setup-failed')
        with self.assertRaisesRegex(ValueError, 'attempt-duplicate'):
            campaign.reduce_attempts(fixture_plan(), [row, row], lambda _: {})
        changed = copy.deepcopy(fixture_plan())
        changed['groups'][0]['cases'].pop()
        with self.assertRaisesRegex(ValueError, 'plan-changed'):
            campaign.reduce_attempts(changed, [], lambda _: {})

    def test_pretended_completion_requires_owner_case_validation(self):
        row = attempt('positive', 1, 'completed')
        with self.assertRaisesRegex(ValueError, 'unverified-cases'):
            campaign.reduce_attempts(fixture_plan(), [row], lambda _: {})


if __name__ == '__main__':
    unittest.main()
