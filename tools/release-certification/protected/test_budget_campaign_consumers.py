"""Downstream budget authority stays separate from original measurement owners.

The campaign fixture runs all budget owner validators; its upstream original observation
capability and filesystem boundaries are synthetic. No live original execution is claimed.
"""
from __future__ import annotations

import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import composed_budget_campaign_admission as admission
import maintenance_runtime_projection as maintenance
import test_composed_budget_campaign_admission as original_vectors
from cryptad_certification.engines import network_scale_soak_impl as network
from cryptad_certification.tests.test_cross_version_evidence import checkpoint_for, fixture_events, rechain


def measurements(plan):
    """Derive actual historical maintenance rows using explicit synthetic products."""
    events, checkpoint = fixture_events(plan)
    products = []
    for node in plan['nodes']:
        binding = {field: 'sha256:' + str(index + 1) * 64
                   for index, field in enumerate(maintenance.BINDING_DIGESTS)}
        binding['provenance'] = 'frozen-with-original-release'
        products.append({**{key: node[key] for key in
            ('role', 'sourceCommit', 'artifactDigest', 'artifactSize', 'packageTarget', 'contractVersion')},
            'maintenanceFreezeDigest': 'sha256:' + 'a' * 64,
            'freezeCompletedAt': '2025-12-31T00:00:00Z',
            'frozenPortableBinding': 'existing-maintenance-freeze-exact-product-v1',
            'runtimeBinding': binding,
            'appMatrix': [{'bundleDigest': digest, 'contractVerifier': 'executed',
                          'nativeAdmission': 'accepted',
                          'contractSnapshotDigest': binding['contractSnapshotDigest']}
                         for digest in node['appDigests']]})
    return maintenance.project(plan, events, checkpoint, products,
        now=dt.datetime(2026, 1, 1, 0, 10, tzinfo=dt.timezone.utc))


class BudgetCampaignConsumersTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.originals = original_vectors.full_originals()
        helper = original_vectors.OriginalCampaignAdmissionTest()
        helper.fixture = cls.originals
        cls.capability = helper.call()
        cls.plan = copy.deepcopy(cls.originals[1][0]['bundle']['plan'])
        source_originals = original_vectors.full_originals(provenance='source-build-comparison')
        helper.fixture = source_originals
        cls.source_capability = helper.call()
        cls.source_plan = copy.deepcopy(source_originals[1][0]['bundle']['plan'])

    def test_maintenance_wraps_exact_historical_rows_and_preserves_independent_blockers(self):
        historical = measurements(self.plan)
        before = json.dumps(historical, sort_keys=True)
        wrapped = maintenance.with_original_budget_campaign(historical, self.capability, plan=self.plan)
        self.assertEqual(before, json.dumps(wrapped['historicalMeasurements'], sort_keys=True))
        self.assertEqual(before, json.dumps(historical, sort_keys=True))
        self.assertEqual('observed', wrapped['budgetCampaignCoverage']['fullAppBudgets'])
        self.assertEqual('blocked', wrapped['maintenanceEligibility'])
        self.assertEqual(historical['observedEligibleSeconds'], wrapped['historicalMeasurements']['observedEligibleSeconds'])
        self.assertEqual(historical['rows'], wrapped['historicalMeasurements']['rows'])
        self.assertTrue(all(row['status'] == 'blocked' for row in wrapped['historicalMeasurements']['rows']))
        performance = next(row for row in historical['rows'] if row['id'] == maintenance.PREFIX + 'performance')
        self.assertIn('reviewed-runtime-baseline-missing', performance['blockers'])
        self.assertIn('scheduler-pressure-adapter-missing', performance['blockers'])
        self.assertTrue(any('routine-full-window-not-observed' in row['blockers'] for row in historical['rows']))
        self.assertIs(wrapped, maintenance.validate(wrapped))

    def test_maintenance_rejects_copied_json_foreign_provenance_and_measurement_plan(self):
        historical = measurements(self.plan)
        with self.assertRaises(ValueError):
            maintenance.with_original_budget_campaign(historical, self.capability.coverage(), plan=self.plan)
        for fault in ('source', 'workload', 'provenance', 'measurement'):
            plan, value = copy.deepcopy(self.plan), copy.deepcopy(historical)
            if fault == 'source':plan['nodes'][0]['sourceCommit'] = 'f' * 40
            elif fault == 'workload':plan['workloadInputs']['scheduler'] = 'sha256:' + 'f' * 64
            elif fault == 'provenance':plan['provenanceClass'] = 'source-build-comparison'
            else:value['planDigest'] = 'sha256:' + 'f' * 64
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                maintenance.with_original_budget_campaign(value, self.capability, plan=plan)
        forged = copy.deepcopy(maintenance.with_original_budget_campaign(historical, self.capability, plan=self.plan))
        forged['maintenanceEligibility'] = 'eligible'
        with self.assertRaises(ValueError):maintenance.validate(forged)

    def test_subclass_overrides_cannot_substitute_for_the_owners_exact_sealed_capability(self):
        real = self.capability
        class Counterfeit(admission.OriginalBudgetCampaign):
            def __init__(self):pass
            def bind(self, plan):pass
            def coverage(self):return real.coverage()
        counterfeit = Counterfeit()
        events, checkpoint = fixture_events(self.plan)
        with self.assertRaisesRegex(ValueError, 'maintenance-budget-campaign-original-required'):
            maintenance.project(self.plan, events, checkpoint, [], budget_campaign=counterfeit)
        with self.assertRaisesRegex(ValueError, 'network-scale-budget-original-capability-required'):
            network.with_authenticated_budget_campaign(copy.deepcopy(network.SUMMARY), counterfeit, plan=self.plan)

    def test_network_wraps_exact_simulated_soak_without_creating_live_duration_or_release_credit(self):
        historical = copy.deepcopy(network.SUMMARY)
        before = json.dumps(historical, sort_keys=True)
        wrapped = network.with_authenticated_budget_campaign(historical, self.capability, plan=self.plan)
        self.assertEqual(before, json.dumps(wrapped['networkScale'], sort_keys=True))
        self.assertEqual(before, json.dumps(historical, sort_keys=True))
        self.assertEqual('simulated-rc-soak', wrapped['networkScale']['mode'])
        self.assertEqual(24, wrapped['networkScale']['durationHoursSimulated'])
        self.assertFalse(wrapped['budgetCampaignCoverage']['phaseComplete'])
        self.assertFalse(wrapped['budgetCampaignCoverage']['releaseEligible'])
        self.assertEqual([], network.validate(wrapped, budget_campaign=self.capability, plan=self.plan))
        self.assertEqual(['network-scale-budget-original-capability-required'], network.validate(wrapped))
        with self.assertRaises(ValueError):
            network.with_authenticated_budget_campaign(historical, self.capability.coverage(), plan=self.plan)

    def test_network_rejects_foreign_plan_copied_original_credit_and_invalid_base_measurements(self):
        wrapped = network.with_authenticated_budget_campaign(copy.deepcopy(network.SUMMARY), self.capability, plan=self.plan)
        for fault in ('source', 'cohort', 'workload', 'provenance'):
            plan = copy.deepcopy(self.plan)
            if fault == 'source':plan['nodes'][0]['sourceCommit'] = 'f' * 40
            elif fault == 'cohort':plan['nodes'][0]['appDigests'] = ['sha256:' + 'f' * 64]
            elif fault == 'workload':plan['workloadInputs']['scheduler'] = 'sha256:' + 'f' * 64
            else:plan['provenanceClass'] = 'source-build-comparison'
            with self.subTest(fault=fault):
                self.assertTrue(network.validate(wrapped, budget_campaign=self.capability, plan=plan))
        copied = copy.deepcopy(wrapped)
        copied['budgetCampaignCoverage']['evidenceClass'] = 'original-protected-source-built-budget-cohort'
        self.assertEqual(['network-scale-budget-original-substituted'],
            network.validate(copied, budget_campaign=self.capability, plan=self.plan))
        for plan in (None, {}, {'nodes': []}):
            self.assertTrue(network.validate(wrapped, budget_campaign=self.capability, plan=plan))
            with self.assertRaisesRegex(ValueError, 'network-scale-budget-original-plan-'):
                network.with_authenticated_budget_campaign(copy.deepcopy(network.SUMMARY), self.capability, plan=plan)
        invalid = copy.deepcopy(network.SUMMARY)
        invalid['durationHoursSimulated'] = 1
        with self.assertRaises(ValueError):
            network.with_authenticated_budget_campaign(invalid, self.capability, plan=self.plan)

    def test_source_built_original_budget_credit_keeps_production_runtime_and_baseline_obligations(self):
        historical = measurements(self.source_plan)
        wrapped = maintenance.with_original_budget_campaign(historical, self.source_capability, plan=self.source_plan)
        self.assertEqual(historical, wrapped['historicalMeasurements'])
        self.assertEqual('original-protected-source-built-budget-cohort', wrapped['budgetCampaignCoverage']['evidenceClass'])
        self.assertEqual('authenticated', wrapped['budgetCampaignCoverage']['originalAuthentication'])
        self.assertEqual('observed', wrapped['budgetCampaignCoverage']['fullAppBudgets'])
        self.assertFalse(wrapped['budgetCampaignCoverage']['phaseComplete'])
        self.assertFalse(wrapped['budgetCampaignCoverage']['releaseEligible'])
        self.assertEqual('blocked', wrapped['maintenanceEligibility'])
        self.assertIn('original-production-products-required', historical['subjectAdmission']['blockers'])
        self.assertTrue(all('original-production-products-required' in row['blockers'] for row in historical['rows']))
        performance = next(row for row in historical['rows'] if row['id'] == maintenance.PREFIX + 'performance')
        self.assertIn('reviewed-runtime-baseline-missing', performance['blockers'])
        self.assertIn('scheduler-pressure-adapter-missing', performance['blockers'])
        network_value = network.with_authenticated_budget_campaign(copy.deepcopy(network.SUMMARY),
            self.source_capability, plan=self.source_plan)
        self.assertEqual(network.SUMMARY, network_value['networkScale'])
        self.assertEqual('original-protected-source-built-budget-cohort', network_value['budgetCampaignCoverage']['evidenceClass'])
        self.assertEqual([], network.validate(network_value, budget_campaign=self.source_capability, plan=self.source_plan))
        with self.assertRaises(ValueError):
            maintenance.with_original_budget_campaign(historical, self.source_capability, plan=self.plan)
        with self.assertRaises(ValueError):
            network.with_authenticated_budget_campaign(copy.deepcopy(network.SUMMARY), self.source_capability, plan=self.plan)

    def test_original_maintenance_authentication_adds_budget_only_after_preserving_the_supervisor_base(self):
        from cryptad_certification.cross_version_evidence import digest
        plan = copy.deepcopy(self.source_plan)
        events, _ = fixture_events(plan)
        now = dt.datetime(2026, 10, 14, 6, tzinfo=dt.timezone.utc)
        offset = dt.datetime(2026, 10, 14, 2, tzinfo=dt.timezone.utc) - dt.datetime.fromisoformat(events[0]['wallTime'])
        for event in events:
            event['wallTime'] = (dt.datetime.fromisoformat(event['wallTime']) + offset).isoformat()
        rechain(events)
        checkpoint = checkpoint_for(plan, events)
        historical = maintenance.project(plan, events, checkpoint, [], now=now)
        coordinates = {'runId': 1, 'runAttempt': 1, 'artifactId': 2}
        report = {'schemaVersion': 8, 'budgetCampaignBaseVersion': historical['schemaVersion'] + 1,
                  'budgetCampaignReceipt': {'schemaVersion': 1, 'kind': 'pr320-original-budget-member-receipt', 'receiptId': 'a' * 32},
                  'operation': 'finish', 'maintenanceMeasurements': historical, 'planDigest': digest(plan),
                  'producer': plan['producer'], 'checkpoint': {'digest': digest(checkpoint)}}
        before = json.dumps(report, sort_keys=True)
        with tempfile.TemporaryDirectory() as temporary, \
             patch('cross_version_supervisor_authority.authenticate_report', return_value=(report, coordinates)):
            authority = maintenance.authenticate(coordinates, Path(temporary), expected_plan_digest=digest(plan),
                expected_policy_digest=historical['policyByteDigest'], now=now,
                budget_campaign=self.source_capability, budget_plan=plan)
            self.assertEqual(historical, authority.measurements()['historicalMeasurements'])
            self.assertEqual('observed', authority.measurements()['budgetCampaignCoverage']['fullAppBudgets'])
            self.assertEqual('blocked', authority.measurements()['maintenanceEligibility'])
            self.assertEqual(coordinates, authority.original_coordinates())
            with self.assertRaises(ValueError):
                maintenance.authenticate(coordinates, Path(temporary), expected_plan_digest=digest(plan),
                    expected_policy_digest=historical['policyByteDigest'], now=now,
                    budget_campaign=self.source_capability.coverage(), budget_plan=plan)
        self.assertEqual(before, json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    unittest.main()
