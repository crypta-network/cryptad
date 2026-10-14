"""Actual Java observations through owning journal and scoped Phase 12 consumers.

The journal scaffold is deliberately synthetic. Native observations are read unchanged
from executed Java producers; neither this scaffold nor local consistency authenticates
an installed campaign or a protected product.
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptad_certification import composed_budget_evidence as owner
from cryptad_certification import composed_budget_restart_evidence as restart
from cryptad_certification import phase_12_runtime_adapters as runtime
from cryptad_certification.cross_version_evidence import digest
from cryptad_certification.tests.test_cross_version_evidence import (
    fixture_plan, fixture_events, checkpoint_for, rechain,
)

ROOT = Path(__file__).resolve().parents[4]
EXPECTED = Path(__file__).parent / 'fixtures/pr319-restart-integration-expected.json'


class NativeRestartIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = json.loads(EXPECTED.read_bytes())
        directory = ROOT / 'platform-api/build/test-results/pr319-native'
        variants = cls.expected['nativeVariants']
        if not any((directory / (name + '.json')).is_file() for name in variants):
            raise unittest.SkipTest('actual Java PR319 producers have not executed')
        # Once any producer exists, missing siblings fail rather than silently skipping.
        cls.rows = [json.loads((directory / (name + '.json')).read_bytes()) for name in variants]
        cls.originals = {name: json.loads((directory / (name + '-original.json')).read_bytes())
                         for name in variants}

    def journal(self):
        plan = fixture_plan()
        plan['workloadInputs'] = {'scheduler': 'sha256:' + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        plan['composedBudgetInputs'] = {
            'collectorDigest': 'sha256:' + hashlib.sha256((ROOT / 'tools/release-certification/cryptad_certification/composed_budget_restart_evidence.py').read_bytes()).hexdigest(),
            'configurationDigest': digest({'purpose': 'synthetic-local-native-consumer-scaffold'})}
        events, _ = fixture_events(plan)
        latest = max(dt.datetime.fromisoformat(row[phase]['diagnostics']['observedAt'])
                     for row in self.rows for phase in ('before', 'during', 'after', 'recovery')
                     if phase in row)
        start = dt.datetime.fromisoformat(events[0]['wallTime'])
        offset = latest + dt.timedelta(seconds=1) - start
        for event in events:
            event['wallTime'] = (dt.datetime.fromisoformat(event['wallTime']) + offset).isoformat()
        event = next(e for e in events if e['kind'] == 'operation'
                     and e['scenario'] == 'app-budgets' and e['role'] == 'candidate-sender')
        node = next(n for n in plan['nodes'] if n['role'] == event['role'])
        attachment = {'schemaVersion': 5, 'workloadDigest': plan['workloadInputs']['scheduler'],
            'productDigest': node['artifactDigest'], 'sourceCommit': node['sourceCommit'],
            'appCohortDigest': digest(node['appDigests']), **plan['composedBudgetInputs'],
            'collectorEpoch': self.rows[-1]['recovery']['collectorEpoch'],
            'nodeEpoch': event['nodeEpoch'], 'segments': [], 'causalCases': [], 'storageCases': [],
            'restartCases': copy.deepcopy(self.rows[:3]), 'diagnosticsCases': copy.deepcopy(self.rows[3:])}
        event.update(outcome='partial', composedBudgetEvidence=attachment)
        rechain(events)
        return plan, events, checkpoint_for(plan, events)

    def measurement(self, plan, events, checkpoint):
        payloads = {name: json.dumps(value).encode() for name, value in (
            ('plan.json', plan), ('events.json', events), ('checkpoint.json', checkpoint),
            ('products.json', []))}
        cutoff = dt.datetime.fromisoformat(events[-1]['wallTime']) + dt.timedelta(seconds=1)
        with tempfile.TemporaryDirectory() as temporary:
            return runtime.verify('maintenance-measurements', payloads, cutoff.isoformat(),
                                  Path(temporary).resolve())

    def test_actual_nine_producer_variants_match_originals_and_fixed_oracle(self):
        for row in self.rows:
            with self.subTest(variant=row['variant']):
                result = restart.derive_controlled(row, originals=self.originals[row['variant']])
                self.assertTrue(result['observed'])
                self.assertTrue(result['originalWitnessMatched'])
                self.assertFalse(result['installedObservation'])
        self.assertEqual(self.expected['inflightTailStatus'],
                         restart.derive_controlled(self.rows[2])['tailStatus'])

    def test_native_trace_owner_journal_and_scoped_phase12_measurement(self):
        plan, events, checkpoint = self.journal()
        coverage = owner.derive_journal(plan, events)
        self.assertEqual(self.expected['observedCases'], coverage['observedCases'])
        self.assertEqual(self.expected['requiredCaseCount'], len(coverage['requiredCases']))
        self.assertEqual(self.expected['requiredCases'], coverage['requiredCases'])
        self.assertEqual(self.expected['missingCaseCount'], len(coverage['missingCases']))
        attachment = next(e['composedBudgetEvidence'] for e in events if 'composedBudgetEvidence' in e)
        self.assertEqual(self.expected['unobservedMandatoryVariants'],
                         restart.derive_variants(attachment)['unobservedVariants'])
        result = self.measurement(plan, events, checkpoint)
        self.assertEqual(coverage, result['measurements']['composedBudgetCoverage'])
        self.assertEqual(self.expected['measurementClaims'], result['claims'])
        self.assertEqual(self.expected['authenticatedObservedSeconds'],
                         result['measurements']['authenticatedObservedSeconds'])
        for name in ('fullAppBudgets', 'originalAuthentication', 'releaseEligible'):
            self.assertEqual(self.expected[name], coverage[name])
        self.assertIn('privacy', coverage['missingCases'])
        self.assertEqual('not-observed', result['dimensions']['runtimeExecution'])
        self.assertIn('composed-budget-original-operations-required', result['blockers'])

    def test_missing_actual_mandatory_variant_keeps_abrupt_case_open(self):
        plan, events, _ = self.journal()
        event = next(e for e in events if 'composedBudgetEvidence' in e)
        event['composedBudgetEvidence']['restartCases'].pop()
        rechain(events)
        result = self.measurement(plan, events, checkpoint_for(plan, events))
        self.assertNotIn('abrupt-restart', result['measurements']['composedBudgetCoverage']['observedCases'])

    def test_changed_native_retained_record_rejects_at_existing_phase12_boundary(self):
        plan, events, _ = self.journal()
        event = next(e for e in events if 'composedBudgetEvidence' in e)
        event['composedBudgetEvidence']['restartCases'][0]['after']['diagnostics']['usage'][0]['count'] += 1
        rechain(events)
        with self.assertRaisesRegex(ValueError, '^phase12-runtime-owner-verification-rejected$'):
            self.measurement(plan, events, checkpoint_for(plan, events))


if __name__ == '__main__':
    unittest.main()
