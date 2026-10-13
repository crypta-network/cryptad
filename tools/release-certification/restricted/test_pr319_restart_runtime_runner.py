"""Prospective clocks, operation admission and legacy dispatch retain installed boundaries."""
import copy
import hashlib
import json
import tempfile
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pr319_restart_runtime_runner as runner
import pr319_installed_dispatch as dispatch
import pr319_restart_selection as selection
import restricted_workload_prepare as preparation
import test_pr317_budget_selection as legacy_fixture
import cross_version_installed_restart_budgets as collector


class RuntimeBoundaryTests(unittest.TestCase):
    def test_invalid_diagnostic_interval_is_inside_same_selected_hour(self):
        phase = {'diagnostics': {'observedAt': '2026-10-13T19:10:00Z'}}
        row = {'caseId': 'diagnostics-unavailable', **{k: copy.deepcopy(phase)
               for k in ('before', 'during', 'after', 'recovery')}}
        value = {'restartCases': [], 'diagnosticsCases': [row]}
        authorization = {'budgetSelection': {'timePlan': {'boundaryEpochSecond': 1791921600}}}
        runner._selected_time_plan(value, authorization)
        row['during']['diagnostics']['observedAt'] = '2026-10-13T18:59:59Z'
        with self.assertRaisesRegex(ValueError, 'selected-hour-missed'):
            runner._selected_time_plan(value, authorization)

    def test_host_clock_bracket_includes_actual_invalid_sample(self):
        second = 1791918000
        def clock(offset):
            ns = (second + offset) * 10**9
            return {'hostEpochBeforeNanos': ns, 'hostEpochAfterNanos': ns + 1000000,
                'guestEpochNanos': ns, 'hostMonotonicBeforeNanos': (offset + 1) * 10**9,
                'hostMonotonicAfterNanos': (offset + 1) * 10**9 + 1000000}
        phase = {'diagnostics': {'observedAt': '2026-10-13T19:00:10Z'}}
        row = {'caseId': 'diagnostics-unavailable', **{k: copy.deepcopy(phase)
               for k in ('before', 'during', 'after', 'recovery')}}
        attachment = {'restartCases': [], 'diagnosticsCases': [row]}
        report = {'storageClock': {'before': clock(0), 'after': clock(60)}}
        runner._clock_binding(report, attachment, {})
        row['during']['diagnostics']['observedAt'] = '2026-10-13T19:02:00Z'
        with self.assertRaisesRegex(ValueError, 'observation-clock-substituted'):
            runner._clock_binding(report, attachment, {})

    def test_historical_startup_measurement_never_runs_new_lane(self):
        called = []
        driver = SimpleNamespace(controller_ready=lambda x: called.append(x),
            readiness_deadline=lambda *a: 123, STARTUP_MEASUREMENT_SECONDS=45)
        result = dispatch.observer_sequence(driver, None, None, None, 0, 0, True)
        self.assertEqual([123], called)
        self.assertFalse(result['installedPositiveExecuted'])
        self.assertEqual('startup-measurement-not-workload-acceptance', result['classification'])


def selected(max_operations):
    with patch.object(legacy_fixture, 'selection', selection):
        plan, private, authorization = legacy_fixture.closed_selection()
    budget = authorization['budgetSelection']
    tools = budget['toolIdentities']
    plan['composedBudgetInputs']['collectorDigest'] = selection.canonical_digest({key: tools[key] for key in
        ('installedDriver', 'localBudgetAdapter', 'schedulerRuntime', 'evidenceOracle',
         'restartOracle', 'administrator', 'roleClients', 'runtimeEvidence',
         'storageAdapter', 'storageOracle', 'transitionDispatch', 'hostRunner')})
    budget['composedBudgetInputs'] = dict(plan['composedBudgetInputs'])
    budget['timePlan'] = {'boundaryEpochSecond': 36000, 'selectedAtEpochSecond': 35500,
                          'startMarginSeconds': 10, 'requestDeadlineMillis': 45000}
    budget['statementFingerprint'] = 'c' * 64
    authorization['maxOperations'] = max_operations
    authorization['planDigest'] = selection.canonical_digest(plan)
    authorization['selectionDigest'] = selection.canonical_digest({
        'executionClass': authorization['executionClass'], 'planDigest': authorization['planDigest'],
        'budgetSelection': budget})
    return plan, private, authorization


def manifest(max_operations):
    contract = selection.contract
    return {'schemaVersion': 1, 'kind': selection.KIND, 'executionClass': selection.EXECUTION_CLASS,
        'classification': selection.CLASSIFICATION,
        'runtimePolicy': {'launcher': preparation.launcher_policy(),
                          'budget': preparation.budget_launcher_policy(selection.EXECUTION_CLASS)},
        'sourceCommit': 'a' * 40, 'products': {}, 'roles': list(selection.ROLES),
        'runtimeDigest': 'sha256:' + 'd' * 64, 'jdkClosureDigest': 'sha256:' + 'd' * 64,
        'apps': {}, 'trustDigest': 'sha256:' + 'd' * 64, 'statementDigest': 'sha256:' + 'd' * 64,
        'statementFingerprint': 'c' * 64, 'verifierDigest': 'sha256:' + 'd' * 64,
        'toolIdentities': {}, 'permissions': {key: list(value) for key, value in contract.PERMISSIONS.items()},
        'caseIds': list(contract.CASES), 'environment': dict(contract.ENVIRONMENT),
        'normalizedConfiguration': copy.deepcopy(contract.NORMALIZED_CONFIGURATION),
        'failurePolicy': dict(contract.FAILURE_POLICY), 'maxSeconds': 600,
        'maxOperations': max_operations, 'members': [],
        'timePlan': {'boundaryEpochSecond': 36000, 'selectedAtEpochSecond': 35500,
                     'startMarginSeconds': 10, 'requestDeadlineMillis': 45000}}


class OperationAdmissionTests(unittest.TestCase):
    def test_protected_admission_rejects_insufficient_missing_or_malformed_allowance(self):
        for limit in (None, True, '1000', 1, selection.contract.MIN_OPERATIONS - 1, 10001):
            plan, private, authorization = selected(limit)
            with self.subTest(limit=limit):
                self.assertFalse(selection.verify_selection_contract(plan, private, authorization))
                self.assertFalse(preparation.valid_execution_selection(plan, private, authorization))

    def test_protected_admission_accepts_complete_selection_at_floor_and_existing_ceiling(self):
        for limit in (selection.contract.MIN_OPERATIONS, 1000, 10000):
            plan, private, authorization = selected(limit)
            with self.subTest(limit=limit):
                self.assertTrue(selection.verify_selection_contract(plan, private, authorization))
                self.assertTrue(preparation.valid_execution_selection(plan, private, authorization))

    def test_insufficient_authorization_prevents_any_installed_role_start(self):
        plan, private, authorization = selected(1)
        adapter = SimpleNamespace(plan=plan, private=private, authorization=authorization, start=Mock())
        with self.assertRaisesRegex(collector.runtime.RuntimeFailure, 'restart-selection-invalid'):
            collector.run_restart_lane(adapter, Mock())
        adapter.start.assert_not_called()

    def test_preparation_rejects_insufficient_allowance_before_source_checks_or_file_creation(self):
        for limit in (1, selection.contract.MIN_OPERATIONS - 1):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / 'prepared'
                args = SimpleNamespace(max_seconds=600, max_operations=limit,
                    candidate_commit='a' * 40, previous_commit='b' * 40,
                    source=Path('/unused'), output=output)
                with patch.object(selection.subprocess, 'check_output') as source_check, \
                        self.assertRaisesRegex(ValueError, 'fixture-selection-invalid'):
                    selection.prepare(args)
                source_check.assert_not_called()
                self.assertFalse(output.exists())

    def test_preparation_accepts_floor_then_enforces_the_independent_source_gate(self):
        args = SimpleNamespace(max_seconds=600, max_operations=selection.contract.MIN_OPERATIONS,
            candidate_commit='a' * 40, previous_commit='b' * 40, source=Path('/unused'))
        with patch.object(selection.subprocess, 'check_output', return_value=b'dirty') as source_check, \
                self.assertRaisesRegex(ValueError, 'clean-helper-source-required'):
            selection.prepare(args)
        source_check.assert_called_once()

    def test_retained_manifest_rejects_insufficient_allowance_before_product_verification(self):
        raw = json.dumps(manifest(1)).encode()
        digest = hashlib.sha256(raw).hexdigest()
        with patch.object(selection.base, 'digest', return_value=digest), \
                patch('runtime_snapshot.read_file', return_value=raw), \
                patch.object(selection.base, 'inventory', return_value=[]), \
                patch.object(selection.base, 'validate_roster') as products, \
                self.assertRaisesRegex(ValueError, 'fixture-manifest-invalid'):
            selection.verify(Path('/unused'), digest, Path('/unused-source'), 'a' * 40)
        products.assert_not_called()

    def test_retained_manifest_accepts_floor_then_enforces_the_independent_product_gate(self):
        raw = json.dumps(manifest(selection.contract.MIN_OPERATIONS)).encode()
        digest = hashlib.sha256(raw).hexdigest()
        with patch.object(selection.base, 'digest', return_value=digest), \
                patch('runtime_snapshot.read_file', return_value=raw), \
                patch.object(selection.base, 'inventory', return_value=[]), \
                patch.object(selection.base, 'validate_roster', side_effect=ValueError('product-gate')) as products, \
                self.assertRaisesRegex(ValueError, 'product-gate'):
            selection.verify(Path('/unused'), digest, Path('/unused-source'), 'a' * 40)
        products.assert_called_once()


if __name__ == '__main__':
    unittest.main()
