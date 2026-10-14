"""Prospective restart selection has its own cohort and delegates unchanged lifecycle semantics."""
import copy
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import pr319_restart_contract as historical
import pr320_restart_contract as contract
import pr320_restart_runtime_runner as runner
import pr320_restart_runtime_evidence as evidence
import cross_version_installed_pr320_restart_budgets as driver
import pr320_installed_dispatch as dispatch
import pr315_workload_guest as guest
import restricted_workload_prepare as prepare
from test_pr320_owner_installed import owner_selection
from test_pr318_storage_installed import resign
from test_pr319_restart_runtime_evidence import bound_vector
from cryptad_certification import composed_budget_evidence as composed
from cryptad_certification import composed_budget_restart_evidence as restart
from cryptad_certification import runtime_pressure_evidence as pressure


def original_vector():
    selection = selected()
    private, diagnostics, terminal, _ = bound_vector()
    row = private['composedBudgetEvidence']['restartCases'][0]
    plan, authorization = selection['plan'], selection['authorization']
    stamp = int(restart._time(row['before']['diagnostics']['observedAt']))
    boundary = (stamp // 3600 + 1) * 3600
    authorization['budgetSelection']['timePlan'] = {'boundaryEpochSecond': boundary,
        'selectedAtEpochSecond': boundary - 300, 'startMarginSeconds': 10, 'requestDeadlineMillis': 45000}
    authorization['budgetSelection']['statementFingerprint'] = row['selectedFingerprint']
    resign(plan, authorization)
    old_digest = private['selectionDigest']
    def bind(value):
        if isinstance(value, dict): return {key: bind(item) for key, item in value.items()}
        if isinstance(value, list): return [bind(item) for item in value]
        return authorization['selectionDigest'] if value == old_digest else value
    private, diagnostics, terminal = bind(private), bind(diagnostics), bind(terminal)
    epoch = private['contexts']['feed-reader']['roleEpochDigest']
    terminal['controllerRecords']['candidate-sender']['record']['roleEpochDigest'] = epoch
    node = plan['nodes'][0]
    attachment = private['composedBudgetEvidence']
    attachment.update(collectorEpoch=row['recovery']['collectorEpoch'], nodeEpoch=epoch[7:39],
        workloadDigest=plan['workloadInputs']['scheduler'], productDigest=node['artifactDigest'],
        sourceCommit=node['sourceCommit'], appCohortDigest=pressure.baseline.digest(node['appDigests']),
        **plan['composedBudgetInputs'], segments=[], causalCases=[], storageCases=[])
    private['composedBudgetCoverage'] = composed.derive(attachment, workload_digest=attachment['workloadDigest'],
        product_digest=attachment['productDigest'], source_commit=attachment['sourceCommit'],
        app_cohort_digest=attachment['appCohortDigest'], node_epoch=attachment['nodeEpoch'],
        collector_digest=attachment['collectorDigest'], configuration_digest=attachment['configurationDigest'])
    checkpoints = [{'caseId': row['caseId'], 'variant': row['variant'], 'phase': phase, 'sample': row[phase]}
        for phase in ('before', 'after', 'recovery')]
    checkpoints.append({'caseId': row['caseId'], 'variant': row['variant'], 'phase': 'terminal',
        'receipt': next(receipt for receipt in private['originalReceipts'] if receipt['phase'] == 'terminal')})
    def clock(second, monotonic):
        return {'hostEpochBeforeNanos': second * 10**9, 'hostEpochAfterNanos': second * 10**9 + 1000000,
            'guestEpochNanos': second * 10**9, 'hostMonotonicBeforeNanos': monotonic * 10**9,
            'hostMonotonicAfterNanos': monotonic * 10**9 + 1000000}
    report = {'storageClock': {'before': clock(stamp - 60, 1), 'after': clock(stamp + 60, 121)}}
    return private, selection, diagnostics, terminal, report, checkpoints


def selected():
    result = owner_selection()
    plan, private, authorization = result['plan'], result['private'], result['authorization']
    plan['experimentId'] = contract.EXPERIMENT
    private['root'] = '/var/lib/cryptad-cross-version/experiments/' + contract.EXPERIMENT
    authorization.update(executionClass=contract.EXECUTION_CLASS, experimentId=contract.EXPERIMENT, root=private['root'])
    budget = authorization['budgetSelection']
    tools = {name: 'sha256:' + 'd' * 64 for name in contract.TOOL_PATHS}
    budget.update(caseIds=list(contract.CASES), toolIdentities=tools, privateRootClass='controller-derived-' + contract.EXPERIMENT)
    plan['composedBudgetInputs']['collectorDigest'] = contract.canonical_digest({key: tools[key] for key in contract.COLLECTOR_TOOLS})
    budget['composedBudgetInputs'] = dict(plan['composedBudgetInputs'])
    from cryptad_certification.composed_budget_journal_member import campaign_inputs
    plan['budgetCampaignInputs'] = campaign_inputs(plan, tools)
    resign(plan, authorization)
    return result


class RestartSuccessorTest(unittest.TestCase):
    def test_original_consumer_accepts_native_v5_and_rejects_prospective_source_substitution(self):
        args = original_vector()
        with patch('pr316_mail_runtime_runner._terminal_cleanup_verified', return_value=True):
            self.assertEqual(['graceful-restart'], evidence.validate_originals(*args)['observedCases'])
        changed = copy.deepcopy(args)
        changed[1]['authorization']['budgetSelection']['statementFingerprint'] = 'f' * 64
        resign(changed[1]['plan'], changed[1]['authorization'])
        with patch('pr316_mail_runtime_runner._terminal_cleanup_verified', return_value=True), self.assertRaises(ValueError):
            evidence.validate_originals(*changed)
    def test_new_fixed_profile_admits_same_cohort_without_reinterpreting_historical_selection(self):
        value = selected()
        self.assertTrue(contract.verify_selection_contract(**value))
        self.assertFalse(historical.verify_selection_contract(**value))
        self.assertTrue(prepare.valid_execution_selection(**value))
        self.assertEqual('budget-restart', dispatch.purpose(contract.EXECUTION_CLASS))
        self.assertEqual(4, len(dispatch.capture_members(contract.EXECUTION_CLASS)))
        guest._validate_mode(startup_measurement=False, lifecycle_scenario='none', workload_group=None,
            retired_authority_preparation=False, execution_class=contract.EXECUTION_CLASS)
        altered = copy.deepcopy(value)
        altered['authorization']['budgetSelection']['permissions'] = {key: list(entry) for key, entry in historical.PERMISSIONS.items()}
        resign(altered['plan'], altered['authorization'])
        self.assertFalse(contract.verify_selection_contract(**altered))

    def test_actual_driver_delegates_same_five_variant_lifecycle_with_new_exact_selection(self):
        with patch.object(driver.historical, 'run_restart_lane', return_value={'actual': 'return'}) as run:
            self.assertEqual({'actual': 'return'}, driver.run_observer('adapter', 'channel', 100, 'diagnostic'))
        self.assertEqual(contract.EXECUTION_CLASS, run.call_args.kwargs['execution_class'])
        self.assertTrue(run.call_args.kwargs['leave_running_for_administrator'])
        adapter = SimpleNamespace(plan={}, private={}, authorization={})
        with self.assertRaises(driver.historical.runtime.RuntimeFailure):
            driver.historical.run_restart_lane(adapter, None, execution_class='pr320-arbitrary-v1')

    def test_export_wrapper_preserves_v5_assessment_limits_and_keeps_closed_new_identity(self):
        projection = evidence.failed_projection('setup-or-execution-failed')
        self.assertEqual(contract.EXECUTION_CLASS, runner._closed_public(projection)['executionClass'])
        self.assertFalse(projection['ownerCancelledInstalledDirection'])
        self.assertEqual('not-observed', projection['fullAppBudgets'])
        altered = {**projection, 'executionClass': historical.EXECUTION_CLASS}
        with self.assertRaises(ValueError):
            runner._closed_public(altered)


if __name__ == '__main__':
    unittest.main()
