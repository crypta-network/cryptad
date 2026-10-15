"""Versioned selection/export wrapper around unchanged historical v5 original readers."""
import pr319_restart_runtime_evidence as historical
import pr320_restart_contract as contract
from cryptad_certification import composed_budget_evidence as composed
from cryptad_certification import runtime_pressure_evidence as pressure

MAX_PRIVATE_BYTES = historical.MAX_PRIVATE_BYTES
PRIVATE_FILE = 'pr319-restart-budget.private.json'
CHECKPOINT_FILE = 'pr319-restart-attempts.private.jsonl'
decode_private = historical.decode_private
decode_checkpoints = historical.decode_checkpoints
PUBLIC_KIND = 'pr320-restart-budget-assessment'


def validate_originals(private, selected, diagnostics, terminal, report, checkpoints):
    """Verify the prospective selection before reusing the exact v5 original readers."""
    import pr319_restart_runtime_runner as original
    if not contract.verify_selection_contract(**selected):
        raise ValueError('pr320-restart-original-selection-invalid')
    if not original.shared._terminal_cleanup_verified(terminal):
        raise ValueError('pr320-restart-original-cleanup-incomplete')
    authorization, plan = selected['authorization'], selected['plan']
    historical.validate_originals(private, diagnostics, terminal, authorization['selectionDigest'])
    attachment = private['composedBudgetEvidence']
    original._selected_time_plan(attachment, authorization)
    original._selected_statement(attachment, authorization)
    original._clock_binding(report, attachment, authorization)
    node_epoch = original._expected_node_epoch(private, terminal)
    node = next(row for row in plan['nodes'] if row['role'] == 'candidate-sender')
    expected_apps = [authorization['budgetSelection']['appBundleDigests'][app] for app in contract.APP_IDS]
    if node['appDigests'] != expected_apps:
        raise ValueError('pr320-restart-original-cohort-substituted')
    recomputed = composed.derive(attachment, workload_digest=plan['workloadInputs']['scheduler'],
        product_digest=node['artifactDigest'], source_commit=node['sourceCommit'],
        app_cohort_digest=pressure.baseline.digest(expected_apps), node_epoch=node_epoch,
        collector_digest=plan['composedBudgetInputs']['collectorDigest'],
        configuration_digest=plan['composedBudgetInputs']['configurationDigest'])
    if recomputed != private['composedBudgetCoverage']:
        raise ValueError('pr320-restart-original-coverage-substituted')
    # Checkpoints retain every private phase, but never grant independent case credit.
    if any(row['phase'] == 'interrupted' for row in checkpoints):
        raise ValueError('pr320-restart-original-checkpoint-substituted')
    samples = {(row['caseId'], row['variant'], row['phase']): row['sample']
               for row in checkpoints if 'sample' in row}
    for row in attachment['restartCases'] + attachment['diagnosticsCases']:
        phases = ('before', 'during', 'after', 'recovery') if row['caseId'] == 'diagnostics-unavailable' else ('before', 'after', 'recovery')
        if any(samples.get((row['caseId'], row['variant'], phase)) != row[phase] for phase in phases):
            raise ValueError('pr320-restart-original-checkpoint-substituted')
    if [row['receipt'] for row in checkpoints if row['phase'] == 'terminal'] != [
            row for row in private['originalReceipts'] if row.get('phase') == 'terminal']:
        raise ValueError('pr320-restart-original-checkpoint-substituted')
    return recomputed


def _version(value):
    # The historical aggregate also commits private fixture/image identities.
    # Keep that original binding private in the prospective public assessment.
    value = {key: child for key, child in value.items() if key != 'sourceIdentityDigest'}
    return {**value, 'kind': PUBLIC_KIND, 'executionClass': contract.EXECUTION_CLASS}


def failed_projection(reason):
    if reason == 'prerequisites-present-not-executed':
        reason = 'setup-or-execution-failed'
    return _version(historical.failed_projection(reason))


def public_projection(private, **kwargs):
    return _version(historical.public_projection(private, **kwargs))
