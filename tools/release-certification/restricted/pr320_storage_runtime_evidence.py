"""Verify one retained storage direction against its original selected role and root receipts."""
from __future__ import annotations

import json
import re

import pr318_storage_runtime_evidence as legacy
import pr318_storage_runtime_runner as original
import pr320_storage_contract as contract
from cryptad_certification import composed_budget_storage_evidence as storage

MAX_PRIVATE_BYTES = legacy.MAX_PRIVATE_BYTES
PRIVATE_FILE = 'pr320-storage-budget.private.json'
CHECKPOINT_FILE = 'pr320-storage-attempts.private.jsonl'


def _need(condition, code):
    if not condition:
        raise ValueError('pr320-storage-original-' + code)


def decode_private(raw):
    _need(isinstance(raw, bytes) and 1 <= len(raw) <= MAX_PRIVATE_BYTES, 'size-invalid')
    value = json.loads(raw, object_pairs_hook=legacy._unique,
                      parse_constant=lambda _v: (_ for _ in ()).throw(ValueError('pr320-storage-value-invalid')))
    _need(isinstance(value, dict) and set(value) == {'schemaVersion', 'kind',
        'selectionDigest', 'executionClass', 'contexts', 'attempts', 'storageComponent',
        'storageCoverage'} and value['schemaVersion'] == 1
        and value['kind'] == 'pr320-private-storage-budget', 'shape-invalid')
    selected = contract.selected_profile(value['executionClass'])
    _need(re.fullmatch(r'sha256:[0-9a-f]{64}', str(value['selectionDigest'])) is not None
          and isinstance(value['contexts'], dict) and set(value['contexts']) == set(contract.APP_IDS)
          and isinstance(value['attempts'], list) and len(value['attempts']) == 1
          and isinstance(value['attempts'][0], dict)
          and value['attempts'][0].get('caseId') == selected['caseId'], 'selection-invalid')
    legacy._private_tree(value)
    context_fields = {'appId', 'role', 'roleEpochDigest', 'daemonEpochDigest',
        'workerEpochDigest', 'originDigest', 'sessionDigest', 'sessionExpiryDigest'}
    for app, context in value['contexts'].items():
        _need(isinstance(context, dict) and set(context) == context_fields
              and context['appId'] == app and context['role'] == 'candidate-sender'
              and all(re.fullmatch(r'sha256:[0-9a-f]{64}', str(context[key])) is not None
                      for key in context_fields - {'appId', 'role'}), 'context-invalid')
    component = value['storageComponent']
    derived = storage.derive_complete_storage(component)
    rows = component['storageCases']
    _need(len(rows) <= 1 and all((row['caseId'], row['variant']) ==
          (selected['caseId'], selected['variant']) for row in rows), 'variant-substituted')
    _need(derived == value['storageCoverage'], 'coverage-substituted')
    _need(value['attempts'][0].get('status') == ('executed' if rows else 'not-observed'),
          'attempt-substituted')
    return value


decode_checkpoints = legacy.decode_checkpoints


def validate_originals(private, selected, diagnostics, terminal, report):
    """Revalidate native details and match root originals, never accept summary-only credit."""
    plan, inputs, authorization = selected['plan'], selected['private'], selected['authorization']
    _need(contract.verify_selection_contract(plan, inputs, authorization), 'selection-invalid')
    profile = contract.selected_profile(authorization['executionClass'])
    _need(private['executionClass'] == profile['executionClass']
          and private['selectionDigest'] == authorization['selectionDigest'], 'selection-substituted')
    from pr316_mail_runtime_runner import _terminal_cleanup_verified
    _need(_terminal_cleanup_verified(terminal), 'cleanup-incomplete')
    rows = private['storageComponent']['storageCases']
    expected_epoch = original._expected_node_epoch(private, terminal)
    generation = terminal['controllerRecords']['candidate-sender']['record'].get('generation')
    record = terminal['controllerRecords']['candidate-sender']['record']
    bootstrap = diagnostics.get('storageBootstrapContext')
    _need(isinstance(bootstrap, dict) and bootstrap.get('apps') == private['contexts']
          and all(bootstrap.get(key) == record.get(key) for key in
                  ('generation', 'managerInvocation', 'bootId', 'handle'))
          and diagnostics.get('storageAccessCleanup') == 'completed'
          and diagnostics.get('storageSelectionDigest') == authorization['selectionDigest'],
          'bootstrap-substituted')
    _need(all(row['nodeEpoch'] == expected_epoch and row['roleGeneration'] == generation
              for row in rows), 'role-substituted')
    wrapper = {'storageCases': rows}
    original._selected_time_plan(wrapper, authorization)
    original._selected_statement(wrapper, authorization)
    original._clock_binding(report, wrapper, authorization)
    if profile['caseId'] != 'window-crossing' and rows:
        original._original_admin_receipts({'composedBudgetEvidence': wrapper}, diagnostics,
                                          terminal, authorization['selectionDigest'])
    # Immutable checkpoints must be verified by the host reader too; row coverage alone
    # cannot establish that interrupted or failed setup evidence was retained.
    return storage.derive_complete_storage(private['storageComponent'])


def public_projection(private, *, source_identity_digest, originals_verified,
                      privacy_verified, watcher_finished, guest_stopped):
    _need(all((originals_verified, privacy_verified, watcher_finished, guest_stopped)),
          'export-prerequisite-incomplete')
    _need(re.fullmatch(r'sha256:[0-9a-f]{64}', str(source_identity_digest)) is not None,
          'source-identity-invalid')
    selected = contract.selected_profile(private['executionClass'])
    derived = storage.derive_complete_storage(private['storageComponent'])
    present = {'caseId': selected['caseId'], 'variant': selected['variant']} in derived['verifiedVariants']
    return {'schemaVersion': 1, 'kind': 'pr320-storage-direction-assessment',
        'caseId': selected['caseId'], 'variant': selected['variant'],
        'status': 'observed' if present else 'incomplete', 'reasons': [],
        'evidenceClass': storage.INSTALLED, 'fullAppBudgets': 'not-observed',
        'originalAuthentication': 'administrator-matched-not-protected-authority',
        'releaseEligible': False, 'phaseComplete': False}


def failed_projection(profile, reason):
    # Candidate failure logs remain private. Public failures use closed classifications.
    allowed = {'prerequisites-present-not-executed', 'setup-or-execution-failed',
               'export-prerequisite-incomplete', 'private-evidence-invalid'}
    return {'schemaVersion': 1, 'kind': 'pr320-storage-direction-assessment',
        'caseId': profile['caseId'], 'variant': profile['variant'], 'status': 'failed',
        'reasons': [reason if reason in allowed else 'setup-or-execution-failed'],
        'evidenceClass': storage.INSTALLED,
        'fullAppBudgets': 'not-observed', 'originalAuthentication': 'not-established',
        'releaseEligible': False, 'phaseComplete': False}
