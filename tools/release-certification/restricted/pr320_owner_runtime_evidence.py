"""Original process-owned cancellation verification; local consistency is not protected authority."""
from __future__ import annotations
import json
import re

import pr318_storage_runtime_evidence as privacy
import pr320_cancellation_contract as contract
from cryptad_certification import composed_budget_evidence as owner
from cryptad_certification import runtime_pressure_evidence as pressure

MAX_PRIVATE_BYTES = 4 * 1024 * 1024
PRIVATE_FILE = 'pr320-owner-budget.private.json'
CHECKPOINT_FILE = 'pr320-owner-checkpoints.private.jsonl'
ROOT_NATIVE_FILE = 'pr320-owner-root-native.private.json'
REASONS = {'native-owner-active-premise-unobserved', 'process-owner-cancel-unobserved',
    'delayed-owner-tail-not-observed', 'retained-slot-not-denied', 'normal-owner-ack-unobserved',
    'owner-recovery-failed', 'owner-operation-identities-unavailable'}


def _need(condition, code):
    if not condition:
        raise ValueError('pr320-owner-original-' + code)


def decode_private(raw):
    _need(isinstance(raw, bytes) and 1 <= len(raw) <= MAX_PRIVATE_BYTES, 'size-invalid')
    value = json.loads(raw, object_pairs_hook=privacy._unique,
        parse_constant=lambda _v: (_ for _ in ()).throw(ValueError('pr320-owner-value-invalid')))
    _need(isinstance(value, dict) and set(value) == {'schemaVersion', 'kind', 'selectionDigest',
        'contexts', 'attempt', 'originalStimulus', 'composedBudgetEvidence', 'composedBudgetCoverage'}
        and value['schemaVersion'] == 1 and value['kind'] == 'pr320-private-owner-cancellation'
        and re.fullmatch(r'sha256:[0-9a-f]{64}', str(value['selectionDigest'])) is not None,
        'shape-invalid')
    context_fields = {'appId', 'role', 'roleEpochDigest', 'daemonEpochDigest',
        'workerEpochDigest', 'originDigest', 'sessionDigest', 'sessionExpiryDigest'}
    _need(isinstance(value['contexts'], dict) and set(value['contexts']) == set(contract.PERMISSIONS),
          'context-invalid')
    for app, context in value['contexts'].items():
        _need(isinstance(context, dict) and set(context) == context_fields
              and context['appId'] == app and context['role'] == 'candidate-sender'
              and all(re.fullmatch(r'sha256:[0-9a-f]{64}', str(context[key])) is not None
                      for key in context_fields - {'appId', 'role'}), 'context-invalid')
    attempt = value['attempt']
    _need(attempt == {'status': 'observed'} or isinstance(attempt, dict)
          and set(attempt) == {'status', 'reason'} and attempt['status'] == 'not-observed'
          and attempt['reason'] in REASONS, 'attempt-invalid')
    attachment = value['composedBudgetEvidence']
    _need(isinstance(attachment, dict) and attachment.get('schemaVersion') == 4
          and attachment.get('segments') == [] and attachment.get('storageCases') == []
          and isinstance(attachment.get('causalCases'), list) and len(attachment['causalCases']) <= 1
          and all(row.get('caseId') == 'cancellation' for row in attachment['causalCases']),
          'attachment-invalid')
    privacy._private_tree(value)
    derived = owner.derive(attachment, workload_digest=attachment['workloadDigest'],
        product_digest=attachment['productDigest'], source_commit=attachment['sourceCommit'],
        app_cohort_digest=attachment['appCohortDigest'], node_epoch=attachment['nodeEpoch'],
        collector_digest=attachment['collectorDigest'], configuration_digest=attachment['configurationDigest'])
    _need(derived == value['composedBudgetCoverage']
          and (attempt['status'] == 'observed') == ('cancellation' in derived['observedCases']),
          'coverage-substituted')
    return value


def decode_checkpoints(raw):
    _need(isinstance(raw, bytes) and 1 <= len(raw) <= MAX_PRIVATE_BYTES, 'checkpoint-size-invalid')
    lines = raw.splitlines()
    _need(1 <= len(lines) <= 16, 'checkpoint-limit')
    result = []
    for line in lines:
        row = json.loads(line, object_pairs_hook=privacy._unique)
        _need(isinstance(row, dict), 'checkpoint-invalid')
        fields = {'before': {'phase', 'native'}, 'active': {'phase', 'native'},
            'during': {'phase', 'native'}, 'after': {'phase', 'native'}, 'final': {'phase', 'native'},
            'owner-start': {'phase', 'receipt'}, 'owner-stop': {'phase', 'httpStatus'},
            'owner-death': {'phase', 'receipt'}, 'attempt-completed': {'phase', 'attempt'},
            'interrupted': {'phase', 'status'}}.get(row.get('phase'))
        _need(fields is not None and set(row) == fields, 'checkpoint-invalid')
        privacy._private_tree(row)
        result.append(row)
    return result


def decode_root_native(raw):
    _need(isinstance(raw, bytes) and 1 <= len(raw) <= MAX_PRIVATE_BYTES, 'native-size-invalid')
    value = json.loads(raw, object_pairs_hook=privacy._unique,
        parse_constant=lambda _v: (_ for _ in ()).throw(ValueError('pr320-owner-native-invalid')))
    _need(isinstance(value, dict) and set(value) == {'schemaVersion', 'kind', 'selectionDigest', 'before', 'after'}
          and value['schemaVersion'] == 1 and value['kind'] == 'pr320-original-owner-native', 'native-shape-invalid')
    for phase in ('before', 'after'):
        state = value[phase]
        _need(isinstance(state, dict) and set(state) == {'native', 'store'}
              and isinstance(state['native'], dict) and isinstance(state['native'].get('work'), dict)
              and isinstance(state['native'].get('budget'), dict)
              and isinstance(state['store'], dict) and set(state['store']) == {'durableUsage', 'graphFacts', 'captureSource', 'capturedMonotonicNs'}
              and state['store']['captureSource'] == 'administrator-fixed-file-store-readback'
              and type(state['store']['capturedMonotonicNs']) is int and state['store']['capturedMonotonicNs'] > 0
              and isinstance(state['store']['durableUsage'], list) and isinstance(state['store']['graphFacts'], list),
              'native-state-invalid')
    privacy._private_tree(value)
    return value


def validate_originals(private, selected, diagnostics, terminal, checkpoints, native_original):
    plan, authorization = selected['plan'], selected['authorization']
    _need(contract.verify_selection_contract(**selected), 'selection-invalid')
    _need(private['selectionDigest'] == authorization['selectionDigest']
          == diagnostics.get('ownerSelectionDigest'), 'selection-substituted')
    from pr316_mail_runtime_runner import _terminal_cleanup_verified
    _need(_terminal_cleanup_verified(terminal)
          and diagnostics.get('ownerOriginalCollection') == 'complete', 'cleanup-incomplete')
    record = terminal['controllerRecords']['candidate-sender']['record']
    bootstrap = diagnostics.get('ownerBootstrapContext')
    _need(isinstance(bootstrap, dict) and bootstrap.get('apps') == private['contexts']
          and all(bootstrap.get(key) == record.get(key) for key in
                  ('generation', 'managerInvocation', 'bootId', 'handle')), 'bootstrap-substituted')
    originals = diagnostics.get('ownerStimulusReceipts')
    _need(isinstance(originals, list) and 2 <= len(originals) <= 3
          and originals[0].get('status') == 'task-intent'
          and originals[1].get('status') == 'request-written'
          and private['originalStimulus'] == originals[1], 'stimulus-substituted')
    fields = {'schemaVersion', 'kind', 'selectionDigest', 'appId', 'generation',
              'managerInvocation', 'bootId', 'handle', 'daemon', 'worker', 'taskDigest',
              'status', 'observedMonotonicNs'}
    for receipt in originals:
        _need(isinstance(receipt, dict) and set(receipt) == fields and receipt['schemaVersion'] == 1
              and receipt['kind'] == 'pr320-original-process-owner' and receipt['appId'] == 'feed-reader'
              and type(receipt['observedMonotonicNs']) is int and receipt['observedMonotonicNs'] > 0
              and re.fullmatch(r'sha256:[0-9a-f]{64}', str(receipt['taskDigest'])) is not None
              and receipt['selectionDigest'] == authorization['selectionDigest']
              and all(receipt.get(key) == record.get(key) for key in
                      ('generation', 'managerInvocation', 'bootId', 'handle'))
              and all(receipt[key] == originals[0][key] for key in
                      fields - {'status', 'observedMonotonicNs'}), 'receipt-substituted')
    _need(all(a['observedMonotonicNs'] < b['observedMonotonicNs'] for a, b in zip(originals, originals[1:])),
          'receipt-order-invalid')
    _need(contract.canonical_digest(originals[1]['worker']) == private['contexts']['feed-reader']['workerEpochDigest']
          and contract.canonical_digest(originals[1]['daemon']) == private['contexts']['feed-reader']['daemonEpochDigest'],
          'worker-substituted')
    attachment = private['composedBudgetEvidence']
    node = next(n for n in plan['nodes'] if n['role'] == 'candidate-sender')
    epoch = record.get('roleEpochDigest')
    _need(re.fullmatch(r'sha256:[0-9a-f]{64}', str(epoch)) is not None
          and {context['roleEpochDigest'] for context in private['contexts'].values()} == {epoch},
          'role-epoch-substituted')
    derived = owner.derive(attachment, workload_digest=plan['workloadInputs']['scheduler'],
        product_digest=node['artifactDigest'], source_commit=node['sourceCommit'],
        app_cohort_digest=pressure.baseline.digest(node['appDigests']), node_epoch=epoch[7:39],
        collector_digest=plan['composedBudgetInputs']['collectorDigest'],
        configuration_digest=plan['composedBudgetInputs']['configurationDigest'])
    _need(derived == private['composedBudgetCoverage'], 'coverage-substituted')
    _need(native_original['selectionDigest'] == private['selectionDigest'], 'native-selection-substituted')
    if 'cancellation' in derived['observedCases']:
        _need(len(originals) == 3 and originals[-1]['status'] == 'worker-death-observed',
              'process-death-missing')
        by_phase = {row['phase']: row for row in checkpoints}
        _need(len(by_phase) == len(checkpoints) and 'interrupted' not in by_phase
              and all(phase in by_phase for phase in ('before', 'active', 'owner-start',
                  'owner-stop', 'owner-death', 'during', 'after', 'final', 'attempt-completed'))
              and by_phase['owner-start']['receipt'] == originals[1]
              and by_phase['owner-death']['receipt'] == originals[2]
              and by_phase['owner-stop']['httpStatus'] == 200, 'checkpoint-substituted')
        from cross_version_installed_budgets import _evidence_snapshot, _events
        row = attachment['causalCases'][0]
        rooted = native_original['after']['native']
        _need(rooted['work']['collectorEpoch'] == row['collectorEpoch']
              and native_original['before']['native']['work']['collectorEpoch'] == row['collectorEpoch']
              and native_original['before']['native']['work']['lastSequence'] == row['sequenceStart'] - 1
              and _events(rooted, row['sequenceStart'] - 1) == row['events'], 'root-native-substituted')
        for phase in ('before', 'during', 'after'):
            raw = by_phase[phase]['native']
            _need(raw['work']['collectorEpoch'] == row['collectorEpoch']
                  and _evidence_snapshot(raw) == row['snapshots'][phase], 'native-source-substituted')
        for phase in ('before', 'after'):
            state = native_original[phase]
            raw = {**state['native'], 'retainedStatements': len(state['store']['graphFacts'])}
            _need(_evidence_snapshot(raw) == row['snapshots'][phase], 'root-state-substituted')
        fetch = next(operation['operationId'] for operation in row['operations'] if operation['role'] == 'primary-fetch')
        _need({(event['operation'], event['scope']) for event in row['events']
              if event['operationId'] == fetch and event['kind'] == 'RATE_CHARGED'} == {
                  ('foreground_content_fetch', row['scope']), ('content_fetch_global', 1)}
              and not any(event['kind'] in {'GRAPH_STORE_ATTEMPT', 'RATE_CHARGED'}
                          and event['operationId'] == row['operationId'] for event in row['events']),
              'primary-charge-substituted')
        _need(_events(by_phase['after']['native'], row['sequenceStart'] - 1) == row['events'],
              'native-event-substituted')
    return derived


def public_projection(private, *, source_identity_digest, originals_verified,
                      privacy_verified, watcher_finished, guest_stopped):
    _need(all((originals_verified, privacy_verified, watcher_finished, guest_stopped)), 'export-incomplete')
    observed = private['composedBudgetCoverage']['observedCases']
    return {'schemaVersion': 1, 'kind': 'pr320-owner-cancellation-assessment',
        'status': 'observed' if observed == ['cancellation'] else 'incomplete',
        'observedCases': observed, 'reasons': [] if observed else [private['attempt']['reason']],
        'evidenceClass': 'installed-process-owner',
        'originalAuthentication': 'administrator-matched-not-protected-authority',
        'fullAppBudgets': 'not-observed', 'releaseEligible': False, 'phaseComplete': False}


def failed_projection(reason):
    return {'schemaVersion': 1, 'kind': 'pr320-owner-cancellation-assessment', 'status': 'failed',
        'observedCases': [], 'reasons': ['prerequisites-present-not-executed' if
            reason == 'prerequisites-present-not-executed' else 'setup-or-execution-failed'],
        'evidenceClass': 'installed-process-owner',
        'originalAuthentication': 'not-established', 'fullAppBudgets': 'not-observed',
        'releaseEligible': False, 'phaseComplete': False}
