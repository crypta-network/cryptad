"""Authenticate native route originals against selected root sessions and file-store readback."""
from __future__ import annotations
import hashlib
import json
import re

import pr318_storage_runtime_evidence as privacy
import pr320_route_contract as contract
from cryptad_certification import composed_budget_route_evidence as routes
from cryptad_certification import runtime_pressure_evidence as pressure

MAX_PRIVATE_BYTES = 4 * 1024 * 1024
PRIVATE_FILE, CHECKPOINT_FILE = contract.PRIVATE_FILE, contract.CHECKPOINT_FILE
ROOT_NATIVE_FILE = 'pr320-route-root-native.private.json'


def _need(condition, code):
    if not condition:
        raise ValueError('pr320-route-original-' + code)


def _decode(raw):
    _need(isinstance(raw, bytes) and 1 <= len(raw) <= MAX_PRIVATE_BYTES, 'size-invalid')
    value = json.loads(raw, object_pairs_hook=privacy._unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('pr320-route-original-number-invalid')))
    privacy._private_tree(value)
    return value


def decode_private(raw):
    value = _decode(raw)
    _need(isinstance(value, dict) and set(value) == {'schemaVersion', 'kind', 'executionClass',
        'selectionDigest', 'contexts', 'component', 'coverage'} and type(value['schemaVersion']) is int
        and value['schemaVersion'] == 1 and value['kind'] == 'pr320-private-route-budget', 'shape-invalid')
    selected = contract.selected_profile(value['executionClass'])
    _need(re.fullmatch('sha256:[0-9a-f]{64}', str(value['selectionDigest'])) is not None
          and isinstance(value['contexts'], dict) and set(value['contexts']) == set(contract.APP_IDS), 'context-invalid')
    fields = {'appId', 'role', 'roleEpochDigest', 'daemonEpochDigest', 'workerEpochDigest',
              'originDigest', 'sessionDigest', 'sessionExpiryDigest'}
    for app, context in value['contexts'].items():
        _need(isinstance(context, dict) and set(context) == fields and context['appId'] == app
              and context['role'] == 'candidate-sender'
              and all(re.fullmatch('sha256:[0-9a-f]{64}', str(context[key])) for key in
                      fields - {'appId', 'role'}), 'context-invalid')
    component = value['component']
    _need(component['profile'] == selected['name'] and component['evidenceClass'] == 'installed-controller-bound'
          and component['bindings']['selectionDigest'] == value['selectionDigest']
          and routes.derive_complete_routes(component) == value['coverage'], 'coverage-substituted')
    return value


def decode_checkpoints(raw):
    _need(isinstance(raw, bytes) and 1 <= len(raw) <= MAX_PRIVATE_BYTES, 'checkpoint-size-invalid')
    lines = raw.splitlines()
    _need(1 <= len(lines) <= 64, 'checkpoint-limit')
    result = []
    for line in lines:
        row = _decode(line)
        _need(isinstance(row, dict), 'checkpoint-invalid')
        fields = {'before-case': {'phase', 'caseId', 'variant', 'appId'},
            'after-case': {'phase', 'observation', 'original'},
            'before-causal': {'phase', 'profile'}, 'after-causal': {'phase', 'attempts', 'originals', 'native'},
            'native-collected': {'phase', 'component'}, 'interrupted': {'phase', 'status'}}.get(row.get('phase'))
        _need(fields is not None and set(row) == fields
              and (row['phase'] != 'interrupted' or row['status'] == 'unknown'), 'checkpoint-invalid')
        result.append(row)
    return result


def decode_root_native(raw):
    value = _decode(raw)
    _need(isinstance(value, dict) and value.get('work', {}).get('known') is True
          and value.get('budget', {}).get('valid') is True, 'root-native-invalid')
    routes._native_history(value['work'])
    return value


def validate_originals(private, selected, diagnostics, terminal, checkpoints, root_native_raw):
    """Match independent exact root bytes and scoped bootstrap, then recompute original native rows."""
    _need(contract.verify_selection_contract(**selected), 'selection-invalid')
    plan, authorization = selected['plan'], selected['authorization']
    profile = contract.selected_profile(authorization['executionClass'])
    from pr316_mail_runtime_runner import _terminal_cleanup_verified
    _need(_terminal_cleanup_verified(terminal)
          and diagnostics.get('routeBudgetCollectorCleanup') == 'completed'
          and private['selectionDigest'] == authorization['selectionDigest']
          == diagnostics.get('routeBudgetSelectionDigest')
          and private['executionClass'] == profile['executionClass'], 'selection-substituted')
    record = terminal['controllerRecords']['candidate-sender']['record']
    bootstrap = diagnostics.get('routeBudgetBootstrapContext')
    _need(isinstance(bootstrap, dict) and bootstrap.get('apps') == private['contexts']
          and all(bootstrap.get(key) == record.get(key) for key in
                  ('generation', 'managerInvocation', 'bootId', 'handle')), 'bootstrap-substituted')
    epoch = record.get('roleEpochDigest')
    _need(re.fullmatch('sha256:[0-9a-f]{64}', str(epoch)) is not None
          and {row['roleEpochDigest'] for row in private['contexts'].values()} == {epoch}, 'epoch-substituted')
    original = diagnostics.get('routeBudgetOriginalRecord')
    _need(isinstance(original, dict) and set(original) == {'durableUsage', 'graphFacts', 'captureSource',
          'capturedMonotonicNs', 'nativeDigest'} and original['captureSource'] == 'administrator-fixed-file-store-readback'
          and type(original['capturedMonotonicNs']) is int and original['capturedMonotonicNs'] > 0
          and original['nativeDigest'] == 'sha256:' + hashlib.sha256(root_native_raw).hexdigest(), 'readback-substituted')
    root_native = decode_root_native(root_native_raw)
    component = private['component']
    node = next(row for row in plan['nodes'] if row['role'] == 'candidate-sender')
    expected = {'workloadDigest': plan['workloadInputs']['scheduler'], 'productDigest': node['artifactDigest'],
        'sourceCommit': node['sourceCommit'], 'appCohortDigest': contract.canonical_digest(node['appDigests']),
        **plan['composedBudgetInputs'], 'nodeEpoch': epoch[7:39],
        'collectorEpoch': root_native['work']['collectorEpoch'], 'selectionDigest': authorization['selectionDigest'],
        'appBundleDigests': authorization['budgetSelection']['appBundleDigests']}
    derived = routes.derive_complete_routes(component, expected)
    _need(derived == private['coverage'], 'coverage-substituted')
    scope_rows, controls = bootstrap.get('routeScopeBindings'), bootstrap.get('routeScopeControls')
    _need(isinstance(scope_rows, list) and len(scope_rows) == 4
          and all(isinstance(row, dict) and set(row) == {'appId', 'scope'} and row['appId'] in contract.APP_IDS
                  and type(row['scope']) is int and row['scope'] >= 3 for row in scope_rows)
          and len({row['appId'] for row in scope_rows}) == len({row['scope'] for row in scope_rows}) == 4,
          'root-scope-invalid')
    scope_map = {str(row['scope']): row['appId'] for row in scope_rows}
    _need(all(scope_map.get(key) == app for key, app in component['scopeBindings'].items()), 'root-scope-substituted')
    _need(isinstance(controls, list) and len(controls) == 4, 'root-controls-invalid')
    final = component['finalSnapshot']
    root_events = routes._native_history(root_native['work'])
    _need(root_native['work']['collectorEpoch'] == final['work']['collectorEpoch']
          and all(root_events.get(row['sequence']) == row for row in final['work']['events'])
          and contract.canonical_digest(root_native.get('budgetConfiguration')) ==
              contract.canonical_digest(routes.native_configuration(profile['name']))
          and root_native.get('schedulerConfiguration', {}).get('enabled') is False, 'root-native-substituted')
    if derived['status'] == 'complete':
        _need(root_native['work']['lastSequence'] == final['work']['lastSequence']
              and all(root_native['budget'].get(key) == final['budget'].get(key) for key in
                      ('valid', 'activeFamilyLeases', 'reservedFamilyRates', 'rates')), 'final-budget-substituted')
    for app, control in zip(contract.APP_IDS, controls):
        _need(isinstance(control, dict) and set(control) == {'appId', 'status', 'beforeSequence',
            'afterSequence', 'collectorEpoch', 'events'} and control['appId'] == app
            and type(control['status']) is int and control['status'] == (400 if app in contract.APP_IDS[:2] else 403)
            and control['collectorEpoch'] == expected['collectorEpoch']
            and type(control['beforeSequence']) is int and type(control['afterSequence']) is int
            and control['events'] == [root_events[index] for index in
                range(control['beforeSequence'] + 1, control['afterSequence'] + 1)], 'root-control-substituted')
        events = control['events']
        _need([row['kind'] for row in events] == ['COMPOSED_URI_IMPORT_START'] +
              ([] if app in contract.APP_IDS[:2] else ['CAPABILITY_DENIED']) + ['REQUEST_FAILED']
              and all(scope_map.get(str(row['scope'])) == app for row in events)
              and len({row['operationId'] for row in events}) == 1, 'root-control-invalid')
    usage = original['durableUsage']
    _need(isinstance(usage, list) and len(usage) <= 32 and isinstance(original['graphFacts'], list)
          and len(original['graphFacts']) == final.get('retainedStatements'), 'root-store-invalid')
    mapped = {}
    for row in usage:
        _need(isinstance(row, dict) and set(row) == {'appId', 'operation', 'windowStart', 'windowSeconds',
            'count', 'lastDecisionAt', 'lastDecision', 'nextAvailableAt'} and type(row['count']) is int
            and row['count'] >= 0, 'root-rate-invalid')
        scopes = {'_cryptad_global': 1, '_cryptad_operator': 2,
                  **{name: int(key) for key, name in scope_map.items()}}
        _need(row['appId'] in scopes, 'root-rate-scope-invalid')
        window = int(pressure.baseline._time(row['windowStart']).timestamp())
        key = row['operation'], scopes[row['appId']], window
        _need(key not in mapped, 'root-rate-replayed')
        mapped[key] = row['count']
    rates = {(row['operation'], row['scope'], row['windowStartEpochSecond']): row['count']
             for row in root_native['budget']['rates']}
    _need(len(rates) == len(root_native['budget']['rates']) and rates == mapped, 'root-rate-substituted')
    for row in original['graphFacts']:
        _need(row.get('documentFingerprint') == authorization['budgetSelection']['statementFingerprint']
              and row.get('signatureVerified') is True, 'root-graph-substituted')
    finals = [row for row in checkpoints if row['phase'] == 'native-collected']
    _need(len(finals) == 1 and finals[0]['component'] == component
          and not any(row['phase'] == 'interrupted' for row in checkpoints), 'checkpoint-substituted')
    for checkpoint in (row for row in checkpoints if row['phase'] == 'after-case'):
        observation = checkpoint['observation']
        _need(observation in component['observations'] and checkpoint['original'] ==
              component['attachment']['segments'][observation['recordIndex']], 'checkpoint-original-substituted')
    return derived


def public_projection(private, *, source_identity_digest, originals_verified,
                      privacy_verified, watcher_finished, guest_stopped):
    _need(all((originals_verified, privacy_verified, watcher_finished, guest_stopped))
          and re.fullmatch('sha256:[0-9a-f]{64}', str(source_identity_digest)), 'export-incomplete')
    derived = routes.derive_complete_routes(private['component'])
    return {'schemaVersion': 1, 'kind': 'pr320-route-profile-assessment',
        'executionClass': private['executionClass'], 'status': derived['status'],
        'observedVariants': derived['verifiedVariants'], 'missingVariants': derived['missingVariants'],
        'reasons': [], 'evidenceClass': 'installed-controller-bound', 'fullAppBudgets': 'not-observed',
        'originalAuthentication': 'administrator-matched-not-protected-authority',
        'releaseEligible': False, 'phaseComplete': False}


def failed_projection(profile, reason):
    return {'schemaVersion': 1, 'kind': 'pr320-route-profile-assessment', 'executionClass': profile['executionClass'],
        'status': 'failed', 'observedVariants': [], 'missingVariants': profile['variants'],
        'reasons': [reason if reason in {'prerequisites-present-not-executed', 'private-evidence-invalid'}
                    else 'setup-or-execution-failed'],
        'evidenceClass': 'installed-controller-bound', 'fullAppBudgets': 'not-observed',
        'originalAuthentication': 'not-established', 'releaseEligible': False, 'phaseComplete': False}
