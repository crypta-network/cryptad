"""Closed restart/diagnostic consistency oracles under the composed-budget owner.

Epochs remain separate native streams.  A dead process censors an old owner; it does
not acknowledge it.  Matching an original is a separate host-owned operation and
local consistency never confers installed authentication or full-cohort admission.
"""
from __future__ import annotations

import json
import re

from . import composed_budget_evidence as owner
from . import composed_budget_storage_evidence as storage
from . import runtime_pressure_evidence as pressure

CASES = ('graceful-restart', 'abrupt-restart', 'diagnostics-unavailable')
REQUIRED_VARIANTS = {
    'graceful-restart': ('settled-graceful',),
    'abrupt-restart': ('settled-abrupt', 'inflight-abrupt'),
    'diagnostics-unavailable': ('enumeration-only', 'required-key-unreadable'),
}
PROCESS = 'controlled-native-process-file-backed'
FILES = 'controlled-native-file-backed'
INSTALLED = 'installed-real-time-filesystem'
PHASE_FIELDS = {'pid', 'collectorEpoch', 'nativeSnapshot', 'diagnostics', 'scopeBindings', 'graph'}
DIAGNOSTIC_FIELDS = {'valid', 'observedAt', 'usage', 'activeFamilyLeases', 'reservedFamilyRates'}
RATE_FIELDS = {'appId', 'operation', 'windowStart', 'windowSeconds', 'count', 'limit',
               'lastDecisionAt', 'lastDecision', 'nextAvailableAt'}
NATIVE_GRAPH_FIELDS = {'document', 'documentFingerprint', 'payloadHash', 'signatureVerified',
                       'source', 'sourceUri', 'sourceUriHash', 'sourceLabel', 'sourceUriKind',
                       'subscriptionId', 'importedAt', 'updatedAt'}
PROCESS_FIELDS = {'schemaVersion', 'caseId', 'variant', 'evidenceClass', 'before', 'after',
                  'recovery', 'transition', 'dataIdentity', 'pendingOperationIds', 'tailStatus',
                  'selectedFingerprint'}
DIAGNOSTICS_FIELDS = {'schemaVersion', 'caseId', 'variant', 'evidenceClass', 'before', 'during',
                      'after', 'recovery', 'fault', 'selectedFingerprint', 'requestStatus',
                      'requestCode', 'recoveryStatus'}


def _need(condition, reason):
    if not condition:
        raise owner.ComposedEvidenceError('composed-budget-restart-' + reason)


def _closed(value, fields):
    _need(isinstance(value, dict) and set(value) == set(fields), 'fields-invalid')


def _int(value, minimum=0):
    return type(value) is int and value >= minimum


def _time(value):
    try:
        return pressure.baseline._time(value).timestamp()
    except (TypeError, ValueError, AttributeError):
        _need(False, 'time-invalid')


def _bounded(value):
    try:
        _need(len(json.dumps(value, allow_nan=False).encode()) <= 4 * 1024 * 1024,
              'byte-limit')
        _private_tree(value)
    except (TypeError, ValueError):
        _need(False, 'private-value-invalid')


def _private_tree(value, depth=0):
    _need(depth <= 24, 'depth-limit')
    if isinstance(value, dict):
        _need(len(value) <= 128 and all(isinstance(k, str) and len(k) <= 128 for k in value),
              'private-fields-invalid')
        _need(not set(value) & {'session', 'browserSessionToken', 'privateKey', 'formPassword',
                               'commandLine'}, 'private-secret-field')
        for child in value.values():
            _private_tree(child, depth + 1)
    elif isinstance(value, list):
        _need(len(value) <= 8192, 'private-list-limit')
        for child in value:
            _private_tree(child, depth + 1)
    elif isinstance(value, str):
        _need(len(value.encode()) <= 8192, 'private-string-limit')
    else:
        _need(value is None or type(value) is bool or type(value) is int
              and abs(value) <= 2**63 - 1, 'private-value-invalid')


def _scopes(rows):
    _need(isinstance(rows, list) and len(rows) <= 128, 'scope-limit')
    result, used = {}, set()
    for row in rows:
        _closed(row, {'appId', 'scope'})
        app, scope = row['appId'], row['scope']
        _need(isinstance(app, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,95}|_cryptad_global|_cryptad_operator', app)
              and _int(scope, 1) and app not in result and scope not in used, 'scope-binding-invalid')
        expected = {'_cryptad_global': 1, '_cryptad_operator': 2}.get(app)
        _need(scope == expected if expected else scope >= 3, 'reserved-scope-substitution')
        result[app] = scope
        used.add(scope)
    return result


def _rates(rows, scopes):
    _need(isinstance(rows, list) and len(rows) <= 4096, 'rates-unavailable')
    result = {}
    for raw in rows:
        _closed(raw, RATE_FIELDS)
        row = dict(raw, operation=str(raw['operation']).lower())
        app, family = row['appId'], row['operation']
        window = _time(row['windowStart'])
        _need(app in scopes and family in pressure.OPERATIONS - {None}
              and _int(row['count']) and _int(row['limit'], 1)
              and row['windowSeconds'] == storage._seconds(family)
              and window >= 0 and window % row['windowSeconds'] == 0,
              'rate-identity-invalid')
        _need(row['lastDecision'] in {None, 'allowed', 'rate_limited', 'concurrency_limited', 'store_unavailable'},
              'rate-decision-invalid')
        for name in ('lastDecisionAt', 'nextAvailableAt'):
            if row[name] is not None:
                _time(row[name])
        key = app, family
        _need(key not in result, 'rate-family-duplicate')
        result[key] = row
    return result


def _graph(rows):
    _need(isinstance(rows, list) and len(rows) <= 4096, 'graph-unavailable')
    result = {}
    for row in rows:
        if isinstance(row, dict) and 'document' in row:
            _closed(row, NATIVE_GRAPH_FIELDS)
            _need(isinstance(row['document'], dict), 'graph-document-invalid')
            key = row['documentFingerprint']
            _need(isinstance(key, str) and re.fullmatch('[0-9a-f]{64}', key)
                  and isinstance(row['payloadHash'], str)
                  and re.fullmatch('[0-9a-f]{64}', row['payloadHash'])
                  and type(row['signatureVerified']) is bool
                  and _time(row['updatedAt']) >= _time(row['importedAt']), 'graph-invalid')
        else:
            storage._graph([row], False)
            key = row['documentFingerprint']
        _need(key not in result, 'graph-duplicate')
        result[key] = row
    return result


def _phase(raw, *, observation_time=None, controlled=True):
    _closed(raw, PHASE_FIELDS)
    _need(_int(raw['pid'], 1), 'process-invalid')
    epoch = raw['collectorEpoch']
    _need(isinstance(epoch, str) and re.fullmatch('[0-9a-f-]{36}', epoch), 'collector-invalid')
    scopes = _scopes(raw['scopeBindings'])
    diagnostic = raw['diagnostics']
    _closed(diagnostic, DIAGNOSTIC_FIELDS)
    _need(type(diagnostic['valid']) is bool
          and _int(diagnostic['activeFamilyLeases']) and _int(diagnostic['reservedFamilyRates']),
          'diagnostics-invalid')
    stamp = _time(diagnostic['observedAt'])
    _need(observation_time is None or stamp <= _time(observation_time), 'future-observation')
    if diagnostic['valid']:
        rates = _rates(diagnostic['usage'], scopes)
    else:
        # Native failure uses []; this is unavailable durable usage, never a zero total.
        _need(diagnostic['usage'] == [], 'invalid-durable-usage')
        rates = None
    snapshot = raw['nativeSnapshot']
    _closed(snapshot, {'version', 'lastSequence', 'dropped', 'events', 'collectorEpoch'})
    _need(snapshot['version'] == 4 and snapshot['collectorEpoch'] == epoch
          and _int(snapshot['lastSequence']) and snapshot['dropped'] == 0
          and isinstance(snapshot['events'], list), 'native-snapshot-invalid')
    events = (storage._events(snapshot['events'], 0, snapshot['lastSequence'], controlled=controlled,
                             observation_time=observation_time) if snapshot['events'] else [])
    _need(bool(events) or snapshot['lastSequence'] == 0, 'native-prefix-missing')
    reverse = {scope: app for app, scope in scopes.items()}
    _need(all(event['scope'] == 0 or event['scope'] in reverse for event in events),
          'event-scope-unbound')
    _need(not events or _time(events[-1]['observedAt']) <= stamp + 1, 'sample-precedes-event')
    return dict(raw=raw, rates=rates, events=events, scopes=scopes, reverse=reverse,
                graph=_graph(raw['graph']), stamp=stamp)


def _suffix(first, second):
    _need(first['raw']['collectorEpoch'] == second['raw']['collectorEpoch']
          and first['raw']['pid'] == second['raw']['pid'], 'same-epoch-required')
    prefix = first['events']
    _need(second['events'][:len(prefix)] == prefix, 'event-prefix-substituted')
    _need(second['stamp'] >= first['stamp'], 'interval-order-invalid')
    return second['events'][len(prefix):]


def _flat_rates(phase):
    _need(phase['rates'] is not None, 'healthy-rates-required')
    return {(row['operation'], phase['scopes'][app], int(_time(row['windowStart']))): row['count']
            for (app, _), row in phase['rates'].items()}


def _reconcile(first, second, events, *, require_charge=False, selected=None):
    _need(first['rates'] is not None and second['rates'] is not None, 'healthy-rates-required')
    _need(all(second['scopes'].get(app) == scope for app, scope in first['scopes'].items()),
          'same-process-scope-substitution')
    storage._ledger(_flat_rates(first), _flat_rates(second), events)
    writes = {(e['operation'], e['scope']) for e in events
              if e['kind'] in {'RATE_CHARGED', 'RATE_METADATA_WRITTEN'}}
    for key in set(first['rates']) | set(second['rates']):
        old, new = first['rates'].get(key), second['rates'].get(key)
        if old == new:
            continue
        _need(new is not None and (key[1], second['scopes'][key[0]]) in writes,
              'rate-metadata-unexplained')
        _need(old is None or old['limit'] == new['limit'], 'rate-limit-substituted')
        relevant = [e for e in events if (e['operation'], e['scope']) ==
                    (key[1], second['scopes'][key[0]]) and e['kind'] in
                    {'RATE_CHARGED', 'RATE_METADATA_WRITTEN'}]
        _need(relevant and new['lastDecisionAt'] is not None
              and _time(new['lastDecisionAt']) <= second['stamp'], 'rate-decision-unexplained')
        last = relevant[-1]
        if last['kind'] == 'RATE_CHARGED':
            _need(new['lastDecision'] == 'allowed' and new['nextAvailableAt'] is None,
                  'rate-decision-substituted')
        else:
            _need(new['lastDecision'] in {'rate_limited', 'concurrency_limited'},
                  'denial-decision-substituted')
    if require_charge:
        _need(any(e['kind'] == 'RATE_CHARGED' for e in events)
              and any(e['kind'] == 'BUDGET_COMMITTED' for e in events), 'recovery-charge-missing')
    _need(set(first['graph']) <= set(second['graph']), 'graph-loss')
    changed = {key for key in first['graph'] if first['graph'][key] != second['graph'][key]}
    _need(changed <= ({selected} if selected else set()), 'graph-metadata-unexplained')
    if changed:
        _need(any(e['kind'] == 'GRAPH_STORE_DUPLICATE' for e in events),
              'graph-duplicate-unobserved')
        old, new = first['graph'][selected], second['graph'][selected]
        mutable = {'source', 'sourceUri', 'sourceUriHash', 'sourceLabel', 'sourceUriKind',
                   'subscriptionId', 'updatedAt', 'lastSeenAt', 'lifecycle', 'sourceType'}
        _need(set(old) == set(new) and all(old[k] == new[k] for k in set(old) - mutable),
              'graph-document-substitution')
        _need(_time(new['updatedAt']) >= _time(old['updatedAt'])
              and _time(new['updatedAt']) <= second['stamp'], 'graph-time-rollback')
        if 'lifecycle' in old:
            _need(set(old['lifecycle']) == set(new['lifecycle']) and
                  all(old['lifecycle'][k] == new['lifecycle'][k]
                      for k in old['lifecycle'] if k != 'updatedAt'), 'graph-lifecycle-substitution')
    added = set(second['graph']) - set(first['graph'])
    outcomes = [e for e in events if e['kind'] == 'GRAPH_STORE_IMPORTED']
    _need(len(added) == len(outcomes), 'graph-import-unexplained')


def _pending_holds(phase):
    active = {}
    for event in phase['events']:
        kind = event['kind']
        if kind not in {'CONCURRENCY_HELD', 'CONCURRENCY_RELEASED', 'RATE_RESERVED',
                        'RATE_RESERVATION_RELEASED'}:
            continue
        rate = kind.startswith('RATE_')
        key = event['operationId'], event['operation'], event['scope'], rate, (
            event['windowStartEpochSecond'] if rate else 0)
        active[key] = active.get(key, 0) + (1 if kind in {'CONCURRENCY_HELD', 'RATE_RESERVED'} else -1)
        _need(active[key] in {0, 1}, 'hold-prefix-unbalanced')
    counts = (sum(v for k, v in active.items() if not k[3]),
              sum(v for k, v in active.items() if k[3]))
    diagnostic = phase['raw']['diagnostics']
    _need(counts == (diagnostic['activeFamilyLeases'], diagnostic['reservedFamilyRates']),
          'hold-prefix-substituted')
    return {key for key, value in active.items() if value}


def _pending(phase):
    return {key[0] for key in _pending_holds(phase)}


def _live_uri_owner(phase):
    """An interrupted URI owner must still hold import and invoked-fetch capacity."""
    events, live = phase['events'], _pending_holds(phase)
    terminal = {'REQUEST_SUCCEEDED', 'REQUEST_FAILED', 'FETCH_SUCCEEDED', 'FETCH_FAILED',
                'FETCH_OWNER_TERMINATED', 'FETCH_OWNER_TERMINATION_FAILED',
                'FETCH_TERMINATION_UNKNOWN', 'BUDGET_RELEASED'}
    for start in events:
        if (start['kind'] != 'COMPOSED_URI_IMPORT_START' or start['scope'] < 3
                or start['operationId'] < 1):
            continue
        parent, scope = start['operationId'], start['scope']
        links = [e for e in events if e['kind'] == 'COMPOSED_CHILD' and e['value'] == parent]
        if (len(links) != 2 or len({e['operationId'] for e in links} | {parent}) != 3
                or any(e['scope'] != scope or e['sequence'] <= start['sequence'] for e in links)):
            continue
        children = {e['operationId'] for e in links}
        group = [e for e in events if e['operationId'] in children | {parent}]
        if any(e['kind'] in terminal for e in group):
            continue
        reserved = [e for e in group if e['kind'] == 'BUDGET_RESERVED'
                    and e['operation'] == 'trust_graph_import' and e['scope'] == scope]
        invoked = [e for e in group if e['kind'] == 'FETCH_INVOKED'
                   and e['operation'] == 'trust_graph_import_uri' and e['scope'] == scope]
        if len(reserved) != 1 or len(invoked) != 1:
            continue
        import_id, fetch_id = reserved[0]['operationId'], invoked[0]['operationId']
        commits = [e for e in group if e['kind'] == 'BUDGET_COMMITTED'
                   and e['operationId'] == fetch_id
                   and e['operation'] == 'trust_graph_import_uri' and e['scope'] == scope]
        if (set((import_id, fetch_id)) != children or len(commits) != 1
                or not reserved[0]['sequence'] < commits[0]['sequence'] < invoked[0]['sequence']
                or not owner._exact_charges(group, fetch_id, owner.FETCH, scope)):
            continue
        expected = {(import_id, 'trust_graph_import', s, False, 0) for s in (scope, 1)}
        expected |= {(fetch_id, family, 1 if role == 'global' else scope, False, 0)
                     for family, role in owner.FETCH}
        reservations = [e for e in group if e['kind'] == 'RATE_RESERVED'
                        and e['operationId'] == import_id]
        if (len(reservations) != 2 or {(e['operation'], e['scope']) for e in reservations}
                != {('trust_graph_import', scope), ('trust_graph_import', 1)}):
            continue
        expected |= {(import_id, e['operation'], e['scope'], True,
                      e['windowStartEpochSecond']) for e in reservations}
        if not expected <= live:
            continue
        admission = {import_id: reserved[0]['sequence'], fetch_id: commits[0]['sequence']}
        if any(e['sequence'] >= admission.get(e['operationId'], 0) for e in group
               if e['kind'] in {'CONCURRENCY_HELD', 'RATE_RESERVED', 'RATE_CHARGED'}):
            continue
        if any(e['kind'] == 'COMPOSED_CHILD' and e['operationId'] in children
               and (e['value'] != parent or e['sequence'] >= admission[e['operationId']])
               for e in events):
            continue
        return True
    return False


def match_originals(raw, originals):
    """Require independently retained parent/admin facts, never an attachment self-digest."""
    names = ('before', 'during', 'after', 'recovery') if raw['caseId'] == 'diagnostics-unavailable' else (
        'before', 'after', 'recovery')
    authority = 'fault' if raw['caseId'] == 'diagnostics-unavailable' else 'transition'
    fields = {authority, 'scopeBindings', 'selectedFingerprint'} | (
        {'dataIdentity'} if authority == 'transition' else set())
    _closed(originals, fields)
    _closed(originals['scopeBindings'], names)
    _need(originals[authority] == raw[authority], 'original-witness-substitution')
    if authority == 'transition':
        _need(originals['dataIdentity'] == raw['dataIdentity'], 'original-data-substitution')
    _need(originals['selectedFingerprint'] == raw['selectedFingerprint'],
          'original-selected-substitution')
    _need(all(originals['scopeBindings'][name] == raw[name]['scopeBindings'] for name in names),
          'original-scope-substitution')
    return True


def _result(raw, observed, *, tail='complete', originals=None):
    if originals is not None:
        match_originals(raw, originals)
    return {'caseId': raw['caseId'], 'variant': raw['variant'], 'observed': observed,
            'status': 'verified' if observed else 'control-verified', 'tailStatus': tail,
            'evidenceClass': raw['evidenceClass'], 'originalAuthentication': 'not-established',
            'originalWitnessMatched': originals is not None, 'installedObservation': False,
            'fullAppBudgets': 'not-observed', 'releaseEligible': False}


def derive_controlled(raw, *, originals=None, observation_time=None):
    """Read real producer observations; authority matching is explicit and independent."""
    _bounded(raw)
    if isinstance(raw, dict) and raw.get('caseId') == 'diagnostics-unavailable':
        return _diagnostics(raw, originals=originals, observation_time=observation_time)
    _closed(raw, PROCESS_FIELDS)
    _need(type(raw['schemaVersion']) is int and raw['schemaVersion'] == 1
          and raw['evidenceClass'] in {PROCESS, INSTALLED}
          and raw['caseId'] in {'graceful-restart', 'abrupt-restart'}, 'binding-invalid')
    variant = raw['variant']
    _need(variant in {'settled-graceful', 'settled-abrupt', 'inflight-abrupt', 'worker-only-control'},
          'variant-invalid')
    _need(raw['caseId'] == ('graceful-restart' if variant in
          {'settled-graceful', 'worker-only-control'} else 'abrupt-restart'), 'case-variant-mismatch')
    phases = [_phase(raw[name], observation_time=observation_time,
                     controlled=raw['evidenceClass'] != INSTALLED)
              for name in ('before', 'after', 'recovery')]
    before, after, recovery = phases
    selected = raw['selectedFingerprint']
    _need(isinstance(selected, str) and re.fullmatch('[0-9a-f]{64}', selected)
          and selected in before['graph'], 'selected-graph-missing')
    _need(all(p['rates'] is not None for p in phases), 'healthy-rates-required')
    _closed(raw['dataIdentity'], {'fileKey'})
    _need(isinstance(raw['dataIdentity']['fileKey'], str) and 0 < len(raw['dataIdentity']['fileKey']) <= 256,
          'retained-data-invalid')
    transition = raw['transition']
    _closed(transition, {'kind', 'oldPid', 'aliveBefore', 'exitCode', 'deadBeforeRestart', 'newPid', 'forced'})
    _need(type(transition['aliveBefore']) is bool and transition['aliveBefore']
          and type(transition['deadBeforeRestart']) is bool
          and type(transition['forced']) is bool
          and (transition['exitCode'] is None or type(transition['exitCode']) is int)
          and transition['oldPid'] == before['raw']['pid']
          and transition['newPid'] == after['raw']['pid'], 'transition-invalid')
    if variant == 'worker-only-control':
        _need(transition['kind'] == 'worker-only' and not transition['forced']
              and not transition['deadBeforeRestart'] and before['raw']['pid'] == after['raw']['pid'],
              'worker-control-invalid')
        _suffix(before, after)
        return _result(raw, False, originals=originals)
    graceful = variant == 'settled-graceful'
    _need(transition['kind'] == ('graceful' if graceful else 'forced')
          and transition['forced'] is (not graceful) and transition['deadBeforeRestart']
          and before['raw']['pid'] != after['raw']['pid']
          and before['raw']['collectorEpoch'] != after['raw']['collectorEpoch']
          and (not graceful or transition['exitCode'] == 0), 'restart-not-established')
    _need(after['stamp'] >= before['stamp'], 'restart-time-invalid')
    _need(before['rates'] == after['rates'] and before['graph'] == after['graph'],
          'retained-state-substituted')
    _need(any(row['count'] > 0 for row in before['rates'].values()), 'durable-seed-missing')
    pending = _pending(before)
    _need(isinstance(raw['pendingOperationIds'], list)
          and all(_int(value, 1) for value in raw['pendingOperationIds'])
          and len(set(raw['pendingOperationIds'])) == len(raw['pendingOperationIds'])
          and set(raw['pendingOperationIds']) == pending, 'pending-prefix-substituted')
    censored = variant == 'inflight-abrupt'
    _need(raw['tailStatus'] == ('censored' if censored else 'complete')
          and (bool(pending) if censored else not pending), 'tail-status-invalid')
    _need(not censored or _live_uri_owner(before), 'inflight-owner-missing')
    _need(not _pending(after), 'new-process-holds-present')
    events = _suffix(after, recovery)
    _reconcile(after, recovery, events, require_charge=True, selected=selected)
    _need(not _pending(recovery), 'recovery-holds-present')
    return _result(raw, True, tail=raw['tailStatus'], originals=originals)


def _diagnostics(raw, *, originals=None, observation_time=None):
    _closed(raw, DIAGNOSTICS_FIELDS)
    _need(type(raw['schemaVersion']) is int and raw['schemaVersion'] == 1
          and raw['evidenceClass'] in {FILES, INSTALLED}, 'binding-invalid')
    variants = {'enumeration-only', 'required-key-unreadable', 'malformed-record', 'identity-mismatch',
                'special-member', 'bounded-exhaustion', 'valid-empty-control'}
    _need(raw['variant'] in variants, 'variant-invalid')
    phases = [_phase(raw[name], observation_time=observation_time,
                     controlled=raw['evidenceClass'] != INSTALLED)
              for name in ('before', 'during', 'after', 'recovery')]
    before, during, after, recovery = phases
    selected = raw['selectedFingerprint']
    _need(selected is None and not before['graph'] or isinstance(selected, str)
          and re.fullmatch('[0-9a-f]{64}', selected) and selected in before['graph'],
          'selected-graph-missing')
    _need(all(p['raw']['pid'] == before['raw']['pid'] and
              p['raw']['collectorEpoch'] == before['raw']['collectorEpoch'] for p in phases),
          'diagnostic-restart-not-permitted')
    _need(before['rates'] is not None and after['rates'] is not None and recovery['rates'] is not None,
          'healthy-boundaries-required')
    events = _suffix(before, during) + _suffix(during, after)
    fault = raw['fault']
    _closed(fault, {'kind', 'targetAppId', 'requiredKeyReadable', 'enumerationReadable', 'restored', 'contentsRestored'})
    _need(fault['kind'] == raw['variant'] and fault['targetAppId'] in before['scopes']
          and all(type(fault[key]) is bool for key in ('requiredKeyReadable', 'enumerationReadable',
                                                     'restored', 'contentsRestored'))
          and fault['restored'] and not fault['contentsRestored'], 'fault-invalid')
    control = raw['variant'] == 'valid-empty-control'
    denied = raw['variant'] in {'required-key-unreadable', 'malformed-record', 'identity-mismatch'}
    _need(raw['requestStatus'] == (503 if denied else 200)
          and raw['requestCode'] == ('network_budget_unavailable' if denied else None)
          and raw['recoveryStatus'] == 200, 'diagnostic-request-outcome-invalid')
    if control:
        _need(during['rates'] == {} and before['rates'] == {}, 'empty-control-invalid')
    else:
        _need(during['rates'] is None and any(e['kind'] == 'STORE_UNAVAILABLE' for e in events),
              'unavailable-not-observed')
        _need(any(row['count'] > 0 for row in before['rates'].values()), 'durable-seed-missing')
        if raw['variant'] == 'enumeration-only':
            _need(not fault['enumerationReadable'] and fault['requiredKeyReadable']
                  and any(e['kind'] == 'RATE_CHARGED' for e in _suffix(before, during)),
                  'enumeration-only-not-established')
        elif raw['variant'] == 'required-key-unreadable':
            _need(not fault['requiredKeyReadable']
                  and any(e['kind'] == 'STORE_UNAVAILABLE' for e in _suffix(before, during))
                  and any(e['kind'] in {'BUDGET_ACQUIRE', 'BUDGET_RESERVE'}
                          for e in _suffix(before, during))
                  and not any(e['kind'] == 'RATE_CHARGED' for e in _suffix(before, during)),
                  'required-key-failure-not-established')
    _reconcile(before, after, events, selected=selected)
    recovery_events = _suffix(after, recovery)
    _reconcile(after, recovery, recovery_events, require_charge=not control, selected=selected)
    _need(not _pending(recovery), 'diagnostic-recovery-holds-present')
    return _result(raw, not control, originals=originals)


def derive_cases(value, *, originals=None, observation_time=None):
    """Award a case only when every closed mandatory variant is actually established."""
    rows = value.get('restartCases', []) + value.get('diagnosticsCases', [])
    _need(isinstance(rows, list) and len(rows) <= 32, 'case-limit')
    verified, seen, event_identities, process_identities = {}, set(), {}, {}
    for raw in rows:
        key = raw.get('caseId'), raw.get('variant')
        _need(key not in seen, 'variant-replayed')
        seen.add(key)
        original = None if originals is None else originals.get(key[1])
        _need(originals is None or original is not None, 'original-missing')
        result = derive_controlled(raw, originals=original, observation_time=observation_time)
        for name in ('before', 'during', 'after', 'recovery'):
            if name not in raw:
                continue
            phase = raw[name]
            epoch = phase['collectorEpoch']
            _need(epoch not in process_identities or process_identities[epoch] == phase['pid'],
                  'collector-process-substitution')
            process_identities[epoch] = phase['pid']
            for event in phase['nativeSnapshot']['events']:
                identity = epoch, event['sequence']
                _need(identity not in event_identities or event_identities[identity] == event,
                      'repeated-native-event-substitution')
                event_identities[identity] = event
        if result['observed']:
            verified.setdefault(key[0], set()).add(key[1])
    return {case for case, variants in REQUIRED_VARIANTS.items()
            if set(variants) <= verified.get(case, set())}


def derive_variants(value, observation_time=None):
    rows = value.get('restartCases', []) + value.get('diagnosticsCases', [])
    derive_cases(value, observation_time=observation_time)
    verified = {raw['variant'] for raw in rows if derive_controlled(raw,
                observation_time=observation_time)['observed']}
    required = {variant for variants in REQUIRED_VARIANTS.values() for variant in variants}
    return {'verifiedVariants': sorted(verified & required),
            'unobservedVariants': sorted(required - verified), 'fullAppBudgets': 'not-observed',
            'releaseEligible': False}
