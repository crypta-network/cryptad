"""Closed PR-318 storage/window consistency oracles; no original authority is conferred.

Controlled Java exports keep their independent service and recorder clocks. Installed
attachments additionally require real-time, role, administrator and recovery witnesses.
Neither an exception nor a missing acknowledgment establishes an unchanged file.
"""
from __future__ import annotations

import json
import math
import re

from . import composed_budget_evidence as owner
from . import runtime_pressure_evidence as pressure

CASES = ('window-crossing', 'partial-rate-write', 'graph-store-unavailable')
CONTROLLED = 'controlled-native-file-backed'
INSTALLED = 'installed-real-time-filesystem'
GRAPH_FIELDS = {'documentFingerprint', 'payloadHash', 'signatureVerified', 'source',
                'sourceLabel', 'sourceUriHash', 'subscriptionId', 'importedAt', 'updatedAt'}


def _fail(reason):
    raise owner.ComposedEvidenceError('composed-budget-storage-' + reason)


def _closed(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        _fail('fields-invalid')


def _need(condition, reason):
    if not condition:
        _fail(reason)


def _stamp(value):
    try:
        return pressure.baseline._time(value).timestamp()
    except (ValueError, TypeError, AttributeError):
        _fail('time-invalid')


def _seconds(family):
    return 3600 if family in {'trust_graph_import', 'subscription_poll',
                              'subscription_manual_refresh'} else 60


def _key(event):
    return event['operation'], event['scope'], event['windowStartEpochSecond']


def _events(rows, start, end, *, controlled=False, epochs=None, epoch=None,
            observation_time=None):
    _need(isinstance(rows, list) and 0 < len(rows) <= 4096
          and len(rows) == end - start, 'event-range-invalid')
    previous = None
    result = []
    for index, raw in enumerate(rows):
        _closed(raw, pressure.EVENT_FIELDS)
        event = dict(raw)
        if controlled and event['operation'] is not None:
            event['operation'] = event['operation'].lower()
        _need(event['kind'] in pressure.KINDS | owner.COMPOSED_KINDS |
              owner.CAUSAL_KINDS | owner.STORAGE_KINDS
              and event['operation'] in pressure.OPERATIONS
              and all(pressure._number(event[k]) for k in pressure.EVENT_FIELDS -
                      {'observedAt', 'kind', 'operation', 'sourceEpoch'})
              and event['sequence'] == start + index + 1, 'event-invalid')
        _need(event['sourceEpoch'] is None or isinstance(event['sourceEpoch'], str)
              and re.fullmatch('[a-zA-Z0-9._-]{1,96}', event['sourceEpoch']), 'source-invalid')
        wall = _stamp(event['observedAt'])
        window = event['windowStartEpochSecond']
        _need(not window or window % _seconds(event['operation']) == 0,
              'window-alignment-invalid')
        _need(controlled or window <= wall, 'future-window')
        _need(observation_time is None or wall <= _stamp(observation_time), 'future-event')
        _need(previous is None or event['elapsedNanos'] >= previous['elapsedNanos']
              and wall >= _stamp(previous['observedAt']), 'event-order-invalid')
        _need(event['sourceSampledAtEpochMillis'] <= wall * 1000 + 1,
              'future-pressure-source')
        if epochs is not None:
            identity = epoch, event['sequence']
            _need(identity not in epochs, 'event-replayed')
            epochs[identity] = event
        previous = event
        result.append(event)
    if not controlled:
        wall_elapsed = _stamp(result[-1]['observedAt']) - _stamp(result[0]['observedAt'])
        monotonic_elapsed = (result[-1]['elapsedNanos'] - result[0]['elapsedNanos']) / 1e9
        # One second permits bounded wall sampling noise; a clock jump is not an elapsed window.
        _need(abs(wall_elapsed - monotonic_elapsed) <= 1, 'recorder-clock-anomaly')
    return result


def _rates(rows, *, controlled=False):
    _need(isinstance(rows, list) and len(rows) <= 4096, 'rates-unavailable')
    result = {}
    families = set()
    for row in rows:
        if controlled:
            _closed(row, {'scope', 'family', 'windowStart', 'windowSeconds', 'count',
                          'lastDecision', 'lastDecisionAt'})
            family, window = row['family'].lower(), _stamp(row['windowStart'])
            _need(row['windowSeconds'] == _seconds(family), 'rate-duration-invalid')
            _need(row['lastDecisionAt'] is None or isinstance(row['lastDecisionAt'], str),
                  'decision-invalid')
        else:
            _closed(row, {'operation', 'scope', 'windowStartEpochSecond', 'count'})
            family, window = row['operation'], row['windowStartEpochSecond']
        _need(family in pressure.OPERATIONS - {None} and pressure._number(row['scope'])
              and row['scope'] >= 1 and pressure._number(row['count'])
              and isinstance(window, (int, float)) and window >= 0
              and window % _seconds(family) == 0, 'rate-invalid')
        key = family, row['scope'], int(window)
        _need(key[:2] not in families, 'rate-family-duplicate')
        families.add(key[:2])
        result[key] = row['count']
    return result


def _ledger(before, after, events, cutpoint=None):
    """Replay original writes; uncertain target is resolved only by complete later state."""
    state = dict(before)
    pending = {}
    acknowledged, uncertain, attempts = [], [], []
    ordered = {}
    for event in events:
        kind = event['kind']
        if kind not in owner.STORAGE_KINDS | {'RATE_CHARGED'}:
            continue
        identity = event['operationId'], _key(event)
        key = _key(event)
        _need(event['operationId'] > 0 and key[0] is not None and key[1] >= 1,
              'write-identity-invalid')
        if kind in {'RATE_WRITE_ATTEMPT', 'RATE_METADATA_WRITE_ATTEMPT'}:
            _need(identity not in pending, 'write-attempt-duplicate')
            pending[identity] = event
            if kind == 'RATE_WRITE_ATTEMPT':
                attempts.append(event)
                ordered.setdefault(event['operationId'], []).append(key[:2])
            continue
        attempt = pending.pop(identity, None)
        _need(attempt is not None and attempt['value'] == event['value'], 'write-without-attempt')
        metadata = attempt['kind'] == 'RATE_METADATA_WRITE_ATTEMPT'
        _need(kind in ({'RATE_METADATA_WRITTEN', 'RATE_METADATA_WRITE_UNKNOWN'} if metadata
                       else {'RATE_CHARGED', 'RATE_WRITE_UNKNOWN'}), 'write-kind-substituted')
        existing = state.get(key, 0)
        _need(event['value'] == existing + (0 if metadata else 1), 'write-count-invalid')
        unknown = kind in {'RATE_WRITE_UNKNOWN', 'RATE_METADATA_WRITE_UNKNOWN'}
        persisted = not unknown
        if unknown:
            uncertain.append(event)
            # This replay interval ends before another request can overwrite the ambiguous key.
            observed = after.get(key, 0)
            _need(observed in {existing, event['value']}, 'write-prefix-unexplained')
            persisted = observed == event['value']
            if not metadata and cutpoint is not None:
                _need(persisted == (cutpoint == 'after-delegate'), 'cutpoint-substituted')
        elif not metadata:
            acknowledged.append(event)
        if persisted:
            for old in list(state):
                if old[:2] == key[:2] and old != key:
                    del state[old]
            state[key] = event['value']
    _need(not pending, 'write-outcome-missing')
    # Denial metadata may create a zero-count record; it must have its own native metadata write.
    _need(state == after, 'rate-state-unexplained')
    for operation_id, families in ordered.items():
        first = families[0]
        scope = first[1]
        expected = ([('trust_graph_import', scope), ('trust_graph_import', 1)]
                    if first[0] == 'trust_graph_import' else
                    [('foreground_content_fetch', scope), ('content_fetch_global', 1)])
        _need(scope >= 3 and families == expected[:len(families)], 'family-order-invalid')
    return attempts, acknowledged, uncertain


def _holds(events, before=None, checkpoints=None):
    active = dict(before or {})
    snapshots = {}
    for event in events:
        kind = event['kind']
        if kind in {'CONCURRENCY_HELD', 'CONCURRENCY_RELEASED', 'RATE_RESERVED',
                    'RATE_RESERVATION_RELEASED'}:
            key = (event['operationId'], event['operation'], event['scope'],
                   'concurrency' if kind.startswith('CONCURRENCY') else 'rate',
                   0 if kind.startswith('CONCURRENCY') else event['windowStartEpochSecond'])
            active[key] = active.get(key, 0) + (1 if kind in
                {'CONCURRENCY_HELD', 'RATE_RESERVED'} else -1)
            _need(active[key] in {0, 1}, 'hold-unbalanced')
        aggregated = {}
        for key, count in active.items():
            if count:
                aggregated[key[:4]] = aggregated.get(key[:4], 0) + count
        snapshots[event['sequence']] = aggregated
    _need(not any(active.values()), 'cleanup-incomplete')
    for sequence, expected in (checkpoints or {}).items():
        _need(snapshots.get(sequence, before or {}) == expected, 'hold-snapshot-substituted')


def _roots(events):
    starts = [e for e in events if e['kind'] in
              {'COMPOSED_URI_IMPORT_START', 'COMPOSED_DIRECT_IMPORT_START'}]
    links = {}
    for event in events:
        if event['kind'] == 'COMPOSED_CHILD':
            _need(event['operationId'] not in links and event['value'] != event['operationId'],
                  'child-replayed')
            links[event['operationId']] = event['value']
    roots = {e['operationId'] for e in starts}
    _need(len(roots) == len(starts), 'operation-replayed')
    for child, parent in links.items():
        _need(parent in roots and child not in roots, 'child-borrowed')
    # Standalone native contender admissions are allowed, but never supply another request's work.
    for event in events:
        if event['kind'].startswith(('GRAPH_', 'PARSE_', 'REQUEST_', 'FINGERPRINT_')):
            _need(event['operationId'] in roots, 'parent-stage-borrowed')
    return starts, links


def _route(events, parent, *, failed=False, graph_failure=False):
    starts, links = _roots(events)
    own = [e for e in events if e['operationId'] == parent]
    _need(own and own[0] in starts and own[-1]['kind'] ==
          ('REQUEST_FAILED' if failed else 'REQUEST_SUCCEEDED'), 'request-terminal-invalid')
    scope = own[0]['scope']
    _need(scope >= 3 and all(e['scope'] == scope for e in own), 'request-scope-invalid')
    children = {child for child, root in links.items() if root == parent}
    group = [e for e in events if e['operationId'] in children]
    _need(all(e['scope'] in {1, scope} or e['scope'] == 0 and e['kind'] == 'BUDGET_RELEASED'
              for e in group), 'child-scope-substituted')
    _need(all(own[0]['sequence'] < e['sequence'] < own[-1]['sequence']
              for e in group), 'child-lifetime-invalid')
    kinds = [e['kind'] for e in own]
    uri = own[0]['kind'] == 'COMPOSED_URI_IMPORT_START'
    if graph_failure or not failed:
        _need('PARSE_SUCCEEDED' in kinds and 'PARSE_FAILED' not in kinds
              and 'GRAPH_STORE_ATTEMPT' in kinds, 'graph-stage-missing')
        verdicts = [k for k in kinds if k in {'GRAPH_STORE_IMPORTED', 'GRAPH_STORE_DUPLICATE',
                                             'GRAPH_STORE_UNKNOWN', 'GRAPH_STORE_UNVERIFIED'}]
        _need(len(verdicts) == 1 and verdicts[0] in
              ({'GRAPH_STORE_UNKNOWN'} if graph_failure else
               {'GRAPH_STORE_IMPORTED', 'GRAPH_STORE_DUPLICATE'}), 'graph-verdict-invalid')
        _need(kinds.index('PARSE_SUCCEEDED') < kinds.index('GRAPH_STORE_ATTEMPT') <
              kinds.index(verdicts[0]), 'graph-order-invalid')
        expected = [own[0]['kind'], 'PARSE_SUCCEEDED'] + (['FINGERPRINT_ACCEPTED'] if uri else [])
        expected += ['GRAPH_STORE_ATTEMPT', verdicts[0], 'REQUEST_FAILED' if failed else 'REQUEST_SUCCEEDED']
        _need(kinds == expected, 'parent-stage-order-invalid')
        if uri:
            _need('FINGERPRINT_ACCEPTED' in kinds and kinds.index('FINGERPRINT_ACCEPTED') <
                  kinds.index('GRAPH_STORE_ATTEMPT'), 'fingerprint-stage-missing')
        imports = {e['operationId'] for e in group if e['kind'] == 'BUDGET_COMMITTED'
                   and e['operation'] == 'trust_graph_import'}
        _need(len(imports) == 1, 'import-commit-missing')
        _need(owner._exact_charges(events, next(iter(imports)), owner.IMPORT, scope),
              'import-charges-missing')
        commit = next(e for e in group if e['kind'] == 'BUDGET_COMMITTED'
                      and e['operation'] == 'trust_graph_import')
        parse = next(e for e in own if e['kind'] == 'PARSE_SUCCEEDED')
        _need(commit['sequence'] < parse['sequence'], 'import-order-invalid')
        _need(owner._concurrency_covers(events, next(iter(imports)), owner.IMPORT,
              scope, [e for e in own if e['kind'].startswith(('PARSE_', 'GRAPH_STORE_'))
                      and e['kind'] != 'GRAPH_STORE_UNKNOWN']),
              'import-hold-missing')
    else:
        _need(kinds == [own[0]['kind'], 'REQUEST_FAILED'],
              'work-after-denial')
    if uri:
        invoked = [e for e in group if e['kind'] == 'FETCH_INVOKED']
        if invoked:
            _need(len(invoked) == 1, 'fetch-duplicate')
            child = invoked[0]['operationId']
            _need(owner._exact_charges(events, child, owner.FETCH, scope), 'fetch-charges-missing')
            terminals = [e for e in group if e['operationId'] == child and e['kind'] in
                         {'FETCH_SUCCEEDED', 'FETCH_FAILED'}]
            _need(len(terminals) == 1 and terminals[0]['kind'] == 'FETCH_SUCCEEDED'
                  and terminals[0]['sequence'] > invoked[0]['sequence'], 'fetch-terminal-invalid')
            _need(owner._concurrency_covers(events, child, owner.FETCH, scope,
                                            invoked + terminals), 'fetch-hold-missing')
            _need(any(e['kind'] == 'BUDGET_COMMITTED' and e['operationId'] == child
                      and e['sequence'] < invoked[0]['sequence'] for e in group),
                  'fetch-admission-missing')
        else:
            _need(failed and not graph_failure, 'fetch-missing')
    return own, group


def _private_value(value, depth=0):
    _need(depth <= 4, 'graph-depth-limit')
    if isinstance(value, str):
        _need(len(value.encode()) <= 4096 and not any(ord(c) < 32 for c in value),
              'graph-string-limit')
    elif isinstance(value, dict):
        _need(len(value) <= 40, 'graph-field-limit')
        for key, item in value.items():
            _need(isinstance(key, str) and len(key) <= 64, 'graph-key-invalid')
            _private_value(item, depth + 1)
    else:
        _need(value is None or type(value) is bool or type(value) is int and abs(value) <= 2**53 - 1,
              'graph-value-invalid')


def _graph(rows, controlled):
    _need(isinstance(rows, list) and len(rows) <= 4096, 'graph-readback-unavailable')
    result = {}
    for row in rows:
        _need(isinstance(row, dict) and GRAPH_FIELDS -
              {'sourceLabel', 'sourceUriHash', 'subscriptionId'} <= set(row), 'graph-fields-invalid')
        if controlled:
            _closed(row, GRAPH_FIELDS)
        else:
            required = (GRAPH_FIELDS - {'sourceLabel', 'sourceUriHash', 'subscriptionId'}) | {
                'type', 'issuerFingerprint', 'subject', 'context', 'score', 'confidence',
                'issuedAt', 'expiresAt', 'signatureAlgorithm', 'signaturePresent', 'sourceType',
                'lastSeenAt', 'lifecycleStatus', 'lifecycle'}
            optional = {'sourceLabel', 'sourceUriHash', 'subscriptionId', 'sourceUri', 'sourceUriKind'}
            _need(required <= set(row) <= required | optional, 'graph-fields-invalid')
            subject = row['subject']
            _need(isinstance(subject, dict) and {'kind', 'uri'} <= set(subject) <=
                  {'kind', 'uri', 'fingerprint'}, 'graph-subject-invalid')
            lifecycle = row['lifecycle']
            fields = {'statementFingerprint', 'status', 'reasonCode', 'createdAt', 'updatedAt', 'source'}
            _need(isinstance(lifecycle, dict) and fields <= set(lifecycle) <= fields |
                  {'note', 'replacementUri', 'actorAppId'}, 'graph-lifecycle-invalid')
            _need(lifecycle['statementFingerprint'] == row['documentFingerprint']
                  and lifecycle['status'] == row['lifecycleStatus']
                  and row['lastSeenAt'] == row['updatedAt'] and row['signaturePresent'] is True,
                  'graph-summary-substituted')
        _private_value(row)
        key = row['documentFingerprint']
        _need(isinstance(key, str) and re.fullmatch('[0-9a-f]{64}', key)
              and key not in result and isinstance(row['payloadHash'], str)
              and re.fullmatch('[0-9a-f]{64}', row['payloadHash'])
              and type(row['signatureVerified']) is bool, 'graph-identity-invalid')
        _need(_stamp(row['updatedAt']) >= _stamp(row['importedAt']), 'graph-time-invalid')
        result[key] = row
    return result


def _graph_reconcile(before, after, recovery, *, cutpoint, failed, controlled, selected,
                     initial_events, recovery_events):
    b, a, r = (_graph(rows, controlled) for rows in (before, after, recovery))
    changed = {key for key in set(b) | set(a) if b.get(key) != a.get(key)}
    recovery_changed = {key for key in set(a) | set(r) if a.get(key) != r.get(key)}
    _need(not (set(b) - set(a)) and not (set(a) - set(r)), 'graph-removal-unexplained')
    _need(isinstance(selected, str) and re.fullmatch('[0-9a-f]{64}', selected),
          'selected-graph-identity-invalid')
    _need(changed | recovery_changed <= {selected}, 'graph-unrelated-mutation')
    for old, new, native in ((b, a, initial_events), (a, r, recovery_events)):
        verdicts = [e['kind'] for e in native if e['kind'] in
                    {'GRAPH_STORE_IMPORTED', 'GRAPH_STORE_DUPLICATE', 'GRAPH_STORE_UNKNOWN'}]
        _need(len(verdicts) <= 1, 'graph-verdict-duplicate')
        if verdicts and verdicts[0] == 'GRAPH_STORE_IMPORTED':
            _need(selected not in old and selected in new and len(new) == len(old) + 1,
                  'graph-import-unreconciled')
        if verdicts and verdicts[0] == 'GRAPH_STORE_DUPLICATE':
            _need(selected in old and selected in new and len(old) == len(new)
                  and all(old[selected][key] == new[selected][key] for key in
                          ('documentFingerprint', 'payloadHash', 'signatureVerified', 'importedAt')),
                  'graph-duplicate-substituted')
    if failed and cutpoint == 'before-delegate':
        _need(not changed, 'graph-before-cutpoint-mutated')
    if failed and cutpoint == 'after-delegate':
        _need(len(changed) == 1, 'graph-after-cutpoint-unreconciled')
    _need(selected in r and r[selected]['signatureVerified']
          and all(r[key]['signatureVerified'] for key in changed | recovery_changed),
          'graph-recovery-invalid')
    return 'confirmed-persisted' if changed else 'confirmed-unchanged'


def _window(events, parent, reserved_at=None, committed_at=None):
    own, group = _route(events, parent, failed=any(e['kind'] == 'REQUEST_FAILED'
                                                 and e['operationId'] == parent for e in events))
    reserved = [e for e in group if e['kind'] == 'RATE_RESERVED'
                and e['operation'] == 'trust_graph_import']
    _need(len(reserved) == 2 and {e['scope'] for e in reserved} == {1, own[0]['scope']}
          and len({e['operationId'] for e in reserved}) == 1
          and len({e['windowStartEpochSecond'] for e in reserved}) == 1,
          'reservation-missing')
    import_id = reserved[0]['operationId']
    fetch_stages = [e for e in group if e['kind'] in {'FETCH_INVOKED', 'FETCH_SUCCEEDED'}]
    _need(len(fetch_stages) == 2 and owner._concurrency_covers(events, import_id, owner.IMPORT,
          own[0]['scope'], fetch_stages), 'reservation-fetch-lifetime-invalid')
    released = [e for e in group if e['kind'] == 'RATE_RESERVATION_RELEASED'
                and e['operationId'] == import_id]
    _need(len(released) == 2 and {_key(e) for e in released} == {_key(e) for e in reserved},
          'reservation-release-invalid')
    current = [e for e in group if e['operationId'] == import_id and e['kind'] in
               {'RATE_WRITE_ATTEMPT', 'RATE_LIMIT_REACHED'}]
    _need(current and all(e['operation'] == 'trust_graph_import' for e in current),
          'current-window-unobserved')
    w0, w1 = reserved[0]['windowStartEpochSecond'], current[0]['windowStartEpochSecond']
    _need(all(e['windowStartEpochSecond'] == w1 for e in current)
          and max(e['sequence'] for e in reserved) < min(e['sequence'] for e in released)
          and max(e['sequence'] for e in released) < min(e['sequence'] for e in current),
          'window-order-invalid')
    _need(fetch_stages[-1]['sequence'] < min(e['sequence'] for e in released),
          'reservation-released-before-fetch')
    if own[-1]['kind'] == 'REQUEST_FAILED':
        denials = [e for e in group if e['operationId'] == import_id
                   and e['kind'] == 'RATE_LIMIT_REACHED']
        _need(len(denials) == 1 and any(e['kind'] == 'BUDGET_RATE_DENIED'
              and e['operationId'] == import_id for e in group)
              and not any(e['kind'] == 'BUDGET_COMMITTED' and e['operationId'] == import_id
                          for e in group), 'window-denial-unconfirmed')
        denial = denials[0]
        _need(any(e['kind'] == 'RATE_CHARGED' and e['operationId'] != import_id
                  and _key(e) == _key(denial) and e['value'] == denial['value']
                  and reserved[-1]['sequence'] < e['sequence'] < denial['sequence']
                  for e in events), 'contested-window-consumption-missing')
    if reserved_at is not None:
        _need(int(_stamp(reserved_at)) // 3600 * 3600 == w0
              and int(_stamp(committed_at)) // 3600 * 3600 == w1, 'service-clock-substituted')
    return w0, w1


def derive_controlled(raw):
    """Verify a raw Java fixture export without treating test time as installed elapsed time."""
    base = {'caseId', 'evidenceClass', 'timeDomain', 'before', 'beforeLastSequence', 'after',
            'graphAfter', 'requestStatus', 'variant', 'nativeSnapshot', 'activeFamilyLeases',
            'reservedFamilyRates', 'selectedFingerprint'}
    case = raw.get('caseId') if isinstance(raw, dict) else None
    extra = ({'reservedAt', 'committedAt', 'contested', 'during', 'duringLastSequence'}
             if case == 'window-crossing' else
             {'cutPoint', 'failedLastSequence', 'recoveryAfter', 'graphRecovery', 'recoveryStatus'} |
             ({'failedWrite'} if case == 'partial-rate-write' else {'graphBefore'}))
    _closed(raw, base | extra)
    _need(len(json.dumps(raw, allow_nan=False).encode()) <= 1024 * 1024, 'byte-limit')
    _need(case in CASES and raw['evidenceClass'] == CONTROLLED
          and raw['timeDomain'] == 'service-clock-controlled-recorder-realtime'
          and raw['activeFamilyLeases'] == 0 and raw['reservedFamilyRates'] == 0,
          'controlled-binding-invalid')
    snapshot = raw['nativeSnapshot']
    _closed(snapshot, {'version', 'lastSequence', 'dropped', 'events', 'collectorEpoch'})
    _need(snapshot['version'] == 4 and snapshot['dropped'] == 0
          and re.fullmatch('[0-9a-f-]{36}', str(snapshot['collectorEpoch'])), 'snapshot-invalid')
    events = _events(snapshot['events'], raw['beforeLastSequence'], snapshot['lastSequence'],
                     controlled=True)
    _holds(events)
    starts, _ = _roots(events)
    _need(starts, 'native-request-missing')
    parent = starts[0]['operationId']
    before, after = (_rates(raw[key], controlled=True) for key in ('before', 'after'))
    uri = starts[0]['kind'] == 'COMPOSED_URI_IMPORT_START'
    if case == 'window-crossing':
        expected_variant = 'window-%d-%d-%s' % (int(_stamp(raw['reservedAt'])),
            int(_stamp(raw['committedAt'])), str(raw['contested']).lower())
    elif case == 'partial-rate-write':
        _need(type(raw['failedWrite']) is int and 1 <= raw['failedWrite'] <= (4 if uri else 2),
              'failed-position-invalid')
        expected_variant = 'rate-%s-%d-%s' % (str(uri).lower(), raw['failedWrite'],
            str(raw['cutPoint'] == 'after-delegate').lower())
    else:
        existing = _graph(raw['graphBefore'], True)
        expected_variant = 'graph-%s-%s-%s' % (str(uri).lower(),
            str(raw['cutPoint'] == 'after-delegate').lower(),
            str(raw['selectedFingerprint'] in existing).lower())
    _need(raw['variant'] == expected_variant, 'variant-substituted')
    observed, outcome = True, 'confirmed-persisted'
    if case == 'window-crossing':
        _need(type(raw['contested']) is bool and raw['requestStatus'] ==
              (429 if raw['contested'] else 200), 'request-status-invalid')
        w0, w1 = _window(events, parent, raw['reservedAt'], raw['committedAt'])
        during = _rates(raw['during'], controlled=True)
        split = raw['duringLastSequence']
        _ledger(before, during, [e for e in events if e['sequence'] <= split])
        _ledger(during, after, [e for e in events if e['sequence'] > split])
        attempts = [e for e in events if e['kind'] == 'RATE_WRITE_ATTEMPT']
        acknowledged = [e for e in events if e['kind'] == 'RATE_CHARGED']
        uncertain = []
        observed = w1 > w0
        outcome = 'safe-request-denial' if raw['contested'] else 'confirmed-persisted'
        selected_graph = _graph(raw['graphAfter'], True)
        _need(len(selected_graph) == (0 if raw['contested'] else 1)
              and (raw['contested'] or raw['selectedFingerprint'] in selected_graph),
              'graph-window-outcome-invalid')
    else:
        _need(raw['cutPoint'] in {'before-delegate', 'after-delegate'}
              and raw['requestStatus'] == 503 and raw['recoveryStatus'] == 200,
              'failure-phase-invalid')
        failed = [e for e in events if e['sequence'] <= raw['failedLastSequence']]
        recovery = [e for e in events if e['sequence'] > raw['failedLastSequence']]
        _need(failed and recovery, 'recovery-missing')
        attempts, acknowledged, uncertain = _ledger(before, after, failed, raw['cutPoint'])
        recovery_rates = _rates(raw['recoveryAfter'], controlled=True)
        _ledger(after, recovery_rates, recovery)
        recovery_starts, _ = _roots(recovery)
        _need(len(recovery_starts) == 1 and recovery_starts[0]['operationId'] != parent,
              'recovery-operation-invalid')
        _route(recovery, recovery_starts[0]['operationId'])
        own, group = _route(failed, parent, failed=True,
                            graph_failure=case == 'graph-store-unavailable')
        if case == 'partial-rate-write':
            _need(len(uncertain) == 1 and uncertain[0]['kind'] == 'RATE_WRITE_UNKNOWN'
                  and len(attempts) == raw['failedWrite']
                  and len(acknowledged) == raw['failedWrite'] - 1,
                  'failure-prefix-invalid')
            fault_id = uncertain[0]['operationId']
            _need(not any(e['kind'] == 'BUDGET_COMMITTED' and e['operationId'] == fault_id
                          for e in failed), 'failed-budget-committed')
            _need(not raw['graphAfter'], 'graph-after-budget-failure')
            outcome = 'partial-prefix' if before != after else 'confirmed-unchanged'
            _graph_reconcile([], [], raw['graphRecovery'], cutpoint='before-delegate',
                             failed=True, controlled=True, selected=raw['selectedFingerprint'],
                             initial_events=failed, recovery_events=recovery)
        else:
            _need(not uncertain and len(attempts) == len(acknowledged), 'budget-failure-misclassified')
            outcome = _graph_reconcile(raw['graphBefore'], raw['graphAfter'], raw['graphRecovery'],
                cutpoint=raw['cutPoint'], failed=True, controlled=True, selected=raw['selectedFingerprint'],
                initial_events=failed, recovery_events=recovery)
    return {'caseId': case, 'variant': raw['variant'], 'evidenceClass': CONTROLLED,
            'status': 'verified' if observed else 'control-verified', 'observed': observed,
            'postcondition': outcome,
            'attemptedWriteCount': len(attempts), 'acknowledgedWriteCount': len(acknowledged),
            'reconciledWriteCount': len(acknowledged) + sum(
                e['kind'] == 'RATE_WRITE_UNKNOWN' and after.get(_key(e), 0) == e['value']
                for e in uncertain),
            'requestOutcome': 'succeeded' if raw['requestStatus'] == 200 else
                              'rate-denied' if raw['requestStatus'] == 429 else 'failed',
            'recoveryOutcome': 'succeeded' if raw.get('recoveryStatus') == 200 else 'not-applicable',
            'originalAuthentication': 'not-established',
            'installedObservation': False, 'fullAppBudgets': 'not-observed',
            'releaseEligible': False}


def validate_writes(events):
    """Require one original attempt per acknowledgment/unknown, without inferring disk state."""
    pending = {}
    for event in events:
        kind = event['kind']
        if kind not in owner.STORAGE_KINDS | {'RATE_CHARGED'}:
            continue
        identity = event['operationId'], _key(event)
        _need(event['operationId'] > 0 and event['operation'] is not None and event['scope'] > 0,
              'write-identity-invalid')
        if kind in {'RATE_WRITE_ATTEMPT', 'RATE_METADATA_WRITE_ATTEMPT'}:
            _need(identity not in pending, 'write-attempt-duplicate')
            pending[identity] = event
        else:
            attempt = pending.pop(identity, None)
            _need(attempt is not None and attempt['value'] == event['value'], 'write-without-attempt')
            permitted = ({'RATE_CHARGED', 'RATE_WRITE_UNKNOWN'} if
                         attempt['kind'] == 'RATE_WRITE_ATTEMPT' else
                         {'RATE_METADATA_WRITTEN', 'RATE_METADATA_WRITE_UNKNOWN'})
            _need(kind in permitted, 'write-kind-substituted')
    _need(not pending, 'write-outcome-missing')


def _snapshot(raw):
    _closed(raw, {'sequence', 'budgetValid', 'droppedEvents', 'rates', 'holds', 'retainedStatements'})
    _need(pressure._number(raw['sequence']) and type(raw['budgetValid']) is bool
          and pressure._number(raw['droppedEvents'])
          and pressure._number(raw['retainedStatements']), 'snapshot-invalid')
    _need(raw['budgetValid'] or raw['rates'] is None, 'unknown-rates-not-null')
    rates = _rates(raw['rates']) if raw['budgetValid'] else None
    _need(isinstance(raw['holds'], list) and len(raw['holds']) <= 128, 'holds-invalid')
    holds = {}
    for row in raw['holds']:
        _closed(row, {'operationId', 'operation', 'scope', 'kind', 'count'})
        key = row['operationId'], row['operation'], row['scope'], row['kind']
        _need(all(pressure._number(row[k]) for k in ('operationId', 'scope', 'count'))
              and row['operationId'] > 0 and row['scope'] >= 1 and row['count'] == 1
              and row['operation'] in pressure.OPERATIONS - {None}
              and row['kind'] in {'rate', 'concurrency'} and key not in holds, 'holds-invalid')
        holds[key] = row['count']
    return rates, holds


def _receipt(receipt, case, generation):
    _closed(receipt, {'restriction', 'restoration'})
    restricted, restored = receipt['restriction'], receipt['restoration']
    common = {'caseId', 'phase', 'targetClass', 'before', 'after', 'generation', 'observedMonotonicNs'}
    _closed(restricted, common | {'roleUidDenied'})
    _closed(restored, common | {'contentsRestored'})
    for row, phase in ((restricted, 'restricted'), (restored, 'restored')):
        _need(row['caseId'] == case and row['targetClass'] == case and row['phase'] == phase
              and row['generation'] == generation and pressure._number(row['observedMonotonicNs']),
              'administrator-binding-invalid')
        for name in ('before', 'after'):
            _closed(row[name], {'device', 'inode', 'uid', 'gid', 'mode'})
            _need(all(pressure._number(value) for value in row[name].values())
                  and row[name]['uid'] > 0 and row[name]['mode'] <= 0o7777,
                  'administrator-target-invalid')
    original, denied = restricted['before'], restricted['after']
    _need(original['mode'] & 0o500 == 0o500 and bool(original['mode'] & 0o200)
          and denied == {**original, 'mode': original['mode'] & ~0o222}
          and restored['before'] == denied and restored['after'] == original
          and restricted['roleUidDenied'] is True and restored['contentsRestored'] is False
          and restored['observedMonotonicNs'] > restricted['observedMonotonicNs'],
          'administrator-restoration-invalid')


def _time_plan(plan, events, parent):
    _closed(plan, {'boundaryEpochSecond', 'startMarginSeconds', 'requestDeadlineMillis',
                   'selectedAtEpochSecond', 'observedReservationEpochSecond', 'releasedAtEpochSecond'})
    _need(all(type(v) in {int, float} and math.isfinite(v) and v >= 0 for v in plan.values()),
          'time-plan-invalid')
    boundary = plan['boundaryEpochSecond']
    _need(boundary % 3600 == 0 and plan['startMarginSeconds'] == 10
          and plan['requestDeadlineMillis'] == 45000
          and plan['selectedAtEpochSecond'] < boundary - 10
          <= plan['observedReservationEpochSecond'] < boundary
          <= plan['releasedAtEpochSecond'] < boundary + 35, 'time-plan-invalid')
    w0, w1 = _window(events, parent)
    _need(w0 == boundary - 3600 and w1 == boundary, 'import-hour-not-crossed')
    _, links = _roots(events)
    selected = [e for e in events if e['operationId'] == parent or links.get(e['operationId']) == parent]
    reservations = [e for e in selected if e['kind'] == 'RATE_RESERVED'
                    and e['operation'] == 'trust_graph_import']
    writes = [e for e in selected if e['kind'] == 'RATE_WRITE_ATTEMPT'
              and e['operation'] == 'trust_graph_import']
    _need(reservations and writes and all(boundary - 10 <= _stamp(e['observedAt']) < boundary
                                          for e in reservations)
          and max(_stamp(e['observedAt']) for e in reservations) <= plan['observedReservationEpochSecond']
          and all(_stamp(e['observedAt']) >= plan['releasedAtEpochSecond'] for e in writes)
          and _stamp(selected[-1]['observedAt']) - _stamp(selected[0]['observedAt']) <= 45
          and (selected[-1]['elapsedNanos'] - selected[0]['elapsedNanos']) / 1e9 <= 45,
          'real-boundary-unobserved')


def derive_cases(value, epochs, observation_time):
    """Derive the three fixed installed representatives; complete policy remains external."""
    rows = value['storageCases']
    _need(isinstance(rows, list) and len(rows) <= 3, 'case-limit')
    observed, seen_cases = set(), set()
    used_operations = {event['operationId'] for event in epochs.values() if event['operationId']}
    fields = {'caseId', 'variant', 'evidenceClass', 'operationId', 'collectorEpoch', 'nodeEpoch',
              'roleGeneration', 'before', 'during', 'after', 'recoveryAfter', 'events',
              'adminReceipt', 'timePlan', 'requestStatus', 'recoveryStatus',
              'graphBefore', 'graphAfter', 'graphRecovery', 'selectedFingerprint'}
    for row in rows:
        _closed(row, fields)
        case = row['caseId']
        _need(case in CASES and case not in seen_cases and row['evidenceClass'] == INSTALLED
              and row['collectorEpoch'] == value['collectorEpoch']
              and row['nodeEpoch'] == value['nodeEpoch']
              and type(row['operationId']) is int and row['operationId'] > 0
              and isinstance(row['roleGeneration'], str)
              and re.fullmatch('[0-9a-f]{64}', row['roleGeneration']),
              'case-binding-invalid')
        seen_cases.add(case)
        snapshots = {name: _snapshot(row[name]) for name in
                     ('before', 'during', 'after', 'recoveryAfter')}
        start, split, end = (row[name]['sequence'] for name in ('before', 'after', 'recoveryAfter'))
        _need(start <= row['during']['sequence'] <= split < end, 'snapshot-order-invalid')
        events = _events(row['events'], start, end, epochs=epochs, epoch=row['collectorEpoch'],
                         observation_time=observation_time)
        ids = {e['operationId'] for e in events if e['operationId']}
        _need(not ids & used_operations, 'operation-replayed')
        used_operations |= ids
        validate_writes(events)
        # Unknown means incomplete evidence, never an empty map or a successful resilience result.
        if any(rates is None or row[name]['droppedEvents'] for name, (rates, _) in snapshots.items()):
            continue
        before, after, recovery_after = (snapshots[name][0] for name in
                                        ('before', 'after', 'recoveryAfter'))
        failed = [e for e in events if e['sequence'] <= split]
        recovery = [e for e in events if e['sequence'] > split]
        _need(not snapshots['before'][1] and not snapshots['after'][1]
              and not snapshots['recoveryAfter'][1], 'foreign-holds-present')
        _holds(events, checkpoints={row[name]['sequence']: snapshots[name][1]
                                   for name in snapshots})
        cutpoint = None if case == 'window-crossing' else 'before-delegate'
        attempts, acknowledgments, unknown = _ledger(before, after, failed, cutpoint)
        _ledger(after, recovery_after, recovery)
        during_events = [e for e in failed if e['sequence'] <= row['during']['sequence']]
        _ledger(before, snapshots['during'][0], during_events)
        all_roots, all_links = _roots(events)
        _need(ids <= {e['operationId'] for e in all_roots} | set(all_links),
              'unattributed-operation')
        roots, _ = _roots(failed)
        _need(len(roots) == 1 and roots[0]['operationId'] == row['operationId'],
              'primary-operation-invalid')
        recovery_roots, _ = _roots(recovery)
        _need(len(recovery_roots) == 1 and row['recoveryStatus'] == 200,
              'recovery-unobserved')
        _route(recovery, recovery_roots[0]['operationId'])
        parent = row['operationId']
        if case == 'window-crossing':
            _need(row['variant'] == 'available-capacity' and row['adminReceipt'] is None
                  and row['requestStatus'] == 200 and not unknown, 'window-variant-invalid')
            _time_plan(row['timePlan'], failed, parent)
            _graph_reconcile(row['graphBefore'], row['graphAfter'], row['graphRecovery'],
                              cutpoint=None, failed=False, controlled=False, selected=row['selectedFingerprint'],
                              initial_events=failed, recovery_events=recovery)
        else:
            _need(row['variant'] == 'direct-readable-directory-denial'
                  and row['timePlan'] is None and row['requestStatus'] == 503,
                  'filesystem-variant-invalid')
            _receipt(row['adminReceipt'], case, row['roleGeneration'])
            _need(roots[0]['kind'] == 'COMPOSED_DIRECT_IMPORT_START', 'filesystem-route-invalid')
            _route(failed, parent, failed=True, graph_failure=case == 'graph-store-unavailable')
            _graph_reconcile(row['graphBefore'], row['graphAfter'], row['graphRecovery'],
                              cutpoint='before-delegate', failed=True, controlled=False, selected=row['selectedFingerprint'],
                              initial_events=failed, recovery_events=recovery)
            if case == 'partial-rate-write':
                _need(len(attempts) == 2 and len(acknowledgments) == 1 and len(unknown) == 1
                      and unknown[0]['kind'] == 'RATE_WRITE_UNKNOWN'
                      and unknown[0]['scope'] == 1
                      and not any(e['kind'] == 'BUDGET_COMMITTED' for e in failed),
                      'partial-prefix-invalid')
            else:
                _need(len(attempts) == 2 and len(acknowledgments) == 2 and not unknown,
                      'graph-budget-unconfirmed')
        for name, graph in (('before', row['graphBefore']), ('after', row['graphAfter']),
                            ('recoveryAfter', row['graphRecovery'])):
            _need(row[name]['retainedStatements'] == len(graph), 'graph-count-substituted')
        observed.add(case)
    return observed


def derive_variants(value, observation_time=None):
    """Public-safe exact installed direction report, independent of broader case coverage."""
    observed = derive_cases(value, {}, observation_time)
    verified = [{'caseId': row['caseId'], 'variant': row['variant'], 'evidenceClass': INSTALLED,
                 'resilienceOutcome': 'verified',
                 'requestOutcome': 'succeeded' if row['requestStatus'] == 200 else 'failed',
                 'recoveryOutcome': 'succeeded'}
                for row in value['storageCases'] if row['caseId'] in observed]
    missing = [{'caseId': case, 'variant': variant} for case, variant in (
        ('window-crossing', 'available-capacity'), ('window-crossing', 'contested-capacity'),
        ('partial-rate-write', 'direct-readable-directory-denial'),
        ('partial-rate-write', 'uri-child-write-denial'),
        ('partial-rate-write', 'uri-import-commit-denial'),
        ('graph-store-unavailable', 'direct-readable-directory-denial'),
        ('graph-store-unavailable', 'uri-readable-directory-denial'))
        if not any(row['caseId'] == case and row['variant'] == variant for row in verified)]
    return {'evidenceClass': INSTALLED, 'verifiedVariants': verified,
            'unobservedVariants': missing, 'fullAppBudgets': 'not-observed',
            'originalAuthentication': 'not-established', 'releaseEligible': False}
