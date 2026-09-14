"""Finite native composed-budget observations, independent of resource-baseline authority.

Inputs are private original observations. This verifier establishes local consistency only;
original producer authentication remains with the existing journal/supervisor owner.
"""
from __future__ import annotations
import json
import re

from . import runtime_pressure_evidence as pressure

COMPOSED_KINDS = frozenset(('COMPOSED_DIRECT_IMPORT_START COMPOSED_PASTED_PREVIEW_START '
    'COMPOSED_URI_PREVIEW_START COMPOSED_URI_IMPORT_START COMPOSED_CHILD '
    'PARSE_SUCCEEDED PARSE_FAILED FINGERPRINT_ACCEPTED FINGERPRINT_REJECTED '
    'GRAPH_STORE_ATTEMPT GRAPH_STORE_IMPORTED GRAPH_STORE_DUPLICATE GRAPH_STORE_UNVERIFIED '
    'GRAPH_STORE_UNKNOWN REQUEST_SUCCEEDED REQUEST_FAILED FETCH_TERMINATION_UNKNOWN PREVIEW_BUILT CONTENT_URI_REJECTED CONTENT_BYTES_REJECTED CONTENT_UTF8_REJECTED FETCH_TIMEOUT RATE_LIMIT_REACHED').split())
# This policy cannot be reduced by a caller choosing an easier subset.
REQUIRED_CASES = tuple(('direct-valid direct-malformed pasted-preview-valid uri-preview-valid '
    'uri-preview-malformed uri-valid uri-malformed uri-fingerprint-mismatch uri-duplicate '
    'authorization-denied app-import-rate global-import-rate import-concurrency '
    'app-fetch-rate global-fetch-rate fetch-concurrency shared-foreground shared-subscription '
    'invalid-uri invalid-utf8 oversized timeout cancellation retry window-crossing '
    'partial-rate-write graph-store-unavailable graceful-restart abrupt-restart '
    'diagnostics-unavailable privacy').split())
ROUTES = {'direct-valid': 'DIRECT_IMPORT', 'direct-malformed': 'DIRECT_IMPORT',
          'pasted-preview-valid': 'PASTED_PREVIEW', 'uri-preview-valid': 'URI_PREVIEW',
          'uri-preview-malformed': 'URI_PREVIEW', 'uri-valid': 'URI_IMPORT',
          'uri-malformed': 'URI_IMPORT', 'uri-fingerprint-mismatch': 'URI_IMPORT',
          'uri-duplicate': 'URI_IMPORT', 'invalid-uri': 'URI_IMPORT',
          'invalid-utf8': 'URI_IMPORT', 'oversized': 'URI_IMPORT'}
EARLY_FAILURES = {'invalid-uri': 'CONTENT_URI_REJECTED',
                  'invalid-utf8': 'CONTENT_UTF8_REJECTED', 'oversized': 'CONTENT_BYTES_REJECTED'}
IMPORT = {('trust_graph_import', 'app'), ('trust_graph_import', 'global')}
FETCH = {('foreground_content_fetch', 'app'), ('content_fetch_global', 'global')}


class ComposedEvidenceError(ValueError):
    """Fixed public error, never interpolated source data."""


def _closed(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ComposedEvidenceError('composed-budget-fields-invalid')


def _concurrency_covers(events, operation_id, families, scope, stages):
    """Each owner's family interval must enclose its protected work, not merely balance."""
    owned = [event for event in events if event['operationId'] == operation_id]
    protected = list(stages) + [event for event in owned
                               if event['kind'] in {'BUDGET_RESERVED', 'BUDGET_COMMITTED'}]
    released = [event for event in owned if event['kind'] == 'BUDGET_RELEASED']
    if not protected or len(released) != 1:
        return False
    first = min(event['sequence'] for event in protected)
    last = max(event['sequence'] for event in protected)
    for family, owner in families:
        selected_scope = 1 if owner == 'global' else scope
        held = [event for event in owned if event['kind'] == 'CONCURRENCY_HELD'
                and event['operation'] == family and event['scope'] == selected_scope]
        closed = [event for event in owned if event['kind'] == 'CONCURRENCY_RELEASED'
                  and event['operation'] == family and event['scope'] == selected_scope]
        if (len(held) != 1 or len(closed) != 1
                or not held[0]['sequence'] < first <= last < closed[0]['sequence'] < released[0]['sequence']):
            return False
    return True


def _import_concurrency_covers(events, parent, scope):
    """Import capacity encloses parsing/store work and the separately budgeted URI child."""
    owners = {event['operationId'] for event in events
              if event['kind'] == 'CONCURRENCY_HELD' and event['operation'] == 'trust_graph_import'}
    if len(owners) != 1:
        return False
    owner = next(iter(owners))
    stages = [event for event in events if (
        event['operationId'] == parent and event['kind'].startswith(
            ('PARSE_', 'FINGERPRINT_', 'GRAPH_STORE_', 'PREVIEW_', 'CONTENT_', 'FETCH_'))
        or event['operationId'] not in {parent, owner} and event['kind'] != 'COMPOSED_CHILD')]
    return _concurrency_covers(events, owner, IMPORT, scope, stages)


def _complete_rate_delta(snapshots, deltas):
    """Complete snapshots must explain every changed key, including previously absent families."""
    before, after = snapshots
    for key, count in deltas.items():
        if after.get(key) != before.get(key, 0) + count:
            return False
    for key, count in after.items():
        if key not in deltas and (key not in before or before[key] != count):
            return False
    for key, count in before.items():
        if key in after:
            continue
        # The store retains one window per family. Replacing its prior window is not a refund.
        if not any(replacement[:2] == key[:2] and replacement[2] > key[2] for replacement in deltas):
            return False
    return True


def _rate_denial(segment, snapshots):
    """Actual denying family is observed natively, not inferred from the caller's case label."""
    case, parent, scope = segment['caseId'], segment['operationId'], segment['scope']
    events = segment['events']
    root = [event for event in events if event['operationId'] == parent]
    if ([event['kind'] for event in root] != ['COMPOSED_URI_IMPORT_START', 'REQUEST_FAILED']
            or any(event['scope'] != scope for event in root)
            or snapshots[0] != snapshots[1] or segment['graphBefore'] != segment['graphAfter']):
        return False
    links = [event for event in events if event['kind'] == 'COMPOSED_CHILD' and event['value'] == parent]
    ids = {event['operationId'] for event in links}
    if (len(ids) != (2 if 'fetch' in case else 1) or parent in ids or len(ids) != len(links)
            or any(event['scope'] != scope for event in links)):
        return False
    group = [event for event in events if event['operationId'] in ids]
    if any(event['kind'].startswith(('FETCH_', 'GRAPH_', 'PARSE_')) or event['kind'] in
           {'RATE_CHARGED', 'BUDGET_COMMITTED'} for event in group):
        return False
    denied = [event for event in group if event['kind'] == 'RATE_LIMIT_REACHED']
    if len(denied) != 1:
        return False
    reached = denied[0]
    expected_operation = ('trust_graph_import' if 'import' in case else
                          'content_fetch_global' if case.startswith('global') else 'foreground_content_fetch')
    expected_scope = 1 if case.startswith('global') else scope
    key = expected_operation, expected_scope, reached['windowStartEpochSecond']
    if (reached['operation'] != expected_operation or reached['scope'] != expected_scope
            or reached['windowStartEpochSecond'] <= 0 or reached['value'] != snapshots[0].get(key)
            or not any(event['kind'] == 'BUDGET_RATE_DENIED'
                       and event['operationId'] == reached['operationId']
                       and event['sequence'] > reached['sequence'] for event in group)):
        return False
    holds = {}
    acquired = set()
    for event in group:
        if not root[0]['sequence'] < event['sequence'] < root[-1]['sequence']:
            return False
        for start, finish in (('CONCURRENCY_HELD', 'CONCURRENCY_RELEASED'),
                              ('RATE_RESERVED', 'RATE_RESERVATION_RELEASED')):
            key = start, event['operationId'], event['operation'], event['scope'], event['windowStartEpochSecond']
            if event['kind'] == start:
                holds[key] = holds.get(key, 0) + 1
                acquired.add((start, event['operation'], 'global' if event['scope'] == 1 else 'app'))
            if event['kind'] == finish:
                holds[key] = holds.get(key, 0) - 1
                if holds[key] < 0:
                    return False
    expected = {(kind, family, owner) for kind in ('CONCURRENCY_HELD', 'RATE_RESERVED')
                for family, owner in IMPORT} if 'fetch' in case else set()
    reserved_ids = {event['operationId'] for event in group if event['kind'] == 'BUDGET_RESERVED'}
    released_ids = {event['operationId'] for event in group if event['kind'] == 'BUDGET_RELEASED'}
    return (not any(holds.values()) and acquired == expected and reserved_ids <= released_ids
            and len(reserved_ids) == (1 if 'fetch' in case else 0)
            and ('fetch' not in case or _import_concurrency_covers(events, parent, scope)))


def _interference(segment, snapshots):
    """Fixed multi-operation interval proves a successful owner interferes with URI admission."""
    case, events = segment['caseId'], segment['events']
    expected_count = 2 if case == 'shared-foreground' else 1
    expected_operation = ('foreground_content_fetch' if case == 'shared-foreground'
                          else 'subscription_manual_refresh')
    expected_families = FETCH if case == 'shared-foreground' else {
        ('subscription_poll', 'app'), ('subscription_poll', 'global'), ('content_fetch_global', 'global')}
    commits = [event for event in events if event['kind'] == 'BUDGET_COMMITTED']
    if (len(commits) != expected_count or any(event['operation'] != expected_operation for event in commits)
            or segment['graphBefore'] != segment['graphAfter']
            or any(event['kind'].startswith('GRAPH_STORE_') for event in events)):
        return False
    admitted_ids = {event['operationId'] for event in commits}
    acquisition_kind = 'BUDGET_ACQUIRE' if case == 'shared-foreground' else 'BUDGET_RESERVE'
    acquisitions = [event for event in events if event['kind'] == acquisition_kind
                    and event['operationId'] in admitted_ids]
    if (len(acquisitions) != expected_count or not acquisitions
            or acquisitions[0]['operationId'] != segment['operationId']
            or any(event['scope'] != segment['scope'] for event in acquisitions)):
        return False
    charges = [event for event in events if event['kind'] == 'RATE_CHARGED']
    expected_deltas = {}
    for operation_id in admitted_ids:
        group = [event for event in events if event['operationId'] == operation_id]
        operation_charges = [event for event in group if event['kind'] == 'RATE_CHARGED']
        families = [(event['operation'], 'global' if event['scope'] == 1 else 'app')
                    for event in operation_charges]
        invoked = [event for event in group if event['kind'] == 'FETCH_INVOKED']
        succeeded = [event for event in group if event['kind'] == 'FETCH_SUCCEEDED']
        released = [event for event in group if event['kind'] == 'BUDGET_RELEASED']
        if (set(families) != expected_families or len(families) != len(expected_families)
                or len(invoked) != 1 or len(succeeded) != 1 or len(released) != 1
                or not invoked[0]['sequence'] < succeeded[0]['sequence'] < released[0]['sequence']
                or any(event['kind'] in {'FETCH_FAILED', 'FETCH_TERMINATION_UNKNOWN'} for event in group)):
            return False
        if not _concurrency_covers(events, operation_id, expected_families,
                                   segment['scope'], invoked + succeeded):
            return False
        before = {}
        holds = {}
        rate_holds = {}
        for event in group:
            key = event['operation'], event['scope'], event['windowStartEpochSecond']
            if event['kind'] == 'RATE_OBSERVED':
                before[key] = event['value']
            if event['kind'] == 'RATE_CHARGED':
                window = 3600 if event['operation'] == 'subscription_poll' else 60
                if (key not in before or event['value'] != before[key] + 1
                        or key[2] <= 0 or key[2] % window
                        or event['scope'] not in {1, segment['scope']}):
                    return False
                expected_deltas[key] = expected_deltas.get(key, 0) + 1
            if event['kind'] == 'RATE_RESERVED':
                rate_holds[key] = rate_holds.get(key, 0) + 1
            if event['kind'] == 'RATE_RESERVATION_RELEASED':
                rate_holds[key] = rate_holds.get(key, 0) - 1
                if rate_holds[key] < 0:
                    return False
            if event['kind'] == 'CONCURRENCY_HELD':
                holds[key] = holds.get(key, 0) + 1
            if event['kind'] == 'CONCURRENCY_RELEASED':
                holds[key] = holds.get(key, 0) - 1
                if holds[key] < 0:
                    return False
        if any(rate_holds.values()) or any(holds.values()) or {(key[0], 'global' if key[1] == 1 else 'app') for key in holds} != expected_families:
            return False
    if len(charges) != expected_count * len(expected_families):
        return False
    if not _complete_rate_delta(snapshots, expected_deltas):
        return False
    starts = [event for event in events if event['kind'] == 'COMPOSED_URI_IMPORT_START']
    if len(starts) != 1:
        return False
    parent = starts[0]
    ends = [event for event in events if event['operationId'] == parent['operationId']
            and event['kind'] == 'REQUEST_FAILED']
    if len(ends) != 1 or parent['scope'] != segment['scope']:
        return False
    if max(event['sequence'] for event in events if event['operationId'] in admitted_ids) >= parent['sequence']:
        return False
    denied_segment = dict(segment, caseId='app-fetch-rate' if case == 'shared-foreground' else 'global-fetch-rate',
        operationId=parent['operationId'], scope=parent['scope'],
        events=[event for event in events if parent['sequence'] <= event['sequence'] <= ends[0]['sequence']])
    if not _rate_denial(denied_segment, [snapshots[1], snapshots[1]]):
        return False
    reached = next(event for event in denied_segment['events'] if event['kind'] == 'RATE_LIMIT_REACHED')
    shared_key = reached['operation'], reached['scope'], reached['windowStartEpochSecond']
    return shared_key in expected_deltas


def derive(value, *, workload_digest, product_digest, source_commit, app_cohort_digest,
           observation_time=None, node_epoch=None, collector_digest=None, configuration_digest=None):
    """Recompute observed route accounting; missing hard cases remain explicitly missing."""
    fields = {'schemaVersion', 'workloadDigest', 'productDigest', 'sourceCommit',
              'appCohortDigest', 'collectorDigest', 'configurationDigest', 'segments'}
    version = value.get('schemaVersion') if isinstance(value, dict) else None
    if version == 2:
        fields |= {'collectorEpoch', 'nodeEpoch'}
    _closed(value, fields)
    if version == 2 and (not re.fullmatch('[0-9a-f-]{36}', str(value['collectorEpoch']))
            or not re.fullmatch('[0-9a-f]{32}', str(value['nodeEpoch']))
            or node_epoch is not None and value['nodeEpoch'] != node_epoch):
        raise ComposedEvidenceError('composed-budget-process-epoch-mismatch')
    if node_epoch is not None and version != 2:
        raise ComposedEvidenceError('composed-budget-original-process-binding-required')
    if node_epoch is not None and (collector_digest is None or configuration_digest is None):
        raise ComposedEvidenceError('composed-budget-original-input-binding-required')
    if any(expected is not None and value[key] != expected for key, expected in
           (('collectorDigest', collector_digest), ('configurationDigest', configuration_digest))):
        raise ComposedEvidenceError('composed-budget-original-input-substitution')
    if (type(value['schemaVersion']) is not int or value['schemaVersion'] not in {1, 2}
            or any(value[key] != expected for key, expected in (
                ('workloadDigest', workload_digest), ('productDigest', product_digest),
                ('sourceCommit', source_commit), ('appCohortDigest', app_cohort_digest)))
            or any(not pressure.baseline.DIGEST.fullmatch(str(value[key])) for key in (
                'workloadDigest', 'productDigest', 'appCohortDigest', 'collectorDigest', 'configurationDigest'))
            or not re.fullmatch('[0-9a-f]{40}', str(source_commit))):
        raise ComposedEvidenceError('composed-budget-binding-invalid')
    if len(json.dumps(value, allow_nan=False).encode()) > 1024 * 1024:
        raise ComposedEvidenceError('composed-budget-byte-limit')
    segments = value['segments']
    if not isinstance(segments, list) or len(segments) > 64:
        raise ComposedEvidenceError('composed-budget-segment-limit')
    seen, epochs, observed, child_owners = set(), {}, set(), {}
    for segment in segments:
        _closed(segment, ('caseId', 'collectorEpoch', 'operationId', 'scope', 'budgetValid',
                          'droppedEvents', 'events', 'beforeRates', 'afterRates', 'graphBefore', 'graphAfter'))
        case, epoch, parent, scope = (segment[key] for key in
                                     ('caseId', 'collectorEpoch', 'operationId', 'scope'))
        if (case not in REQUIRED_CASES or not isinstance(epoch, str)
                or not re.fullmatch('[0-9a-f-]{36}', epoch)
                or type(parent) is not int or parent < 1 or type(scope) is not int or scope < (3 if version == 2 else 2)
                or type(segment['budgetValid']) is not bool
                or not pressure._number(segment['droppedEvents'])
                or (epoch, parent) in seen):
            raise ComposedEvidenceError('composed-budget-segment-binding-invalid')
        if version == 2 and epoch != value['collectorEpoch']:
            raise ComposedEvidenceError('composed-budget-collector-epoch-mismatch')
        seen.add((epoch, parent))
        snapshots = []
        for name in ('beforeRates', 'afterRates'):
            rows = segment[name]
            if not isinstance(rows, list) or len(rows) > 4096:
                raise ComposedEvidenceError('composed-budget-rate-snapshot-invalid')
            mapped = {}
            for row in rows:
                _closed(row, ('operation', 'scope', 'windowStartEpochSecond', 'count'))
                key = (row['operation'], row['scope'], row['windowStartEpochSecond'])
                if (row['operation'] not in pressure.OPERATIONS - {None}
                        or any(not pressure._number(row[k]) for k in ('scope', 'windowStartEpochSecond', 'count'))
                        or key in mapped):
                    raise ComposedEvidenceError('composed-budget-rate-snapshot-invalid')
                mapped[key] = row['count']
            snapshots.append(mapped)
        for name in ('graphBefore', 'graphAfter'):
            _closed(segment[name], ('retainedStatements',))
            if not pressure._number(segment[name]['retainedStatements']):
                raise ComposedEvidenceError('composed-budget-graph-snapshot-invalid')
        events = segment['events']
        if not isinstance(events, list) or len(events) > 4096:
            raise ComposedEvidenceError('composed-budget-event-limit')
        previous = None
        for event in events:
            _closed(event, pressure.EVENT_FIELDS)
            if (event['kind'] not in pressure.KINDS | COMPOSED_KINDS
                    or event['operation'] not in pressure.OPERATIONS
                    or any(not pressure._number(event[key]) for key in pressure.EVENT_FIELDS -
                           {'observedAt', 'kind', 'operation', 'sourceEpoch'})
                    or event['sequence'] < 1 or event['sourceEpoch'] is not None and
                       not re.fullmatch('[a-zA-Z0-9._-]{1,96}', str(event['sourceEpoch']))):
                raise ComposedEvidenceError('composed-budget-event-invalid')
            if event['kind'].startswith(('RATE_', 'CONCURRENCY_')) and (
                    event['operation'] is None or event['scope'] < 1):
                raise ComposedEvidenceError('composed-budget-family-scope-invalid')
            stamp = pressure.baseline._time(event['observedAt'])
            window = event['windowStartEpochSecond']
            seconds = 3600 if event['operation'] in {'subscription_poll', 'subscription_manual_refresh', 'trust_graph_import'} else 60
            if window and (window % seconds or window > stamp.timestamp()):
                raise ComposedEvidenceError('composed-budget-rate-window-invalid')
            if (observation_time is not None and stamp > pressure.baseline._time(observation_time)
                    or previous and (event['sequence'] != previous['sequence'] + 1
                        or event['elapsedNanos'] < previous['elapsedNanos']
                        or stamp < pressure.baseline._time(previous['observedAt']))):
                raise ComposedEvidenceError('composed-budget-event-order-invalid')
            identity = (epoch, event['sequence'])
            if identity in epochs and epochs[identity] != event:
                raise ComposedEvidenceError('composed-budget-event-substituted')
            epochs[identity] = event
            previous = event
        if not segment['budgetValid'] or segment['droppedEvents']:
            continue
        if case == 'authorization-denied':
            root = [event for event in events if event['operationId'] == parent]
            kinds = [event['kind'] for event in root]
            starts = {'COMPOSED_' + route + '_START' for route in set(ROUTES.values())}
            if (len(kinds) == 3 and kinds[0] in starts
                    and kinds[1:] == ['CAPABILITY_DENIED', 'REQUEST_FAILED']
                    and all(event['scope'] == scope for event in root)
                    and not any(event['kind'] == 'COMPOSED_CHILD' and event['value'] == parent for event in events)
                    and snapshots[0] == snapshots[1]
                    and segment['graphBefore'] == segment['graphAfter']):
                observed.add(case)
            continue
        if case in {'shared-foreground', 'shared-subscription'}:
            if _interference(segment, snapshots):
                observed.add(case)
            continue
        if case in {'app-import-rate', 'global-import-rate', 'app-fetch-rate', 'global-fetch-rate'}:
            if _rate_denial(segment, snapshots):
                observed.add(case)
            continue
        if case not in ROUTES:
            continue
        root = [event for event in events if event['operationId'] == parent]
        kinds = [event['kind'] for event in root]
        start = 'COMPOSED_' + ROUTES[case] + '_START'
        if kinds.count(start) != 1 or sum(kinds.count(k) for k in ('REQUEST_SUCCEEDED', 'REQUEST_FAILED')) != 1:
            continue
        links = [event for event in events if event['kind'] == 'COMPOSED_CHILD' and event['value'] == parent]
        for link in links:
            child = (epoch, link['operationId'])
            if link['operationId'] == parent or child_owners.setdefault(child, parent) != parent:
                raise ComposedEvidenceError('composed-budget-child-rebound')
        if len({link['operationId'] for link in links}) != len(links):
            raise ComposedEvidenceError('composed-budget-child-replayed')
        ids = {parent} | {event['operationId'] for event in links}
        group = [event for event in events if event['operationId'] in ids]
        if any(event['scope'] not in (0, 1, scope) for event in group):
            continue
        charges = [event for event in group if event['kind'] == 'RATE_CHARGED']
        expected = set(IMPORT)
        if ROUTES[case].startswith('URI'):
            expected |= FETCH
        if case == 'uri-preview-malformed' or case in EARLY_FAILURES:
            expected = set() if case == 'invalid-uri' else set(FETCH)
        actual = [(event['operation'], 'global' if event['scope'] == 1 else 'app') for event in charges]
        if set(actual) != expected or len(actual) != len(expected):
            continue
        # Valid complete store enumeration establishes absence in the current fixed window.
        # An unavailable diagnostic never reaches this branch; another window is not a refund.
        if any((event['operation'], event['scope'], event['windowStartEpochSecond']) not in snapshots[1]
                or snapshots[1][(event['operation'], event['scope'], event['windowStartEpochSecond'])]
                   != snapshots[0].get((event['operation'], event['scope'], event['windowStartEpochSecond']), 0) + 1
                or snapshots[1][(event['operation'], event['scope'], event['windowStartEpochSecond'])] != event['value']
                for event in charges):
            continue
        deltas = {(event['operation'], event['scope'], event['windowStartEpochSecond']): 1
                  for event in charges}
        if not _complete_rate_delta(snapshots, deltas):
            continue
        balanced, holds, before = True, {}, {}
        for event in group:
            key = (event['operationId'], event['operation'], event['scope'], event['windowStartEpochSecond'])
            kind = event['kind']
            if kind == 'RATE_OBSERVED':
                before[key] = event['value']
            if kind == 'RATE_CHARGED':
                window = 3600 if event['operation'] == 'trust_graph_import' else 60
                balanced &= (key in before and event['value'] == before[key] + 1
                             and event['windowStartEpochSecond'] > 0
                             and event['windowStartEpochSecond'] % window == 0)
            for acquire, release in (('CONCURRENCY_HELD', 'CONCURRENCY_RELEASED'),
                                     ('RATE_RESERVED', 'RATE_RESERVATION_RELEASED')):
                hold = (acquire, key)
                if kind == acquire:
                    holds[hold] = holds.get(hold, 0) + 1
                if kind == release:
                    holds[hold] = holds.get(hold, 0) - 1
                    balanced &= holds[hold] >= 0
        if not balanced or any(holds.values()):
            continue
        acquired = [(event['operation'], 'global' if event['scope'] == 1 else 'app')
                    for event in group if event['kind'] == 'CONCURRENCY_HELD']
        expected_holds = set(IMPORT)
        if ROUTES[case].startswith('URI') and case != 'invalid-uri':
            expected_holds |= FETCH
        if set(acquired) != expected_holds or len(acquired) != len(expected_holds):
            continue
        admitted_ids = {event['operationId'] for event in group if event['kind'] in
                        {'BUDGET_RESERVED', 'BUDGET_COMMITTED'}}
        released_ids = {event['operationId'] for event in group if event['kind'] == 'BUDGET_RELEASED'}
        if not admitted_ids or not admitted_ids <= released_ids:
            continue
        if not _import_concurrency_covers(group, parent, scope):
            continue
        if ROUTES[case].startswith('URI') and case != 'invalid-uri':
            fetch = [event for event in group if event['kind'] == 'FETCH_INVOKED']
            if len(fetch) != 1:
                continue
            completed = [event for event in group
                         if event['operationId'] == fetch[0]['operationId']
                         and event['kind'] in {'FETCH_SUCCEEDED', 'FETCH_FAILED'}]
            if (len(completed) != 1 or completed[0]['sequence'] <= fetch[0]['sequence']
                    or case != 'oversized' and completed[0]['kind'] != 'FETCH_SUCCEEDED'
                    or not _concurrency_covers(group, fetch[0]['operationId'], FETCH,
                                               scope, fetch + completed)):
                continue
        # Case names are policy inputs, never verdicts. Check each native stage and its order.
        terminal = 'REQUEST_FAILED' if case in {'direct-malformed', 'uri-preview-malformed',
            'uri-malformed', 'uri-fingerprint-mismatch'} | set(EARLY_FAILURES) else 'REQUEST_SUCCEEDED'
        if kinds[-1] != terminal:
            continue
        if case in EARLY_FAILURES:
            if EARLY_FAILURES[case] not in kinds or any(kind.startswith(('PARSE_', 'GRAPH_STORE_', 'FINGERPRINT_')) for kind in kinds):
                continue
            if case == 'invalid-uri' and any(event['kind'] == 'FETCH_INVOKED' for event in group):
                continue
        malformed = case in {'direct-malformed', 'uri-preview-malformed', 'uri-malformed'}
        if malformed and ('PARSE_FAILED' not in kinds or 'PARSE_SUCCEEDED' in kinds):
            continue
        if not malformed and case not in EARLY_FAILURES and ROUTES[case] != 'PASTED_PREVIEW' and ('PARSE_SUCCEEDED' not in kinds or 'PARSE_FAILED' in kinds):
            continue
        if case == 'uri-fingerprint-mismatch' and ('FINGERPRINT_REJECTED' not in kinds
                or 'FINGERPRINT_ACCEPTED' in kinds):
            continue
        if case != 'uri-fingerprint-mismatch' and 'FINGERPRINT_REJECTED' in kinds:
            continue
        if (malformed or case == 'uri-fingerprint-mismatch' or 'PREVIEW' in ROUTES[case]) and any(
                kind.startswith('GRAPH_STORE_') for kind in kinds):
            continue
        if 'FETCH_TERMINATION_UNKNOWN' in [event['kind'] for event in group]:
            continue
        commits = [event for event in group if event['kind'] == 'BUDGET_COMMITTED'
                   and event['operation'] == 'trust_graph_import']
        parse = next((event for event in root if event['kind'] in {'PARSE_SUCCEEDED', 'PARSE_FAILED'}), None)
        if ROUTES[case] == 'PASTED_PREVIEW':
            parse = next((event for event in root if event['kind'] == 'PREVIEW_BUILT'), None)
        if expected & IMPORT and (len(commits) != 1 or parse is None):
            continue
        if commits and parse:
            if ROUTES[case] == 'URI_PREVIEW':
                if parse['sequence'] >= commits[0]['sequence']:
                    continue
            elif commits[0]['sequence'] >= parse['sequence']:
                continue
        if ROUTES[case].startswith('URI') and parse:
            if completed[0]['sequence'] >= parse['sequence']:
                continue
            if ROUTES[case] == 'URI_IMPORT' and commits and completed[0]['sequence'] >= commits[0]['sequence']:
                continue
        success = case in {'direct-valid', 'uri-valid', 'uri-duplicate'}
        if success and not ('GRAPH_STORE_ATTEMPT' in kinds and any(k in kinds for k in
                ('GRAPH_STORE_IMPORTED', 'GRAPH_STORE_DUPLICATE', 'GRAPH_STORE_UNVERIFIED'))):
            continue
        if success:
            attempt = kinds.index('GRAPH_STORE_ATTEMPT')
            verdicts = [k for k in kinds if k in {'GRAPH_STORE_IMPORTED', 'GRAPH_STORE_DUPLICATE'}]
            if len(verdicts) != 1 or attempt >= kinds.index(verdicts[0]) or kinds.index('PARSE_SUCCEEDED') >= attempt:
                continue
            if case == 'uri-duplicate' and verdicts[0] != 'GRAPH_STORE_DUPLICATE':
                continue
        if terminal == 'REQUEST_SUCCEEDED':
            # Require the complete native route, including stages with no graph-count effect.
            # Exact ordering also rejects duplicate or contradictory stage observations.
            if ROUTES[case] == 'PASTED_PREVIEW':
                stages = ['PREVIEW_BUILT']
            elif ROUTES[case] == 'URI_PREVIEW':
                stages = ['PARSE_SUCCEEDED', 'PREVIEW_BUILT']
            else:
                stages = ['PARSE_SUCCEEDED']
                if ROUTES[case] == 'URI_IMPORT':
                    stages.append('FINGERPRINT_ACCEPTED')
                stages += ['GRAPH_STORE_ATTEMPT', verdicts[0]]
            if kinds != [start] + stages + ['REQUEST_SUCCEEDED']:
                continue
            if ROUTES[case] == 'URI_PREVIEW':
                built = next(event for event in root if event['kind'] == 'PREVIEW_BUILT')
                if commits[0]['sequence'] >= built['sequence']:
                    continue
        if (root[0]['kind'] != start or root[-1]['kind'] not in {'REQUEST_SUCCEEDED', 'REQUEST_FAILED'}
                or any(event['sequence'] <= root[0]['sequence'] or event['sequence'] >= root[-1]['sequence']
                       for event in group if event['operationId'] != parent)):
            continue
        graph_delta = segment['graphAfter']['retainedStatements'] - segment['graphBefore']['retainedStatements']
        if graph_delta != (1 if 'GRAPH_STORE_IMPORTED' in kinds else 0):
            continue
        observed.add(case)
    return {'schemaVersion': 1, 'kind': 'composed-budget-coverage',
            'requiredCases': list(REQUIRED_CASES), 'observedCases': sorted(observed),
            'missingCases': sorted(set(REQUIRED_CASES) - observed),
            'evidenceClass': 'native-observation-local-consistency',
            'originalAuthentication': 'not-established', 'fullAppBudgets': 'not-observed',
            'releaseEligible': False}


def derive_journal(plan, events):
    """Recompute process-bound originals; fixed-case union never adds process-local counts."""
    attached = [event for event in events if 'composedBudgetEvidence' in event]
    if not attached:
        return None
    if len(attached) > 8:
        raise ComposedEvidenceError('composed-budget-attachment-limit')
    inputs = plan.get('composedBudgetInputs')
    _closed(inputs, ('collectorDigest', 'configurationDigest'))
    node_epochs, collector_epochs, results = set(), set(), []
    for event in attached:
        value = event['composedBudgetEvidence']
        if (value.get('nodeEpoch') in node_epochs or value.get('collectorEpoch') in collector_epochs):
            raise ComposedEvidenceError('composed-budget-process-epoch-replayed')
        node_epochs.add(value.get('nodeEpoch'))
        collector_epochs.add(value.get('collectorEpoch'))
        selected = next(node for node in plan['nodes'] if node['role'] == event['role'])
        results.append(derive(value,
            workload_digest=plan['workloadInputs']['scheduler'], product_digest=selected['artifactDigest'],
            source_commit=selected['sourceCommit'], app_cohort_digest=pressure.baseline.digest(selected['appDigests']),
            observation_time=event['wallTime'], node_epoch=event['nodeEpoch'],
            collector_digest=inputs['collectorDigest'], configuration_digest=inputs['configurationDigest']))
    observed = set().union(*(set(result['observedCases']) for result in results))
    result = dict(results[0], observedCases=sorted(observed),
                  missingCases=sorted(set(REQUIRED_CASES) - observed))
    return result
