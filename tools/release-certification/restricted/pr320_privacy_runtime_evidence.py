"""Closed installed native privacy and independent original readback/cleanup validation.

The observer component is local consistency. Only separately captured administrator,
bootstrap and terminal records establish original matching; this is not protected authority.
"""
from __future__ import annotations
import datetime as dt
import base64
import hashlib
import json
import re
import urllib.parse

from cryptad_certification import composed_budget_privacy_evidence as privacy
from cryptad_certification import composed_budget_storage_evidence as storage
from cryptad_certification.io import read_json_bytes
import pr320_privacy_contract as contract

MAX_PRIVATE_BYTES = 4 * 1024 * 1024
MAX_ORIGINAL_BYTES = 8 * 1024 * 1024
PRIVATE_FILE, CHECKPOINT_FILE = contract.PRIVATE_FILE, contract.CHECKPOINT_FILE
BROWSER_FILE = 'pr320-privacy-browser.private.json'
ORIGINALS_FILE = 'pr320-privacy-originals.private.json'
EVIDENCE_CLASS = 'installed-four-role-private-observer'
SURFACES = frozenset({'appErrors', 'appAudit', 'supportBundle', 'supportPreview', 'workSnapshot',
                     'operatorRuntime', 'queueSummary', 'subscriptionSummary', 'logs', 'supportBundleText'})
REQUIRED_PRINCIPALS = frozenset({'other-app-origin', 'hostile-origin', 'missing-origin', 'invalid-session', 'wrong-role', 'expired-session', 'stale-worker'})
ROUTES = frozenset({'operator/runtime-observation', 'operator/support-bundle', 'operator/app-data/backups',
                    'operator/network-budgets', 'operator/beta-dashboard', 'trust-graph/statements'})
CONTEXT_FIELDS = frozenset({'appId', 'role', 'roleEpochDigest', 'daemonEpochDigest',
                           'workerEpochDigest', 'originDigest', 'sessionDigest', 'sessionExpiryDigest'})


def _need(condition, code):
    if not condition:
        raise ValueError('pr320-privacy-original-' + code)


def _native(value):
    _need(isinstance(value, dict) and isinstance(value.get('work'), dict)
          and isinstance(value.get('budget'), dict), 'native-shape-invalid')
    work, budget = value['work'], value['budget']
    _need(work.get('version') == 4 and work.get('known') is True and work.get('dropped') == 0
          and budget.get('valid') is True and isinstance(work.get('events'), list)
          and len(work['events']) <= 4096 and type(work.get('lastSequence')) is int
          and work['lastSequence'] == len(work['events'])
          and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                           str(work.get('collectorEpoch'))) is not None,
          'native-unavailable')
    if work['events']:
        storage._events(work['events'], 0, work['lastSequence'])
    return work, budget


def _same_native(before, after):
    first, first_budget = _native(before)
    last, last_budget = _native(after)
    return (all(first.get(key) == last.get(key) for key in ('collectorEpoch', 'lastSequence', 'dropped'))
            and all(first_budget.get(key) == last_budget.get(key) for key in
                    ('rates', 'activeFamilyLeases', 'reservedFamilyRates')))


def _read_record(surface):
    _need(isinstance(surface, dict) and isinstance(surface.get('record'), dict), 'app-data-missing')
    record = surface['record']
    raw = base64.b64decode(record['valueBase64'], validate=True)
    _need(0 < len(raw) <= 16384 and record.get('valueBytes') == len(raw)
          and record.get('sha256') == hashlib.sha256(raw).hexdigest()
          and record.get('valueText') == raw.decode('utf-8')
          and record.get('namespace') == 'pr320-privacy'
          and record.get('key') == 'pr320-private-app-data-key', 'app-data-readback-invalid')
    return record, raw


def _support(bundle, preview, *, wire=None):
    _need(isinstance(bundle, dict) and bundle.get('kind') == 'cryptad-operator-support-bundle'
          and bundle.get('schemaVersion') == 2 and bundle.get('sections') and bundle.get('dashboard')
          and bundle.get('diagnostics') and bundle.get('redaction', {}).get('status') == 'pass'
          and bundle['redaction'].get('rawSensitiveMaterialExcluded') is True
          and bundle['redaction'].get('redactionFindings') == [], 'support-unavailable')
    # The Java builder hashes its original compact wire lexemes, including number formats.
    raw = privacy._encoded(bundle).decode() if wire is None else wire
    _need(isinstance(raw, str) and privacy.verify_support_wire(raw) == bundle, 'support-wire-mismatch')
    _need(isinstance(preview, dict) and preview.get('kind') == 'crypta-operator-support-bundle-preview'
          and preview.get('supportBundleVersion') == 2 and preview.get('includedSections')
          and preview.get('redaction', {}).get('status') == 'pass', 'support-preview-unavailable')


def _verify_boundaries(value, contexts):
    _need(isinstance(value, dict) and set(value) == {'expiredSession', 'staleWorkerBefore', 'staleWorkerAfter'},
          'boundary-roster-invalid')
    for key, app, command in (('expiredSession', 'feed-reader', 'privacy:expired-session'),
                              ('staleWorkerBefore', 'budget-importer', 'privacy:stale-worker-before')):
        row = value[key]
        _need(isinstance(row, dict) and set(row) == {'kind', 'appId', 'context', 'binding',
            'observedEpochNs', 'observedMonotonicNs', 'expiresAt'} | ({'denial'} if key == 'expiredSession' else set())
            and row['kind'] == command
            and row['appId'] == app and row['context'] == contexts[app]
            and contract.canonical_digest(row['expiresAt']) == contexts[app]['sessionExpiryDigest']
            and contract.canonical_digest(row['binding']['worker']) == contexts[app]['workerEpochDigest']
            and contract.canonical_digest(row['binding']['daemon']) == contexts[app]['daemonEpochDigest'],
            'boundary-context-substituted')
        expiry = dt.datetime.fromisoformat(row['expiresAt'].replace('Z', '+00:00'))
        _need(expiry.tzinfo is not None and type(row['observedEpochNs']) is int
              and type(row['observedMonotonicNs']) is int and row['observedMonotonicNs'] > 0,
              'boundary-clock-invalid')
        expired = row['observedEpochNs'] >= int(expiry.timestamp() * 10**9)
        _need(expired is (key == 'expiredSession'), 'boundary-expiry-premise-invalid')
    before, after = value['staleWorkerBefore'], value['staleWorkerAfter']
    _need(isinstance(after, dict) and set(after) == {'kind', 'appId', 'context', 'runtime',
          'terminatedWorkers', 'observedEpochNs', 'observedMonotonicNs', 'denial'}
          and after['kind'] == 'privacy:stale-worker-after' and after['appId'] == 'budget-importer'
          and after['context'] == before['context'] and after['runtime'].get('running') is False
          and after['runtime'].get('pid') is None and after['observedMonotonicNs'] > before['observedMonotonicNs']
          and before['observedEpochNs'] <= after['observedEpochNs'] < int(
              dt.datetime.fromisoformat(before['expiresAt'].replace('Z', '+00:00')).timestamp() * 10**9)
          and after['terminatedWorkers'] == [dict(before['binding']['worker'][key], dead=True)
              for key in ('appHostLeader', 'fixtureProcess')], 'boundary-worker-death-invalid')
    for row in (value['expiredSession'], after):
        denial = row['denial']
        _need(isinstance(denial,dict) and set(denial) == {'status','body','beforeNative','afterNative'}
              and denial['status'] in {401,403} and isinstance(denial['body'],dict) and denial['body']
              and _same_native(denial['beforeNative'],denial['afterNative']), 'boundary-denial-unverified')


def verify_component(value):
    """Recompute native/export consistency; no browser or protected coverage is implied."""
    privacy._encoded(value)
    fields = {'schemaVersion', 'caseId', 'evidenceClass', 'producer', 'stimuli', 'privateSurfaces',
              'surfaces', 'denials', 'phaseContexts', 'originalReceipts', 'boundaryEvidence'}
    _need(isinstance(value, dict) and set(value) == fields and type(value['schemaVersion']) is int
          and value['schemaVersion'] == 1 and value['caseId'] == 'privacy'
          and value['evidenceClass'] == EVIDENCE_CLASS
          and value['producer'] == 'cross_version_installed_privacy_budgets', 'component-invalid')
    private, surfaces, contexts = value['privateSurfaces'], value['surfaces'], value['phaseContexts']
    _need(isinstance(private, dict) and set(private) == {'graph', 'appData', 'backup'}
          and isinstance(surfaces, dict) and set(surfaces) == SURFACES
          and isinstance(contexts, dict) and set(contexts) == {'before', 'after', 'apps'}, 'component-surfaces-invalid')
    record, raw_data = _read_record(private['appData'])
    _need(isinstance(private['graph'], list) and private['graph'], 'graph-stimulus-missing')
    backup = private['backup']
    _need(isinstance(backup, dict) and isinstance(backup.get('payloadBase64'), str), 'backup-missing')
    payload = backup['payloadBase64']
    _need(re.fullmatch('[A-Za-z0-9_-]+', payload) is not None, 'backup-encoding-invalid')
    backup_raw = base64.b64decode(payload + '=' * (-len(payload) % 4), altchars=b'-_', validate=True)
    _need(base64.urlsafe_b64encode(backup_raw).decode().rstrip('=') == payload, 'backup-encoding-invalid')
    _need(raw_data in backup_raw or record['valueBase64'].encode() in backup_raw, 'backup-stimulus-missing')
    rows = value['stimuli']
    _need(isinstance(rows, list) and 0 < len(rows) <= 64, 'stimulus-limit')
    seen, purposes, markers = set(), set(), []
    for row in rows:
        _need(isinstance(row, dict) and set(row) == {'purpose', 'marker', 'privateSurface'}
              and row['purpose'] in privacy.PURPOSES and row['privateSurface'] in {'graph', 'appData'},
              'stimulus-binding-invalid')
        marker = row['marker']
        privacy.representations(marker)
        _need(marker not in seen and marker.encode() in privacy._encoded(private[row['privateSurface']]),
              'stimulus-not-observed')
        seen.add(marker)
        purposes.add(row['purpose'])
        markers.append(marker)
    _need(privacy.PURPOSES <= purposes, 'stimulus-purpose-missing')
    for surface in surfaces.values():
        privacy.check_omission(surface, markers)
    _support(surfaces['supportBundle'], surfaces['supportPreview'], wire=surfaces['supportBundleText'])
    work_before, _ = _native(contexts['before'])
    work_after, budget_after = _native(contexts['after'])
    _need(work_after == surfaces['workSnapshot'] and contexts['after'] == surfaces['operatorRuntime']
          and work_before['collectorEpoch'] == work_after['collectorEpoch']
          and work_after['lastSequence'] > work_before['lastSequence']
          and work_after['events'] and not budget_after['activeFamilyLeases']
          and not budget_after['reservedFamilyRates'], 'native-stimulus-missing')
    events = [row for row in work_after['events'] if row['sequence'] > work_before['lastSequence']]
    _need(events and [row['sequence'] for row in events] ==
          list(range(work_before['lastSequence'] + 1, work_after['lastSequence'] + 1))
          and any(row['kind'] == 'GRAPH_STORE_IMPORTED' for row in events)
          and any(row['kind'] == 'FETCH_SUCCEEDED' for row in events), 'native-range-incomplete')
    _need(isinstance(surfaces['appErrors'], list) and len(surfaces['appErrors']) == 7
          and [row.get('status') for row in surfaces['appErrors']] == [400,400,403,403,415,502,504]
          and all(isinstance(row, dict) and set(row) == {'status', 'body'}
                  and row['status'] in {400, 401, 403, 415, 429, 502, 503, 504}
                  and isinstance(row['body'], dict) and row['body'] for row in surfaces['appErrors']),
          'error-collector-missing')
    _need(isinstance(surfaces['appAudit'], dict) and set(surfaces['appAudit']) == {'stimulus', 'final'}
          and all(isinstance(snapshot, dict) and snapshot.get('audit', {}).get('appId') == 'feed-reader'
                  and snapshot['audit'].get('events') for snapshot in surfaces['appAudit'].values()),
          'audit-collector-missing')
    logs = surfaces['logs']
    _need(isinstance(logs, dict) and {'stdout.private.log', 'stderr.private.log'} <= set(logs)
          and all(isinstance(raw, str) for raw in logs.values()), 'log-collector-missing')
    _need(isinstance(contexts['apps'], dict) and set(contexts['apps']) == set(contract.APP_IDS),
          'context-roster-invalid')
    for app, context in contexts['apps'].items():
        _need(isinstance(context, dict) and set(context) == CONTEXT_FIELDS and context['appId'] == app
              and context['role'] == 'candidate-sender' and all(
              re.fullmatch('sha256:[0-9a-f]{64}', str(context[key])) for key in CONTEXT_FIELDS - {'appId', 'role'}),
              'context-invalid')
    _verify_boundaries(value['boundaryEvidence'], contexts['apps'])
    for key in ('expiredSession','staleWorkerAfter'):
        privacy.check_omission(value['boundaryEvidence'][key]['denial']['body'], markers)
    denials = value['denials']
    _need(isinstance(denials, list) and len(denials) == len(ROUTES) + len(REQUIRED_PRINCIPALS),
          'denial-roster-invalid')
    seen_denials = set()
    for row in denials:
        _need(isinstance(row, dict) and set(row) == {'route', 'principal', 'status', 'body', 'beforeNative', 'afterNative'}
              and row['route'] in ROUTES and row['principal'] in REQUIRED_PRINCIPALS | {'non-operator-app'}
              and row['status'] in {401, 403} and isinstance(row['body'], dict) and row['body']
              and _same_native(row['beforeNative'], row['afterNative']), 'denial-invalid')
        identity = row['route'], row['principal']
        _need(identity not in seen_denials and (row['principal'] == 'non-operator-app'
              or row['route'] == 'operator/support-bundle'), 'denial-replayed')
        privacy.check_omission(row['body'], markers)
        seen_denials.add(identity)
    _need({(route, 'non-operator-app') for route in ROUTES} |
          {('operator/support-bundle', principal) for principal in REQUIRED_PRINCIPALS} == seen_denials,
          'denial-roster-incomplete')
    receipts = value['originalReceipts']
    _need(isinstance(receipts, list) and len(receipts) == 2
          and all(isinstance(row, dict) and row.get('kind') == 'pr320-original-privacy-readback' for row in receipts)
          and receipts[0]['graphFacts'] == private['graph'] and receipts[1]['logs'] == logs
          and receipts[0]['appData']['valueBase64'] == record['valueBase64']
          and receipts[1]['boundaryEvidence'] == value['boundaryEvidence'], 'original-control-mismatch')
    return {'caseId': 'privacy', 'component': 'native', 'status': 'verified',
        'evidenceClass': EVIDENCE_CLASS, 'stimulusCount': len(rows), 'surfaceCount': len(surfaces),
        'originalAuthentication': 'not-established', 'installedObservation': False,
        'fullAppBudgets': 'not-observed', 'releaseEligible': False, 'phaseComplete': False}


def decode_private(raw):
    _need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_PRIVATE_BYTES, 'size-invalid')
    value = read_json_bytes(raw, 'pr320-private-privacy')
    _need(isinstance(value, dict) and set(value) == {'schemaVersion', 'kind', 'selectionDigest', 'component'}
          and value['schemaVersion'] == 1 and value['kind'] == 'pr320-private-native-privacy'
          and re.fullmatch('sha256:[0-9a-f]{64}', str(value['selectionDigest'])) is not None, 'shape-invalid')
    verify_component(value['component'])
    return value


def decode_checkpoints(raw):
    _need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_PRIVATE_BYTES, 'checkpoint-size-invalid')
    lines = raw.splitlines()
    _need(0 < len(lines) <= 16, 'checkpoint-limit')
    result = []
    for line in lines:
        row = read_json_bytes(line, 'privacy-checkpoint')
        _need(isinstance(row, dict), 'checkpoint-invalid')
        if row.get('phase') == 'interrupted':
            _need(set(row) == {'phase', 'status'} and row['status'] == 'unknown', 'checkpoint-invalid')
        elif row.get('phase') == 'native-collected':
            _need(set(row) == {'phase', 'component'} and row['phase'] == 'native-collected', 'checkpoint-invalid')
            verify_component(row['component'])
        else:
            _need(set(row) == {'phase', 'component'} and row['phase'] == 'browser-collected'
                  and row['component'].get('kind') == 'composed-budget-installed-browser-component', 'checkpoint-invalid')
        result.append(row)
    return result


def verify_browser_component(browser, native, *, native_digest, script_digest):
    return privacy.verify_installed_browser(browser, native, native_digest=native_digest,
                                           script_digest=script_digest)


def decode_browser(raw):
    _need(isinstance(raw, bytes) and 0 < len(raw) <= 2 * 1024 * 1024, 'browser-size-invalid')
    value = read_json_bytes(raw, 'privacy-browser')
    _need(isinstance(value, dict) and value.get('kind') == 'composed-budget-installed-browser-component',
          'browser-shape-invalid')
    privacy._encoded(value)
    return value


def decode_originals(raw):
    _need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_ORIGINAL_BYTES, 'original-size-invalid')
    value = read_json_bytes(raw, 'privacy-root-originals')
    _need(isinstance(value, dict) and set(value) == {'schemaVersion', 'kind', 'selectionDigest',
          'bootstrapContext', 'receipts', 'finalLogs', 'cleanupStatus', 'browserFailure'}
          and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
          and value['kind'] == 'pr320-private-privacy-originals'
          and re.fullmatch('sha256:[0-9a-f]{64}', str(value['selectionDigest'])) is not None
          and isinstance(value['receipts'], list) and len(value['receipts']) <= 3
          and isinstance(value['finalLogs'], dict)
          and value['cleanupStatus'] in {'completed', 'original-capture-incomplete'}, 'original-shape-invalid')
    pending, visited = [(value, (), 0)], 0
    while pending:
        child, path, depth = pending.pop()
        visited += 1
        _need(depth <= 24 and visited <= 100000, 'original-tree-limit')
        if isinstance(child, dict):
            _need(len(child) <= 128 and all(isinstance(key, str) and len(key) <= 128 for key in child),
                  'original-fields-invalid')
            pending.extend((item, path + (key,), depth + 1) for key, item in child.items())
        elif isinstance(child, list):
            _need(len(child) <= 8192, 'original-list-limit')
            pending.extend((item, path + (index,), depth + 1) for index, item in enumerate(child))
        elif isinstance(child, str):
            # Large raw text is allowed only in fixed private log/browser-output positions.
            log = path and (path[0] == 'finalLogs' or len(path) >= 4 and path[:1] == ('receipts',)
                           and path[2] in {'logs', 'collectorOutput'})
            browser = len(path) >= 4 and path[0] == 'receipts' and path[2] == 'component'
            failed = path and path[0] == 'browserFailure'
            _need(len(child.encode()) <= (2 * 1024 * 1024 if log or browser or failed else 8192),
                  'original-string-limit')
        else:
            _need(child is None or type(child) in {bool, int}, 'original-scalar-invalid')
    for receipt in value['receipts']:
        _need(isinstance(receipt, dict) and receipt.get('kind') in
              {'pr320-original-privacy-readback', 'pr320-original-browser-observation'}, 'receipt-kind-invalid')
        fields = ({'schemaVersion', 'kind', 'role', 'generation', 'managerInvocation', 'bootId',
                   'selectionDigest', 'daemon', 'dataIdentity', 'durableUsage', 'graphFacts',
                   'captureSource', 'capturedMonotonicNs', 'appData', 'logs', 'observedMonotonicNs', 'boundaryEvidence'}
                  if receipt['kind'] == 'pr320-original-privacy-readback' else
                  {'schemaVersion', 'kind', 'selectionDigest', 'generation', 'managerInvocation',
                   'bootId', 'daemon', 'provider', 'component', 'appBinding', 'packagedScriptDigest', 'appOrigin',
                   'collectorOutput', 'startedMonotonicNs', 'finishedMonotonicNs', 'collectorDigest'})
        _need(set(receipt) == fields and receipt['schemaVersion'] == 1, 'receipt-fields-invalid')
    return value


def validate_originals(private, selected, diagnostics, terminal, report, *, originals, browser, native_digest):
    _need(contract.verify_selection_contract(selected['plan'], selected['private'], selected['authorization']),
          'selection-invalid')
    _need(private['selectionDigest'] == selected['authorization']['selectionDigest']
          and originals['selectionDigest'] == private['selectionDigest']
          and originals['cleanupStatus'] == 'completed' and originals['browserFailure'] is None
          and diagnostics.get('privacyCollectorCleanup') == 'completed', 'selection-substituted')
    from pr316_mail_runtime_runner import _terminal_cleanup_verified
    root_report = isinstance(report,dict) and report.get('kind') == 'pr320-root-native-original-report'
    if root_report:
        fields={'schemaVersion','kind','clockDomain','bootId','unit','invocationId','storageClock',
                'planDigest','activationDigest','observationDigest','checkpointDigest','roleCleanup','roleKernelEpochs'}
        _need(set(report)==fields and type(report['schemaVersion']) is int and report['schemaVersion']==1
              and report['clockDomain']=='protected-host-and-role-common-kernel-utc'
              and report['roleCleanup']=='completed' and report['unit']=='cryptad-pr320-original-acquisition.service'
              and report['planDigest']==contract.canonical_digest(selected['plan'])
              and isinstance(report['roleKernelEpochs'],dict) and set(report['roleKernelEpochs'])==set(contract.ROLES),
              'root-cleanup-report-invalid')
        _need(all(re.fullmatch('sha256:[0-9a-f]{64}',str(report[key])) for key in
                  ('activationDigest','observationDigest','checkpointDigest'))
              and re.fullmatch('[0-9a-f]{32}',str(report['invocationId'])) is not None
              and isinstance(report['storageClock'],dict) and set(report['storageClock'])=={'before','after'},
              'root-cleanup-report-invalid')
        from pr318_storage_runtime_runner import _clock_sample
        first,last=(_clock_sample(report['storageClock'][key]) for key in ('before','after'))
        _need(first['hostMonotonicAfterNanos'] < last['hostMonotonicBeforeNanos']
              and first['hostEpochAfterNanos'] < last['hostEpochBeforeNanos'], 'root-cleanup-clock-invalid')
        for role in contract.ROLES:
            actual=terminal['controllerRecords'][role]['record']
            _need(report['bootId']==actual['bootId'] and report['roleKernelEpochs'][role]=={
                key:actual[key] for key in ('bootId','generation','managerInvocation','roleEpochDigest')},
                'root-cleanup-epoch-substituted')
    _need(_terminal_cleanup_verified(terminal) and (root_report or report.get('guestStopped') is True), 'cleanup-incomplete')
    component = private['component']
    bootstrap = originals['bootstrapContext']
    record = terminal['controllerRecords']['candidate-sender']['record']
    _need(isinstance(bootstrap, dict) and bootstrap.get('apps') == component['phaseContexts']['apps']
          and all(bootstrap.get(key) == record.get(key) for key in
                  ('generation', 'managerInvocation', 'bootId', 'handle')), 'bootstrap-substituted')
    receipts = originals['receipts']
    _need(len(receipts) == 3 and receipts[:2] == component['originalReceipts'] and all(
        row['selectionDigest'] == private['selectionDigest'] and all(row[key] == record[key]
        for key in ('generation', 'managerInvocation', 'bootId')) for row in receipts),
        'readback-original-substituted')
    # The same administrator-selected Java process owns readbacks and browser navigation.
    _need(all(row['daemon'] == receipts[0]['daemon'] for row in receipts)
          and receipts[0]['daemon'].get('hostPid', 0) > 0
          and receipts[0]['daemon'].get('startTicks', 0) > 0
          and any(row.get('documentFingerprint') == selected['authorization']['budgetSelection']['statementFingerprint']
                  for row in component['privateSurfaces']['graph']), 'native-owner-substituted')
    _need(receipts[0]['appData']['valueBase64'] == receipts[1]['appData']['valueBase64'],
          'app-data-original-substituted')
    final_logs = originals['finalLogs']
    _need(isinstance(final_logs, dict) and 'stdio.private.json' in final_logs, 'terminal-logs-missing')
    capture = read_json_bytes(final_logs['stdio.private.json'].encode(), 'stdio-original')
    _need(capture.get('schemaVersion') == 2
          and capture.get('generation') == receipts[0]['managerInvocation'], 'stdio-generation-substituted')
    _need(capture.get('status') == 'complete' and set(capture.get('completeStreams', [])) ==
          {'stdout.private.log', 'stderr.private.log'}, 'stdio-tail-incomplete')
    for name in ('stdout.private.log', 'stderr.private.log'):
        _need(final_logs[name].startswith(component['surfaces']['logs'][name])
              and capture['bytes'][name] == len(final_logs[name].encode()), 'stdio-tail-substituted')
    privacy.check_omission(final_logs, [row['marker'] for row in component['stimuli']])
    original_browser = receipts[2]
    _need(original_browser['kind'] == 'pr320-original-browser-observation'
          and original_browser['component'] == browser
          and original_browser['provider'] == selected['authorization']['browserProvider']
          and contract.canonical_digest(original_browser['appBinding']['worker']) == bootstrap['apps']['feed-reader']['workerEpochDigest']
          and contract.canonical_digest(original_browser['appBinding']['daemon']) == bootstrap['apps']['feed-reader']['daemonEpochDigest']
          and original_browser['collectorDigest'] == selected['authorization']['budgetSelection']['toolIdentities']['browserCollector']
          and browser['nativeMemberDigest'] == native_digest
          and browser['scriptDigest'] == original_browser['packagedScriptDigest']
          and original_browser['finishedMonotonicNs'] >= original_browser['startedMonotonicNs']
          and original_browser['finishedMonotonicNs'] - original_browser['startedMonotonicNs'] <= 65 * 10**9,
          'browser-original-substituted')
    origin = original_browser['appOrigin']
    parsed_origin = urllib.parse.urlsplit(origin)
    _need(parsed_origin.scheme == 'http' and parsed_origin.hostname == '127.0.0.1'
          and parsed_origin.port is not None and 1024 <= parsed_origin.port <= 65535
          and parsed_origin.port != 19402 and not parsed_origin.username and not parsed_origin.password
          and not parsed_origin.query and not parsed_origin.fragment and parsed_origin.path in {'', '/'}
          and contract.canonical_digest(origin) == bootstrap['apps']['feed-reader']['originDigest']
          and {row['origin'] for row in browser['requests']} ==
              {'http://127.0.0.1:19402', origin.rstrip('/')}, 'browser-origin-substituted')
    output = original_browser['collectorOutput']
    _need(isinstance(output, list) and len(output) == 1 and output[0]['stderr'] == ''
          and read_json_bytes(output[0]['stdout'].encode(), 'browser-output') == browser,
          'browser-output-substituted')
    browser_result = verify_browser_component(browser, component, native_digest=native_digest,
                                              script_digest=original_browser['packagedScriptDigest'])
    return {'native': verify_component(component), 'browser': browser_result}


def failed_projection(reason):
    _need(reason in {'setup-or-execution-failed', 'private-evidence-invalid', 'privacy-export-failed',
                     'cleanup-incomplete', 'watcher-incomplete'}, 'failure-code-invalid')
    return {'schemaVersion': 1, 'kind': 'pr320-native-privacy-assessment', 'status': 'failed',
        'reasons': [reason], 'observedComponents': [], 'evidenceClass': EVIDENCE_CLASS,
        'originalAuthentication': 'not-established', 'fullAppBudgets': 'not-observed',
        'releaseEligible': False, 'phaseComplete': False}


def public_projection(private, *, browser, native_digest, selected, diagnostics, terminal, report, originals):
    validate_originals(private, selected, diagnostics, terminal, report, originals=originals,
                       browser=browser, native_digest=native_digest)
    return {'schemaVersion': 1, 'kind': 'pr320-native-privacy-assessment', 'status': 'observed',
        'reasons': [], 'observedComponents': ['native', 'browser'], 'evidenceClass': EVIDENCE_CLASS,
        'originalAuthentication': 'administrator-matched-not-protected-authority',
        'fullAppBudgets': 'not-observed', 'releaseEligible': False, 'phaseComplete': False}
