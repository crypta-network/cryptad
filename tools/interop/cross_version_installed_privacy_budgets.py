"""Finite privacy collection over exact controller-bound roles and signed synthetic apps.

Authorized private readback proves stimulus. Only fixed native/export surfaces are
scanned for omission. Raw graph/backup data remains private and is never projected.
Browser observations are a separate required campaign component.
"""
from __future__ import annotations
import datetime as dt
import base64
import hashlib
import json
import os
import re
from pathlib import Path
import socket
import stat
import time
import urllib.parse
import urllib.request

import cross_version_installed_budgets as transport
from cryptad_certification import composed_budget_privacy_evidence as privacy

EXECUTION_CLASS = 'pr320-installed-budget-privacy-v1'
EXPERIMENT = 'pr320-installed-budget-privacy'
PRIVATE_FILE = 'pr320-privacy-native.private.json'
CHECKPOINT_FILE = 'pr320-privacy-checkpoints.private.jsonl'
BROWSER_FILE = 'pr320-privacy-browser.private.json'
ROLE = transport.ROLE
APP_IDS = transport.APP_IDS
MAX_PRIVATE_BYTES = 4 * 1024 * 1024
NAMESPACE = 'pr320-privacy'
KEY = 'pr320-private-app-data-key'
LABEL = 'PR320_PRIVATE_GRAPH_SOURCE_LABEL'
DATA_VALUE = 'PR320_PRIVATE_APP_DATA_VALUE'
# Sentinel values are synthetic, never credentials for a real service.
DATA_SENTINELS = {
    'credentialShape': 'PR320_PRIVATE_SYNTHETIC_SESSION_SENTINEL',
    'filesystem': '/private/PR320_SYNTHETIC_FILESYSTEM_SENTINEL',
    'selectionMapping': 'PR320_PRIVATE_SELECTION_MAPPING',
    'fieldName': 'PR320_PRIVATE_UNSAFE_FIELD_NAME',
    'nestedCredential': 'PR320_PRIVATE_NESTED_CREDENTIAL_SENTINEL',
    'backupShape': 'PR320_PRIVATE_BACKUP_PAYLOAD_SENTINEL',
    'attachmentName': 'PR320_PRIVATE_ATTACHMENT_NAME.json',
}
DENIAL_ROUTES = (
    ('GET', '/api/v1/operator/runtime-observation'),
    ('GET', '/api/v1/operator/support-bundle'),
    ('POST', '/api/v1/operator/app-data/backups'),
    ('GET', '/api/v1/operator/network-budgets'),
    ('GET', '/api/v1/operator/beta-dashboard'),
    ('GET', '/api/v1/trust-graph/statements'),
)
ALLOWED = frozenset(DENIAL_ROUTES) | frozenset({
    ('GET', '/api/v1/operator/support-bundle/preview'),
    ('POST', '/api/v1/app-data/records'),
    ('GET', '/api/v1/app-data/records/' + NAMESPACE + '/' + KEY),
    ('GET', '/api/v1/apps/feed-reader/audit'), ('GET', '/api/v1/queue'),
    ('GET', '/api/v1/content/subscriptions'), ('GET', '/api/v1/trust-graph/audit'),
    ('POST', '/api/v1/trust-graph/import'), ('POST', '/api/v1/trust-graph/import-uri'),
    ('POST', '/api/v1/trust-graph/import-preview'), ('POST', '/api/v1/trust-graph/import-preview-uri'),
    ('POST', '/api/v1/content/fetch'),
})


def _fail(reason):
    raise transport.runtime.RuntimeFailure('installed-privacy-' + reason)


def _request(handle, method, path, parameters=None, *, principal='app', origin='bound', session='bound'):
    """A closed additional HTTP vocabulary over the existing descriptor-only role transport."""
    if (method, path) not in ALLOWED or principal not in {'app', 'host'}:
        _fail('request-not-selected')
    context = transport._context(handle.context, handle.app_id) if principal == 'app' else None
    values, headers = dict(parameters or {}), {'Accept': 'application/json'}
    if principal == 'app':
        selected_origin = context['origin'] if origin == 'bound' else origin
        if selected_origin is not None:
            headers['Origin'] = selected_origin
        headers['X-Crypta-App-Session'] = context['session'] if session == 'bound' else session
    elif method != 'GET':
        if not isinstance(handle.password, str) or not handle.password:
            _fail('host-bootstrap-unavailable')
        values['formPassword'] = handle.password
    deadline = min(handle.supervisor.deadline, time.monotonic() + 45)
    handle.supervisor.next_operation()
    data = urllib.parse.urlencode(values).encode() if method == 'POST' else None
    if data is not None:
        if len(data) > 65536:
            _fail('request-size-limit')
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    query = ('?' + urllib.parse.urlencode(values)) if method == 'GET' and values else ''
    request = urllib.request.Request(handle.base + path + query, data=data, headers=headers, method=method)
    try:
        with transport.runtime.absolute_deadline(handle.supervisor.remaining(45)):
            with handle.opener.open(request, timeout=max(.001, deadline - time.monotonic())) as response:
                if response.status in {301, 302, 303, 307, 308}:
                    _fail('redirect-forbidden')
                raw = response.read(privacy.MAX_BYTES + 1)
                if not raw or len(raw) > privacy.MAX_BYTES:
                    _fail('response-size-limit')
                value = json.loads(raw, object_pairs_hook=transport._unique)
                if not isinstance(value, dict):
                    _fail('response-shape-invalid')
                result = {'status': response.status, 'body': value}
                if principal == 'host' and path == '/api/v1/operator/support-bundle' and response.status == 200:
                    result['wire'] = raw.decode('utf-8')
                return result
    except (OSError, ValueError):
        _fail('collection-failed')


def _expect(response, statuses):
    if response['status'] not in statuses:
        _fail('unexpected-http-result')
    return response['body']


def _write(root, filename, value, *, append=False):
    if filename not in {PRIVATE_FILE, CHECKPOINT_FILE, BROWSER_FILE}:
        _fail('private-member-not-selected')
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if append:
        raw += b'\n'
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_APPEND if append else os.O_EXCL)
    fd = os.open(Path(root) / filename, flags, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or info.st_mode & 0o077 or info.st_size + len(raw) > MAX_PRIVATE_BYTES):
            _fail('private-output-budget')
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                _fail('private-output-incomplete')
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _emitted_bytes(root, filename, expected_digest):
    if filename not in {PRIVATE_FILE,BROWSER_FILE}:
        _fail('private-member-not-selected')
    fd=os.open(Path(root)/filename,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1 or before.st_mode & 0o077:
            _fail('private-member-invalid')
        with os.fdopen(os.dup(fd),'rb') as stream:
            raw=stream.read(MAX_PRIVATE_BYTES+1)
        after=os.fstat(fd)
        if not 0 < len(raw) <= MAX_PRIVATE_BYTES or expected_digest != 'sha256:'+hashlib.sha256(raw).hexdigest() or any(
            getattr(before,key)!=getattr(after,key) for key in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):
            _fail('private-member-changed')
        return raw
    finally:
        os.close(fd)


def _wait_actual_expiry(handle):
    """Wait for the authentic bootstrap expiration without adjusting either clock or token."""
    expires = dt.datetime.fromisoformat(handle.context['sessionExpiresAt'].replace('Z', '+00:00'))
    if expires.tzinfo is None:
        _fail('expiry-invalid')
    expiry = expires.timestamp()
    deadline = min(handle.supervisor.deadline, time.monotonic() + 3660)
    while time.time() < expiry:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail('expiry-not-observed')
        time.sleep(min(1, remaining, max(.001, expiry - time.time())))
    if time.monotonic() >= deadline:
        _fail('expiry-not-observed')


def _boundary_context(handle):
    return {'appOrigin': handle.origin, 'appSession': handle.session,
            'sessionExpiresAt': handle.context['sessionExpiresAt']}


def collect_native(adapter, handles, statement, administrator):
    """Execute real stimuli and collect before ring eviction, before role teardown."""
    handle = handles[APP_IDS[0]]
    before = transport._snapshot(handle)
    errors, denials, stimuli, private = [], [], [], {}
    signed = json.loads(statement)
    imported = _request(handle, 'POST', '/api/v1/trust-graph/import',
        {'document': statement.decode(), 'sourceLabel': LABEL})
    _expect(imported, {200})
    preview = _request(handle, 'POST', '/api/v1/trust-graph/import-preview',
        {'document': statement.decode()})
    _expect(preview, {200})
    selected = transport._new_content_key(adapter)
    transport._publish(adapter, selected, statement)
    uri_import = _request(handle, 'POST', '/api/v1/trust-graph/import-uri',
        {'uri': selected['uri'], 'sourceLabel': LABEL})
    _expect(uri_import, {200})
    uri_preview = _request(handle, 'POST', '/api/v1/trust-graph/import-preview-uri', {'uri': selected['uri']})
    _expect(uri_preview, {200})
    data = {'value': DATA_VALUE, 'sentinels': DATA_SENTINELS,
            DATA_SENTINELS['fieldName']: {'session': DATA_SENTINELS['nestedCredential']}}
    put = _request(handle, 'POST', '/api/v1/app-data/records',
        {'namespace': NAMESPACE, 'key': KEY, 'schemaVersion': '1', 'valueJson': json.dumps(data)})
    _expect(put, {201})
    read = _request(handle, 'GET', '/api/v1/app-data/records/' + NAMESPACE + '/' + KEY)
    private['appData'] = _expect(read, {200})
    private['backup'] = _expect(_request(handle, 'POST', '/api/v1/operator/app-data/backups',
                                        {'appId': APP_IDS[0]}, principal='host'), {200})
    original = administrator('privacy:snapshot')
    private['graph'] = original['graphFacts']
    audit_stimulus = _expect(_request(handle, 'GET', '/api/v1/apps/feed-reader/audit', principal='host'), {200})
    for purpose, marker in (('statement', signed['payload']['reason']), ('sourceLabel', LABEL),
                            ('sourceUri', selected['uri']), ('subject', signed['payload']['subject']['uri']),
                            ('documentIdentity', imported['body']['importResult']['documentFingerprint'])):
        stimuli.append({'purpose': purpose, 'marker': marker, 'privateSurface': 'graph'})
    stimuli.extend({'purpose': purpose, 'marker': marker, 'privateSurface': 'appData'}
                   for purpose, marker in {'appDataKey': KEY, 'appDataValue': DATA_VALUE, **DATA_SENTINELS}.items())
    # Safe app errors cover distinct parse/acquisition/permission serializers without storing raw corpus logs.
    for app, path, values, statuses in (
        (handle, '/api/v1/trust-graph/import', {'document': '{}'}, {400}),
        (handle, '/api/v1/trust-graph/import-uri', {'uri': DATA_SENTINELS['filesystem']}, {400}),
        (handles['budget-no-trust'], '/api/v1/trust-graph/import-uri', {'uri': selected['uri']}, {403}),
        (handles['budget-no-fetch'], '/api/v1/trust-graph/import-uri', {'uri': selected['uri']}, {403}),
    ):
        response = _request(app, 'POST', path, values)
        _expect(response, statuses)
        errors.append(response)
    for payload, limit, expected in ((b'\xc3\x28', '8192', 415), (b'x' * 2048, '1024', 502)):
        fault_key = transport._new_content_key(adapter)
        transport._publish(adapter, fault_key, payload)
        response = _request(handle, 'POST', '/api/v1/content/fetch',
            {'uri': fault_key['uri'], 'maxBytes': limit, 'format': 'text'})
        _expect(response, {expected})
        errors.append(response)
    timed_key = transport._new_content_key(adapter)
    response = _request(handle, 'POST', '/api/v1/content/fetch',
        {'uri': timed_key['uri'], 'timeoutMillis': '100', 'format': 'text'})
    _expect(response, {504})
    errors.append(response)
    acknowledged = transport._wait_for(adapter, handle, before['work']['lastSequence'],
        lambda snapshot, _events: snapshot['budget']['activeFamilyLeases'] == 0
        and snapshot['budget']['reservedFamilyRates'] == 0, maximum=45)
    if acknowledged is None:
        _fail('timeout-owner-tail-unobserved')
    for method, path in DENIAL_ROUTES:
        selected_handle = handles['budget-no-trust'] if path.endswith('/trust-graph/statements') else handle
        start = transport._snapshot(handle)
        response = _request(selected_handle, method, path, {'appId': APP_IDS[0]} if method == 'POST' else None)
        _expect(response, {401, 403})
        end = transport._snapshot(handle)
        if not transport._unchanged_native(start, end):
            _fail('denied-native-work-observed')
        denials.append({'route': path.removeprefix('/api/v1/'), 'principal': 'non-operator-app',
            'status': response['status'], 'body': response['body'], 'beforeNative': start, 'afterNative': end})
    for principal, origin, session in (
        ('other-app-origin', handles[APP_IDS[1]].origin, 'bound'),
        ('hostile-origin', 'http://127.0.0.1:9', 'bound'),
        ('missing-origin', None, 'bound'),
        ('invalid-session', 'bound', 'PR320_INVALID_SYNTHETIC_SESSION'),
    ):
        start = transport._snapshot(handle)
        response = _request(handle, 'GET', '/api/v1/operator/support-bundle', origin=origin, session=session)
        _expect(response, {401, 403})
        end = transport._snapshot(handle)
        if not transport._unchanged_native(start, end):
            _fail('denied-native-work-observed')
        denials.append({'route': 'operator/support-bundle', 'principal': principal,
            'status': response['status'], 'body': response['body'], 'beforeNative': start, 'afterNative': end})
    recipient = transport.BudgetAppHandle(adapter, APP_IDS[0], 'candidate-recipient')
    recipient.host_bootstrap()
    # A genuine sender app credential is intentionally sent on the separately
    # controller-bound recipient connection; no namespace or host fallback is added.
    recipient.context = handle.context
    start = transport._snapshot(recipient)
    response = _request(recipient, 'GET', '/api/v1/operator/support-bundle')
    _expect(response, {401, 403})
    end = transport._snapshot(recipient)
    if not transport._unchanged_native(start, end):
        _fail('wrong-role-native-work-observed')
    denials.append({'route': 'operator/support-bundle', 'principal': 'wrong-role',
        'status': response['status'], 'body': response['body'], 'beforeNative': start, 'afterNative': end})
    # Natural expiry and an actual AppHost worker stop are distinct admission premises.
    stale = handles[APP_IDS[1]]
    administrator.boundary_context = _boundary_context(stale)
    stale_before = administrator('privacy:stale-worker-before')
    code, _body = stale.request('POST', '/api/v1/apps/' + APP_IDS[1] + '/stop')
    if code != 200:
        _fail('stale-worker-stop-failed')
    stale_after = administrator('privacy:stale-worker-after')
    start = transport._snapshot(handle)
    response = _request(stale, 'GET', '/api/v1/operator/support-bundle')
    end = transport._snapshot(handle)
    _expect(response, {401, 403})
    if not transport._unchanged_native(start, end):
        _fail('stale-worker-native-work-observed')
    denials.append({'route': 'operator/support-bundle', 'principal': 'stale-worker',
        'status': response['status'], 'body': response['body'], 'beforeNative': start, 'afterNative': end})
    subscription_summary = _expect(_request(handle, 'GET', '/api/v1/content/subscriptions'), {200})
    _wait_actual_expiry(handle)
    administrator.boundary_context = _boundary_context(handle)
    expiry_original = administrator('privacy:expired-session')
    start = transport._snapshot(handle)
    response = _request(handle, 'GET', '/api/v1/operator/support-bundle')
    end = transport._snapshot(handle)
    _expect(response, {401, 403})
    if not transport._unchanged_native(start, end):
        _fail('expired-session-native-work-observed')
    denials.append({'route': 'operator/support-bundle', 'principal': 'expired-session',
        'status': response['status'], 'body': response['body'], 'beforeNative': start, 'afterNative': end})
    boundaries = {'expiredSession': expiry_original, 'staleWorkerBefore': stale_before,
                  'staleWorkerAfter': stale_after}
    support = _request(handle, 'GET', '/api/v1/operator/support-bundle', principal='host')
    surfaces = {'appErrors': errors,
        'appAudit': {'stimulus': audit_stimulus,
            'final': _expect(_request(handle, 'GET', '/api/v1/apps/feed-reader/audit', principal='host'), {200})},
        'supportBundle': _expect(support, {200}), 'supportBundleText': support['wire'],
        'supportPreview': _expect(_request(handle, 'GET', '/api/v1/operator/support-bundle/preview', principal='host'), {200}),
        'queueSummary': _expect(_request(handle, 'GET', '/api/v1/queue', principal='host'), {200}),
        'subscriptionSummary': subscription_summary}
    after = transport._snapshot(handle)
    surfaces['workSnapshot'] = after['work']
    surfaces['operatorRuntime'] = after
    original_after = administrator('privacy:snapshot')
    surfaces['logs'] = original_after['logs']
    # Actual ephemeral credentials are inspected only in this private process; never recorded in fixtures/artifacts.
    markers = [row['marker'] for row in stimuli] + [handle.session, handle.password]
    for value in surfaces.values():
        privacy.check_omission(value, markers)
    component = {'schemaVersion': 1, 'caseId': 'privacy',
        'evidenceClass': 'installed-four-role-private-observer',
        'producer': 'cross_version_installed_privacy_budgets', 'stimuli': stimuli,
        'privateSurfaces': private, 'surfaces': surfaces, 'denials': denials,
        'phaseContexts': {'before': before, 'after': after,
            'apps': {app: transport._context_evidence(h.context) for app, h in handles.items()}},
        'originalReceipts': [original, original_after], 'boundaryEvidence': boundaries}
    _write(adapter.root, CHECKPOINT_FILE, {'phase': 'native-collected', 'component': component}, append=True)
    return component


def run_privacy_lane(adapter, administrator, *, leave_running_for_administrator=False, on_start_failure=None):
    from pr320_privacy_contract import verify_selection_contract
    if not verify_selection_contract(adapter.plan, adapter.private, adapter.authorization):
        _fail('selection-invalid')
    completed = False
    try:
        for role in transport.runtime.ROLES:
            adapter.start(role)
        adapter.connect()
        handles, statement = transport._bootstrap_apps(adapter)
        component = collect_native(adapter, handles, statement, administrator)
        from pr320_privacy_runtime_evidence import verify_component
        verify_component(component)
        private = {'schemaVersion': 1, 'kind': 'pr320-private-native-privacy',
            'selectionDigest': adapter.authorization['selectionDigest'], 'component': component}
        digest = _write(adapter.root, PRIVATE_FILE, private)
        from cryptad_certification.composed_budget_journal_member import append_member
        append_member(adapter.journal,'installed-privacy',_emitted_bytes(adapter.root,PRIVATE_FILE,digest))
        administrator.browser_context = {'appOrigin': handles[APP_IDS[0]].origin,
                                         'appSession': handles[APP_IDS[0]].session}
        browser_receipt = administrator('privacy:browser')
        browser = browser_receipt['component']
        from pr320_privacy_runtime_evidence import verify_browser_component
        verify_browser_component(browser, component, native_digest=digest,
                                 script_digest=browser_receipt['packagedScriptDigest'])
        browser_digest = _write(adapter.root, BROWSER_FILE, browser)
        append_member(adapter.journal,'installed-browser-privacy',
            _emitted_bytes(adapter.root,BROWSER_FILE,browser_digest),
            collector_epoch=component['surfaces']['workSnapshot']['collectorEpoch'])
        _write(adapter.root, CHECKPOINT_FILE, {'phase': 'browser-collected', 'component': browser}, append=True)
        from pr320_privacy_artifact_producer import produce
        produce(adapter)
        completed = True
        return {'schemaVersion': 1, 'kind': 'pr320-installed-native-privacy-observation',
            'executionClass': EXECUTION_CLASS, 'selectionDigest': private['selectionDigest'],
            'privateEvidenceDigest': digest, 'browserEvidenceDigest': browser_digest,
            'evidenceClass': 'installed-four-role-private-observer',
            'observedComponents': ['native', 'browser'],
            'fullAppBudgets': 'not-observed', 'phaseComplete': False, 'releaseEligible': False,
            'cleanupState': 'administrator-required' if leave_running_for_administrator else 'observer-owned'}
    except BaseException:
        _write(adapter.root, CHECKPOINT_FILE, {'phase': 'interrupted', 'status': 'unknown'}, append=True)
        if adapter.active_start_role is not None and on_start_failure is not None:
            on_start_failure(adapter.active_start_role, adapter.active_start_stage)
        raise
    finally:
        if (not completed or not leave_running_for_administrator) and adapter.cleanup() != 'complete':
            _fail('cleanup-required')


def validate_guest_observation(value, expected_selection_digest=None):
    fields = {'schemaVersion', 'kind', 'executionClass', 'selectionDigest', 'privateEvidenceDigest',
        'browserEvidenceDigest', 'evidenceClass', 'observedComponents', 'fullAppBudgets',
        'phaseComplete', 'releaseEligible', 'cleanupState'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['schemaVersion']) is not int
            or value['schemaVersion'] != 1 or value['kind'] != 'pr320-installed-native-privacy-observation'
            or value['executionClass'] != EXECUTION_CLASS
            or value['evidenceClass'] != 'installed-four-role-private-observer'
            or value['observedComponents'] != ['native', 'browser']
            or value['fullAppBudgets'] != 'not-observed' or value['phaseComplete'] is not False
            or value['releaseEligible'] is not False
            or value['cleanupState'] not in {'administrator-required', 'observer-owned', 'completed'}
            or any(re.fullmatch('sha256:[0-9a-f]{64}', str(value[key])) is None for key in
                   ('selectionDigest', 'privateEvidenceDigest', 'browserEvidenceDigest'))
            or expected_selection_digest is not None and value['selectionDigest'] != expected_selection_digest):
        _fail('guest-observation-invalid')
    return value


def attach_guest_context(value, identity, runtime_policy, campaign_deadline):
    validate_guest_observation(value)
    return {**value, 'identity': identity, 'runtimePolicy': runtime_policy,
        'campaignDeadlineMonotonicNs': campaign_deadline,
        'workloadAcceptance': 'incomplete-pr320-privacy-originals-not-verified',
        'protectedExecutionEnabled': False}
