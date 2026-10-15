"""Finite retained-role restart and strict diagnostics observations for PR-319.

All application calls use the existing controller-transferred clients. Administrator
phases are fixed test-kit operations over the inherited private channel.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
from pathlib import Path
import socket
import time

import cross_version_installed_budgets as transport
import cross_version_installed_storage_budgets as storage
from cryptad_certification import composed_budget_restart_evidence as oracle

EXECUTION_CLASS = 'pr319-composed-budget-restart-diagnostics-v1'
EXPERIMENT = 'pr319-composed-budget-restart-diagnostics'
CASES = oracle.CASES
PRIVATE_FILE = 'pr319-restart-budget.private.json'
ATTEMPTS_FILE = 'pr319-restart-attempts.private.jsonl'
ROLE = transport.ROLE
runtime, installed, pressure = transport.runtime, transport.installed, transport.pressure


def _checkpoint(root, value):
    # Reuse the bounded/fsynced append implementation without its historical filename.
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    import stat
    fd = os.open(Path(root) / ATTEMPTS_FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or info.st_mode & 0o077 or info.st_size + len(raw) > 4 * 1024 * 1024):
            transport.fail('restart-checkpoint-unsafe')
        pending = memoryview(raw)
        while pending:
            written = os.write(fd, pending)
            if written <= 0:
                transport.fail('restart-checkpoint-write-incomplete')
            pending = pending[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _scope_bindings(native, usage):
    """Bind each original file identity to the native ordered strict enumeration."""
    rates = native['budget']['rates']
    if (usage != sorted(usage, key=lambda r: (r['appId'], r['operation']))
            or len({(r['appId'], r['operation']) for r in usage}) != len(usage)
            or len(rates) != len(usage)):
        transport.fail('restart-store-sample-changed')
    scopes = {'_cryptad_global': 1, '_cryptad_operator': 2}
    for record, rate in zip(usage, rates):
        stamp = transport.pressure.baseline._time(record['windowStart']).timestamp()
        if (rate['operation'] != record['operation'] or rate['windowStartEpochSecond'] != stamp
                or rate['count'] != record['count'] or scopes.get(record['appId'], rate['scope']) != rate['scope']):
            transport.fail('restart-scope-binding-changed')
        scopes[record['appId']] = rate['scope']
    if (len(set(scopes.values())) != len(scopes)
            or any(type(scope) is not int or scope < (1 if app == '_cryptad_global' else
                2 if app == '_cryptad_operator' else 3) for app, scope in scopes.items())):
        transport.fail('restart-scope-binding-invalid')
    return [{'appId': app, 'scope': scope} for app, scope in sorted(scopes.items())]


def _sample(adapter, handles, administrator, state, case, variant, phase, *, command='restart:snapshot'):
    handle = handles[transport.APP_IDS[0]]
    native = transport._snapshot(handle)
    receipt = administrator(command)
    if native['budget']['valid'] is False:
        # The route samples the ring before strict diagnostics. Keep this original
        # invalid view, then actually resample to observe the diagnostic failure event.
        first = {'pid': receipt['daemon']['hostPid'], 'collectorEpoch': native['work']['collectorEpoch'],
            'nativeSnapshot': {k: native['work'][k] for k in ('version', 'lastSequence', 'dropped', 'events', 'collectorEpoch')},
            'diagnostics': {**{k: native['budget'][k] for k in ('valid', 'observedAt', 'activeFamilyLeases', 'reservedFamilyRates')},
                            'usage': []}, 'scopeBindings': state['bindings'], 'graph': receipt['graphFacts']}
        _checkpoint(adapter.root, {'caseId': case, 'variant': variant, 'phase': phase, 'sample': first})
        native = transport._snapshot(handle)
        receipt = administrator(command)
        if native['budget']['valid'] is not False:
            transport.fail('restart-diagnostic-interval-changed')
    if native['budget']['valid']:
        bindings = _scope_bindings(native, receipt['durableUsage'])
        state['bindings'] = bindings
    else:
        bindings = state['bindings']
    daemon = receipt['daemon']
    expected_daemon = adapter.daemon_epochs[ROLE]
    if (any(daemon[k] != expected_daemon[k] for k in ('hostPid', 'startTicks', 'executableDigest'))
            or any(tuple(daemon[k]) != tuple(expected_daemon[k]) for k in ('namespacePids', 'networkNamespaceIdentity'))):
        transport.fail('restart-daemon-sample-substituted')
    sample = {'pid': daemon['hostPid'], 'collectorEpoch': native['work']['collectorEpoch'],
        'nativeSnapshot': {k: native['work'][k] for k in ('version', 'lastSequence', 'dropped', 'events', 'collectorEpoch')},
        'diagnostics': {**{k: native['budget'][k] for k in ('valid', 'observedAt', 'activeFamilyLeases', 'reservedFamilyRates')},
                        'usage': receipt['durableUsage'] if native['budget']['valid'] else []},
        'scopeBindings': bindings, 'graph': receipt['graphFacts']}
    if phase != 'setup':
        state['phaseReceipts'].append({'caseId': case, 'variant': variant, 'phase': phase, 'receipt': receipt, 'native': native})
    _checkpoint(adapter.root, {'caseId': case, 'variant': variant, 'phase': 'before' if phase == 'setup' else phase, 'sample': sample})
    return sample, receipt


def _rebootstrap(adapter, old_handles, statement):
    """Recover retained signed installs normally; bind fresh controller contexts."""
    fresh = {}
    host = transport.BudgetAppHandle(adapter, transport.APP_IDS[0])
    host.host_bootstrap()
    status, installed_apps = host.request('GET', '/api/v1/apps')
    if status != 200 or sorted(row['appId'] for row in installed_apps.get('apps', [])) != sorted(transport.APP_IDS):
        transport.fail('restart-retained-app-roster-changed')
    for app in transport.APP_IDS:
        handle = transport.BudgetAppHandle(adapter, app)
        handle.password = host.password
        status, value = handle.request('GET', '/api/v1/apps/' + app + '/runtime')
        if status != 200:
            transport.fail('restart-app-runtime-unavailable')
        if value.get('runtime', {}).get('running') is not True:
            status, _ = handle.request('POST', '/api/v1/apps/' + app + '/start')
            if status not in {200, 201}:
                transport.fail('restart-retained-app-start-failed')
        fresh[app] = handle
    response = adapter.control.request('bootstrap-budget', adapter.handles[ROLE])
    if set(response) != {'apps', 'corpus'} or set(response['apps']) != set(transport.APP_IDS):
        transport.fail('restart-bootstrap-incomplete')
    if response['corpus']['statementDigest'] != 'sha256:' + hashlib.sha256(statement).hexdigest():
        transport.fail('restart-corpus-substituted')
    for app in transport.APP_IDS:
        context = transport._context(response['apps'][app], app)
        old = old_handles[app].context
        if (context['generation'] == old['generation'] or context['managerInvocation'] == old['managerInvocation']
                or context['bootId'] != old['bootId'] or context['daemonEpoch'] == old['daemonEpoch']
                or context['worker'] == old['worker']):
            transport.fail('restart-app-context-stale')
        fresh[app].bind(context)
        adapter.apps[(ROLE, app)] = fresh[app]
    return fresh


def _same_hour(adapter):
    plan = adapter.authorization['budgetSelection']['timePlan']
    if not plan['boundaryEpochSecond'] - 3600 <= time.time() < plan['boundaryEpochSecond'] - 60:
        transport.fail('restart-selected-hour-missed')
    adapter.remaining()


def _transition(adapter, handles, statement, administrator, state, before, variant, *, active_client=None):
    _same_hour(adapter)
    graceful = variant == 'settled-graceful'
    case = 'graceful-restart' if graceful else 'abrupt-restart'
    contexts = {app: transport._context_evidence(handle.context) for app, handle in handles.items()}
    if graceful:
        pin = administrator('graceful:pin')
        if pin['daemon']['hostPid'] != before['pid']:
            transport.fail('restart-graceful-target-changed')
        with adapter.client(ROLE) as client:
            client.send('Shutdown', {})
        terminal = administrator('graceful:terminal')
        if terminal.get('gracefulExitObserved') is not True:
            transport.fail('restart-graceful-exit-unobserved')
    else:
        if variant == 'inflight-abrupt' and (active_client is None
                or not active_client.process.is_alive() or active_client.channel.poll(0)):
            transport.fail('restart-inflight-premise-finished-before-fault')
        terminal = administrator(('abrupt-inflight' if variant == 'inflight-abrupt' else 'abrupt-settled') + ':terminate')
    _checkpoint(adapter.root, {'caseId': case, 'variant': variant, 'phase': 'terminal', 'receipt': terminal})
    # The administrator reconciled exact old descendants. Controller stop independently
    # verifies the existing stop receipt before start can create new ownership.
    adapter.restart(ROLE)
    fresh = _rebootstrap(adapter, handles, statement)
    state['epochContexts'].append({'caseId': case, 'variant': variant, 'before': contexts,
        'after': {app: transport._context_evidence(handle.context) for app, handle in fresh.items()}})
    after, readback = _sample(adapter, fresh, administrator, state, case, variant, 'after', command='restart:readback')
    if terminal['dataIdentity'] != readback['dataIdentity']:
        transport.fail('restart-retained-mount-substituted')
    _same_hour(adapter)
    return fresh, after, {'kind': 'graceful' if graceful else 'forced', 'oldPid': before['pid'],
        'aliveBefore': True, 'exitCode': terminal['kernelExit']['exitCode'] if graceful else None,
        'deadBeforeRestart': terminal['pidfdDeathObserved'], 'newPid': after['pid'], 'forced': not graceful}, terminal


def _restart_case(adapter, handles, statement, administrator, state, variant, fingerprint):
    case = 'graceful-restart' if variant == 'settled-graceful' else 'abrupt-restart'
    before, original = _sample(adapter, handles, administrator, state, case, variant,
        'setup' if variant == 'inflight-abrupt' else 'before')
    pending = []
    if variant == 'inflight-abrupt':
        key = transport._new_content_key(adapter)
        task = {'method': 'POST', 'path': '/api/v1/trust-graph/import-uri', 'parameters': {'uri': key['uri']}}
        with transport._start_client(adapter, handles[transport.APP_IDS[0]].context, task) as client:
            client.release()
            active = transport._wait_for(adapter, handles[transport.APP_IDS[0]], before['nativeSnapshot']['lastSequence'],
                lambda snapshot, events: any(e['kind'] == 'FETCH_INVOKED' for e in events)
                    and snapshot['budget']['activeFamilyLeases'] > 0
                    and snapshot['budget']['reservedFamilyRates'] > 0
                    and not any(e['kind'] in {'REQUEST_SUCCEEDED', 'REQUEST_FAILED'} for e in events))
            if active is None:
                transport.fail('restart-inflight-premise-not-established')
            before, original = _sample(adapter, handles, administrator, state, case, variant, 'before')
            pending = sorted(oracle._pending(oracle._phase(before)))
            fresh, after, transition, terminal = _transition(adapter, handles, statement, administrator, state, before, variant, active_client=client)
    else:
        fresh, after, transition, terminal = _transition(adapter, handles, statement, administrator, state, before, variant)
    # The same exhausted app must still be denied, independently of zero new holds.
    denied = storage._request(adapter, fresh['budget-importer'], statement, response=True)
    if denied['status'] != 429:
        transport.fail('restart-exhausted-hour-refunded')
    recovered = storage._request(adapter, fresh[transport.APP_IDS[0]], statement, response=True)
    if recovered['status'] != 200:
        transport.fail('restart-recovery-request-failed')
    recovery, _ = _sample(adapter, fresh, administrator, state, case, variant, 'recovery')
    row = {'schemaVersion': 1, 'caseId': case, 'variant': variant, 'evidenceClass': oracle.INSTALLED,
        'before': before, 'after': after, 'recovery': recovery, 'transition': transition,
        'dataIdentity': {'fileKey': transport.runtime.canonical_digest(terminal['dataIdentity'])},
        'selectedFingerprint': fingerprint, 'pendingOperationIds': pending,
        'tailStatus': 'censored' if pending else 'complete'}
    oracle.derive_controlled(row)
    return fresh, row


def _diagnostic_case(adapter, handles, statement, administrator, state, variant, fingerprint):
    case = 'diagnostics-unavailable'
    before, _ = _sample(adapter, handles, administrator, state, case, variant, 'before')
    command = 'diagnostics-enumeration' if variant == 'enumeration-only' else 'diagnostics-required-key'
    restriction = administrator(command + ':restrict')
    try:
        response = storage._request(adapter, handles[transport.APP_IDS[0]], statement, response=True)
        during, _ = _sample(adapter, handles, administrator, state, case, variant, 'during')
    finally:
        restoration = administrator(command + ':restore')
    after, _ = _sample(adapter, handles, administrator, state, case, variant, 'after')
    recovered = storage._request(adapter, handles[transport.APP_IDS[0]], statement, response=True)
    recovery, _ = _sample(adapter, handles, administrator, state, case, variant, 'recovery')
    row = {'schemaVersion': 1, 'caseId': case, 'variant': variant, 'evidenceClass': oracle.INSTALLED,
        'selectedFingerprint': fingerprint, 'before': before, 'during': during, 'after': after, 'recovery': recovery,
        'requestStatus': response['status'], 'requestCode': response.get('value', {}).get('error', {}).get('code'),
        'recoveryStatus': recovered['status'], 'fault': {'kind': variant, 'targetAppId': 'feed-reader',
            'requiredKeyReadable': restriction['roleUidExactKeyReadable'],
            'enumerationReadable': not restriction['roleUidEnumerationDenied'],
            'restored': restoration['selectedPathUnchanged'], 'contentsRestored': restoration['contentsRestored']}}
    oracle.derive_controlled(row)
    return row


def run_restart_lane(adapter, administrator, *, leave_running_for_administrator=False, on_start_failure=None,
                     execution_class=EXECUTION_CLASS):
    with runtime.fixed_helper_imports():
        from pr319_restart_contract import verify_selection_contract
        from pr320_budget_contract import RESTART_EXECUTION_CLASS as prospective_class
        if execution_class == prospective_class:
            from pr320_restart_contract import verify_selection_contract
        elif execution_class != EXECUTION_CLASS:
            transport.fail('restart-class-invalid')
        if not verify_selection_contract(adapter.plan, adapter.private, adapter.authorization):
            transport.fail('restart-selection-invalid')
    state = {'bindings': [], 'phaseReceipts': [], 'epochContexts': []}
    completed = False
    try:
        for role in transport.runtime.ROLES:
            adapter.start(role)
        adapter.connect()
        handles, statement = transport._bootstrap_apps(adapter)
        raw = transport._snapshot(handles[transport.APP_IDS[0]])
        expected = adapter.authorization['budgetSelection']['normalizedConfiguration']['budgetConfiguration']
        if raw['budgetConfiguration'] != expected:
            transport.fail('restart-effective-configuration-mismatch')
        _same_hour(adapter)
        prime = storage._request(adapter, handles[transport.APP_IDS[0]], statement, response=True)
        if prime['status'] != 200:
            transport.fail('restart-seed-failed')
        fingerprint = storage._fingerprint(prime)
        # A fixed synthetic unverified statement is retained under the native store's
        # normal rules. It is an unrelated graph control, never used for recovery.
        control = json.loads(statement)
        control['payload']['reason'] = 'PR319_PRIVATE_CONTROL_CANARY'
        control_bytes = json.dumps(control, sort_keys=True, separators=(',', ':')).encode()
        control_response = storage._request(adapter, handles[transport.APP_IDS[0]], control_bytes, response=True)
        if control_response['status'] != 200 or storage._fingerprint(control_response) == fingerprint:
            transport.fail('restart-graph-control-not-established')
        # A separate family/app control is charged by the production subscription route.
        key = transport._new_content_key(adapter)
        transport._publish(adapter, key, statement)
        unrelated = handles['budget-importer']
        with transport.runtime.absolute_deadline(adapter.remaining(45)):
            code, subscription = unrelated.request('POST', '/api/v1/content/subscriptions',
                {'uri': key['uri'], 'label': 'Synthetic restart control', 'pollIntervalSeconds': '2',
                 'maxBytes': '8192', 'timeoutMillis': '3000'}, principal='app')
            if code != 201:
                transport.fail('restart-family-control-setup-failed')
            code, _ = unrelated.request('POST', '/api/v1/content/subscriptions/' +
                subscription['subscription']['subscriptionId'] + '/refresh', principal='app')
            if code != 200:
                transport.fail('restart-family-control-charge-failed')
        # All exhaustion charges travel through the real handler. No counter bytes are written by observer/admin.
        for _ in range(expected['trustGraphImportPerAppPerHour']):
            if storage._request(adapter, handles['budget-importer'], statement) != 200:
                transport.fail('restart-exhaustion-setup-failed')
        restarts = []
        for variant in ('settled-graceful', 'settled-abrupt', 'inflight-abrupt'):
            handles, row = _restart_case(adapter, handles, statement, administrator, state, variant, fingerprint)
            restarts.append(row)
        diagnostics = [_diagnostic_case(adapter, handles, statement, administrator, state, variant, fingerprint)
                       for variant in ('enumeration-only', 'required-key-unreadable')]
        final = transport._snapshot(handles[transport.APP_IDS[0]])
        node = next(n for n in adapter.plan['nodes'] if n['role'] == ROLE)
        attachment = {'schemaVersion': 5, 'collectorEpoch': final['work']['collectorEpoch'],
            'nodeEpoch': adapter.journal.node_epochs[('', ROLE)], 'workloadDigest': adapter.plan['workloadInputs']['scheduler'],
            'productDigest': node['artifactDigest'], 'sourceCommit': node['sourceCommit'],
            'appCohortDigest': transport.pressure.baseline.digest(node['appDigests']),
            **adapter.plan['composedBudgetInputs'], 'segments': [], 'causalCases': [], 'storageCases': [],
            'restartCases': restarts, 'diagnosticsCases': diagnostics}
        coverage = transport.composed.derive(attachment, workload_digest=attachment['workloadDigest'],
            product_digest=node['artifactDigest'], source_commit=node['sourceCommit'],
            app_cohort_digest=attachment['appCohortDigest'], node_epoch=attachment['nodeEpoch'],
            collector_digest=attachment['collectorDigest'], configuration_digest=attachment['configurationDigest'])
        private = {'schemaVersion': 1, 'kind': 'pr319-private-restart-budget',
            'selectionDigest': adapter.authorization['selectionDigest'],
            'contexts': {app: transport._context_evidence(handle.context) for app, handle in handles.items()},
            'attempts': [], 'composedBudgetEvidence': attachment, 'composedBudgetCoverage': coverage,
            'originalReceipts': administrator.receipts, 'phaseReceipts': state['phaseReceipts'], 'epochContexts': state['epochContexts']}
        encoded = json.dumps(private, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if len(encoded) > 4 * 1024 * 1024:
            transport.fail('restart-private-size-limit')
        fd = os.open(Path(adapter.root) / PRIVATE_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
        if execution_class == prospective_class:
            from cryptad_certification.composed_budget_journal_member import append_member
            append_member(adapter.journal, 'legacy-attachment', json.dumps(
                attachment, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())
        completed = True
        return {'schemaVersion': 1, 'kind': 'pr319-installed-restart-budget-observation', 'executionClass': execution_class,
            'selectionDigest': private['selectionDigest'], 'privateEvidenceDigest': 'sha256:' + hashlib.sha256(encoded).hexdigest(),
            'evidenceClass': oracle.INSTALLED, 'observedCases': [c for c in CASES if c in coverage['observedCases']],
            'fullAppBudgets': 'not-observed', 'phaseComplete': False, 'releaseEligible': False,
            'cleanupState': 'administrator-required' if leave_running_for_administrator else 'observer-owned'}
    except Exception:
        _checkpoint(adapter.root, {'phase': 'interrupted', 'status': 'unknown'})
        if adapter.active_start_role is not None and on_start_failure is not None:
            on_start_failure(adapter.active_start_role, adapter.active_start_stage)
        raise
    finally:
        if (not completed or not leave_running_for_administrator) and adapter.cleanup() != 'complete':
            transport.fail('restart-cleanup-required')


class _Administrator:
    def __init__(self, channel, deadline):
        self.channel, self.deadline, self.receipts = channel, deadline, []

    def __call__(self, command):
        from pr319_restart_admin import COMMANDS
        if self.channel is None or command not in COMMANDS:
            transport.fail('restart-admin-command-invalid')
        self.channel.settimeout(max(.001, min(45, self.deadline / 1e9 - time.monotonic())))
        self.channel.sendall(b'R' + command.encode('ascii'))
        raw, _ancillary, flags, _address = self.channel.recvmsg(131073)
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(raw) > 131072:
            transport.fail('restart-admin-response-limit')
        receipt = json.loads(raw, object_pairs_hook=transport._unique)
        if not isinstance(receipt, dict) or 'error' in receipt:
            transport.fail('restart-admin-observation-unavailable')
        self.receipts.append(receipt)
        return receipt


def run_observer(adapter, channel, deadline, diagnostic):
    return run_restart_lane(adapter, _Administrator(channel, deadline),
        leave_running_for_administrator=True, on_start_failure=diagnostic)


def validate_guest_observation(value, expected_selection_digest=None, *, execution_class=EXECUTION_CLASS):
    fields = {'schemaVersion', 'kind', 'executionClass', 'selectionDigest', 'privateEvidenceDigest',
        'evidenceClass', 'observedCases', 'fullAppBudgets', 'phaseComplete', 'releaseEligible', 'cleanupState'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
            or value['kind'] != 'pr319-installed-restart-budget-observation' or value['executionClass'] != execution_class
            or value['evidenceClass'] != oracle.INSTALLED or value['fullAppBudgets'] != 'not-observed'
            or value['phaseComplete'] is not False or value['releaseEligible'] is not False
            or value['cleanupState'] not in {'administrator-required', 'observer-owned', 'completed'}
            or not isinstance(value['observedCases'], list)
            or value['observedCases'] != [c for c in CASES if c in value['observedCases']]
            or any(re.fullmatch('sha256:[0-9a-f]{64}', str(value[k])) is None for k in ('selectionDigest', 'privateEvidenceDigest'))
            or expected_selection_digest is not None and value['selectionDigest'] != expected_selection_digest):
        transport.fail('restart-guest-observation-invalid')
    return value


def attach_guest_context(value, identity, runtime_policy, campaign_deadline):
    validate_guest_observation(value)
    return {**value, 'identity': identity, 'runtimePolicy': runtime_policy,
        'campaignDeadlineMonotonicNs': campaign_deadline, 'workloadAcceptance': 'incomplete-pr319-private-evidence-not-verified',
        'protectedExecutionEnabled': False}
