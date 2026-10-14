#!/usr/bin/python3
"""Controller-bound finite route/coexistence profiles using the existing native recorder owners."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import time

import cross_version_installed_budgets as lifecycle
import cross_version_runtime as runtime
with runtime.fixed_helper_imports():
    import cross_version_app_budgets as local
    import pr320_route_contract as contract
    from cryptad_certification import composed_budget_evidence as composed
    from cryptad_certification import composed_budget_route_evidence as complete

ROLE, APP_IDS = lifecycle.ROLE, lifecycle.APP_IDS
PRIVATE_FILE, CHECKPOINT_FILE = contract.PRIVATE_FILE, contract.CHECKPOINT_FILE


def need(condition, code):
    if not condition:
        raise runtime.RuntimeFailure('pr320-route-' + code)


class RouteRecorder:
    """Only the original recorder methods are reused; no packaged-local lifecycle is invoked."""
    case = local.AppBudgetLane.case
    shared_segment = local.AppBudgetLane.shared_segment
    reconcile_ambiguous_request = local.AppBudgetLane.reconcile_ambiguous_request
    require = staticmethod(local.AppBudgetLane.require)

    def __init__(self, adapter, handles):
        self.adapter, self.apps = adapter, {(ROLE, app): handle for app, handle in handles.items()}
        self.handle = handles[APP_IDS[0]]
        self.root, self.deadline = adapter.root, adapter.deadline
        self.segments, self.case_results, self.observations, self.scope_bindings = [], [], [], {}

    def observe(self):
        return lifecycle._snapshot(self.handle)

    def graph(self):
        status, value = self.handle.request('GET', '/api/v1/trust-graph/statements', principal='app')
        need(status == 200 and isinstance(value.get('statements'), list), 'graph-unavailable')
        return value['statements']

    def record(self, case, parameters, *, status=200, app=APP_IDS[0], variant='native-route', path=None):
        _checkpoint(self.adapter, {'phase': 'before-case', 'caseId': case, 'variant': variant, 'appId': app})
        before = len(self.segments)
        result, events = self.case(case, parameters, status=status, app=app, path=path)
        need(len(self.segments) == before + 1, 'native-parent-unobserved')
        self.bind_scope(self.segments[-1]['scope'], app)
        self.observations.append({'caseId': case, 'variant': variant, 'appId': app,
            'scope': self.segments[-1]['scope'], 'recordKind': 'segment', 'recordIndex': before,
            'responseStatus': status, 'responseCode': result.get('error', {}).get('code')
                if case == 'authorization-denied' else None})
        _checkpoint(self.adapter, {'phase': 'after-case', 'observation': self.observations[-1],
                                    'original': self.segments[-1]})
        return result, events

    def bind_scope(self, scope, app):
        need(type(scope) is int and scope >= 3 and app in APP_IDS, 'scope-invalid')
        key = str(scope)
        need(self.scope_bindings.get(key, app) == app
             and all(name != app or selected == key for selected, name in self.scope_bindings.items()),
             'scope-rebound')
        self.scope_bindings[key] = app


def _checkpoint(adapter, row):
    raw = json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    need(len(raw) <= 4 * 1024 * 1024, 'checkpoint-budget')
    target = Path(adapter.root) / CHECKPOINT_FILE
    fd = os.open(target, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        need(info.st_size + len(raw) <= 4 * 1024 * 1024, 'checkpoint-budget')
        with os.fdopen(fd, 'ab', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    finally:
        os.close(fd)


def _corpus(adapter, statement, main):
    payloads = {'valid': statement}
    if main:
        payloads.update(malformed=b'{"type":"synthetic-invalid"}',
                        **{'invalid-utf8': b'\xc3\x28', 'oversized': b'x' * 2048})
    result = {}
    for name, payload in payloads.items():
        selected = lifecycle._new_content_key(adapter)
        lifecycle._publish(adapter, selected, payload)
        result[name] = {'uri': selected['uri'], 'bytes': payload}
    return result


def _main(recorder, corpus):
    valid = corpus['valid']
    fixed = (
        ('direct-malformed', {'document': '{}'}, 400),
        ('pasted-preview-valid', {'document': valid['bytes'].decode()}, 200),
        ('uri-preview-valid', {'uri': valid['uri']}, 200),
        ('uri-preview-malformed', {'uri': corpus['malformed']['uri']}, 400),
        ('uri-malformed', {'uri': corpus['malformed']['uri']}, 400),
        ('uri-fingerprint-mismatch', {'uri': valid['uri'], 'expectedDocumentFingerprint': '0' * 64}, 409),
        ('invalid-uri', {'uri': 'file:/pr320-private-synthetic'}, 400),
        ('invalid-utf8', {'uri': corpus['invalid-utf8']['uri']}, 415),
        ('oversized', {'uri': corpus['oversized']['uri'], 'maxBytes': '1024'}, 502),
        ('uri-valid', {'uri': valid['uri']}, 200),
        ('uri-duplicate', {'uri': valid['uri']}, 200),
        ('direct-valid', {'document': valid['bytes'].decode()}, 200))
    for case, parameters, status in fixed:
        response, _events = recorder.record(case, parameters, status=status)
        if case == 'uri-valid':
            need(response.get('importResult', {}).get('imported') is True
                 and response['importResult'].get('signatureVerified') is True, 'signed-import-unverified')
        if case == 'uri-duplicate':
            need(response.get('importResult', {}).get('imported') is False, 'duplicate-not-retained')
    for app, variant in ((APP_IDS[2], 'no-trust'), (APP_IDS[3], 'no-fetch')):
        recorder.record('authorization-denied', {'uri': valid['uri']}, status=403, app=app,
                        variant=variant, path='/api/v1/trust-graph/import-uri')
    controls = []
    for label, headers, expected in (
            ('other-app-origin', {'Origin': recorder.apps[(ROLE, APP_IDS[1])].origin}, 403),
            ('invalid-session', {'X-Crypta-App-Session': 'pr320-invalid-session'}, 401)):
        before = recorder.observe()
        status, _value = recorder.handle.request('POST', '/api/v1/trust-graph/import-uri',
            {'uri': valid['uri']}, principal='app', headers_override=headers)
        after = recorder.observe()
        need(status == expected and lifecycle._unchanged_native(before, after), 'transport-denial-produced-work')
        controls.append({'kind': label, 'status': status, 'before': lifecycle._evidence_snapshot(before),
                         'after': lifecycle._evidence_snapshot(after)})
    return controls


def _interference(recorder, corpus):
    adapter, valid = recorder.adapter, corpus['valid']
    # Reserve one finite real-minute interval before work; no quota or clock mutation after setup.
    while time.time() % 60 > 45:
        adapter.remaining(1); time.sleep(.1)
    recorder.case('direct-malformed', {'document': '{}'}, status=400)
    recorder.case('uri-valid', {'uri': valid['uri']})
    def foreground(app, expected):
        handle = recorder.apps[(ROLE, app)]
        before = recorder.observe()
        status, _ = handle.request('POST', '/api/v1/content/fetch',
            {'uri': valid['uri'], 'maxBytes': '8192', 'timeoutMillis': '3000'}, principal='app')
        after = recorder.observe()
        rows = lifecycle._events(after, before['work']['lastSequence'])
        need(status == expected and sum(row['kind'] == 'FETCH_INVOKED' for row in rows)
             == (1 if expected == 200 else 0), 'foreground-response-invalid')
        if expected == 200:
            selected = next(row for row in rows if row['kind'] == 'BUDGET_ACQUIRE')
            recorder.bind_scope(selected['scope'], app)
        return before, after
    graph_before, before = len(recorder.graph()), recorder.observe()
    foreground(APP_IDS[0], 200); foreground(APP_IDS[0], 200)
    recorder.record('app-fetch-rate', {'uri': valid['uri']}, status=429,
                    path='/api/v1/trust-graph/import-uri')
    recorder.shared_segment('shared-foreground', before, recorder.observe(), graph_before)
    row = recorder.segments[-1]
    recorder.observations.append({'caseId': 'shared-foreground', 'variant': 'native-route',
        'appId': APP_IDS[0], 'scope': row['scope'], 'recordKind': 'segment',
        'recordIndex': len(recorder.segments) - 1, 'responseStatus': 200, 'responseCode': None})
    foreground(APP_IDS[1], 200)
    other = recorder.apps[(ROLE, APP_IDS[1])]
    status, subscription = other.request('POST', '/api/v1/content/subscriptions',
        {'uri': valid['uri'], 'label': 'Synthetic budget subscription', 'pollIntervalSeconds': '2',
         'maxBytes': '8192', 'timeoutMillis': '3000'}, principal='app')
    need(status == 201, 'subscription-create-failed')
    sid = subscription.get('subscription', {}).get('subscriptionId')
    need(isinstance(sid, str) and re.fullmatch('[A-Za-z0-9-]{1,128}', sid), 'subscription-identity-invalid')
    graph_before, before = len(recorder.graph()), recorder.observe()
    status, _ = other.request('POST', '/api/v1/content/subscriptions/' + sid + '/refresh', principal='app')
    after = recorder.observe()
    charges = [row['operation'] for row in lifecycle._events(after, before['work']['lastSequence'])
               if row['kind'] == 'RATE_CHARGED']
    need(status == 200 and sorted(charges) == ['content_fetch_global', 'subscription_poll', 'subscription_poll'],
         'subscription-charging-invalid')
    foreground(APP_IDS[1], 429)
    recorder.record('global-fetch-rate', {'uri': valid['uri']}, status=429, app=APP_IDS[1],
                    path='/api/v1/trust-graph/import-uri')
    recorder.shared_segment('shared-subscription', before, recorder.observe(), graph_before)
    row = recorder.segments[-1]
    recorder.bind_scope(row['scope'], APP_IDS[1])
    recorder.observations.append({'caseId': 'shared-subscription', 'variant': 'native-route',
        'appId': APP_IDS[1], 'scope': row['scope'], 'recordKind': 'segment',
        'recordIndex': len(recorder.segments) - 1, 'responseStatus': 200, 'responseCode': None})
    for _ in range(2): recorder.case('direct-valid', {'document': valid['bytes'].decode()})
    recorder.record('app-import-rate', {'uri': valid['uri']}, status=429, path='/api/v1/trust-graph/import-uri')
    for _ in range(2): recorder.case('direct-valid', {'document': valid['bytes'].decode()}, app=APP_IDS[1])
    recorder.record('global-import-rate', {'uri': valid['uri']}, status=429, app=APP_IDS[1],
                    path='/api/v1/trust-graph/import-uri')
    return []


def _causal(adapter, handles, statement, selected):
    rows, attempts = [], []
    _checkpoint(adapter, {'phase': 'before-causal', 'profile': selected['name']})
    if selected['name'] == 'lifecycle':
        rows.append(lifecycle._run_retry_case(adapter, handles, statement))
        attempts.append({'caseId': 'retry', 'variant': 'independently-charged', 'status': 'executed'})
        timeout, result = lifecycle._run_timeout_case(adapter, handles, statement, capture_response=True)
        if timeout is not None: rows.append(timeout)
        attempts.append({'caseId': 'timeout', 'variant': 'deferred-normal-owner',
                         'status': 'executed' if timeout is not None else 'not-observed',
                         'reason': result.get('reason'), 'responseStatus': result.get('httpStatus')})
    else:
        case, variant = selected['cases'][0], selected['name'].rsplit('-', 1)[1]
        rows.append(lifecycle._run_concurrency_case(adapter, handles, statement, case, variant=variant))
        attempts.append({'caseId': case, 'variant': variant, 'status': 'executed'})
    _checkpoint(adapter, {'phase': 'after-causal', 'attempts': attempts, 'originals': rows,
                          'native': lifecycle._with_graph(handles[APP_IDS[0]], lifecycle._snapshot(handles[APP_IDS[0]]))})
    return rows, attempts


def run_route_lane(adapter, *, leave_running_for_administrator=False, on_start_failure=None):
    need(contract.verify_selection_contract(adapter.plan, adapter.private, adapter.authorization), 'selection-unbound')
    selected = contract.selected_profile(adapter.authorization['executionClass'])
    observations, attempts, controls, causal = [], [], [], []
    completed = False
    try:
        for role in runtime.ROLES: adapter.start(role)
        adapter.connect()
        handles, statement = lifecycle._bootstrap_apps(adapter)
        recorder = RouteRecorder(adapter, handles)
        need(len(recorder.graph()) == 0, 'graph-not-fresh')
        initial = recorder.observe()
        need(initial.get('budgetConfiguration') == selected['normalizedConfiguration']['budgetConfiguration']
             and initial.get('schedulerConfiguration', {}).get('enabled') is False, 'configuration-substituted')
        contexts = {app: lifecycle._context_evidence(handle.context) for app, handle in handles.items()}
        if selected['name'] in {'main', 'interference'}:
            corpus = _corpus(adapter, statement, selected['name'] == 'main')
            controls = _main(recorder, corpus) if selected['name'] == 'main' else _interference(recorder, corpus)
            observations = recorder.observations
            attempts = [{'caseId': row['caseId'], 'variant': row['variant'], 'status': 'executed'} for row in observations]
        else:
            causal, attempts = _causal(adapter, handles, statement, selected)
            for index, row in enumerate(causal):
                variant = next(item['variant'] for item in selected['variants'] if item['caseId'] == row['caseId'])
                app = APP_IDS[0] if variant == 'app' or row['caseId'] == 'timeout' else APP_IDS[1]
                recorder.bind_scope(row['scope'], app)
                for operation in row['operations']:
                    role = operation['role'].split('-', 1)[0]
                    owner = (APP_IDS[1] if row['caseId'] == 'retry' or role == 'contender'
                             and row['caseId'] == 'timeout' else APP_IDS[0]
                             if role == 'holder' or row['caseId'] == 'timeout' else app)
                    if operation['scope'] >= 3:
                        recorder.bind_scope(operation['scope'], owner)
                observations.append({'caseId': row['caseId'], 'variant': variant, 'appId': app,
                    'scope': row['scope'], 'recordKind': 'causal', 'recordIndex': index,
                    'responseStatus': 429 if row['caseId'].endswith('concurrency') else
                        next(item['responseStatus'] for item in attempts if item['caseId'] == 'timeout')
                        if row['caseId'] == 'timeout' else 200, 'responseCode': None})
        node_epoch = adapter.journal.node_epochs[('', ROLE)]
        for row in causal: row['nodeEpoch'] = node_epoch
        node = next(row for row in adapter.plan['nodes'] if row['role'] == ROLE)
        final = lifecycle._with_graph(recorder.handle, recorder.observe())
        attachment = {'schemaVersion': 4, 'collectorEpoch': final['work']['collectorEpoch'], 'nodeEpoch': node_epoch,
            'workloadDigest': adapter.plan['workloadInputs']['scheduler'], 'productDigest': node['artifactDigest'],
            'sourceCommit': node['sourceCommit'], 'appCohortDigest': runtime.canonical_digest(node['appDigests']),
            **adapter.plan['composedBudgetInputs'], 'segments': recorder.segments,
            'causalCases': causal, 'storageCases': []}
        bindings = {key: attachment[key] for key in ('workloadDigest', 'productDigest', 'sourceCommit',
            'appCohortDigest', 'collectorDigest', 'configurationDigest', 'nodeEpoch', 'collectorEpoch')}
        bindings.update(selectionDigest=adapter.authorization['selectionDigest'],
            appBundleDigests=adapter.authorization['budgetSelection']['appBundleDigests'])
        component = {'schemaVersion': 1, 'kind': 'pr320-complete-route-component', 'profile': selected['name'],
            'evidenceClass': 'installed-controller-bound', 'bindings': bindings, 'attachment': attachment,
            'observations': observations, 'attempts': attempts, 'transportControls': controls,
            'scopeBindings': recorder.scope_bindings, 'finalSnapshot': final}
        derived = complete.derive_complete_routes(component)
        if 'budgetCampaignInputs' in adapter.plan:
            from cryptad_certification.composed_budget_journal_member import append_member
            append_member(adapter.journal, 'route-component',
                json.dumps(component, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())
        adapter.journal.append('operation', role=ROLE, scenario='app-budgets', outcome='partial',
            operation='composed-budget-attachment', composed_budget_evidence=attachment)
        private = {'schemaVersion': 1, 'kind': 'pr320-private-route-budget',
            'executionClass': selected['executionClass'], 'selectionDigest': adapter.authorization['selectionDigest'],
            'contexts': contexts, 'component': component, 'coverage': derived}
        _checkpoint(adapter, {'phase': 'native-collected', 'component': component})
        raw = json.dumps(private, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        need(len(raw) <= 4 * 1024 * 1024, 'private-output-budget')
        target = Path(adapter.root) / PRIVATE_FILE
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        completed = True
        return {'schemaVersion': 1, 'kind': 'pr320-installed-route-observation',
            'executionClass': selected['executionClass'], 'selectionDigest': private['selectionDigest'],
            'privateEvidenceDigest': 'sha256:' + hashlib.sha256(raw).hexdigest(), 'evidenceClass': 'installed-controller-bound',
            'observedVariants': derived['verifiedVariants'], 'status': derived['status'],
            'fullAppBudgets': 'not-observed', 'releaseEligible': False, 'phaseComplete': False,
            'cleanupState': 'administrator-required' if leave_running_for_administrator else 'completed'}
    except BaseException:
        _checkpoint(adapter, {'phase': 'interrupted', 'status': 'unknown'})
        if on_start_failure is not None and adapter.active_start_role is not None:
            on_start_failure(adapter.active_start_role, adapter.active_start_stage)
        raise
    finally:
        if (not leave_running_for_administrator or not completed) and adapter.cleanup() != 'complete':
            need(False, 'terminal-reconciliation-required')


def validate_guest_observation(value, expected_selection_digest=None):
    fields = {'schemaVersion', 'kind', 'executionClass', 'selectionDigest', 'privateEvidenceDigest',
        'evidenceClass', 'observedVariants', 'status', 'fullAppBudgets', 'releaseEligible',
        'phaseComplete', 'cleanupState'}
    need(isinstance(value, dict) and set(value) == fields and value['schemaVersion'] == 1
         and value['kind'] == 'pr320-installed-route-observation'
         and value['executionClass'] in contract.EXECUTION_CLASSES
         and value['evidenceClass'] == 'installed-controller-bound'
         and value['status'] in {'complete', 'incomplete'} and value['fullAppBudgets'] == 'not-observed'
         and value['releaseEligible'] is False and value['phaseComplete'] is False
         and value['cleanupState'] in {'administrator-required', 'completed'}
         and all(re.fullmatch('sha256:[a-f0-9]{64}', str(value[key])) for key in
                 ('selectionDigest', 'privateEvidenceDigest'))
         and (expected_selection_digest is None or value['selectionDigest'] == expected_selection_digest),
         'observation-invalid')
    required = contract.selected_profile(value['executionClass'])['variants']
    rows = value['observedVariants']
    need(isinstance(rows, list) and all(row in required for row in rows)
         and rows == sorted(rows, key=lambda row: (row['caseId'], row['variant']))
         and len({(row['caseId'], row['variant']) for row in rows}) == len(rows)
         and (value['status'] == 'complete') == (len(rows) == len(required)), 'observation-variants-invalid')
    return value


def attach_guest_context(value, identity, runtime_policy, campaign_deadline):
    validate_guest_observation(value)
    return {**value, 'identity': identity, 'runtimePolicy': runtime_policy,
        'campaignDeadlineMonotonicNs': campaign_deadline,
        'workloadAcceptance': 'incomplete-pr320-private-evidence-not-verified',
        'protectedExecutionEnabled': False}
