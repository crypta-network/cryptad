"""Offline original vectors exercise real consumers; these never claim installed execution."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
from types import SimpleNamespace
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import zipfile

import pr320_privacy_contract as contract
import pr320_privacy_runtime_evidence as evidence
import pr320_privacy_runtime_runner as runner
import pr320_privacy_browser_admin as browser_admin
import pr320_privacy_admin as administrator_module
import pr320_stdio_capture as stdio
import cross_version_installed_privacy_budgets as driver
from cryptad_certification import composed_budget_privacy_evidence as privacy
from cryptad_certification.tests.test_composed_budget_storage_evidence import Vector, EPOCH
from test_pr318_storage_installed import host_selection


def encoded(value):
    return json.dumps(value, separators=(',', ':'), allow_nan=False).encode()


class PrivacyCollectionRegressionTest(unittest.TestCase):
    def test_actual_seqpacket_admin_roundtrip_retains_large_snapshot_and_browser_receipts(self):
        from pr314_workload_driver import AdministratorFnpSampler
        for command, result in (
            ('privacy:snapshot', {'logs': {'daemon.log': 'synthetic private log\n' * 15000}}),
            ('privacy:browser', {'collectorOutput': [{'stdout': 'synthetic browser output' * 20000}],
                                 'component': {'kind': 'synthetic browser fixture'}}),
        ):
            with self.subTest(command=command):
                server, observer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                failures = []
                sampler = AdministratorFnpSampler(SimpleNamespace(), 'fixed', {})
                sampler.privacy_collector = SimpleNamespace(request=lambda *_args: result)
                server.settimeout(5)
                def serve():
                    try:
                        sampler.serve(server)
                    except BaseException as error:
                        failures.append(error)
                    finally:
                        server.close()
                thread = threading.Thread(target=serve)
                thread.start()
                try:
                    def lane(adapter, administrator, **kwargs):
                        administrator.browser_context = {'appOrigin': 'synthetic-origin', 'appSession': 'synthetic-session'}
                        return administrator(command)
                    with patch.object(driver, 'run_privacy_lane', side_effect=lane):
                        received = administrator_module.run_observer(None, observer,
                            time.monotonic_ns() + 5 * 10**9, None)
                    self.assertEqual(result, received)
                    self.assertGreater(len(encoded(received)), 300 * 1024)
                finally:
                    observer.close()
                    thread.join(timeout=6)
                self.assertFalse(thread.is_alive())
                self.assertEqual([], failures)

    def test_framed_reply_preserves_exact_bytes_at_chunk_and_total_limits(self):
        for size in (1, administrator_module.REPLY_CHUNK_BYTES,
                     administrator_module.REPLY_CHUNK_BYTES + 1, administrator_module.MAX_REPLY_BYTES):
            with self.subTest(size=size):
                server, observer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                original = (b'private-byte-vector-' * (size // 20 + 1))[:size]
                failures = []
                def send():
                    try:
                        administrator_module._send_reply(server, original, time.monotonic() + 5)
                    except BaseException as error:
                        failures.append(error)
                    finally:
                        server.close()
                thread = threading.Thread(target=send)
                thread.start()
                try:
                    self.assertEqual(original, administrator_module._receive_reply(observer, time.monotonic() + 5))
                finally:
                    observer.close()
                    thread.join(timeout=6)
                self.assertFalse(thread.is_alive())
                self.assertEqual([], failures)

    def test_framed_reply_rejects_invalid_size_order_digest_truncation_and_interrupted_transfer(self):
        for fault in ('oversize', 'zero', 'order', 'digest', 'truncated', 'missing', 'deadline'):
            with self.subTest(fault=fault):
                server, observer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                try:
                    raw = b'original receipt'
                    size = administrator_module.MAX_REPLY_BYTES + 1 if fault == 'oversize' else (0 if fault == 'zero' else len(raw))
                    header = administrator_module.REPLY_MAGIC + size.to_bytes(4, 'big') + hashlib.sha256(raw).digest()
                    server.sendall(header)
                    if fault != 'missing':
                        index = 1 if fault == 'order' else 0
                        chunk = index.to_bytes(4, 'big') + (b'changed receipt!' if fault == 'digest' else raw)
                        if fault == 'truncated': chunk += b'x' * administrator_module.REPLY_CHUNK_BYTES
                        server.sendall(chunk)
                    server.close()
                    with self.assertRaises(ValueError):
                        administrator_module._receive_reply(observer,
                            time.monotonic() + (-1 if fault == 'deadline' else 2))
                finally:
                    server.close()
                    observer.close()

    def test_reply_budget_and_collector_failure_remain_closed_after_framing(self):
        for fault in ('budget', 'collector'):
            with self.subTest(fault=fault):
                server, observer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                try:
                    def request(*_args):
                        if fault == 'collector': raise ValueError('synthetic-private-failure')
                        return {'logs': {'daemon.log': 'x' * administrator_module.MAX_REPLY_BYTES}}
                    sampler = SimpleNamespace(privacy_collector=SimpleNamespace(request=request))
                    administrator_module.serve_privacy(sampler, server, b'Q{"command":"privacy:snapshot"}', 0)
                    received = json.loads(administrator_module._receive_reply(observer, time.monotonic() + 2))
                    self.assertEqual({'error': 'pr320-privacy-collector-' + ('budget' if fault == 'budget' else 'failed')}, received)
                    self.assertNotIn('synthetic-private-failure', json.dumps(received))
                finally:
                    server.close()
                    observer.close()

    def test_subscription_summary_is_collected_before_original_session_expires(self):
        expired, requests = False, []
        handles = {app: SimpleNamespace(app_id=app, origin='http://127.0.0.1:19403',
            session='synthetic-session-' + app, password='synthetic-password',
            context={'sessionExpiresAt': '2026-10-14T01:00:00Z'},
            request=lambda *_args: (200, {})) for app in driver.APP_IDS}
        recipient = SimpleNamespace(context={}, host_bootstrap=lambda: None)
        snapshot = {'work': {'lastSequence': 0},
                    'budget': {'activeFamilyLeases': 0, 'reservedFamilyRates': 0}}
        def request(handle, method, path, parameters=None, *, principal='app', **kwargs):
            requests.append((path, principal, expired))
            status, body = 200, {}
            if principal == 'app':
                if expired or handle is recipient or kwargs or (method, path) in driver.DENIAL_ROUTES:
                    status = 403
                elif path == '/api/v1/trust-graph/import' and parameters['document'] == '{}':
                    status = 400
                elif path == '/api/v1/trust-graph/import-uri' and parameters['uri'] == driver.DATA_SENTINELS['filesystem']:
                    status = 400
                elif handle.app_id in {'budget-no-trust', 'budget-no-fetch'}:
                    status = 403
                elif path == '/api/v1/content/fetch':
                    status = {'8192': 415, '1024': 502}.get(parameters.get('maxBytes'), 504)
                elif path == '/api/v1/app-data/records':
                    status = 201
                elif path == '/api/v1/content/subscriptions':
                    body = {'subscriptions': [], 'count': 0}
                elif path == '/api/v1/trust-graph/import':
                    body = {'importResult': {'documentFingerprint': 'synthetic-document-identity'}}
            return {'status': status, 'body': body, 'wire': '{}'}
        def expire(_handle):
            nonlocal expired
            expired = True
        def original(_action):
            return {'graphFacts': [], 'logs': {}}
        statement = encoded({'payload': {'reason': 'synthetic-reason',
                                        'subject': {'uri': 'synthetic-subject'}}})
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(driver, '_request', side_effect=request), \
                patch.object(driver, '_wait_actual_expiry', side_effect=expire), \
                patch.object(driver.transport, '_snapshot', return_value=snapshot), \
                patch.object(driver.transport, '_new_content_key', return_value={'uri': 'synthetic-uri'}), \
                patch.object(driver.transport, '_publish'), \
                patch.object(driver.transport, '_wait_for', return_value=snapshot), \
                patch.object(driver.transport, '_unchanged_native', return_value=True), \
                patch.object(driver.transport, '_context_evidence', return_value={}), \
                patch.object(driver.transport, 'BudgetAppHandle', return_value=recipient):
            result = driver.collect_native(SimpleNamespace(root=Path(temporary)), handles, statement, original)
            self.assertTrue((Path(temporary) / driver.CHECKPOINT_FILE).exists())
        self.assertEqual({'subscriptions': [], 'count': 0}, result['surfaces']['subscriptionSummary'])
        self.assertEqual([('/api/v1/content/subscriptions', 'app', False)],
                         [row for row in requests if row[0] == '/api/v1/content/subscriptions'])
        self.assertEqual([('/api/v1/operator/support-bundle', 'app', True)],
                         [row for row in requests if row[1] == 'app' and row[2]])
        self.assertEqual(403, next(row['status'] for row in result['denials']
                                  if row['principal'] == 'expired-session'))

    def test_log_collection_reads_bound_generation_and_base_logs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / 'state' / administrator_module.ROLE
            (state / 'logs').mkdir(parents=True, mode=0o700)
            state.chmod(0o700)
            (state / 'logs/wrapper.log').write_text('synthetic wrapper output')
            (state / 'logs/wrapper.log').chmod(0o600)
            capture = stdio.Capture(state, generation='a' * 32)
            os.write(capture.files['stdout.private.log'], b'synthetic daemon output')
            capture.close()
            with patch.object(administrator_module.historical, '_fixed_mount'):
                logs = administrator_module._logs(SimpleNamespace(ROOT=root), os.geteuid(), 'a' * 32)
                self.assertEqual('synthetic daemon output', logs['stdout.private.log'])
                self.assertEqual('synthetic wrapper output', logs['wrapper.log'])
                duplicate = state / 'logs/stdout.private.log'
                duplicate.write_text('ambiguous capture output')
                duplicate.chmod(0o600)
                with self.assertRaises(ValueError):
                    administrator_module._logs(SimpleNamespace(ROOT=root), os.geteuid(), 'a' * 32)
                duplicate.unlink()
                with self.assertRaises(ValueError):
                    administrator_module._logs(SimpleNamespace(ROOT=root), os.geteuid(), 'b' * 32)
                foreign = stdio.Capture(state, generation='b' * 32)
                foreign.close()
                with self.assertRaises(ValueError):
                    administrator_module._logs(SimpleNamespace(ROOT=root), os.geteuid(), 'a' * 32)


def selection():
    value, fixture = host_selection()
    profile = contract.profile()
    plan, private, auth = value['plan'], value['private'], value['authorization']
    plan['experimentId'] = profile['experiment']
    private['root'] = '/var/lib/cryptad-cross-version/experiments/' + profile['experiment']
    auth.update(executionClass=profile['executionClass'], experimentId=profile['experiment'], root=private['root'])
    provider = {'schemaVersion': 1, 'kind': 'pr320-qualified-browser-provider',
                **{key: 'sha256:' + 'f' * 64 for key in ('nodeDigest', 'chromiumDigest', 'packageDigest')}}
    auth['browserProvider'] = provider
    tools = {key: 'sha256:' + 'd' * 64 for key in contract.TOOL_PATHS}
    tools['webShellScript'] = 'sha256:' + 'e' * 64
    budget = auth['budgetSelection']
    budget.update(caseIds=['privacy'], environment=profile['environment'],
        normalizedConfiguration=profile['normalizedConfiguration'], toolIdentities=tools,
        permissions={key: list(value) for key, value in contract.PERMISSIONS.items()},
        privateRootClass='controller-derived-' + profile['experiment'])
    plan['workloadInputs'] = {'scheduler': tools['installedDriver']}
    plan['composedBudgetInputs'] = {'collectorDigest': contract.canonical_digest({key: tools[key] for key in
        ('installedDriver', 'localBudgetAdapter', 'schedulerRuntime', 'evidenceOracle', 'storageOracle',
         'administrator', 'roleClients', 'runtimeEvidence')}),
        'configurationDigest': contract.configuration_digest(plan, provider)}
    budget['composedBudgetInputs'] = copy.deepcopy(plan['composedBudgetInputs'])
    from cryptad_certification.composed_budget_journal_member import campaign_inputs
    plan['budgetCampaignInputs']=campaign_inputs(plan,tools)
    auth['planDigest'] = contract.canonical_digest(plan)
    auth['selectionDigest'] = contract.selection_digest(auth)
    fixture.update(browserProvider=provider, toolIdentities=tools, permissions=budget['permissions'])
    return value, fixture


def vector():
    selected, _ = selection()
    selection_digest = selected['authorization']['selectionDigest']
    origin = 'http://127.0.0.1:19403'
    context = {key: 'sha256:' + 'a' * 64 for key in evidence.CONTEXT_FIELDS - {'appId', 'role'}}
    context.update(appId='feed-reader', role='candidate-sender', originDigest=contract.canonical_digest(origin))
    apps = {app: dict(context, appId=app) for app in contract.APP_IDS}
    markers = {purpose: 'PR320_SYNTHETIC_PRIVATE_' + purpose + '_VECTOR' for purpose in privacy.PURPOSES}
    markers['appDataKey'] = driver.KEY
    markers['documentIdentity'] = selected['authorization']['budgetSelection']['statementFingerprint']
    data = {key: value for key, value in markers.items() if key not in
            {'statement', 'sourceLabel', 'sourceUri', 'subject', 'documentIdentity'}}
    raw = encoded(data)
    app_record = {'namespace': driver.NAMESPACE, 'key': driver.KEY, 'valueBytes': len(raw),
        'sha256': hashlib.sha256(raw).hexdigest(), 'valueText': raw.decode(),
        'valueBase64': base64.b64encode(raw).decode()}
    graph = [{'documentFingerprint': markers['documentIdentity'], 'signatureVerified': True,
        'sourceLabel': markers['sourceLabel'], 'sourceUri': markers['sourceUri'],
        'document': {'payload': {'reason': markers['statement'], 'subject': {'uri': markers['subject']}}}}]
    v = Vector()
    def snapshot():
        return {'work': {'version': 4, 'known': True, 'dropped': 0, 'collectorEpoch': EPOCH,
            'lastSequence': len(v.events), 'events': copy.deepcopy(v.events)},
            'budget': {'valid': True, 'rates': [], 'activeFamilyLeases': 0, 'reservedFamilyRates': 0}}
    before = snapshot()
    v.direct(1)
    v.event('FETCH_SUCCEEDED', 3, 'trust_graph_import_uri')
    after = snapshot()
    bundle = {'kind': 'cryptad-operator-support-bundle', 'schemaVersion': 2,
        'generatedAt': '2026-10-14T01:00:00Z', 'sections': ['dashboard', 'diagnostics'],
        'dashboard': {'trustGraph': {'statementCount': 1}}, 'diagnostics': {'sectionCount': 1},
        'redaction': {'status': 'pass', 'rawSensitiveMaterialExcluded': True, 'redactionFindings': []}}
    bundle['supportDigest'] = {'algorithm': 'SHA-256', 'digest': hashlib.sha256(encoded(bundle)).hexdigest()}
    wire = encoded(bundle).decode()
    preview = {'kind': 'crypta-operator-support-bundle-preview', 'supportBundleVersion': 2,
        'includedSections': ['dashboard'], 'redaction': {'status': 'pass'}}
    logs = {'stdout.private.log': '', 'stderr.private.log': ''}
    daemon = {'hostPid': 500, 'startTicks': 400, 'executableDigest': 'sha256:' + 'b' * 64,
        'networkNamespaceIdentity': [2, 3]}
    owner = {'generation': 'a' * 64, 'managerInvocation': 'b' * 32, 'bootId': EPOCH, 'handle': 'c' * 64}
    worker = {'appHostLeader': {'hostPid': 501, 'startTicks': 401, 'pidNamespace': 'pid:[1]'},
              'fixtureProcess': {'hostPid': 502, 'startTicks': 402, 'pidNamespace': 'pid:[2]'}}
    binding = {'daemon': {'hostPid': 500, 'startTicks': 400, 'pidNamespace': 'pid:[0]'}, 'worker': worker}
    expires = '2026-10-14T01:00:00Z'
    import datetime as dt
    expiry_ns = int(dt.datetime.fromisoformat(expires.replace('Z','+00:00')).timestamp() * 10**9)
    for app in ('feed-reader', 'budget-importer'):
        apps[app].update(workerEpochDigest=contract.canonical_digest(worker),
            daemonEpochDigest=contract.canonical_digest(binding['daemon']),
            sessionExpiryDigest=contract.canonical_digest(expires))
    boundaries = {'expiredSession': {'kind': 'privacy:expired-session', 'appId': 'feed-reader',
            'context':apps['feed-reader'],'binding':binding,'observedEpochNs':expiry_ns+10**9,
            'observedMonotonicNs':500,'expiresAt':expires},
        'staleWorkerBefore':{'kind':'privacy:stale-worker-before','appId':'budget-importer',
            'context':apps['budget-importer'],'binding':binding,'observedEpochNs':expiry_ns-3*10**9,
            'observedMonotonicNs':100,'expiresAt':expires},
        'staleWorkerAfter':{'kind':'privacy:stale-worker-after','appId':'budget-importer',
            'context':apps['budget-importer'],'runtime':{'running':False,'pid':None},
            'terminatedWorkers':[dict(worker[key],dead=True) for key in ('appHostLeader','fixtureProcess')],
            'observedEpochNs':expiry_ns-2*10**9,'observedMonotonicNs':200}}
    for key in ('expiredSession','staleWorkerAfter'):
        boundaries[key]['denial']={'status':403,'body':{'error':'denied'},'beforeNative':after,'afterNative':after}
    receipt = {'schemaVersion': 1, 'kind': 'pr320-original-privacy-readback', 'role': 'candidate-sender',
        **{key: owner[key] for key in ('generation', 'managerInvocation', 'bootId')},
        'selectionDigest': selection_digest, 'daemon': daemon, 'dataIdentity': {'device': 1, 'inode': 2},
        'durableUsage': [], 'graphFacts': graph, 'captureSource': 'administrator-fixed-file-store-readback',
        'capturedMonotonicNs': 100, 'observedMonotonicNs': 100, 'appData': app_record, 'logs': logs,
        'boundaryEvidence': {}}
    component = {'schemaVersion': 1, 'caseId': 'privacy', 'evidenceClass': evidence.EVIDENCE_CLASS,
        'producer': 'cross_version_installed_privacy_budgets',
        'stimuli': [{'purpose': key, 'marker': value, 'privateSurface': 'graph' if key in
            {'statement', 'sourceLabel', 'sourceUri', 'subject', 'documentIdentity'} else 'appData'}
            for key, value in markers.items()],
        'privateSurfaces': {'graph': graph, 'appData': {'record': app_record},
            'backup': {'payloadBase64': base64.urlsafe_b64encode(encoded({'valueBase64': app_record['valueBase64']})).decode().rstrip('=')}},
        'surfaces': {'appErrors': [{'status': status, 'body': {'error': 'request rejected'}}
            for status in (400, 400, 403, 403, 415, 502, 504)],
            'appAudit': {phase: {'audit': {'appId': 'feed-reader', 'events': [{'kind': 'import'}]}}
                         for phase in ('stimulus', 'final')},
            'supportBundle': bundle, 'supportBundleText': wire, 'supportPreview': preview,
            'workSnapshot': after['work'], 'operatorRuntime': after, 'queueSummary': {'count': 0},
            'subscriptionSummary': {'count': 0}, 'logs': logs},
        'denials': [{'route': route, 'principal': principal, 'status': 403, 'body': {'error': 'denied'},
                     'beforeNative': after, 'afterNative': after}
            for route, principal in sorted({(route, 'non-operator-app') for route in evidence.ROUTES} |
                {('operator/support-bundle', principal) for principal in evidence.REQUIRED_PRINCIPALS})],
        'phaseContexts': {'before': before, 'after': after, 'apps': apps},
        'originalReceipts': [copy.deepcopy(receipt), dict(copy.deepcopy(receipt), boundaryEvidence=boundaries)],
        'boundaryEvidence': boundaries}
    private = {'schemaVersion': 1, 'kind': 'pr320-private-native-privacy',
               'selectionDigest': selection_digest, 'component': component}
    native_digest = 'sha256:' + hashlib.sha256(encoded(private)).hexdigest()
    script_digest = 'sha256:' + 'e' * 64
    browser = {'schemaVersion': 1, 'kind': 'composed-budget-installed-browser-component',
        'transport': 'selected-role-namespace-http', 'nativeMemberDigest': native_digest,
        'scriptDigest': script_digest, 'browserBundleText': wire, 'clipboardText': wire + '\n',
        'downloadText': wire + '\n', 'downloadName': 'cryptad-support-bundle-2026.json',
        'domText': 'Support bundle verified', 'persistence': {'local': [], 'session': [], 'databases': []},
        'appPersistence': {'local': [], 'session': [], 'databases': []},
        'failedExports': [{'variant': name, 'copyDisabled': True, 'downloadDisabled': True,
            'statusText': 'Support bundle could not be verified; generate it again before export.',
            'domText': 'Export unavailable'} for name in ('failed', 'malformed', 'digest', 'redaction')],
        'browserDenials': [{'route': route, 'status': 403, 'body': '{"error":"denied"}'} for route in
            ('operator/runtime-observation', 'operator/network-budgets', 'operator/support-bundle', 'operator/beta-dashboard')],
        'requests': [{'origin': base, 'path': path, 'method': 'GET'} for base, path in
            [('http://127.0.0.1:19402', '/api/v1/operator/support-bundle'),
             ('http://127.0.0.1:19402', '/api/v1/operator/support-bundle/preview'), (origin, '/')]],
        'faultEvidenceClass': 'browser-response-negative-fixture'}
    browser_receipt = {'schemaVersion': 1, 'kind': 'pr320-original-browser-observation',
        'selectionDigest': selection_digest, **{key: owner[key] for key in ('generation', 'managerInvocation', 'bootId')},
        'daemon': daemon, 'provider': selected['authorization']['browserProvider'], 'component': browser, 'appBinding':binding,
        'packagedScriptDigest': script_digest, 'appOrigin': origin,
        'collectorOutput': [{'stdout': encoded(browser).decode(), 'stderr': ''}],
        'startedMonotonicNs': 100, 'finishedMonotonicNs': 200,
        'collectorDigest': selected['authorization']['budgetSelection']['toolIdentities']['browserCollector']}
    originals = {'schemaVersion': 1, 'kind': 'pr320-private-privacy-originals',
        'selectionDigest': selection_digest, 'bootstrapContext': dict(owner, apps=apps),
        'receipts': component['originalReceipts'] + [browser_receipt],
        'finalLogs': {**logs, 'stdio.private.json': encoded({'schemaVersion': 2,
            'generation': component['originalReceipts'][0]['managerInvocation'], 'status': 'complete',
            'completeStreams': sorted(logs), 'bytes': {key: 0 for key in logs}}).decode()},
        'cleanupStatus': 'completed', 'browserFailure': None}
    records, stops = {}, {}
    for role in contract.ROLES:
        record = dict(owner, role=role, state='quiescent', cgroupIdentity=[1, 2])
        records[role] = {'status': 'captured', 'record': record}
        stops[role] = {'current': {'status': 'captured', 'record': dict(record,
                          membership='only-stop-helper', descendantCgroups=0)}}
    terminal = {'schemaVersion': 1, 'kind': 'pr315-private-volatile-diagnostics',
        'cleanupReportedByCaller': True, 'sentinel': {'status': 'matched', 'expectedDigest': 'sha256:'+'a'*64,
            'observedDigest': 'sha256:'+'a'*64, 'sizeBytes': 32}, 'controllerRecords': records, 'stopReceipts': stops}
    return dict(private=private, selected=selected, diagnostics={'privacyCollectorCleanup': 'completed'},
        terminal=terminal, report={'guestStopped': True}, originals=originals, browser=browser,
        native_digest=native_digest)


class PrivacyInstalledTests(unittest.TestCase):
    def test_stdio_receipt_must_match_the_observed_manager_invocation(self):
        for generation in (None, 'c' * 32):
            args = vector()
            receipt = json.loads(args['originals']['finalLogs']['stdio.private.json'])
            receipt['generation'] = generation
            args['originals']['finalLogs']['stdio.private.json'] = encoded(receipt).decode()
            with self.assertRaisesRegex(ValueError, 'stdio-generation-substituted'):
                evidence.validate_originals(**args)

    def test_closed_new_selection_binds_provider_and_same_new_signed_cohort(self):
        selected, fixture = selection()
        self.assertTrue(contract.verify_selection_contract(**selected))
        self.assertEqual(selected['authorization']['selectionDigest'], runner._selection(selected, fixture))
        old = copy.deepcopy(selected)
        old['authorization']['browserProvider']['packageDigest'] = 'sha256:' + '0' * 64
        self.assertFalse(contract.verify_selection_contract(**old))

    def test_source_closure_members_exist_and_prospective_expiry_ceiling_is_bound(self):
        import pr320_privacy_selection
        root=Path(__file__).resolve().parents[3]
        identities=pr320_privacy_selection.tool_identities(root)
        self.assertEqual(set(contract.TOOL_PATHS),set(identities))
        selected,_=selection()
        for seconds, accepted in ((3600,True),(7200,True),(7201,False)):
            value=copy.deepcopy(selected)
            value['plan']['requestedSeconds']=seconds
            value['authorization']['maxSeconds']=seconds
            value['authorization']['planDigest']=contract.canonical_digest(value['plan'])
            value['authorization']['selectionDigest']=contract.selection_digest(value['authorization'])
            self.assertIs(accepted,contract.verify_selection_contract(**value))

    def test_actual_consumer_accepts_complete_raw_native_browser_and_terminal_original_vectors(self):
        args = vector()
        evidence.decode_private(encoded(args['private']))
        evidence.decode_originals(encoded(args['originals']))
        evidence.decode_browser(encoded(args['browser']))
        result = evidence.validate_originals(**args)
        self.assertEqual({'native', 'browser'}, set(result))
        projected = evidence.public_projection(**args)
        self.assertEqual('observed', projected['status'])
        self.assertEqual('administrator-matched-not-protected-authority', projected['originalAuthentication'])
        self.assertFalse(projected['releaseEligible'])
        privacy.check_omission(projected, [row['marker'] for row in args['private']['component']['stimuli']], public=True)

    def test_raw_original_rejects_provider_source_namespace_role_copy_loss_and_cleanup_substitution(self):
        for mutation in ('provider', 'collector', 'script', 'origin', 'role', 'daemon', 'native', 'copy',
                         'loss', 'cleanup', 'stdio', 'tail', 'statement', 'browser-output'):
            args = vector()
            root = args['originals']; receipt = root['receipts'][2]
            if mutation == 'provider': receipt['provider'] = dict(receipt['provider'], packageDigest='sha256:'+'0'*64)
            if mutation == 'collector': receipt['collectorDigest'] = 'sha256:'+'0'*64
            if mutation == 'script': receipt['packagedScriptDigest'] = 'sha256:'+'0'*64
            if mutation == 'origin': receipt['appOrigin'] = 'http://127.0.0.1:19404'
            if mutation == 'role': root['bootstrapContext']['generation'] = '0'*64
            if mutation == 'daemon': receipt['daemon'] = dict(receipt['daemon'], startTicks=900)
            if mutation == 'native': args['browser']['nativeMemberDigest'] = 'sha256:'+'0'*64
            if mutation == 'copy': args['browser']['clipboardText'] = 'copied unrelated data'
            if mutation == 'loss': root['receipts'].pop()
            if mutation == 'cleanup': args['report']['guestStopped'] = False
            if mutation == 'stdio': root['finalLogs']['stdio.private.json'] = '{"status":"running"}'
            if mutation == 'tail': root['finalLogs']['stdout.private.log'] = 'unrecorded tail'
            if mutation == 'statement': args['selected']['authorization']['budgetSelection']['statementFingerprint'] = '0'*64
            if mutation == 'browser-output': receipt['collectorOutput'][0]['stdout'] = '{}'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                evidence.validate_originals(**args)

    def test_native_boolean_missing_wire_empty_audit_error_roster_and_composed_denial_reject(self):
        for mutation in ('boolean', 'wire', 'audit', 'errors', 'denial-work', 'contamination'):
            component = vector()['private']['component']
            if mutation == 'boolean': component['privacyVerified'] = True
            if mutation == 'wire': component['surfaces'].pop('supportBundleText')
            if mutation == 'audit': component['surfaces']['appAudit']['stimulus']['audit']['events'] = []
            if mutation == 'errors': component['surfaces']['appErrors'].pop()
            if mutation == 'denial-work': component['denials'][0]['afterNative'] = component['phaseContexts']['before']
            if mutation == 'contamination': component['surfaces']['logs']['stderr.private.log'] = component['stimuli'][0]['marker']
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): evidence.verify_component(component)

    def test_browser_failed_copy_network_persistence_and_false_server_fault_reject(self):
        for mutation in ('persistent', 'failed-export', 'false-server-fault', 'network', 'lost-denial', 'port'):
            args = vector(); browser = args['browser']
            if mutation == 'persistent': browser['persistence']['local'] = ['stored']
            if mutation == 'failed-export': browser['failedExports'][0]['copyDisabled'] = False
            if mutation == 'false-server-fault': browser['faultEvidenceClass'] = 'actual-server-fault'
            if mutation == 'network': browser['requests'][0]['origin'] = 'http://external.example'
            if mutation == 'lost-denial': browser['browserDenials'].pop()
            if mutation == 'port': browser['requests'][-1]['origin'] = 'http://127.0.0.1:99999'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                evidence.verify_browser_component(browser, args['private']['component'],
                    native_digest=args['native_digest'], script_digest=browser['scriptDigest'])

    def test_failed_postprocess_preserves_fixed_original_stdout_stderr(self):
        args = vector(); selected = args['selected']
        workload = SimpleNamespace(ROOT=Path('/unused'), group=lambda role: Path('/unused'),
            read=lambda path:args['originals']['bootstrapContext'])
        campaign = {'budgetSelectionDigest': selected['authorization']['selectionDigest'],
                    'deadlineMonotonicNs': 10**30}
        def process(*argv, **kwargs):
            kwargs['diagnostic_sink'](b'{"invalid":"original"}', b'')
            return b'{"invalid":"original"}'
        with patch.object(browser_admin, '_selected', return_value=selected), \
             patch.object(browser_admin, '_validate_context', return_value={'appOrigin':'http://127.0.0.1:19403','appSession':'x'*20}), \
             patch.object(browser_admin, 'verify_provider', return_value=selected['authorization']['browserProvider']), \
             patch.object(browser_admin.historical, '_daemon', return_value=({'hostPid':500}, -1)), \
             patch.object(browser_admin.os, 'close'), patch.object(browser_admin, 'run', side_effect=process), \
             patch('pr320_privacy_admin.FixedPrivacyCollector._worker',return_value=(args['originals']['receipts'][2]['appBinding'],{})), \
             patch.object(browser_admin, '_packaged_script_digest', return_value='sha256:'+'e'*64), \
             patch('pr320_privacy_admin._write_root') as write:
            with self.assertRaises(ValueError): browser_admin.collect_browser(workload, campaign, {'handle':'fixed','generation':'a'*64}, None, {})
            self.assertEqual('pr320-privacy-browser-failure.json', write.call_args.args[1])
            self.assertEqual('{"invalid":"original"}', write.call_args.args[2]['diagnostics'][0]['stdout'])

    def test_root_common_kernel_report_preserves_role_cleanup_without_inventing_vm_stop(self):
        args=vector()
        for authority in args['terminal']['controllerRecords'].values():
            authority['record']['roleEpochDigest']='sha256:'+'a'*64
        epochs={role:{key:authority['record'][key] for key in
            ('bootId','generation','managerInvocation','roleEpochDigest')}
            for role,authority in args['terminal']['controllerRecords'].items()}
        report={'schemaVersion':1,'kind':'pr320-root-native-original-report',
            'clockDomain':'protected-host-and-role-common-kernel-utc','bootId':EPOCH,
            'unit':'cryptad-pr320-original-acquisition.service','invocationId':'a'*32,
            'storageClock':{'before':{'hostEpochBeforeNanos':1791939600000000000,'hostEpochAfterNanos':1791939600000000001,
                'guestEpochNanos':1791939600000000000,'hostMonotonicBeforeNanos':1,'hostMonotonicAfterNanos':2},
                'after':{'hostEpochBeforeNanos':1791939601000000000,'hostEpochAfterNanos':1791939601000000001,
                'guestEpochNanos':1791939601000000000,'hostMonotonicBeforeNanos':1000,'hostMonotonicAfterNanos':1001}},'planDigest':contract.canonical_digest(args['selected']['plan']),
            'activationDigest':'sha256:'+'b'*64,'observationDigest':'sha256:'+'c'*64,
            'checkpointDigest':'sha256:'+'d'*64,'roleCleanup':'completed','roleKernelEpochs':epochs}
        args['report']=report
        self.assertNotIn('guestStopped',report)
        self.assertEqual({'native','browser'},set(evidence.validate_originals(**args)))
        for fault in ('boot','epoch','clock','cleanup','plan','guest-flag'):
            changed=copy.deepcopy(args)
            if fault=='boot':changed['report']['bootId']='different-kernel'
            if fault=='epoch':changed['report']['roleKernelEpochs']['candidate-sender']['generation']='0'*64
            if fault=='clock':changed['report']['clockDomain']='invented-guest-clock'
            if fault=='cleanup':changed['report']['roleCleanup']='incomplete'
            if fault=='plan':changed['report']['planDigest']='sha256:'+'0'*64
            if fault=='guest-flag':changed['report']['guestStopped']=True
            with self.subTest(fault=fault),self.assertRaises(ValueError):evidence.validate_originals(**changed)

    def test_actual_expiry_wait_uses_only_observed_clock_and_honestly_fails_short_deadline(self):
        import datetime as dt
        expiry = dt.datetime.fromisoformat('2026-10-14T01:00:00+00:00').timestamp()
        now = [expiry-2, 10.0]
        handle = SimpleNamespace(context={'sessionExpiresAt':'2026-10-14T01:00:00Z'},
                                 supervisor=SimpleNamespace(deadline=100.0))
        def sleep(seconds):
            now[0] += seconds; now[1] += seconds
        with patch.object(driver.time,'time',side_effect=lambda:now[0]), \
             patch.object(driver.time,'monotonic',side_effect=lambda:now[1]), \
             patch.object(driver.time,'sleep',side_effect=sleep) as sleeping:
            driver._wait_actual_expiry(handle)
            self.assertEqual(expiry,now[0]); self.assertEqual(2,sleeping.call_count)
            now[:] = [expiry-2,10.0]; handle.supervisor.deadline=10.5
            with self.assertRaisesRegex(driver.transport.runtime.RuntimeFailure,'expiry-not-observed'):
                driver._wait_actual_expiry(handle)
            self.assertLess(now[0],expiry)

    def test_boundary_cannot_relabel_early_expiry_dead_worker_or_expired_stale_token(self):
        for mutation in ('early-expiry','dead-worker','wrong-worker','expired-stale','alive-stale'):
            component=vector()['private']['component']; boundary=component['boundaryEvidence']
            if mutation=='early-expiry': boundary['expiredSession']['observedEpochNs']=0
            if mutation=='dead-worker': boundary['expiredSession']['binding']['worker']['fixtureProcess']['startTicks']=999
            if mutation=='wrong-worker': boundary['staleWorkerBefore']['context']['workerEpochDigest']='sha256:'+'0'*64
            if mutation=='expired-stale': boundary['staleWorkerAfter']['observedEpochNs']=10**30
            if mutation=='alive-stale': boundary['staleWorkerAfter']['terminatedWorkers'][0]['dead']=False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): evidence.verify_component(component)

    def test_host_attempt_reads_exact_original_members_and_rejects_transfer_tampering(self):
        args = vector()
        selected, fixture = selection()
        raw = encoded(args['private'])
        browser_raw = encoded(args['browser'])
        original_raw = encoded(args['originals'])
        native_digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
        observation = driver.attach_guest_context({'schemaVersion':1,
            'kind':'pr320-installed-native-privacy-observation', 'executionClass':contract.EXECUTION_CLASS,
            'selectionDigest':selected['authorization']['selectionDigest'],
            'privateEvidenceDigest':native_digest,
            'browserEvidenceDigest':'sha256:' + hashlib.sha256(browser_raw).hexdigest(),
            'evidenceClass':evidence.EVIDENCE_CLASS, 'observedComponents':['native','browser'],
            'fullAppBudgets':'not-observed', 'phaseComplete':False, 'releaseEligible':False,
            'cleanupState':'completed'}, {}, {}, 10**12)
        diagnostics = dict(args['diagnostics'], privacyOriginalsFile=evidence.ORIGINALS_FILE,
            privacyOriginalsBytes=len(original_raw),
            privacyOriginalsDigest='sha256:' + hashlib.sha256(original_raw).hexdigest())
        with tempfile.TemporaryDirectory() as directory:
            attempt = Path(directory)
            members = {evidence.PRIVATE_FILE:raw, evidence.BROWSER_FILE:browser_raw,
                evidence.ORIGINALS_FILE:original_raw, 'pr320-selection.private.json':encoded(selected),
                'pr314-workload-observation.private.json':encoded(observation),
                'pr315-workload-memory.private.json':encoded(diagnostics),
                'pr315-workload-volatile.private.json':encoded(args['terminal']),
                evidence.CHECKPOINT_FILE:encoded({'phase':'native-collected','component':args['private']['component']}) + b'\n' +
                    encoded({'phase':'browser-collected','component':args['browser']}) + b'\n'}
            for name, payload in members.items():
                path=attempt/name; path.write_bytes(payload); path.chmod(0o600)
            import pr320_privacy_artifact_producer as artifact_producer
            producer_adapter=SimpleNamespace(root=attempt, private=dict(selected['private'],root=str(attempt)),
                plan=selected['plan'],authorization=selected['authorization'],
                journal=SimpleNamespace(plan=selected['plan'],append=lambda *args,**kwargs:None))
            with patch.object(artifact_producer.contract,'verify_selection_contract',return_value=True):
                artifact_producer.produce(producer_adapter)
            host_args=SimpleNamespace(product_source_commit='a'*40, prepared_image_digest='b'*64,
                                      fixture_manifest_digest='c'*64)
            report={'schemaVersion':7,'mode':'workload-positive','workloadPurpose':'budget-privacy',
                'status':'guest-report-retained','guestExitCode':0,'guestStopped':True,
                'helperSourceCommit':'d'*40,'productSourceCommit':host_args.product_source_commit,
                'preparedImageDigest':host_args.prepared_image_digest,
                'fixtureManifestDigest':host_args.fixture_manifest_digest}
            result=runner._attempt_projection(host_args, attempt, report, fixture, 'd'*40, True)
            self.assertEqual('observed',result['status'])
            for name in (evidence.BROWSER_FILE,evidence.ORIGINALS_FILE,evidence.CHECKPOINT_FILE):
                path=attempt/name; original=path.read_bytes(); path.write_bytes(b'{}')
                with self.subTest(member=name), self.assertRaises(ValueError):
                    runner._attempt_projection(host_args, attempt, report, fixture, 'd'*40, True)
                path.write_bytes(original)
            with self.assertRaises(ValueError):
                runner._attempt_projection(host_args, attempt, report, fixture, 'd'*40, False)
            import pr320_campaign_capture
            host_args.source=Path(__file__).resolve().parents[3]
            with self.assertRaisesRegex(ValueError,'root-capture-required'):
                runner._capture_originals(host_args,attempt,report)
            with tempfile.TemporaryDirectory() as root_directory:
                root_collector=Path(root_directory)
                (root_collector/'authority').mkdir(mode=0o700)
                workload=SimpleNamespace(ROOT=root_collector,secured=lambda *_args,**_kwargs:None)
                source_files={evidence.PRIVATE_FILE:attempt/evidence.PRIVATE_FILE,
                    evidence.CHECKPOINT_FILE:attempt/evidence.CHECKPOINT_FILE,
                    evidence.ORIGINALS_FILE:attempt/evidence.ORIGINALS_FILE,
                    evidence.BROWSER_FILE:attempt/evidence.BROWSER_FILE,
                    artifact_producer.FILE:attempt/artifact_producer.FILE}
                def actual_read(path,maximum,uid):
                    return artifact_producer.export._read_regular(source_files[path.name],maximum)
                with patch.object(pr320_campaign_capture.os,'geteuid',return_value=0), \
                     patch.object(pr320_campaign_capture.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=1000)), \
                     patch.object(pr320_campaign_capture,'_read_owned',side_effect=actual_read):
                    metadata=pr320_campaign_capture.prepare_root(workload,selected,diagnostics,args['terminal'])
                root_bytes=(root_collector/'authority'/metadata['file']).read_bytes()
                root_path=attempt/pr320_campaign_capture.ROOT_FILE
                root_path.write_bytes(root_bytes);root_path.chmod(0o600)
            capsule=runner._capture_originals(host_args,attempt,report)
            captured=pr320_campaign_capture.decode_capsule(capsule.read_bytes())
            self.assertEqual(['member-15.json','member-16.json','member-17.json'],[row['member'] for row in captured['entries']])
            self.assertEqual(raw,base64.b64decode(captured['entries'][0]['rawBase64'],validate=True))
            self.assertEqual(browser_raw,base64.b64decode(captured['entries'][1]['rawBase64'],validate=True))

    def test_bounded_http_reader_keeps_original_java_wire_and_rejects_unselected_route(self):
        import time
        wire = '{"fraction":1.0,"exponent":1.0E-7}'
        digest = hashlib.sha256(wire.encode()).hexdigest()
        raw = (wire[:-1] + ',"supportDigest":{"algorithm":"SHA-256","digest":"' + digest + '"}}').encode()
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit): return raw
        observed = []
        def open_request(request, timeout):
            observed.append(request)
            return Response()
        supervisor = SimpleNamespace(deadline=time.monotonic()+60, next_operation=lambda:None,
                                     remaining=lambda seconds:seconds)
        handle = SimpleNamespace(supervisor=supervisor, opener=SimpleNamespace(open=open_request),
                                 base='http://127.0.0.1:19402')
        value = driver._request(handle, 'GET', '/api/v1/operator/support-bundle', principal='host')
        self.assertEqual(raw.decode(), value['wire'])
        self.assertEqual(value['body'], privacy.verify_support_wire(value['wire']))
        self.assertEqual('http://127.0.0.1:19402/api/v1/operator/support-bundle', observed[0].full_url)
        with self.assertRaises(driver.transport.runtime.RuntimeFailure):
            driver._request(handle, 'GET', '/unselected-private-sentinel', principal='host')
        self.assertEqual(1, len(observed))

    def test_selected_package_original_script_bytes_and_missing_or_duplicate_member_reject(self):
        if os.geteuid() != 0: self.skipTest('root-owned fixed package reader requires root fixture')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / 'roles/candidate-sender/package/lib/cryptad.jar'
            archive.parent.mkdir(parents=True)
            member = 'network/crypta/platform/webshell/static/web-shell.js'
            source = Path(__file__).resolve().parents[3] / contract.TOOL_PATHS['webShellScript']
            script = source.read_bytes()
            with zipfile.ZipFile(archive, 'w') as output: output.writestr(member, script)
            archive.chmod(0o600)
            workload = SimpleNamespace(ROOT=root)
            self.assertEqual('sha256:' + hashlib.sha256(script).hexdigest(),
                             browser_admin._packaged_script_digest(workload))
            with zipfile.ZipFile(archive, 'w') as output:
                output.writestr(member, b'x' * (512 * 1024 + 1))
            with self.assertRaises(ValueError): browser_admin._packaged_script_digest(workload)
            with zipfile.ZipFile(archive, 'w') as output: output.writestr('other-resource', b'bytes')
            with self.assertRaises(ValueError): browser_admin._packaged_script_digest(workload)
            archive.unlink()
            archive.symlink_to(root / 'untrusted')
            with self.assertRaises(OSError): browser_admin._packaged_script_digest(workload)

    def test_missing_fixed_provider_cannot_emit_original_or_private_exception_paths(self):
        import shutil
        import subprocess
        node=shutil.which('node')
        if not node: self.skipTest('Node unavailable for fixed missing-provider CLI check')
        if (browser_admin.PROVIDER_ROOT/'lib/node_modules/playwright').exists():
            self.skipTest('qualified provider present; missing-provider check does not launch Chromium')
        payload={'base':'http://127.0.0.1:19402','appOrigin':'http://127.0.0.1:19403',
            'appSession':'PR320_SYNTHETIC_PRIVATE_SESSION','nativeMemberDigest':'sha256:'+'a'*64,
            'stimuli':['PR320_SYNTHETIC_PRIVATE_VALUE']}
        result=subprocess.run([node,str(browser_admin.COLLECTOR)],input=encoded(payload),capture_output=True,timeout=10,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
        self.assertNotEqual(0,result.returncode)
        self.assertEqual(b'',result.stdout)
        self.assertEqual(b'installed-privacy-browser-failed\n',result.stderr)

    def test_root_context_uses_retained_original_expiry_and_session_bindings(self):
        from pr320_privacy_admin import FixedPrivacyCollector
        supplied={'appOrigin':'http://127.0.0.1:19403','appSession':'original-session',
                  'sessionExpiresAt':'2026-10-14T01:00:00Z'}
        original={'originDigest':contract.canonical_digest(supplied['appOrigin']),
            'sessionDigest':contract.canonical_digest(supplied['appSession']),
            'sessionExpiryDigest':contract.canonical_digest(supplied['sessionExpiresAt'])}
        workload=SimpleNamespace(ROOT=Path('/fixed'),read=lambda path:{'apps':{'feed-reader':original}})
        collector=FixedPrivacyCollector(workload,'fixed-handle')
        self.assertEqual(original,collector._boundary_context({'generation':'fixed'},supplied,'feed-reader'))
        for key in supplied:
            changed=dict(supplied); changed[key]+='-changed'
            with self.subTest(field=key),self.assertRaises(ValueError):
                collector._boundary_context({'generation':'fixed'},changed,'feed-reader')

    def test_fixed_cli_rejects_arbitrary_commands_without_trace_or_paths(self):
        import subprocess
        result = subprocess.run(['/usr/bin/python3', '-I', '-B', str(Path(browser_admin.__file__)), '--namespace', 'private-sentinel'],
            capture_output=True, timeout=10)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(b'', result.stdout)
        self.assertEqual(b'installed-privacy-browser-failed\n', result.stderr)


if __name__ == '__main__': unittest.main()
