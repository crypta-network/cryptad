#!/usr/bin/env python3
"""Finite packaged app-budget workload on owned synthetic content and installed app sessions.

Reuses the scheduler supervisor's package admission, safe HTTP, FCP and owned process lifecycle.
All inputs and source observations stay in the private run root. No protected authority is made.
"""
from __future__ import annotations
import datetime as dt
import json
import os
import signal
import select
import subprocess
from pathlib import Path
import time

import scheduler_pressure_runtime as scheduler
from cryptad_certification import composed_budget_evidence as composed

runtime = scheduler.runtime
APP_IDS = ('feed-reader', 'budget-importer', 'budget-no-trust', 'budget-no-fetch')
ENVIRONMENT = {**scheduler.ENVIRONMENT,
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_ENABLED': 'false'}
ROUTES = {'direct-valid': 'import', 'direct-malformed': 'import',
    'pasted-preview-valid': 'import-preview', 'uri-preview-valid': 'import-preview-uri',
    'uri-preview-malformed': 'import-preview-uri', 'uri-valid': 'import-uri',
    'uri-malformed': 'import-uri', 'uri-fingerprint-mismatch': 'import-uri',
    'uri-duplicate': 'import-uri', 'invalid-uri': 'import-uri',
    'invalid-utf8': 'import-uri', 'oversized': 'import-uri'}


class AppBudgetLane(scheduler.SchedulerLane):
    """An explicitly local synthetic cohort, with original daemon observations kept private."""
    app_budget_lane = True

    def __init__(self, *args, interference=False, **kwargs):
        self.interference = interference
        super().__init__(*args, **kwargs)
        self.segments = []
        self.attached_epochs = set()
        self.case_results = []
        self.documents = {}
        self.stopped_worker_epochs = set()
        self.restored_fixture_content = False
        self.private['nodes']['candidate-sender']['apps'] = [
            {'appId': app, 'bundleDigest': runtime.digest_file(self.fixture / (app + '.zip'))}
            for app in APP_IDS]
        for app in APP_IDS[1:]:
            staged = self.root / ('staged-' + app)
            runtime.extract_app_bundle(self.fixture / (app + '.zip'), staged,
                                       runtime.digest_file(self.fixture / (app + '.zip')))
            self.app_staging[('candidate-sender', app)] = staged
            self.app_staging_identities['candidate-sender/' + app] = runtime.tree_digest(staged, require_java=False)
        self.fingerprint['appCohortDigest'] = runtime.canonical_digest([
            row['bundleDigest'] for row in self.private['nodes']['candidate-sender']['apps']])
        self.fingerprint['workloadDigest'] = runtime.digest_file(Path(__file__))
        self.fingerprint['collectorDigest'] = runtime.canonical_digest({
            'workload': runtime.digest_file(Path(__file__)),
            'supervisor': runtime.digest_file(scheduler.HERE / 'cross_version_runtime.py'),
            'verifier': runtime.digest_file(Path(composed.__file__))})
        self.composed_budget_inputs = {
            'collectorDigest': self.fingerprint['collectorDigest'],
            'configurationDigest': runtime.canonical_digest({
                'nodeConfigDigest': self.prepared['candidate-sender'][4],
                'environment': self.scheduler_process_environment('candidate-sender')})}

    def scheduler_process_environment(self, role):
        values = dict(ENVIRONMENT)
        if self.interference:
            values.update({
                'CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_PER_APP_PER_MINUTE': '3',
                'CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_GLOBAL_PER_MINUTE': '5',
                'CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_PER_APP_PER_HOUR': '4',
                'CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_GLOBAL_PER_HOUR': '6'})
        return values

    def start_app(self, install):
        super().start_app(install)
        for app in APP_IDS[1:]:
            handle = runtime.AppHandle(self, 'candidate-sender', app)
            handle.host_bootstrap()
            if install:
                status, value = handle.request('POST', '/api/v1/apps/install',
                    {'stagedDir': str(self.app_staging[('candidate-sender', app)])})
                self.require(status == 201 and value.get('app', {}).get('appId') == app,
                             'budget-signed-app-install-failed')
            status, _ = handle.request('POST', '/api/v1/apps/' + app + '/start')
            self.require(status in (200, 201), 'budget-signed-app-start-failed')
            handle.observe_worker()
            handle.refresh_session()
            self.apps[('candidate-sender', app)] = handle

    @staticmethod
    def require(condition, code):
        if not condition:
            raise runtime.RuntimeFailure(code)

    def graph(self):
        status, value = self.handle.request('GET', '/api/v1/trust-graph/statements', principal='app')
        self.require(status == 200 and isinstance(value.get('statements'), list), 'budget-graph-unavailable')
        return value['statements']

    def create_corpus(self):
        valid = (self.fixture / 'statement.json').read_bytes()
        invalid_signature = json.loads(valid)
        signature = invalid_signature['signature']['value']
        invalid_signature['signature']['value'] = ('A' if signature[0] != 'A' else 'B') + signature[1:]
        payloads = {'valid': valid, 'malformed': b'{"type":"synthetic-invalid"}',
                    'invalid-utf8': b'\xc3\x28', 'oversized': b'x' * 2048,
                    'unverified': json.dumps(invalid_signature).encode()}
        if self.interference:
            payloads = {'valid': valid}
        with self.client('candidate-sender') as client:
            for name, payload in payloads.items():
                insert, request = runtime.interop.generate_ssk(client, self.next_operation())
                uri = runtime.interop.usk_from_ssk(request, 'budget-synthetic', 0)
                insert_uri = runtime.interop.usk_from_ssk(insert, 'budget-synthetic', 0)
                runtime.interop.put_and_wait_for_success(client, self.next_operation(), insert_uri,
                    payload, 'application/json', local_request_only=True, uri_fallback=uri)
                self.documents[name] = {'uri': uri, 'bytes': payload, 'insertUri': insert_uri}
        self.useful_uri = self.documents['valid']['uri']

    def case(self, case, parameters, *, status=200, app='feed-reader', headers=None, path=None):
        handle = self.apps[('candidate-sender', app)]
        before_graph = self.graph()
        before = self.observe()
        try:
            code, response = handle.request('POST', path or '/api/v1/trust-graph/' + ROUTES[case],
                                            parameters, principal='app', headers_override=headers)
        except runtime.RuntimeFailure:
            self.reconcile_ambiguous_request(case, before)
            raise
        after = self.observe()
        after_graph = self.graph()
        self.require(code == status, 'budget-case-response-mismatch-' + case)
        self.require(after['budget']['valid'] and before['budget']['valid'], 'budget-diagnostics-unavailable')
        self.require(after['budget']['activeFamilyLeases'] == 0 and after['budget']['reservedFamilyRates'] == 0,
                     'budget-transient-hold-remains')
        work = after['work']
        events = [row for row in work['events'] if row['sequence'] > before['work']['lastSequence']]
        starts = [row for row in events if row['kind'].startswith('COMPOSED_') and row['kind'].endswith('_START')]
        if len(starts) == 1:
            self.segments.append({'caseId': case, 'collectorEpoch': work['collectorEpoch'],
                'operationId': starts[0]['operationId'], 'scope': starts[0]['scope'],
                'budgetValid': True, 'droppedEvents': work['dropped'], 'events': events,
                'beforeRates': before['budget']['rates'], 'afterRates': after['budget']['rates'],
                'graphBefore': {'retainedStatements': len(before_graph)},
                'graphAfter': {'retainedStatements': len(after_graph)}})
        self.case_results.append({'caseId': case, 'status': code})
        scheduler.private_json(self.root / 'native-cases.json', {'segments': self.segments, 'results': self.case_results})
        return response, events

    def reconcile_ambiguous_request(self, case, before):
        """Retain bounded native state after lost HTTP delivery; the request still fails its lane."""
        deadline = min(self.deadline, time.monotonic() + 35)
        result = {'caseId': case, 'observed': False, 'terminalObserved': False}
        while time.monotonic() < deadline:
            try:
                after = self.observe()
                events = [row for row in after['work']['events']
                          if row['sequence'] > before['work']['lastSequence']]
                terminal = any(row['kind'] in ('REQUEST_SUCCEEDED', 'REQUEST_FAILED') for row in events)
                result = {'caseId': case, 'observed': True, 'terminalObserved': terminal,
                          'work': after['work'], 'budget': after['budget'],
                          'retainedStatements': len(self.graph())}
                if terminal and after['budget']['activeFamilyLeases'] == 0:
                    break
            except runtime.RuntimeFailure:
                break
            time.sleep(0.1)
        scheduler.private_json(self.root / 'ambiguous-request-reconciliation.json', result)

    def restore_valid_content_fixture(self):
        """Reinsert identical owned bytes/key; no content-datastore durability is claimed."""
        valid = self.documents['valid']
        with self.client('candidate-sender') as client:
            runtime.interop.put_and_wait_for_success(client, self.next_operation(), valid['insertUri'],
                valid['bytes'], 'application/json', local_request_only=True, uri_fallback=valid['uri'])
        self.restored_fixture_content = True

    def shared_segment(self, case, before, after, before_graph_count):
        events = [row for row in after['work']['events'] if row['sequence'] > before['work']['lastSequence']]
        kind = 'BUDGET_ACQUIRE' if case == 'shared-foreground' else 'BUDGET_RESERVE'
        first = next(row for row in events if row['kind'] == kind)
        count = len(self.graph())
        self.segments.append({'caseId': case, 'collectorEpoch': after['work']['collectorEpoch'],
            'operationId': first['operationId'], 'scope': first['scope'],
            'budgetValid': before['budget']['valid'] and after['budget']['valid'],
            'droppedEvents': after['work']['dropped'], 'events': events,
            'beforeRates': before['budget']['rates'], 'afterRates': after['budget']['rates'],
            'graphBefore': {'retainedStatements': before_graph_count}, 'graphAfter': {'retainedStatements': count}})

    def flush_attachment(self):
        """Bind one native collector epoch to the original journal's current owned process epoch."""
        current = self.observe()['work']['collectorEpoch']
        segments = [row for row in self.segments if row['collectorEpoch'] == current]
        if not segments:
            return
        self.require(current not in self.attached_epochs, 'budget-collector-epoch-already-attached')
        node = self.nodes['candidate-sender']
        self.require(runtime.process_identity(node.runtime.process.pid) == node.identity,
                     'budget-attachment-process-changed')
        attachment = {'schemaVersion': 2, 'collectorEpoch': current,
            'nodeEpoch': self.journal.node_epochs[('', 'candidate-sender')],
            **{key: self.fingerprint[key] for key in
                ('workloadDigest', 'productDigest', 'sourceCommit', 'appCohortDigest')},
            **self.composed_budget_inputs,
            'segments': segments}
        self.journal.append('operation', role='candidate-sender', scenario='app-budgets',
            outcome='partial', operation='composed-budget-attachment', composed_budget_evidence=attachment)
        self.attached_epochs.add(current)
        scheduler.private_json(self.root / ('composed-budget-evidence-' + str(len(self.attached_epochs)) + '.json'), attachment)

    def execute_interference(self):
        """Exercise shared family ownership with fixed short-test rates on a fresh owned node."""
        self.prepare_journal()
        try:
            self.start('candidate-sender')
            self.start_app(True)
            self.create_corpus()
            uri = self.documents['valid']['uri']
            document = self.documents['valid']['bytes'].decode()
            # Reserve a declared 15-second same-window case interval before offering work.
            while time.time() % 60 > 45:
                self.remaining(1)
                time.sleep(0.25)
            self.case('direct-malformed', {'document': '{}'}, status=400)
            self.case('uri-valid', {'uri': uri})
            def foreground(app, expected):
                handle = self.apps[('candidate-sender', app)]
                before = self.observe()
                code, _ = handle.request('POST', '/api/v1/content/fetch',
                    {'uri': uri, 'maxBytes': '8192', 'timeoutMillis': '3000'}, principal='app')
                after = self.observe()
                self.require(code == expected, 'budget-interference-fetch-response')
                rows = [row for row in after['work']['events'] if row['sequence'] > before['work']['lastSequence']]
                self.require(sum(row['kind'] == 'FETCH_INVOKED' for row in rows) == (1 if expected == 200 else 0),
                             'budget-interference-fetch-invocation')
                return before, after
            shared_graph_before = len(self.graph())
            shared_before = self.observe()
            foreground('feed-reader', 200)
            foreground('feed-reader', 200)
            _, events = self.case('app-fetch-rate', {'uri': uri}, status=429,
                                  path='/api/v1/trust-graph/import-uri')
            self.require(not any(row['kind'] in ('FETCH_INVOKED', 'RATE_CHARGED') for row in events),
                         'budget-app-denial-debited-work')
            self.shared_segment('shared-foreground', shared_before, self.observe(), shared_graph_before)
            foreground('budget-importer', 200)
            second = self.apps[('candidate-sender', 'budget-importer')]
            code, subscription = second.request('POST', '/api/v1/content/subscriptions',
                {'uri': uri, 'label': 'Synthetic budget subscription', 'pollIntervalSeconds': '2',
                 'maxBytes': '8192', 'timeoutMillis': '3000'}, principal='app')
            self.require(code == 201, 'budget-interference-subscription-create')
            sid = subscription['subscription']['subscriptionId']
            before = self.observe()
            subscription_graph_before = len(self.graph())
            subscription_before = before
            code, _ = second.request('POST', '/api/v1/content/subscriptions/' + sid + '/refresh', principal='app')
            after = self.observe()
            rows = [row for row in after['work']['events'] if row['sequence'] > before['work']['lastSequence']]
            charges = [row['operation'] for row in rows if row['kind'] == 'RATE_CHARGED']
            self.require(code == 200 and sorted(charges) == ['content_fetch_global', 'subscription_poll', 'subscription_poll'],
                         'budget-subscription-shared-family-mismatch')
            self.case_results.append({'caseId': 'shared-subscription', 'status': code})
            foreground('budget-importer', 429)
            _, events = self.case('global-fetch-rate', {'uri': uri}, status=429, app='budget-importer',
                                  path='/api/v1/trust-graph/import-uri')
            self.require(not any(row['kind'] in ('FETCH_INVOKED', 'RATE_CHARGED') for row in events),
                         'budget-global-denial-debited-work')
            self.shared_segment('shared-subscription', subscription_before, self.observe(), subscription_graph_before)
            self.case('direct-valid', {'document': document})
            self.case('direct-valid', {'document': document})
            self.case('app-import-rate', {'uri': uri}, status=429, path='/api/v1/trust-graph/import-uri')
            self.case('direct-valid', {'document': document}, app='budget-importer')
            self.case('direct-valid', {'document': document}, app='budget-importer')
            _, events = self.case('global-import-rate', {'uri': uri}, status=429, app='budget-importer',
                                  path='/api/v1/trust-graph/import-uri')
            self.require(not any(row['kind'] in ('FETCH_INVOKED', 'RATE_CHARGED') for row in events),
                         'budget-global-import-denial-debited-work')
            observed = self.observe()
            window = max(row['windowStartEpochSecond'] for row in observed['budget']['rates']
                         if row['operation'] == 'content_fetch_global')
            # Wait for the real existing fixed minute. Never alter clocks or persistent counters.
            deadline = time.monotonic() + 65
            while time.time() < window + 61:
                self.require(time.monotonic() < deadline, 'budget-window-recovery-timeout')
                self.remaining(1)
                time.sleep(0.25)
            before, after = foreground('feed-reader', 200)
            self.require(any(row['operation'] == 'content_fetch_global'
                and row['windowStartEpochSecond'] > window and row['count'] == 1 for row in after['budget']['rates']),
                'budget-new-window-recovery-unobserved')
            self.case_results.append({'caseId': 'shared-foreground', 'status': 200})
            result = {'schemaVersion': 1, 'evidenceClass': 'packaged-local-synthetic',
                'observedChecks': sorted({row['caseId'] for row in self.case_results}),
                'releaseEligible': False, 'fullAppBudgets': 'not-observed'}
            self.flush_attachment()
            result['composedCoverage'] = composed.derive_journal(self.plan, self.journal.events)
            scheduler.private_json(self.root / 'interference-result.json', result)
            return result
        finally:
            self.stop_owned()
            self.journal.append('cleanup')
            self.journal.append('finish', outcome='partial')
            self.journal.checkpoint('complete')
            self.journal.__exit__(None, None, None)

    @staticmethod
    def owned_pidfd(identity, label):
        """Pin an already authenticated actor; do not signal a reused numeric PID."""
        try:
            descriptor = os.pidfd_open(identity['pid'])
        except ProcessLookupError:
            return None
        try:
            exited = select.poll()
            exited.register(descriptor, select.POLLIN)
            if not exited.poll(0):
                try:
                    actual = runtime.process_identity(identity['pid'])
                except OSError:
                    AppBudgetLane.require(bool(exited.poll(0)), f'budget-owned-{label}-identity-unavailable')
                else:
                    AppBudgetLane.require(actual == identity, f'budget-owned-{label}-identity-changed')
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def stop_mode(self, abrupt):
        """Stop exact wrapper, native JVM and synthetic workers, despite separate process groups."""
        node = self.nodes['candidate-sender']
        descriptors = []
        try:
            native = getattr(self, 'identity', None)
            if native is not None:
                descriptor = self.owned_pidfd(native, 'jvm')
                if descriptor is not None:
                    descriptors.append((descriptor, 'jvm', native))
            for (role, _), handle in self.apps.items():
                if role != 'candidate-sender' or handle.worker_identity is None:
                    continue
                descriptor = self.owned_pidfd(handle.worker_identity, 'worker')
                if descriptor is not None:
                    descriptors.append((descriptor, 'worker', handle.worker_identity))
                else:
                    # The authenticated process may already have exited before shutdown.
                    # ESRCH proves absence; there is no live owner left to acknowledge.
                    self.stopped_worker_epochs.add(tuple(handle.worker_identity[key]
                                                        for key in ('pid', 'startTicks', 'bootId')))
            if node.runtime.process.poll() is None:
                current = runtime.process_identity(node.runtime.process.pid)
                self.require(all(current[key] == node.identity[key]
                                 for key in ('pid', 'startTicks', 'bootId')),
                             'budget-owned-process-identity-changed')
                # Stop supervision before its JVM, preventing an unintended automatic restart.
                os.killpg(node.runtime.process.pid, signal.SIGKILL if abrupt else signal.SIGTERM)
            if abrupt:
                for descriptor, _, _ in descriptors:
                    try:
                        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            node.runtime.process.wait(timeout=30)
            deadline = time.monotonic() + 30
            for descriptor, label, identity in descriptors:
                exited = select.poll()
                exited.register(descriptor, select.POLLIN)
                self.require(bool(exited.poll(max(0, int((deadline - time.monotonic()) * 1000)))),
                             f'budget-{label}-stop-unacknowledged')
                if label == 'worker':
                    self.stopped_worker_epochs.add(tuple(identity[key] for key in ('pid', 'startTicks', 'bootId')))
            node.runtime.stdout_handle.close()
            node.runtime.stderr_handle.close()
            self.journal.append('node-stop', role='candidate-sender')
        finally:
            for descriptor, _, _ in descriptors:
                os.close(descriptor)

    def stop_owned(self):
        """Cleanup retains exact JVM ownership even when startup or graceful shutdown fails."""
        for child, _ in self.driver_processes:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
        self.driver_processes = []
        self.driver_process = None
        node = self.nodes.get('candidate-sender')
        if node is None:
            return
        if node.runtime.process.poll() is None:
            try:
                self.stop_mode(False)
                return
            except (OSError, subprocess.TimeoutExpired, runtime.RuntimeFailure):
                # Cleanup fallback is never evidence of a successful graceful-stop case.
                self.stop_mode(True)
        elif getattr(self, 'identity', None) is not None:
            # A failed wrapper can leave its already authenticated JVM alive briefly.
            self.stop_mode(True)

    def privacy_checks(self):
        """Check ordinary redacted surfaces before constructing a public field-by-field result."""
        canaries = (b'PR309_PRIVATE_ISSUER_CANARY', b'PR309_PRIVATE_BODY_CANARY')
        surfaces = (('app-audit', '/api/v1/apps/feed-reader/audit', None),
                    ('queue-downloads', '/api/v1/queue', {'page': 'downloads'}),
                    ('queue-uploads', '/api/v1/queue', {'page': 'uploads'}),
                    ('support-bundle', '/api/v1/operator/support-bundle', None))
        for label, path, parameters in surfaces:
            code, body = self.handle.request('GET', path, parameters, raw=True)
            self.require(code == 200, f'budget-privacy-{label}-status-{code}')
            self.require(not any(canary in body for canary in canaries), 'budget-private-canary-leak')
        node_root = self.prepared['candidate-sender'][1]
        for name in ('stdout.log', 'stderr.log'):
            path = node_root / 'logs' / name
            self.require(path.stat().st_size <= 16 * 1024**2, 'budget-private-log-bound')
            self.require(not any(canary in path.read_bytes() for canary in canaries), 'budget-private-log-canary')

    def durable_inventory(self):
        """Private exact persisted bytes keyed by owned relative paths, independent of epochs."""
        root = self.prepared['candidate-sender'][1] / 'data/node/apps'
        values = {}
        for family in ('network-budget', 'trust-graph/statements', 'trust-graph/anchors'):
            base = root / family
            if not base.exists():
                continue
            for path in sorted(base.rglob('*')):
                self.require(not path.is_symlink(), 'budget-durable-link-invalid')
                if path.is_file():
                    self.require(path.stat().st_size <= 1024 * 1024, 'budget-durable-file-budget')
                    values[path.relative_to(root).as_posix()] = runtime.digest_file(path)
                    self.require(len(values) <= 4096, 'budget-durable-inventory-budget')
        return values

    def execute(self):
        self.prepare_journal()
        try:
            self.start('candidate-sender')
            self.start_app(True)
            self.create_corpus()
            valid = self.documents['valid']
            # All oracle expectations below are fixed by route semantics, not returned pass flags.
            self.case('direct-malformed', {'document': '{}'}, status=400)
            self.case('pasted-preview-valid', {'document': valid['bytes'].decode()})
            self.case('uri-preview-valid', {'uri': valid['uri']})
            self.case('uri-preview-malformed', {'uri': self.documents['malformed']['uri']}, status=400)
            self.case('uri-malformed', {'uri': self.documents['malformed']['uri']}, status=400)
            self.case('uri-fingerprint-mismatch', {'uri': valid['uri'], 'expectedDocumentFingerprint': '0' * 64}, status=409)
            self.case('invalid-uri', {'uri': 'crypta:SSK@'}, status=400)
            self.case('invalid-utf8', {'uri': self.documents['invalid-utf8']['uri']}, status=415)
            self.case('oversized', {'uri': self.documents['oversized']['uri'], 'maxBytes': '1024'}, status=502)
            result, _ = self.case('uri-valid', {'uri': valid['uri']})
            self.require(result.get('importResult', {}).get('imported') is True and result.get('importResult', {}).get('signatureVerified') is True,
                         'budget-native-import-not-verified')
            result, _ = self.case('uri-duplicate', {'uri': valid['uri']})
            self.require(result.get('importResult', {}).get('imported') is False, 'budget-native-deduplication-missing')
            self.case('direct-valid', {'document': valid['bytes'].decode()})
            expected_scope = self.segments[-1]['scope']
            _, events = self.case('uri-duplicate', {'uri': valid['uri'], 'appId': 'budget-importer'})
            self.require(events[0]['scope'] == expected_scope, 'budget-caller-scope-rebound')
            for app in ('budget-no-trust', 'budget-no-fetch'):
                _, events = self.case('authorization-denied', {'uri': valid['uri']}, status=403,
                                     app=app, path='/api/v1/trust-graph/import-uri')
                self.require([row['kind'] for row in events] == ['COMPOSED_URI_IMPORT_START', 'CAPABILITY_DENIED', 'REQUEST_FAILED'], 'budget-unauthorized-work-observed')
            _, events = self.case('authorization-denied', {'uri': valid['uri']}, status=403,
                headers={'Origin': self.apps[('candidate-sender', 'budget-importer')].origin},
                path='/api/v1/trust-graph/import-uri')
            self.require(not events, 'budget-cross-origin-work-observed')
            _, events = self.case('authorization-denied', {'uri': valid['uri']}, status=401,
                headers={'X-Crypta-App-Session': 'synthetic-invalid-session'},
                path='/api/v1/trust-graph/import-uri')
            self.require(not events, 'budget-invalid-session-work-observed')
            before = self.observe()
            graph_before = self.graph()
            durable_before = self.durable_inventory()
            self.flush_attachment()
            self.stop_mode(False)
            self.start('candidate-sender')
            self.start_app(False)
            after = self.observe()
            self.require(before['work']['collectorEpoch'] != after['work']['collectorEpoch'], 'budget-epoch-reused')
            self.require(durable_before == self.durable_inventory(), 'budget-restart-durable-state-changed')
            self.require(graph_before == self.graph(), 'budget-restart-graph-state-changed')
            self.privacy_checks()
            graceful_epoch = after['work']['collectorEpoch']
            durable_before = self.durable_inventory()
            self.stop_mode(True)
            self.start('candidate-sender')
            self.start_app(False)
            after_abrupt = self.observe()
            self.require(graceful_epoch != after_abrupt['work']['collectorEpoch'], 'budget-abrupt-epoch-reused')
            self.require(durable_before == self.durable_inventory(), 'budget-abrupt-durable-state-changed')
            self.require(graph_before == self.graph(), 'budget-abrupt-graph-state-changed')
            self.restore_valid_content_fixture()
            result, _ = self.case('uri-duplicate', {'uri': valid['uri']})
            self.require(result.get('importResult', {}).get('imported') is False, 'budget-retry-deduplication-missing')
            self.flush_attachment()
            result = composed.derive_journal(self.plan, self.journal.events)
            scheduler.private_json(self.root / 'composed-budget-result.json', result)
            public = json.dumps(result)
            for secret in ('PR309_PRIVATE_', str(self.root), self.handle.session,
                           *(row['uri'] for row in self.documents.values()),
                           *(row['insertUri'] for row in self.documents.values())):
                self.require(secret not in public, 'budget-public-private-data')
            return result
        finally:
            self.stop_owned()
            self.journal.append('cleanup')
            self.journal.append('finish', outcome='partial')
            self.journal.checkpoint('complete')
            self.journal.__exit__(None, None, None)
