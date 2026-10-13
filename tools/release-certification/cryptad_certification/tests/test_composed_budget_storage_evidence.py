"""Synthetic contract vectors and separately identified real Java export integration."""
import copy
import datetime as dt
import json
from pathlib import Path
import unittest
import sys
from types import SimpleNamespace
from unittest.mock import patch

from cryptad_certification import composed_budget_evidence as owner
from cryptad_certification import composed_budget_storage_evidence as storage

EPOCH = '12345678-1234-1234-1234-123456789012'
NODE = 'a' * 32
GENERATION = 'b' * 64
W0 = 1778976000
W1 = W0 + 3600
FAMILY = 'trust_graph_import'


def stamp(seconds):
    return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).isoformat()


def graph():
    return [dict(documentFingerprint='a' * 64, payloadHash='b' * 64,
        signatureVerified=True, source='manual', sourceLabel=None, sourceUriHash=None,
        subscriptionId=None, importedAt=stamp(W1), updatedAt=stamp(W1),
        type='trust-statement-v1', issuerFingerprint='c' * 64,
        subject=dict(kind='profile', uri='USK@synthetic/subject'), context='profile', score=50,
        confidence=80, issuedAt=stamp(W0), expiresAt=None, signatureAlgorithm='Ed25519',
        signaturePresent=True, sourceType='manual', lastSeenAt=stamp(W1), lifecycleStatus='active',
        lifecycle=dict(statementFingerprint='a' * 64, status='active', reasonCode='active',
                       createdAt=stamp(W1), updatedAt=stamp(W1), source='local'))]


class Vector:
    """Synthetic generator; no claim that this emits actual native observations."""
    def __init__(self):
        self.events = []
        self.rates = {}
        self.holds = {}
        self.retained = 0
        self.wall = W1 + 1

    def event(self, kind, op, family=None, scope=3, value=0, window=0):
        event = dict(sequence=len(self.events) + 1, observedAt=stamp(self.wall),
            elapsedNanos=int((self.wall - (dt.datetime.fromisoformat(self.events[0]['observedAt']).timestamp()
                if self.events else self.wall)) * 1e9) + len(self.events) * 1000,
            kind=kind, operation=family,
            windowStartEpochSecond=window, value=value, operationId=op, scope=scope,
            sourceEpoch=None, sourceSequence=0, sourceSampledAtEpochMillis=0)
        self.events.append(event)
        if kind in {'CONCURRENCY_HELD', 'CONCURRENCY_RELEASED', 'RATE_RESERVED',
                    'RATE_RESERVATION_RELEASED'}:
            key = op, family, scope, 'concurrency' if kind.startswith('CONCURRENCY') else 'rate'
            self.holds[key] = self.holds.get(key, 0) + (1 if kind in
                {'CONCURRENCY_HELD', 'RATE_RESERVED'} else -1)
        if kind == 'RATE_CHARGED':
            self.rates[(family, scope, window)] = value
        return event

    def charge(self, op, family, scope, window, unknown=False):
        value = self.rates.get((family, scope, window), 0) + 1
        self.event('RATE_WRITE_ATTEMPT', op, family, scope, value, window)
        self.event('RATE_WRITE_UNKNOWN' if unknown else 'RATE_CHARGED',
                   op, family, scope, value, window)

    def hold(self, op, families, release=False):
        for family, scope in families:
            self.event('CONCURRENCY_RELEASED' if release else 'CONCURRENCY_HELD',
                       op, family, scope)
        if release:
            self.event('BUDGET_RELEASED', op, scope=0)

    def snapshot(self):
        return dict(sequence=len(self.events), budgetValid=True, droppedEvents=0,
            rates=[dict(operation=f, scope=s, windowStartEpochSecond=w, count=c)
                   for (f, s, w), c in self.rates.items()],
            holds=[dict(operationId=o, operation=f, scope=s, kind=k, count=c)
                   for (o, f, s, k), c in self.holds.items() if c],
            retainedStatements=self.retained)

    def direct(self, parent, case=None):
        child = parent + 1
        self.event('COMPOSED_DIRECT_IMPORT_START', parent)
        self.event('COMPOSED_CHILD', child, value=parent)
        self.event('BUDGET_ACQUIRE', child, FAMILY)
        self.charge(child, FAMILY, 3, W1)
        self.charge(child, FAMILY, 1, W1, case == 'partial-rate-write')
        if case == 'partial-rate-write':
            self.event('STORE_UNAVAILABLE', 0, scope=0)
            self.event('REQUEST_FAILED', parent)
            return
        families = [(FAMILY, 3), (FAMILY, 1)]
        self.hold(child, families)
        self.event('BUDGET_COMMITTED', child, FAMILY)
        self.event('PARSE_SUCCEEDED', parent)
        self.event('GRAPH_STORE_ATTEMPT', parent)
        if case != 'graph-store-unavailable':
            self.event('GRAPH_STORE_IMPORTED' if not self.retained else 'GRAPH_STORE_DUPLICATE', parent)
            self.retained = 1
        self.hold(child, families, True)
        if case == 'graph-store-unavailable':
            self.event('GRAPH_STORE_UNKNOWN', parent)
        self.event('REQUEST_FAILED' if case else 'REQUEST_SUCCEEDED', parent)


def receipt(case):
    original = dict(device=1, inode=2, uid=1000, gid=1000, mode=0o700)
    denied = {**original, 'mode': 0o500}
    common = dict(caseId=case, targetClass=case, generation=GENERATION)
    return dict(restriction=dict(**common, phase='restricted', before=original, after=denied,
        roleUidDenied=True, observedMonotonicNs=100),
        restoration=dict(**common, phase='restored', before=denied, after=original,
        contentsRestored=False, observedMonotonicNs=200))


def installed(case):
    vector = Vector()
    before = vector.snapshot()
    if case == 'window-crossing':
        vector.wall = W1 - 2
        vector.event('COMPOSED_URI_IMPORT_START', 1)
        vector.event('COMPOSED_CHILD', 2, value=1)
        for scope in (3, 1):
            vector.event('RATE_RESERVED', 2, FAMILY, scope, 1, W0)
        imports = [(FAMILY, 3), (FAMILY, 1)]
        vector.hold(2, imports)
        vector.event('BUDGET_RESERVED', 2, FAMILY)
        vector.event('COMPOSED_CHILD', 3, value=1)
        fetches = [('foreground_content_fetch', 3), ('content_fetch_global', 1)]
        for family, scope in fetches:
            vector.charge(3, family, scope, W1 - 60)
        vector.hold(3, fetches)
        vector.event('BUDGET_COMMITTED', 3, 'trust_graph_import_uri')
        vector.event('FETCH_INVOKED', 3, 'trust_graph_import_uri')
        during = vector.snapshot()
        vector.wall = W1 + 1
        vector.event('FETCH_SUCCEEDED', 3, 'trust_graph_import_uri')
        vector.hold(3, fetches, True)
        for scope in (3, 1):
            vector.event('RATE_RESERVATION_RELEASED', 2, FAMILY, scope, 0, W0)
        for family, scope in imports:
            vector.charge(2, family, scope, W1)
        vector.event('BUDGET_COMMITTED', 2, FAMILY)
        for kind in ('PARSE_SUCCEEDED', 'FINGERPRINT_ACCEPTED', 'GRAPH_STORE_ATTEMPT', 'GRAPH_STORE_IMPORTED'):
            vector.event(kind, 1)
        vector.retained = 1
        vector.hold(2, imports, True)
        vector.event('REQUEST_SUCCEEDED', 1)
        time_plan = dict(boundaryEpochSecond=W1, startMarginSeconds=10, requestDeadlineMillis=45000,
            selectedAtEpochSecond=W1 - 100, observedReservationEpochSecond=W1 - 1,
            releasedAtEpochSecond=W1)
    else:
        during = vector.snapshot()
        vector.direct(1, case)
        time_plan = None
    after = vector.snapshot()
    vector.direct(4)
    return dict(caseId=case, variant='available-capacity' if case == 'window-crossing' else
        'direct-readable-directory-denial', evidenceClass=storage.INSTALLED,
        operationId=1, collectorEpoch=EPOCH, nodeEpoch=NODE, roleGeneration=GENERATION,
        before=before, during=during, after=after, recoveryAfter=vector.snapshot(),
        events=vector.events, adminReceipt=None if time_plan else receipt(case), timePlan=time_plan,
        requestStatus=200 if time_plan else 503, recoveryStatus=200,
        graphBefore=[], graphAfter=graph() if time_plan else [], graphRecovery=graph(),
        selectedFingerprint='a' * 64)


def attachment(row):
    return dict(schemaVersion=4, workloadDigest='sha256:' + '1' * 64,
        productDigest='sha256:' + '2' * 64, sourceCommit='3' * 40,
        appCohortDigest='sha256:' + '4' * 64, collectorDigest='sha256:' + '5' * 64,
        configurationDigest='sha256:' + '6' * 64, collectorEpoch=EPOCH, nodeEpoch=NODE,
        segments=[], causalCases=[], storageCases=[row])


class StorageContractTests(unittest.TestCase):
    def derive(self, row):
        value = attachment(row)
        return owner.derive(value, workload_digest=value['workloadDigest'],
            product_digest=value['productDigest'], source_commit=value['sourceCommit'],
            app_cohort_digest=value['appCohortDigest'], node_epoch=NODE,
            collector_digest=value['collectorDigest'], configuration_digest=value['configurationDigest'])

    def test_synthetic_positive_vectors_reach_owning_dispatch_without_full_credit(self):
        for case in storage.CASES:
            with self.subTest(case=case):
                result = self.derive(installed(case))
                self.assertEqual([case], result['observedCases'])
                self.assertEqual(31, len(result['requiredCases']))
                self.assertEqual('not-observed', result['fullAppBudgets'])
                self.assertFalse(result['releaseEligible'])

    def test_actual_journal_admission_and_union_call_the_storage_owner(self):
        from cryptad_certification import cross_version_evidence as journal
        from cryptad_certification import runtime_pressure_evidence as pressure
        value = attachment(installed('partial-rate-write'))
        apps = ['sha256:' + '4' * 64]
        value['appCohortDigest'] = pressure.baseline.digest(apps)
        plan = dict(workloadInputs={'scheduler': value['workloadDigest']},
            composedBudgetInputs={key: value[key] for key in ('collectorDigest', 'configurationDigest')},
            nodes=[dict(role='candidate-sender', artifactDigest=value['productDigest'],
                        sourceCommit=value['sourceCommit'], appDigests=apps)])
        event = dict(sequence=1, previousDigest=journal.ZERO, planDigest=journal.digest(plan),
            epoch='c' * 32, wallTime=stamp(W1 + 3), monotonicNs=1, kind='operation',
            role='candidate-sender', scenario='app-budgets', operation='storage-observation',
            outcome='partial', counters={}, nodeEpoch=NODE, peerRole='', composedBudgetEvidence=value)
        journal._validate_event(event, plan)
        self.assertEqual(['partial-rate-write'], owner.derive_journal(plan, [event])['observedCases'])
        forged = copy.deepcopy(event)
        forged['composedBudgetEvidence']['storageCases'][0]['adminReceipt']['restoration']['contentsRestored'] = True
        with self.assertRaises(journal.EvidenceError):
            journal._validate_event(forged, plan)
        with self.assertRaises(owner.ComposedEvidenceError):
            owner.derive_journal(plan, [event, copy.deepcopy(event)])

    def test_actual_collector_case_builder_reaches_consumer_with_controller_generation(self):
        # Execute the real installed collector's builder, with synthetic native input only.
        # This tests producer/consumer interoperability, not installed runtime observation.
        root = Path(__file__).resolve().parents[4]
        with patch.object(sys, 'path', [str(root / 'tools/interop')] + sys.path):
            import cross_version_installed_storage_budgets as producer
        adapter = SimpleNamespace(nodes={'candidate-sender': {'generation': GENERATION}},
            journal=SimpleNamespace(node_epochs={('', 'candidate-sender'): NODE}))
        for case in storage.CASES:
            row = installed(case)
            built = producer._case(adapter, row['caseId'], row['variant'],
                {'work': {'collectorEpoch': EPOCH}}, row['before'], row['during'], row['after'],
                row['recoveryAfter'], row['graphBefore'], row['graphAfter'], row['graphRecovery'],
                row['requestStatus'], row['recoveryStatus'], {'work': {'events': row['events']}},
                selected_fingerprint=row['selectedFingerprint'], admin_receipt=row['adminReceipt'],
                time_plan=row['timePlan'])
            self.assertEqual(row, built)
            self.assertEqual([case], self.derive(built)['observedCases'])
        # Exercise the real graph collector's independent completeness count as well.
        rows = graph()
        for key in ('sourceLabel', 'sourceUriHash', 'subscriptionId'):
            rows[0].pop(key)
        def request(method, path, principal):
            return (200, {'statements': rows}) if path.endswith('/statements') else (
                200, {'trustGraph': {'statementCount': len(rows)}})
        captured = producer._graph(SimpleNamespace(request=request))
        self.assertEqual({'a' * 64}, set(storage._graph(captured, False)))

    def test_controller_generation_requires_exact_hex_string(self):
        for value in (1, True, 'b' * 63, 'B' * 64, 'g' * 64, None):
            row = installed('partial-rate-write')
            row['roleGeneration'] = value
            for receipt in row['adminReceipt'].values():
                receipt['generation'] = value
            with self.subTest(generation=value), self.assertRaises(owner.ComposedEvidenceError):
                self.derive(row)

    def test_closed_schema_rejects_claimed_rollback_and_historical_relabeling(self):
        row = installed('partial-rate-write')
        row['rollback'] = True
        with self.assertRaises(owner.ComposedEvidenceError):
            self.derive(row)
        for version in (1, 2, 3):
            value = attachment(installed('partial-rate-write'))
            value['schemaVersion'] = version
            with self.assertRaises(owner.ComposedEvidenceError):
                owner.derive(value, workload_digest=value['workloadDigest'],
                    product_digest=value['productDigest'], source_commit=value['sourceCommit'],
                    app_cohort_digest=value['appCohortDigest'])

    def test_substituted_receipts_and_cleanup_fail(self):
        mutations = [lambda r: r['adminReceipt']['restriction'].update(roleUidDenied=False),
                     lambda r: r['adminReceipt']['restoration'].update(contentsRestored=True),
                     lambda r: r['adminReceipt']['restoration']['after'].update(inode=99),
                     lambda r: r.update(roleGeneration='c' * 64),
                     lambda r: r.update(recoveryStatus=503),
                     lambda r: r['recoveryAfter'].update(retainedStatements=3)]
        for change in mutations:
            row = installed('partial-rate-write')
            change(row)
            with self.subTest(change=change), self.assertRaises(owner.ComposedEvidenceError):
                self.derive(row)

    def test_unknown_readback_stays_unobserved_and_null_is_not_zero(self):
        row = installed('partial-rate-write')
        row['after'].update(budgetValid=False, rates=None)
        self.assertEqual([], self.derive(row)['observedCases'])
        row['after']['rates'] = []
        with self.assertRaises(owner.ComposedEvidenceError):
            self.derive(row)

    def test_ring_loss_cannot_verify_a_case(self):
        row = installed('graph-store-unavailable')
        row['during']['droppedEvents'] = 1
        self.assertEqual([], self.derive(row)['observedCases'])

    def test_unknown_unrelated_events_and_borrowed_operations_fail(self):
        for change in (lambda r: r['events'][0].update(kind='ARBITRARY_SUCCESS'),
                       lambda r: r['events'][1].update(value=999),
                       lambda r: r.update(nodeEpoch='f' * 32),
                       lambda r: r['events'][4].update(scope=17)):
            row = installed('partial-rate-write')
            change(row)
            with self.assertRaises(owner.ComposedEvidenceError):
                self.derive(row)
        row = installed('partial-rate-write')
        with self.assertRaises(owner.ComposedEvidenceError):
            storage.derive_cases(attachment(row), {(EPOCH, 999): dict(operationId=1)}, None)

    def test_unexplained_prefix_unknown_substitution_and_hidden_graph_mutation_fail(self):
        for change in (lambda r: r['after']['rates'][0].update(count=2),
                       lambda r: r['after'].update(rates=[]),
                       lambda r: next(e for e in r['events'] if e['kind'] == 'RATE_WRITE_UNKNOWN').update(kind='STORE_UNAVAILABLE'),
                       lambda r: r.update(graphAfter=graph())):
            row = installed('partial-rate-write')
            change(row)
            with self.assertRaises(owner.ComposedEvidenceError):
                self.derive(row)

    def test_wrong_hour_and_unrelated_boundary_do_not_pass(self):
        for change in (lambda r: r['timePlan'].update(boundaryEpochSecond=W1 + 60),
                       lambda r: r['timePlan'].update(releasedAtEpochSecond=W1 - 1),
                       lambda r: next(e for e in r['events'] if e['kind'] == 'RATE_RESERVED').update(windowStartEpochSecond=W1),
                       lambda r: r['timePlan'].update(requestDeadlineMillis=3600000)):
            row = installed('window-crossing')
            change(row)
            with self.assertRaises(owner.ComposedEvidenceError):
                self.derive(row)

    def test_free_recovery_and_wrong_selected_statement_fail(self):
        row = installed('partial-rate-write')
        split = row['after']['sequence']
        row['events'] = [e for e in row['events'] if not (e['sequence'] > split and
                         e['kind'] in {'RATE_WRITE_ATTEMPT', 'RATE_CHARGED'})]
        for index, event in enumerate(row['events']):
            event['sequence'] = index + 1
        row['recoveryAfter']['sequence'] = len(row['events'])
        row['recoveryAfter']['rates'] = copy.deepcopy(row['after']['rates'])
        with self.assertRaises(owner.ComposedEvidenceError):
            self.derive(row)
        row = installed('graph-store-unavailable')
        row['selectedFingerprint'] = 'f' * 64
        with self.assertRaises(owner.ComposedEvidenceError):
            self.derive(row)

    def test_reservation_release_cannot_borrow_another_window(self):
        row = installed('window-crossing')
        event = next(e for e in row['events'] if e['kind'] == 'RATE_RESERVATION_RELEASED')
        event['windowStartEpochSecond'] = W1
        with self.assertRaises(owner.ComposedEvidenceError):
            self.derive(row)

    def test_graph_summary_rejects_unknown_keys_and_unbounded_private_values(self):
        for change in (lambda r: r['graphRecovery'][0].update(arbitraryFault=True),
                       lambda r: r['graphRecovery'][0].update(sourceLabel='X' * 4097),
                       lambda r: r['graphRecovery'][0]['subject'].update(secret='value')):
            row = installed('graph-store-unavailable')
            change(row)
            with self.assertRaises(owner.ComposedEvidenceError):
                self.derive(row)

    def test_wall_boundary_with_conflicting_monotonic_clock_fails(self):
        row = installed('window-crossing')
        for index, event in enumerate(row['events']):
            event['elapsedNanos'] = index
        with self.assertRaises(owner.ComposedEvidenceError):
            self.derive(row)

    def test_precise_variant_report_preserves_missing_contested_direction(self):
        result = storage.derive_variants(attachment(installed('window-crossing')))
        self.assertEqual('available-capacity', result['verifiedVariants'][0]['variant'])
        self.assertIn(dict(caseId='window-crossing', variant='contested-capacity'),
                      result['unobservedVariants'])

    def test_acknowledgments_need_exact_attempt_identity(self):
        events = installed('partial-rate-write')['events']
        storage.validate_writes(events)
        changed = [e for e in events if e['kind'] != 'RATE_WRITE_ATTEMPT']
        with self.assertRaises(owner.ComposedEvidenceError):
            storage.validate_writes(changed)


class JavaNativeExportIntegrationTests(unittest.TestCase):
    def test_actual_file_backed_handler_exports_without_rewriting_recorder_time(self):
        root = Path(__file__).resolve().parents[4]
        directory = root / 'platform-api/build/test-results/pr318-native'
        paths = sorted(directory.glob('*.json'))
        if not paths:
            self.skipTest('Run :platform-api:test --tests network.crypta.platform.api.TrustGraphStorageBudgetTest first')
        self.assertEqual(26, len(paths))
        results = []
        for path in paths:
            with self.subTest(variant=path.stem):
                raw = json.loads(path.read_text())
                original = copy.deepcopy(raw)
                result = storage.derive_controlled(raw)
                self.assertEqual(original, raw)
                self.assertEqual(storage.CONTROLLED, result['evidenceClass'])
                self.assertFalse(result['installedObservation'])
                self.assertFalse(result['releaseEligible'])
                results.append(result)
        self.assertEqual(3, sum(r['status'] == 'control-verified' for r in results))
        self.assertEqual(set(storage.CASES), {r['caseId'] for r in results if r['observed']})

    def test_actual_export_cutpoint_and_prefix_substitutions_are_rejected(self):
        root = Path(__file__).resolve().parents[4]
        path = root / 'platform-api/build/test-results/pr318-native/rate-false-2-true.json'
        if not path.exists():
            self.skipTest('Native Java export unavailable')
        raw = json.loads(path.read_text())
        raw['cutPoint'] = 'before-delegate'
        with self.assertRaises(owner.ComposedEvidenceError):
            storage.derive_controlled(raw)
