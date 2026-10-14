"""Prospective seven-direction storage admission; vectors remain explicitly synthetic."""
import copy
import json
from pathlib import Path
import unittest

from cryptad_certification import composed_budget_evidence as owner
from cryptad_certification import composed_budget_storage_evidence as storage
from cryptad_certification.tests.test_composed_budget_storage_evidence import (
    Vector, installed, graph, receipt, FAMILY, W0, W1, EPOCH, NODE, GENERATION)


class UriVector(Vector):
    def uri(self, variant):
        imports = [(FAMILY, 3), (FAMILY, 1)]
        fetches = [('foreground_content_fetch', 3), ('content_fetch_global', 1)]
        self.event('COMPOSED_URI_IMPORT_START', 1)
        self.event('COMPOSED_CHILD', 2, value=1)
        for family, scope in imports:
            self.event('RATE_RESERVED', 2, family, scope, 1, W1)
        self.hold(2, imports)
        self.event('BUDGET_RESERVED', 2, FAMILY)
        self.event('COMPOSED_CHILD', 3, value=1)
        self.event('BUDGET_ACQUIRE', 3, 'trust_graph_import_uri')
        for family, scope in fetches:
            self.charge(3, family, scope, W1,
                        variant == 'uri-child-write-denial' and scope == 1)
        if variant != 'uri-child-write-denial':
            self.hold(3, fetches)
            self.event('BUDGET_COMMITTED', 3, 'trust_graph_import_uri')
            self.event('FETCH_INVOKED', 3, 'trust_graph_import_uri')
            self.event('FETCH_SUCCEEDED', 3, 'trust_graph_import_uri')
            self.hold(3, fetches, True)
        for family, scope in imports:
            self.event('RATE_RESERVATION_RELEASED', 2, family, scope, 0, W1)
        if variant != 'uri-child-write-denial':
            for family, scope in imports:
                self.charge(2, family, scope, W1,
                            variant == 'uri-import-commit-denial' and scope == 1)
        if variant == 'uri-readable-directory-denial':
            self.event('BUDGET_COMMITTED', 2, FAMILY)
            for kind in ('PARSE_SUCCEEDED', 'FINGERPRINT_ACCEPTED', 'GRAPH_STORE_ATTEMPT'):
                self.event(kind, 1)
        self.hold(2, imports, True)
        if variant == 'uri-readable-directory-denial':
            self.event('GRAPH_STORE_UNKNOWN', 1)
        self.event('REQUEST_FAILED', 1)


def uri_row(variant):
    v = UriVector()
    before = v.snapshot()
    v.uri(variant)
    after = v.snapshot()
    v.direct(4)
    case = 'graph-store-unavailable' if variant == 'uri-readable-directory-denial' else 'partial-rate-write'
    return dict(caseId=case, variant=variant, evidenceClass=storage.INSTALLED,
        operationId=1, collectorEpoch=EPOCH, nodeEpoch=NODE, roleGeneration=GENERATION,
        before=before, during=before, after=after, recoveryAfter=v.snapshot(),
        events=v.events, adminReceipt=receipt(case), timePlan=None,
        requestStatus=503, recoveryStatus=200, graphBefore=[], graphAfter=[],
        graphRecovery=graph(), selectedFingerprint='a' * 64)


def contested_row():
    v = Vector()
    before = v.snapshot()
    v.wall = W1 - 2
    imports = [(FAMILY, 3), (FAMILY, 1)]
    fetches = [('foreground_content_fetch', 3), ('content_fetch_global', 1)]
    v.event('COMPOSED_URI_IMPORT_START', 1)
    v.event('COMPOSED_CHILD', 2, value=1)
    for family, scope in imports:
        v.event('RATE_RESERVED', 2, family, scope, 1, W0)
    v.hold(2, imports)
    v.event('BUDGET_RESERVED', 2, FAMILY)
    v.event('COMPOSED_CHILD', 3, value=1)
    for family, scope in fetches:
        v.charge(3, family, scope, W1 - 60)
    v.hold(3, fetches)
    v.event('BUDGET_COMMITTED', 3, 'trust_graph_import_uri')
    v.event('FETCH_INVOKED', 3, 'trust_graph_import_uri')
    during = v.snapshot()
    v.wall = W1 + 1
    v.direct(4)
    v.event('FETCH_SUCCEEDED', 3, 'trust_graph_import_uri')
    v.hold(3, fetches, True)
    for family, scope in imports:
        v.event('RATE_RESERVATION_RELEASED', 2, family, scope, 0, W0)
    v.event('RATE_LIMIT_REACHED', 2, FAMILY, 3, 1, W1)
    v.event('BUDGET_RATE_DENIED', 2, FAMILY)
    v.hold(2, imports, True)
    v.event('REQUEST_FAILED', 1)
    after = v.snapshot()
    v.direct(6)
    return dict(caseId='window-crossing', variant='contested-capacity',
        evidenceClass=storage.INSTALLED, operationId=1, collectorEpoch=EPOCH,
        nodeEpoch=NODE, roleGeneration=GENERATION, before=before, during=during,
        after=after, recoveryAfter=v.snapshot(), events=v.events, adminReceipt=None,
        timePlan=dict(boundaryEpochSecond=W1, startMarginSeconds=10,
            requestDeadlineMillis=45000, selectedAtEpochSecond=W1 - 100,
            observedReservationEpochSecond=W1 - 1, releasedAtEpochSecond=W1),
        requestStatus=429, recoveryStatus=200, graphBefore=[], graphAfter=graph(),
        graphRecovery=graph(), selectedFingerprint='a' * 64)


def component(rows):
    return dict(schemaVersion=1, kind='composed-budget-storage-component', storageCases=rows)


def complete_rows():
    rows = [installed(case) for case in storage.CASES] + [contested_row()] + [uri_row(variant)
        for variant in ('uri-child-write-denial', 'uri-import-commit-denial',
                        'uri-readable-directory-denial')]
    for index, row in enumerate(rows):
        row['collectorEpoch'] = '%08d-1234-1234-1234-123456789012' % index
        row['nodeEpoch'] = '%032x' % index
    return rows


class CompleteStorageTests(unittest.TestCase):
    def test_all_seven_revalidated_directions_complete_only_storage_parents(self):
        source = component(complete_rows())
        before = copy.deepcopy(source)
        result = storage.derive_complete_storage(source)
        self.assertEqual(sorted(storage.CASES), result['observedCases'])
        self.assertEqual(7, len(result['verifiedVariants']))
        self.assertEqual([], result['unobservedVariants'])
        self.assertEqual(source, before)
        self.assertEqual('not-observed', result['fullAppBudgets'])
        self.assertEqual('not-established', result['originalAuthentication'])
        self.assertFalse(result['releaseEligible'])

    def test_each_missing_direction_withholds_its_parent(self):
        rows = complete_rows()
        for index, row in enumerate(rows):
            with self.subTest(variant=row['variant']):
                result = storage.derive_complete_storage(component(rows[:index] + rows[index + 1:]))
                self.assertNotIn(row['caseId'], result['observedCases'])

    def test_replays_substituted_epoch_and_invalid_ledger_fail(self):
        rows = complete_rows()
        mutations = []
        repeated = copy.deepcopy(rows[:2])
        repeated[1] = copy.deepcopy(repeated[0])
        mutations.append(repeated)
        replay = copy.deepcopy(rows)
        replay[3]['collectorEpoch'] = replay[0]['collectorEpoch']
        replay[3]['nodeEpoch'] = replay[0]['nodeEpoch']
        mutations.append(replay)
        forged = copy.deepcopy(rows)
        next(e for e in forged[4]['events'] if e['kind'] == 'RATE_WRITE_ATTEMPT')['value'] = 99
        mutations.append(forged)
        no_recovery = copy.deepcopy(rows)
        no_recovery[5]['recoveryStatus'] = 503
        mutations.append(no_recovery)
        for changed in mutations:
            with self.assertRaises(owner.ComposedEvidenceError):
                storage.derive_complete_storage(component(changed))

    def test_wrong_uri_fault_phase_and_contested_stimulus_reject(self):
        row = uri_row('uri-child-write-denial')
        row['variant'] = 'uri-import-commit-denial'
        with self.assertRaises(owner.ComposedEvidenceError):
            storage.derive_complete_storage(component([row]))

    def test_balanced_cleanup_without_actual_import_capacity_or_reservation_rejects(self):
        for kind_pair in (('CONCURRENCY_HELD', 'CONCURRENCY_RELEASED'),
                          ('RATE_RESERVED', 'RATE_RESERVATION_RELEASED')):
            row = uri_row('uri-child-write-denial')
            for event in row['events']:
                if event['operationId'] == 2 and event['kind'] in kind_pair:
                    event['kind'] = 'RATE_OBSERVED'
            with self.assertRaises(owner.ComposedEvidenceError):
                storage.derive_complete_storage(component([row]))

    def test_disjoint_sequences_cannot_reuse_native_operation_identity(self):
        first = installed('partial-rate-write')
        second = uri_row('uri-child-write-denial')
        for event in second['events']:
            event['sequence'] += 200
        for name in ('before', 'during', 'after', 'recoveryAfter'):
            # The fixture intentionally shares before/during, so copy before changing.
            second[name] = dict(second[name], sequence=second[name]['sequence'] + 200)
        with self.assertRaisesRegex(owner.ComposedEvidenceError, 'component-native-replayed'):
            storage.derive_complete_storage(component([first, second]))
        row = contested_row()
        row['events'] = [e for e in row['events'] if not (
            e['kind'] == 'RATE_CHARGED' and e['operationId'] == 5)]
        with self.assertRaises(owner.ComposedEvidenceError):
            storage.derive_complete_storage(component([row]))

    def test_historical_v4_still_rejects_successor_directions(self):
        from cryptad_certification.tests.test_composed_budget_storage_evidence import attachment
        for row in (contested_row(), uri_row('uri-child-write-denial')):
            with self.assertRaises(owner.ComposedEvidenceError):
                storage.derive_cases(attachment(row), {}, None)

    def test_unknown_snapshot_and_ring_loss_are_incomplete(self):
        for fault in ('unknown', 'ring'):
            rows = complete_rows()
            if fault == 'unknown':
                rows[4]['during']['budgetValid'] = False
                rows[4]['during']['rates'] = None
            else:
                rows[4]['during']['droppedEvents'] = 1
            result = storage.derive_complete_storage(component(rows))
            self.assertNotIn('partial-rate-write', result['observedCases'])

    def test_native_controlled_exports_keep_original_evidence_class(self):
        root = Path(__file__).resolve().parents[4]
        files = sorted((root / 'platform-api/build/test-results/pr318-native').glob('*.json'))
        if not files:
            self.skipTest('Native Java exports unavailable; this is not synthetic installed evidence')
        for path in files:
            raw = json.loads(path.read_text())
            original = copy.deepcopy(raw)
            result = storage.derive_controlled(raw)
            self.assertEqual(raw, original)
            self.assertEqual(storage.CONTROLLED, result['evidenceClass'])
            self.assertFalse(result['installedObservation'])
            with self.assertRaises(owner.ComposedEvidenceError):
                storage.derive_complete_storage(component([raw]))
