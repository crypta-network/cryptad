"""Causal attachment v3 proves overlap and deferred-owner lifecycle without legacy credit."""
import copy
import unittest
from unittest.mock import patch

from cryptad_certification import composed_budget_evidence as owner
from cryptad_certification import runtime_pressure_evidence as pressure


EPOCH = '12345678-1234-1234-1234-123456789012'
NODE_EPOCH = 'a' * 32
WINDOW = 1789387200
ORDERED_REQUIRED_CASES = tuple(('direct-valid direct-malformed pasted-preview-valid uri-preview-valid '
    'uri-preview-malformed uri-valid uri-malformed uri-fingerprint-mismatch uri-duplicate '
    'authorization-denied app-import-rate global-import-rate import-concurrency '
    'app-fetch-rate global-fetch-rate fetch-concurrency shared-foreground shared-subscription '
    'invalid-uri invalid-utf8 oversized timeout cancellation retry window-crossing '
    'partial-rate-write graph-store-unavailable graceful-restart abrupt-restart '
    'diagnostics-unavailable privacy').split())


class CausalFixture:
    def __init__(self, case_id, operations, operation_id, request_outcome,
                 owner_outcome='not-applicable', retry_of=None):
        self.events = []
        self.operations = [dict(operationId=operation, parentOperationId=parent,
                                role=role, scope=3)
                           for role, operation, parent in operations]
        self.case = dict(caseId=case_id, collectorEpoch=EPOCH, nodeEpoch=NODE_EPOCH,
                         scope=3, operationId=operation_id, sequenceStart=2, sequenceEnd=1,
                         budgetValid=True, droppedEvents=0, requestOutcome=request_outcome,
                         ownerOutcome=owner_outcome, unresolved=False, censored=False,
                         retryOfOperationId=retry_of, operations=self.operations, events=self.events,
                         snapshots={}, rateAttribution=[])

    def event(self, kind, operation_id, operation=None, scope=3, value=0, window=0):
        self.events.append(dict(sequence=len(self.events) + 2,
            observedAt='2026-09-14T12:00:00Z', elapsedNanos=len(self.events), kind=kind,
            operation=operation, windowStartEpochSecond=window, value=value,
            operationId=operation_id, scope=scope, sourceEpoch=None, sourceSequence=0,
            sourceSampledAtEpochMillis=0))

    def link(self, child, parent):
        self.event('COMPOSED_CHILD', child, value=parent)

    def charge(self, operation_id, family, scope=3):
        count = 1 + sum(event['kind'] == 'RATE_CHARGED'
                        and event['operation'] == family and event['scope'] == scope
                        and event['windowStartEpochSecond'] == WINDOW for event in self.events)
        self.event('RATE_CHARGED', operation_id, family, scope, count, WINDOW)

    def finish(self, during_holds, retained_before=0, retained_after=0):
        self.case['sequenceEnd'] = self.events[-1]['sequence']
        totals = {}
        attributed = {}
        for event in self.events:
            if event['kind'] != 'RATE_CHARGED':
                continue
            family = event['operation'], event['scope'], event['windowStartEpochSecond']
            totals[family] = totals.get(family, 0) + 1
            key = (event['operationId'],) + family
            attributed[key] = attributed.get(key, 0) + 1
        before_rates = [dict(operation=family, scope=scope,
                             windowStartEpochSecond=window, count=0)
                        for family, scope, window in totals]
        after_rates = [dict(operation=family, scope=scope,
                            windowStartEpochSecond=window, count=count)
                       for (family, scope, window), count in totals.items()]
        self.case['rateAttribution'] = [dict(operationId=operation_id, operation=family,
            scope=scope, windowStartEpochSecond=window, delta=delta)
            for (operation_id, family, scope, window), delta in attributed.items()]
        hold_rows = [dict(operationId=operation_id, operation=family, scope=scope,
                          kind=kind, count=1)
                     for operation_id, family, scope, kind in during_holds]
        during_sequence = next(event['sequence'] for event in self.events
                               if event['kind'] == 'CONCURRENCY_LIMIT_REACHED') \
            if any(event['kind'] == 'CONCURRENCY_LIMIT_REACHED' for event in self.events) \
            else self.events[len(self.events) // 2]['sequence']
        during_totals = {key: 0 for key in totals}
        during_retained = retained_before
        for event in self.events:
            if event['sequence'] > during_sequence:
                continue
            if event['kind'] == 'RATE_CHARGED':
                key = event['operation'], event['scope'], event['windowStartEpochSecond']
                during_totals[key] = event['value']
            if event['kind'] == 'GRAPH_STORE_IMPORTED':
                during_retained += 1
        during_rates = [dict(operation=family, scope=scope,
                             windowStartEpochSecond=window, count=count)
                        for (family, scope, window), count in during_totals.items()]
        def snapshot(sequence, rates, holds, retained):
            return dict(sequence=sequence, budgetValid=True, droppedEvents=0,
                        rates=copy.deepcopy(rates), holds=copy.deepcopy(holds),
                        retainedStatements=retained)
        self.case['snapshots'] = {
            'before': snapshot(1, before_rates, [], retained_before),
            'during': snapshot(during_sequence, during_rates, hold_rows, during_retained),
            'after': snapshot(self.case['sequenceEnd'], after_rates, [], retained_after),
        }
        return attachment(self.case)


def attachment(case):
    return dict(schemaVersion=3, workloadDigest='sha256:' + '1' * 64,
                productDigest='sha256:' + '2' * 64, sourceCommit='3' * 40,
                appCohortDigest='sha256:' + '4' * 64,
                collectorDigest='sha256:' + '5' * 64,
                configurationDigest='sha256:' + '6' * 64,
                collectorEpoch=EPOCH, nodeEpoch=NODE_EPOCH, segments=[], causalCases=[case])


def import_concurrency_fixture():
    fixture = CausalFixture('import-concurrency', (
        ('holder-parent', 1, None), ('holder-import', 2, 1),
        ('contender-parent', 3, None), ('contender-import', 4, 3),
        ('recovery-parent', 5, None), ('recovery-import', 6, 5)), 3, 'denied')
    fixture.event('COMPOSED_DIRECT_IMPORT_START', 1)
    fixture.link(2, 1)
    fixture.charge(2, 'trust_graph_import')
    fixture.event('CONCURRENCY_HELD', 2, 'trust_graph_import')
    fixture.event('BUDGET_COMMITTED', 2, 'trust_graph_import')
    fixture.event('COMPOSED_DIRECT_IMPORT_START', 3)
    fixture.link(4, 3)
    fixture.event('CONCURRENCY_LIMIT_REACHED', 4, 'trust_graph_import', value=1)
    fixture.event('BUDGET_CONCURRENCY_DENIED', 4, 'trust_graph_import')
    fixture.event('REQUEST_FAILED', 3)
    fixture.event('CONCURRENCY_RELEASED', 2, 'trust_graph_import')
    fixture.event('BUDGET_RELEASED', 2, 'trust_graph_import')
    fixture.event('REQUEST_SUCCEEDED', 1)
    fixture.event('COMPOSED_DIRECT_IMPORT_START', 5)
    fixture.link(6, 5)
    fixture.event('BUDGET_ACQUIRE', 6, 'trust_graph_import')
    fixture.charge(6, 'trust_graph_import')
    fixture.charge(6, 'trust_graph_import', scope=1)
    fixture.event('CONCURRENCY_HELD', 6, 'trust_graph_import')
    fixture.event('CONCURRENCY_HELD', 6, 'trust_graph_import', scope=1)
    fixture.event('BUDGET_COMMITTED', 6, 'trust_graph_import')
    fixture.event('GRAPH_STORE_ATTEMPT', 5)
    fixture.event('GRAPH_STORE_DUPLICATE', 5)
    fixture.event('CONCURRENCY_RELEASED', 6, 'trust_graph_import')
    fixture.event('CONCURRENCY_RELEASED', 6, 'trust_graph_import', scope=1)
    fixture.event('BUDGET_RELEASED', 6, 'trust_graph_import')
    fixture.event('REQUEST_SUCCEEDED', 5)
    return fixture.finish([(2, 'trust_graph_import', 3, 'concurrency')])


def fetch_concurrency_fixture():
    fixture = CausalFixture('fetch-concurrency', (
        ('holder-parent', 11, None), ('holder-fetch', 12, 11),
        ('contender-parent', 13, None), ('contender-import', 14, 13),
        ('contender-fetch', 15, 13), ('recovery-parent', 16, None),
        ('recovery-fetch', 17, 16), ('recovery-import', 18, 16)), 13, 'denied')
    fixture.event('COMPOSED_URI_IMPORT_START', 11)
    fixture.link(12, 11)
    fixture.charge(12, 'foreground_content_fetch')
    fixture.event('CONCURRENCY_HELD', 12, 'foreground_content_fetch')
    fixture.event('FETCH_INVOKED', 12, 'trust_graph_import_uri')
    fixture.event('COMPOSED_URI_IMPORT_START', 13)
    fixture.link(14, 13)
    fixture.event('BUDGET_RESERVED', 14, 'trust_graph_import')
    fixture.link(15, 13)
    fixture.event('CONCURRENCY_LIMIT_REACHED', 15, 'foreground_content_fetch', value=1)
    fixture.event('BUDGET_CONCURRENCY_DENIED', 15, 'trust_graph_import_uri')
    fixture.event('BUDGET_RELEASED', 14, 'trust_graph_import')
    fixture.event('REQUEST_FAILED', 13)
    fixture.event('FETCH_SUCCEEDED', 12, 'trust_graph_import_uri')
    fixture.event('CONCURRENCY_RELEASED', 12, 'foreground_content_fetch')
    fixture.event('BUDGET_RELEASED', 12, 'trust_graph_import_uri')
    fixture.event('REQUEST_SUCCEEDED', 11)
    fixture.event('COMPOSED_URI_IMPORT_START', 16)
    fixture.link(18, 16)
    fixture.event('BUDGET_RESERVE', 18, 'trust_graph_import')
    fixture.event('CONCURRENCY_HELD', 18, 'trust_graph_import')
    fixture.event('CONCURRENCY_HELD', 18, 'trust_graph_import', scope=1)
    fixture.event('BUDGET_RESERVED', 18, 'trust_graph_import')
    fixture.link(17, 16)
    fixture.event('BUDGET_ACQUIRE', 17, 'trust_graph_import_uri')
    fixture.charge(17, 'foreground_content_fetch')
    fixture.charge(17, 'content_fetch_global', scope=1)
    fixture.event('CONCURRENCY_HELD', 17, 'foreground_content_fetch')
    fixture.event('CONCURRENCY_HELD', 17, 'content_fetch_global', scope=1)
    fixture.event('BUDGET_COMMITTED', 17, 'trust_graph_import_uri')
    fixture.event('FETCH_INVOKED', 17, 'trust_graph_import_uri')
    fixture.event('FETCH_SUCCEEDED', 17, 'trust_graph_import_uri')
    fixture.event('CONCURRENCY_RELEASED', 17, 'foreground_content_fetch')
    fixture.event('CONCURRENCY_RELEASED', 17, 'content_fetch_global', scope=1)
    fixture.event('BUDGET_RELEASED', 17, 'trust_graph_import_uri')
    fixture.charge(18, 'trust_graph_import')
    fixture.charge(18, 'trust_graph_import', scope=1)
    fixture.event('BUDGET_COMMITTED', 18, 'trust_graph_import')
    fixture.event('GRAPH_STORE_ATTEMPT', 16)
    fixture.event('GRAPH_STORE_DUPLICATE', 16)
    fixture.event('CONCURRENCY_RELEASED', 18, 'trust_graph_import')
    fixture.event('CONCURRENCY_RELEASED', 18, 'trust_graph_import', scope=1)
    fixture.event('BUDGET_RELEASED', 18, 'trust_graph_import')
    fixture.event('REQUEST_SUCCEEDED', 16)
    return fixture.finish([(12, 'foreground_content_fetch', 3, 'concurrency')])


def deferred_owner_fixture(cancelled=False):
    fixture = CausalFixture('cancellation' if cancelled else 'timeout', (
        ('primary-parent', 21, None), ('primary-import', 22, 21), ('primary-fetch', 23, 21),
        ('contender-parent', 24, None), ('contender-fetch', 25, 24),
        ('recovery-parent', 26, None), ('recovery-import', 27, 26)),
        21, 'cancelled' if cancelled else 'timed-out',
        'normal-ack')
    fixture.event('COMPOSED_URI_IMPORT_START', 21)
    fixture.link(22, 21)
    fixture.event('CONCURRENCY_HELD', 22, 'trust_graph_import')
    fixture.event('CONCURRENCY_HELD', 22, 'trust_graph_import', scope=1)
    fixture.event('BUDGET_RESERVED', 22, 'trust_graph_import')
    fixture.link(23, 21)
    fixture.charge(23, 'foreground_content_fetch')
    fixture.event('CONCURRENCY_HELD', 23, 'foreground_content_fetch')
    fixture.event('FETCH_INVOKED', 23, 'trust_graph_import_uri')
    if not cancelled:
        fixture.event('FETCH_TIMEOUT', 21)
    fixture.event('FETCH_CANCEL_REQUESTED', 23, 'trust_graph_import_uri')
    fixture.event('FETCH_TERMINATION_UNKNOWN', 23, 'trust_graph_import_uri')
    fixture.event('REQUEST_FAILED', 21)
    fixture.event('COMPOSED_URI_IMPORT_START', 24)
    fixture.link(25, 24)
    fixture.event('CONCURRENCY_LIMIT_REACHED', 25, 'foreground_content_fetch', value=1)
    fixture.event('BUDGET_CONCURRENCY_DENIED', 25, 'trust_graph_import_uri')
    fixture.event('REQUEST_FAILED', 24)
    fixture.event('FETCH_OWNER_TERMINATED', 23, 'trust_graph_import_uri')
    fixture.event('FETCH_FAILED', 23, 'trust_graph_import_uri')
    fixture.event('CONCURRENCY_RELEASED', 23, 'foreground_content_fetch')
    fixture.event('BUDGET_RELEASED', 23, 'trust_graph_import_uri')
    fixture.event('CONCURRENCY_RELEASED', 22, 'trust_graph_import')
    fixture.event('CONCURRENCY_RELEASED', 22, 'trust_graph_import', scope=1)
    fixture.event('BUDGET_RELEASED', 22, 'trust_graph_import')
    fixture.event('COMPOSED_DIRECT_IMPORT_START', 26)
    fixture.link(27, 26)
    fixture.event('BUDGET_ACQUIRE', 27, 'trust_graph_import')
    fixture.charge(27, 'trust_graph_import')
    fixture.charge(27, 'trust_graph_import', scope=1)
    fixture.event('CONCURRENCY_HELD', 27, 'trust_graph_import')
    fixture.event('CONCURRENCY_HELD', 27, 'trust_graph_import', scope=1)
    fixture.event('BUDGET_COMMITTED', 27, 'trust_graph_import')
    fixture.event('GRAPH_STORE_ATTEMPT', 26)
    fixture.event('GRAPH_STORE_DUPLICATE', 26)
    fixture.event('CONCURRENCY_RELEASED', 27, 'trust_graph_import')
    fixture.event('CONCURRENCY_RELEASED', 27, 'trust_graph_import', scope=1)
    fixture.event('BUDGET_RELEASED', 27, 'trust_graph_import')
    fixture.event('REQUEST_SUCCEEDED', 26)
    return fixture.finish([(22, 'trust_graph_import', 3, 'concurrency'),
                           (22, 'trust_graph_import', 1, 'concurrency'),
                           (23, 'foreground_content_fetch', 3, 'concurrency')])


def retry_fixture():
    fixture = CausalFixture('retry', (
        ('prior-parent', 31, None), ('prior-import', 32, 31), ('prior-fetch', 33, 31),
        ('retry-parent', 34, None), ('retry-import', 35, 34), ('retry-fetch', 36, 34)),
        34, 'response-lost-retry-succeeded', retry_of=31)
    fixture.event('COMPOSED_URI_IMPORT_START', 31)
    fixture.link(32, 31)
    fixture.link(33, 31)
    fixture.event('CONCURRENCY_HELD', 32, 'trust_graph_import')
    fixture.charge(32, 'trust_graph_import')
    fixture.charge(32, 'trust_graph_import', scope=1)
    fixture.charge(33, 'foreground_content_fetch')
    fixture.charge(33, 'content_fetch_global', scope=1)
    fixture.event('FETCH_INVOKED', 33, 'trust_graph_import_uri')
    fixture.event('FETCH_SUCCEEDED', 33, 'trust_graph_import_uri')
    fixture.event('BUDGET_RELEASED', 33, 'trust_graph_import_uri')
    fixture.event('GRAPH_STORE_ATTEMPT', 31)
    fixture.event('GRAPH_STORE_IMPORTED', 31)
    fixture.event('CONCURRENCY_RELEASED', 32, 'trust_graph_import')
    fixture.event('BUDGET_RELEASED', 32, 'trust_graph_import')
    fixture.event('REQUEST_SUCCEEDED', 31)
    fixture.event('COMPOSED_URI_IMPORT_START', 34)
    fixture.link(35, 34)
    fixture.link(36, 34)
    fixture.charge(35, 'trust_graph_import')
    fixture.charge(35, 'trust_graph_import', scope=1)
    fixture.charge(36, 'foreground_content_fetch')
    fixture.charge(36, 'content_fetch_global', scope=1)
    fixture.event('FETCH_INVOKED', 36, 'trust_graph_import_uri')
    fixture.event('FETCH_SUCCEEDED', 36, 'trust_graph_import_uri')
    fixture.event('BUDGET_RELEASED', 36, 'trust_graph_import_uri')
    fixture.event('GRAPH_STORE_ATTEMPT', 34)
    fixture.event('GRAPH_STORE_DUPLICATE', 34)
    fixture.event('BUDGET_RELEASED', 35, 'trust_graph_import')
    fixture.event('REQUEST_SUCCEEDED', 34)
    value = fixture.finish([(32, 'trust_graph_import', 3, 'concurrency')], retained_after=1)
    value['causalCases'][0]['snapshots']['during']['sequence'] = 5
    value['causalCases'][0]['snapshots']['during']['rates'] = copy.deepcopy(
        value['causalCases'][0]['snapshots']['before']['rates'])
    value['causalCases'][0]['snapshots']['during']['retainedStatements'] = 0
    return value


class ComposedBudgetCausalEvidenceTest(unittest.TestCase):
    def derive(self, value):
        return owner.derive(value, workload_digest='sha256:' + '1' * 64,
            product_digest='sha256:' + '2' * 64, source_commit='3' * 40,
            app_cohort_digest='sha256:' + '4' * 64)

    def assert_not_observed(self, value):
        self.assertEqual([], self.derive(value)['observedCases'])

    def test_all_five_causal_cases_are_observed_without_claiming_full_coverage(self):
        fixtures = (import_concurrency_fixture(), fetch_concurrency_fixture(),
                    deferred_owner_fixture(), deferred_owner_fixture(True), retry_fixture())
        for value in fixtures:
            case_id = value['causalCases'][0]['caseId']
            with self.subTest(case_id=case_id):
                result = self.derive(value)
                self.assertEqual([case_id], result['observedCases'])
                self.assertEqual(list(owner.REQUIRED_CASES), result['requiredCases'])
                self.assertEqual(31, len(result['requiredCases']))
                self.assertEqual(1, result['schemaVersion'])
                self.assertEqual('not-observed', result['fullAppBudgets'])
                self.assertFalse(result['releaseEligible'])

    def test_v3_is_a_narrow_companion_and_v1_v2_vocabulary_stays_closed(self):
        self.assertEqual(ORDERED_REQUIRED_CASES, owner.REQUIRED_CASES)
        for kind in owner.CAUSAL_KINDS:
            self.assertNotIn(kind, owner.COMPOSED_KINDS)
            self.assertNotIn(kind, pressure.KINDS)
        value = import_concurrency_fixture()
        value['schemaVersion'] = 2
        with self.assertRaises(owner.ComposedEvidenceError):
            self.derive(value)
        from cryptad_certification.tests.test_composed_budget_evidence import (
            ComposedBudgetEvidenceTest)
        legacy = ComposedBudgetEvidenceTest().valid_uri()
        legacy.update(schemaVersion=3, causalCases=[])
        self.assertEqual(['uri-valid'], self.derive(legacy)['observedCases'])

    def test_concurrency_rejects_wrong_family_count_nonoverlap_missing_hold_and_started_work(self):
        for mutation in ('family', 'scope', 'count', 'nonoverlap', 'missing-hold',
                         'started-work'):
            value = import_concurrency_fixture()
            case = value['causalCases'][0]
            limit = next(event for event in case['events']
                         if event['kind'] == 'CONCURRENCY_LIMIT_REACHED')
            if mutation == 'family':
                limit['operation'] = 'foreground_content_fetch'
            elif mutation == 'scope':
                limit['scope'] = 7
            elif mutation == 'count':
                limit['value'] = 2
            elif mutation == 'nonoverlap':
                released = next(event for event in case['events']
                                if event['kind'] == 'CONCURRENCY_RELEASED')
                case['events'].remove(released)
                case['events'].insert(case['events'].index(limit), released)
                self.renumber(case)
            elif mutation == 'missing-hold':
                case['snapshots']['during']['holds'] = []
            else:
                denied = next(row['operationId'] for row in case['operations']
                              if row['role'] == 'contender-import')
                self.append_event(case, 'FETCH_INVOKED', denied, 'trust_graph_import_uri')
            with self.subTest(mutation=mutation):
                if mutation == 'scope':
                    with self.assertRaises(owner.ComposedEvidenceError):
                        self.derive(value)
                else:
                    self.assert_not_observed(value)

    def test_deferred_owner_requires_both_import_concurrency_scopes(self):
        for kind in ('CONCURRENCY_HELD', 'CONCURRENCY_RELEASED'):
            value = deferred_owner_fixture()
            case = value['causalCases'][0]
            event = next(event for event in case['events']
                         if event['kind'] == kind
                         and event['operationId'] == 22 and event['scope'] == 1)
            case['events'].remove(event)
            if kind == 'CONCURRENCY_HELD':
                case['snapshots']['during']['holds'] = [
                    row for row in case['snapshots']['during']['holds']
                    if not (row['operationId'] == 22 and row['scope'] == 1)]
            self.renumber(case)
            with self.subTest(kind=kind):
                self.assert_not_observed(value)

    def test_deferred_owner_requires_normal_ack_before_release_in_same_complete_epoch(self):
        for mutation in ('early-release', 'exceptional-ack', 'missing-ack', 'epoch', 'gap'):
            value = deferred_owner_fixture()
            case = value['causalCases'][0]
            ack = next(event for event in case['events'] if event['kind'] == 'FETCH_OWNER_TERMINATED')
            if mutation == 'early-release':
                released = next(event for event in case['events']
                                if event['kind'] == 'CONCURRENCY_RELEASED')
                case['events'].remove(released)
                case['events'].insert(case['events'].index(ack), released)
                self.renumber(case)
            elif mutation == 'exceptional-ack':
                ack['kind'] = 'FETCH_OWNER_TERMINATION_FAILED'
                case['ownerOutcome'] = 'exceptional-ack'
            elif mutation == 'missing-ack':
                case['events'].remove(ack)
                self.renumber(case)
            elif mutation == 'epoch':
                case['collectorEpoch'] = '87654321-4321-4321-4321-210987654321'
            else:
                case['events'][3]['sequence'] += 1
            with self.subTest(mutation=mutation):
                if mutation in {'epoch', 'gap'}:
                    with self.assertRaises(owner.ComposedEvidenceError):
                        self.derive(value)
                else:
                    self.assert_not_observed(value)

    def test_deferred_owner_requires_server_observed_request_to_native_owner(self):
        for cancelled in (False, True):
            value = deferred_owner_fixture(cancelled)
            case = value['causalCases'][0]
            requested = next(event for event in case['events']
                             if event['kind'] == 'FETCH_CANCEL_REQUESTED')
            case['events'].remove(requested)
            self.renumber(case)

            with self.subTest(cancelled=cancelled):
                self.assert_not_observed(value)

    def test_recovery_requires_budget_admission_and_store_work(self):
        for fixture in (import_concurrency_fixture, fetch_concurrency_fixture,
                        deferred_owner_fixture):
            value = fixture()
            case = value['causalCases'][0]
            recovery_import = next(row['operationId'] for row in case['operations']
                                   if row['role'] == 'recovery-import')
            committed = next(event for event in case['events']
                             if event['operationId'] == recovery_import
                             and event['kind'] == 'BUDGET_COMMITTED')
            case['events'].remove(committed)
            self.renumber(case)
            with self.subTest(case=case['caseId']):
                with patch.object(owner, '_successful_recovery', return_value=True):
                    self.assertEqual([case['caseId']], self.derive(value)['observedCases'])
                self.assert_not_observed(value)

    def test_deferred_owner_requires_failure_after_acknowledgment(self):
        value = deferred_owner_fixture()
        case = value['causalCases'][0]
        failed = next(event for event in case['events'] if event['kind'] == 'FETCH_FAILED')
        case['events'].remove(failed)
        self.renumber(case)

        with patch.object(owner, '_causal_deferred_owner', return_value=True):
            self.assertEqual(['timeout'], self.derive(value)['observedCases'])
        self.assert_not_observed(value)

    def test_complete_rate_attribution_rejects_unexplained_delta_or_contender_charge(self):
        value = fetch_concurrency_fixture()
        value['causalCases'][0]['snapshots']['after']['rates'][0]['count'] += 1
        self.assert_not_observed(value)
        value = fetch_concurrency_fixture()
        case = value['causalCases'][0]
        denied = next(row['operationId'] for row in case['operations']
                      if row['role'] == 'contender-fetch')
        self.append_event(case, 'RATE_CHARGED', denied, 'foreground_content_fetch', WINDOW)
        case['rateAttribution'].append(dict(operationId=denied,
            operation='foreground_content_fetch', scope=3,
            windowStartEpochSecond=WINDOW, delta=1))
        case['snapshots']['after']['rates'][0]['count'] += 1
        self.assert_not_observed(value)

    def test_retry_rejects_id_reuse_child_borrowing_refund_and_guessed_success(self):
        for mutation in ('reuse', 'borrowing', 'refund', 'guessed'):
            value = retry_fixture()
            case = value['causalCases'][0]
            if mutation == 'reuse':
                retry = next(row for row in case['operations'] if row['role'] == 'retry-parent')
                retry['operationId'] = case['retryOfOperationId']
            elif mutation == 'borrowing':
                link = next(event for event in case['events']
                            if event['kind'] == 'COMPOSED_CHILD' and event['operationId'] == 36)
                link['value'] = 31
            elif mutation == 'refund':
                case['snapshots']['after']['rates'][0]['count'] -= 1
            else:
                case['requestOutcome'] = 'succeeded'
            with self.subTest(mutation=mutation):
                if mutation == 'reuse':
                    with self.assertRaises(owner.ComposedEvidenceError):
                        self.derive(value)
                else:
                    self.assert_not_observed(value)

    def test_retry_requires_exact_app_and_global_rate_families_for_each_child(self):
        for mutation in ('missing-global', 'wrong-family', 'duplicate'):
            value = retry_fixture()
            case = value['causalCases'][0]
            charge = next(event for event in case['events']
                          if event['kind'] == 'RATE_CHARGED'
                          and event['operationId'] == 32 and event['scope'] == 1)
            if mutation == 'missing-global':
                case['events'].remove(charge)
                case['rateAttribution'] = [row for row in case['rateAttribution']
                    if not (row['operationId'] == 32 and row['scope'] == 1)]
                after = next(row for row in case['snapshots']['after']['rates']
                             if row['operation'] == 'trust_graph_import' and row['scope'] == 1)
                after['count'] -= 1
                later = next(event for event in case['events']
                             if event['kind'] == 'RATE_CHARGED'
                             and event['operationId'] == 35 and event['scope'] == 1)
                later['value'] -= 1
                self.renumber(case)
            elif mutation == 'wrong-family':
                charge['operation'] = 'subscription_poll'
                attribution = next(row for row in case['rateAttribution']
                                   if row['operationId'] == 32 and row['scope'] == 1)
                attribution['operation'] = 'subscription_poll'
                after = next(row for row in case['snapshots']['after']['rates']
                             if row['operation'] == 'trust_graph_import' and row['scope'] == 1)
                after['count'] -= 1
                later = next(event for event in case['events']
                             if event['kind'] == 'RATE_CHARGED'
                             and event['operationId'] == 35 and event['scope'] == 1)
                later['value'] -= 1
                for name in ('before', 'during', 'after'):
                    case['snapshots'][name]['rates'].append(dict(
                        operation='subscription_poll', scope=1,
                        windowStartEpochSecond=WINDOW,
                        count=1 if name == 'after' else 0))
            else:
                duplicate = copy.deepcopy(charge)
                duplicate['value'] += 1
                case['events'].insert(case['events'].index(charge) + 1, duplicate)
                later = next(event for event in case['events']
                             if event['kind'] == 'RATE_CHARGED'
                             and event['operationId'] == 35 and event['scope'] == 1)
                later['value'] += 1
                attribution = next(row for row in case['rateAttribution']
                                   if row['operationId'] == 32 and row['scope'] == 1)
                attribution['delta'] += 1
                after = next(row for row in case['snapshots']['after']['rates']
                             if row['operation'] == 'trust_graph_import' and row['scope'] == 1)
                after['count'] += 1
                self.renumber(case)
            with self.subTest(mutation=mutation):
                with patch.object(owner, '_causal_retry', return_value=True):
                    self.assertEqual(['retry'], self.derive(value)['observedCases'])
                self.assert_not_observed(value)

    def test_retry_requires_both_native_fetches_before_store_verdicts(self):
        value = retry_fixture()
        case = value['causalCases'][0]
        case['events'] = [event for event in case['events']
                          if event['kind'] not in {'FETCH_INVOKED', 'FETCH_SUCCEEDED'}]
        self.renumber(case)

        with patch.object(owner, '_causal_retry', return_value=True):
            self.assertEqual(['retry'], self.derive(value)['observedCases'])
        self.assert_not_observed(value)

    @staticmethod
    def renumber(case):
        for index, event in enumerate(case['events'], start=2):
            event['sequence'] = index
            event['elapsedNanos'] = index - 2
        case['sequenceEnd'] = case['events'][-1]['sequence']
        case['snapshots']['after']['sequence'] = case['sequenceEnd']
        limits = [event for event in case['events'] if event['kind'] == 'CONCURRENCY_LIMIT_REACHED']
        if limits:
            case['snapshots']['during']['sequence'] = limits[0]['sequence']

    @classmethod
    def append_event(cls, case, kind, operation_id, operation, window=0):
        template = case['events'][-1]
        case['events'].append(dict(template, kind=kind, operationId=operation_id,
                                   operation=operation, scope=3, value=1,
                                   windowStartEpochSecond=window))
        cls.renumber(case)


if __name__ == '__main__':
    unittest.main()
