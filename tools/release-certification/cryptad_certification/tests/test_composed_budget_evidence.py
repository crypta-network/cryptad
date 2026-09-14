"""Closed prospective inputs cannot manufacture authority or omit hard cases."""
import copy
import unittest
from cryptad_certification import composed_budget_evidence as owner
from cryptad_certification import runtime_pressure_evidence as pressure


class ComposedBudgetEvidenceTest(unittest.TestCase):
    @staticmethod
    def promote_v2(value):
        # Collector v2 reserves 1 for global and 2 for host/operator; native apps begin at 3.
        def relabel(child):
            if isinstance(child, dict):
                for key, item in child.items():
                    if key == 'scope' and item == 2:
                        child[key] = 3
                    else:
                        relabel(item)
            elif isinstance(child, list):
                for item in child:
                    relabel(item)
        relabel(value)
        value.update(schemaVersion=2, collectorEpoch=value['segments'][0]['collectorEpoch'], nodeEpoch='a' * 32)

    def attachment(self):
        return dict(schemaVersion=1, workloadDigest='sha256:' + '1' * 64,
            productDigest='sha256:' + '2' * 64, sourceCommit='3' * 40,
            appCohortDigest='sha256:' + '4' * 64, collectorDigest='sha256:' + '5' * 64,
            configurationDigest='sha256:' + '6' * 64, segments=[])

    def derive(self, value):
        return owner.derive(value, workload_digest='sha256:' + '1' * 64,
            product_digest='sha256:' + '2' * 64, source_commit='3' * 40,
            app_cohort_digest='sha256:' + '4' * 64)

    def test_empty_input_preserves_every_required_case_and_no_authority(self):
        result = self.derive(self.attachment())
        self.assertEqual(set(owner.REQUIRED_CASES), set(result['missingCases']))
        self.assertEqual([], result['observedCases'])
        self.assertEqual('not-observed', result['fullAppBudgets'])
        self.assertFalse(result['releaseEligible'])
        self.assertNotIn('sha256:', str(result))

    def test_wrong_original_product_and_caller_claims_rejected(self):
        for key, value in [('productDigest', 'sha256:' + '8' * 64),
                           ('sourceCommit', '8' * 40), ('requiredCases', []),
                           ('uri', 'PRIVATE_CANARY')]:
            with self.subTest(key=key):
                attached = self.attachment()
                attached[key] = value
                with self.assertRaises(owner.ComposedEvidenceError):
                    self.derive(attached)

    def test_caller_cannot_reduce_policy_with_unknown_case(self):
        attached = self.attachment()
        attached['segments'] = [dict(caseId='easy-pass', collectorEpoch='0' * 36,
            operationId=1, scope=2, budgetValid=True, droppedEvents=0, events=[], beforeRates=[], afterRates=[],
            graphBefore={"retainedStatements": 0}, graphAfter={"retainedStatements": 0})]
        with self.assertRaises(owner.ComposedEvidenceError):
            self.derive(attached)

    def test_truncated_unavailable_and_missing_terminal_never_observed(self):
        for valid, dropped in [(True, 0), (False, 0), (True, 1)]:
            attached = self.attachment()
            attached['segments'] = [dict(caseId='uri-valid', collectorEpoch='0' * 36,
                operationId=1, scope=2, budgetValid=valid, droppedEvents=dropped, events=[], beforeRates=[], afterRates=[],
                graphBefore={"retainedStatements": 0}, graphAfter={"retainedStatements": 0})]
            self.assertEqual([], self.derive(attached)['observedCases'])

    def test_operation_replay_is_rejected(self):
        attached = self.attachment()
        segment = dict(caseId='uri-valid', collectorEpoch='0' * 36,
            operationId=1, scope=2, budgetValid=True, droppedEvents=0, events=[], beforeRates=[], afterRates=[],
            graphBefore={"retainedStatements": 0}, graphAfter={"retainedStatements": 0})
        attached['segments'] = [segment, copy.deepcopy(segment)]
        with self.assertRaises(owner.ComposedEvidenceError):
            self.derive(attached)

    def test_historical_kinds_are_not_silently_widened(self):
        self.assertNotIn('COMPOSED_URI_IMPORT_START', pressure.KINDS)
        self.assertIn('COMPOSED_URI_IMPORT_START', owner.COMPOSED_KINDS)

    def valid_direct(self):
        value = self.attachment()
        events = []
        def event(kind, operation=None, scope=2, count=0, opid=1, window=0):
            events.append(dict(sequence=len(events)+1, observedAt='2026-09-14T12:00:00Z',
                elapsedNanos=len(events), kind=kind, operation=operation,
                windowStartEpochSecond=window, value=count, operationId=opid, scope=scope,
                sourceEpoch=None, sourceSequence=0, sourceSampledAtEpochMillis=0))
        event('COMPOSED_DIRECT_IMPORT_START')
        event('COMPOSED_CHILD', count=1, opid=2)
        rates = []
        for scope in (2, 1):
            event('RATE_OBSERVED', 'trust_graph_import', scope, opid=2, window=1789387200)
            event('RATE_CHARGED', 'trust_graph_import', scope, count=1, opid=2, window=1789387200)
            event('CONCURRENCY_HELD', 'trust_graph_import', scope, count=1, opid=2)
            rates.append(dict(operation='trust_graph_import', scope=scope,
                windowStartEpochSecond=1789387200, count=0))
        event('BUDGET_COMMITTED', 'trust_graph_import', opid=2)
        event('PARSE_SUCCEEDED')
        event('GRAPH_STORE_ATTEMPT')
        event('GRAPH_STORE_IMPORTED')
        for scope in (2, 1):
            event('CONCURRENCY_RELEASED', 'trust_graph_import', scope, opid=2)
        event('BUDGET_RELEASED', 'trust_graph_import', opid=2)
        event('REQUEST_SUCCEEDED')
        value['segments'] = [dict(caseId='direct-valid', collectorEpoch='12345678-1234-1234-1234-123456789012',
            operationId=1, scope=2, budgetValid=True, droppedEvents=0, events=events,
            beforeRates=rates, afterRates=[dict(row, count=1) for row in rates],
            graphBefore={'retainedStatements': 0}, graphAfter={'retainedStatements': 1})]
        return value

    @staticmethod
    def move_before(events, selected, target):
        moved = [event for event in events if selected(event)]
        remaining = [event for event in events if not selected(event)]
        index = next(index for index, event in enumerate(remaining) if event['kind'] == target)
        events[:] = remaining[:index] + moved + remaining[index:]
        for index, event in enumerate(events):
            event.update(sequence=index + 1, elapsedNanos=index)

    def valid_uri(self, preview=False):
        value = self.valid_direct()
        segment = value['segments'][0]
        template = segment['events'][0]
        events = []
        window = 1789387200
        def record(kind, opid, family=None, scope=2, count=0, rate=False):
            events.append(dict(template, sequence=len(events) + 1, elapsedNanos=len(events),
                kind=kind, operationId=opid, operation=family, scope=scope, value=count,
                windowStartEpochSecond=window if rate else 0))
        record('COMPOSED_URI_PREVIEW_START' if preview else 'COMPOSED_URI_IMPORT_START', 1)
        record('COMPOSED_CHILD', 2, count=1)
        record('BUDGET_RESERVE', 2, 'trust_graph_import')
        for scope in (2, 1):
            record('RATE_RESERVED', 2, 'trust_graph_import', scope, rate=True)
            record('CONCURRENCY_HELD', 2, 'trust_graph_import', scope)
        record('BUDGET_RESERVED', 2, 'trust_graph_import')
        record('COMPOSED_CHILD', 3, count=1)
        record('BUDGET_ACQUIRE', 3, 'trust_graph_import_uri')
        fetch_families = [('foreground_content_fetch', 2), ('content_fetch_global', 1)]
        for family, scope in fetch_families:
            record('RATE_OBSERVED', 3, family, scope, rate=True)
            record('RATE_CHARGED', 3, family, scope, count=1, rate=True)
            record('CONCURRENCY_HELD', 3, family, scope)
        record('BUDGET_COMMITTED', 3, 'trust_graph_import_uri')
        record('FETCH_INVOKED', 3, 'trust_graph_import_uri')
        record('FETCH_SUCCEEDED', 3, 'trust_graph_import_uri')
        for family, scope in fetch_families:
            record('CONCURRENCY_RELEASED', 3, family, scope)
        record('BUDGET_RELEASED', 3)
        if preview:
            record('PARSE_SUCCEEDED', 1)
        for scope in (2, 1):
            record('RATE_RESERVATION_RELEASED', 2, 'trust_graph_import', scope, rate=True)
            record('RATE_OBSERVED', 2, 'trust_graph_import', scope, rate=True)
            record('RATE_CHARGED', 2, 'trust_graph_import', scope, count=1, rate=True)
        record('BUDGET_COMMITTED', 2, 'trust_graph_import')
        if preview:
            record('PREVIEW_BUILT', 1)
        else:
            record('PARSE_SUCCEEDED', 1)
            record('FINGERPRINT_ACCEPTED', 1)
            record('GRAPH_STORE_ATTEMPT', 1)
            record('GRAPH_STORE_IMPORTED', 1)
        for scope in (2, 1):
            record('CONCURRENCY_RELEASED', 2, 'trust_graph_import', scope)
        record('BUDGET_RELEASED', 2)
        record('REQUEST_SUCCEEDED', 1)
        segment.update(caseId='uri-preview-valid' if preview else 'uri-valid', events=events,
                       graphAfter={'retainedStatements': 0 if preview else 1})
        segment['afterRates'] += [dict(operation=family, scope=scope,
            windowStartEpochSecond=window, count=1) for family, scope in fetch_families]
        self.promote_v2(value)
        return value

    def test_successful_uri_requires_each_route_stage_exactly_once(self):
        for preview in (False, True):
            stages = ('PARSE_SUCCEEDED', 'PREVIEW_BUILT') if preview else (
                'PARSE_SUCCEEDED', 'FINGERPRINT_ACCEPTED', 'GRAPH_STORE_ATTEMPT', 'GRAPH_STORE_IMPORTED')
            for stage in stages:
                for mutation in ('missing', 'duplicate'):
                    with self.subTest(preview=preview, stage=stage, mutation=mutation):
                        value = self.valid_uri(preview)
                        self.assertEqual([value['segments'][0]['caseId']], self.derive(value)['observedCases'])
                        events = value['segments'][0]['events']
                        index = next(i for i, event in enumerate(events) if event['kind'] == stage)
                        if mutation == 'missing':
                            events.pop(index)
                        else:
                            events.insert(index, dict(events[index]))
                        for i, event in enumerate(events):
                            event.update(sequence=i + 1, elapsedNanos=i)
                        self.assertEqual([], self.derive(value)['observedCases'])

    def test_uri_success_stages_follow_native_causal_order(self):
        for preview, stage, target in (
                (True, 'PREVIEW_BUILT', 'PARSE_SUCCEEDED'),
                (False, 'FINGERPRINT_ACCEPTED', 'PARSE_SUCCEEDED'),
                (False, 'GRAPH_STORE_ATTEMPT', 'FINGERPRINT_ACCEPTED'),
                (False, 'GRAPH_STORE_IMPORTED', 'GRAPH_STORE_ATTEMPT'),
                (True, 'PARSE_SUCCEEDED', 'FETCH_SUCCEEDED')):
            with self.subTest(preview=preview, stage=stage, target=target):
                value = self.valid_uri(preview)
                self.move_before(value['segments'][0]['events'],
                                 lambda event: event['kind'] == stage, target)
                self.assertEqual([], self.derive(value)['observedCases'])

    def test_uri_preview_build_requires_committed_import_quota(self):
        value = self.valid_uri(True)
        events = value['segments'][0]['events']
        built = next(event for event in events if event['kind'] == 'PREVIEW_BUILT')
        events.remove(built)
        index = next(i for i, event in enumerate(events)
                     if event['kind'] == 'BUDGET_COMMITTED' and event['operation'] == 'trust_graph_import')
        events.insert(index, built)
        for i, event in enumerate(events):
            event.update(sequence=i + 1, elapsedNanos=i)
        self.assertEqual([], self.derive(value)['observedCases'])

    def test_uri_import_commit_requires_completed_fetch(self):
        value = self.valid_uri()
        self.move_before(value['segments'][0]['events'], lambda event:
                         event['kind'] == 'BUDGET_COMMITTED' and event['operation'] == 'trust_graph_import',
                         'FETCH_SUCCEEDED')
        self.assertEqual([], self.derive(value)['observedCases'])

    def test_duplicate_uri_import_still_requires_fingerprint_acceptance(self):
        value = self.valid_uri()
        segment = value['segments'][0]
        segment['caseId'] = 'uri-duplicate'
        segment['graphBefore'] = {'retainedStatements': 1}
        for event in segment['events']:
            if event['kind'] == 'GRAPH_STORE_IMPORTED':
                event['kind'] = 'GRAPH_STORE_DUPLICATE'
        self.assertEqual(['uri-duplicate'], self.derive(value)['observedCases'])
        segment['events'] = [event for event in segment['events'] if event['kind'] != 'FINGERPRINT_ACCEPTED']
        for i, event in enumerate(segment['events']):
            event.update(sequence=i + 1, elapsedNanos=i)
        self.assertEqual([], self.derive(value)['observedCases'])

    def test_direct_import_holds_cover_parse_and_store_not_just_balance(self):
        for target in ('PARSE_SUCCEEDED', 'GRAPH_STORE_ATTEMPT', 'GRAPH_STORE_IMPORTED'):
            for release in ('all', 'app', 'global', 'budget'):
                with self.subTest(target=target, release=release):
                    value = self.valid_direct()
                    self.promote_v2(value)
                    self.assertEqual(['direct-valid'], self.derive(value)['observedCases'])
                    def selected(event):
                        if release == 'all':
                            return event['kind'] in {'CONCURRENCY_RELEASED', 'BUDGET_RELEASED'}
                        if release == 'budget':
                            return event['kind'] == 'BUDGET_RELEASED'
                        return event['kind'] == 'CONCURRENCY_RELEASED' and event['scope'] == (3 if release == 'app' else 1)
                    self.move_before(value['segments'][0]['events'], selected, target)
                    self.assertEqual([], self.derive(value)['observedCases'])

    def test_uri_holds_cover_child_fetch_and_import_or_preview_stages(self):
        for preview in (False, True):
            for opid, target in ((2, 'FETCH_INVOKED'), (2, 'FETCH_SUCCEEDED'),
                                (2, 'PARSE_SUCCEEDED'),
                                (2, 'PREVIEW_BUILT' if preview else 'GRAPH_STORE_IMPORTED'),
                                (3, 'FETCH_INVOKED'), (3, 'FETCH_SUCCEEDED')):
                for scope in (1, 3, None):
                    with self.subTest(preview=preview, opid=opid, target=target, scope=scope):
                        value = self.valid_uri(preview)
                        self.assertEqual([value['segments'][0]['caseId']], self.derive(value)['observedCases'])
                        self.move_before(value['segments'][0]['events'],
                            lambda event: event['operationId'] == opid and (
                                event['kind'] == 'BUDGET_RELEASED' if scope is None else
                                event['kind'] == 'CONCURRENCY_RELEASED' and event['scope'] == scope), target)
                        self.assertEqual([], self.derive(value)['observedCases'])

    def test_shared_fetch_holds_cover_completion_for_each_family(self):
        for subscription in (False, True):
            baseline = self.interference(subscription)
            self.promote_v2(baseline)
            releases = [event for event in baseline['segments'][0]['events']
                        if event['operationId'] == 1 and event['kind'] == 'CONCURRENCY_RELEASED']
            for release in releases:
                with self.subTest(subscription=subscription, family=release['operation'], scope=release['scope']):
                    value = copy.deepcopy(baseline)
                    self.assertEqual([value['segments'][0]['caseId']], self.derive(value)['observedCases'])
                    self.move_before(value['segments'][0]['events'], lambda event: event == release, 'FETCH_SUCCEEDED')
                    self.assertEqual([], self.derive(value)['observedCases'])

    def test_late_acquisition_cannot_be_hidden_by_balanced_release(self):
        for uri in (False, True):
            value = self.valid_uri() if uri else self.valid_direct()
            if not uri:
                self.promote_v2(value)
            for scope in (1, 3):
                with self.subTest(uri=uri, scope=scope):
                    changed = copy.deepcopy(value)
                    self.move_before(changed['segments'][0]['events'],
                        lambda event: event['kind'] == 'CONCURRENCY_HELD'
                            and event['operationId'] == (3 if uri else 2) and event['scope'] == scope,
                        'FETCH_SUCCEEDED' if uri else 'GRAPH_STORE_ATTEMPT')
                    self.assertEqual([], self.derive(changed)['observedCases'])

    def test_preview_and_parse_failure_still_require_import_capacity(self):
        for preview in (False, True):
            value = self.valid_direct()
            segment = value['segments'][0]
            segment['caseId'] = 'pasted-preview-valid' if preview else 'direct-malformed'
            segment['graphAfter'] = {'retainedStatements': 0}
            segment['events'] = [event for event in segment['events']
                                 if not event['kind'].startswith('GRAPH_STORE_')]
            target = 'PREVIEW_BUILT' if preview else 'PARSE_FAILED'
            for index, event in enumerate(segment['events']):
                event.update(sequence=index + 1, elapsedNanos=index)
                if event['kind'] == 'PARSE_SUCCEEDED':
                    event['kind'] = target
            if preview:
                segment['events'][0]['kind'] = 'COMPOSED_PASTED_PREVIEW_START'
            else:
                segment['events'][-1]['kind'] = 'REQUEST_FAILED'
            self.promote_v2(value)
            with self.subTest(preview=preview):
                self.assertEqual([segment['caseId']], self.derive(value)['observedCases'])
                self.move_before(segment['events'], lambda event: event['kind'] in
                    {'CONCURRENCY_RELEASED', 'BUDGET_RELEASED'}, target)
                self.assertEqual([], self.derive(value)['observedCases'])

    def test_import_reservation_stays_held_through_child_admission_denial(self):
        value = self.interference()
        self.promote_v2(value)
        self.assertEqual(['shared-foreground'], self.derive(value)['observedCases'])
        self.move_before(value['segments'][0]['events'], lambda event:
            event['operationId'] == 11 and event['kind'] in
            {'RATE_RESERVATION_RELEASED', 'CONCURRENCY_RELEASED', 'BUDGET_RELEASED'},
            'RATE_LIMIT_REACHED')
        self.assertEqual([], self.derive(value)['observedCases'])

    def test_native_direct_accounting_and_independent_snapshots(self):
        value = self.valid_direct()
        self.assertEqual(['direct-valid'], self.derive(value)['observedCases'])
        value['segments'][0]['afterRates'][0]['count'] = 2
        self.assertEqual([], self.derive(value)['observedCases'])

    def test_rebound_case_wrong_terminal_parent_and_store_result_are_incomplete(self):
        for alteration in ('case', 'terminal', 'parent', 'store', 'sequence', 'canary'):
            value = self.valid_direct()
            segment = value['segments'][0]
            if alteration == 'case':
                segment['caseId'] = 'direct-malformed'
            elif alteration == 'terminal':
                segment['events'][-1]['kind'] = 'REQUEST_FAILED'
            elif alteration == 'parent':
                segment['events'][1]['value'] = 3
            elif alteration == 'store':
                segment['graphAfter']['retainedStatements'] = 0
            elif alteration == 'sequence':
                segment['events'][-1]['sequence'] = 1
            else:
                segment['events'][0]['uri'] = 'PRIVATE_CANARY'
            with self.subTest(alteration=alteration):
                if alteration in {'sequence', 'canary'}:
                    with self.assertRaises(owner.ComposedEvidenceError):
                        self.derive(value)
                else:
                    self.assertEqual([], self.derive(value)['observedCases'])

    def test_pressure_v2_is_explicit_and_v1_rejects_new_vocabulary(self):
        from cryptad_certification.tests.test_runtime_pressure_evidence import evidence_fixture
        value = evidence_fixture()
        value['workEvents'][0]['kind'] = 'COMPOSED_URI_IMPORT_START'
        with self.assertRaises(pressure.RuntimeEvidenceError):
            pressure.validate(value, workload_digest=value['workloadDigest'])
        value.update(schemaVersion=2, collectorEpoch='12345678-1234-1234-1234-123456789012')
        pressure.validate(value, workload_digest=value['workloadDigest'])
        value['collectorEpoch'] = 'PRIVATE_CANARY'
        with self.assertRaises(pressure.RuntimeEvidenceError):
            pressure.validate(value, workload_digest=value['workloadDigest'])

    def test_valid_complete_empty_before_store_is_zero_but_unavailable_is_unknown(self):
        value = self.valid_direct()
        value['segments'][0]['beforeRates'] = []
        self.assertEqual(['direct-valid'], self.derive(value)['observedCases'])
        value['segments'][0]['budgetValid'] = False
        self.assertEqual([], self.derive(value)['observedCases'])

    def test_epoch_local_identifier_reuse_cannot_substitute_same_epoch_sequence(self):
        value = self.valid_direct()
        other = copy.deepcopy(value['segments'][0])
        other['operationId'] = 9
        other['events'][0]['value'] = 7
        value['segments'].append(other)
        with self.assertRaises(owner.ComposedEvidenceError):
            self.derive(value)

    def test_authenticated_capability_denial_requires_native_start_and_unchanged_state(self):
        value = self.valid_direct()
        segment = value['segments'][0]
        segment['caseId'] = 'authorization-denied'
        start = segment['events'][0]
        segment['events'] = [dict(start, sequence=index + 1, elapsedNanos=index, kind=kind)
            for index, kind in enumerate(('COMPOSED_URI_IMPORT_START', 'CAPABILITY_DENIED', 'REQUEST_FAILED'))]
        segment['afterRates'] = copy.deepcopy(segment['beforeRates'])
        segment['graphAfter'] = copy.deepcopy(segment['graphBefore'])
        self.assertEqual(['authorization-denied'], self.derive(value)['observedCases'])
        segment['events'].pop(0)
        self.assertEqual([], self.derive(value)['observedCases'])

    def test_rate_denial_requires_actual_family_not_requested_operation_or_case_label(self):
        value = self.valid_direct()
        segment = value['segments'][0]
        segment['caseId'] = 'global-import-rate'
        template = segment['events'][0]
        specifications = [
            ('COMPOSED_URI_IMPORT_START', 1, None, 2, 0, 0),
            ('COMPOSED_CHILD', 2, None, 2, 1, 0),
            ('BUDGET_RESERVE', 2, 'trust_graph_import', 2, 0, 0),
            ('RATE_LIMIT_REACHED', 2, 'trust_graph_import', 1, 1, 1789387200),
            ('BUDGET_RATE_DENIED', 2, 'trust_graph_import', 2, 0, 0),
            ('REQUEST_FAILED', 1, None, 2, 0, 0)]
        segment['events'] = [dict(template, sequence=index+1, elapsedNanos=index,
            kind=kind, operationId=opid, operation=family, scope=scope, value=count,
            windowStartEpochSecond=window)
            for index, (kind, opid, family, scope, count, window) in enumerate(specifications)]
        segment['beforeRates'][1]['count'] = 1
        segment['afterRates'] = copy.deepcopy(segment['beforeRates'])
        segment['graphAfter'] = copy.deepcopy(segment['graphBefore'])
        self.assertEqual(['global-import-rate'], self.derive(value)['observedCases'])
        segment['caseId'] = 'app-import-rate'
        self.assertEqual([], self.derive(value)['observedCases'])
        segment['caseId'] = 'global-import-rate'
        segment['events'][3]['kind'] = 'BUDGET_CHECK'
        self.assertEqual([], self.derive(value)['observedCases'])

    def interference(self, subscription=False):
        value = self.attachment()
        events = []
        window = 1789387200
        def record(kind, opid, family=None, scope=2, count=0, rate=False):
            events.append(dict(sequence=len(events)+1, observedAt='2026-09-14T12:00:00Z',
                elapsedNanos=len(events), kind=kind, operation=family, operationId=opid,
                scope=scope, value=count, windowStartEpochSecond=window if rate else 0,
                sourceEpoch=None, sourceSequence=0, sourceSampledAtEpochMillis=0))
        families = [('subscription_poll', 2), ('subscription_poll', 1), ('content_fetch_global', 1)] if subscription else [('foreground_content_fetch', 2), ('content_fetch_global', 1)]
        count = 1 if subscription else 2
        for opid in range(1, count+1):
            operation = 'subscription_manual_refresh' if subscription else 'foreground_content_fetch'
            record('BUDGET_RESERVE' if subscription else 'BUDGET_ACQUIRE', opid, operation)
            for family, scope in families:
                if subscription:
                    record('RATE_RESERVED', opid, family, scope, rate=True)
                    record('RATE_RESERVATION_RELEASED', opid, family, scope, rate=True)
                record('RATE_OBSERVED', opid, family, scope, opid-1, True)
                record('RATE_CHARGED', opid, family, scope, opid, True)
                record('CONCURRENCY_HELD', opid, family, scope)
            record('BUDGET_COMMITTED', opid, operation)
            record('FETCH_INVOKED', opid, operation)
            record('FETCH_SUCCEEDED', opid, operation)
            for family, scope in families:
                record('CONCURRENCY_RELEASED', opid, family, scope)
            record('BUDGET_RELEASED', opid, operation)
        record('COMPOSED_URI_IMPORT_START', 10)
        record('COMPOSED_CHILD', 11, count=10)
        record('BUDGET_RESERVE', 11, 'trust_graph_import')
        for scope in (2, 1):
            record('RATE_RESERVED', 11, 'trust_graph_import', scope, rate=True)
            record('CONCURRENCY_HELD', 11, 'trust_graph_import', scope)
        record('BUDGET_RESERVED', 11, 'trust_graph_import')
        record('COMPOSED_CHILD', 12, count=10)
        record('BUDGET_ACQUIRE', 12, 'trust_graph_import_uri')
        record('RATE_LIMIT_REACHED', 12, 'content_fetch_global' if subscription else 'foreground_content_fetch',
               1 if subscription else 2, count, True)
        record('BUDGET_RATE_DENIED', 12, 'trust_graph_import_uri')
        for scope in (2, 1):
            record('RATE_RESERVATION_RELEASED', 11, 'trust_graph_import', scope, rate=True)
            record('CONCURRENCY_RELEASED', 11, 'trust_graph_import', scope)
        record('BUDGET_RELEASED', 11, 'trust_graph_import')
        record('REQUEST_FAILED', 10)
        value['segments'] = [dict(caseId='shared-subscription' if subscription else 'shared-foreground',
            collectorEpoch='12345678-1234-1234-1234-123456789012', operationId=1, scope=2,
            budgetValid=True, droppedEvents=0, events=events, beforeRates=[],
            afterRates=[dict(operation=family, scope=scope, windowStartEpochSecond=window, count=count)
                        for family, scope in families], graphBefore={'retainedStatements': 0},
            graphAfter={'retainedStatements': 0})]
        return value

    def test_shared_owners_require_actual_fetch_accounting_and_uri_denial(self):
        for subscription in (False, True):
            with self.subTest(subscription=subscription):
                value = self.interference(subscription)
                expected = 'shared-subscription' if subscription else 'shared-foreground'
                self.assertEqual([expected], self.derive(value)['observedCases'])
                event = next(event for event in value['segments'][0]['events'] if event['kind'] == 'FETCH_SUCCEEDED')
                event['kind'] = 'FETCH_FAILED'
                self.assertEqual([], self.derive(value)['observedCases'])

    def test_original_process_binding_rejects_legacy_mixed_or_rebound_epoch(self):
        value = self.valid_direct()
        bindings = dict(workload_digest=value['workloadDigest'], product_digest=value['productDigest'],
            source_commit=value['sourceCommit'], app_cohort_digest=value['appCohortDigest'], node_epoch='a' * 32,
            collector_digest=value['collectorDigest'], configuration_digest=value['configurationDigest'])
        with self.assertRaises(owner.ComposedEvidenceError):
            owner.derive(value, **bindings)
        self.promote_v2(value)
        self.assertEqual(['direct-valid'], owner.derive(value, **bindings)['observedCases'])
        value['segments'][0]['collectorEpoch'] = '87654321-4321-4321-4321-210987654321'
        with self.assertRaises(owner.ComposedEvidenceError):
            owner.derive(value, **bindings)
        value['segments'][0]['collectorEpoch'] = value['collectorEpoch']
        value['nodeEpoch'] = 'b' * 32
        with self.assertRaises(owner.ComposedEvidenceError):
            owner.derive(value, **bindings)

    def test_journal_union_checks_each_original_process_and_rejects_epoch_reuse(self):
        value = self.valid_direct()
        self.promote_v2(value)
        # Product roster digest comes from independently selected original plan, not this attachment.
        app_roster = ['sha256:' + '4' * 64]
        value['appCohortDigest'] = pressure.baseline.digest(app_roster)
        plan = dict(composedBudgetInputs={key: value[key] for key in ('collectorDigest', 'configurationDigest')},
            workloadInputs={'scheduler': value['workloadDigest']}, nodes=[dict(role='candidate-sender',
            artifactDigest=value['productDigest'], sourceCommit=value['sourceCommit'], appDigests=app_roster)])
        event = dict(role='candidate-sender', nodeEpoch='a' * 32, wallTime='2026-09-14T12:00:01Z',
                     composedBudgetEvidence=value)
        self.assertEqual(['direct-valid'], owner.derive_journal(plan, [event])['observedCases'])
        with self.assertRaises(owner.ComposedEvidenceError):
            owner.derive_journal(plan, [event, copy.deepcopy(event)])
        rebound = copy.deepcopy(event)
        rebound['nodeEpoch'] = 'b' * 32
        with self.assertRaises(owner.ComposedEvidenceError):
            owner.derive_journal(plan, [rebound])

    def test_unexplained_new_family_or_removed_family_cannot_hide_in_complete_snapshot(self):
        for shared in (False, True):
            value = self.interference() if shared else self.valid_direct()
            value['segments'][0]['afterRates'].append(dict(operation='subscription_poll', scope=9,
                windowStartEpochSecond=1789387200, count=3))
            self.assertEqual([], self.derive(value)['observedCases'])
        value = self.valid_direct()
        value['segments'][0]['beforeRates'].append(dict(operation='subscription_poll', scope=9,
            windowStartEpochSecond=1789387200, count=3))
        self.assertEqual([], self.derive(value)['observedCases'])

    def test_future_rate_window_cannot_be_rebound_to_current_observation(self):
        value = self.valid_direct()
        for event in value['segments'][0]['events']:
            if event['windowStartEpochSecond']:
                event['windowStartEpochSecond'] += 86400
        with self.assertRaises(owner.ComposedEvidenceError):
            self.derive(value)

    def test_original_collector_and_configuration_require_independent_expected_inputs(self):
        value = self.valid_direct()
        self.promote_v2(value)
        bindings = dict(workload_digest=value['workloadDigest'], product_digest=value['productDigest'],
            source_commit=value['sourceCommit'], app_cohort_digest=value['appCohortDigest'], node_epoch='a' * 32)
        with self.assertRaises(owner.ComposedEvidenceError):
            owner.derive(value, **bindings)
        bindings.update(collector_digest=value['collectorDigest'], configuration_digest=value['configurationDigest'])
        self.assertEqual(['direct-valid'], owner.derive(value, **bindings)['observedCases'])
        for key in ('collectorDigest', 'configurationDigest'):
            changed = copy.deepcopy(value)
            changed[key] = 'sha256:' + '9' * 64
            with self.subTest(key=key), self.assertRaises(owner.ComposedEvidenceError):
                owner.derive(changed, **bindings)

    def test_original_plan_input_binding_is_closed_and_historical_plan_is_unchanged(self):
        from cryptad_certification.cross_version_evidence import validate_plan, EvidenceError
        from cryptad_certification.tests.test_cross_version_evidence import fixture_plan
        plan = fixture_plan()
        validate_plan(plan)
        plan['workloadInputs'] = {'scheduler': 'sha256:' + '1' * 64}
        plan['composedBudgetInputs'] = {'collectorDigest': 'sha256:' + '5' * 64,
                                       'configurationDigest': 'sha256:' + '6' * 64}
        validate_plan(plan)
        plan['composedBudgetInputs']['scopeOverride'] = 'PRIVATE_CANARY'
        with self.assertRaises(EvidenceError):
            validate_plan(plan)

    def test_unknown_numeric_scope_cannot_masquerade_as_app_family(self):
        value = self.valid_direct()
        for event in value['segments'][0]['events']:
            if event['kind'].startswith(('RATE_', 'CONCURRENCY_')) and event['scope'] == 2:
                event['scope'] = 0
        for name in ('beforeRates', 'afterRates'):
            value['segments'][0][name][0]['scope'] = 0
        with self.assertRaises(owner.ComposedEvidenceError):
            self.derive(value)

    def test_v2_host_operator_segment_cannot_supply_app_principal_proof(self):
        value = self.valid_direct()
        # V1 local inputs retain their old opaque-scope semantics.
        self.assertEqual(['direct-valid'], self.derive(value)['observedCases'])
        value.update(schemaVersion=2, collectorEpoch=value['segments'][0]['collectorEpoch'], nodeEpoch='a' * 32)
        with self.assertRaises(owner.ComposedEvidenceError):
            self.derive(value)
        self.promote_v2(value)
        self.assertEqual(['direct-valid'], self.derive(value)['observedCases'])
        # Relabeling only the outer segment cannot turn authentic host events into app events.
        for event in value['segments'][0]['events']:
            if event['scope'] == 3:
                event['scope'] = 2
        self.assertEqual([], self.derive(value)['observedCases'])
