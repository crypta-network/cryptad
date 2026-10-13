"""Adversarial contract vectors plus separately identified actual Java producer exports."""
import copy
import json
from pathlib import Path
import unittest

from cryptad_certification import composed_budget_evidence as owner
from cryptad_certification import composed_budget_restart_evidence as restart
from cryptad_certification.tests.test_composed_budget_storage_evidence import Vector, stamp, W1


EPOCH_A = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
EPOCH_B = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'


def phase(vector, epoch, pid, *, scope=3, valid=True):
    scopes = [{'appId': '_cryptad_global', 'scope': 1},
              {'appId': '_cryptad_operator', 'scope': 2}, {'appId': 'selected-app', 'scope': scope}]
    usage = [dict(appId='selected-app' if s == scope else '_cryptad_global', operation=f,
                  windowStart=stamp(w), windowSeconds=3600 if f == 'trust_graph_import' else 60,
                  count=c, limit=32, lastDecisionAt=stamp(W1 + 1), lastDecision='allowed',
                  nextAvailableAt=None) for (f, s, w), c in vector.rates.items()]
    return dict(pid=pid, collectorEpoch=epoch, scopeBindings=scopes, graph=[],
        diagnostics=dict(valid=valid, observedAt=stamp(W1 + 2), usage=usage if valid else [],
            activeFamilyLeases=sum(v for k, v in vector.holds.items() if k[-1] == 'concurrency'),
            reservedFamilyRates=sum(v for k, v in vector.holds.items() if k[-1] == 'rate')),
        nativeSnapshot=dict(version=4, collectorEpoch=epoch, lastSequence=len(vector.events),
                            dropped=0, events=copy.deepcopy(vector.events)))


def process(variant='settled-graceful'):
    old = Vector()
    old.charge(1, 'trust_graph_import', 3, W1)
    old.charge(1, 'trust_graph_import', 1, W1)
    if variant == 'inflight-abrupt':
        old.event('COMPOSED_URI_IMPORT_START', 4)
        old.event('COMPOSED_CHILD', 2, value=4)
        old.event('BUDGET_RESERVE', 2, 'trust_graph_import')
        for scope in (3, 1):
            old.event('RATE_RESERVED', 2, 'trust_graph_import', scope, 1, W1)
        old.hold(2, [('trust_graph_import', 3), ('trust_graph_import', 1)])
        old.event('BUDGET_RESERVED', 2, 'trust_graph_import')
        old.event('COMPOSED_CHILD', 3, value=4)
        old.event('BUDGET_ACQUIRE', 3, 'trust_graph_import_uri')
        old.charge(3, 'foreground_content_fetch', 3, W1)
        old.charge(3, 'content_fetch_global', 1, W1)
        old.hold(3, [('foreground_content_fetch', 3), ('content_fetch_global', 1)])
        old.event('BUDGET_COMMITTED', 3, 'trust_graph_import_uri')
        old.event('FETCH_INVOKED', 3, 'trust_graph_import_uri')
    before = phase(old, EPOCH_A, 101)
    new = Vector()
    new.rates = {(family, 4 if scope == 3 else scope, window): count
                 for (family, scope, window), count in old.rates.items()}
    after = phase(new, EPOCH_B, 202, scope=4)
    new.charge(1, 'trust_graph_import', 4, W1)
    new.charge(1, 'trust_graph_import', 1, W1)
    new.event('BUDGET_COMMITTED', 1, 'trust_graph_import', 4)
    recovery = phase(new, EPOCH_B, 202, scope=4)
    graph = dict(document={'type': 'synthetic'}, documentFingerprint='a' * 64, payloadHash='b' * 64,
        signatureVerified=True, source='manual', sourceUri=None, sourceUriHash=None, sourceLabel=None,
        sourceUriKind=None, subscriptionId=None, importedAt=stamp(W1), updatedAt=stamp(W1))
    for observed in (before, after, recovery):
        observed['graph'] = [copy.deepcopy(graph)]
    return dict(schemaVersion=1, caseId='graceful-restart' if variant == 'settled-graceful' else 'abrupt-restart',
        variant=variant, evidenceClass=restart.PROCESS, before=before, after=after, recovery=recovery,
        transition=dict(kind='graceful' if variant == 'settled-graceful' else 'forced', oldPid=101,
            aliveBefore=True, exitCode=0 if variant == 'settled-graceful' else 137,
            deadBeforeRestart=True, newPid=202, forced=variant != 'settled-graceful'),
        dataIdentity={'fileKey': '(dev=1,ino=2)'},
        selectedFingerprint='a' * 64,
        pendingOperationIds=[2, 3] if variant == 'inflight-abrupt' else [],
        tailStatus='censored' if variant == 'inflight-abrupt' else 'complete')


def originals(raw):
    return {key: copy.deepcopy(raw[key]) for key in ('transition', 'dataIdentity', 'selectedFingerprint')} | {
        'scopeBindings': {name: copy.deepcopy(raw[name]['scopeBindings'])
                          for name in ('before', 'after', 'recovery')}}


def diagnostics(variant='enumeration-only'):
    vector = Vector()
    vector.charge(1, 'trust_graph_import', 3, W1)
    vector.charge(1, 'trust_graph_import', 1, W1)
    before = phase(vector, EPOCH_A, 101)
    vector.event('BUDGET_ACQUIRE', 2, 'trust_graph_import', 3)
    vector.event('STORE_UNAVAILABLE', 0, scope=0)
    if variant == 'enumeration-only':
        vector.charge(2, 'trust_graph_import', 3, W1)
        vector.charge(2, 'trust_graph_import', 1, W1)
        vector.event('BUDGET_COMMITTED', 2, 'trust_graph_import', 3)
    during = phase(vector, EPOCH_A, 101, valid=False)
    after = phase(vector, EPOCH_A, 101)
    vector.charge(3, 'trust_graph_import', 3, W1)
    vector.charge(3, 'trust_graph_import', 1, W1)
    vector.event('BUDGET_COMMITTED', 3, 'trust_graph_import', 3)
    recovery = phase(vector, EPOCH_A, 101)
    return dict(schemaVersion=1, caseId='diagnostics-unavailable', variant=variant,
        evidenceClass=restart.FILES, before=before, during=during, after=after, recovery=recovery,
        selectedFingerprint=None, requestStatus=503 if variant == 'required-key-unreadable' else 200,
        requestCode='network_budget_unavailable' if variant == 'required-key-unreadable' else None,
        recoveryStatus=200,
        fault=dict(kind=variant, targetAppId='selected-app',
            requiredKeyReadable=variant == 'enumeration-only', enumerationReadable=False,
            restored=True, contentsRestored=False))


class RestartEvidenceTests(unittest.TestCase):
    def test_scope_numbers_remap_by_app_and_operation_ids_restart(self):
        for variant in ('settled-graceful', 'settled-abrupt', 'inflight-abrupt'):
            raw = process(variant)
            with self.subTest(variant=variant):
                result = restart.derive_controlled(raw, originals=originals(raw))
                self.assertTrue(result['observed'])
                self.assertEqual('not-established', result['originalAuthentication'])
                self.assertEqual('not-observed', result['fullAppBudgets'])
                self.assertFalse(result['releaseEligible'])

    def test_case_requires_all_mandatory_variants(self):
        value = dict(restartCases=[process('settled-abrupt')], diagnosticsCases=[])
        self.assertEqual(set(), restart.derive_cases(value))
        value['restartCases'].append(process('inflight-abrupt'))
        self.assertEqual({'abrupt-restart'}, restart.derive_cases(value))
        value['restartCases'].append(process())
        value['diagnosticsCases'] = [diagnostics('enumeration-only'), diagnostics('required-key-unreadable')]
        for index, row in enumerate(value['restartCases'] + value['diagnosticsCases'], 1):
            for name in ('before', 'during', 'after', 'recovery'):
                if name in row:
                    observed = row[name]
                    epoch = str(index) * 8 + observed['collectorEpoch'][8:]
                    observed['collectorEpoch'] = observed['nativeSnapshot']['collectorEpoch'] = epoch
        self.assertEqual(set(restart.CASES), restart.derive_cases(value))
        self.assertEqual([], restart.derive_variants(value)['unobservedVariants'])

    def test_dead_owner_is_censored_without_synthetic_releases(self):
        raw = process('inflight-abrupt')
        result = restart.derive_controlled(raw)
        self.assertEqual('censored', result['tailStatus'])
        for change in (lambda r: r.update(tailStatus='complete'),
                       lambda r: r.update(pendingOperationIds=[]),
                       lambda r: r['before']['diagnostics'].update(activeFamilyLeases=0)):
            forged = copy.deepcopy(raw)
            change(forged)
            with self.assertRaises(owner.ComposedEvidenceError):
                restart.derive_controlled(forged)

    def test_reservation_only_prefix_cannot_credit_interrupted_owner(self):
        raw = process('inflight-abrupt')
        reservation = Vector()
        reservation.charge(1, 'trust_graph_import', 3, W1)
        reservation.charge(1, 'trust_graph_import', 1, W1)
        reservation.event('RATE_RESERVED', 2, 'trust_graph_import', 3, 1, W1)
        reservation.hold(2, [('trust_graph_import', 3), ('trust_graph_import', 1)])
        before = phase(reservation, EPOCH_A, 101)
        before['graph'] = raw['before']['graph']
        raw['before'] = before
        raw['pendingOperationIds'] = [2]
        for name in ('after', 'recovery'):
            raw[name]['diagnostics']['usage'] = [r for r in raw[name]['diagnostics']['usage']
                                                if r['operation'] == 'trust_graph_import']
        with self.assertRaisesRegex(owner.ComposedEvidenceError, 'inflight-owner-missing'):
            restart.derive_controlled(raw)
        with self.assertRaisesRegex(owner.ComposedEvidenceError, 'inflight-owner-missing'):
            restart.derive_cases(dict(restartCases=[process('settled-abrupt'), raw], diagnosticsCases=[]))

    def test_inflight_owner_requires_ordered_parent_links_and_fetch_admission(self):
        for kind, field, value in (
                ('COMPOSED_URI_IMPORT_START', 'kind', 'COMPOSED_DIRECT_IMPORT_START'),
                ('FETCH_INVOKED', 'kind', 'BUDGET_ACQUIRE'),
                ('FETCH_INVOKED', 'operationId', 2),
                ('FETCH_INVOKED', 'scope', 1),
                ('COMPOSED_CHILD', 'value', 99),
                ('BUDGET_RESERVED', 'kind', 'BUDGET_RESERVE'),
                ('BUDGET_COMMITTED', 'kind', 'BUDGET_ACQUIRE')):
            raw = process('inflight-abrupt')
            event = next(e for e in raw['before']['nativeSnapshot']['events'] if e['kind'] == kind)
            event[field] = value
            with self.subTest(kind=kind, field=field), self.assertRaisesRegex(
                    owner.ComposedEvidenceError, 'inflight-owner-missing'):
                restart.derive_controlled(raw)

    def test_terminal_owner_with_unreleased_holds_cannot_credit_inflight_variant(self):
        for kind, operation_id in (('REQUEST_SUCCEEDED', 4), ('REQUEST_FAILED', 4),
                                   ('FETCH_SUCCEEDED', 3), ('FETCH_FAILED', 3),
                                   ('FETCH_OWNER_TERMINATED', 3), ('BUDGET_RELEASED', 2)):
            raw = process('inflight-abrupt')
            snapshot = raw['before']['nativeSnapshot']
            event = copy.deepcopy(snapshot['events'][-1])
            event.update(kind=kind, operationId=operation_id, sequence=snapshot['lastSequence'] + 1,
                         elapsedNanos=event['elapsedNanos'] + 1000)
            snapshot['events'].append(event)
            snapshot['lastSequence'] += 1
            with self.subTest(kind=kind), self.assertRaisesRegex(
                    owner.ComposedEvidenceError, 'inflight-owner-missing'):
                restart.derive_controlled(raw)

    def test_inflight_links_holds_and_admission_must_precede_fetch_invocation(self):
        for first, second in (('COMPOSED_URI_IMPORT_START', 'COMPOSED_CHILD'),
                              ('BUDGET_RESERVED', 'FETCH_INVOKED'),
                              ('CONCURRENCY_HELD', 'BUDGET_RESERVED'),
                              ('BUDGET_COMMITTED', 'FETCH_INVOKED')):
            raw = process('inflight-abrupt')
            events = raw['before']['nativeSnapshot']['events']
            left = next(e for e in events if e['kind'] == first)
            right = next(e for e in events if e['kind'] == second)
            fields = ('kind', 'operationId', 'operation', 'scope', 'value', 'windowStartEpochSecond')
            left_values, right_values = {k: left[k] for k in fields}, {k: right[k] for k in fields}
            left.update(right_values)
            right.update(left_values)
            with self.subTest(first=first, second=second), self.assertRaisesRegex(
                    owner.ComposedEvidenceError, 'inflight-owner-missing'):
                restart.derive_controlled(raw)

    def test_import_and_fetch_holds_must_be_live_when_prefix_is_captured(self):
        for operation_id, family, scope, rate in (
                (2, 'trust_graph_import', 3, True), (2, 'trust_graph_import', 1, True),
                (2, 'trust_graph_import', 3, False), (2, 'trust_graph_import', 1, False),
                (3, 'foreground_content_fetch', 3, False), (3, 'content_fetch_global', 1, False)):
            raw = process('inflight-abrupt')
            snapshot = raw['before']['nativeSnapshot']
            event = copy.deepcopy(snapshot['events'][-1])
            event.update(kind='RATE_RESERVATION_RELEASED' if rate else 'CONCURRENCY_RELEASED',
                         operationId=operation_id, operation=family, scope=scope,
                         windowStartEpochSecond=W1 if rate else 0,
                         sequence=snapshot['lastSequence'] + 1, elapsedNanos=event['elapsedNanos'] + 1000)
            snapshot['events'].append(event)
            snapshot['lastSequence'] += 1
            raw['before']['diagnostics']['reservedFamilyRates' if rate else 'activeFamilyLeases'] -= 1
            with self.subTest(family=family, scope=scope, rate=rate), self.assertRaisesRegex(
                    owner.ComposedEvidenceError, 'inflight-owner-missing'):
                restart.derive_controlled(raw)

    def test_original_wrong_stop_or_scope_cannot_authenticate_self_consistent_guest(self):
        raw = process('settled-abrupt')
        for change in (lambda o: o['transition'].update(oldPid=999),
                       lambda o: o['dataIdentity'].update(fileKey='other'),
                       lambda o: o['scopeBindings']['after'][-1].update(appId='other-app')):
            actual = originals(raw)
            change(actual)
            with self.assertRaises(owner.ComposedEvidenceError):
                restart.derive_controlled(raw, originals=actual)

    def test_restart_loss_escalation_or_old_survival_rejected(self):
        for change in (lambda r: r['transition'].update(forced=True),
                       lambda r: r['transition'].update(exitCode=137),
                       lambda r: r['transition'].update(deadBeforeRestart=False),
                       lambda r: r['after']['diagnostics']['usage'].pop(),
                       lambda r: r['after']['diagnostics']['usage'][0].update(count=0),
                       lambda r: r['after']['diagnostics']['usage'][0].update(lastDecision='rate_limited'),
                       lambda r: r['after'].update(collectorEpoch=EPOCH_A)):
            raw = process()
            change(raw)
            with self.assertRaises(owner.ComposedEvidenceError):
                restart.derive_controlled(raw)

    def test_later_valid_diagnostics_do_not_erase_invalid_interval(self):
        raw = diagnostics()
        self.assertTrue(restart.derive_controlled(raw)['observed'])
        self.assertFalse(raw['during']['diagnostics']['valid'])
        for change in (lambda r: r['during']['diagnostics'].update(valid=True),
                       lambda r: r['during']['diagnostics'].update(usage=r['before']['diagnostics']['usage']),
                       lambda r: r['fault'].update(restored=False),
                       lambda r: r['fault'].update(contentsRestored=True),
                       lambda r: r['fault'].update(requiredKeyReadable=False),
                       lambda r: r['during'].update(nativeSnapshot=None)):
            forged = copy.deepcopy(raw)
            change(forged)
            with self.assertRaises(owner.ComposedEvidenceError):
                restart.derive_controlled(forged)

    def test_unreadable_key_is_distinct_from_enumeration_only(self):
        raw = diagnostics('required-key-unreadable')
        self.assertTrue(restart.derive_controlled(raw)['observed'])
        raw['variant'] = raw['fault']['kind'] = 'enumeration-only'
        raw['fault']['requiredKeyReadable'] = True
        with self.assertRaises(owner.ComposedEvidenceError):
            restart.derive_controlled(raw)

    def test_free_recovery_unexplained_metadata_and_private_claims_rejected(self):
        for change in (lambda r: r['recovery']['diagnostics'].update(usage=r['after']['diagnostics']['usage']),
                       lambda r: r['recovery']['diagnostics']['usage'][0].update(limit=99),
                       lambda r: r.update(passed=True),
                       lambda r: r.update(session='PRIVATE_CANARY')):
            raw = process()
            change(raw)
            with self.assertRaises(owner.ComposedEvidenceError):
                restart.derive_controlled(raw)

    def test_actual_java_process_exports_reach_reader(self):
        root = Path(__file__).resolve().parents[4]
        directory = root / 'platform-api/build/test-results/pr319-native'
        expected = {'settled-graceful': ('graceful-restart', 'complete'),
                    'settled-abrupt': ('abrupt-restart', 'complete'),
                    'inflight-abrupt': ('abrupt-restart', 'censored')}
        if not any((directory / (variant + '.json')).is_file() for variant in expected):
            self.skipTest('actual Java PR319 producer exports not executed in this checkout')
        for variant, (case, tail) in expected.items():
            with self.subTest(variant=variant):
                raw = json.loads((directory / (variant + '.json')).read_bytes())
                actual = json.loads((directory / (variant + '-original.json')).read_bytes())
                result = restart.derive_controlled(raw, originals=actual)
                self.assertEqual((case, variant, True, tail),
                    (result['caseId'], result['variant'], result['observed'], result['tailStatus']))
                self.assertFalse(result['installedObservation'])

    def test_actual_java_diagnostics_exports_reach_reader(self):
        root = Path(__file__).resolve().parents[4]
        directory = root / 'platform-api/build/test-results/pr319-native'
        expected = ('enumeration-only', 'required-key-unreadable', 'malformed-record',
                    'identity-mismatch', 'special-member', 'bounded-exhaustion')
        if not any((directory / (variant + '.json')).is_file() for variant in expected):
            self.skipTest('actual Java PR319 diagnostic producer exports not executed in this checkout')
        for variant in expected:
            with self.subTest(variant=variant):
                raw = json.loads((directory / (variant + '.json')).read_bytes())
                actual = json.loads((directory / (variant + '-original.json')).read_bytes())
                result = restart.derive_controlled(raw, originals=actual)
                self.assertEqual(('diagnostics-unavailable', variant, True, 'complete'),
                    (result['caseId'], result['variant'], result['observed'], result['tailStatus']))
                self.assertTrue(result['originalWitnessMatched'])
                self.assertFalse(result['installedObservation'])
                self.assertEqual('not-observed', result['fullAppBudgets'])
                self.assertFalse(result['releaseEligible'])


if __name__ == '__main__':
    unittest.main()
