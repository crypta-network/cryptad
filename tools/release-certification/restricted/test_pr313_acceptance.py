"""Synthetic verifier tests, not installed execution or original authority."""
import copy
import json
import os
import unittest

import pr313_acceptance as acceptance


def synthetic_identity():
    return {key: 'a' * (40 if key.endswith(('Commit', 'Tree')) else 64)
            for key in acceptance.IDENTITY_FIELDS}


def synthetic_consumer_phases():
    phases = []
    for index, name in enumerate(acceptance.CONSUMER_PHASES):
        invocations = [dict(managerInvocationId=f'{index * 10 + 1:032x}', operation='package-api',
                            stdoutDigest='b' * 64, appId=None)]
        invocations += [dict(managerInvocationId=f'{index * 10 + number + 2:032x}',
            operation='app-projection', stdoutDigest='c' * 64, appId=app)
            for number, app in enumerate(sorted(acceptance.CONSUMER_APPS))]
        phases.append(dict(phase=name, operationId=f'{index + 1:064x}',
            startedMonotonicNs=index * 3 + 1, finishedMonotonicNs=index * 3 + 3,
            invocations=invocations, quiescent=dict(activeState='inactive',
                cgroupPopulated=False, activeRecordPresent=False)))
    return phases


def synthetic_observation(name, identity):
    """A complete isolated synthetic record; never exported as an installed result."""
    case = acceptance.CASES[name]
    kind = case.witness
    digest = 'b' * 64
    if kind == 'reference':
        witness = dict(storageFormat='qcow2', backingFiles=[], externalDataFiles=[],
            bootClosureDigest=identity['bootClosureDigest'], preparedImageDigest=identity['preparedImageDigest'],
            snapshotVerified='exact-private-copy')
    elif kind == 'installation':
        witness = {key: identity[key] for key in ('bundleIdentity', 'testKitDigest', 'profileDigest')}
        witness['testKitLocation'] = 'separate-administrator-owned'
    elif kind == 'readiness':
        witness = dict(Type='notify', NotifyAccess='main', ActiveState='active', SubState='running', MainPID=42)
    elif kind == 'socket':
        witness = dict(peerClass='wrong-uid' if name == 'socket-wrong-uid' else 'runner',
                       exitCode=0 if name == 'socket-wrong-uid' else 2, stdoutBytes=0,
                       stderrClassification='dac-permission-denied' if name == 'socket-wrong-uid'
                       else 'restricted-operation-unavailable')
    elif kind in ('owner', 'native'):
        witness = dict(operation=case.operation, operationMarker=name, ownerOutcome=case.outcome,
                       stdoutDigest=digest, startedMonotonicNs=1, finishedMonotonicNs=2)
    elif kind == 'mutation':
        mutation = name.split('-', 1)[1]
        before = dict(dev=1, ino=2, size=32, nlink=1)
        after = dict(before)
        if mutation in ('inode', 'ancestor', 'symlink'):
            after['ino'] = 3
        elif mutation == 'hardlink':
            after['nlink'] = 2
        else:
            after['size'] = 16 if mutation == 'truncation' else 64
        witness = dict(mutation=mutation, barrier='source-opened' if name.startswith('input-') else 'output-opened', before=before, after=after)
    elif kind == 'canary':
        witness = dict(controlResponseDigest='sha256:' + digest, expectedCanaryDigest='sha256:' + digest, serverPidStartTime=99,
                       controlBefore='retrieved', controlAfter='retrieved', nativeRetrievals=0,
                       distinctServerUid=65534, marker='pr313-active-sibling-denied')
    elif kind == 'revocation':
        witness = dict(registrationDigest='sha256:' + digest, revokedDigest='sha256:' + 'c' * 64, candidateMarker='candidate-started',
                       revocationObserved='restricted-operation-revoked')
    elif kind == 'worker-running-revocation':
        witness = dict(registrationDigest='sha256:' + digest, revokedDigest='sha256:' + 'c' * 64,
                       revocationObserved='restricted-operation-revoked', nativeProcess='java', retryAndCollect='revoked')
    elif kind == 'worker-death':
        witness = dict(controllerStartTime=99, signal='SIGKILL', durableDigestBefore='sha256:' + digest,
                       durableDigestAfter='sha256:' + digest, nativeRetryLaunches=0)
    elif kind == 'worker-completed-revocation':
        witness = dict(controllerStartTime=99, signal='SIGKILL', durableDigestBefore='sha256:' + digest,
                       durableDigestAfter='sha256:' + digest, nativeRetryLaunches=0,
                       registrationDigest='sha256:' + digest, revokedDigest='sha256:' + 'c' * 64,
                       retryAndCollect='revoked')
    elif kind == 'death':
        witness = dict(pidStartTime=99, signal='SIGKILL', durablePhase=case.phase,
                       retryError='restricted-native-execution-failed',
                       nativeLaunchCount=0 if name == 'death-active' else 1,
                       activeRecordDigestBefore='sha256:' + digest, activeRecordDigestAfter='sha256:' + digest)
    elif kind == 'retry':
        witness = dict(retainedDigest=digest, responseDigest=digest, nativeLaunchCountBefore=1,
                       nativeLaunchCountAfter=1, decryptCountBefore=1, decryptCountAfter=1, durablePhase=case.phase)
    elif kind == 'semantic-public':
        witness = dict(candidateOutput='collected', semanticOwner='rejected', publicFields='closed',
                       privateCanary='absent', candidateOutputDigest='sha256:' + digest, stdoutDigest='sha256:' + 'c' * 64)
    else:
        witness = dict(candidateOutputDigest='sha256:' + digest, clientResponseDigest='sha256:' + 'c' * 64,
                       semanticOwner='rejected', workerResultPresent=False,
                       publicArtifactNames=['client.log', 'report.json', 'summary.md'],
                       privateCanary='absent', failedArtifacts='private-only')
    if name == 'product-selection-native-consumers':
        witness['consumerPhases'] = synthetic_consumer_phases()
        witness['finishedMonotonicNs'] = 10
    native = kind not in ('reference', 'installation', 'readiness', 'socket') and name not in ('death-active', 'completed-revocation-retry') and not name.startswith(('input-', 'worker-death-'))
    return dict(caseId=name, phase=case.phase, outcome=case.outcome,
                managerInvocationId=(witness['consumerPhases'][-1]['invocations'][0]['managerInvocationId']
                    if name == 'product-selection-native-consumers' else 'd' * 32 if native else None),
                attackWitness=witness,
                quiescent=dict(activeState='inactive', cgroupPopulated=False,
                               activeRecordPresent=case.cleanup == 'owned-stop-and-retained-active'))


def synthetic_attempt():
    identity = synthetic_identity()
    return dict(contract=acceptance.CONTRACT, identity=identity,
                declaredCases=list(acceptance.CASES), guestStopped=True, attemptCompleted=True,
                observations=[synthetic_observation(name, identity) for name in acceptance.CASES])


class FiniteAcceptanceTest(unittest.TestCase):
    def evaluate(self, attempt):
        return acceptance.verify_attempts(synthetic_identity(), [attempt])

    def test_complete_synthetic_evidence_has_reachable_narrow_positive(self):
        # Transported JSON is supported after the host independently verifies identity/SSH.
        result = self.evaluate(json.loads(json.dumps(synthetic_attempt())))
        self.assertTrue(result['installedKeylessNativeAcceptanceSatisfied'])
        self.assertTrue(all(row['status'] == 'passed' for row in result['cases']))
        self.assertFalse(result['mandatoryIsolationTestSatisfied'])
        self.assertFalse(result['productionAuthorityObserved'])
        self.assertFalse(result['phase12Complete'])

    def test_consumers_require_all_three_independent_bounded_owner_windows(self):
        identity = synthetic_identity()
        original = synthetic_observation('product-selection-native-consumers', identity)
        self.assertEqual('passed', acceptance.observation_status(original, identity))
        mutations = {
            'borrow-worker-binding': lambda row: row['attackWitness'].pop('consumerPhases'),
            'missing-phase': lambda row: row['attackWitness']['consumerPhases'].pop(),
            'wrong-phase': lambda row: row['attackWitness']['consumerPhases'][0].update(phase='worker-cms'),
            'reused-owner': lambda row: row['attackWitness']['consumerPhases'][1].update(operationId='1'.zfill(64)),
            'reused-manager': lambda row: row['attackWitness']['consumerPhases'][1]['invocations'][0].update(
                managerInvocationId='1'.zfill(32)),
            'earlier-manager': lambda row: row.update(managerInvocationId='1'.zfill(32)),
            'earlier-output': lambda row: row['attackWitness'].update(stdoutDigest='e' * 64),
            'missing-app': lambda row: row['attackWitness']['consumerPhases'][0]['invocations'].pop(),
            'wrong-app': lambda row: row['attackWitness']['consumerPhases'][1]['invocations'][1].update(appId='external-app'),
            'duplicate-app': lambda row: row['attackWitness']['consumerPhases'][1]['invocations'][1].update(
                appId=row['attackWitness']['consumerPhases'][1]['invocations'][2]['appId']),
            'wrong-operation': lambda row: row['attackWitness']['consumerPhases'][1]['invocations'][0].update(operation='probe'),
            'overlapping-windows': lambda row: row['attackWitness']['consumerPhases'][1].update(startedMonotonicNs=2),
            'outside-owner-window': lambda row: row['attackWitness']['consumerPhases'][2].update(finishedMonotonicNs=11),
            'running-cgroup': lambda row: row['attackWitness']['consumerPhases'][2]['quiescent'].update(cgroupPopulated=True),
            'private-extra': lambda row: row['attackWitness']['consumerPhases'][0].update(private='PRIVATE-CANARY'),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(original)
                mutate(changed)
                self.assertEqual('inconclusive', acceptance.observation_status(changed, identity))
                attempt = synthetic_attempt()
                attempt['observations'] = [changed if row['caseId'] == changed['caseId'] else row
                                           for row in attempt['observations']]
                result = self.evaluate(attempt)
                self.assertFalse(result['installedKeylessNativeAcceptanceSatisfied'])
                self.assertNotIn('PRIVATE-CANARY', json.dumps(result))

    def test_consumer_owner_budget_is_bounded_per_phase(self):
        record = synthetic_observation('product-selection-native-consumers', synthetic_identity())
        for index, phase in enumerate(record['attackWitness']['consumerPhases']):
            phase.update(startedMonotonicNs=1 + index * 901_000_000_000,
                         finishedMonotonicNs=1 + index * 901_000_000_000 + 900_000_000_000)
        record['attackWitness']['finishedMonotonicNs'] = 2_703_000_000_000
        self.assertEqual('passed', acceptance.observation_status(record, synthetic_identity()))
        record['attackWitness']['consumerPhases'][0]['finishedMonotonicNs'] += 1
        self.assertEqual('inconclusive', acceptance.observation_status(record, synthetic_identity()))

    def test_every_required_case_remains_required_and_visible(self):
        for name in acceptance.CASES:
            with self.subTest(case=name):
                attempt = synthetic_attempt()
                attempt['declaredCases'].remove(name)
                attempt['observations'] = [row for row in attempt['observations'] if row['caseId'] != name]
                result = self.evaluate(attempt)
                self.assertFalse(result['installedKeylessNativeAcceptanceSatisfied'])
                self.assertEqual(len(acceptance.CASES), len(result['cases']))
                self.assertEqual('not-executed', next(row['status'] for row in result['cases'] if row['caseId'] == name))

    def test_no_failure_status_can_be_counted_as_successful_denial(self):
        for status in acceptance.STATUSES - {'passed'}:
            attempt = synthetic_attempt()
            attempt['observations'][6] = dict(caseId=attempt['declaredCases'][6], status=status)
            result = self.evaluate(attempt)
            self.assertFalse(result['installedKeylessNativeAcceptanceSatisfied'])
            self.assertEqual(status, result['cases'][6]['status'])

    def test_forged_passed_boolean_or_legacy_dimensions_are_not_evidence(self):
        for record in ({'caseId': 'package-api', 'passed': True},
                       {'caseId': 'package-api', 'status': 'passed'},
                       {'installedKeylessNativeAcceptanceSatisfied': True, 'dimensions': list(acceptance.CASES)}):
            attempt = synthetic_attempt()
            attempt['observations'][6] = record
            self.assertFalse(self.evaluate(attempt)['installedKeylessNativeAcceptanceSatisfied'])

    def test_terminal_driver_failure_rejects_even_complete_causal_rows_and_stopped_guest(self):
        attempt = synthetic_attempt()
        attempt['attemptCompleted'] = False
        result = self.evaluate(attempt)
        self.assertFalse(result['installedKeylessNativeAcceptanceSatisfied'])
        self.assertFalse(result['recordContractValid'])
        self.assertTrue(attempt['guestStopped'])

    def test_identity_drift_and_unstopped_guest_reject_even_complete_rows(self):
        for key in acceptance.IDENTITY_FIELDS:
            attempt = synthetic_attempt()
            attempt['identity'][key] = 'e' * len(attempt['identity'][key])
            self.assertFalse(self.evaluate(attempt)['installedKeylessNativeAcceptanceSatisfied'])
        attempt = synthetic_attempt()
        attempt['guestStopped'] = False
        self.assertFalse(self.evaluate(attempt)['installedKeylessNativeAcceptanceSatisfied'])

    def test_every_witness_is_needed_and_private_extra_fields_are_rejected(self):
        for name in acceptance.CASES:
            for witness in ({}, {'accepted': True}, {'private': 'PRIVATE-CANARY'}):
                with self.subTest(case=name, witness=witness):
                    attempt = synthetic_attempt()
                    row = next(row for row in attempt['observations'] if row['caseId'] == name)
                    row['attackWitness'] = witness
                    result = self.evaluate(attempt)
                    self.assertFalse(result['installedKeylessNativeAcceptanceSatisfied'])
                    self.assertNotIn('PRIVATE-CANARY', json.dumps(result))

    def test_mutation_without_observed_change_is_inconclusive(self):
        for name, case in acceptance.CASES.items():
            if case.witness != 'mutation':
                continue
            record = synthetic_observation(name, synthetic_identity())
            record['attackWitness']['after'] = dict(record['attackWitness']['before'])
            self.assertEqual('inconclusive', acceptance.observation_status(record, synthetic_identity()))

    def test_no_canary_listener_and_retrieved_canary_both_fail(self):
        record = synthetic_observation('sibling-control-canary', synthetic_identity())
        for field, value in (('controlBefore', 'absent'), ('controlResponseDigest', 'e' * 64),
                             ('nativeRetrievals', 1)):
            changed = copy.deepcopy(record)
            changed['attackWitness'][field] = value
            self.assertEqual('inconclusive', acceptance.observation_status(changed, synthetic_identity()))

    def test_retry_must_not_repeat_launch_or_decrypt(self):
        for name in ('retained-exact-retry',):
            for field in ('nativeLaunchCountAfter', 'decryptCountAfter'):
                record = synthetic_observation(name, synthetic_identity())
                record['attackWitness'][field] += 1
                self.assertEqual('inconclusive', acceptance.observation_status(record, synthetic_identity()))

    def test_retained_active_state_cannot_be_erased_after_death(self):
        record = synthetic_observation('death-running', synthetic_identity())
        record['quiescent']['activeRecordPresent'] = False
        self.assertEqual('failed', acceptance.observation_status(record, synthetic_identity()))

    def test_grouping_cannot_select_a_pass_over_a_failed_duplicate(self):
        attempt = synthetic_attempt()
        duplicate = copy.deepcopy(attempt)
        duplicate['observations'][0] = {'caseId': 'reference-identity', 'status': 'failed'}
        result = acceptance.verify_attempts(synthetic_identity(), [duplicate, attempt])
        self.assertFalse(result['installedKeylessNativeAcceptanceSatisfied'])
        self.assertFalse(result['recordContractValid'])

    def test_predeclared_disjoint_groups_can_complete_same_profile(self):
        original = synthetic_attempt()
        groups = []
        for start, stop in ((0, 8), (8, len(acceptance.CASES))):
            group = copy.deepcopy(original)
            group['declaredCases'] = original['declaredCases'][start:stop]
            group['observations'] = original['observations'][start:stop]
            groups.append(group)
        self.assertTrue(acceptance.verify_attempts(synthetic_identity(), groups)
                        ['installedKeylessNativeAcceptanceSatisfied'])

    def test_missing_prerequisite_invalidates_downstream_credit(self):
        attempt = synthetic_attempt()
        attempt['observations'][0] = {'caseId': 'reference-identity', 'status': 'setup-failed'}
        result = self.evaluate(attempt)
        self.assertTrue(all(row['status'] == 'setup-failed' for row in result['cases']))

    def test_real_mutation_driver_witnesses_match_closed_adapter(self):
        import tempfile
        from pathlib import Path
        import pr313_faults
        for mutation in pr313_faults.MUTATIONS:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary) / 'parent'
                parent.mkdir()
                path = parent / 'input'
                path.write_bytes(b'original bounded input')
                actual = pr313_faults.mutation(path, mutation)
                record = synthetic_observation('input-' + mutation, synthetic_identity())
                record['attackWitness'] = {key: actual[key] for key in ('mutation', 'before', 'after')}
                record['attackWitness']['barrier'] = 'source-opened'
                self.assertEqual('passed', acceptance.observation_status(record, synthetic_identity()))

    @unittest.skipUnless(hasattr(os, 'fork') and os.path.exists('/proc/self/stat'), 'Linux process observer')
    def test_actual_death_observer_emits_verifiable_retention_record(self):
        # Real controller process/signalling and durable files, explicitly fake service manager.
        # This catches producer/adapter drift; it is not a kernel sandbox test.
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from contextlib import nullcontext
        import pr313_faults
        for name in ('death-active', 'death-running', 'death-output'):
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                native = SimpleNamespace(ROOT=root, NativeBoundaryError=ValueError,
                    owning_boundary=lambda **kwargs: nullcontext(), _quiesce=lambda: None,
                    _manager=lambda action: {'InvocationID': 'a' * 32, 'SubState': 'running', 'ActiveState': 'inactive'})
                native._write = lambda path, value, **kwargs: Path(path).write_text(json.dumps(value))
                native._read_output = lambda path, maximum: Path(path).read_bytes()
                def execute(*args, **kwargs):
                    if (root / 'active.json').exists():
                        raise ValueError('restricted-native-execution-failed')
                    stage = root / ('b' * 64)
                    stage.mkdir()
                    native._write(root / 'active.json', {'invocation': stage.name})
                    native._write(stage / 'manager.json', {'invocationId': 'a' * 32})
                    from pr312_output_faults import CONTROL_BYTES
                    output = stage / 'output'
                    output.mkdir()
                    (output / 'stdout').write_bytes(b'pr313-output-ready\n')
                    (output / 'projection.json').write_bytes(CONTROL_BYTES)
                    native._write(output / 'complete.json', {'invocation': stage.name, 'status': 'complete'})
                    native._quiesce()
                native.run = execute
                record = pr313_faults._death(name, root, native, [], {})
                self.assertEqual('passed', acceptance.observation_status(record, synthetic_identity()))

    def test_public_result_cannot_supply_original_provider_authority(self):
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protected'))
        import restricted_worker
        result = self.evaluate(synthetic_attempt())
        # Production authentication requires an original job response; even a passing local
        # report does not have that closed original-job record shape.
        with self.assertRaises((KeyError, ValueError, TypeError)):
            restricted_worker.authenticate_job(result, {})


if __name__ == '__main__':
    unittest.main()
