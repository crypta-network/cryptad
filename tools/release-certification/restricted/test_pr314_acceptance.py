"""Contract-only synthetic observations, never installed workload acceptance."""
import copy
import unittest

import pr314_acceptance as a


def identity():
    return {key: 'a' * (40 if key.endswith(('Commit', 'Tree')) else 64) for key in a.IDENTITY_FIELDS}


def roles():
    return [dict(role=role, uid=2000+i, gid=2000+i, invocationId=f'{i+1:032x}',
                 processEpoch=100+i, bootId='a'*32, cgroupDigest=f'{i+1:064x}',
                 networkNamespace=300+i) for i, role in enumerate(a.ROLES)]


def observation(name):
    case = a.CASES[name]
    digest = 'b'*64
    witnesses = {
        'identity': dict(profile=a.PROFILE, bundleIdentity=identity()['bundleIdentity'],
                         testKitDigest=identity()['testKitDigest']),
        'roster': dict(observerUid=1000, roles=roles()),
        'app': dict(role='candidate-sender', provider='bubblewrap', hostPid=101, namespacePid=2,
                    processEpoch=100, invocationId='0'*31+'1', installedAppDigest=digest),
        'exchange': dict(requestDigest=digest, expectedResponseDigest=digest, responseDigest=digest,
                         serverInvocationId='0'*31+'1', serverRequests=1),
        'resources': dict(source='cgroup-v2', memoryCurrentBytes=1024, pidsCurrent=4, cpuUsageUsec=2),
        'restart': dict(beforeInvocationId='a'*32, afterInvocationId='b'*32, beforeEpoch=1,
                        afterEpoch=2, beforeStateDigest=digest, afterStateDigest=digest,
                        deadlineUnchanged=True),
        'denial': dict(actorUid=2000, attackStartedNs=3, targetActiveBeforeNs=2,
                       targetActiveAfterNs=4, controlResponseDigest=digest, denialSource='kernel',
                       denialCode='EACCES', unrelatedStateBefore=digest, unrelatedStateAfter=digest),
        'lifecycle': dict(triggerStartedNs=2, terminalObservedNs=4, roles=roles(),
                          populatedCgroups=[], remainingDescendants=0, retention='retained'),
    }
    return dict(caseId=name, status='passed', actor=case.actor, target=case.target,
                outcome=case.outcome, startedMonotonicNs=1, finishedMonotonicNs=5,
                witness=witnesses[case.witness])


def attempt():
    return dict(contract=a.CONTRACT, identity=identity(), declaredCases=list(a.CASES),
                observations=[observation(name) for name in a.CASES],
                guestStopped=True, attemptCompleted=True)


class WorkloadAcceptanceTest(unittest.TestCase):
    def test_complete_synthetic_contract_is_reachable_without_granting_authority(self):
        result = a.verify_attempts(identity(), [attempt()])
        self.assertTrue(result['installedWorkloadAcceptanceSatisfied'])
        for key in ('finiteNativeAcceptanceSatisfied', 'productionAuthorityObserved',
                    'protectedExecutionEligible', 'phase12Complete'):
            self.assertFalse(result[key])

    def test_every_missing_case_prevents_acceptance(self):
        for name in a.CASES:
            with self.subTest(case=name):
                value = attempt()
                value['observations'] = [dict(caseId=name, status='not-executed')
                    if row['caseId'] == name else row for row in value['observations']]
                result = a.verify_attempts(identity(), [value])
                self.assertTrue(result['recordContractValid'])
                self.assertFalse(result['installedWorkloadAcceptanceSatisfied'])

    def test_positive_flag_without_causal_witness_is_rejected(self):
        for name in a.CASES:
            with self.subTest(case=name):
                value = attempt()
                value['observations'] = [dict(caseId=name, status='passed')
                    if row['caseId'] == name else row for row in value['observations']]
                self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])

    def test_active_target_and_actual_denial_are_required(self):
        for field, replacement in (('targetActiveBeforeNs', 4), ('targetActiveAfterNs', 2),
                                   ('denialSource', 'timeout'), ('denialCode', 'no-listener'),
                                   ('unrelatedStateAfter', 'c'*64), ('actorUid', 0)):
            with self.subTest(field=field):
                value = observation('sibling-fcp')
                value['witness'][field] = replacement
                with self.assertRaises(ValueError):
                    a.observation_status(value, identity())

    def test_four_roles_have_distinct_uids_and_namespaces(self):
        for field in ('uid', 'gid', 'invocationId', 'networkNamespace', 'cgroupDigest', 'role'):
            with self.subTest(field=field):
                value = observation('four-role-start')
                value['witness']['roles'][1][field] = value['witness']['roles'][0][field]
                with self.assertRaises(ValueError):
                    a.observation_status(value, identity())

    def test_observer_uid_cannot_own_candidate(self):
        value = observation('four-role-start')
        value['witness']['observerUid'] = value['witness']['roles'][0]['uid']
        with self.assertRaises(ValueError):
            a.observation_status(value, identity())

    def test_remaining_descendant_or_populated_cgroup_prevents_terminal_pass(self):
        for field, replacement in (('remainingDescendants', 1), ('remainingDescendants', False),
                                   ('populatedCgroups', ['owned-role'])):
            value = observation('late-child')
            value['witness'][field] = replacement
            with self.assertRaises(ValueError):
                a.observation_status(value, identity())

    def test_duplicate_attempt_cannot_hide_failed_attempt(self):
        failed = attempt()
        failed['observations'][0] = dict(caseId='installed-ready', status='failed')
        self.assertFalse(a.verify_attempts(identity(), [failed, attempt()])['recordContractValid'])

    def test_identity_mismatch_and_live_guest_are_rejected(self):
        for field, replacement in (('identity', {**identity(), 'profileDigest': 'c'*64}),
                                   ('guestStopped', False), ('attemptCompleted', False)):
            value = attempt()
            value[field] = replacement
            self.assertFalse(a.verify_attempts(identity(), [value])['installedWorkloadAcceptanceSatisfied'])

    def test_private_fields_are_not_projected(self):
        value = attempt()
        value['observations'][0]['privateCanary'] = 'must-not-escape'
        result = a.verify_attempts(identity(), [value])
        self.assertFalse(result['recordContractValid'])
        self.assertNotIn('must-not-escape', repr(result))

    def test_malformed_inputs_fail_closed(self):
        for value in (None, {}, [], [None], [dict(contract=[])], [attempt()] * (len(a.CASES)+1)):
            with self.subTest(value=type(value)):
                self.assertFalse(a.verify_attempts(identity(), value)['installedWorkloadAcceptanceSatisfied'])
        self.assertFalse(a.verify_attempts({}, [attempt()])['installedWorkloadAcceptanceSatisfied'])

    def test_restart_requires_new_epoch_and_durable_state(self):
        for field, replacement in (('afterEpoch', 1), ('afterInvocationId', 'a'*32),
                                   ('afterStateDigest', 'c'*64), ('deadlineUnchanged', False)):
            value = copy.deepcopy(observation('restart-durable-state'))
            value['witness'][field] = replacement
            with self.assertRaises(ValueError):
                a.observation_status(value, identity())


if __name__ == '__main__':
    unittest.main()
