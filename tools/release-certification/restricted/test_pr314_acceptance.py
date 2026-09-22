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


def target(name):
    case = a.CASES[name]
    role = a.TARGET_ROLES.get(case.target)
    owner = next((row for row in roles() if row['role'] == role),
                 dict(invocationId='e'*32, cgroupDigest='e'*64, bootId='a'*32))
    return dict(caseId=name, target=case.target, role=role,
                **{key: owner[key] for key in ('invocationId', 'cgroupDigest', 'bootId')},
                probeDigest=f'{list(a.CASES).index(name)+1:064x}', controlResponseDigest='b'*64)


def observation(name):
    case = a.CASES[name]
    digest = 'b'*64
    witnesses = {
        'identity': dict(profile=a.PROFILE, bundleIdentity=identity()['bundleIdentity'],
                         testKitDigest=identity()['testKitDigest']),
        'roster': dict(observerUid=1000, roles=roles()),
        'app': dict(role='candidate-sender', provider='bubblewrap', hostPid=101, namespacePid=2,
                    processEpoch=100, invocationId='0'*31+'1', installedAppDigest=identity()['admittedAppDigest']),
        'exchange': dict(caseId=name, operationDigest=f'{1000+list(a.CASES).index(name):064x}',
                         requestDigest=f'{1000+list(a.CASES).index(name):064x}',
                         expectedResponseDigest=digest, responseDigest=digest,
                         serverInvocationId='0'*31+('2' if name == 'fnp-content-retrieval' else '1'), serverRequests=1),
        'resources': dict(source='cgroup-v2', measurements=[{
            **{key: row[key] for key in ('role', 'invocationId', 'processEpoch', 'bootId', 'cgroupDigest')},
            'memoryCurrentBytes': 1024, 'pidsCurrent': 4, 'cpuUsageUsec': 2} for row in roles()]),
        'restart': dict(role='candidate-sender', beforeInvocationId='a'*32,
                        afterInvocationId=roles()[0]['invocationId'], beforeEpoch=1,
                        afterEpoch=roles()[0]['processEpoch'], beforeStateDigest=digest, afterStateDigest=digest,
                        deadlineUnchanged=True),
        'denial': dict(actorUid={'observer': 1000, 'runner': 1001}.get(case.actor, 2000),
                       attackDigest=f'{3000+list(a.CASES).index(name):064x}',
                       targetIdentity=target(name),
                       attackStartedNs=3, targetActiveBeforeNs=2,
                       targetActiveAfterNs=4, controlResponseDigest=digest, denialSource='kernel',
                       denialCode='EACCES', unrelatedStateBefore=digest, unrelatedStateAfter=digest),
        'lifecycle': dict(caseId=name, triggerDigest=f'{1000+list(a.CASES).index(name):064x}',
                          trigger=dict(kind=name, eventDigest=f'{2000+list(a.CASES).index(name):064x}'),
                          triggerStartedNs=2, terminalObservedNs=4, roles=roles(),
                          populatedCgroups=[], remainingDescendants=0, retention='retained'),
    }
    witness = witnesses[case.witness]
    if case.witness in ('exchange', 'lifecycle'):
        field = 'operationDigest' if case.witness == 'exchange' else 'triggerDigest'
        witness[field] = a.payload_commitment(name, witness)
    elif case.witness == 'denial':
        witness['targetIdentity']['probeDigest'] = a.payload_commitment(name, witness)
    return dict(caseId=name, status='passed', actor=case.actor, target=case.target,
                outcome=case.outcome, startedMonotonicNs=1, finishedMonotonicNs=5,
                witness=witness)


def restart_context():
    before = {**roles()[0], 'invocationId': 'a'*32, 'processEpoch': 1}
    return {stage: dict(roleIdentity=row, stateDigest='b'*64, deadlineNs=10,
                        observedMonotonicNs=timestamp)
            for stage, row, timestamp in (('before', before, 2), ('after', roles()[0], 4))}


def attempt():
    return dict(contract=a.CONTRACT, identity=identity(), declaredCases=list(a.CASES),
                principals=dict(observerUid=1000, runnerUid=1001, roles=roles()),
                targets={name: observation(name)['witness']['targetIdentity'] for name, case in a.CASES.items()
                         if case.witness == 'denial'},
                caseCommitments={name: a.payload_commitment(name, observation(name)['witness']) for name, case in a.CASES.items()
                                 if case.witness in ('exchange', 'lifecycle')},
                restartContext=restart_context(),
                appProcess=observation('signed-apphost-child')['witness'],
                observations=[observation(name) for name in a.CASES],
                guestStopped=True, attemptCompleted=True)


class WorkloadAcceptanceTest(unittest.TestCase):
    def test_denial_payload_cannot_be_copied_by_replacing_target_metadata(self):
        value = attempt()
        original = observation('sibling-fcp')['witness']
        for row in value['observations']:
            if a.CASES[row['caseId']].witness != 'denial':
                continue
            own = row['witness']
            row['witness'] = copy.deepcopy(original)
            for key in ('actorUid', 'targetIdentity', 'controlResponseDigest'):
                row['witness'][key] = own[key]
        result = a.verify_attempts(identity(), [value])
        self.assertFalse(result['recordContractValid'])
        self.assertFalse(result['installedWorkloadAcceptanceSatisfied'])

    def test_denial_commitment_covers_measured_attack_and_outcome(self):
        for field, replacement in (('attackDigest', 'f'*64), ('attackStartedNs', 4),
                ('denialSource', 'server'), ('denialCode', 'EPERM'), ('unrelatedStateBefore', 'f'*64)):
            value = attempt()
            row = next(row for row in value['observations'] if row['caseId'] == 'sibling-fcp')
            # Preserve otherwise valid interval/state checks while changing the payload.
            if field == 'attackStartedNs':
                row['witness']['targetActiveAfterNs'] = 5
            if field == 'unrelatedStateBefore':
                row['witness']['unrelatedStateAfter'] = replacement
            row['witness'][field] = replacement
            with self.subTest(field=field):
                self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])
                row['witness']['targetIdentity']['probeDigest'] = a.payload_commitment(row['caseId'], row['witness'])
                self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])

    def test_relabel_and_replace_commitment_cannot_copy_payload(self):
        for source, destination in (('own-management', 'dynamic-app-bootstrap'),
                                     ('deadline', 'observer-death')):
            for recompute in (False, True):
                value = attempt()
                row = next(row for row in value['observations'] if row['caseId'] == destination)
                row['witness'] = observation(source)['witness']
                row['witness']['caseId'] = destination
                field = 'operationDigest' if a.CASES[destination].witness == 'exchange' else 'triggerDigest'
                row['witness'][field] = (a.payload_commitment(destination, row['witness']) if recompute
                                        else value['caseCommitments'][destination])
                with self.subTest(destination=destination, recompute=recompute):
                    self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])

    def test_commitment_covers_exchange_and_terminal_payload(self):
        for name, field, replacement in (('own-management', 'requestDigest', 'f'*64),
                ('own-management', 'responseDigest', 'f'*64), ('own-management', 'serverRequests', 2),
                ('deadline', 'terminalObservedNs', 5), ('deadline', 'retention', 'cleaned-after-quiescence'),
                ('deadline', 'trigger', {'kind': 'deadline', 'eventDigest': 'f'*64})):
            value = attempt()
            row = next(row for row in value['observations'] if row['caseId'] == name)
            row['witness'][field] = replacement
            if field == 'responseDigest':
                row['witness']['expectedResponseDigest'] = replacement
            with self.subTest(case=name, field=field):
                self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])

    def test_app_process_identity_must_match_independent_observation(self):
        for field, replacement in (('hostPid', 1), ('hostPid', 999), ('namespacePid', 99), ('processEpoch', 999)):
            value = attempt()
            row = next(row for row in value['observations'] if row['caseId'] == 'signed-apphost-child')
            row['witness'][field] = replacement
            with self.subTest(field=field, replacement=replacement):
                self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])
        for replacement in (None, {}, {**observation('signed-apphost-child')['witness'], 'hostPid': 1}):
            value = attempt()
            value['appProcess'] = replacement
            self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])

    def test_exchange_and_lifecycle_witnesses_cannot_be_relabelled(self):
        for kind in ('exchange', 'lifecycle'):
            names = [name for name, case in a.CASES.items() if case.witness == kind]
            for name in names:
                other = next(other for other in names if other != name)
                for relabel in (False, True):
                    value = attempt()
                    row = next(row for row in value['observations'] if row['caseId'] == name)
                    row['witness'] = observation(other)['witness']
                    if relabel:
                        row['witness']['caseId'] = name
                    with self.subTest(case=name, relabel=relabel):
                        self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])

    def test_case_commitments_cannot_be_reused_within_or_across_attempts(self):
        for split in (False, True):
            value = attempt()
            for name in value['caseCommitments']:
                value['caseCommitments'][name] = 'f'*64
                row = next(row for row in value['observations'] if row['caseId'] == name)
                field = 'operationDigest' if a.CASES[name].witness == 'exchange' else 'triggerDigest'
                row['witness'][field] = 'f'*64
            attempts = [value]
            if split:
                attempts = []
                for name in a.CASES:
                    part = copy.deepcopy(value)
                    part['declaredCases'] = [name]
                    if name != 'restart-durable-state':
                        part['restartContext'] = None
                    if name != 'signed-apphost-child':
                        part['appProcess'] = None
                    part['observations'] = [row for row in part['observations'] if row['caseId'] == name]
                    for key in ('targets', 'caseCommitments'):
                        part[key] = {name: part[key][name]} if name in part[key] else {}
                    attempts.append(part)
            for ordered in (attempts, list(reversed(attempts))):
                with self.subTest(split=split):
                    self.assertFalse(a.verify_attempts(identity(), ordered)['recordContractValid'])

    def test_missing_or_malformed_case_commitments_reject(self):
        for replacement in (None, {}, {'own-management': 'not-a-digest'}):
            value = attempt()
            value['caseCommitments'] = replacement
            self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])
        for name in ('own-management', 'dynamic-app-bootstrap', 'deadline'):
            with self.assertRaises(ValueError):
                a.observation_status(observation(name), identity(), attempt()['principals'], attempt()['targets'])

    def test_probe_commitments_are_unique_across_all_attempts(self):
        attempts = []
        for name in a.CASES:
            value = attempt()
            value['declaredCases'] = [name]
            if name != 'restart-durable-state':
                value['restartContext'] = None
            if name != 'signed-apphost-child':
                value['appProcess'] = None
            value['observations'] = [row for row in value['observations'] if row['caseId'] == name]
            value['targets'] = {name: value['targets'][name]} if name in value['targets'] else {}
            value['caseCommitments'] = {name: value['caseCommitments'][name]} if name in value['caseCommitments'] else {}
            attempts.append(value)
        self.assertTrue(a.verify_attempts(identity(), attempts)['installedWorkloadAcceptanceSatisfied'])
        for value in attempts:
            for selected in value['targets'].values():
                selected['probeDigest'] = 'f'*64
                value['observations'][0]['witness']['targetIdentity']['probeDigest'] = 'f'*64
        for ordered in (attempts, list(reversed(attempts))):
            result = a.verify_attempts(identity(), ordered)
            self.assertFalse(result['recordContractValid'])
            self.assertFalse(result['installedWorkloadAcceptanceSatisfied'])

    def test_app_digest_must_match_expected_admitted_identity(self):
        value = attempt()
        row = next(row for row in value['observations'] if row['caseId'] == 'signed-apphost-child')
        row['witness']['installedAppDigest'] = 'f'*64
        self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])
        value['identity']['admittedAppDigest'] = 'f'*64
        self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])

    def test_denial_cannot_reuse_another_cases_target(self):
        names = [name for name, case in a.CASES.items() if case.witness == 'denial']
        for name in names:
            value = attempt()
            row = next(row for row in value['observations'] if row['caseId'] == name)
            other = next(other for other in names if other != name)
            row['witness']['targetIdentity'] = target(other)
            with self.subTest(case=name):
                self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])

    def test_denial_target_must_match_independent_context(self):
        for field, replacement in (('probeDigest', 'f'*64), ('controlResponseDigest', 'f'*64),
                ('invocationId', 'f'*32), ('cgroupDigest', 'f'*64), ('bootId', 'f'*32),
                ('role', 'candidate-sender'), ('target', 'resolver')):
            value = attempt()
            row = next(row for row in value['observations'] if row['caseId'] == 'sibling-fcp')
            row['witness']['targetIdentity'][field] = replacement
            with self.subTest(field=field):
                self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])

    def test_targets_require_case_specific_probes_and_current_roster(self):
        for change in ('missing', 'duplicate-probe', 'stale-role', 'wrong-control'):
            value = attempt()
            if change == 'missing':
                del value['targets']
            elif change == 'duplicate-probe':
                value['targets']['sibling-fcp']['probeDigest'] = value['targets']['sibling-http']['probeDigest']
            elif change == 'stale-role':
                value['targets']['sibling-fcp']['invocationId'] = 'f'*32
            else:
                row = next(row for row in value['observations'] if row['caseId'] == 'sibling-fcp')
                row['witness']['controlResponseDigest'] = 'f'*64
            with self.subTest(change=change):
                self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])

    def test_resource_measurements_bind_every_owned_cgroup(self):
        for index in range(4):
            for field, replacement in (('role', 'controller'), ('cgroupDigest', 'f'*64),
                    ('invocationId', 'f'*32), ('bootId', 'f'*32), ('processEpoch', 9999),
                    ('memoryCurrentBytes', True), ('pidsCurrent', -1), ('cpuUsageUsec', '2')):
                value = attempt()
                row = next(row for row in value['observations'] if row['caseId'] == 'kernel-resource-scope')
                row['witness']['measurements'][index][field] = replacement
                with self.subTest(index=index, field=field):
                    self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])

    def test_resource_measurements_require_complete_unique_roster(self):
        for change in ('missing', 'duplicate', 'old-shape'):
            value = observation('kernel-resource-scope')
            if change == 'missing':
                value['witness']['measurements'].pop()
            elif change == 'duplicate':
                value['witness']['measurements'][1] = value['witness']['measurements'][0]
            else:
                value['witness'] = dict(source='cgroup-v2', memoryCurrentBytes=1024, pidsCurrent=4, cpuUsageUsec=2)
            with self.subTest(change=change), self.assertRaises(ValueError):
                a.observation_status(value, identity(), attempt()['principals'], attempt()['targets'], attempt()['caseCommitments'], attempt()['appProcess'], attempt()['restartContext'])
        with self.assertRaises(ValueError):
            a.observation_status(observation('kernel-resource-scope'), identity())

    def test_restart_cannot_invent_pre_restart_identity(self):
        for field, replacement in (('beforeInvocationId', 'f'*32), ('beforeEpoch', 99),
                                    ('beforeStateDigest', 'c'*64)):
            value = attempt()
            row = next(row for row in value['observations'] if row['caseId'] == 'restart-durable-state')
            row['witness'][field] = replacement
            if field == 'beforeStateDigest':
                row['witness']['afterStateDigest'] = replacement
            with self.subTest(field=field):
                result = a.verify_attempts(identity(), [value])
                self.assertFalse(result['recordContractValid'])
                self.assertFalse(result['installedWorkloadAcceptanceSatisfied'])

    def test_restart_requires_both_independent_measured_snapshots(self):
        for replacement in (None, {}, {'after': restart_context()['after']},
                            {'before': restart_context()['after'], 'after': restart_context()['after']}):
            value = attempt()
            value['restartContext'] = replacement
            with self.subTest(context=replacement):
                self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])
        with self.assertRaises(ValueError):
            value = attempt()
            a.observation_status(observation('restart-durable-state'), identity(), value['principals'])

    def test_restart_context_rejects_changed_scope_deadline_state_and_timing(self):
        for stage in ('before', 'after'):
            for field, replacement in (('bootId', 'f'*32), ('uid', 9999), ('gid', 9999),
                    ('role', 'candidate-recipient'), ('cgroupDigest', 'f'*64),
                    ('networkNamespace', 9999), ('invocationId', roles()[1]['invocationId']),
                    ('processEpoch', True), ('deadlineNs', 11), ('stateDigest', 'f'*64),
                    ('observedMonotonicNs', 6), ('observedMonotonicNs', 1)):
                value = attempt()
                snapshot = value['restartContext'][stage]
                container = snapshot['roleIdentity'] if field in snapshot['roleIdentity'] else snapshot
                container[field] = replacement
                # A before sample at the start of the case is legitimate.
                if stage == 'before' and field == 'observedMonotonicNs' and replacement == 1:
                    continue
                with self.subTest(stage=stage, field=field, replacement=replacement):
                    self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])

    def test_restart_terminal_identity_matches_sender(self):
        for field, replacement in (('role', 'candidate-recipient'), ('role', 'controller'),
                ('afterInvocationId', 'f'*32), ('afterInvocationId', roles()[1]['invocationId']),
                ('afterEpoch', 9999), ('afterEpoch', roles()[1]['processEpoch'])):
            value = attempt()
            row = next(row for row in value['observations'] if row['caseId'] == 'restart-durable-state')
            row['witness'][field] = replacement
            with self.subTest(field=field, replacement=replacement):
                self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])
        with self.assertRaises(ValueError):
            a.observation_status(observation('restart-durable-state'), identity())

    def test_previous_contract_versions_cannot_supply_new_witnesses(self):
        for version in ('pr314-workload-roles-v1', 'pr314-workload-roles-v2', 'pr314-workload-roles-v3', 'pr314-workload-roles-v4', 'pr314-workload-roles-v5', 'pr314-workload-roles-v6', 'pr314-workload-roles-v7'):
            value = attempt()
            value['contract'] = version
            self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])

    def test_exchange_must_match_expected_active_role(self):
        for name in ('own-management', 'fnp-content-retrieval', 'dynamic-app-bootstrap'):
            expected_role = 'candidate-recipient' if name == 'fnp-content-retrieval' else 'candidate-sender'
            for invocation in [row['invocationId'] for row in roles() if row['role'] != expected_role] + ['f' * 32]:
                value = attempt()
                row = next(row for row in value['observations'] if row['caseId'] == name)
                row['witness']['serverInvocationId'] = invocation
                with self.subTest(case=name, invocation=invocation):
                    self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])
            with self.assertRaises(ValueError):
                a.observation_status(observation(name), identity())

    def test_lifecycle_must_match_attempt_roster(self):
        for name, case in a.CASES.items():
            if case.witness != 'lifecycle':
                continue
            for field, replacement in (('uid', 9999), ('gid', 9999), ('invocationId', 'f'*32),
                    ('processEpoch', 9999), ('networkNamespace', 9999), ('cgroupDigest', 'f'*64)):
                value = attempt()
                row = next(row for row in value['observations'] if row['caseId'] == name)
                row['witness']['roles'][0][field] = replacement
                with self.subTest(case=name, field=field):
                    self.assertTrue(a._roster(row['witness']['roles']))
                    self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])
            with self.assertRaises(ValueError):
                a.observation_status(observation(name), identity())

    def test_app_witness_must_match_active_sender_invocation(self):
        for invocation in (roles()[1]['invocationId'], 'f' * 32):
            value = attempt()
            row = next(row for row in value['observations'] if row['caseId'] == 'signed-apphost-child')
            row['witness']['invocationId'] = invocation
            with self.subTest(invocation=invocation):
                result = a.verify_attempts(identity(), [value])
                self.assertFalse(result['recordContractValid'])
                self.assertFalse(result['installedWorkloadAcceptanceSatisfied'])

    def test_app_witness_requires_principal_context(self):
        with self.assertRaises(ValueError):
            a.observation_status(observation('signed-apphost-child'), identity())

    def test_denials_require_the_declared_installed_principal(self):
        for name, case in a.CASES.items():
            if case.witness != 'denial':
                continue
            for uid in (0, 1000, 1001, 2000, 2001, 2002, 2003, 9999):
                value = attempt()
                row = next(row for row in value['observations'] if row['caseId'] == name)
                expected_uid = row['witness']['actorUid']
                row['witness']['actorUid'] = uid
                with self.subTest(case=name, uid=uid):
                    self.assertEqual(uid == expected_uid,
                        a.verify_attempts(identity(), [value])['installedWorkloadAcceptanceSatisfied'])

    def test_principal_context_is_required_distinct_and_matches_start_roster(self):
        for change in ('missing', 'observer-role', 'runner-observer', 'roster-mismatch', 'legacy'):
            value = attempt()
            if change == 'missing':
                del value['principals']
            elif change == 'observer-role':
                value['principals']['observerUid'] = 2000
            elif change == 'runner-observer':
                value['principals']['runnerUid'] = 1000
            elif change == 'legacy':
                value['contract'] = 'pr314-workload-roles-v1'
            else:
                value['principals']['roles'][0]['uid'] = 9999
            with self.subTest(change=change):
                self.assertFalse(a.verify_attempts(identity(), [value])['recordContractValid'])

    def test_denial_without_principal_context_is_not_accepted(self):
        with self.assertRaises(ValueError):
            a.observation_status(observation('sibling-fcp'), identity())

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
                    a.observation_status(value, identity(), attempt()['principals'], attempt()['targets'], attempt()['caseCommitments'], attempt()['appProcess'], attempt()['restartContext'])

    def test_four_roles_have_distinct_uids_and_namespaces(self):
        for field in ('uid', 'gid', 'invocationId', 'networkNamespace', 'cgroupDigest', 'role'):
            with self.subTest(field=field):
                value = observation('four-role-start')
                value['witness']['roles'][1][field] = value['witness']['roles'][0][field]
                with self.assertRaises(ValueError):
                    a.observation_status(value, identity(), attempt()['principals'], attempt()['targets'], attempt()['caseCommitments'], attempt()['appProcess'], attempt()['restartContext'])

    def test_observer_uid_cannot_own_candidate(self):
        value = observation('four-role-start')
        value['witness']['observerUid'] = value['witness']['roles'][0]['uid']
        with self.assertRaises(ValueError):
            a.observation_status(value, identity(), attempt()['principals'], attempt()['targets'], attempt()['caseCommitments'], attempt()['appProcess'], attempt()['restartContext'])

    def test_remaining_descendant_or_populated_cgroup_prevents_terminal_pass(self):
        for field, replacement in (('remainingDescendants', 1), ('remainingDescendants', False),
                                   ('populatedCgroups', ['owned-role'])):
            value = observation('late-child')
            value['witness'][field] = replacement
            with self.assertRaises(ValueError):
                a.observation_status(value, identity(), attempt()['principals'], attempt()['targets'], attempt()['caseCommitments'], attempt()['appProcess'], attempt()['restartContext'])

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
                a.observation_status(value, identity(), attempt()['principals'], attempt()['targets'], attempt()['caseCommitments'], attempt()['appProcess'], attempt()['restartContext'])


if __name__ == '__main__':
    unittest.main()
