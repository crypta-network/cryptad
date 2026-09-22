"""Closed prospective workload observations, separate from finite native acceptance.

Only an administrator driver over its pinned guest transport may call this verifier with
observations. JSON shape and digests do not authenticate execution. There is deliberately no
report-import CLI or production approval API. Contract tests use synthetic records, which are
not installed observations and must never be published as such.
"""
from dataclasses import dataclass
import hashlib
import json
import re

CONTRACT = 'pr314-workload-roles-v7'
PROFILE = 'debian13-systemd257-workload-v1'
ROLES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')
IDENTITY_FIELDS = ('helperSourceCommit', 'helperSourceTree', 'productSelectionDigest',
                   'bundleIdentity', 'testKitDigest', 'profileDigest', 'bootClosureDigest',
                   'preparedImageDigest', 'fixtureManifestDigest', 'admittedAppDigest')
STATUSES = frozenset(('passed', 'failed', 'setup-failed', 'not-executed', 'inconclusive'))


@dataclass(frozen=True)
class Case:
    actor: str
    target: str
    outcome: str
    witness: str
    server_role: str | None = None


CASES = {
    'installed-ready': Case('administrator', 'installation', 'verified', 'identity'),
    'four-role-start': Case('observer', 'four-role-roster', 'running', 'roster'),
    'signed-apphost-child': Case('observer', 'own-app', 'sandboxed', 'app'),
    'own-management': Case('observer', 'own-management', 'connected', 'exchange', 'candidate-sender'),
    'fnp-content-retrieval': Case('observer', 'approved-fnp-links', 'retrieved', 'exchange', 'candidate-recipient'),
    'dynamic-app-bootstrap': Case('observer', 'own-app', 'bound-session', 'exchange', 'candidate-sender'),
    'kernel-resource-scope': Case('administrator', 'owned-cgroups', 'measured', 'resources'),
    'restart-durable-state': Case('observer', 'owned-role', 'new-epoch', 'restart'),
}
for name, actor, target in (
    ('observer-private-read', 'candidate', 'observer-private'),
    ('observer-private-write', 'candidate', 'observer-private'),
    ('resolver-authority', 'candidate', 'resolver'),
    ('provider-authority', 'app', 'original-provider'),
    ('sibling-data', 'candidate', 'sibling-data'),
    ('sibling-fcp', 'candidate', 'sibling-fcp'),
    ('sibling-http', 'candidate', 'sibling-http'),
    ('sibling-app', 'app', 'sibling-app'),
    ('host-network', 'candidate', 'host-canary'),
    ('runner-control', 'runner', 'manager'),
    ('observer-control', 'observer', 'manager'),
    ('arbitrary-endpoint', 'observer', 'connector'),
    ('hostile-app-origin', 'candidate', 'own-app'),
    ('package-expectation', 'candidate', 'immutable-inputs'),
    ('forged-runtime-identity', 'candidate', 'process-observer'),
    ('namespace-mount-escape', 'app', 'outer-role'),
    ('cgroup-migration', 'candidate', 'owned-cgroups'),
    ('resource-exhaustion', 'app', 'outer-role'),
    ('output-symlink', 'candidate', 'output-collector'),
    ('output-fifo', 'candidate', 'output-collector'),
    ('output-hardlink', 'candidate', 'output-collector'),
    ('output-replacement', 'candidate', 'output-collector'),
    ('output-flood', 'candidate', 'output-collector'),
    ('stale-handle', 'observer', 'controller'),
    ('stale-pid-uid', 'observer', 'process-observer'),
    ('forged-counters', 'candidate', 'kernel-metrics'),
):
    CASES[name] = Case(actor, target, 'denied', 'denial')
for name in ('lost-start-response', 'observer-death', 'controller-restart', 'late-child',
             'setsid-double-fork', 'deadline', 'revocation-running', 'cancellation',
             'partial-launch', 'stuck-output', 'cleanup-race'):
    CASES[name] = Case('administrator', 'owned-roles', 'quiescent', 'lifecycle')


def _closed(value, fields):
    return isinstance(value, dict) and set(value) == set(fields)


def _hex(value, length=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % length, value) is not None


def _positive(value):
    return type(value) is int and value > 0


def _identity(value):
    return (_closed(value, IDENTITY_FIELDS) and all(_hex(value[key],
        40 if key.endswith(('Commit', 'Tree')) else 64) for key in IDENTITY_FIELDS))


def _roster(rows):
    if not isinstance(rows, list) or len(rows) != len(ROLES):
        return False
    if not all(_closed(row, ('role', 'uid', 'gid', 'invocationId', 'processEpoch',
                            'bootId', 'cgroupDigest', 'networkNamespace')) for row in rows):
        return False
    if not all(isinstance(row['role'], str) and row['role'] in ROLES and
               all(_positive(row[key]) for key in ('uid', 'gid', 'processEpoch', 'networkNamespace'))
               and _hex(row['invocationId'], 32) and _hex(row['bootId'], 32)
               and _hex(row['cgroupDigest']) for row in rows):
        return False
    return (set(row['role'] for row in rows) == set(ROLES)
            and all(len({row[key] for row in rows}) == 4 for key in
                    ('uid', 'gid', 'invocationId', 'cgroupDigest', 'networkNamespace'))
            and len({row['bootId'] for row in rows}) == 1)


def _principals(value):
    """Measured per-attempt accounts; candidate/app probes originate in candidate-sender."""
    return (_closed(value, ('observerUid', 'runnerUid', 'roles'))
            and _roster(value['roles'])
            and _positive(value['observerUid']) and _positive(value['runnerUid'])
            and len({value['observerUid'], value['runnerUid'],
                     *(row['uid'] for row in value['roles'])}) == len(ROLES) + 2)


def _actor_uid(actor, principals):
    if actor in ('candidate', 'app'):
        return next(row['uid'] for row in principals['roles'] if row['role'] == 'candidate-sender')
    return principals[actor + 'Uid']


TARGET_ROLES = {'sibling-data': 'candidate-recipient', 'sibling-fcp': 'candidate-recipient',
                'sibling-http': 'candidate-recipient', 'sibling-app': 'candidate-recipient',
                'own-app': 'candidate-sender', 'immutable-inputs': 'candidate-sender',
                'outer-role': 'candidate-sender', 'owned-cgroups': 'candidate-sender'}


def _target(name, target, principals):
    case = CASES[name]
    if not (_closed(target, ('caseId', 'target', 'role', 'invocationId', 'cgroupDigest',
                             'bootId', 'probeDigest', 'controlResponseDigest'))
            and target['caseId'] == name and target['target'] == case.target
            and target['role'] == TARGET_ROLES.get(case.target) and _principals(principals)
            and _hex(target['invocationId'], 32) and _hex(target['cgroupDigest'])
            and _hex(target['probeDigest']) and _hex(target['controlResponseDigest'])
            and target['bootId'] == principals['roles'][0]['bootId']):
        return False
    if target['role'] is not None:
        expected = next(row for row in principals['roles'] if row['role'] == target['role'])
        return all(target[key] == expected[key] for key in ('invocationId', 'cgroupDigest', 'bootId'))
    return (target['invocationId'] not in {row['invocationId'] for row in principals['roles']}
            and target['cgroupDigest'] not in {row['cgroupDigest'] for row in principals['roles']})


def _targets(targets, principals, declared):
    names = {name for name in declared if CASES[name].witness == 'denial'}
    return (_closed(targets, names) and all(_target(name, targets[name], principals) for name in names)
            and len({targets[name]['probeDigest'] for name in names}) == len(names))


def _case_commitments(commitments, declared):
    names = {name for name in declared if CASES[name].witness in ('exchange', 'lifecycle')}
    return (_closed(commitments, names) and all(_hex(commitments[name]) for name in names)
            and len(set(commitments.values())) == len(names))


def _resources(witness, principals):
    if not (_closed(witness, ('source', 'measurements')) and witness['source'] == 'cgroup-v2'
            and _principals(principals) and isinstance(witness['measurements'], list)
            and len(witness['measurements']) == len(ROLES)):
        return False
    identity_fields = ('role', 'invocationId', 'processEpoch', 'bootId', 'cgroupDigest')
    metrics = ('memoryCurrentBytes', 'pidsCurrent', 'cpuUsageUsec')
    observed = set()
    for measurement in witness['measurements']:
        if not (_closed(measurement, (*identity_fields, *metrics))
                and isinstance(measurement['role'], str) and measurement['role'] in ROLES
                and measurement['role'] not in observed
                and all(_positive(measurement[key]) for key in metrics)):
            return False
        expected = next(row for row in principals['roles'] if row['role'] == measurement['role'])
        if any(type(measurement[key]) is not type(expected[key]) or measurement[key] != expected[key]
               for key in identity_fields):
            return False
        observed.add(measurement['role'])
    return observed == set(ROLES)


def payload_commitment(name, witness):
    """Canonical payload binding, not authentication; compare to independent driver context."""
    kind = CASES[name].witness
    if kind == 'denial':
        payload = {**witness, 'targetIdentity': {
            key: value for key, value in witness['targetIdentity'].items() if key != 'probeDigest'}}
    else:
        field = 'operationDigest' if kind == 'exchange' else 'triggerDigest'
        payload = {key: value for key, value in witness.items() if key != field}
    raw = json.dumps({'domain': CONTRACT, 'caseId': name, 'target': CASES[name].target,
                      'payload': payload}, sort_keys=True, separators=(',', ':'), allow_nan=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def _app_process(value, identity, principals):
    return (_closed(value, ('role', 'provider', 'hostPid', 'namespacePid',
                           'processEpoch', 'invocationId', 'installedAppDigest'))
            and value['role'] == 'candidate-sender' and value['provider'] == 'bubblewrap'
            and all(_positive(value[key]) for key in ('hostPid', 'namespacePid', 'processEpoch'))
            and value['hostPid'] > 1 and value['hostPid'] != value['namespacePid']
            and value['installedAppDigest'] == identity['admittedAppDigest']
            and _principals(principals)
            and value['invocationId'] == next(row['invocationId'] for row in principals['roles']
                                               if row['role'] == value['role']))


def _witness(case, witness, identity, principals, app_process):
    kind = case.witness
    if kind == 'identity':
        return witness == {'profile': PROFILE, 'bundleIdentity': identity['bundleIdentity'],
                           'testKitDigest': identity['testKitDigest']}
    if kind == 'roster':
        return (_closed(witness, ('observerUid', 'roles')) and _roster(witness['roles'])
                and _positive(witness['observerUid'])
                and witness['observerUid'] not in {row['uid'] for row in witness['roles']}
                and (principals is None or (witness['observerUid'] == principals['observerUid']
                     and witness['roles'] == principals['roles'])))
    if kind == 'app':
        return (_app_process(witness, identity, principals)
                and _app_process(app_process, identity, principals) and witness == app_process)
    if kind == 'exchange':
        return (_closed(witness, ('caseId', 'operationDigest', 'requestDigest', 'expectedResponseDigest', 'responseDigest',
                                 'serverInvocationId', 'serverRequests'))
                and all(_hex(witness[key]) for key in ('requestDigest', 'expectedResponseDigest', 'responseDigest'))
                and witness['responseDigest'] == witness['expectedResponseDigest']
                and _hex(witness['serverInvocationId'], 32) and _positive(witness['serverRequests'])
                and _principals(principals)
                and witness['serverInvocationId'] == next(row['invocationId'] for row in principals['roles']
                                                          if row['role'] == case.server_role))
    if kind == 'resources':
        return _resources(witness, principals)
    if kind == 'restart':
        return (_closed(witness, ('role', 'beforeInvocationId', 'afterInvocationId', 'beforeEpoch',
                                 'afterEpoch', 'beforeStateDigest', 'afterStateDigest', 'deadlineUnchanged'))
                and witness['role'] == 'candidate-sender' and _principals(principals)
                and all(_hex(witness[key], 32) for key in ('beforeInvocationId', 'afterInvocationId'))
                and witness['beforeInvocationId'] != witness['afterInvocationId']
                and _positive(witness['beforeEpoch']) and _positive(witness['afterEpoch'])
                and witness['beforeEpoch'] != witness['afterEpoch']
                and any(row['role'] == witness['role']
                        and row['invocationId'] == witness['afterInvocationId']
                        and row['processEpoch'] == witness['afterEpoch'] for row in principals['roles'])
                and _hex(witness['beforeStateDigest'])
                and witness['beforeStateDigest'] == witness['afterStateDigest']
                and witness['deadlineUnchanged'] is True)
    if kind == 'denial':
        return (_closed(witness, ('actorUid', 'attackDigest', 'attackStartedNs', 'targetActiveBeforeNs',
                                 'targetActiveAfterNs', 'controlResponseDigest', 'denialSource',
                                 'denialCode', 'unrelatedStateBefore', 'unrelatedStateAfter', 'targetIdentity'))
                and _positive(witness['actorUid'])
                and _hex(witness['attackDigest'])
                and _principals(principals)
                and witness['actorUid'] == _actor_uid(case.actor, principals)
                and all(_positive(witness[key]) for key in
                        ('attackStartedNs', 'targetActiveBeforeNs', 'targetActiveAfterNs'))
                and witness['targetActiveBeforeNs'] < witness['attackStartedNs'] < witness['targetActiveAfterNs']
                and _hex(witness['controlResponseDigest'])
                and witness['denialSource'] in ('kernel', 'server', 'controller')
                and witness['denialCode'] in ('EACCES', 'EPERM', 'policy-rejected', 'resource-limit')
                and _hex(witness['unrelatedStateBefore'])
                and witness['unrelatedStateBefore'] == witness['unrelatedStateAfter'])
    if kind == 'lifecycle':
        return (_closed(witness, ('caseId', 'triggerDigest', 'trigger', 'triggerStartedNs', 'terminalObservedNs', 'roles',
                                 'populatedCgroups', 'remainingDescendants', 'retention'))
                and _closed(witness['trigger'], ('kind', 'eventDigest'))
                and witness['trigger']['kind'] == witness['caseId']
                and _hex(witness['trigger']['eventDigest'])
                and _positive(witness['triggerStartedNs']) and _positive(witness['terminalObservedNs'])
                and witness['triggerStartedNs'] < witness['terminalObservedNs']
                and _roster(witness['roles']) and witness['populatedCgroups'] == []
                and _principals(principals) and witness['roles'] == principals['roles']
                and type(witness['remainingDescendants']) is int and witness['remainingDescendants'] == 0
                and witness['retention'] in ('retained', 'cleaned-after-quiescence'))
    return False


def inventory(statuses=None):
    statuses = statuses or {}
    return [{'caseId': name, 'actor': case.actor, 'target': case.target,
             'expectedOutcome': case.outcome, 'status': statuses.get(name, 'not-executed')}
            for name, case in CASES.items()]


def observation_status(record, identity, principals=None, targets=None, case_commitments=None, app_process=None):
    if not isinstance(record, dict) or not isinstance(record.get('caseId'), str) or record['caseId'] not in CASES:
        raise ValueError('workload-case-invalid')
    if record.get('status') != 'passed':
        if (_closed(record, ('caseId', 'status')) and isinstance(record['status'], str)
                and record['status'] in STATUSES - {'passed'}):
            return record['status']
        raise ValueError('workload-status-invalid')
    case = CASES[record['caseId']]
    if not (_closed(record, ('caseId', 'status', 'actor', 'target', 'outcome',
                            'startedMonotonicNs', 'finishedMonotonicNs', 'witness'))
            and (record['actor'], record['target'], record['outcome']) == (case.actor, case.target, case.outcome)
            and _positive(record['startedMonotonicNs']) and _positive(record['finishedMonotonicNs'])
            and record['startedMonotonicNs'] < record['finishedMonotonicNs']
            and _witness(case, record['witness'], identity, principals, app_process)):
        raise ValueError('workload-observation-invalid')
    if case.witness in ('exchange', 'lifecycle'):
        field = 'operationDigest' if case.witness == 'exchange' else 'triggerDigest'
        if not (record['witness']['caseId'] == record['caseId']
                and isinstance(case_commitments, dict) and record['caseId'] in case_commitments
                and _hex(record['witness'][field])
                and record['witness'][field] == payload_commitment(record['caseId'], record['witness'])
                and record['witness'][field] == case_commitments[record['caseId']]):
            raise ValueError('workload-case-commitment-mismatch')
    if case.witness == 'denial':
        target = record['witness']['targetIdentity']
        if not (isinstance(targets, dict) and record['caseId'] in targets
                and _target(record['caseId'], target, principals)
                and target['probeDigest'] == payload_commitment(record['caseId'], record['witness'])
                and target == targets[record['caseId']]
                and record['witness']['controlResponseDigest'] == target['controlResponseDigest']):
            raise ValueError('workload-denial-target-mismatch')
    for key in ('attackStartedNs', 'targetActiveBeforeNs', 'targetActiveAfterNs',
                'triggerStartedNs', 'terminalObservedNs'):
        if key in record['witness'] and not (
                record['startedMonotonicNs'] <= record['witness'][key] <= record['finishedMonotonicNs']):
            raise ValueError('workload-witness-outside-invocation')
    return 'passed'


def verify_attempts(expected_identity, attempts):
    """Check driver records; caller must bind transport, source and measured principal context.

    UID equality binds the host account, not proof of app sandbox execution. The installed
    driver must capture the actual probe process under its current role/app invocation.
    expected_identity.admittedAppDigest must come from the authenticated selection's exact
    installed-app projection, never from the observed app. Targets are independently measured
    active services; probeDigest commits to the endpoint/object and operation for that case.
    Denial attackDigest must identify the actual measured attack transcript; the probe
    commitment covers it and the complete denial payload, not just target metadata.
    caseCommitments independently binds each exchange operation and measured lifecycle trigger;
    the driver must not derive this expected context by copying the submitted witness.
    appProcess is a separate kernel observation of the current AppHost child, including its
    host/namespace PID and start epoch; it must not be copied from candidate API claims.
    """
    statuses = {}
    probe_commitments = set()
    valid = _identity(expected_identity) and isinstance(attempts, list) and 0 < len(attempts) <= len(CASES)
    for attempt in attempts if isinstance(attempts, list) and len(attempts) <= len(CASES) else ():
        try:
            if not (_closed(attempt, ('contract', 'identity', 'declaredCases', 'observations',
                                     'guestStopped', 'attemptCompleted', 'principals', 'targets', 'caseCommitments',
                                     'appProcess'))
                    and attempt['contract'] == CONTRACT and attempt['identity'] == expected_identity
                    and _principals(attempt['principals'])
                    and attempt['guestStopped'] is True and attempt['attemptCompleted'] is True
                    and isinstance(attempt['declaredCases'], list) and attempt['declaredCases']
                    and all(isinstance(name, str) and name in CASES for name in attempt['declaredCases'])
                    and (_app_process(attempt['appProcess'], expected_identity, attempt['principals'])
                         if 'signed-apphost-child' in attempt['declaredCases'] else attempt['appProcess'] is None)
                    and _targets(attempt['targets'], attempt['principals'], attempt['declaredCases'])
                    and _case_commitments(attempt['caseCommitments'], attempt['declaredCases'])
                    and len(set(attempt['declaredCases'])) == len(attempt['declaredCases'])
                    and not set(attempt['declaredCases']) & set(statuses)
                    and isinstance(attempt['observations'], list)
                    and len(attempt['observations']) == len(attempt['declaredCases'])):
                raise ValueError('workload-attempt-invalid')
            attempt_probes = {target['probeDigest'] for target in attempt['targets'].values()}
            operations = set(attempt['caseCommitments'].values())
            if attempt_probes & operations:
                raise ValueError('workload-commitment-reused')
            attempt_probes |= operations
            if probe_commitments & attempt_probes:
                raise ValueError('workload-probe-reused-across-attempts')
            probe_commitments.update(attempt_probes)
            observed = {}
            for row in attempt['observations']:
                status = observation_status(row, expected_identity, attempt['principals'], attempt['targets'],
                                            attempt['caseCommitments'], attempt['appProcess'])
                if row['caseId'] in observed:
                    raise ValueError('workload-duplicate-observation')
                observed[row['caseId']] = status
            if set(observed) != set(attempt['declaredCases']):
                raise ValueError('workload-roster-mismatch')
            statuses.update(observed)
        except (KeyError, TypeError, ValueError):
            valid = False
    accepted = valid and all(statuses.get(name) == 'passed' for name in CASES)
    return {'schemaVersion': 1, 'kind': 'pr314-workload-assessment', 'contract': CONTRACT,
            'profile': PROFILE, 'recordContractValid': valid, 'cases': inventory(statuses),
            'installedWorkloadAcceptanceSatisfied': accepted,
            'finiteNativeAcceptanceSatisfied': False, 'productionAuthorityObserved': False,
            'protectedExecutionEligible': False, 'phase12Complete': False}
