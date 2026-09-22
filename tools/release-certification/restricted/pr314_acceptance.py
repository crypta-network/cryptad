"""Closed prospective workload observations, separate from finite native acceptance.

Only an administrator driver over its pinned guest transport may call this verifier with
observations. JSON shape and digests do not authenticate execution. There is deliberately no
report-import CLI or production approval API. Contract tests use synthetic records, which are
not installed observations and must never be published as such.
"""
from dataclasses import dataclass
import re

CONTRACT = 'pr314-workload-roles-v1'
PROFILE = 'debian13-systemd257-workload-v1'
ROLES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')
IDENTITY_FIELDS = ('helperSourceCommit', 'helperSourceTree', 'productSelectionDigest',
                   'bundleIdentity', 'testKitDigest', 'profileDigest', 'bootClosureDigest',
                   'preparedImageDigest', 'fixtureManifestDigest')
STATUSES = frozenset(('passed', 'failed', 'setup-failed', 'not-executed', 'inconclusive'))


@dataclass(frozen=True)
class Case:
    actor: str
    target: str
    outcome: str
    witness: str


CASES = {
    'installed-ready': Case('administrator', 'installation', 'verified', 'identity'),
    'four-role-start': Case('observer', 'four-role-roster', 'running', 'roster'),
    'signed-apphost-child': Case('observer', 'own-app', 'sandboxed', 'app'),
    'own-management': Case('observer', 'own-management', 'connected', 'exchange'),
    'fnp-content-retrieval': Case('observer', 'approved-fnp-links', 'retrieved', 'exchange'),
    'dynamic-app-bootstrap': Case('observer', 'own-app', 'bound-session', 'exchange'),
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


def _witness(case, witness, identity):
    kind = case.witness
    if kind == 'identity':
        return witness == {'profile': PROFILE, 'bundleIdentity': identity['bundleIdentity'],
                           'testKitDigest': identity['testKitDigest']}
    if kind == 'roster':
        return (_closed(witness, ('observerUid', 'roles')) and _roster(witness['roles'])
                and _positive(witness['observerUid'])
                and witness['observerUid'] not in {row['uid'] for row in witness['roles']})
    if kind == 'app':
        return (_closed(witness, ('role', 'provider', 'hostPid', 'namespacePid',
                                 'processEpoch', 'invocationId', 'installedAppDigest'))
                and witness['role'] == 'candidate-sender' and witness['provider'] == 'bubblewrap'
                and all(_positive(witness[key]) for key in ('hostPid', 'namespacePid', 'processEpoch'))
                and _hex(witness['invocationId'], 32) and _hex(witness['installedAppDigest']))
    if kind == 'exchange':
        return (_closed(witness, ('requestDigest', 'expectedResponseDigest', 'responseDigest',
                                 'serverInvocationId', 'serverRequests'))
                and all(_hex(witness[key]) for key in ('requestDigest', 'expectedResponseDigest', 'responseDigest'))
                and witness['responseDigest'] == witness['expectedResponseDigest']
                and _hex(witness['serverInvocationId'], 32) and _positive(witness['serverRequests']))
    if kind == 'resources':
        return (_closed(witness, ('source', 'memoryCurrentBytes', 'pidsCurrent', 'cpuUsageUsec'))
                and witness['source'] == 'cgroup-v2'
                and all(_positive(witness[key]) for key in ('memoryCurrentBytes', 'pidsCurrent', 'cpuUsageUsec')))
    if kind == 'restart':
        return (_closed(witness, ('beforeInvocationId', 'afterInvocationId', 'beforeEpoch',
                                 'afterEpoch', 'beforeStateDigest', 'afterStateDigest', 'deadlineUnchanged'))
                and all(_hex(witness[key], 32) for key in ('beforeInvocationId', 'afterInvocationId'))
                and witness['beforeInvocationId'] != witness['afterInvocationId']
                and _positive(witness['beforeEpoch']) and _positive(witness['afterEpoch'])
                and witness['beforeEpoch'] != witness['afterEpoch']
                and _hex(witness['beforeStateDigest'])
                and witness['beforeStateDigest'] == witness['afterStateDigest']
                and witness['deadlineUnchanged'] is True)
    if kind == 'denial':
        return (_closed(witness, ('actorUid', 'attackStartedNs', 'targetActiveBeforeNs',
                                 'targetActiveAfterNs', 'controlResponseDigest', 'denialSource',
                                 'denialCode', 'unrelatedStateBefore', 'unrelatedStateAfter'))
                and _positive(witness['actorUid'])
                and all(_positive(witness[key]) for key in
                        ('attackStartedNs', 'targetActiveBeforeNs', 'targetActiveAfterNs'))
                and witness['targetActiveBeforeNs'] < witness['attackStartedNs'] < witness['targetActiveAfterNs']
                and _hex(witness['controlResponseDigest'])
                and witness['denialSource'] in ('kernel', 'server', 'controller')
                and witness['denialCode'] in ('EACCES', 'EPERM', 'policy-rejected', 'resource-limit')
                and _hex(witness['unrelatedStateBefore'])
                and witness['unrelatedStateBefore'] == witness['unrelatedStateAfter'])
    if kind == 'lifecycle':
        return (_closed(witness, ('triggerStartedNs', 'terminalObservedNs', 'roles',
                                 'populatedCgroups', 'remainingDescendants', 'retention'))
                and _positive(witness['triggerStartedNs']) and _positive(witness['terminalObservedNs'])
                and witness['triggerStartedNs'] < witness['terminalObservedNs']
                and _roster(witness['roles']) and witness['populatedCgroups'] == []
                and type(witness['remainingDescendants']) is int and witness['remainingDescendants'] == 0
                and witness['retention'] in ('retained', 'cleaned-after-quiescence'))
    return False


def inventory(statuses=None):
    statuses = statuses or {}
    return [{'caseId': name, 'actor': case.actor, 'target': case.target,
             'expectedOutcome': case.outcome, 'status': statuses.get(name, 'not-executed')}
            for name, case in CASES.items()]


def observation_status(record, identity):
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
            and _witness(case, record['witness'], identity)):
        raise ValueError('workload-observation-invalid')
    for key in ('attackStartedNs', 'targetActiveBeforeNs', 'targetActiveAfterNs',
                'triggerStartedNs', 'terminalObservedNs'):
        if key in record['witness'] and not (
                record['startedMonotonicNs'] <= record['witness'][key] <= record['finishedMonotonicNs']):
            raise ValueError('workload-witness-outside-invocation')
    return 'passed'


def verify_attempts(expected_identity, attempts):
    """Check driver records; caller must independently bind transport and source identity."""
    statuses = {}
    valid = _identity(expected_identity) and isinstance(attempts, list) and 0 < len(attempts) <= len(CASES)
    for attempt in attempts if isinstance(attempts, list) and len(attempts) <= len(CASES) else ():
        try:
            if not (_closed(attempt, ('contract', 'identity', 'declaredCases', 'observations',
                                     'guestStopped', 'attemptCompleted'))
                    and attempt['contract'] == CONTRACT and attempt['identity'] == expected_identity
                    and attempt['guestStopped'] is True and attempt['attemptCompleted'] is True
                    and isinstance(attempt['declaredCases'], list) and attempt['declaredCases']
                    and all(isinstance(name, str) and name in CASES for name in attempt['declaredCases'])
                    and len(set(attempt['declaredCases'])) == len(attempt['declaredCases'])
                    and not set(attempt['declaredCases']) & set(statuses)
                    and isinstance(attempt['observations'], list)
                    and len(attempt['observations']) == len(attempt['declaredCases'])):
                raise ValueError('workload-attempt-invalid')
            observed = {}
            for row in attempt['observations']:
                status = observation_status(row, expected_identity)
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
