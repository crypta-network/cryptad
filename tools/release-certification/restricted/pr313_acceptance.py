"""Finite local native acceptance; never an original protected evidence authority.

Only the administrator-owned test driver supplies observations. The host must first bind its
pinned SSH transport and installed test kit to the independently measured expected identity.
Candidate JSON, historical dimension labels and public reports are not observations. This small
verifier checks the fixed causal record contract; it does not authenticate an arbitrary report
found on disk. Private observations remain private; only inventory statuses are projected.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

CONTRACT = 'pr313-finite-native-v1'
IDENTITY_FIELDS = ('helperSourceCommit', 'helperSourceTree', 'productSourceCommit',
                   'productDigest', 'bundleIdentity', 'testKitDigest', 'profileDigest',
                   'bootClosureDigest', 'preparedImageDigest', 'fixtureManifestDigest')
STATUSES = frozenset(('passed', 'failed', 'setup-failed', 'not-executed', 'inconclusive'))


@dataclass(frozen=True)
class Case:
    operation: str
    layer: str
    prerequisites: tuple[str, ...]
    phase: str
    outcome: str
    witness: str
    cleanup: str = 'native-quiescent'


def _cases():
    result = {
        'reference-identity': Case('reference-boot', 'host', (), 'before-boot',
            'verified', 'reference', 'guest-stopped'),
        'installed-identity': Case('installation.verify', 'administrator',
            ('reference-identity',), 'before-bootstrap', 'verified', 'installation'),
        'bootstrap-ready': Case('bootstrap.main', 'production', ('installed-identity',),
            'ready', 'ready', 'readiness'),
        'socket-wrong-uid': Case('Worker.process', 'production', ('bootstrap-ready',),
            'socket-request', 'denied', 'socket'),
        'socket-unknown-handle': Case('Worker.process', 'production', ('bootstrap-ready',),
            'socket-request', 'denied', 'socket'),
    }
    for name, operation, outcome in (
        ('construction-probe', 'bootstrap-probe', 'accepted'),
        ('package-api', 'package-api', 'owner-validated'),
        ('signed-app', 'app-projection', 'owner-validated'),
        ('wrong-app', 'app-projection', 'rejected'),
        ('wrong-product', 'package-api', 'rejected'),
        ('cms-five-member-context', 'maintenance-prepare', 'owner-validated'),
        ('cms-wrong-recipient', 'maintenance-prepare', 'rejected'),
        ('cms-tampered-envelope', 'maintenance-prepare', 'rejected'),
        ('cms-subject-substitution', 'maintenance-prepare', 'rejected'),
        ('product-selection-native-consumers', 'maintenance-prepare', 'owner-validated'),
    ):
        result[name] = Case(operation, 'synthetic-owner', ('bootstrap-ready',),
                            'native-complete', outcome, 'owner')
    for name in ('setid', 'filecap', 'openat2-hostile', 'descendant-userns', 'device-write',
                 'root-write', 'environment', 'fd', 'proc', 'cross-operation',
                 'pipe-overflow', 'timeout', 'setsid-descendant', 'unexpected-output',
                 'output-symlink', 'output-hardlink-roster', 'output-fifo', 'output-socket',
                 'output-oversize', 'output-race-timeout', 'output-open-timeout'):
        result['hostile-' + name] = Case('package-api' if not name.startswith('output-')
            else 'app-projection', 'synthetic-native', ('construction-probe',),
            'attack-executed', 'quiescent' if name == 'setsid-descendant' else 'rejected', 'native')
    result['openat2-safe'] = Case('package-api', 'synthetic-native', ('construction-probe',),
                                 'attack-executed', 'accepted', 'native')
    for side in ('input', 'output'):
        for mutation in ('inode', 'ancestor', 'symlink', 'hardlink', 'truncation', 'growth'):
            result[side + '-' + mutation] = Case('restricted_native._copy' if side == 'input'
                else 'restricted_native._read_output', 'administrator-toctou',
                ('construction-probe',), ('staging-read' if side == 'input' else 'quiescent-collection-read'), 'rejected', 'mutation')
    result['sibling-control-canary'] = Case('package-api', 'synthetic-native', ('construction-probe',),
                                   'native-network-connect', 'denied', 'canary')
    result['owner-revocation-running'] = Case('require_not_revoked', 'synthetic-owner',
        ('construction-probe',), 'native-running', 'rejected', 'revocation')
    result['worker-revocation-running'] = Case('Worker.process', 'synthetic-owner',
        ('owner-revocation-running',), 'native-running', 'rejected', 'worker-running-revocation')
    result['worker-death-intent'] = Case('Worker.process', 'synthetic-owner',
        ('cms-five-member-context',), 'intent.json', 'reconciliation-required', 'worker-death')
    result['completed-revocation-retry'] = Case('Worker.process', 'synthetic-owner',
        ('retained-exact-retry',), 'result.json', 'revoked', 'worker-completed-revocation')
    for name, phase in (('death-active', 'intent-written'), ('death-running', 'native-running'),
                        ('death-output', 'output-ready')):
        result[name] = Case('restricted_native.run', 'synthetic-owner', ('construction-probe',),
                            phase, 'reconciliation-required', 'death', 'owned-stop-and-retained-active')
    result['worker-death-result'] = Case('Worker.process', 'synthetic-owner', ('package-api',),
        'result.json', 'exact-retained-result', 'worker-death')
    result['retained-exact-retry'] = Case('Worker.process', 'synthetic-owner',
        ('cms-five-member-context',), 'completed-retry', 'exact-retry', 'retry')
    for name in ('public-malformed', 'public-claimed-accepted', 'public-private-fields', 'public-wrong-subject'):
        result[name] = Case('app_subject_projection.produce', 'synthetic-native', ('signed-app',),
                            'owner-semantic-validation', 'rejected', 'semantic-public')
    result['public-adversarial-output'] = Case('Worker.process', 'synthetic-owner',
        ('signed-app',), 'public-export', 'rejected', 'public')
    result['restart-ready'] = Case('bootstrap.main', 'production', ('bootstrap-ready',),
                                   'after-restart', 'ready', 'readiness')
    return result


CASES = _cases()

# Driver availability is distinct from verifier shape coverage and actual execution. Keep this
# source-owned inventory synchronized when a producer starts writing complete causal records.
COMPLETE_EMITTERS = {
    **{name: 'pr312_reference_vm' for name in ('reference-identity', 'installed-identity')},
    **{name: 'disposable_integration' for name in ('bootstrap-ready', 'socket-wrong-uid',
        'socket-unknown-handle', 'construction-probe', 'package-api', 'signed-app',
        'retained-exact-retry', 'restart-ready')},
    **{name: 'test_pr307_product_consumer_integration' for name in ('wrong-product', 'wrong-app',
        'cms-five-member-context', 'cms-wrong-recipient', 'cms-tampered-envelope',
        'cms-subject-substitution', 'product-selection-native-consumers')},
    **{name: 'pr313_public_faults' for name in ('public-malformed', 'public-claimed-accepted',
                                              'public-private-fields', 'public-wrong-subject')},
    **{name: 'pr312_native_faults' if not name.startswith('hostile-output-') else 'pr312_output_faults'
       for name in CASES if name.startswith('hostile-') or name == 'openat2-safe'},
    **{side + '-' + mutation: 'pr313_faults' for side in ('input', 'output')
       for mutation in ('inode', 'ancestor', 'symlink', 'hardlink', 'truncation', 'growth')},
    **{name: 'pr313_faults' for name in ('sibling-control-canary', 'owner-revocation-running',
                                       'death-active', 'death-running', 'death-output')},
    **{name: 'pr313_worker_faults' for name in ('worker-death-intent', 'worker-death-result',
                                              'worker-revocation-running', 'completed-revocation-retry',
                                              'public-adversarial-output')},
}
MISSING_DRIVERS = frozenset()


def implementation_coverage():
    """Do not mistake a verifier adapter or an old dimension string for a completed driver."""
    return [{'caseId': name,
             'status': ('driver-and-record-implemented' if name in COMPLETE_EMITTERS else
                        'driver-missing' if name in MISSING_DRIVERS else 'causal-record-adapter-missing'),
             'emitter': COMPLETE_EMITTERS.get(name)} for name in CASES]


def inventory(statuses=None):
    """The complete fixed matrix remains visible when setup fails or a case is missing."""
    statuses = statuses or {}
    return [{'caseId': name, 'operation': case.operation, 'layer': case.layer,
             'prerequisites': list(case.prerequisites), 'phase': case.phase,
             'witness': case.witness, 'expectedOutcome': case.outcome, 'cleanup': case.cleanup,
             'status': statuses.get(name, 'not-executed')} for name, case in CASES.items()]


def _digest(value, length=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def _sha256(value):
    return isinstance(value, str) and value.startswith('sha256:') and _digest(value[7:])


def _identity(value):
    return (isinstance(value, dict) and set(value) == set(IDENTITY_FIELDS)
            and all(_digest(value[name], 40 if name.endswith(('Commit', 'Tree')) else 64)
                    for name in IDENTITY_FIELDS))


def _closed(value, fields):
    return isinstance(value, dict) and set(value) == set(fields)


def _quiescent(value, retained=False):
    return (_closed(value, ('activeState', 'cgroupPopulated', 'activeRecordPresent'))
            and value['activeState'] in ('inactive', 'failed')
            and value['cgroupPopulated'] is False
            and value['activeRecordPresent'] is retained)


def _timing(witness):
    start, end = witness.get('startedMonotonicNs'), witness.get('finishedMonotonicNs')
    return type(start) is int and type(end) is int and 0 < start < end


def _stat(value):
    return (_closed(value, ('dev', 'ino', 'size', 'nlink'))
            and all(type(item) is int and item >= 0 for item in value.values())
            and value['ino'] > 0 and value['nlink'] > 0)


def _witness(name, case, value, identity):
    """Interpret fixed observer facts, never a guest 'accepted' or 'passed' flag."""
    if not isinstance(value, dict):
        return False
    kind = case.witness
    if kind == 'reference':
        return (_closed(value, ('storageFormat', 'backingFiles', 'externalDataFiles',
            'bootClosureDigest', 'preparedImageDigest', 'snapshotVerified'))
            and value['storageFormat'] == 'qcow2' and value['backingFiles'] == []
            and value['externalDataFiles'] == [] and value['snapshotVerified'] == 'exact-private-copy'
            and all(value[key] == identity[key] for key in ('bootClosureDigest', 'preparedImageDigest')))
    if kind == 'installation':
        return (_closed(value, ('bundleIdentity', 'testKitDigest', 'profileDigest', 'testKitLocation'))
            and value['testKitLocation'] == 'separate-administrator-owned'
            and all(value[key] == identity[key] for key in ('bundleIdentity', 'testKitDigest', 'profileDigest')))
    if kind == 'readiness':
        return (_closed(value, ('Type', 'NotifyAccess', 'ActiveState', 'SubState', 'MainPID'))
            and value['Type'] == 'notify' and value['NotifyAccess'] == 'main'
            and value['ActiveState'] == 'active' and value['SubState'] == 'running'
            and type(value['MainPID']) is int and value['MainPID'] > 0)
    if kind == 'socket':
        return (_closed(value, ('peerClass', 'exitCode', 'stdoutBytes', 'stderrClassification'))
            and value['peerClass'] == ('wrong-uid' if name == 'socket-wrong-uid' else 'runner')
            and type(value['exitCode']) is int
            and value['exitCode'] == (0 if name == 'socket-wrong-uid' else 2)
            and type(value['stdoutBytes']) is int and value['stdoutBytes'] == 0
            and value['stderrClassification'] == ('dac-permission-denied' if name == 'socket-wrong-uid'
                                                   else 'restricted-operation-unavailable'))
    if kind in ('owner', 'native'):
        return (_closed(value, ('operation', 'operationMarker', 'ownerOutcome', 'stdoutDigest',
                                'startedMonotonicNs', 'finishedMonotonicNs'))
            and value['operation'] == case.operation and value['operationMarker'] == name
            and value['ownerOutcome'] == case.outcome and _digest(value['stdoutDigest']) and _timing(value))
    if kind == 'mutation':
        mutation = name.split('-', 1)[1]
        if not (_closed(value, ('mutation', 'barrier', 'before', 'after'))
                and value['mutation'] == mutation and value['barrier'] == ('source-opened' if name.startswith('input-') else 'output-opened')
                and _stat(value['before']) and _stat(value['after'])):
            return False
        before, after = value['before'], value['after']
        if mutation in ('inode', 'ancestor', 'symlink'):
            return (before['dev'], before['ino']) != (after['dev'], after['ino'])
        if mutation == 'hardlink':
            return after['nlink'] > before['nlink']
        return after['size'] < before['size'] if mutation == 'truncation' else after['size'] > before['size']
    if kind == 'canary':
        return (_closed(value, ('controlBefore', 'controlAfter', 'nativeRetrievals', 'distinctServerUid',
                                'marker', 'serverPidStartTime', 'controlResponseDigest', 'expectedCanaryDigest'))
            and value['controlBefore'] == value['controlAfter'] == 'retrieved'
            and type(value['nativeRetrievals']) is int and value['nativeRetrievals'] == 0
            and type(value['distinctServerUid']) is int and value['distinctServerUid'] > 0
            and value['marker'] == 'pr313-active-sibling-denied'
            and type(value['serverPidStartTime']) is int and value['serverPidStartTime'] > 0
            and _sha256(value['expectedCanaryDigest'])
            and value['controlResponseDigest'] == value['expectedCanaryDigest'])
    if kind == 'revocation':
        return (_closed(value, ('registrationDigest', 'revokedDigest', 'candidateMarker', 'revocationObserved'))
            and all(isinstance(value[key], str) and value[key].startswith('sha256:')
                    and _digest(value[key][7:]) for key in ('registrationDigest', 'revokedDigest'))
            and value['candidateMarker'] == 'candidate-started'
            and value['revocationObserved'] == 'restricted-operation-revoked')
    if kind == 'worker-running-revocation':
        return (_closed(value, ('registrationDigest', 'revokedDigest', 'revocationObserved',
                                'nativeProcess', 'retryAndCollect'))
            and all(isinstance(value[key], str) and value[key].startswith('sha256:')
                    and _digest(value[key][7:]) for key in ('registrationDigest', 'revokedDigest'))
            and value['revocationObserved'] == 'restricted-operation-revoked'
            and value['nativeProcess'] == 'java' and value['retryAndCollect'] == 'revoked')
    if kind == 'worker-death':
        return (_closed(value, ('controllerStartTime', 'signal', 'durableDigestBefore',
                                'durableDigestAfter', 'nativeRetryLaunches'))
            and type(value['controllerStartTime']) is int and value['controllerStartTime'] > 0
            and value['signal'] == 'SIGKILL'
            and isinstance(value['durableDigestBefore'], str)
            and value['durableDigestBefore'].startswith('sha256:')
            and _digest(value['durableDigestBefore'][7:])
            and value['durableDigestBefore'] == value['durableDigestAfter']
            and type(value['nativeRetryLaunches']) is int and value['nativeRetryLaunches'] == 0)
    if kind == 'worker-completed-revocation':
        fields = ('controllerStartTime', 'signal', 'durableDigestBefore', 'durableDigestAfter',
                  'nativeRetryLaunches', 'registrationDigest', 'revokedDigest', 'retryAndCollect')
        if not _closed(value, fields):
            return False
        return (_witness(name, Case(case.operation, case.layer, case.prerequisites, case.phase,
                                   case.outcome, 'worker-death'),
                         {key: value[key] for key in fields[:5]}, identity)
            and all(isinstance(value[key], str) and value[key].startswith('sha256:')
                    and _digest(value[key][7:]) for key in ('registrationDigest', 'revokedDigest'))
            and value['retryAndCollect'] == 'revoked')
    if kind == 'death':
        return (_closed(value, ('pidStartTime', 'signal', 'durablePhase', 'retryError', 'nativeLaunchCount',
                                'activeRecordDigestBefore', 'activeRecordDigestAfter'))
            and type(value['pidStartTime']) is int and value['pidStartTime'] > 0
            and value['signal'] == 'SIGKILL' and value['durablePhase'] == case.phase
            and value['retryError'] == 'restricted-native-execution-failed'
            and type(value['nativeLaunchCount']) is int
            and value['nativeLaunchCount'] == (0 if name == 'death-active' else 1)
            and _sha256(value['activeRecordDigestBefore'])
            and value['activeRecordDigestBefore'] == value['activeRecordDigestAfter'])
    if kind == 'retry':
        return (_closed(value, ('retainedDigest', 'responseDigest', 'nativeLaunchCountBefore',
                                'nativeLaunchCountAfter', 'decryptCountBefore', 'decryptCountAfter', 'durablePhase'))
            and _digest(value['retainedDigest']) and value['retainedDigest'] == value['responseDigest']
            and value['durablePhase'] == case.phase
            and all(type(value[key]) is int and value[key] >= 0 for key in (
                'nativeLaunchCountBefore', 'nativeLaunchCountAfter', 'decryptCountBefore', 'decryptCountAfter'))
            and value['nativeLaunchCountBefore'] == value['nativeLaunchCountAfter']
            and value['decryptCountBefore'] == value['decryptCountAfter'])
    if kind == 'semantic-public':
        return (_closed(value, ('candidateOutput', 'semanticOwner', 'publicFields', 'privateCanary',
                                'candidateOutputDigest', 'stdoutDigest'))
            and value['candidateOutput'] == 'collected' and value['semanticOwner'] == 'rejected'
            and value['publicFields'] == 'closed' and value['privateCanary'] == 'absent'
            and _sha256(value['candidateOutputDigest']) and _sha256(value['stdoutDigest']))
    if kind == 'public':
        return (_closed(value, ('candidateOutputDigest', 'clientResponseDigest', 'semanticOwner',
                                'workerResultPresent', 'publicArtifactNames', 'privateCanary', 'failedArtifacts'))
            and all(isinstance(value[key], str) and value[key].startswith('sha256:')
                    and _digest(value[key][7:]) for key in ('candidateOutputDigest', 'clientResponseDigest'))
            and value['semanticOwner'] == 'rejected' and value['workerResultPresent'] is False
            and value['publicArtifactNames'] == ['client.log', 'report.json', 'summary.md']
            and value['privateCanary'] == 'absent' and value['failedArtifacts'] == 'private-only')
    return False


def observation_status(record, identity):
    """Validate one private administrator observation without accepting a supplied verdict."""
    if not isinstance(record, dict) or record.get('caseId') not in CASES:
        raise ValueError('pr313-observation-case-invalid')
    name = record['caseId']
    if set(record) == {'caseId', 'status'} and record['status'] in STATUSES - {'passed'}:
        return record['status']
    if not _closed(record, ('caseId', 'phase', 'outcome', 'managerInvocationId', 'attackWitness', 'quiescent')):
        return 'failed'
    case = CASES[name]
    needs_native = case.witness not in ('reference', 'installation', 'readiness', 'socket') and name not in ('death-active', 'completed-revocation-retry') and not name.startswith(('input-', 'worker-death-'))
    invocation = record['managerInvocationId']
    if (needs_native and not _digest(invocation, 32)) or (not needs_native and invocation is not None):
        return 'failed'
    if record['phase'] != case.phase or record['outcome'] != case.outcome:
        return 'failed'
    if not _quiescent(record['quiescent'], case.cleanup == 'owned-stop-and-retained-active'):
        return 'failed'
    return 'passed' if _witness(name, case, record['attackWitness'], identity) else 'inconclusive'


def verify_attempts(expected_identity, attempts):
    """Derive a local verdict from pinned-transport private driver records.

    ``expected_identity`` is independently measured by the host, never learned from guest JSON.
    Attempts are a predeclared suite under that identity. Duplicate cases are rejected, including
    retry attempts: failures cannot be hidden by choosing later successful rows. Each attempt
    names its declared case group and retains all group rows, including unexecuted cases.
    """
    statuses = {}
    valid = _identity(expected_identity) and isinstance(attempts, list) and 0 < len(attempts) <= len(CASES)
    if isinstance(attempts, list) and len(attempts) <= len(CASES):
        for attempt in attempts:
            if not (_closed(attempt, ('contract', 'identity', 'declaredCases', 'observations', 'guestStopped', 'attemptCompleted'))
                    and attempt['contract'] == CONTRACT and isinstance(attempt['declaredCases'], list)
                    and isinstance(attempt['observations'], list)):
                valid = False
                continue
            admitted = (_identity(expected_identity) and attempt['identity'] == expected_identity
                        and attempt['guestStopped'] is True and attempt['attemptCompleted'] is True)
            if not admitted:
                valid = False
            declared, observations = attempt['declaredCases'], attempt['observations']
            if (not declared or any(not isinstance(name, str) or name not in CASES for name in declared)
                    or len(set(declared)) != len(declared) or set(declared) & set(statuses)
                    or len(observations) != len(declared)):
                valid = False
                continue
            actual = []
            for record in observations:
                try:
                    status = observation_status(record, expected_identity or {})
                    if status == 'passed' and not admitted:
                        status = 'setup-failed'
                    name = record['caseId']
                    actual.append(name)
                    if name in statuses:
                        valid = False
                    statuses[name] = status
                except (ValueError, TypeError, KeyError):
                    valid = False
            if sorted(actual) != sorted(declared):
                valid = False
    # Dependencies remain required even when cases ran in independent disposable guests.
    changed = True
    while changed:
        changed = False
        for name, case in CASES.items():
            if statuses.get(name) == 'passed' and any(statuses.get(dep) != 'passed' for dep in case.prerequisites):
                statuses[name] = 'setup-failed'
                changed = True
    accepted = valid and all(statuses.get(name) == 'passed' for name in CASES)
    return {'schemaVersion': 1, 'kind': 'pr313-finite-native-assessment', 'contract': CONTRACT,
            'evidenceClass': 'local-synthetic-administrator-observation',
            'recordContractValid': valid, 'cases': inventory(statuses),
            'implementationCoverage': implementation_coverage(),
            'installedKeylessNativeAcceptanceSatisfied': accepted,
            'mandatoryIsolationTestSatisfied': False, 'productionAuthorityObserved': False,
            'phase12Complete': False}
