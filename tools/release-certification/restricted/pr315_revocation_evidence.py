#!/usr/bin/python3
"""Trusted host validation of the fixed accepted-request revocation case."""

def case(driver, report, diagnostics, terminal, principals, source):
    """Bind the live revocation marker and refused controller request to owned cleanup."""
    if (not isinstance(diagnostics, dict) or not isinstance(terminal, dict)
            or report.get('guestStopped') is not True
            or terminal.get('cleanupReportedByCaller') is not True):
        return None
    context = diagnostics.get('revocationRunning')
    try:
        fields = {'schemaVersion', 'kind', 'triggerStartedNs', 'triggerEventDigest',
            'campaignDeadlineNs', 'preRoles', 'markerIdentity', 'markerDigest',
            'controllerBefore', 'controllerAfter', 'actor', 'requestDigest',
            'responseDigest', 'requestStartedNs', 'responseObservedNs',
            'terminalObservedNs', 'populatedCgroups', 'remainingDescendants',
            'retention', 'controllerSynchronization'}
        if (not isinstance(context, dict) or set(context) != fields
                or context['schemaVersion'] != 2
                or context['kind'] != 'pr315-administrator-revocation-running'
                or context['populatedCgroups'] != []
                or context['remainingDescendants'] != 0
                or context['retention'] != 'retained'
                or not 0 < context['triggerStartedNs'] < context['campaignDeadlineNs']
                or not context['triggerStartedNs'] < context['requestStartedNs']
                    < context['responseObservedNs'] < context['terminalObservedNs']
                or driver.re.fullmatch('[0-9a-f]{64}', context['markerDigest']) is None
                or not isinstance(context['markerIdentity'], list)
                or len(context['markerIdentity']) != 3
                or any(type(part) is not int or part <= 0
                       for part in context['markerIdentity'])
                or context['markerIdentity'][2] != 32
                or len(context['preRoles']) != len(driver.acceptance.ROLES)):
            return None
        campaign = terminal['controllerRecords']['campaign']
        if (campaign['status'] != 'captured'
                or campaign['record']['state'] != 'terminalizing'
                or campaign['record']['deadlineMonotonicNs'] !=
                    context['campaignDeadlineNs']):
            return None
        before, after = context['controllerBefore'], context['controllerAfter']
        stable = ('invocationId', 'cgroupIdentity', 'bootId', 'mainPid',
                  'mainStartTicks')
        actor = context['actor']
        if not synchronization_valid(driver, context, terminal, source):
            return None
        if (any(before[key] != after[key] for key in stable)
                or not before['observedMonotonicNs'] < context['triggerStartedNs']
                    < context['requestStartedNs'] < context['responseObservedNs']
                    < after['observedMonotonicNs']
                or actor['uid'] != principals['observerUid']
                or type(actor['pid']) is not int or actor['pid'] <= 1
                or type(actor['startTicks']) is not int or actor['startTicks'] <= 0
                or context['responseDigest'] != driver.hashlib.sha256(
                    b'{"error":"restricted-workload-request-failed"}\n').hexdigest()
                or driver.re.fullmatch('[0-9a-f]{64}', context['requestDigest']) is None):
            return None
        rows = context['preRoles']
        if (not all(isinstance(row, dict) and set(row) == {
                'role', 'managerInvocation', 'bootId', 'cgroupIdentity', 'mainPid'}
                for row in rows)
                or {row['role'] for row in rows} != set(driver.acceptance.ROLES)):
            return None
        event = {'kind': 'revocation-running', 'roles': rows,
                 'campaignDeadlineNs': context['campaignDeadlineNs'],
                 'markerDigest': context['markerDigest']}
        if context['triggerEventDigest'] != driver.fixtures.runtime.canonical_digest(event)[7:]:
            return None
        for row in rows:
            role = row['role']
            principal = next(item for item in principals['roles']
                             if item['role'] == role)
            receipt = terminal['stopReceipts'][role]['current']
            record = terminal['controllerRecords'][role]
            if (type(row['mainPid']) is not int or row['mainPid'] <= 0
                    or row['managerInvocation'] != principal['invocationId']
                    or row['bootId'].replace('-', '').lower() != principal['bootId']
                    or driver.fixtures.runtime.canonical_digest({
                        'role': role, 'identity': row['cgroupIdentity']})[7:] !=
                        principal['cgroupDigest']
                    or receipt['status'] != 'captured'
                    or record['status'] != 'captured'
                    or record['record']['stopReason'] != 'controller-reconciliation'):
                return None
            stopped = receipt['record']
            if (any(stopped[key] != row[key] for key in
                    ('role', 'managerInvocation', 'bootId', 'cgroupIdentity'))
                    or stopped['membership'] != 'only-stop-helper'
                    or stopped['descendantCgroups'] != 0
                or stopped['startedMonotonicNs'] <= context['controllerSynchronization'][
                    'releaseObservedMonotonicNs']
                or not context['responseObservedNs'] < stopped['startedMonotonicNs']
                        <= stopped['observedMonotonicNs']
                        <= context['terminalObservedNs']):
                return None
    except (AttributeError, KeyError, StopIteration, TypeError, ValueError):
        return None
    witness = {'caseId': 'revocation-running', 'triggerDigest': '',
        'trigger': {'kind': 'revocation-running',
                    'eventDigest': context['triggerEventDigest']},
        'triggerStartedNs': context['triggerStartedNs'],
        'terminalObservedNs': context['terminalObservedNs'],
        'roles': principals['roles'], 'populatedCgroups': [],
        'remainingDescendants': 0, 'retention': 'retained'}
    commitment = driver.acceptance.payload_commitment('revocation-running', witness)
    witness['triggerDigest'] = commitment
    return witness, {'startedMonotonicNs': context['triggerStartedNs'],
                     'finishedMonotonicNs': context['terminalObservedNs']}, commitment


def synchronization_valid(driver, context, terminal, source):
    """Require a measured root barrier, exact peers, actual denial and release."""
    proof = context.get('controllerSynchronization')
    fields = {'schemaVersion', 'policy', 'caseId', 'nonceDigest', 'campaign', 'bootId',
        'controllerPid', 'controllerStartTicks', 'observerPid', 'observerStartTicks',
        'markerDigest', 'sourceDigest', 'acceptedMonotonicNs', 'kind',
        'requestDigest', 'replyEnqueuedMonotonicNs', 'errorCode', 'releaseObservedMonotonicNs'}
    try:
        before, actor = context['controllerBefore'], context['actor']
        expected = driver.reference.sha256(source /
            'tools/release-certification/protected/restricted_workload_revocation_barrier.py')
        return (isinstance(proof, dict) and set(proof) == fields
            and proof['schemaVersion'] == 1
            and proof['policy'] == 'pr315-revocation-accepted-rpc-v1'
            and proof['caseId'] == 'revocation-running'
            and proof['kind'] == 'pr315-fixed-revocation-denial'
            and proof['errorCode'] == 'authority-expired-or-revoked'
            and proof['sourceDigest'] == expected
            and proof['campaign'] == terminal['controllerRecords']['campaign']['record']['generation']
            and driver.re.fullmatch('[0-9a-f]{64}', str(proof['nonceDigest'])) is not None
            and proof['bootId'] == before['bootId']
            and proof['controllerPid'] == before['mainPid']
            and proof['controllerStartTicks'] == before['mainStartTicks']
            and proof['observerPid'] == actor['pid']
            and proof['observerStartTicks'] == actor['startTicks']
            and proof['requestDigest'] == context['requestDigest']
            and proof['markerDigest'] == context['markerDigest']
            and all(type(proof[key]) is int and proof[key] > 0 for key in (
                'acceptedMonotonicNs', 'replyEnqueuedMonotonicNs', 'releaseObservedMonotonicNs'))
            and before['observedMonotonicNs'] < proof['acceptedMonotonicNs']
                < context['triggerStartedNs'] < context['requestStartedNs']
                < proof['replyEnqueuedMonotonicNs'] < proof['releaseObservedMonotonicNs']
                < context['terminalObservedNs']
            and context['responseObservedNs'] < context['controllerAfter']['observedMonotonicNs']
                < proof['releaseObservedMonotonicNs'])
    except (KeyError, TypeError, AttributeError, OSError, ValueError):
        return False
