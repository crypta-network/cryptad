#!/usr/bin/python3
"""Administrator-only revocation at an accepted installed controller request."""


def begin(driver, workload, handoff, result, observer):
    from cross_version_runtime import canonical_digest
    import restricted_workload_revocation_barrier as barrier
    import runtime_snapshot as snapshot
    active = driver.begin_cancellation(workload, handoff, result)
    before = driver.controller_unit_identity(workload)
    authority = workload.ROOT / 'authority'
    marker = workload.ROOT / 'revoked'
    raw = driver.secrets.token_bytes(32)
    nonce = driver.secrets.token_hex(32)
    digest = driver.hashlib.sha256(raw).hexdigest()
    source_digest = driver.hashlib.sha256(driver.Path(barrier.__file__).read_bytes()).hexdigest()
    state = {}

    def prepare_peer(actor):
        campaign = workload.read(workload.ROOT / 'campaign.json')
        if campaign['deadlineMonotonicNs'] != active['campaignDeadlineNs']:
            raise ValueError('workload-revocation-campaign-changed')
        selected = {'schemaVersion': 1, 'policy': barrier.POLICY,
            'caseId': 'revocation-running',
            'nonceDigest': driver.hashlib.sha256(nonce.encode()).hexdigest(),
            'campaign': campaign['generation'], 'bootId': before['bootId'],
            'controllerPid': before['mainPid'],
            'controllerStartTicks': before['mainStartTicks'],
            'observerPid': actor['pid'], 'observerStartTicks': actor['startTicks'],
            'markerDigest': digest, 'sourceDigest': source_digest}
        workload.write(authority / barrier.REQUEST_NAME, selected, create=True)
        state['request'] = selected

    def publish():
        descriptor = driver.os.open(marker, driver.os.O_WRONLY | driver.os.O_CREAT
            | driver.os.O_EXCL | driver.os.O_NOFOLLOW, 0o600)
        try:
            if driver.os.write(descriptor, raw) != len(raw):
                raise ValueError('workload-revocation-marker-short-write')
            driver.os.fsync(descriptor)
            info = driver.os.fstat(descriptor)
            if (not driver.stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_nlink != 1 or info.st_mode & 0o077):
                raise ValueError('workload-revocation-marker-invalid')
            state['markerIdentity'] = [info.st_dev, info.st_ino, info.st_size]
            state['trigger'] = driver.time.monotonic_ns()
        finally:
            driver.os.close(descriptor)

    def release():
        if 'request' in state:
            workload.write(authority / barrier.RELEASE_NAME,
                {'schemaVersion': 1, 'policy': barrier.POLICY, 'nonce': nonce}, create=True)
            state['released'] = driver.time.monotonic_ns()

    try:
        denial = driver._revocation_request(observer,
            handoff['handles']['candidate-sender'], before['mainPid'],
            prepare_peer=prepare_peer, publish=publish)
        after = driver.controller_unit_identity(workload)
        stable = ('invocationId', 'cgroupIdentity', 'bootId', 'mainPid', 'mainStartTicks')
        if (any(before[key] != after[key] for key in stable)
                or not before['observedMonotonicNs'] < state['trigger']
                    < denial['requestStartedNs'] < denial['responseObservedNs']
                    < after['observedMonotonicNs']
                or snapshot.read_file(workload.ROOT, 'revoked', maximum=32, timeout=2) != raw):
            raise ValueError('workload-revocation-target-changed')
        marker_after = marker.lstat()
        if [marker_after.st_dev, marker_after.st_ino, marker_after.st_size] != state['markerIdentity']:
            raise ValueError('workload-revocation-marker-changed')
        for row in active['preRoles']:
            observed = workload.manager(row['role'], 'show')
            if (observed['ActiveState'] != 'active' or observed['SubState'] != 'running'
                    or observed['MainPID'] != str(row['mainPid'])
                    or observed['InvocationID'] != row['managerInvocation']):
                raise ValueError('workload-revocation-sibling-changed')
        until = min(driver.time.monotonic_ns() + 2_000_000_000, active['campaignDeadlineNs'])
        while not driver.os.path.lexists(authority / barrier.PHASE_NAME):
            if driver.time.monotonic_ns() >= until:
                raise ValueError('workload-revocation-denial-proof-unavailable')
            driver.time.sleep(.01)
        proof = workload.read(authority / barrier.PHASE_NAME)
        expected = state['request']
        fields = set(expected) | {'kind', 'acceptedMonotonicNs',
                                 'replyEnqueuedMonotonicNs', 'requestDigest', 'errorCode'}
        if (not isinstance(proof, dict) or set(proof) != fields
                or any(proof[key] != value for key, value in expected.items())
                or proof['kind'] != 'pr315-fixed-revocation-denial'
                or proof['errorCode'] != 'authority-expired-or-revoked'
                or proof['requestDigest'] != denial['requestDigest']
                or not before['observedMonotonicNs'] < proof['acceptedMonotonicNs']
                    < state['trigger'] < denial['requestStartedNs']
                    < proof['replyEnqueuedMonotonicNs'] < driver.time.monotonic_ns()):
            raise ValueError('workload-revocation-denial-proof-invalid')
    finally:
        release()
    event = {'kind': 'revocation-running', 'roles': active['preRoles'],
             'campaignDeadlineNs': active['campaignDeadlineNs'], 'markerDigest': digest}
    return {'schemaVersion': 2, 'kind': 'pr315-administrator-revocation-running',
        'triggerStartedNs': state['trigger'], 'triggerEventDigest': canonical_digest(event)[7:],
        'campaignDeadlineNs': active['campaignDeadlineNs'], 'preRoles': active['preRoles'],
        'markerIdentity': state['markerIdentity'], 'markerDigest': digest,
        'controllerBefore': before, 'controllerAfter': after, **denial,
        'controllerSynchronization': {**proof, 'releaseObservedMonotonicNs': state['released']}}


def complete(driver, workload, context):
    import runtime_snapshot as snapshot
    marker = workload.ROOT / 'revoked'
    info = marker.lstat()
    if ([info.st_dev, info.st_ino, info.st_size] != context['markerIdentity']
            or driver.hashlib.sha256(snapshot.read_file(workload.ROOT, 'revoked',
                maximum=32, timeout=2)).hexdigest() != context['markerDigest']):
        raise ValueError('workload-revocation-marker-changed')
    for row in context['preRoles']:
        role = row['role']
        state = workload.manager(role, 'show')
        receipt = workload.read(workload.ROOT / 'authority' / (role + '-stop.json'))
        if (state['ActiveState'] not in {'inactive', 'failed'}
                or state['SubState'] not in {'dead', 'failed'} or state['MainPID'] != '0'
                or not workload.quiescent(role)
                or any(receipt[key] != row[key] for key in
                       ('role', 'managerInvocation', 'bootId', 'cgroupIdentity'))
                or receipt['membership'] != 'only-stop-helper' or receipt['descendantCgroups'] != 0
                or receipt['startedMonotonicNs'] <= context['responseObservedNs']
                or receipt['startedMonotonicNs'] <=
                    context['controllerSynchronization']['releaseObservedMonotonicNs']):
            raise ValueError('workload-revocation-terminal-mismatch')
    return {**context, 'terminalObservedNs': driver.time.monotonic_ns(),
            'populatedCgroups': [], 'remainingDescendants': 0, 'retention': 'retained'}
