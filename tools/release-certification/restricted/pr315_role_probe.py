#!/usr/bin/python3
"""Fixed candidate-role process used by the measured PR-315 test kit.

The administrator independently observes this process and its active target.
This child cannot authorize a case or supply its own trusted identity.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time

TARGET = Path('/var/lib/cryptad-cross-version/experiments/pr315-installed-workload/observer-private-canary')
SIBLING = Path('/var/lib/cryptad-restricted-workload/state/candidate-recipient/pr315-sibling-data-canary')
PACKAGE = Path('/package/lib/cryptad.jar')
CGROUP_TARGET = Path('/sys/fs/cgroup/system.slice/cryptad-workload@candidate-recipient.service/cgroup.procs')
OUTPUT = Path('/node/tmp/pr315-observer-private-read.json')
READY = Path('/node/tmp/pr315-observer-private-read-ready.json')
TRIGGER = Path('/node/tmp/pr315-observer-private-read-trigger.json')
SIBLING_ADDRESS = '10.231.0.2'
NETWORK_CASES = {'sibling-fcp': (19401, 'pr315-sibling-fcp'),
                 'sibling-http': (19402, 'pr315-sibling-http')}


def attempt_network(case_id: str, nonce: str) -> dict:
    """Emit one finite TCP SYN from the actual candidate role network namespace."""
    if case_id not in NETWORK_CASES:
        raise ValueError('pr315-network-case-invalid')
    port, _prefix = NETWORK_CASES[case_id]
    started = time.monotonic_ns()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as channel:
            channel.settimeout(2)
            channel.connect((SIBLING_ADDRESS, port))
    except TimeoutError:
        outcome = {'connected': False, 'errno': 'ETIMEDOUT'}
    except OSError as error:
        outcome = {'connected': False,
                   'errno': errno.errorcode.get(error.errno, 'UNKNOWN')}
    else:
        outcome = {'connected': True, 'errno': None}
    return {'schemaVersion': 1, 'kind': 'pr315-candidate-network-probe',
            'caseId': case_id, 'nonce': nonce, 'pid': os.getpid(),
            'uid': os.getuid(), 'gid': os.getgid(),
            'startedMonotonicNs': started, 'finishedMonotonicNs': time.monotonic_ns(),
            'targetEndpointDigest': hashlib.sha256(
                f'{SIBLING_ADDRESS}:{port}'.encode()).hexdigest(),
            'outcome': outcome}


def wait_network_trigger(case_id: str, nonce: str) -> Path:
    if case_id not in NETWORK_CASES:
        raise ValueError('pr315-network-case-invalid')
    _port, prefix = NETWORK_CASES[case_id]
    trigger = Path('/node/tmp') / (prefix + '-trigger.json')
    until = time.monotonic() + 60
    while not trigger.exists():
        if time.monotonic() >= until:
            raise ValueError('pr315-network-trigger-timeout')
        time.sleep(.05)
    descriptor = os.open(trigger, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor) as stream:
        selected = json.load(stream)
    if selected != {'caseId': case_id, 'nonce': nonce}:
        raise ValueError('pr315-network-trigger-invalid')
    return Path('/node/tmp') / (prefix + '-result.json')


def publish_network_result(case_id: str, nonce: str) -> None:
    result_path = wait_network_trigger(case_id, nonce)
    raw = json.dumps(attempt_network(case_id, nonce), sort_keys=True,
                     separators=(',', ':')).encode()
    if len(raw) > 4096:
        raise ValueError('pr315-network-result-limit')
    descriptor = os.open(result_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def attempt_read(nonce: str) -> dict:
    """Open the existing observer canary from the candidate role sandbox."""
    started = time.monotonic_ns()
    try:
        descriptor = os.open(TARGET, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        outcome = {'opened': False, 'errno': errno.errorcode.get(error.errno, 'UNKNOWN')}
    else:
        os.close(descriptor)
        outcome = {'opened': True, 'errno': None}
    finished = time.monotonic_ns()
    return {'schemaVersion': 1, 'kind': 'pr315-candidate-role-probe',
            'caseId': 'observer-private-read', 'nonce': nonce,
            'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
            'startedMonotonicNs': started, 'finishedMonotonicNs': finished,
            'targetPathDigest': hashlib.sha256(os.fsencode(TARGET)).hexdigest(),
            'outcome': outcome,
            'namespaceInodes': {name: (Path('/proc/self/ns') / name).stat().st_ino
                                for name in ('mnt', 'pid', 'net', 'user')}}


def attempt_write() -> dict:
    """Attempt one finite write to the same observer-owned canary."""
    started = time.monotonic_ns()
    written = 0
    try:
        descriptor = os.open(TARGET, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        outcome = {'opened': False, 'errno': errno.errorcode.get(error.errno, 'UNKNOWN')}
    else:
        try:
            try:
                written = os.write(descriptor, b'pr315!')
            except OSError as error:
                outcome = {'opened': True, 'errno': errno.errorcode.get(error.errno, 'UNKNOWN')}
            else:
                outcome = {'opened': True, 'errno': None}
        finally:
            os.close(descriptor)
    finished = time.monotonic_ns()
    return {'operation': 'observer-private-write', 'startedMonotonicNs': started,
            'finishedMonotonicNs': finished, 'writtenBytes': written, 'outcome': outcome}


def fixed_false_claims() -> tuple[dict, dict]:
    """Publish two deliberately false values for administrator kernel controls."""
    started = time.monotonic_ns()
    identity = {'claimedHostPid': 1, 'claimedHostUid': 0,
                'startedMonotonicNs': started, 'finishedMonotonicNs': time.monotonic_ns()}
    started = time.monotonic_ns()
    counters = {'claimedMemoryCurrentBytes': 0, 'claimedTasksCurrent': 0,
                'startedMonotonicNs': started, 'finishedMonotonicNs': time.monotonic_ns()}
    return identity, counters


def attempt_fixed_access(operation: str, path: Path, payload: bytes | None = None) -> dict:
    """Attempt one fixed role-boundary open and at most six candidate bytes."""
    if (operation, path, payload is None) not in (
            ('sibling-data', SIBLING, True),
            ('package-expectation', PACKAGE, False),
            ('cgroup-migration', CGROUP_TARGET, False)):
        raise ValueError('pr315-role-probe-operation-invalid')
    started = time.monotonic_ns()
    written = 0
    flags = (os.O_RDONLY if payload is None else os.O_WRONLY) | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        outcome = {'opened': False, 'errno': errno.errorcode.get(error.errno, 'UNKNOWN')}
    else:
        try:
            if payload is None:
                outcome = {'opened': True, 'errno': None}
            else:
                if not 1 <= len(payload) <= 6:
                    raise ValueError('pr315-role-probe-payload-invalid')
                try:
                    written = os.write(descriptor, payload)
                except OSError as error:
                    outcome = {'opened': True, 'errno': errno.errorcode.get(error.errno, 'UNKNOWN')}
                else:
                    outcome = {'opened': True, 'errno': None}
        finally:
            os.close(descriptor)
    return {'operation': operation, 'startedMonotonicNs': started,
            'finishedMonotonicNs': time.monotonic_ns(), 'writtenBytes': written,
            'outcome': outcome,
            'targetPathDigest': hashlib.sha256(os.fsencode(path)).hexdigest()}


def main() -> None:
    if (len(sys.argv) != 2 or len(sys.argv[1]) != 64
            or any(value not in '0123456789abcdef' for value in sys.argv[1])
            or not sys.flags.isolated or not sys.flags.no_site):
        raise ValueError('pr315-role-probe-fixed-invocation-required')
    ready = {'schemaVersion': 1, 'kind': 'pr315-candidate-role-probe-ready',
             'caseId': 'observer-private-read', 'nonce': sys.argv[1],
             'pid': os.getpid(), 'startedMonotonicNs': time.monotonic_ns()}
    descriptor = os.open(READY, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(ready, stream, sort_keys=True, separators=(',', ':'))
        stream.flush()
        os.fsync(stream.fileno())
    deadline = time.monotonic() + 30
    while not TRIGGER.exists():
        if time.monotonic() >= deadline:
            raise ValueError('pr315-role-probe-trigger-timeout')
        time.sleep(.05)
    descriptor = os.open(TRIGGER, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as stream:
        trigger = json.load(stream)
    if trigger != {'caseId': 'observer-private-read', 'nonce': sys.argv[1]}:
        raise ValueError('pr315-role-probe-trigger-invalid')
    record = attempt_read(sys.argv[1])
    record['writeAttempt'] = attempt_write()
    record['identityClaim'], record['counterClaim'] = fixed_false_claims()
    record['siblingRead'] = attempt_fixed_access('sibling-data', SIBLING)
    record['packageWrite'] = attempt_fixed_access('package-expectation', PACKAGE, b'pr315!')
    record['cgroupMigration'] = attempt_fixed_access(
        'cgroup-migration', CGROUP_TARGET, str(os.getpid()).encode())
    descriptor = os.open(OUTPUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(record, stream, sort_keys=True, separators=(',', ':'))
        stream.flush()
        os.fsync(stream.fileno())
    for case_id in NETWORK_CASES:
        publish_network_result(case_id, sys.argv[1])
    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()
