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
import sys
import time

TARGET = Path('/var/lib/cryptad-cross-version/experiments/pr315-installed-workload/observer-private-canary')
OUTPUT = Path('/node/tmp/pr315-observer-private-read.json')
READY = Path('/node/tmp/pr315-observer-private-read-ready.json')
TRIGGER = Path('/node/tmp/pr315-observer-private-read-trigger.json')


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
    descriptor = os.open(OUTPUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(record, stream, sort_keys=True, separators=(',', ':'))
        stream.flush()
        os.fsync(stream.fileno())
    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()
