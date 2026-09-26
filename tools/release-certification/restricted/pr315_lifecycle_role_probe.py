#!/usr/bin/python3
"""Measured role-side child created only after a fixed root stop-intent barrier."""
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

READY = Path('/node/tmp/pr315-late-child-ready.json')
TRIGGER = Path('/node/tmp/pr315-late-child-trigger.json')
CHILD = Path('/node/tmp/pr315-late-child-child.json')


def _publish(path, value):
    pending = path.with_name('.' + path.name + '.pending')
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    if not 0 < len(raw) <= 1024:
        raise ValueError('pr315-late-child-output-limit')
    descriptor = os.open(pending,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600)
    try:
        if os.write(descriptor, raw) != len(raw):
            raise ValueError('pr315-late-child-short-write')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.link(pending, path, follow_symlinks=False)
    pending.unlink()


def _wait_trigger(nonce):
    until = time.monotonic() + 60
    while not os.path.lexists(TRIGGER):
        if time.monotonic() >= until:
            raise ValueError('pr315-late-child-trigger-timeout')
        time.sleep(.01)
    descriptor = os.open(TRIGGER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077
                or not 0 < info.st_size <= 512):
            raise ValueError('pr315-late-child-trigger-invalid')
        raw = os.read(descriptor, 513)
        if len(raw) != info.st_size or os.fstat(descriptor).st_size != info.st_size:
            raise ValueError('pr315-late-child-trigger-changed')
    finally:
        os.close(descriptor)
    if json.loads(raw) != {'schemaVersion': 1,
            'kind': 'pr315-late-child-trigger', 'nonce': nonce}:
        raise ValueError('pr315-late-child-trigger-mismatch')


def main():
    if (len(sys.argv) != 3 or not sys.flags.isolated or not sys.flags.no_site
            or re.fullmatch('[0-9a-f]{64}', sys.argv[1]) is None
            or sys.argv[2] != 'late-child'):
        raise ValueError('pr315-late-child-fixed-invocation-required')
    nonce = sys.argv[1]
    _publish(READY, {'schemaVersion': 1,
        'kind': 'pr315-candidate-late-child-ready',
        'caseId': 'late-child', 'nonce': nonce,
        'pid': os.getpid(), 'uid': os.getuid(),
        'observedMonotonicNs': time.monotonic_ns()})
    _wait_trigger(nonce)
    started = time.monotonic_ns()
    child = os.fork()
    if child == 0:
        until = time.monotonic() + 180
        while time.monotonic() < until:
            time.sleep(.1)
        os._exit(0)
    _publish(CHILD, {'schemaVersion': 1,
        'kind': 'pr315-candidate-late-child-created',
        'caseId': 'late-child', 'nonce': nonce,
        'parentPid': os.getpid(), 'childPid': child,
        'uid': os.getuid(), 'startedMonotonicNs': started,
        'observedMonotonicNs': time.monotonic_ns()})
    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()
