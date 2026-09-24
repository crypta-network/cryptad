#!/usr/bin/python3
"""Fixed signed AppHost actor for prospective PR-315 mount-boundary evidence.

This child never reads or emits its AppHost token. Its file is candidate-origin
evidence; the administrator must independently bind the child and active target.
"""
import ctypes
import errno
import json
import os
from pathlib import Path
import time

CLONE_NEWNS = 0x00020000


def mount_escape():
    """Attempt one bounded kernel mount-namespace escape without changing host paths."""
    library = ctypes.CDLL(None, use_errno=True)
    library.unshare.argtypes = [ctypes.c_int]
    library.unshare.restype = ctypes.c_int
    ctypes.set_errno(0)
    started = time.monotonic_ns()
    result = library.unshare(CLONE_NEWNS)
    finished = time.monotonic_ns()
    return {'operation': 'unshare-mount', 'startedMonotonicNs': started,
            'finishedMonotonicNs': finished, 'returnCode': result,
            'errno': errno.errorcode.get(ctypes.get_errno(), 'UNKNOWN') if result else None}


def main():
    if not os.environ.get('CRYPTAD_APP_TOKEN'):
        raise ValueError('apphost-token-required')
    data = Path(os.environ['CRYPTAD_APP_DATA_DIR'])
    if not data.is_absolute() or not data.is_dir():
        raise ValueError('apphost-data-required')
    record = {'schemaVersion': 1, 'kind': 'pr315-signed-apphost-probe',
              'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
              'startedMonotonicNs': time.monotonic_ns(),
              'namespaceInodes': {name: os.stat('/proc/self/ns/' + name).st_ino
                                  for name in ('mnt', 'pid', 'net', 'user')},
              'mountEscape': mount_escape()}
    target = data / 'pr315-probe-result.json'
    temporary = data / '.pr315-probe-result.new'
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(record, stream, sort_keys=True, separators=(',', ':'))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, target)
    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()
