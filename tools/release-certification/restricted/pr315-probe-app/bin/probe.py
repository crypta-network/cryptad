#!/usr/bin/python3
"""Fixed signed AppHost actor for prospective PR-315 mount-boundary evidence.

This child never reads or emits its AppHost token. Its file is candidate-origin
evidence; the administrator must independently bind the child and active target.
"""
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import time

CLONE_NEWNS = 0x00020000
PROVIDER_CANARY = Path('/var/lib/cryptad-restricted/pr315-provider/pr315-provider-canary')
PROVIDER_TRIGGER = 'pr315-provider-trigger.json'
PROVIDER_RESULT = 'pr315-provider-result.json'
SIBLING_APP_TRIGGER = 'pr315-sibling-app-trigger.json'
SIBLING_APP_RESULT = 'pr315-sibling-app-result.json'
SIBLING_APP_SOURCE = ('10.231.0.1', 19404)
SIBLING_APP_TARGET = ('10.231.0.2', 19402)


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


def provider_authority(data: Path) -> dict:
    """Read only one root-triggered fixed provider canary from the signed child."""
    trigger = data / PROVIDER_TRIGGER
    descriptor = os.open(trigger, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077
                or not 0 < info.st_size <= 512):
            raise ValueError('provider-trigger-unsafe')
        raw = os.read(descriptor, 513)
        if len(raw) != info.st_size or os.fstat(descriptor).st_size != info.st_size:
            raise ValueError('provider-trigger-changed')
    finally:
        os.close(descriptor)
    selected = json.loads(raw)
    nonce = selected.get('nonce') if isinstance(selected, dict) else None
    if (not isinstance(selected, dict) or set(selected) != {
            'schemaVersion', 'kind', 'nonce'}
            or selected['schemaVersion'] != 1
            or selected['kind'] != 'pr315-provider-trigger'
            or not isinstance(nonce, str) or len(nonce) != 64
            or any(part not in '0123456789abcdef' for part in nonce)):
        raise ValueError('provider-trigger-invalid')
    if os.path.lexists(data / PROVIDER_RESULT):
        raise ValueError('provider-result-already-published')
    started = time.monotonic_ns()
    try:
        opened = os.open(PROVIDER_CANARY,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        outcome = {'opened': False,
                   'errno': errno.errorcode.get(error.errno, 'UNKNOWN')}
    else:
        os.close(opened)
        outcome = {'opened': True, 'errno': None}
    result = {'schemaVersion': 1, 'kind': 'pr315-signed-provider-authority-probe',
              'caseId': 'provider-authority', 'nonce': nonce,
              'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
              'startedMonotonicNs': started,
              'finishedMonotonicNs': time.monotonic_ns(),
              'targetPathDigest': hashlib.sha256(os.fsencode(PROVIDER_CANARY)).hexdigest(),
              'outcome': outcome}
    encoded = json.dumps(result, sort_keys=True, separators=(',', ':')).encode()
    if not 0 < len(encoded) <= 2048:
        raise ValueError('provider-result-budget')
    pending = data / ('.' + PROVIDER_RESULT + '.pending')
    destination = data / PROVIDER_RESULT
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.link(pending, destination, follow_symlinks=False)
    pending.unlink()
    return result


def sibling_app(data: Path) -> dict:
    """Emit one fixed signed AppHost SYN toward the active sibling HTTP app."""
    trigger = data / SIBLING_APP_TRIGGER
    descriptor = os.open(trigger, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077
                or not 0 < info.st_size <= 512):
            raise ValueError('sibling-app-trigger-unsafe')
        raw = os.read(descriptor, 513)
        if len(raw) != info.st_size or os.fstat(descriptor).st_size != info.st_size:
            raise ValueError('sibling-app-trigger-changed')
    finally:
        os.close(descriptor)
    selected = json.loads(raw)
    nonce = selected.get('nonce') if isinstance(selected, dict) else None
    if (not isinstance(selected, dict) or set(selected) != {
            'schemaVersion', 'kind', 'nonce'}
            or selected['schemaVersion'] != 1
            or selected['kind'] != 'pr315-sibling-app-trigger'
            or not isinstance(nonce, str) or len(nonce) != 64
            or any(part not in '0123456789abcdef' for part in nonce)):
        raise ValueError('sibling-app-trigger-invalid')
    if os.path.lexists(data / SIBLING_APP_RESULT):
        raise ValueError('sibling-app-result-already-published')
    started = time.monotonic_ns()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as channel:
        channel.settimeout(3)
        try:
            channel.bind(SIBLING_APP_SOURCE)
        except OSError as error:
            outcome = {'connected': False, 'phase': 'bind',
                       'errno': errno.errorcode.get(error.errno, 'UNKNOWN')}
        else:
            try:
                channel.connect(SIBLING_APP_TARGET)
            except TimeoutError:
                outcome = {'connected': False, 'phase': 'connect',
                           'errno': 'ETIMEDOUT'}
            except OSError as error:
                outcome = {'connected': False, 'phase': 'connect',
                           'errno': errno.errorcode.get(error.errno, 'UNKNOWN')}
            else:
                outcome = {'connected': True, 'phase': 'connect', 'errno': None}
    result = {'schemaVersion': 1, 'kind': 'pr315-signed-sibling-app-probe',
              'caseId': 'sibling-app', 'nonce': nonce,
              'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
              'startedMonotonicNs': started,
              'finishedMonotonicNs': time.monotonic_ns(),
              'sourcePort': SIBLING_APP_SOURCE[1],
              'targetEndpointDigest': hashlib.sha256(
                  f'{SIBLING_APP_TARGET[0]}:{SIBLING_APP_TARGET[1]}'.encode()).hexdigest(),
              'outcome': outcome}
    encoded = json.dumps(result, sort_keys=True, separators=(',', ':')).encode()
    if not 0 < len(encoded) <= 2048:
        raise ValueError('sibling-app-result-budget')
    pending = data / ('.' + SIBLING_APP_RESULT + '.pending')
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.link(pending, data / SIBLING_APP_RESULT, follow_symlinks=False)
    pending.unlink()
    return result


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
    first = data / 'pr315-probe-result-first.json'
    second = data / 'pr315-probe-result-second.json'
    if not os.path.lexists(first):
        slot = first
    elif not os.path.lexists(second):
        slot = second
    else:
        raise ValueError('probe-launch-budget-exhausted')
    descriptor = os.open(slot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(record, stream, sort_keys=True, separators=(',', ':'))
        stream.flush()
        os.fsync(stream.fileno())
    target = data / 'pr315-probe-result.json'
    temporary = data / '.pr315-probe-result.new'
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(record, stream, sort_keys=True, separators=(',', ':'))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, target)
    provider_done = sibling_done = False
    while True:
        if not provider_done and os.path.lexists(data / PROVIDER_TRIGGER):
            provider_authority(data)
            provider_done = True
        if not sibling_done and os.path.lexists(data / SIBLING_APP_TRIGGER):
            sibling_app(data)
            sibling_done = True
        time.sleep(1)


if __name__ == '__main__':
    main()
