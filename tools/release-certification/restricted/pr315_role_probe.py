#!/usr/bin/python3
"""Fixed candidate-role process used by the measured PR-315 test kit.

The administrator independently observes this process and its active target.
This child cannot authorize a case or supply its own trusted identity.
"""
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import time

TARGET = Path('/var/lib/cryptad-cross-version/experiments/pr315-installed-workload/observer-private-canary')
SIBLING = Path('/var/lib/cryptad-restricted-workload/state/candidate-recipient/pr315-sibling-data-canary')
PACKAGE = Path('/package/lib/cryptad.jar')
CGROUP_TARGET = Path('/sys/fs/cgroup/system.slice/cryptad-workload@candidate-recipient.service/cgroup.procs')
RESOLVER_TARGET = Path('/var/lib/cryptad-restricted/resolver/pr315-workload-canary')
OUTPUT = Path('/node/tmp/pr315-observer-private-read.json')
READY = Path('/node/tmp/pr315-observer-private-read-ready.json')
TRIGGER = Path('/node/tmp/pr315-observer-private-read-trigger.json')
ROLE_BOUNDARY_OUTPUT = Path('/node/tmp/pr315-role-boundary.json')
ROLE_BOUNDARY_READY = Path('/node/tmp/pr315-role-boundary-ready.json')
ROLE_BOUNDARY_TRIGGER = Path('/node/tmp/pr315-role-boundary-trigger.json')
AUTHORITY_OUTPUT = Path('/node/tmp/pr315-authority.json')
AUTHORITY_READY = Path('/node/tmp/pr315-authority-ready.json')
AUTHORITY_TRIGGER = Path('/node/tmp/pr315-authority-trigger.json')
HOSTILE_ORIGIN_INPUT = Path('/node/tmp/pr315-hostile-origin-input.json')
HOSTILE_ORIGIN = 'http://127.0.0.1:1'
HOSTILE_ORIGIN_PORT = 19402
HOSTILE_ORIGIN_ENDPOINT = '/api/v1/app-data/status'
NETWORK_APP_READY = Path('/node/tmp/pr315-network-app-ready.json')
SETSID_READY = Path('/node/tmp/pr315-setsid-double-fork-ready.json')
SETSID_TRIGGER = Path('/node/tmp/pr315-setsid-double-fork-trigger.json')
SETSID_RESULT = Path('/node/tmp/pr315-setsid-double-fork-result.json')
SETSID_CHILD_READY = Path('/node/tmp/pr315-setsid-double-fork-child.json')
SIBLING_ADDRESS = '10.231.0.2'
NETWORK_CASES = {'sibling-fcp': (19401, 'pr315-sibling-fcp'),
                 'sibling-http': (19402, 'pr315-sibling-http')}
HOST_CASE = ('host-network', '10.0.2.15', 19405, 'pr315-host-network')
OUTPUT_CANARY = Path('/node/tmp/pr315-output-target-canary')
OUTPUT_SYMLINK = Path('/node/tmp/pr315-output-symlink-artifact')
OUTPUT_SYMLINK_READY = Path('/node/tmp/pr315-output-symlink-ready.json')
OUTPUT_SYMLINK_TRIGGER = Path('/node/tmp/pr315-output-symlink-trigger.json')
OUTPUT_SYMLINK_RESULT = Path('/node/tmp/pr315-output-symlink-result.json')
OUTPUT_FIFO = Path('/node/tmp/pr315-output-fifo-artifact')
OUTPUT_FIFO_READY = Path('/node/tmp/pr315-output-fifo-ready.json')
OUTPUT_FIFO_TRIGGER = Path('/node/tmp/pr315-output-fifo-trigger.json')
OUTPUT_FIFO_RESULT = Path('/node/tmp/pr315-output-fifo-result.json')
OUTPUT_HARDLINK = Path('/node/tmp/pr315-output-hardlink-artifact')
OUTPUT_HARDLINK_READY = Path('/node/tmp/pr315-output-hardlink-ready.json')
OUTPUT_HARDLINK_TRIGGER = Path('/node/tmp/pr315-output-hardlink-trigger.json')
OUTPUT_HARDLINK_RESULT = Path('/node/tmp/pr315-output-hardlink-result.json')
OUTPUT_FLOOD = Path('/node/tmp/pr315-output-flood-artifact')
OUTPUT_FLOOD_READY = Path('/node/tmp/pr315-output-flood-ready.json')
OUTPUT_FLOOD_TRIGGER = Path('/node/tmp/pr315-output-flood-trigger.json')
OUTPUT_FLOOD_RESULT = Path('/node/tmp/pr315-output-flood-result.json')
OUTPUT_FLOOD_BYTES = 65537
OUTPUT_REPLACEMENT = Path('/node/tmp/pr315-output-replacement-artifact')
OUTPUT_REPLACEMENT_READY = Path('/node/tmp/pr315-output-replacement-ready.json')
OUTPUT_REPLACEMENT_TRIGGER = Path('/node/tmp/pr315-output-replacement-trigger.json')
OUTPUT_REPLACEMENT_RESULT = Path('/node/tmp/pr315-output-replacement-result.json')
OUTPUT_REPLACEMENT_SWAP_TRIGGER = Path('/node/tmp/pr315-output-replacement-swap-trigger.json')
OUTPUT_REPLACEMENT_SWAP_RESULT = Path('/node/tmp/pr315-output-replacement-swap-result.json')
OUTPUT_REPLACEMENT_NEXT = Path('/node/tmp/pr315-output-replacement-next')


def _publish_record(path: Path, value: dict) -> None:
    """Expose complete, exclusive role output after the inode is synced."""
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    if not 0 < len(raw) <= 4096:
        raise ValueError('pr315-role-probe-output-limit')
    pending = path.with_name(path.name + '.pending')
    descriptor = os.open(pending,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.link(pending, path, follow_symlinks=False)
    pending.unlink()


def attempt_network(case_id: str, nonce: str) -> dict:
    """Emit one finite TCP SYN from the actual candidate role network namespace."""
    if case_id not in NETWORK_CASES and case_id != HOST_CASE[0]:
        raise ValueError('pr315-network-case-invalid')
    address, port = ((SIBLING_ADDRESS, NETWORK_CASES[case_id][0])
                     if case_id in NETWORK_CASES else (HOST_CASE[1], HOST_CASE[2]))
    started = time.monotonic_ns()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as channel:
            channel.settimeout(2)
            channel.connect((address, port))
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
                f'{address}:{port}'.encode()).hexdigest(),
            'outcome': outcome}


def wait_network_trigger(case_id: str, nonce: str) -> Path:
    if case_id not in NETWORK_CASES and case_id != HOST_CASE[0]:
        raise ValueError('pr315-network-case-invalid')
    prefix = (NETWORK_CASES[case_id][1] if case_id in NETWORK_CASES
              else HOST_CASE[3])
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
    _publish_record(result_path, attempt_network(case_id, nonce))


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


def attempt_hostile_origin(nonce: str) -> dict:
    """Use one valid browser session but a fixed wrong Origin from this role."""
    descriptor = os.open(HOSTILE_ORIGIN_INPUT,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077
                or not 0 < info.st_size <= 8192):
            raise ValueError('pr315-hostile-origin-input-unsafe')
        raw = os.read(descriptor, 8193)
        if len(raw) != info.st_size or os.fstat(descriptor).st_size != info.st_size:
            raise ValueError('pr315-hostile-origin-input-changed')
    finally:
        os.close(descriptor)
    selected = json.loads(raw)
    if (not isinstance(selected, dict) or set(selected) != {
            'caseId', 'nonce', 'session', 'expectedOrigin'}
            or selected['caseId'] != 'hostile-app-origin'
            or selected['nonce'] != nonce
            or not isinstance(selected['session'], str)
            or not 1 <= len(selected['session']) <= 4096
            or not selected['session'].isascii()
            or any(ord(character) < 33 or ord(character) > 126
                   for character in selected['session'])
            or not isinstance(selected['expectedOrigin'], str)
            or re.fullmatch(r'http://127\.0\.0\.1:[1-9][0-9]{3,4}',
                            selected['expectedOrigin']) is None
            or selected['expectedOrigin'] == HOSTILE_ORIGIN):
        raise ValueError('pr315-hostile-origin-input-invalid')

    def request(origin: str) -> dict:
        started = time.monotonic_ns()
        connection = http.client.HTTPConnection('127.0.0.1', HOSTILE_ORIGIN_PORT,
                                                timeout=5)
        try:
            connection.request('GET', HOSTILE_ORIGIN_ENDPOINT, headers={
                'Accept': 'application/json', 'Origin': origin,
                'X-Crypta-App-Session': selected['session']})
            response = connection.getresponse()
            body = response.read(65537)
            if len(body) > 65536:
                raise ValueError('pr315-hostile-origin-response-limit')
            value = json.loads(body)
            error = value.get('error') if isinstance(value, dict) else None
            return {'status': response.status,
                    'errorCode': error.get('code') if isinstance(error, dict) else None,
                    'responseDigest': hashlib.sha256(body).hexdigest(),
                    'startedMonotonicNs': started,
                    'finishedMonotonicNs': time.monotonic_ns()}
        finally:
            connection.close()

    before = request(selected['expectedOrigin'])
    attack = request(HOSTILE_ORIGIN)
    after = request(selected['expectedOrigin'])
    return {'caseId': 'hostile-app-origin',
            'endpointDigest': hashlib.sha256(HOSTILE_ORIGIN_ENDPOINT.encode()).hexdigest(),
            'sessionDigest': hashlib.sha256(selected['session'].encode()).hexdigest(),
            'expectedOriginDigest': hashlib.sha256(
                selected['expectedOrigin'].encode()).hexdigest(),
            'hostileOriginDigest': hashlib.sha256(HOSTILE_ORIGIN.encode()).hexdigest(),
            'before': before, 'attack': attack, 'after': after}


def attempt_fixed_access(operation: str, path: Path, payload: bytes | None = None) -> dict:
    """Attempt one fixed role-boundary open and at most six candidate bytes."""
    if (operation, path, payload is None) not in (
            ('sibling-data', SIBLING, True),
            ('package-expectation', PACKAGE, False),
            ('cgroup-migration', CGROUP_TARGET, False),
            ('resolver-authority', RESOLVER_TARGET, True)):
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


def publish_output_symlink(nonce: str) -> None:
    """Create one fixed candidate-owned attack object after the root barrier."""
    until = time.monotonic() + 60
    while not OUTPUT_SYMLINK_TRIGGER.exists():
        if time.monotonic() >= until:
            raise ValueError('pr315-output-symlink-trigger-timeout')
        time.sleep(.05)
    descriptor = os.open(OUTPUT_SYMLINK_TRIGGER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor) as stream:
        selected = json.load(stream)
    if selected != {'caseId': 'output-symlink', 'nonce': nonce}:
        raise ValueError('pr315-output-symlink-trigger-invalid')
    started = time.monotonic_ns()
    os.symlink(OUTPUT_CANARY, OUTPUT_SYMLINK)
    finished = time.monotonic_ns()
    record = {'schemaVersion': 1, 'kind': 'pr315-candidate-output-symlink',
              'caseId': 'output-symlink', 'nonce': nonce,
              'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
              'startedMonotonicNs': started, 'finishedMonotonicNs': finished,
              'artifactPathDigest': hashlib.sha256(os.fsencode(OUTPUT_SYMLINK)).hexdigest(),
              'targetPathDigest': hashlib.sha256(os.fsencode(OUTPUT_CANARY)).hexdigest()}
    _publish_record(OUTPUT_SYMLINK_RESULT, record)


def publish_output_fifo(nonce: str) -> None:
    """Create one role-owned FIFO after the fixed administrator barrier."""
    until = time.monotonic() + 60
    while not OUTPUT_FIFO_TRIGGER.exists():
        if time.monotonic() >= until:
            raise ValueError('pr315-output-fifo-trigger-timeout')
        time.sleep(.05)
    descriptor = os.open(OUTPUT_FIFO_TRIGGER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor) as stream:
        selected = json.load(stream)
    if selected != {'caseId': 'output-fifo', 'nonce': nonce}:
        raise ValueError('pr315-output-fifo-trigger-invalid')
    started = time.monotonic_ns()
    os.mkfifo(OUTPUT_FIFO, 0o600)
    finished = time.monotonic_ns()
    record = {'schemaVersion': 1, 'kind': 'pr315-candidate-output-fifo',
              'caseId': 'output-fifo', 'nonce': nonce,
              'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
              'startedMonotonicNs': started, 'finishedMonotonicNs': finished,
              'artifactPathDigest': hashlib.sha256(os.fsencode(OUTPUT_FIFO)).hexdigest(),
              'targetPathDigest': hashlib.sha256(os.fsencode(OUTPUT_CANARY)).hexdigest()}
    _publish_record(OUTPUT_FIFO_RESULT, record)


def publish_output_hardlink(nonce: str) -> None:
    """Link the fixed role canary after the root barrier without changing its bytes."""
    until = time.monotonic() + 60
    while not OUTPUT_HARDLINK_TRIGGER.exists():
        if time.monotonic() >= until:
            raise ValueError('pr315-output-hardlink-trigger-timeout')
        time.sleep(.05)
    descriptor = os.open(OUTPUT_HARDLINK_TRIGGER,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor) as stream:
        selected = json.load(stream)
    if selected != {'caseId': 'output-hardlink', 'nonce': nonce}:
        raise ValueError('pr315-output-hardlink-trigger-invalid')
    started = time.monotonic_ns()
    os.link(OUTPUT_CANARY, OUTPUT_HARDLINK, follow_symlinks=False)
    finished = time.monotonic_ns()
    record = {'schemaVersion': 1, 'kind': 'pr315-candidate-output-hardlink',
              'caseId': 'output-hardlink', 'nonce': nonce,
              'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
              'startedMonotonicNs': started, 'finishedMonotonicNs': finished,
              'artifactPathDigest': hashlib.sha256(os.fsencode(OUTPUT_HARDLINK)).hexdigest(),
              'targetPathDigest': hashlib.sha256(os.fsencode(OUTPUT_CANARY)).hexdigest()}
    _publish_record(OUTPUT_HARDLINK_RESULT, record)


def publish_output_flood(nonce: str) -> None:
    """Write a fixed 65,537-byte role artifact beyond the collector's 64-KiB cap."""
    until = time.monotonic() + 60
    while not OUTPUT_FLOOD_TRIGGER.exists():
        if time.monotonic() >= until:
            raise ValueError('pr315-output-flood-trigger-timeout')
        time.sleep(.05)
    descriptor = os.open(OUTPUT_FLOOD_TRIGGER,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor) as stream:
        selected = json.load(stream)
    if selected != {'caseId': 'output-flood', 'nonce': nonce}:
        raise ValueError('pr315-output-flood-trigger-invalid')
    started = time.monotonic_ns()
    descriptor = os.open(OUTPUT_FLOOD,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    written = 0
    try:
        for _ in range(16):
            written += os.write(descriptor, b'F' * 4096)
        written += os.write(descriptor, b'F')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    finished = time.monotonic_ns()
    if written != OUTPUT_FLOOD_BYTES:
        raise ValueError('pr315-output-flood-write-incomplete')
    record = {'schemaVersion': 1, 'kind': 'pr315-candidate-output-flood',
              'caseId': 'output-flood', 'nonce': nonce,
              'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
              'startedMonotonicNs': started, 'finishedMonotonicNs': finished,
              'artifactPathDigest': hashlib.sha256(os.fsencode(OUTPUT_FLOOD)).hexdigest(),
              'targetPathDigest': hashlib.sha256(os.fsencode(OUTPUT_CANARY)).hexdigest(),
              'writtenBytes': written}
    _publish_record(OUTPUT_FLOOD_RESULT, record)


def publish_output_replacement(nonce: str) -> None:
    """Create one fixed file, then atomically replace it at the root barrier."""
    until = time.monotonic() + 60
    while not OUTPUT_REPLACEMENT_TRIGGER.exists():
        if time.monotonic() >= until:
            raise ValueError('pr315-output-replacement-trigger-timeout')
        time.sleep(.05)
    descriptor = os.open(OUTPUT_REPLACEMENT_TRIGGER,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor) as stream:
        selected = json.load(stream)
    if selected != {'caseId': 'output-replacement', 'nonce': nonce}:
        raise ValueError('pr315-output-replacement-trigger-invalid')
    started = time.monotonic_ns()
    descriptor = os.open(OUTPUT_REPLACEMENT,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        if stream.write(b'A' * 32) != 32:
            raise ValueError('pr315-output-replacement-initial-short-write')
        stream.flush()
        os.fsync(stream.fileno())
    finished = time.monotonic_ns()
    record = {'schemaVersion': 1, 'kind': 'pr315-candidate-output-replacement',
              'caseId': 'output-replacement', 'nonce': nonce,
              'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
              'startedMonotonicNs': started, 'finishedMonotonicNs': finished,
              'artifactPathDigest': hashlib.sha256(
                  os.fsencode(OUTPUT_REPLACEMENT)).hexdigest(),
              'targetPathDigest': hashlib.sha256(os.fsencode(OUTPUT_CANARY)).hexdigest()}
    _publish_record(OUTPUT_REPLACEMENT_RESULT, record)
    while not OUTPUT_REPLACEMENT_SWAP_TRIGGER.exists():
        if time.monotonic() >= until:
            raise ValueError('pr315-output-replacement-swap-timeout')
        time.sleep(.02)
    descriptor = os.open(OUTPUT_REPLACEMENT_SWAP_TRIGGER,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor) as stream:
        selected = json.load(stream)
    if selected != {'caseId': 'output-replacement', 'nonce': nonce}:
        raise ValueError('pr315-output-replacement-swap-invalid')
    swap_started = time.monotonic_ns()
    descriptor = os.open(OUTPUT_REPLACEMENT_NEXT,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        if stream.write(b'B' * 32) != 32:
            raise ValueError('pr315-output-replacement-next-short-write')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(OUTPUT_REPLACEMENT_NEXT, OUTPUT_REPLACEMENT)
    swap_finished = time.monotonic_ns()
    swapped = {'schemaVersion': 1, 'kind': 'pr315-candidate-output-replacement-swap',
               'caseId': 'output-replacement', 'nonce': nonce, 'pid': os.getpid(),
               'startedMonotonicNs': swap_started,
               'finishedMonotonicNs': swap_finished}
    _publish_record(OUTPUT_REPLACEMENT_SWAP_RESULT, swapped)


def publish_setsid_double_fork(nonce: str) -> None:
    """Create one detached session descendant inside the same role service cgroup."""
    until = time.monotonic() + 30
    while not SETSID_TRIGGER.exists():
        if time.monotonic() >= until:
            raise ValueError('pr315-setsid-trigger-timeout')
        time.sleep(.05)
    descriptor = os.open(SETSID_TRIGGER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor) as stream:
        selected = json.load(stream)
    if selected != {'caseId': 'setsid-double-fork', 'nonce': nonce}:
        raise ValueError('pr315-setsid-trigger-invalid')
    started = time.monotonic_ns()
    first = os.fork()
    if first == 0:
        try:
            os.setsid()
            if os.fork() == 0:
                os.execv('/usr/bin/python3', ['/usr/bin/python3', '-I', '-S', '-B',
                          __file__, nonce, 'setsid-child'])
            os._exit(0)
        except BaseException:
            os._exit(1)
    until = time.monotonic() + 5
    while True:
        child, status = os.waitpid(first, os.WNOHANG)
        if child == first:
            if status != 0:
                raise ValueError('pr315-setsid-first-child-failed')
            break
        if time.monotonic() >= until:
            os.kill(first, 9)
            os.waitpid(first, 0)
            raise ValueError('pr315-setsid-first-child-timeout')
        time.sleep(.02)
    _publish_record(SETSID_RESULT,
        {'schemaVersion': 1, 'kind': 'pr315-candidate-setsid-double-fork',
         'caseId': 'setsid-double-fork', 'nonce': nonce,
         'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
         'firstPid': first, 'startedMonotonicNs': started,
         'finishedMonotonicNs': time.monotonic_ns()})


def main() -> None:
    if (len(sys.argv) != 3 or len(sys.argv[1]) != 64
            or any(value not in '0123456789abcdef' for value in sys.argv[1])
            or sys.argv[2] not in ('observer-private-read', 'role-boundary',
                                   'authority', 'network-app',
                                   'setsid-double-fork', 'setsid-child',
                                   'output-symlink',
                                   'output-fifo', 'output-hardlink', 'output-flood',
                                   'output-replacement')
            or not sys.flags.isolated or not sys.flags.no_site):
        raise ValueError('pr315-role-probe-fixed-invocation-required')
    case_id = sys.argv[2]
    if case_id == 'setsid-child':
        _publish_record(SETSID_CHILD_READY,
            {'schemaVersion': 1, 'kind': 'pr315-candidate-setsid-child',
             'caseId': 'setsid-double-fork', 'nonce': sys.argv[1],
             'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
             'startedMonotonicNs': time.monotonic_ns()})
        while True:
            time.sleep(1)
    ready = {'schemaVersion': 1, 'kind': 'pr315-candidate-role-probe-ready',
             'caseId': case_id, 'nonce': sys.argv[1],
             'pid': os.getpid(), 'startedMonotonicNs': time.monotonic_ns()}
    ready_path = (READY if case_id == 'observer-private-read' else
                  ROLE_BOUNDARY_READY if case_id == 'role-boundary' else
                  AUTHORITY_READY if case_id == 'authority' else
                  NETWORK_APP_READY if case_id == 'network-app' else
                  SETSID_READY if case_id == 'setsid-double-fork' else
                  OUTPUT_FIFO_READY if case_id == 'output-fifo' else
                  OUTPUT_HARDLINK_READY if case_id == 'output-hardlink' else
                  OUTPUT_FLOOD_READY if case_id == 'output-flood' else
                  OUTPUT_REPLACEMENT_READY if case_id == 'output-replacement' else
                  OUTPUT_SYMLINK_READY)
    _publish_record(ready_path, ready)
    if case_id == 'output-symlink':
        publish_output_symlink(sys.argv[1])
        while True:
            time.sleep(1)
    if case_id == 'output-fifo':
        publish_output_fifo(sys.argv[1])
        while True:
            time.sleep(1)
    if case_id == 'output-hardlink':
        publish_output_hardlink(sys.argv[1])
        while True:
            time.sleep(1)
    if case_id == 'output-flood':
        publish_output_flood(sys.argv[1])
        while True:
            time.sleep(1)
    if case_id == 'output-replacement':
        publish_output_replacement(sys.argv[1])
        while True:
            time.sleep(1)
    if case_id == 'network-app':
        for network_case in NETWORK_CASES:
            publish_network_result(network_case, sys.argv[1])
        publish_network_result(HOST_CASE[0], sys.argv[1])
        while True:
            time.sleep(1)
    if case_id == 'setsid-double-fork':
        publish_setsid_double_fork(sys.argv[1])
        while True:
            time.sleep(1)
    if case_id == 'authority':
        deadline = time.monotonic() + 30
        while not AUTHORITY_TRIGGER.exists():
            if time.monotonic() >= deadline:
                raise ValueError('pr315-authority-trigger-timeout')
            time.sleep(.05)
        descriptor = os.open(AUTHORITY_TRIGGER, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor) as stream:
            trigger = json.load(stream)
        if trigger != {'caseId': 'authority', 'nonce': sys.argv[1]}:
            raise ValueError('pr315-authority-trigger-invalid')
        started = time.monotonic_ns()
        identity, counters = fixed_false_claims()
        resolver = attempt_fixed_access('resolver-authority', RESOLVER_TARGET)
        hostile_origin = attempt_hostile_origin(sys.argv[1])
        record = {'schemaVersion': 1, 'kind': 'pr315-candidate-authority-probe',
                  'caseId': 'authority', 'nonce': sys.argv[1],
                  'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
                  'startedMonotonicNs': started,
                  'finishedMonotonicNs': time.monotonic_ns(),
                  'identityClaim': identity, 'counterClaim': counters,
                  'resolverRead': resolver, 'hostileOrigin': hostile_origin}
        _publish_record(AUTHORITY_OUTPUT, record)
        while True:
            time.sleep(1)
    role_boundary = case_id == 'role-boundary'
    trigger_path = ROLE_BOUNDARY_TRIGGER if role_boundary else TRIGGER
    deadline = time.monotonic() + 30
    while not trigger_path.exists():
        if time.monotonic() >= deadline:
            raise ValueError('pr315-role-probe-trigger-timeout')
        time.sleep(.05)
    descriptor = os.open(trigger_path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as stream:
        trigger = json.load(stream)
    if trigger != {'caseId': case_id, 'nonce': sys.argv[1]}:
        raise ValueError('pr315-role-probe-trigger-invalid')
    record = attempt_read(sys.argv[1])
    record['writeAttempt'] = attempt_write()
    if not role_boundary:
        record['identityClaim'], record['counterClaim'] = fixed_false_claims()
    record['siblingRead'] = attempt_fixed_access('sibling-data', SIBLING)
    record['packageWrite'] = attempt_fixed_access('package-expectation', PACKAGE, b'pr315!')
    record['cgroupMigration'] = attempt_fixed_access(
        'cgroup-migration', CGROUP_TARGET, str(os.getpid()).encode())
    if not role_boundary:
        record['resolverRead'] = attempt_fixed_access('resolver-authority', RESOLVER_TARGET)
    _publish_record(ROLE_BOUNDARY_OUTPUT if role_boundary else OUTPUT, record)
    if not role_boundary:
        for network_case in NETWORK_CASES:
            publish_network_result(network_case, sys.argv[1])
    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()
