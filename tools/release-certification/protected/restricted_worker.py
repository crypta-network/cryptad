"""Installed serial controller for administrator-registered, finite local operations.

Peer credentials admit a local principal only. Every new operation separately verifies its
administrator-selected original GitHub job. Results remain in root-owned storage; client copies
are never accepted back as authority. Unknown intent is retained and never automatically rerun.
"""
from __future__ import annotations

from contextlib import contextmanager
import datetime as dt
import hashlib
import os
from pathlib import Path
try:
    import fcntl
    import pwd
except ImportError:
    fcntl = pwd = None
import re
import signal
import socket
import stat
import struct
import sys
import time

# Bootstrap verifies this entire installed closure before importing the worker. Local tests use
# the same repository-owned package root; the socket never supplies an import location.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from restricted_protocol import (BoundaryError, METHODS, MAX_REQUEST, MAX_RESULT,
                                 decode, encode, receive, request, send)

STATE = Path('/var/lib/cryptad-restricted')
OPERATIONS = STATE / 'operations'
CREDENTIAL = Path('/etc/cryptad-certification/restricted-provider.json')
MAX_RECORD = 1024 * 1024
POLICIES = {
    'maintenance-prepare': ('.github/workflows/stable-1.0-maintenance-release.yml', 'freeze-and-validate'),
    'maintenance-validate': ('.github/workflows/stable-1.0-maintenance-release.yml', 'freeze-and-validate'),
    'baseline-prepare': ('.github/workflows/runtime-baseline-approval.yml', 'prepare-runtime-baseline'),
    'baseline-approve': ('.github/workflows/runtime-baseline-approval.yml', 'approve-runtime-baseline'),
    **{method: ('.github/workflows/cross-version-live-network-soak.yml', 'supervise-cross-version')
       for method in METHODS if method.startswith('supervisor-')},
}
JOB_NAMES = {
    'maintenance-prepare': 'Freeze exact bytes or validate a prior frozen Stable maintenance candidate',
    'maintenance-validate': 'Freeze exact bytes or validate a prior frozen Stable maintenance candidate',
}


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def utc(value):
    try:
        result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if result.utcoffset() != dt.timedelta(0):
            raise ValueError()
        return result
    except (ValueError, AttributeError, TypeError):
        raise BoundaryError('restricted-invalid-time') from None


def now():
    return dt.datetime.now(dt.timezone.utc)


def secure(path, *, private=True):
    path = Path(path)
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise BoundaryError('restricted-private-state-unavailable')
    if private and path.stat().st_mode & 0o077:
        raise BoundaryError('restricted-private-state-unavailable')
    return path


def read(path, maximum=MAX_RECORD):
    secure(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise BoundaryError('restricted-private-state-invalid')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(raw) > maximum:
            raise BoundaryError('restricted-private-state-changed')
        return raw
    finally:
        os.close(fd)


def persist(path, value):
    """Create once and fsync both file and directory; never overwrite an intent or result."""
    raw = encode(value)
    if len(raw) > MAX_RESULT:
        raise BoundaryError('restricted-result-limit')
    secure(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def validate_record(value):
    fields = {'schemaVersion', 'method', 'handle', 'bundleIdentity', 'callerUid', 'context',
              'notBefore', 'expiresAt', 'collectUntil', 'inputFiles', 'configurationFiles'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['schemaVersion']) is not int
            or value['schemaVersion'] != 1 or value['method'] not in METHODS
            or re.fullmatch('[0-9a-f]{64}', str(value['handle'])) is None
            or re.fullmatch('[0-9a-f]{64}', str(value['bundleIdentity'])) is None
            or type(value['callerUid']) is not int or value['callerUid'] <= 0):
        raise BoundaryError('restricted-registration-invalid')
    context = value['context']
    if (not isinstance(context, dict) or set(context) != {'sourceCommit', 'runId', 'runAttempt', 'jobId'}
            or re.fullmatch('[0-9a-f]{40}', str(context['sourceCommit'])) is None
            or any(type(context[k]) is not int or not 1 <= context[k] < 2**53
                   for k in ('runId', 'runAttempt', 'jobId'))
            or value['method'].startswith('baseline-') and context['runAttempt'] != 1):
        raise BoundaryError('restricted-registration-context-invalid')
    start, end, collect = map(utc, (value['notBefore'], value['expiresAt'], value['collectUntil']))
    if not start < end <= collect or end - start > dt.timedelta(hours=24) or collect - end > dt.timedelta(days=30):
        raise BoundaryError('restricted-registration-window-invalid')
    for key in ('inputFiles', 'configurationFiles'):
        records = value[key]
        if not isinstance(records, dict) or len(records) > 1024:
            raise BoundaryError('restricted-registration-input-invalid')
        for name, identity in records.items():
            path = Path(name)
            if (not isinstance(name, str) or '..' in path.parts or '\\' in name
                    or (key == 'inputFiles' and (path.is_absolute() or path.as_posix() != name))
                    or (key == 'configurationFiles' and (not path.is_absolute()
                        or not path.is_relative_to('/etc/cryptad-certification')))
                    or not isinstance(identity, dict) or set(identity) != {'digest', 'size'}
                    or re.fullmatch('sha256:[0-9a-f]{64}', str(identity['digest'])) is None
                    or type(identity['size']) is not int or not 0 <= identity['size'] <= 1024**3):
                raise BoundaryError('restricted-registration-input-invalid')
    return value


def check_inputs(record, root):
    from restricted_configuration import require_roster
    require_roster(record['method'], record['configurationFiles'], read)
    inputs = secure(root / 'inputs')
    names = set()
    total = 0
    for directory, directories, files in os.walk(inputs, followlinks=False):
        secure(Path(directory))
        if any((Path(directory) / name).is_symlink() for name in directories):
            raise BoundaryError('restricted-input-link')
        for name in files:
            path = Path(directory) / name
            relative = path.relative_to(inputs).as_posix()
            names.add(relative)
            if len(names) > 1024 or relative not in record['inputFiles']:
                raise BoundaryError('restricted-input-roster-invalid')
            identity = record['inputFiles'][relative]
            raw = read(path, identity['size'])
            total += len(raw)
            if total > 2 * 1024**3 or len(raw) != identity['size'] or digest(raw) != identity['digest']:
                raise BoundaryError('restricted-input-substituted')
    if names != set(record['inputFiles']):
        raise BoundaryError('restricted-input-roster-invalid')
    for name, identity in record['configurationFiles'].items():
        raw = read(Path(name), min(identity['size'], 16 * 1024 * 1024))
        if len(raw) != identity['size'] or digest(raw) != identity['digest']:
            raise BoundaryError('restricted-selection-substituted')


@contextmanager
def original_environment(record):
    """Credential ingress is one administrator-managed expiring read credential file."""
    credential = decode(read(CREDENTIAL, 32768), 32768)
    if (not isinstance(credential, dict) or set(credential) != {'token', 'expiresAt'}
            or not isinstance(credential['token'], str) or not 1 <= len(credential['token']) <= 16384
            or not now() < utc(credential['expiresAt']) <= now() + dt.timedelta(hours=1)):
        raise BoundaryError('restricted-provider-credential-unavailable')
    context = record['context']
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/nonexistent',
                   'GH_TOKEN': credential['token'], 'GITHUB_ACTIONS': 'true',
                   'GITHUB_SHA': context['sourceCommit'], 'GITHUB_RUN_ID': str(context['runId']),
                   'GITHUB_RUN_ATTEMPT': str(context['runAttempt']),
                   'GITHUB_JOB': POLICIES[record['method']][1], 'PYTHONDONTWRITEBYTECODE': '1'}
    previous = dict(os.environ)
    os.environ.clear()
    os.environ.update(environment)
    try:
        yield environment
    finally:
        os.environ.clear()
        os.environ.update(previous)


def authenticate_job(record, environment):
    from original_artifact_authentication import _gh, REPOSITORY
    context = record['context']
    workflow, job_name = POLICIES[record['method']]
    prefix = f'repos/{REPOSITORY}/actions/runs/{context["runId"]}'
    current = _gh(['api', prefix], environment)
    run = _gh(['api', prefix + f'/attempts/{context["runAttempt"]}'], environment)
    if (current.get('run_attempt') != context['runAttempt']
            or run.get('id') != context['runId'] or run.get('run_attempt') != context['runAttempt']
            or run.get('path') != workflow or run.get('head_sha') != context['sourceCommit']
            or run.get('event') != 'workflow_dispatch'
            or run.get('repository', {}).get('full_name') != REPOSITORY
            or run.get('actor', {}).get('login') != 'leumor'
            or run.get('triggering_actor', {}).get('login') != 'leumor'):
        raise BoundaryError('restricted-original-job-rejected')
    job = _gh(['api', f'repos/{REPOSITORY}/actions/jobs/{context["jobId"]}'], environment)
    if (job.get('id') != context['jobId'] or job.get('run_id') != context['runId']
            or job.get('run_attempt') != context['runAttempt']
            or job.get('name') != JOB_NAMES.get(record['method'], job_name)
            or job.get('head_sha') != context['sourceCommit']
            or job.get('status') != 'in_progress'
            or not utc(record['notBefore']) <= utc(job.get('started_at')) <= now()):
        raise BoundaryError('restricted-original-job-rejected')


def dispatch(record, root):
    from restricted_native import owning_boundary
    with owning_boundary():
        if record['method'].startswith('maintenance-'):
            from restricted_maintenance import dispatch as maintenance
            return maintenance(record['method'], root)
        if record['method'] in {'supervisor-authorize', 'supervisor-start', 'supervisor-checkpoint'}:
            # The inherited workload still shares its observer's host UID and writable journal.
            # Do not grant new restricted execution until that separate boundary is implemented.
            raise BoundaryError('restricted-workload-observer-boundary-unavailable')
        from cross_version_supervisor_authority import dispatch_owned
        return dispatch_owned(record['method'])


@contextmanager
def operation_deadline():
    """Bound the complete owner call as well as each owner's individual subprocesses."""
    def expired(_signal, _frame):
        raise BoundaryError('restricted-operation-deadline')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 900)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def require_not_revoked(root, record):
    """Apply current security revocations to execution, collection and original admission."""
    revoked = decode(read(STATE / 'revocations.json'), MAX_RECORD)
    if not isinstance(revoked, list) or any(
            not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None
            for value in revoked):
        raise BoundaryError('restricted-revocation-state-invalid')
    # Any marker, including a dangling symlink, prevents admission. Other lookup errors fail closed.
    try:
        (root / 'revoked.json').lstat()
    except FileNotFoundError:
        operation_revoked = False
    else:
        operation_revoked = True
    if record['bundleIdentity'] in revoked or operation_revoked:
        raise BoundaryError('restricted-operation-revoked')


class Worker:
    def __init__(self, bundle_identity):
        self.bundle_identity = bundle_identity

    def process(self, selected, peer_uid):
        request(encode(selected))
        root = secure(OPERATIONS / selected['handle'])
        record_raw = read(root / 'registration.json')
        record = validate_record(decode(record_raw, MAX_RECORD))
        if (record['handle'] != selected['handle'] or record['callerUid'] != peer_uid
                or peer_uid != pwd.getpwnam('cryptad-runner').pw_uid
                or selected['method'] not in {record['method'], 'collect'}):
            raise BoundaryError('restricted-operation-unavailable')
        # Global security revocation remains authoritative across code rollback and collection.
        require_not_revoked(root, record)
        result_path = root / 'result.json'
        if result_path.exists():
            if now() >= utc(record['collectUntil']):
                raise BoundaryError('restricted-collection-expired')
            result = decode(read(result_path, MAX_RESULT), MAX_RESULT)
            if (not isinstance(result, dict) or set(result) != {'registrationDigest', 'receipt', 'result'}
                    or result.get('registrationDigest') != digest(record_raw)):
                raise BoundaryError('restricted-result-substituted')
            public = result['result']
            expected = {'schemaVersion': 1, 'kind': 'restricted-owner-result',
                        'operationId': record['handle'], 'method': record['method'],
                        'bundleIdentity': record['bundleIdentity'], 'resultDigest': digest(encode(public))}
            if result['receipt'] != expected:
                raise BoundaryError('restricted-result-substituted')
            return {'status': 'complete', 'receipt': result['receipt'], 'result': public}
        if selected['method'] == 'collect':
            raise BoundaryError('restricted-result-unavailable')
        if record['bundleIdentity'] != self.bundle_identity:
            raise BoundaryError('restricted-helper-version-mismatch')
        if not utc(record['notBefore']) <= now() < utc(record['expiresAt']):
            raise BoundaryError('restricted-operation-expired')
        if (root / 'intent.json').exists():
            raise BoundaryError('restricted-reconciliation-required')
        check_inputs(record, root)
        with operation_deadline(), original_environment(record) as environment:
            authenticate_job(record, environment)
            if now() >= utc(record['expiresAt']):
                raise BoundaryError('restricted-operation-expired')
            persist(root / 'intent.json', {'registrationDigest': digest(record_raw),
                    'startedAt': now().isoformat(), 'method': record['method']})
            from restricted_configuration import owning_configuration
            with owning_configuration(record):
                public = dispatch(record, root)
        # No payload controls arbitrary public fields: each owner constructs its closed projection.
        raw = encode(public)
        if len(raw) > MAX_RESULT - 2048:
            raise BoundaryError('restricted-result-limit')
        from cryptad_certification.redaction import scan_value
        if scan_value(public):
            raise BoundaryError('restricted-public-projection-rejected')
        receipt = {'schemaVersion': 1, 'kind': 'restricted-owner-result',
                   'operationId': record['handle'], 'method': record['method'],
                   'bundleIdentity': self.bundle_identity, 'resultDigest': digest(raw)}
        persist(result_path, {'registrationDigest': digest(record_raw), 'receipt': receipt,
                             'result': public})
        return {'status': 'complete', 'receipt': receipt, 'result': public}


def main(*, bundle_identity):
    """Systemd socket activation only; no caller-selected bind path or command options."""
    if (pwd is None or fcntl is None or os.geteuid() != 0 or os.environ.get('LISTEN_PID') != str(os.getpid())
            or os.environ.get('LISTEN_FDS') != '1'):
        raise BoundaryError('restricted-socket-activation-required')
    os.umask(0o077)
    os.chdir('/')
    sys.dont_write_bytecode = True
    secure(OPERATIONS)
    lock_fd = os.open(STATE / 'controller.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    worker = Worker(bundle_identity)
    listener = socket.socket(fileno=3)
    if listener.family != socket.AF_UNIX or listener.getsockname() != '/run/cryptad-restricted/control.sock':
        raise BoundaryError('restricted-socket-activation-required')
    # One in-flight owner operation, backlog configured by the socket unit, no worker pool.
    last_request = 0.0
    while True:
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(5)
            try:
                peer_pid, peer_uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if peer_pid <= 0 or peer_uid != pwd.getpwnam('cryptad-runner').pw_uid:
                    raise BoundaryError('restricted-operation-unavailable')
                if time.monotonic() - last_request < 1:
                    raise BoundaryError('restricted-rate-limit')
                last_request = time.monotonic()
                selected = request(receive(connection, MAX_REQUEST))
                # Additional bytes, SCM_RIGHTS and additional requests never enter an owner API.
                result = worker.process(selected, peer_uid)
                send(connection, result, MAX_RESULT)
            except (ValueError, OSError, KeyError, TypeError, RuntimeError):
                try:
                    send(connection, {'status': 'unavailable'}, MAX_RESULT)
                except OSError:
                    pass
