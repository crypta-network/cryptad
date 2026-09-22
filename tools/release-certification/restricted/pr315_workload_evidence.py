"""Fixed private volatile diagnostics for the disposable workload administrator kit.

These observations are not acceptance records or a runtime restore format. The caller owns
cleanup verification; a missing cgroup is never interpreted here as proof of quiescence.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import time

import runtime_snapshot as snapshot

ROOT = Path('/var/lib/cryptad-restricted-workload')
ROLES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')
SENTINEL = 'pr315-retention-sentinel'
MAX_RECORD = 32768
MAX_OUTPUT = 256 * 1024
CAMPAIGN_FIELDS = ('generation', 'bootId', 'state', 'deadlineMonotonicNs', 'usedOperations')
ROLE_FIELDS = ('generation', 'bootId', 'state', 'managerInvocation', 'cgroupIdentity', 'stopReason')


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _installed(workload):
    if os.geteuid() != 0 or workload.ROOT != ROOT or tuple(workload.ROLES) != ROLES:
        raise ValueError('workload-evidence-fixed-administrator-required')


def _wait(pid, deadline):
    while True:
        child, status = os.waitpid(pid, os.WNOHANG)
        if child == pid:
            return status
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('workload-sentinel-child-timeout')
        time.sleep(min(.02, remaining))


def _create(parent, raw):
    """The caller has already selected and pinned the one fixed state directory."""
    fd = os.open(SENTINEL, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=parent)
    try:
        if os.write(fd, raw) != len(raw):
            raise ValueError('workload-sentinel-short-write')
        os.fsync(fd)
    finally:
        os.close(fd)


def prepare_sentinel(workload):
    """After prepare(), before role start: create only a new synthetic 32-byte subject."""
    _installed(workload)
    user = workload.account('candidate-sender')
    if user.pw_uid <= 0 or user.pw_gid <= 0:
        raise ValueError('workload-sentinel-role-owner-invalid')
    if any(workload.read(ROOT / 'authority' / (role + '.json')).get('state') != 'prepared'
           for role in ROLES):
        raise ValueError('workload-sentinel-before-launch-required')
    raw = os.urandom(32)
    root = ROOT / 'state/candidate-sender'
    # No candidate process has run yet. Pin all ancestors and the selected tmpfs before
    # dropping privileges, then create the exclusive leaf as its actual selected owner.
    with snapshot._directory(root) as parent:
        info = os.fstat(parent)
        if (info.st_uid != user.pw_uid or info.st_gid != user.pw_gid
                or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077):
            raise ValueError('workload-sentinel-state-owner-invalid')
        pid = os.fork()
        if pid == 0:
            try:
                os.setgroups([])
                os.setgid(user.pw_gid)
                os.setuid(user.pw_uid)
                os.umask(0o077)
                _create(parent, raw)
                os._exit(0)
            except BaseException:
                os._exit(1)
        try:
            status = _wait(pid, time.monotonic() + 5)
        except TimeoutError:
            os.kill(pid, signal.SIGKILL)
            _wait(pid, time.monotonic() + 5)
            raise
        if status != 0:
            raise ValueError('workload-sentinel-creation-failed')
    actual = snapshot.read_file(root, SENTINEL, maximum=32, timeout=2)
    if actual != raw:
        raise ValueError('workload-sentinel-initial-observation-mismatch')
    return _digest(raw)


def _record(root, name, fields, deadline):
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {'status': 'capture-deadline'}
        raw = snapshot.read_file(root, name, maximum=MAX_RECORD, timeout=min(2, remaining))
        value = json.loads(raw)
        if not isinstance(value, dict):
            return {'status': 'invalid-record'}
        # No candidate values, tokens, handles, selections or arbitrary role-tree entries.
        projection = {key: value[key] for key in fields if key in value}
        if any(type(item) not in (str, int, type(None)) for key, item in projection.items()
               if key != 'cgroupIdentity'):
            return {'status': 'invalid-record'}
        if 'cgroupIdentity' in projection and not (
                projection['cgroupIdentity'] is None or
                isinstance(projection['cgroupIdentity'], list)
                and len(projection['cgroupIdentity']) == 2
                and all(type(part) is int and part >= 0 for part in projection['cgroupIdentity'])):
            return {'status': 'invalid-record'}
        return {'status': 'captured', 'record': projection}
    except (OSError, ValueError, UnicodeError):
        return {'status': 'unavailable-or-unsafe'}


def _capture(root, expected, cleanup_complete):
    """Internal acquisition over the fixed selection; tests use synthetic temporary roots."""
    if not isinstance(expected, str) or re.fullmatch('sha256:[0-9a-f]{64}', expected) is None:
        raise ValueError('workload-sentinel-expected-digest-invalid')
    started = time.monotonic_ns()
    result = {'schemaVersion': 1, 'kind': 'pr315-private-volatile-diagnostics',
        'classification': 'synthetic-private-diagnostic-not-acceptance-or-restore',
        'observedWallTimeNs': time.time_ns(), 'startedMonotonicNs': started,
        'cleanupReportedByCaller': cleanup_complete is True,
        'quiescenceIndependentlyEstablished': False,
        'snapshotLimitations': 'fixed-files-not-atomic-not-runtime-continuation',
        'sentinel': {'status': 'not-captured-cleanup-unverified'}, 'controllerRecords': {}}
    if cleanup_complete is True:
        deadline = time.monotonic() + 15
        result['controllerRecords']['campaign'] = _record(root, 'campaign.json', CAMPAIGN_FIELDS, deadline)
        for role in ROLES:
            result['controllerRecords'][role] = _record(root / 'authority', role + '.json', ROLE_FIELDS, deadline)
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('workload-evidence-deadline')
            raw = snapshot.read_file(root / 'state/candidate-sender', SENTINEL,
                                     maximum=32, timeout=min(2, remaining))
            actual = _digest(raw)
            result['sentinel'] = {'status': 'matched' if len(raw) == 32 and actual == expected else 'changed',
                                  'expectedDigest': expected, 'observedDigest': actual, 'sizeBytes': len(raw)}
        except (OSError, ValueError):
            result['sentinel'] = {'status': 'unavailable-or-unsafe', 'expectedDigest': expected}
    result['finishedMonotonicNs'] = time.monotonic_ns()
    if len(json.dumps(result, sort_keys=True, allow_nan=False).encode()) > MAX_OUTPUT:
        raise ValueError('workload-evidence-output-limit')
    return result


def capture(workload, expected, cleanup_complete):
    """After trusted cleanup: return private bounded observations, never infer acceptance."""
    _installed(workload)
    return _capture(ROOT, expected, cleanup_complete)
