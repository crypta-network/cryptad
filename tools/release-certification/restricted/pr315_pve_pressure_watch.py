#!/usr/bin/python3
"""Watch one fixed PR-315 TCG QEMU on PVE using a PID file descriptor.

This is task-private host supervision.  It never signals another PVE VM,
container, service, or a process selected by a user-supplied PID.  A monitor
failure invalidates an installed attempt; the guest runner still owns normal
guest shutdown and evidence collection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import time

from pr315_pve_host_admission import TASK_ROOT, _pressure

CT_ROOT = Path('/work/pr315-task')
GIB = 1024 ** 3
SAMPLE_SECONDS = 2
MAX_SECONDS = 4500
PRELAUNCH_SECONDS = 30
LAUNCH_HEADROOM_SECONDS = 5
LIMITS = {'physical': 5, 'swap': 2, 'memoryPressure': 15, 'ioPressure': 15}


def _meminfo() -> dict:
    selected = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, separator, raw = line.partition(':')
        if separator and key in ('MemAvailable', 'SwapFree'):
            value = raw.split()
            if len(value) != 2 or value[1] != 'kB' or not value[0].isdecimal():
                raise ValueError('pr315-pressure-memory-unavailable')
            selected[key] = int(value[0]) * 1024
    if set(selected) != {'MemAvailable', 'SwapFree'}:
        raise ValueError('pr315-pressure-memory-unavailable')
    return selected


def sample() -> dict:
    memory = _meminfo()
    return {'observedMonotonicNs': time.monotonic_ns(),
            'memAvailableBytes': memory['MemAvailable'],
            'swapFreeBytes': memory['SwapFree'],
            'memoryFullAvg10Pct': _pressure(Path('/proc/pressure/memory')),
            'ioFullAvg10Pct': _pressure(Path('/proc/pressure/io'))}


def step(counters: dict, observation: dict) -> tuple[dict, str | None]:
    """Apply the previously used consecutive-sample pressure thresholds."""
    conditions = {'physical': observation['memAvailableBytes'] < GIB,
                  'swap': observation['swapFreeBytes'] < 2 * GIB,
                  'memoryPressure': observation['memoryFullAvg10Pct'] > 20,
                  'ioPressure': observation['ioFullAvg10Pct'] > 50}
    updated = {name: counters[name] + 1 if conditions[name] else 0 for name in LIMITS}
    action = next((name for name in LIMITS if updated[name] >= LIMITS[name]), None)
    return updated, action


def prelaunch_expired(started: float, seen: bool, observed: float) -> bool:
    """Close an authenticated watcher that never observes its expected QEMU launch."""
    return seen is False and observed - started >= PRELAUNCH_SECONDS


def _start_ticks(pid: int) -> int:
    raw = (Path('/proc') / str(pid) / 'stat').read_text()
    close = raw.rfind(')')
    if close < 0:
        raise ValueError('pr315-pressure-process-stat-invalid')
    fields = raw[close + 2:].split()
    if len(fields) <= 19 or not fields[19].isdecimal():
        raise ValueError('pr315-pressure-process-stat-invalid')
    return int(fields[19])


def _matches_command(command: list[bytes], uid: int, suite: str) -> bool:
    attempt = CT_ROOT / suite / 'attempt-01'
    executable = str(attempt / 'tools/qemu-system-x86_64').encode()
    library = str(attempt / 'boot-runtime/usr/lib/x86_64-linux-gnu').encode()
    loader = library + b'/ld-linux-x86-64.so.2'
    drive = b'file=' + str(attempt / 'guest.qcow2').encode() + b',if=virtio,format=qcow2'
    return (uid == 101000 and len(command) > 8
            and command[:7] == [loader, b'--inhibit-cache', b'--library-path',
                                library, executable, b'-name', b'pr312-disposable']
            and any(command[index:index + 2] == [b'-drive', drive]
                    for index in range(7, len(command) - 1)))


def _loader_matches_process(executable: Path, loader: Path, expected_uid: int = 101000) -> bool:
    """Bind the observed kernel executable inode to the task's copied loader."""
    try:
        expected = loader.lstat()
        actual = executable.stat()
        return (stat.S_ISREG(expected.st_mode) and expected.st_uid == expected_uid
                and expected.st_nlink == 1 and expected.st_mode & 0o022 == 0
                and (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino))
    except OSError:
        return False


def _exact_process(pid: int, suite: str) -> tuple[int, int] | None:
    """Bind CT-mapped UID, private loader, QEMU path and start epoch."""
    directory = Path('/proc') / str(pid)
    try:
        command = (directory / 'cmdline').read_bytes().split(b'\0')
        status = (directory / 'status').read_text()
        uid_line = next(line for line in status.splitlines() if line.startswith('Uid:'))
        uid = int(uid_line.split()[1])
        attempt = TASK_ROOT / suite / 'attempt-01'
        local_executable = attempt / 'tools/qemu-system-x86_64'
        loader = attempt / 'boot-runtime/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'
        qemu = local_executable.lstat()
        if (not _matches_command(command, uid, suite)
                or not stat.S_ISREG(qemu.st_mode) or qemu.st_uid != 101000
                or qemu.st_nlink != 1 or qemu.st_mode & 0o022
                or not _loader_matches_process(directory / 'exe', loader)):
            return None
        return pid, _start_ticks(pid)
    except (OSError, StopIteration, ValueError):
        return None


def _processes(suite: str) -> list[tuple[int, int]]:
    selected = []
    for entry in Path('/proc').iterdir():
        if entry.name.isdecimal():
            value = _exact_process(int(entry.name), suite)
            if value is not None:
                selected.append(value)
    return selected


def _write_once(path: Path, value: dict, mode: int) -> None:
    pending = path.with_name(path.name + '.pending')
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'w', closefd=False) as stream:
            json.dump(value, stream, sort_keys=True, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)
    # A hard link publishes the complete inode without replacing an earlier receipt.
    # The private pending file remains available for diagnosis if publication fails.
    os.link(pending, path, follow_symlinks=False)
    pending.unlink()
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def watch(suite: str, source_commit: str) -> int:
    if (os.geteuid() != 0 or re.fullmatch(r'suite-[1-9][0-9]*', suite) is None
            or re.fullmatch(r'[0-9a-f]{40}', source_commit) is None
            or not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal')):
        raise ValueError('pr315-pressure-watch-owner-or-platform-invalid')
    info = TASK_ROOT.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 101000 or info.st_mode & 0o077:
        raise ValueError('pr315-pressure-watch-task-root-invalid')
    if _processes(suite):
        raise ValueError('pr315-pressure-watch-process-already-started')
    directory = TASK_ROOT / 'host-monitor'
    try:
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
    except FileExistsError:
        pass
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('pr315-pressure-watch-directory-invalid')
    ready = directory / (suite + '.ready.json')
    finished = directory / (suite + '.finished.json')
    stop = directory / (suite + '.stop')
    if finished.exists() or stop.exists():
        raise ValueError('pr315-pressure-watch-output-reused')
    with (directory / (suite + '.private.jsonl')).open('x') as log:
        os.fchmod(log.fileno(), 0o600)
        started = time.monotonic()
        _write_once(ready, {'schemaVersion': 1, 'kind': 'pr315-pve-watch-ready',
                            'suite': suite, 'sourceCommit': source_commit,
                            'moduleDigest': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                            'observedMonotonicNs': time.monotonic_ns()}, 0o444)
        counters = {name: 0 for name in LIMITS}
        tracked = None
        seen = False
        absent_since = None
        action = 'not-started'
        while time.monotonic() - started < MAX_SECONDS:
            processes = _processes(suite)
            if len(processes) > 1:
                action = 'ambiguous-task-process'
                break
            if processes:
                seen = True
                absent_since = None
                if tracked is None:
                    pid, ticks = processes[0]
                    descriptor = os.pidfd_open(pid)
                    if _exact_process(pid, suite) != (pid, ticks):
                        os.close(descriptor)
                        action = 'process-epoch-changed'
                        break
                    tracked = (pid, ticks, descriptor)
                elif processes[0] != tracked[:2]:
                    action = 'process-epoch-changed'
                    break
            elif seen and absent_since is None:
                absent_since = time.monotonic()
            if prelaunch_expired(started, seen, time.monotonic()):
                action = 'stopped-before-launch'
                break
            try:
                observed = sample()
            except (OSError, ValueError):
                action = 'pressure-observation-unavailable'
                break
            observed['taskQemuPid'] = tracked[0] if tracked is not None else None
            log.write(json.dumps(observed, sort_keys=True) + '\n')
            log.flush()
            if processes:
                counters, threshold = step(counters, observed)
                if threshold is not None:
                    action = 'pressure-' + threshold
                    break
            if stop.exists() and not processes:
                action = 'stopped-before-launch' if not seen else 'completed'
                break
            if absent_since is not None and time.monotonic() - absent_since > 10:
                action = 'completed'
                break
            time.sleep(SAMPLE_SECONDS)
        else:
            action = 'watch-deadline-exceeded'
        if tracked is not None:
            pid, ticks, descriptor = tracked
            try:
                if action != 'completed' and _exact_process(pid, suite) == (pid, ticks):
                    poll = select.poll()
                    poll.register(descriptor, select.POLLIN)
                    if not poll.poll(0):
                        signal.pidfd_send_signal(descriptor, signal.SIGTERM)
            finally:
                os.close(descriptor)
        log.flush()
        os.fsync(log.fileno())
        _write_once(finished, {'schemaVersion': 1, 'kind': 'pr315-pve-watch-finished',
                               'suite': suite, 'sourceCommit': source_commit,
                               'moduleDigest': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                               'action': action, 'seenTaskQemu': seen,
                               'finishedMonotonicNs': time.monotonic_ns()}, 0o444)
    return 0 if action == 'completed' else 2


def _ct_record(path: Path, suite: str, kind: str) -> dict:
    base = Path('/work/pr315-task/host-monitor')
    suffix = '.ready.json' if kind == 'pr315-pve-watch-ready' else '.finished.json'
    if path != base / (suite + suffix):
        raise ValueError('pr315-pressure-watch-record-path-invalid')
    directory = path.parent.lstat()
    info = path.lstat()
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 65534
            or directory.st_mode & 0o022 or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 65534 or info.st_mode & 0o222 or info.st_nlink != 1
            or not 0 < info.st_size <= 2048):
        raise ValueError('pr315-pressure-watch-record-owner-invalid')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        current = os.fstat(descriptor)
        if (info.st_dev, info.st_ino, info.st_size) != (
                current.st_dev, current.st_ino, current.st_size):
            raise ValueError('pr315-pressure-watch-record-changed')
        value = json.loads(os.read(descriptor, 2049))
    finally:
        os.close(descriptor)
    if (not isinstance(value, dict) or value.get('schemaVersion') != 1
            or value.get('kind') != kind or value.get('suite') != suite
            or value.get('moduleDigest') != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()):
        raise ValueError('pr315-pressure-watch-record-invalid')
    return value


def verify_ready(suite: str, source_commit: str) -> dict:
    record = _ct_record(Path('/work/pr315-task/host-monitor') /
                        (suite + '.ready.json'), suite, 'pr315-pve-watch-ready')
    ns = record.get('observedMonotonicNs')
    if (set(record) != {'schemaVersion', 'kind', 'suite', 'sourceCommit',
                        'moduleDigest', 'observedMonotonicNs'}
            or record['sourceCommit'] != source_commit or type(ns) is not int
            or not 0 <= time.monotonic_ns() - ns <= 120_000_000_000):
        raise ValueError('pr315-pressure-watch-ready-invalid')
    return record


def wait_ready(suite: str, source_commit: str) -> dict:
    """Complete the fixed prelaunch handshake after atomic receipt publication."""
    until = time.monotonic() + 5
    while True:
        try:
            return verify_ready(suite, source_commit)
        except (OSError, ValueError):
            remaining = until - time.monotonic()
            if remaining <= 0:
                raise ValueError('pr315-pressure-watch-ready-unavailable') from None
            time.sleep(min(.05, remaining))


def verify_launch_ready(suite: str, source_commit: str) -> dict:
    """Require a fresh active watcher with headroom for the immediate QEMU launch."""
    ready = verify_ready(suite, source_commit)
    age = time.monotonic_ns() - ready['observedMonotonicNs']
    if (age < 0 or age >
            (PRELAUNCH_SECONDS - LAUNCH_HEADROOM_SECONDS) * 1_000_000_000):
        raise ValueError('pr315-pressure-watch-launch-ready-expired')
    try:
        _ct_record(Path('/work/pr315-task/host-monitor') /
                   (suite + '.finished.json'), suite,
                   'pr315-pve-watch-finished')
    except FileNotFoundError:
        return ready
    except (OSError, ValueError):
        raise ValueError('pr315-pressure-watch-launch-ready-invalid') from None
    raise ValueError('pr315-pressure-watch-launch-already-finished')


def verify_finished(suite: str, source_commit: str, ready: dict) -> dict:
    record = _ct_record(Path('/work/pr315-task/host-monitor') /
                        (suite + '.finished.json'), suite, 'pr315-pve-watch-finished')
    if (set(record) != {'schemaVersion', 'kind', 'suite', 'sourceCommit',
                        'moduleDigest', 'action', 'seenTaskQemu', 'finishedMonotonicNs'}
            or record['sourceCommit'] != source_commit or record['action'] != 'completed'
            or record['seenTaskQemu'] is not True
            or type(record['finishedMonotonicNs']) is not int
            or record['finishedMonotonicNs'] <= ready['observedMonotonicNs']):
        raise ValueError('pr315-pressure-watch-finished-invalid')
    return record


def verify_stopped_before_launch(suite: str, source_commit: str,
                                 ready: dict) -> dict:
    """Authenticate a watcher closed before any task QEMU was observed."""
    observed_ready = _ct_record(Path('/work/pr315-task/host-monitor') /
        (suite + '.ready.json'), suite, 'pr315-pve-watch-ready')
    if (observed_ready != ready
            or set(observed_ready) != {'schemaVersion', 'kind', 'suite',
                                      'sourceCommit', 'moduleDigest',
                                      'observedMonotonicNs'}
            or observed_ready['sourceCommit'] != source_commit
            or type(observed_ready['observedMonotonicNs']) is not int):
        raise ValueError('pr315-pressure-watch-ready-changed')
    record = _ct_record(Path('/work/pr315-task/host-monitor') /
                        (suite + '.finished.json'), suite, 'pr315-pve-watch-finished')
    if (set(record) != {'schemaVersion', 'kind', 'suite', 'sourceCommit',
                        'moduleDigest', 'action', 'seenTaskQemu', 'finishedMonotonicNs'}
            or record['sourceCommit'] != source_commit
            or record['action'] != 'stopped-before-launch'
            or record['seenTaskQemu'] is not False
            or type(record['finishedMonotonicNs']) is not int
            or not ready['observedMonotonicNs'] <
                record['finishedMonotonicNs'] <=
                ready['observedMonotonicNs'] + MAX_SECONDS * 1_000_000_000):
        raise ValueError('pr315-pressure-watch-prelaunch-stop-invalid')
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', required=True)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    return watch(args.suite, args.source_commit)


if __name__ == '__main__':
    raise SystemExit(main())
