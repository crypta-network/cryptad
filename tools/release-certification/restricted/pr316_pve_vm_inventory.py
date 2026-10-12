#!/usr/bin/python3
"""Root PVE inventory receipt required before a PR-316 copied-VM allocation."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time


TASK_ROOT = Path('/mnt/tank1/files/pr315-workload-acceptance')
VISIBLE_ROOT = Path('/work/pr315-task/host-inventory')
QEMU_ROOTS = ('/work/pr315-task/', '/mnt/tank1/files/pr315-workload-acceptance/')
MAX_ENTRIES = 500000
PHASES = ('pre', 'final')


@contextmanager
def _pinned_receipt_directory(root=TASK_ROOT, task_uid=101000, receipt_uid=0):
    """Open the PVE task and receipt directories without following CT-controlled links."""
    root_descriptor = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    directory_descriptor = None
    try:
        root_info = os.fstat(root_descriptor)
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != task_uid
                or root_info.st_mode & 0o077):
            raise ValueError('pr316-pve-inventory-task-root-invalid')
        try:
            os.mkdir('host-inventory', 0o755, dir_fd=root_descriptor)
        except FileExistsError:
            pass
        directory_descriptor = os.open(
            'host-inventory', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
            os.O_CLOEXEC, dir_fd=root_descriptor)
        directory_info = os.fstat(directory_descriptor)
        if (not stat.S_ISDIR(directory_info.st_mode)
                or directory_info.st_uid != receipt_uid
                or directory_info.st_dev != root_info.st_dev
                or directory_info.st_mode & 0o022):
            raise ValueError('pr316-pve-inventory-directory-invalid')
        os.fchmod(directory_descriptor, 0o755)
        yield directory_descriptor
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        os.close(root_descriptor)


def _allocated_bytes(root):
    device = root.stat().st_dev
    total = count = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in [None, *files]:
            path = Path(directory) if name is None else Path(directory) / name
            info = path.lstat()
            count += 1
            if (count > MAX_ENTRIES or info.st_dev != device
                    or stat.S_ISLNK(info.st_mode)):
                raise ValueError('pr316-pve-storage-inventory-invalid')
            total += info.st_blocks * 512
        for name in directories:
            info = (Path(directory) / name).lstat()
            if info.st_dev != device or stat.S_ISLNK(info.st_mode):
                raise ValueError('pr316-pve-storage-inventory-invalid')
    return total


def _task_qemu_command(arguments):
    """Recognize direct or fixed copied-loader QEMU invocations under the task roots."""
    if not arguments:
        return False
    if 'qemu-system-' in Path(arguments[0]).name:
        qemu_index = 0
    elif (len(arguments) > 4
            and Path(arguments[0]).name.startswith('ld-linux-')
            and arguments[1:3] == ['--inhibit-cache', '--library-path']
            and Path(arguments[0]).parent == Path(arguments[3])
            and 'qemu-system-' in Path(arguments[4]).name):
        qemu_index = 4
    else:
        return False
    return any(any(root in value for root in QEMU_ROOTS)
               for value in arguments[qemu_index:])


def snapshot(proc=Path('/proc'), root=TASK_ROOT):
    """Measure task QEMU processes and actual allocated task storage as PVE root."""
    if os.geteuid() != 0 or not proc.is_dir():
        raise ValueError('pr316-pve-inventory-root-required')
    active = []
    for entry in proc.iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            raw = (entry / 'cmdline').read_bytes()
            arguments = [value.decode('utf-8', 'strict')
                         for value in raw.split(b'\0') if value]
            if not _task_qemu_command(arguments):
                continue
            ticks = int((entry / 'stat').read_text().rsplit(')', 1)[1].split()[19])
            active.append({'pid': int(entry.name), 'startTicks': ticks})
        except FileNotFoundError:
            continue
        except (PermissionError, ProcessLookupError, UnicodeError, ValueError, OSError):
            raise ValueError('pr316-pve-process-inventory-unavailable') from None
    usage = os.statvfs(root)
    return {'observedMonotonicNs': time.monotonic_ns(),
            'activeTaskQemu': sorted(active, key=lambda row: row['pid']),
            'allocatedTaskBytes': _allocated_bytes(root),
            'availableTaskBytes': usage.f_bavail * usage.f_frsize}


def publish(suite, source_commit, observed, phase):
    """Publish one immutable PVE-root receipt into the CT-visible task root."""
    if (os.geteuid() != 0 or phase not in PHASES
            or re.fullmatch(r'suite-[1-9][0-9]*', suite) is None
            or re.fullmatch(r'[0-9a-f]{40}', source_commit) is None
            or observed.get('activeTaskQemu') != []):
        raise ValueError('pr316-pve-inventory-publication-invalid')
    record = {'schemaVersion': 1, 'kind': 'pr316-pve-vm-inventory-v1',
        'suite': suite, 'phase': phase, 'sourceCommit': source_commit,
        'moduleDigest': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'observation': observed}
    filename = suite + '-' + phase + '.json'
    with _pinned_receipt_directory() as directory_descriptor:
        descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o444,
                             dir_fd=directory_descriptor)
        try:
            with os.fdopen(descriptor, 'w', closefd=False) as stream:
                json.dump(record, stream, sort_keys=True, separators=(',', ':'))
                stream.flush()
                os.fsync(stream.fileno())
            os.fchmod(descriptor, 0o444)
            os.fsync(directory_descriptor)
        finally:
            os.close(descriptor)
    return record


def verify_receipt(path, suite, source_commit, phase):
    """Verify the fresh root-PVE receipt from the unprivileged CT runner."""
    if phase not in PHASES or path != VISIBLE_ROOT / (suite + '-' + phase + '.json'):
        raise ValueError('pr316-pve-inventory-receipt-path-invalid')
    parent, info = path.parent.lstat(), path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 65534
            or parent.st_mode & 0o022 or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 65534 or info.st_nlink != 1 or info.st_mode & 0o222
            or not 0 < info.st_size <= 8192):
        raise ValueError('pr316-pve-inventory-receipt-owner-invalid')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        current = os.fstat(descriptor)
        if (current.st_dev, current.st_ino, current.st_size) != (
                info.st_dev, info.st_ino, info.st_size):
            raise ValueError('pr316-pve-inventory-receipt-changed')
        raw = os.read(descriptor, 8193)
    finally:
        os.close(descriptor)
    value = json.loads(raw)
    observation = value.get('observation', {})
    observed = observation.get('observedMonotonicNs')
    if (set(value) != {'schemaVersion', 'kind', 'suite', 'phase', 'sourceCommit',
                       'moduleDigest', 'observation'}
            or value['schemaVersion'] != 1
            or value['kind'] != 'pr316-pve-vm-inventory-v1'
            or value['suite'] != suite or value['phase'] != phase
            or value['sourceCommit'] != source_commit
            or value['moduleDigest'] != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            or type(observed) is not int
            or not 0 <= time.monotonic_ns() - observed <= 120_000_000_000
            or observation.get('activeTaskQemu') != []
            or any(type(observation.get(name)) is not int
                   or observation[name] < 0 for name in
                   ('allocatedTaskBytes', 'availableTaskBytes'))):
        raise ValueError('pr316-pve-inventory-receipt-invalid')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--phase', required=True, choices=PHASES)
    args = parser.parse_args()
    try:
        publish(args.suite, args.source_commit, snapshot(), args.phase)
        result = {'status': 'inventory-published', 'activeTaskQemu': 0}
        code = 0
    except (OSError, ValueError):
        result = {'status': 'inventory-failed', 'activeTaskQemu': None}
        code = 78
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
