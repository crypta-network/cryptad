#!/usr/bin/env python3
"""PVE-only read-only inventory of a stopped, Mac-archived PR-315 guest.

The Mac coordinator supplies a closed, receipt-bound plan through the pinned
host transport. This tool has no deletion operation and never accepts an
arbitrary path, PID, unit or command.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

TASK = Path('/mnt/tank1/files/pr315-workload-acceptance')
OWNER_UID = 101000
FILES = ('guest.qcow2', 'prepared.qcow2', 'source.tar.gz')
DIRECTORIES = ('cryptad', 'expected-bundle', 'boot-runtime', 'tools')
SUITE = re.compile(r'suite-[1-9][0-9]*\Z')
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode()


def _hash(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def _regular(path, uid, maximum=None):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
            or info.st_nlink != 1
            or maximum is not None and info.st_size > maximum):
        raise ValueError('pr315-cleanup-file-identity-invalid')
    return info


def _directory(path, uid):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
        raise ValueError('pr315-cleanup-directory-identity-invalid')
    return info


def _plan(value):
    if (not isinstance(value, dict) or set(value) != {
            'schemaVersion', 'kind', 'suite', 'sourceCommit',
            'campaignPlanDigest', 'sealedReceiptDigest',
            'macFullArchiveDigest', 'fileDigests'}
            or value['schemaVersion'] != 1
            or value['kind'] != 'pr315-host-success-copy-release-plan-v1'
            or SUITE.fullmatch(str(value['suite'])) is None
            or HEX40.fullmatch(str(value['sourceCommit'])) is None
            or any(HEX64.fullmatch(str(value[key])) is None for key in (
                'campaignPlanDigest', 'sealedReceiptDigest',
                'macFullArchiveDigest'))
            or not isinstance(value['fileDigests'], dict)
            or set(value['fileDigests']) != set(FILES)
            or any(HEX64.fullmatch(str(digest)) is None
                   for digest in value['fileDigests'].values())):
        raise ValueError('pr315-cleanup-plan-invalid')
    return value


def _qemu_processes(base):
    targets = {str(base / 'tools/qemu-system-x86_64').encode(),
        str(Path('/work/pr315-task') / base.relative_to(TASK) /
            'tools/qemu-system-x86_64').encode()}
    found = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            if targets.intersection((entry / 'cmdline').read_bytes().split(b'\0')):
                found.append(int(entry.name))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return found


def _open_users(files, directories):
    file_ids = {(info.st_dev, info.st_ino) for info in files.values()}
    directory_ids = {(info.st_dev, info.st_ino) for info in directories.values()}
    prefixes = tuple(prefix + '/' for path in directories
                     for prefix in (str(path),
                                    str(Path('/work/pr315-task') /
                                        path.relative_to(TASK))))
    users = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            for descriptor in (entry / 'fd').iterdir():
                try:
                    info = descriptor.stat()
                    target = os.readlink(descriptor)
                except (FileNotFoundError, PermissionError, OSError):
                    continue
                if ((info.st_dev, info.st_ino) in file_ids | directory_ids
                        or target.startswith(prefixes)):
                    users.append(int(entry.name))
                    break
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return users


def _backing_on_pve(disk, backing):
    path = Path(backing)
    if '..' in path.parts:
        raise ValueError('pr315-cleanup-backing-path-invalid')
    if path.is_absolute() and path.is_relative_to('/work/pr315-task'):
        return TASK / path.relative_to('/work/pr315-task')
    return (path if path.is_absolute() else disk.parent / path).resolve()


def _external_backing_users(selected):
    found = []
    scanned = 0
    for directory, _children, files in os.walk(TASK):
        for name in files:
            if not name.endswith('.qcow2'):
                continue
            disk = Path(directory) / name
            _regular(disk, disk.lstat().st_uid)
            value = json.loads(subprocess.run(['/usr/bin/qemu-img', 'info',
                '--output=json', str(disk)], capture_output=True,
                check=True, timeout=15).stdout)
            scanned += 1
            backing = value.get('full-backing-filename') or value.get('backing-filename')
            if backing:
                resolved = _backing_on_pve(disk, backing)
                if resolved in selected and disk not in selected:
                    found.append(str(disk.relative_to(TASK)))
            data_file = (value.get('data-file') or value.get(
                'format-specific', {}).get('data', {}).get('data-file'))
            if data_file and disk not in selected:
                if _backing_on_pve(disk, data_file) in selected:
                    found.append(str(disk.relative_to(TASK)))
    return found, scanned


def inspect(plan):
    """Pure read-only proof under the caller-held task lease."""
    plan = _plan(plan)
    if os.geteuid() != 0:
        raise ValueError('pr315-cleanup-pve-root-required')
    _directory(TASK, OWNER_UID)
    suite_root = TASK / plan['suite']
    base = suite_root / 'attempt-01'
    _directory(suite_root, OWNER_UID)
    _directory(base, OWNER_UID)
    report_path = base / 'attempt.private.json'
    monitor_path = TASK / 'host-monitor' / (plan['suite'] + '.finished.json')
    _regular(report_path, OWNER_UID, 65536)
    _regular(monitor_path, 0, 8192)
    report = json.loads(report_path.read_bytes())
    monitor = json.loads(monitor_path.read_bytes())
    if (report.get('status') != 'guest-report-retained'
            or report.get('guestStopped') is not True
            or report.get('guestExitCode') != 0
            or report.get('helperSourceCommit') != plan['sourceCommit']
            or monitor.get('kind') != 'pr315-pve-watch-finished'
            or monitor.get('suite') != plan['suite']
            or monitor.get('sourceCommit') != plan['sourceCommit']
            or monitor.get('action') != 'completed'
            or monitor.get('seenTaskQemu') is not True):
        raise ValueError('pr315-cleanup-success-stop-proof-invalid')
    files = {}
    for name in FILES:
        path = base / name
        info = _regular(path, OWNER_UID)
        if _hash(path) != plan['fileDigests'][name]:
            raise ValueError('pr315-cleanup-file-digest-changed')
        files[name] = info
    if (plan['fileDigests']['source.tar.gz'] !=
            report.get('sourceArchiveDigest')
            or plan['fileDigests']['prepared.qcow2'] !=
                report.get('preparedImageDigest')):
        raise ValueError('pr315-cleanup-input-identity-changed')
    disk_metadata = {}
    for name in ('guest.qcow2', 'prepared.qcow2'):
        disk_metadata[name] = json.loads(subprocess.run(
            ['/usr/bin/qemu-img', 'info', '--output=json', str(base / name)],
            capture_output=True, check=True, timeout=15).stdout)
    guest_backing = (disk_metadata['guest.qcow2'].get('full-backing-filename')
                     or disk_metadata['guest.qcow2'].get('backing-filename'))
    guest_data = disk_metadata['guest.qcow2'].get(
        'format-specific', {}).get('data', {})
    prepared_data = disk_metadata['prepared.qcow2'].get(
        'format-specific', {}).get('data', {})
    if (disk_metadata['guest.qcow2'].get('format') != 'qcow2'
            or disk_metadata['prepared.qcow2'].get('format') != 'qcow2'
            or not guest_backing
            or _backing_on_pve(base / 'guest.qcow2', guest_backing) !=
                base / 'prepared.qcow2'
            or 'data-file' in guest_data
            or 'data-file' in prepared_data
            or any(key in disk_metadata['prepared.qcow2'] for key in
                   ('backing-filename', 'full-backing-filename', 'data-file'))):
        raise ValueError('pr315-cleanup-disk-chain-invalid')
    directories = {}
    for name in DIRECTORIES:
        path = base / name
        info = _directory(path, OWNER_UID)
        if any(path.rglob('*.qcow2')):
            raise ValueError('pr315-cleanup-generated-directory-has-disk')
        directories[path] = info
    clone = base / 'cryptad'
    if ((clone / '.git/HEAD').read_text().strip() !=
            plan['sourceCommit']
            or _hash(clone / 'build/cryptad-dist/lib/cryptad.jar') !=
                report.get('productDigest')):
        raise ValueError('pr315-cleanup-source-clone-changed')
    qemu = _qemu_processes(base)
    users = _open_users(files, directories)
    disks = {base / 'guest.qcow2', base / 'prepared.qcow2'}
    dependents, count = _external_backing_users(disks)
    if qemu or users or dependents:
        raise ValueError('pr315-cleanup-copy-still-in-use')
    return {'schemaVersion': 1,
        'kind': 'pr315-pve-success-copy-release-check-v1',
        'suite': plan['suite'], 'sourceCommit': plan['sourceCommit'],
        'campaignPlanDigest': plan['campaignPlanDigest'],
        'sealedReceiptDigest': plan['sealedReceiptDigest'],
        'macFullArchiveDigest': plan['macFullArchiveDigest'],
        'files': {name: {'device': row.st_dev, 'inode': row.st_ino,
            'sizeBytes': row.st_size, 'allocatedBytes': row.st_blocks * 512,
            'sha256': plan['fileDigests'][name]} for name, row in files.items()},
        'directories': {path.name: {'device': row.st_dev,
            'inode': row.st_ino} for path, row in directories.items()},
        'taskQemuPids': qemu, 'openUserPids': users,
        'externalBackingDependents': dependents,
        'qcowMetadataScanned': count}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', required=True)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args(argv)
    if (SUITE.fullmatch(args.suite) is None
            or HEX40.fullmatch(args.source_commit) is None):
        raise SystemExit('pr315-cleanup-selection-invalid')
    plan_root = TASK / 'host-release'
    root_info = _directory(plan_root, 0)
    if root_info.st_mode & 0o077:
        raise SystemExit('pr315-cleanup-plan-root-not-private')
    plan_path = TASK / 'host-release' / (args.suite + '.plan.private.json')
    _regular(plan_path, 0, 16384)
    plan = _plan(json.loads(plan_path.read_bytes()))
    if (plan['suite'] != args.suite
            or plan['sourceCommit'] != args.source_commit):
        raise SystemExit('pr315-cleanup-selection-invalid')
    lease = TASK / 'workload-suite.lock'
    _regular(lease, OWNER_UID)
    descriptor = os.open(lease, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = inspect(plan)
        result['checkDigest'] = hashlib.sha256(_canonical(result)).hexdigest()
        print(json.dumps(result, sort_keys=True))
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    main()
