#!/usr/bin/python3
"""Fixed manager start and stop receipts; stop observations do not grant launch authority."""
import os
from pathlib import Path
import re
import stat
import sys
import time

# ExecStartPre runs as root outside the unprivileged role's mount boundary. Imports
# must not add bytecode files to the exact immutable installation inventory.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import restricted_workload as workload


def _read_fd(fd, limit):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        workload.reject('manager-stop-file-invalid')
    raw = bytearray()
    while len(raw) <= limit:
        block = os.read(fd, min(4096, limit + 1 - len(raw)))
        if not block:
            break
        raw.extend(block)
    after = os.fstat(fd)
    if len(raw) > limit or any(getattr(before, key) != getattr(after, key)
            for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
        workload.reject('manager-stop-file-changed-or-limit')
    return raw.decode('ascii')


def _self_epoch():
    fd = os.open('/proc/self/stat', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        raw = _read_fd(fd, 8192)
    finally:
        os.close(fd)
    fields = raw.rsplit(')', 1)[1].split()
    pid, ticks = int(raw.split('(', 1)[0]), int(fields[19])
    if pid != os.getpid() or ticks <= 0:
        workload.reject('manager-stop-helper-epoch-invalid')
    return pid, ticks


def _members(group_fd, own_pid):
    # This profile uses one role cgroup. Any child cgroup requires reconciliation,
    # even if it appears empty; no recursive candidate-selected traversal is admitted.
    with os.scandir(group_fd) as entries:
        for index, entry in enumerate(entries):
            if index >= 128 or entry.is_symlink() or entry.is_dir(follow_symlinks=False):
                workload.reject('manager-stop-subtree-unavailable')
    fd = os.open('cgroup.procs', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=group_fd)
    try:
        raw = _read_fd(fd, 8192)
    finally:
        os.close(fd)
    # Do not collapse duplicates or accept whitespace/empty membership as success.
    if raw != str(own_pid) + '\n':
        workload.reject('manager-stop-other-processes-or-unavailable')


def _publish(role, receipt):
    path = workload.ROOT / 'authority' / (role + '-stop.json')
    if not os.path.lexists(path):
        workload.write(path, receipt, create=True)
        return
    old = workload.read(path)
    generation = old.get('generation')
    if (set(old) != set(receipt) or not isinstance(generation, str)
            or re.fullmatch('[0-9a-f]{64}', generation) is None
            or generation == receipt['generation']
            or any(old.get(key) != receipt[key] for key in
                   ('schemaVersion', 'role', 'campaign', 'bootId', 'membership', 'descendantCgroups'))):
        workload.reject('manager-stop-receipt-retained')
    archive = workload.ROOT / 'authority' / (role + '-stop-' + generation + '.json')
    if workload.read(archive) != old or workload.read(path) != old:
        workload.reject('manager-stop-archive-mismatch')
    # The owner durably archived the complete preceding receipt before issuing the
    # new generation. Retain that archive and atomically replace only its current copy.
    workload.write(path, receipt)


def stop_receipt(role, invocation, record, campaign):
    started = time.monotonic_ns()
    marker = workload.read(workload.ROOT / 'authority' / (role + '-start.json'))
    boot = workload.boot()
    if (record.get('state') not in {'launching', 'running', 'stopping', 'reconciliation-required'}
            or not isinstance(invocation, str) or re.fullmatch('[0-9a-f]{32}', invocation) is None
            or campaign.get('generation') != record.get('campaign')
            or campaign.get('bootId') != boot or record.get('bootId') != boot
            or not isinstance(record.get('generation'), str)
            or re.fullmatch('[0-9a-f]{64}', record['generation']) is None
            or marker.get('generation') != record['generation'] or marker.get('bootId') != boot
            or marker.get('managerInvocation') != invocation
            or (record.get('state') != 'launching'
                and (record.get('managerInvocation') is None or record.get('cgroupIdentity') is None))
            or (record.get('managerInvocation') is not None and record['managerInvocation'] != invocation)
            or (record.get('cgroupIdentity') is not None
                and record['cgroupIdentity'] != marker.get('cgroupIdentity'))):
        workload.reject('manager-stop-identity-invalid')
    path = workload.group(role)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        identity = [info.st_dev, info.st_ino]
        if identity != marker.get('cgroupIdentity'):
            workload.reject('manager-stop-cgroup-changed')
        epoch = _self_epoch()
        _members(fd, epoch[0])
        _members(fd, epoch[0])
        after = path.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(after.st_mode) or [after.st_dev, after.st_ino] != identity
                or _self_epoch() != epoch or workload.boot() != boot
                or time.monotonic_ns() - started > 5_000_000_000):
            workload.reject('manager-stop-observation-changed')
        receipt = {'schemaVersion': 1, 'role': role, 'campaign': record['campaign'],
            'generation': record['generation'], 'bootId': boot, 'managerInvocation': invocation,
            'cgroupIdentity': identity, 'helperPid': epoch[0], 'helperStartTimeTicks': epoch[1],
            'startedMonotonicNs': started, 'observedMonotonicNs': time.monotonic_ns(),
            'membership': 'only-stop-helper', 'descendantCgroups': 0}
        _publish(role, receipt)
    finally:
        os.close(fd)


def main():
    if (not sys.flags.isolated or not sys.flags.no_site or os.geteuid() != 0
            or len(sys.argv) not in {2, 3} or sys.argv[1] not in workload.ROLES
            or (len(sys.argv) == 3 and sys.argv[2] != 'stop')):
        workload.reject('manager-receipt-entry-invalid')
    role = sys.argv[1]
    invocation = os.environ.get('INVOCATION_ID', '')
    if (re.fullmatch('[0-9a-f]{32}', invocation) is None
            or Path('/proc/self/cgroup').read_text().strip() != '0::/system.slice/' + workload.unit(role)):
        workload.reject('manager-receipt-scope-invalid')
    os.environ.clear()
    record = workload.read(workload.ROOT / 'authority' / (role + '.json'))
    campaign = workload.read(workload.ROOT / 'campaign.json')
    if len(sys.argv) == 3:
        stop_receipt(role, invocation, record, campaign)
        return
    workload.current(campaign)
    if record['state'] != 'launching' or record['bootId'] != workload.boot():
        workload.reject('manager-receipt-intent-invalid')
    info = workload.group(role).stat()
    workload.write(workload.ROOT / 'authority' / (role + '-start.json'), {
        'generation': record['generation'], 'bootId': record['bootId'],
        'managerInvocation': invocation, 'cgroupIdentity': [info.st_dev, info.st_ino]})


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit(1) from None
