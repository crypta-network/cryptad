#!/usr/bin/python3
"""Measured PVE admission for the fixed CT102 TCG workload campaign.

Run this on the PVE host immediately before each allocation.  The CT's own
``/proc/meminfo`` is not an observation of physical host headroom.  This
module records the prospective swap policy without changing guest or role
limits.  A returned admission is only a capacity observation, never a case
witness or an installed acceptance verdict.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time

GIB = 1024 ** 3
POLICY = 'pve-tcg-swap-admission-v1'
CT_CGROUP = Path('/sys/fs/cgroup/lxc/102')
TASK_ROOT = Path('/mnt/tank1/files/pr315-workload-acceptance')
TOTAL_BUDGET = 7 * GIB
GUEST_AND_OVERHEAD = 6 * GIB
PHYSICAL_RESERVE = GIB
SWAP_RESERVE = 2 * GIB
PHASES = ('launch',)


def receipt_name(suite: str, phase: str | None = None) -> str:
    """Return the immutable legacy or phase-bound receipt filename."""
    if phase is not None and phase not in PHASES:
        raise ValueError('pve-admission-phase-invalid')
    return suite + (('-' + phase) if phase is not None else '') + '.json'


def _number(path: Path) -> int:
    raw = path.read_text().strip()
    if not raw.isdecimal():
        raise ValueError('pve-admission-counter-unavailable')
    return int(raw)


def _pressure(path: Path) -> float:
    match = re.search(r'(?m)^full avg10=([0-9]+(?:\.[0-9]+)?)\b', path.read_text())
    if match is None:
        raise ValueError('pve-admission-pressure-unavailable')
    return float(match.group(1))


def snapshot(meminfo: Path = Path('/proc/meminfo'),
             pressure: Path = Path('/proc/pressure'),
             cgroup: Path = CT_CGROUP) -> dict:
    """Observe host memory, swap, PSI and the actual PVE CT102 cgroup."""
    values = {}
    for line in meminfo.read_text().splitlines():
        key, separator, data = line.partition(':')
        if separator and key in ('MemAvailable', 'SwapFree'):
            fields = data.split()
            if len(fields) != 2 or fields[1] != 'kB' or not fields[0].isdecimal():
                raise ValueError('pve-admission-memory-unavailable')
            values[key] = int(fields[0]) * 1024
    if set(values) != {'MemAvailable', 'SwapFree'}:
        raise ValueError('pve-admission-memory-unavailable')
    return {'policy': POLICY, 'observedMonotonicNs': time.monotonic_ns(),
            'hostAvailableBytes': values['MemAvailable'],
            'hostSwapFreeBytes': values['SwapFree'],
            'memoryFullAvg10Pct': _pressure(pressure / 'memory'),
            'ioFullAvg10Pct': _pressure(pressure / 'io'),
            'ctMemoryMaxBytes': _number(cgroup / 'memory.max'),
            'ctMemoryCurrentBytes': _number(cgroup / 'memory.current'),
            'ctSwapMaxBytes': _number(cgroup / 'memory.swap.max'),
            'ctSwapCurrentBytes': _number(cgroup / 'memory.swap.current')}


def admission_reason(observed: dict) -> str | None:
    """Require unchanged VM budget with separate physical and swap reserves."""
    fields = {'hostAvailableBytes', 'hostSwapFreeBytes', 'memoryFullAvg10Pct',
              'ioFullAvg10Pct', 'ctMemoryMaxBytes', 'ctMemoryCurrentBytes',
              'ctSwapMaxBytes', 'ctSwapCurrentBytes'}
    if (not isinstance(observed, dict) or observed.get('policy') != POLICY
            or type(observed.get('observedMonotonicNs')) is not int
            or observed['observedMonotonicNs'] <= 0 or not fields <= set(observed)
            or any(type(observed[key]) not in (int, float) or not math.isfinite(observed[key])
                   or observed[key] < 0 for key in fields)
            or any(type(observed[key]) is not int for key in fields if not key.endswith('Pct'))):
        return 'pve-admission-observation-invalid'
    if (observed['ctMemoryCurrentBytes'] > observed['ctMemoryMaxBytes']
            or observed['ctSwapCurrentBytes'] > observed['ctSwapMaxBytes']):
        return 'pve-admission-cgroup-invalid'
    if observed['memoryFullAvg10Pct'] > 5 or observed['ioFullAvg10Pct'] > 10:
        return 'pve-admission-pressure-high'
    physical = observed['hostAvailableBytes']
    if physical < PHYSICAL_RESERVE:
        return 'pve-admission-physical-reserve-unavailable'
    # Keep the physical reserve available to the host after admitting the VM.
    # Only the remainder may count toward the unchanged total requirement.
    shortfall = max(0, TOTAL_BUDGET - (physical - PHYSICAL_RESERVE))
    if observed['hostSwapFreeBytes'] < shortfall + SWAP_RESERVE:
        return 'pve-admission-host-swap-unavailable'
    if observed['ctMemoryMaxBytes'] - observed['ctMemoryCurrentBytes'] < GUEST_AND_OVERHEAD:
        return 'pve-admission-ct-memory-unavailable'
    if observed['ctSwapMaxBytes'] - observed['ctSwapCurrentBytes'] < shortfall:
        return 'pve-admission-ct-swap-unavailable'
    return None


def publish(suite: str, source_commit: str, observed: dict,
            phase: str | None = None) -> dict:
    """Write one immutable PVE-owned receipt for a named CT102 suite."""
    if (os.geteuid() != 0 or re.fullmatch(r'suite-[1-9][0-9]*', suite) is None
            or re.fullmatch(r'[0-9a-f]{40}', source_commit) is None):
        raise ValueError('pve-admission-publisher-invalid')
    info = TASK_ROOT.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 101000 or info.st_mode & 0o077:
        raise ValueError('pve-admission-task-root-invalid')
    directory = TASK_ROOT / 'host-admission'
    try:
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
    except FileExistsError:
        pass
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('pve-admission-directory-invalid')
    reason = admission_reason(observed)
    record = {'schemaVersion': 1, 'kind': 'pr315-pve-host-admission',
              'policy': POLICY, 'suite': suite, 'sourceCommit': source_commit,
              'moduleDigest': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'admitted': reason is None, 'reason': reason, 'observation': observed}
    if phase is not None:
        record['phase'] = phase
    path = directory / receipt_name(suite, phase)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    try:
        with os.fdopen(descriptor, 'w', closefd=False) as stream:
            json.dump(record, stream, sort_keys=True, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        os.fchmod(descriptor, 0o444)
    finally:
        os.close(descriptor)
    return record


def verify_receipt(path: Path, suite: str, source_commit: str,
                   phase: str | None = None) -> dict:
    """Check a fresh host-root receipt as seen by the unprivileged CT runner."""
    if path != Path('/work/pr315-task/host-admission') / receipt_name(suite, phase):
        raise ValueError('pve-admission-receipt-path-invalid')
    parent = path.parent.lstat()
    info = path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 65534
            or parent.st_mode & 0o022 or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 65534 or info.st_nlink != 1 or info.st_mode & 0o222
            or info.st_size <= 0 or info.st_size > 8192):
        raise ValueError('pve-admission-receipt-owner-invalid')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        current = os.fstat(descriptor)
        if (current.st_dev, current.st_ino, current.st_size) != (
                info.st_dev, info.st_ino, info.st_size):
            raise ValueError('pve-admission-receipt-changed')
        raw = os.read(descriptor, 8193)
    finally:
        os.close(descriptor)
    value = json.loads(raw)
    if not isinstance(value, dict) or not isinstance(value.get('observation'), dict):
        raise ValueError('pve-admission-receipt-invalid')
    expected = {'schemaVersion', 'kind', 'policy', 'suite', 'sourceCommit',
                'moduleDigest', 'admitted', 'reason', 'observation'}
    if phase is not None:
        expected.add('phase')
    observed_ns = value['observation'].get('observedMonotonicNs')
    if type(observed_ns) is not int:
        raise ValueError('pve-admission-receipt-invalid')
    interval = time.monotonic_ns() - observed_ns
    if (set(value) != expected
            or value['schemaVersion'] != 1 or value['kind'] != 'pr315-pve-host-admission'
            or value['policy'] != POLICY or value['suite'] != suite
            or phase is not None and value.get('phase') != phase
            or value['sourceCommit'] != source_commit
            or value['moduleDigest'] != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            or value['admitted'] is not True or value['reason'] is not None
            or admission_reason(value['observation']) is not None
            or not 0 <= interval <= 120_000_000_000):
        raise ValueError('pve-admission-receipt-invalid')
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--phase', choices=PHASES)
    args = parser.parse_args()
    try:
        observed = snapshot()
        reason = publish(args.suite, args.source_commit, observed,
                         args.phase)['reason']
    except (OSError, ValueError):
        reason = 'pve-admission-observation-or-publication-failed'
    print(json.dumps({'policy': POLICY, 'admitted': reason is None, 'reason': reason},
                     sort_keys=True))
    return 0 if reason is None else 78


if __name__ == '__main__':
    raise SystemExit(main())
