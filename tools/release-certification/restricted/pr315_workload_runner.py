#!/usr/bin/python3
"""Bounded workload suite using the existing copied-reference transport.

The positive aggregate is diagnostic execution, not a 45-case acceptance record. Missing
hostile emitters remain explicitly unexecuted. No stored report can be imported as evidence.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from types import SimpleNamespace

import pr312_reference_vm as reference
import pr313_acceptance_runner as native_runner
import pr314_acceptance as acceptance
from pr314_workload_driver import STARTUP_MEASUREMENT_SECONDS

GUEST_MEMORY = 5632 * 1024**2
ROLE_MEMORY = 1024**3
ROLE_TMPFS = 512 * 1024**2
HOST_OVERHEAD = 512 * 1024**2


def groups():
    """Predeclare the unchanged complete inventory, including absent emitters."""
    return [('positive', [name for name, case in acceptance.CASES.items()
                          if case.witness not in ('denial', 'lifecycle')]),
            ('denial', [name for name, case in acceptance.CASES.items() if case.witness == 'denial']),
            ('lifecycle', [name for name, case in acceptance.CASES.items() if case.witness == 'lifecycle'])]


def memory_snapshot():
    """Measure host and current container headroom without treating missing metrics as zero."""
    fields = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        if key in ('MemTotal', 'MemAvailable'):
            parts = value.split()
            if len(parts) != 2 or parts[1] != 'kB' or not parts[0].isdigit():
                raise ValueError('workload-host-memory-unavailable')
            fields[key] = int(parts[0]) * 1024
    if set(fields) != {'MemTotal', 'MemAvailable'}:
        raise ValueError('workload-host-memory-unavailable')
    root = Path('/sys/fs/cgroup')
    limit = (root / 'memory.max').read_text().strip()
    current = (root / 'memory.current').read_text().strip()
    if not current.isdigit() or (limit != 'max' and not limit.isdigit()):
        raise ValueError('workload-container-memory-unavailable')
    available = fields['MemAvailable']
    if limit != 'max':
        available = min(available, max(0, int(limit) - int(current)))
    return {'hostTotalBytes': fields['MemTotal'], 'hostAvailableBytes': fields['MemAvailable'],
            'containerLimitBytes': None if limit == 'max' else int(limit),
            'containerCurrentBytes': int(current), 'effectiveAvailableBytes': available}


def memory_reason(args, measured):
    if (type(args.memory_budget_bytes) is not int or type(args.min_host_memory_bytes) is not int
            or args.min_host_memory_bytes <= 0 or args.memory_budget_bytes < GUEST_MEMORY + HOST_OVERHEAD):
        return 'memory-budget-insufficient'
    if measured['effectiveAvailableBytes'] < GUEST_MEMORY + HOST_OVERHEAD + args.min_host_memory_bytes:
        return 'host-memory-reserve-unavailable'
    return None


def prerequisites(args):
    """Missing reference prerequisites fail before any large allocation."""
    reasons = []
    for attribute in ('source', 'prepared_fixtures', 'qemu_root'):
        if not getattr(args, attribute).is_dir():
            reasons.append(attribute.replace('_', '-') + '-unavailable')
    for attribute in ('prepared_image', 'seed', 'ssh_key', 'known_hosts'):
        if not getattr(args, attribute).is_file():
            reasons.append(attribute.replace('_', '-') + '-unavailable')
    return reasons


def positive_executed(report, result):
    """Bind diagnostics to this transport and post-cleanup driver result, never to JSON alone."""
    identity = report.get('hostVerifiedIdentity')
    return (report.get('mode') == 'workload-positive' and report.get('guestStopped') is True
            and report.get('workloadPurpose', 'positive') == 'positive'
            and report.get('status') == 'guest-report-retained' and report.get('guestExitCode') == 0
            and isinstance(identity, dict) and isinstance(result, dict)
            and isinstance(result.get('identity'), dict)
            and re.fullmatch('[0-9a-f]{64}', str(identity.get('bundleIdentity'))) is not None
            and re.fullmatch('[0-9a-f]{40}', str(identity.get('helperSourceCommit'))) is not None
            and result['identity'].get('bundleIdentity') == identity.get('bundleIdentity')
            and result['identity'].get('sourceCommit') == identity.get('helperSourceCommit')
            and result.get('contentRetrieval') == 'observed' and result.get('newEpoch') is True
            and result.get('profile') == acceptance.PROFILE
            and result.get('topologyRoles') == 4 and result.get('signedAppWorkers') in (2, 3)
            and result.get('workloadAcceptance') == 'incomplete-hostile-contract-not-executed'
            and result.get('protectedExecutionEnabled') is False)


def public_result(status, positive=False, reasons=(), statuses=None):
    return {'schemaVersion': 1, 'kind': 'pr315-workload-suite', 'contract': acceptance.CONTRACT,
            'profile': acceptance.PROFILE, 'status': status, 'reasons': list(reasons),
            'implementationCoverage': 'incomplete', 'installedPositiveExecuted': positive,
            'installedWorkloadAcceptanceSatisfied': False, 'finiteNativeAcceptance': False,
            'protectedExecutionEnabled': False, 'phaseComplete': False,
            # Aggregate success is not sufficient for any individual v8 assertion.
            'cases': acceptance.inventory(statuses)}


def run(args):
    if os.geteuid() == 0:
        raise ValueError('reference-unprivileged-host-required')
    for module in (reference, native_runner, acceptance):
        expected = args.source / 'tools/release-certification/restricted' / Path(module.__file__).name
        if reference.sha256(module.__file__) != reference.sha256(expected):
            raise ValueError('executing-workload-source-mismatch')
    if reference.sha256(__file__) != reference.sha256(
            args.source / 'tools/release-certification/restricted' / Path(__file__).name):
        raise ValueError('executing-workload-source-mismatch')
    os.umask(0o077)
    output = args.output.absolute()
    root = native_runner.storage_policy(args, output)
    for name in ('prepared_image', 'prepared_fixtures', 'qemu_root', 'seed', 'ssh_key', 'known_hosts'):
        if not getattr(args, name).resolve(strict=False).is_relative_to(root):
            raise ValueError('workload-input-outside-task-storage-budget')
    info = root.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('workload-private-storage-root-required')
    # One suite per task-wide budget/role pool. Retained failures are never deleted here.
    fd = os.open(root / 'workload-suite.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise ValueError('workload-suite-lock-invalid')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output.mkdir(mode=0o700, exist_ok=False)
        native_runner._save(output / 'plan.private.json', {
            'contract': acceptance.CONTRACT, 'profile': acceptance.PROFILE,
            'executionPurpose': 'startup-measurement' if getattr(args, 'startup_measurement', False) else 'positive',
            'startupMeasurementCeilingSeconds': STARTUP_MEASUREMENT_SECONDS if getattr(args, 'startup_measurement', False) else None,
            'groups': [{'group': name, 'declaredCases': cases} for name, cases in groups()],
            'storageBudgetBytes': args.storage_budget_bytes, 'minimumFreeBytes': args.min_free_bytes,
            'memoryBudgetBytes': args.memory_budget_bytes, 'minimumHostMemoryBytes': args.min_host_memory_bytes,
            'guestMemoryBytes': GUEST_MEMORY, 'roleMemoryMaxBytes': ROLE_MEMORY,
            'roleSwapMaxBytes': 0, 'roleTasksMax': 512, 'roleTmpfsMaxBytes': ROLE_TMPFS,
            'roleTmpfsMaxInodes': 32768, 'tmpfsAccounting': 'allocated-pages-charge-memory',
            'cpuModel': reference.CPU_MODEL, 'accelerator': args.profile,
            'retention': 'all-attempts-private-no-automatic-deletion'})
        reasons = prerequisites(args)
        try:
            measured = memory_snapshot()
            reason = memory_reason(args, measured)
            if reason:
                reasons.append(reason)
        except (OSError, ValueError):
            measured = {'status': 'unavailable'}
            reasons.append('memory-observation-unavailable')
        capacity = {'allocatedBytes': native_runner.allocated_bytes(root), 'memory': measured}
        if not reasons:
            required = native_runner.required_attempt_bytes(args)
            capacity['requiredAttemptBytes'] = required
            reason = native_runner.capacity_reason(args, root, required)
            if reason:
                reasons.append(reason)
        native_runner._save(output / 'capacity.private.json', capacity)
        if reasons:
            result, code = public_result('setup-blocked', reasons=reasons), 78
        elif getattr(args, 'probe', False):
            result, code = public_result('prerequisites-present-not-executed'), 78
        else:
            # Source and pinned transport checks remain in the reused reference runner.
            selected = SimpleNamespace(**vars(args), attempt=output / 'attempt-01',
                mode='workload-positive', case_group=None, fault_case=None)
            with (output / 'transport.private.log').open('x') as log, redirect_stdout(log):
                reference.run(selected)
            report = native_runner.private_json(selected.attempt / 'attempt.private.json')
            observation = selected.attempt / 'pr314-workload-observation.private.json'
            value = native_runner.private_json(observation) if observation.exists() and observation.stat().st_size else None
            startup_measurement = getattr(args, 'startup_measurement', False)
            positive = not startup_measurement and positive_executed(report, value)
            diagnostic = selected.attempt / 'pr315-workload-memory.private.json'
            reached = diagnostic.exists() and diagnostic.stat().st_size > 0
            # A reached aggregate without per-case witnesses is inconclusive. An
            # installation failure is setup-failed; neither is an observed denial.
            statuses = {case: 'inconclusive' if reached else 'setup-failed' for case in groups()[0][1]}
            if startup_measurement:
                statuses = None  # No workload case was invoked by this diagnostic.
            result, code = public_result('implementation-incomplete', positive, statuses=statuses,
                reasons=('startup-measurement-not-workload-execution',) if startup_measurement else ()), 2
        native_runner._save(output / 'assessment.json', result)
        print(json.dumps(result, sort_keys=True))
        return code
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', action='store_true', help='Check capacity and inputs without allocating a VM.')
    parser.add_argument('--startup-measurement', action='store_true',
        help='Measure only installed controller startup under a fixed diagnostic ceiling; no role launch or acceptance.')
    for name in ('source', 'output', 'prepared-image', 'qemu-root', 'seed', 'ssh-key', 'known-hosts',
                 'prepared-fixtures', 'storage-root'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('product-source-commit', 'prepared-image-digest', 'fixture-manifest-digest'):
        parser.add_argument('--' + name)
    for name in ('storage-budget-bytes', 'min-free-bytes', 'memory-budget-bytes', 'min-host-memory-bytes'):
        parser.add_argument('--' + name, required=True, type=int)
    parser.add_argument('--profile', choices=tuple(reference.PROFILES), required=True)
    parser.add_argument('--port', type=int, default=23112)
    parser.add_argument('--timeout', type=int, default=3600)
    parser.add_argument('--development-snapshot', action='store_true')
    parser.add_argument('--host-key-pin-origin', required=True,
        choices=('preselected-host-key', 'administrator-preparation-tofu'))
    args = parser.parse_args()
    if ((not args.probe and (re.fullmatch('[0-9a-f]{40}', str(args.product_source_commit)) is None
            or any(re.fullmatch('[0-9a-f]{64}', str(value)) is None for value in
                   (args.prepared_image_digest, args.fixture_manifest_digest))))
            or not 1024 <= args.port <= 65535 or not 60 <= args.timeout <= 4200):
        parser.error('invalid fixed reference identity or bounded option')
    return run(args)


if __name__ == '__main__':
    try:
        exit_code = main()
    except (OSError, ValueError, subprocess.SubprocessError):
        print(json.dumps(public_result('setup-or-execution-failed')))
        exit_code = 2
    raise SystemExit(exit_code)
