#!/usr/bin/python3
"""Run one bounded copied-VM PR-316 Mail execution outside the PR-315 campaign.

This host-side entry point owns no historical case, campaign, or release authority.  It admits
one fixed execution class, retains one copied-VM attempt, validates the private causal Mail record
and terminal administrator cleanup, and emits only the closed public PR-316 projection.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from contextlib import redirect_stdout
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

import pr312_reference_vm as reference
import pr313_acceptance_runner as retained_runner
import pr315_pve_host_admission as host_admission
import pr315_pve_pressure_watch as pressure_watch
import pr315_workload_fixtures as fixtures
import pr316_mail_runtime_evidence as evidence
import pr316_pve_vm_inventory as pve_inventory


PROFILE = 'tcg-multi'
PORT = 23113
TIMEOUT_SECONDS = 4200
# The reference path permits 180 seconds each for boot and source transfer. Its
# explicit post-command collection/shutdown timeouts total 795 seconds; retain
# 900 seconds so process startup and bounded polling cannot consume the margin.
WATCHER_REQUIRED_SECONDS = (
    pressure_watch.PRELAUNCH_SECONDS + 180 + 180 + TIMEOUT_SECONDS + 900)
GUEST_MEMORY = 5632 * 1024**2
HOST_OVERHEAD = 512 * 1024**2
MAX_PRIVATE_RECORD = 8 * 1024**2
SOURCE_IDENTITY_FIELDS = frozenset((
    'helperSourceCommit', 'helperSourceTree', 'bundleIdentity', 'testKitDigest',
    'profileDigest', 'bootClosureDigest', 'preparedImageDigest',
    'fixtureManifestDigest', 'productDigest'))
FALSE_PUBLIC_CLAIMS = frozenset((
    'historicalPr315AcceptanceTransferred', 'installedWorkloadAcceptanceSatisfied',
    'finiteNativeAcceptance', 'originalProtectedAuthority',
    'independentSecurityReview', 'releaseEligible', 'phaseComplete'))
PUBLIC_FIELDS = frozenset({
    'schemaVersion', 'kind', 'contract', 'executionClass', 'status', 'reasons',
    'sourceIdentityDigest', 'selectionDigest', 'topologyRoles',
    *evidence.PUBLIC_FLAGS, *FALSE_PUBLIC_CLAIMS})


def memory_snapshot():
    """Measure physical and cgroup headroom without treating missing metrics as zero."""
    fields = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        if key in ('MemTotal', 'MemAvailable'):
            parts = value.split()
            if len(parts) != 2 or parts[1] != 'kB' or not parts[0].isdigit():
                raise ValueError('pr316-host-memory-unavailable')
            fields[key] = int(parts[0]) * 1024
    if set(fields) != {'MemTotal', 'MemAvailable'}:
        raise ValueError('pr316-host-memory-unavailable')
    root = Path('/sys/fs/cgroup')
    limit = (root / 'memory.max').read_text().strip()
    current = (root / 'memory.current').read_text().strip()
    if not current.isdigit() or (limit != 'max' and not limit.isdigit()):
        raise ValueError('pr316-container-memory-unavailable')
    available = fields['MemAvailable']
    if limit != 'max':
        available = min(available, max(0, int(limit) - int(current)))
    return {'hostTotalBytes': fields['MemTotal'],
            'hostAvailableBytes': fields['MemAvailable'],
            'containerLimitBytes': None if limit == 'max' else int(limit),
            'containerCurrentBytes': int(current),
            'effectiveAvailableBytes': available}


def memory_reason(args, measured):
    if (type(args.memory_budget_bytes) is not int
            or type(args.min_host_memory_bytes) is not int
            or args.min_host_memory_bytes <= 0
            or args.memory_budget_bytes < GUEST_MEMORY + HOST_OVERHEAD):
        return 'memory-budget-insufficient'
    if (measured['effectiveAvailableBytes'] <
            GUEST_MEMORY + HOST_OVERHEAD + args.min_host_memory_bytes):
        return 'host-memory-reserve-unavailable'
    return None


def known_hosts_matches_fixed_port(path):
    """Require the single pinned ED25519 key for the fixed local QEMU SSH port."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o022
                    or not 0 < info.st_size <= 4096):
                return False
            raw = os.read(descriptor, 4097)
            if len(raw) != info.st_size or os.fstat(descriptor).st_size != info.st_size:
                return False
        finally:
            os.close(descriptor)
        lines = raw.splitlines()
        if len(lines) != 1:
            return False
        fields = lines[0].split()
        if (len(fields) not in (3, 4)
                or fields[0] != f'[127.0.0.1]:{PORT}'.encode()
                or fields[1] != b'ssh-ed25519'):
            return False
        key = base64.b64decode(fields[2], validate=True)
        return (len(key) == 51 and int.from_bytes(key[:4], 'big') == 11
                and key[4:15] == b'ssh-ed25519'
                and int.from_bytes(key[15:19], 'big') == 32)
    except (OSError, ValueError, binascii.Error):
        return False


def prerequisites(args):
    """Check all fixed inputs before a copied image or guest overlay can be allocated."""
    reasons = []
    for attribute in ('source', 'prepared_fixtures', 'qemu_root'):
        if not getattr(args, attribute).is_dir():
            reasons.append(attribute.replace('_', '-') + '-unavailable')
    for attribute in ('prepared_image', 'seed', 'ssh_key', 'known_hosts'):
        if not getattr(args, attribute).is_file():
            reasons.append(attribute.replace('_', '-') + '-unavailable')
    if args.known_hosts.is_file() and not known_hosts_matches_fixed_port(args.known_hosts):
        reasons.append('known-hosts-port-pin-invalid')
    if pressure_watch.MAX_SECONDS < WATCHER_REQUIRED_SECONDS:
        reasons.append('pve-host-monitor-window-insufficient')
    return reasons


def task_vm_inventory(root):
    """Inventory retained task storage and require no task-owned QEMU before allocation."""
    root = Path(root).resolve(strict=True)
    active = []
    proc = Path('/proc')
    if not proc.is_dir():
        raise ValueError('pr316-task-vm-inventory-unavailable')
    for entry in proc.iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            arguments = [os.fsdecode(value) for value in
                         (entry / 'cmdline').read_bytes().split(b'\0') if value]
            if (not arguments or 'qemu-system-' not in Path(arguments[0]).name
                    or not any(str(root) in value for value in arguments[1:])):
                continue
            ticks = int((entry / 'stat').read_text().rsplit(')', 1)[1].split()[19])
            active.append({'pid': int(entry.name), 'startTicks': ticks})
        except (FileNotFoundError, PermissionError, ProcessLookupError,
                UnicodeError, ValueError, OSError):
            continue
    retained = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if path.is_symlink():
            raise ValueError('pr316-task-storage-link-invalid')
        try:
            allocated = retained_runner.allocated_bytes(path)
        except (OSError, ValueError):
            raise ValueError('pr316-task-storage-inventory-invalid') from None
        retained.append({'name': path.name, 'allocatedBytes': allocated})
    if active:
        raise ValueError('pr316-existing-task-qemu-active')
    return {'activeQemu': active, 'retained': retained,
            'allocatedBytes': retained_runner.allocated_bytes(root)}


def wait_final_pve_inventory(root, output, suite, source_commit):
    """Wait for a distinct root-PVE inventory taken after final local preparation."""
    not_before = time.monotonic_ns()
    retained_runner._save(output / 'awaiting-final-pve-inventory.private.json', {
        'schemaVersion': 1, 'kind': 'pr316-awaiting-final-pve-inventory',
        'suite': suite, 'sourceCommit': source_commit,
        'notBeforeMonotonicNs': not_before})
    path = root / 'host-inventory' / (suite + '-final.json')
    deadline = time.monotonic() + 120
    while True:
        try:
            receipt = pve_inventory.verify_receipt(
                path, suite, source_commit, 'final')
        except (FileNotFoundError, ValueError):
            if time.monotonic() >= deadline:
                raise ValueError('pr316-final-pve-inventory-unavailable') from None
            time.sleep(.25)
            continue
        observed = receipt.get('observation', {}).get('observedMonotonicNs')
        if type(observed) is not int or observed <= not_before:
            raise ValueError('pr316-final-pve-inventory-before-barrier')
        return receipt


def validate_pve_capacity(args, observation, required):
    """Require the authoritative host view to admit one attempt and its free-space reserve."""
    allocated = observation.get('allocatedTaskBytes') if isinstance(observation, dict) else None
    available = observation.get('availableTaskBytes') if isinstance(observation, dict) else None
    if (type(required) is not int or required <= 0
            or type(allocated) is not int or allocated < 0
            or type(available) is not int or available < 0):
        raise ValueError('pr316-final-pve-capacity-invalid')
    if (allocated + required > args.storage_budget_bytes
            or available < required + args.min_free_bytes):
        raise ValueError('pr316-final-pve-capacity-unavailable')


def launch_remaining_bytes(required, prepared):
    """Return only the bounded growth still possible after host preparation."""
    reserve = retained_runner.GUEST_WRITE_RESERVE + retained_runner.REPORT_RESERVE
    if (type(required) is not int or required < reserve
            or type(prepared) is not int or prepared < 0):
        raise ValueError('pr316-launch-capacity-requirement-invalid')
    return max(reserve, required - prepared)


def wait_pressure_watcher(args, root, output, suite, source_commit, prepared, remaining, *, execution_class=None):
    """Require fresh PVE admission, inventory and watcher at the launch boundary."""
    not_before = time.monotonic_ns()
    retained_runner._save(output / 'awaiting-pressure-watcher.private.json', {
        'schemaVersion': 1, 'kind': 'pr316-awaiting-pressure-watcher',
        'suite': suite, 'sourceCommit': source_commit,
        'notBeforeMonotonicNs': not_before,
        'preparedAttemptBytes': prepared,
        'requiredRemainingBytes': remaining,
        'requiredHostAdmissionPhase': 'launch',
        'requiredPveInventoryPhase': 'launch',
        **({'executionClass': execution_class} if execution_class is not None else {})})
    deadline = time.monotonic() + 120
    admission_path = root / 'host-admission' / host_admission.receipt_name(
        suite, 'launch')
    while True:
        try:
            admission = host_admission.verify_receipt(
                admission_path, suite, source_commit, 'launch')
            break
        except (FileNotFoundError, OSError, ValueError):
            if time.monotonic() >= deadline:
                raise ValueError('pr316-launch-host-admission-unavailable') from None
            time.sleep(.25)
    admitted = admission.get('observation', {}).get('observedMonotonicNs')
    if type(admitted) is not int or admitted <= not_before:
        raise ValueError('pr316-launch-host-admission-before-barrier')
    retained_runner._save(
        output / 'launch-host-admission.private.json', admission)
    inventory_path = root / 'host-inventory' / (suite + '-launch.json')
    while True:
        try:
            inventory = pve_inventory.verify_receipt(
                inventory_path, suite, source_commit, 'launch')
            break
        except (FileNotFoundError, OSError, ValueError):
            if time.monotonic() >= deadline:
                raise ValueError('pr316-launch-pve-inventory-unavailable') from None
            time.sleep(.25)
    observed = inventory.get('observation', {}).get('observedMonotonicNs')
    if type(observed) is not int or observed <= not_before:
        raise ValueError('pr316-launch-pve-inventory-before-barrier')
    validate_pve_capacity(args, inventory['observation'], remaining)
    retained_runner._save(
        output / 'launch-pve-inventory.private.json', inventory)
    while True:
        try:
            return (pressure_watch.verify_launch_ready(suite, source_commit) if execution_class is None
                    else pressure_watch.verify_launch_ready(suite, source_commit, execution_class=execution_class))
        except (FileNotFoundError, OSError, ValueError):
            if time.monotonic() >= deadline:
                raise ValueError('pr316-pve-host-monitor-unavailable') from None
            time.sleep(.25)


def reconcile_failed_watcher(suite, source_commit, ready):
    """Authenticate watcher closure after a failure beyond the ready boundary."""
    deadline = time.monotonic() + pressure_watch.PRELAUNCH_SECONDS + 15
    while True:
        for verifier in (pressure_watch.verify_finished,
                         pressure_watch.verify_stopped_before_launch):
            try:
                return verifier(suite, source_commit, ready)
            except (FileNotFoundError, OSError, ValueError):
                pass
        if time.monotonic() >= deadline:
            raise ValueError('pr316-pve-host-monitor-incomplete') from None
        time.sleep(.25)


def _private_bytes(path, maximum=MAX_PRIVATE_RECORD):
    """Read one owner-private, single-link regular record exactly once."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_nlink != 1 or before.st_mode & 0o077
                or not 0 < before.st_size <= maximum):
            raise ValueError('pr316-private-record-invalid')
        raw = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        fields = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                               info.st_gid, info.st_nlink, info.st_size,
                               info.st_mtime_ns, info.st_ctime_ns)
        if len(raw) != before.st_size or fields(before) != fields(after):
            raise ValueError('pr316-private-record-changed')
    finally:
        os.close(descriptor)
    return raw


def _private_json(path, maximum=MAX_PRIVATE_RECORD):
    """Read and decode one owner-private, single-link regular JSON record exactly once."""
    raw = _private_bytes(path, maximum)

    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('pr316-private-json-duplicate')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _value: (_ for _ in ()).throw(
            ValueError('pr316-private-json-invalid')))


def _terminal_cleanup_verified(value):
    """Require root-captured quiescence for every fixed role after Mail execution."""
    sentinel = value.get('sentinel') if isinstance(value, dict) else None
    if (not isinstance(value, dict) or value.get('schemaVersion') != 1
            or value.get('kind') != 'pr315-private-volatile-diagnostics'
            or value.get('cleanupReportedByCaller') is not True
            or not isinstance(sentinel, dict)
            or sentinel.get('status') != 'matched'
            or re.fullmatch('sha256:[0-9a-f]{64}',
                            str(sentinel.get('expectedDigest'))) is None
            or sentinel.get('expectedDigest') != sentinel.get('observedDigest')
            or sentinel.get('sizeBytes') != 32
            or not isinstance(value.get('controllerRecords'), dict)
            or not isinstance(value.get('stopReceipts'), dict)
            or set(fixtures.ROLES) - set(value['controllerRecords'])
            or set(fixtures.ROLES) - set(value['stopReceipts'])):
        return False
    try:
        for role in fixtures.ROLES:
            authority = value['controllerRecords'][role]
            current = value['stopReceipts'][role]['current']
            if (set(authority) != {'status', 'record'}
                    or set(current) != {'status', 'record'}
                    or authority['status'] != 'captured'
                    or current['status'] != 'captured'):
                return False
            active, stopped = authority['record'], current['record']
            identity = active['cgroupIdentity']
            if (active['role'] != role or active['state'] != 'quiescent'
                    or not isinstance(identity, list) or len(identity) != 2
                    or any(type(part) is not int or part < 1 for part in identity)
                    or any(stopped[key] != active[key] for key in
                           ('role', 'generation', 'bootId', 'managerInvocation',
                            'cgroupIdentity'))
                    or stopped['membership'] != 'only-stop-helper'
                    or stopped['descendantCgroups'] != 0):
                return False
    except (AttributeError, KeyError, TypeError, ValueError):
        return False
    return True


def _driver_observation(value):
    """Admit only the fixed post-cleanup observer result; never a historical result shape."""
    expected = {
        'schemaVersion', 'kind', 'contract', 'executionClass',
        'selectionDigest', 'privateEvidenceDigest', 'evidenceClass',
        'topologyRoles', 'namespaceTransportImplemented',
        'installedMailFlowObserved', 'observerMailFlowObserved',
        'ciphertextInsertionAndRecipientFetch', 'wrongRecipientObserved',
        'duplicateBeforeRestart', 'duplicateAfterRestart', 'workerRestart',
        'roleRestart', 'replyObserved', 'privacyCanarySurfacesObserved',
        'uncertainOperationState', 'cleanupState',
        'installedWorkloadAcceptanceSatisfied', 'finiteNativeAcceptance',
        'originalProtectedAuthority', 'independentSecurityReview', 'phaseComplete',
        'historicalPr315AcceptanceTransferred', 'releaseEligible',
        'identity', 'runtimePolicy', 'campaignDeadlineMonotonicNs',
        'workloadAcceptance', 'protectedExecutionEnabled'}
    if (not isinstance(value, dict) or set(value) != expected
            or value['schemaVersion'] != 1
            or value['kind'] != 'pr316-installed-mail-runtime-observation'
            or value['contract'] != evidence.CONTRACT
            or value['executionClass'] != evidence.EXECUTION_CLASS
            or re.fullmatch('sha256:[0-9a-f]{64}',
                            str(value['selectionDigest'])) is None
            or re.fullmatch('sha256:[0-9a-f]{64}',
                            str(value['privateEvidenceDigest'])) is None
            or value['evidenceClass'] != 'installed-four-role-private-observer'
            or value['topologyRoles'] != 4
            or value['namespaceTransportImplemented'] is not True
            or value['installedMailFlowObserved'] is not True
            or value['observerMailFlowObserved'] is not True
            or value['ciphertextInsertionAndRecipientFetch'] != 'worker-observed'
            or any(value[name] is not True for name in (
                'wrongRecipientObserved', 'duplicateBeforeRestart',
                'duplicateAfterRestart', 'workerRestart', 'roleRestart',
                'replyObserved', 'privacyCanarySurfacesObserved'))
            or value['uncertainOperationState'] is not False
            or value['cleanupState'] != 'completed'
            or any(value[name] is not False for name in (
                'installedWorkloadAcceptanceSatisfied', 'finiteNativeAcceptance',
                'originalProtectedAuthority', 'independentSecurityReview',
                'historicalPr315AcceptanceTransferred', 'releaseEligible',
                'phaseComplete', 'protectedExecutionEnabled'))
            or not isinstance(value['identity'], dict)
            or not isinstance(value['runtimePolicy'], dict)
            or type(value['campaignDeadlineMonotonicNs']) is not int
            or value['campaignDeadlineMonotonicNs'] <= 0
            or value['workloadAcceptance'] !=
                'incomplete-pr316-private-evidence-not-verified'):
        raise ValueError('pr316-driver-observation-invalid')
    return value


def _source_identity(report):
    identity = report.get('hostVerifiedIdentity')
    if (not isinstance(identity, dict)
            or not SOURCE_IDENTITY_FIELDS <= set(identity)
            or re.fullmatch('[0-9a-f]{40}',
                            str(identity.get('helperSourceCommit'))) is None
            or re.fullmatch('[0-9a-f]{40}',
                            str(identity.get('helperSourceTree'))) is None
            or any(re.fullmatch('[0-9a-f]{64}', str(identity.get(name))) is None
                   for name in SOURCE_IDENTITY_FIELDS - {
                       'helperSourceCommit', 'helperSourceTree'})):
        raise ValueError('pr316-host-source-identity-invalid')
    return {name: identity[name] for name in SOURCE_IDENTITY_FIELDS}


def _mail_selection(value, fixture, fixture_root):
    """Recompute the class-bound selection from host-authenticated fixture identities."""
    if not isinstance(value, dict) or set(value) != {'plan', 'private', 'authorization'}:
        raise ValueError('pr316-host-selection-shape-invalid')
    plan, private, authorization = (value[name] for name in
                                    ('plan', 'private', 'authorization'))
    selected_digest = evidence.selection_digest(plan, authorization)
    if (set(plan) != {'schemaVersion', 'kind', 'experimentId', 'profile',
                      'topologyClass', 'provenanceClass', 'requestedSeconds',
                      'probeIntervalSeconds', 'policy', 'requiredScenarios',
                      'producer', 'nodes'}
            or plan.get('schemaVersion') != 1
            or plan.get('kind') != fixtures.evidence.KIND
            or plan.get('experimentId') != 'pr316-installed-mail-runtime'
            or plan.get('profile') != 'bounded-live'
            or plan.get('topologyClass') != 'single-host-independent-processes'
            or plan.get('provenanceClass') != 'source-build-comparison'
            or plan.get('requestedSeconds') != fixture.get('maxSeconds')
            or plan.get('probeIntervalSeconds') != 1
            or plan.get('policy') != {'id': 'cross-version-observed-v1',
                'minimumObservedSeconds': 0, 'maxGapSeconds': 600,
                'maxEvents': 10000}
            or plan.get('requiredScenarios') != sorted(fixtures.evidence.SCENARIOS)
            or private.get('root') !=
               '/var/lib/cryptad-cross-version/experiments/pr316-installed-mail-runtime'
            or set(private.get('nodes', {})) != set(fixtures.ROLES)
            or len(plan.get('nodes', [])) != 4
            or [row.get('role') for row in plan['nodes']] != list(fixtures.ROLES)
            or set(authorization) != {'syntheticContent', 'experimentId', 'root',
                                      'planDigest', 'maxSeconds', 'maxOperations',
                                      'executionClass', 'selectionDigest'}
            or authorization.get('syntheticContent') is not True
            or authorization.get('experimentId') != plan['experimentId']
            or authorization.get('root') != private['root']
            or authorization.get('maxSeconds') != fixture.get('maxSeconds')
            or authorization.get('maxOperations') != fixture.get('maxOperations')):
        raise ValueError('pr316-host-selection-invalid')
    producer = plan.get('producer')
    if (not isinstance(producer, dict)
            or set(producer) != {'sourceCommit', 'runnerDigest', 'adapterDigest'}
            or producer.get('sourceCommit') != fixture.get('sourceCommit')
            or any(re.fullmatch(r'sha256:[0-9a-f]{64}', str(producer.get(name))) is None
                   for name in ('runnerDigest', 'adapterDigest'))):
        raise ValueError('pr316-host-selection-producer-invalid')
    mail_digest = fixture.get('mailDigest')
    products = fixture.get('products', {})
    fixture_root = Path(fixture_root)
    for index, role in enumerate(fixtures.ROLES):
        node, private_node = plan['nodes'][index], private['nodes'][role]
        apps = private_node.get('apps')
        expected = ([{'appId': 'mail-prototype'}]
                    if role in {'candidate-sender', 'candidate-recipient'} else [])
        product_name = 'previous' if role == 'previous' else 'candidate'
        product = products.get(product_name, {})
        expected_node = {key: product.get(key) for key in (
            'sourceCommit', 'artifactDigest', 'artifactSize',
            'packageTarget', 'contractVersion')}
        expected_node.update(role=role, product='cryptad',
            runtimeDigest=fixture.get('runtimeDigest'),
            configDigest=node.get('configDigest'),
            appDigests=[mail_digest] if expected else [])
        expected_private = {
            'archivePath': str(fixture_root / (product_name + '.tar.gz')),
            'javaHome': str(fixture_root / 'jdk'),
            'fnpPort': 19400, 'fcpPort': 19401, 'httpPort': 19402,
            'apps': apps,
            'trustedKeysPath': str(fixture_root / 'trusted-app-keys.properties'),
            'trustedKeysDigest': fixture.get('trustDigest')}
        if (not isinstance(apps, list)
                or [{key: app.get(key) for key in ('appId',)} for app in apps] != expected
                or any(app.get('bundleDigest') != mail_digest for app in apps)
                or any(set(app) != {'appId', 'bundlePath', 'bundleDigest'}
                       or app.get('bundlePath') != str(fixture_root / 'mail.zip')
                       for app in apps)
                or re.fullmatch(r'sha256:[0-9a-f]{64}',
                                str(node.get('configDigest'))) is None
                or node != expected_node or private_node != expected_private):
            raise ValueError('pr316-host-selection-roster-invalid')
    return selected_digest


def _closed_public(value):
    """Reject any projection that could transfer historical or release acceptance."""
    if (not isinstance(value, dict) or set(value) != PUBLIC_FIELDS
            or value.get('schemaVersion') != 1
            or value.get('kind') != evidence.PUBLIC_KIND
            or value.get('contract') != evidence.CONTRACT
            or value.get('executionClass') != evidence.EXECUTION_CLASS
            or value.get('topologyRoles') != 4
            or value.get('status') not in ('observed', 'incomplete', 'failed')
            or not isinstance(value.get('reasons'), list)
            or len(value['reasons']) > 8
            or any(not isinstance(reason, str)
                   or re.fullmatch('[a-z][a-z0-9-]{1,100}', reason) is None
                   for reason in value['reasons'])
            or any(value.get(name) is not False for name in FALSE_PUBLIC_CLAIMS)):
        raise ValueError('pr316-public-projection-invalid')
    return value


def _scan_retained_privacy(root, *, exclude_source_clone=False):
    """Scan every bounded retained text/JSON surface collected for public assessment."""
    root = Path(root).absolute()
    source_clone = root / 'attempt-01' / 'cryptad'
    source_clone_present = source_clone.exists() or source_clone.is_symlink()
    if exclude_source_clone and source_clone_present:
        info = source_clone.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise ValueError('pr316-retained-source-clone-invalid')
    binary_suffixes = {'.qcow2', '.img', '.iso', '.jar', '.zip', '.gz', '.class',
                       '.so', '.dll', '.exe', '.bin', '.db'}
    count = total = 0
    for path in sorted(root.rglob('*')):
        if exclude_source_clone and path.is_relative_to(source_clone):
            continue
        if path.is_symlink():
            raise ValueError('pr316-retained-surface-link-invalid')
        if not path.is_file() or path.suffix.lower() in binary_suffixes:
            continue
        info = path.stat()
        count += 1
        total += info.st_size
        if count > 4096 or info.st_size > 8 * 1024 * 1024 \
                or total > 64 * 1024 * 1024:
            raise ValueError('pr316-retained-surface-budget')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(descriptor)
            raw = os.read(descriptor, info.st_size + 1)
            after = os.fstat(descriptor)
            if (len(raw) != info.st_size
                    or (before.st_dev, before.st_ino, before.st_size,
                        before.st_mtime_ns, before.st_ctime_ns) !=
                       (after.st_dev, after.st_ino, after.st_size,
                        after.st_mtime_ns, after.st_ctime_ns)
                    or evidence.payload_exposed(raw)):
                raise ValueError('pr316-private-canary-exposure')
        finally:
            os.close(descriptor)
    return {'filesScanned': count, 'bytesScanned': total,
            'sourceCloneExcluded': exclude_source_clone and source_clone_present}


def _attempt_projection(args, attempt, report, fixture, source_commit,
                        watcher_finished):
    if (not isinstance(report, dict) or report.get('schemaVersion') != 7
            or report.get('mode') != 'workload-positive'
            or report.get('workloadPurpose') != 'mail-runtime'
            or report.get('status') != 'guest-report-retained'
            or report.get('guestExitCode') != 0
            or report.get('guestStopped') is not True
            or report.get('helperSourceCommit') != source_commit
            or report.get('productSourceCommit') != args.product_source_commit
            or report.get('preparedImageDigest') != args.prepared_image_digest
            or report.get('fixtureManifestDigest') != args.fixture_manifest_digest):
        raise ValueError('pr316-reference-attempt-invalid')
    identity = _source_identity(report)
    if (identity['helperSourceCommit'] != source_commit
            or identity['helperSourceTree'] != report.get('helperSourceTree')
            or identity['productDigest'] != report.get('productDigest')
            or identity['preparedImageDigest'] != args.prepared_image_digest
            or identity['fixtureManifestDigest'] != args.fixture_manifest_digest
            or fixture.get('sourceCommit') != identity['helperSourceCommit']
            or fixture.get('products', {}).get('candidate', {}).get(
                'sourceCommit') != args.product_source_commit
            or re.fullmatch('sha256:[0-9a-f]{64}',
                            str(fixture.get('mailDigest'))) is None):
        raise ValueError('pr316-attempt-selection-changed')
    observed = _driver_observation(_private_json(
        attempt / 'pr314-workload-observation.private.json', 65536))
    if (observed['identity'].get('sourceCommit') != identity['helperSourceCommit']
            or observed['identity'].get('bundleIdentity') != identity['bundleIdentity']):
        raise ValueError('pr316-observer-host-identity-mismatch')
    private = evidence.validate_private_observation(_private_json(
        attempt / evidence.PRIVATE_FILENAME, evidence.MAX_PRIVATE_BYTES))
    host_selection_digest = _mail_selection(_private_json(
        attempt / 'pr316-selection.private.json', 131072), fixture,
        args.prepared_fixtures)
    if (observed['selectionDigest'] != private['selectionDigest']
            or private['selectionDigest'] != host_selection_digest
            or observed['privateEvidenceDigest'] !=
                evidence.canonical_digest(private)):
        raise ValueError('pr316-private-evidence-binding-invalid')
    terminal = _private_json(
        attempt / 'pr315-workload-volatile.private.json', 262144)
    if not _terminal_cleanup_verified(terminal):
        raise ValueError('pr316-terminal-cleanup-invalid')
    source_digest = evidence.source_identity_digest(identity)
    selection_digest = private['selectionDigest']
    projected = evidence.public_projection(private,
        source_identity_digest=source_digest,
        selection_digest=selection_digest, cleanup_verified=True,
        guest_stopped=True, watcher_finished=watcher_finished,
        privacy_verified=True)
    return _closed_public(projected)


def run(args):
    """Run or probe exactly one retained copied-VM Mail attempt."""
    if os.geteuid() == 0:
        raise ValueError('reference-unprivileged-host-required')
    for module in (reference, retained_runner, fixtures, evidence, pve_inventory,
                   host_admission, pressure_watch):
        expected = (args.source / 'tools/release-certification/restricted' /
                    Path(module.__file__).name)
        if reference.sha256(module.__file__) != reference.sha256(expected):
            raise ValueError('pr316-executing-source-mismatch')
    if reference.sha256(__file__) != reference.sha256(
            args.source / 'tools/release-certification/restricted' /
            Path(__file__).name):
        raise ValueError('pr316-executing-source-mismatch')
    os.umask(0o077)
    output = args.output.absolute()
    root = retained_runner.storage_policy(args, output)
    for name in ('prepared_image', 'prepared_fixtures', 'qemu_root', 'seed',
                 'ssh_key', 'known_hosts'):
        if not getattr(args, name).resolve(strict=False).is_relative_to(root):
            raise ValueError('pr316-input-outside-task-storage-budget')
    root_info = root.stat()
    if root_info.st_uid != os.geteuid() or root_info.st_mode & 0o077:
        raise ValueError('pr316-private-storage-root-required')
    lock = os.open(root / 'pr316-mail-runtime.lock',
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid()):
            raise ValueError('pr316-suite-lock-invalid')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        initial_inventory = task_vm_inventory(root)
        output.mkdir(mode=0o700, exist_ok=False)
        reasons = prerequisites(args)
        try:
            measured = memory_snapshot()
            reason = memory_reason(args, measured)
            if reason:
                reasons.append(reason)
        except (OSError, ValueError):
            measured = {'status': 'unavailable'}
            reasons.append('memory-observation-unavailable')
        watch_ready = None
        source_commit = None
        try:
            source_commit = subprocess.run(['git', '-C', str(args.source),
                'rev-parse', 'HEAD'], check=True, capture_output=True,
                text=True, timeout=10).stdout.strip()
            receipt = host_admission.verify_receipt(
                root / 'host-admission' / (output.name + '.json'),
                output.name, source_commit)
            measured['pveHost'] = receipt['observation']
            inventory_receipt = pve_inventory.verify_receipt(
                root / 'host-inventory' / (output.name + '-pre.json'),
                output.name, source_commit, 'pre')
            measured['pveTaskInventory'] = inventory_receipt['observation']
        except (OSError, ValueError, TypeError, KeyError,
                json.JSONDecodeError, subprocess.SubprocessError):
            reasons.append('pve-host-admission-unavailable')
        capacity = {'allocatedBytes': retained_runner.allocated_bytes(root),
                    'taskInventory': initial_inventory,
                    'memory': measured}
        if not reasons:
            required = retained_runner.required_attempt_bytes(args)
            capacity['requiredAttemptBytes'] = required
            reason = retained_runner.capacity_reason(args, root, required)
            if reason:
                reasons.append(reason)
        retained_runner._save(output / 'capacity.private.json', capacity)
        retained_runner._save(output / 'plan.private.json', {
            'schemaVersion': 1, 'kind': 'pr316-mail-runtime-host-plan',
            'executionClass': evidence.EXECUTION_CLASS,
            'sourceCommit': source_commit,
            'productSourceCommit': args.product_source_commit,
            'preparedImageDigest': args.prepared_image_digest,
            'fixtureManifestDigest': args.fixture_manifest_digest,
            'profile': PROFILE, 'port': PORT, 'timeoutSeconds': TIMEOUT_SECONDS,
            'storageBudgetBytes': args.storage_budget_bytes,
            'minimumFreeBytes': args.min_free_bytes,
            'memoryBudgetBytes': args.memory_budget_bytes,
            'minimumHostMemoryBytes': args.min_host_memory_bytes,
            'retention': 'one-attempt-private-no-automatic-deletion'})
        if reasons:
            result, code = evidence.failed_projection(reasons[0]), 78
        elif args.probe:
            result, code = evidence.failed_projection(
                'prerequisites-present-not-executed'), 78
        else:
            try:
                fixture = fixtures.verify(args.prepared_fixtures,
                    args.fixture_manifest_digest, args.source,
                    args.product_source_commit)
                selected = SimpleNamespace(**vars(args),
                    attempt=output / 'attempt-01', mode='workload-positive',
                    profile=PROFILE, port=PORT, timeout=TIMEOUT_SECONDS,
                    development_snapshot=False,
                    host_key_pin_origin='preselected-host-key',
                    execution_class=evidence.EXECUTION_CLASS,
                    workload_group=None, lifecycle_scenario='none',
                    startup_measurement=False,
                    retired_authority_preparation=False,
                    case_group=None, fault_case=None,
                    retired_authority_input=None,
                    retired_authority_input_digest=None)
                capacity['preAllocationInventory'] = task_vm_inventory(root)
                final_inventory = wait_final_pve_inventory(
                    root, output, output.name, source_commit)
                capacity['finalPveTaskInventory'] = final_inventory['observation']
                required = capacity['requiredAttemptBytes']
                validate_pve_capacity(args, final_inventory['observation'], required)
                reason = retained_runner.capacity_reason(args, root, required)
                if reason:
                    raise ValueError('pr316-preallocation-capacity-unavailable')
                retained_runner._save(
                    output / 'pre-allocation.private.json',
                    capacity['preAllocationInventory'])

                def start_pressure_watcher():
                    nonlocal watch_ready
                    prepared = retained_runner.allocated_bytes(selected.attempt)
                    remaining = launch_remaining_bytes(required, prepared)
                    watch_ready = wait_pressure_watcher(
                        args, root, output, output.name, source_commit,
                        prepared, remaining)

                with (output / 'transport.private.log').open('x') as log, \
                        redirect_stdout(log):
                    reference.workload_guest_command(selected)
                    reference.run(
                        selected, before_guest_launch=start_pressure_watcher)
                until = time.monotonic() + 20
                while True:
                    try:
                        monitor = pressure_watch.verify_finished(
                            output.name, source_commit, watch_ready)
                        retained_runner._save(
                            output / 'host-monitor.private.json', monitor)
                        break
                    except (OSError, ValueError):
                        if time.monotonic() >= until:
                            raise ValueError(
                                'pr316-pve-host-monitor-incomplete')
                        time.sleep(.25)
                report = _private_json(
                    selected.attempt / 'attempt.private.json', 1024 * 1024)
                privacy = _scan_retained_privacy(output, exclude_source_clone=True)
                retained_runner._save(
                    output / 'privacy-scan.private.json', privacy)
                result = _attempt_projection(args, selected.attempt, report,
                                             fixture, source_commit, True)
                code = 0
            except (OSError, ValueError, KeyError, TypeError,
                    subprocess.SubprocessError, json.JSONDecodeError) as error:
                if (watch_ready is not None
                        and not (output / 'host-monitor.private.json').exists()):
                    try:
                        monitor = reconcile_failed_watcher(
                            output.name, source_commit, watch_ready)
                        retained_runner._save(
                            output / 'host-monitor.private.json', monitor)
                    except (OSError, ValueError):
                        error = ValueError('pr316-pve-host-monitor-incomplete')
                try:
                    failure_scan = _scan_retained_privacy(
                        output, exclude_source_clone=True)
                    retained_runner._save(
                        output / 'privacy-failure-scan.private.json', {
                            'schemaVersion': 1,
                            'kind': 'pr316-private-failure-surface-scan',
                            'status': 'passed', **failure_scan})
                except (OSError, ValueError):
                    retained_runner._save(
                        output / 'privacy-failure-scan.private.json', {
                            'schemaVersion': 1,
                            'kind': 'pr316-private-failure-surface-scan',
                            'status': 'failed'})
                detail = str(error)
                reason = (detail if re.fullmatch(
                    r'pr316-[a-z0-9-]{1,94}', detail) else
                    'execution-failed-private-reconciliation-required')
                retained_runner._save(output / 'failure.private.json', {
                    'schemaVersion': 1,
                    'kind': 'pr316-private-host-execution-failure',
                    'executionClass': evidence.EXECUTION_CLASS,
                    'exceptionType': type(error).__name__[:128],
                    'reason': reason, 'installedMailFlowObserved': False})
                result, code = evidence.failed_projection(reason), 2
        result = _closed_public(result)
        retained_runner._save(output / 'assessment.json', result)
        print(json.dumps(result, sort_keys=True))
        return code
    finally:
        os.close(lock)


def parser():
    """Return the closed CLI; callers cannot select campaigns, cases, or histories."""
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument('--probe', action='store_true',
        help='Check fixed inputs and capacity without allocating a VM.')
    for name in ('source', 'output', 'prepared-image', 'qemu-root', 'seed',
                 'ssh-key', 'known-hosts', 'prepared-fixtures', 'storage-root'):
        value.add_argument('--' + name, required=True, type=Path)
    for name in ('product-source-commit', 'prepared-image-digest',
                 'fixture-manifest-digest'):
        value.add_argument('--' + name, required=True)
    for name in ('storage-budget-bytes', 'min-free-bytes',
                 'memory-budget-bytes', 'min-host-memory-bytes'):
        value.add_argument('--' + name, required=True, type=int)
    return value


def main(argv=None):
    args = parser().parse_args(argv)
    if (re.fullmatch('[0-9a-f]{40}', args.product_source_commit) is None
            or any(re.fullmatch('[0-9a-f]{64}', value) is None for value in
                   (args.prepared_image_digest,
                    args.fixture_manifest_digest))):
        parser().error('invalid fixed source or fixture identity')
    return run(args)


if __name__ == '__main__':
    try:
        exit_code = main()
    except (OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError, json.JSONDecodeError) as error:
        detail = str(error)
        reason = (detail if re.fullmatch(r'pr316-[a-z0-9-]{1,126}', detail)
                  else 'setup-or-execution-failed')
        print(json.dumps(evidence.failed_projection(reason), sort_keys=True))
        exit_code = 2
    raise SystemExit(exit_code)
