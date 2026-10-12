#!/usr/bin/python3
"""Bounded workload suite using the existing copied-reference transport.

The positive aggregate is diagnostic execution, not a 45-case acceptance record. Missing
hostile emitters remain explicitly unexecuted. No stored report can be imported as evidence.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import copy
from contextlib import redirect_stdout
import fcntl
import hashlib
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
import pr313_acceptance_runner as native_runner
import pr314_acceptance as acceptance
import pr315_workload_fixtures as fixtures
import pr315_pve_host_admission as host_admission
import pr315_pve_pressure_watch as pressure_watch
import pr315_workload_campaign as campaign
import pr315_campaign_seal as campaign_seal
import pr315_case_v10 as case_v10
import restricted_workload_network as workload_network
from pr314_workload_driver import STARTUP_MEASUREMENT_SECONDS, LIFECYCLE_SCENARIOS

GUEST_MEMORY = 5632 * 1024**2
ROLE_MEMORY = 1024**3
ROLE_TMPFS = 512 * 1024**2
HOST_OVERHEAD = 512 * 1024**2
EXCHANGE_AUDIT_FIELDS = frozenset(('schemaVersion', 'kind', 'caseId', 'method', 'role',
    'managerInvocation', 'bootId', 'cgroupIdentity', 'requestDigest', 'responseDigest',
    'startedMonotonicNs', 'finishedMonotonicNs', 'serverRequests'))


def groups():
    """Predeclare each exclusive group of the fixed 45-case campaign."""
    return [(name, list(cases)) for name, cases in campaign.GROUPS]


SUPPORTED_GROUPS = frozenset(('positive', 'role-boundary', 'authority',
                              'network-app', 'cancellation', 'controller-restart',
                              'deadline', 'revocation-running',
                              'setsid-double-fork', 'observer-death',
                              'lost-start-response',
                              'resource-exhaustion', 'partial-launch',
                              'stuck-output', 'late-child', 'cleanup-race',
                              'output-symlink', 'output-fifo', 'output-hardlink',
                              'output-flood', 'output-replacement'))


def selected_cases(group):
    """A development selection can claim only its predeclared group IDs."""
    if group is None:
        return None
    if group not in dict(campaign.GROUPS):
        raise ValueError('workload-group-selection-invalid')
    return frozenset(dict(campaign.GROUPS)[group])


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
    if args.known_hosts.is_file() and not known_hosts_matches_port(args.known_hosts, args.port):
        reasons.append('known-hosts-port-pin-invalid')
    return reasons


def known_hosts_matches_port(path, port):
    """Require the one pinned ED25519 key for the selected local QEMU SSH port."""
    if type(port) is not int or not 1 <= port <= 65535:
        return False
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
                or fields[0] != f'[127.0.0.1]:{port}'.encode()
                or fields[1] != b'ssh-ed25519'):
            return False
        key = base64.b64decode(fields[2], validate=True)
        return (len(key) == 51 and int.from_bytes(key[:4], 'big') == 11
                and key[4:15] == b'ssh-ed25519'
                and int.from_bytes(key[15:19], 'big') == 32)
    except (OSError, ValueError, TypeError, binascii.Error):
        return False


def positive_executed(report, result, terminal):
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
            and fixtures.runtime.canonical_digest(result.get('runtimePolicy'))
                == fixtures.runtime.canonical_digest(fixtures.preparation.launcher_policy())
            and result.get('topologyRoles') == 4 and result.get('signedAppWorkers') in (2, 3)
            and acceptance._principals(result.get('roleKernelRoster'))
            and terminal_roster_matches(result['roleKernelRoster'], terminal)
            and result.get('workloadAcceptance') == 'incomplete-hostile-contract-not-executed'
            and result.get('protectedExecutionEnabled') is False)


def terminal_roster_matches(roster, terminal, *, require_sender_restart=True):
    """Cross-check final observer kernel roles against root-captured terminal authority."""
    if (not acceptance._principals(roster) or not isinstance(terminal, dict)
            or terminal.get('schemaVersion') != 1
            or terminal.get('kind') != 'pr315-private-volatile-diagnostics'
            or terminal.get('cleanupReportedByCaller') is not True
            or not isinstance(terminal.get('sentinel'), dict)
            or terminal['sentinel'].get('status') != 'matched'):
        return False
    try:
        for row in roster['roles']:
            role = row['role']
            authority = terminal['controllerRecords'][role]
            receipt = terminal['stopReceipts'][role]['current']
            if authority['status'] != 'captured' or receipt['status'] != 'captured':
                return False
            current, stopped = authority['record'], receipt['record']
            identity = current['cgroupIdentity']
            if (current['state'] != 'quiescent' or current['managerInvocation'] != row['invocationId']
                    or current['bootId'].replace('-', '').lower() != row['bootId']
                    or not isinstance(identity, list) or len(identity) != 2
                    or any(type(part) is not int or part < 1 for part in identity)
                    or row['cgroupDigest'] != fixtures.runtime.canonical_digest({
                        'role': role, 'identity': identity})[7:]
                    or any(stopped[key] != current[key] for key in
                           ('generation', 'bootId', 'managerInvocation', 'cgroupIdentity'))
                    or stopped['membership'] != 'only-stop-helper'
                    or stopped['descendantCgroups'] != 0):
                return False
        previous = terminal['stopReceipts']['candidate-sender'].get('previous')
        if require_sender_restart and (not isinstance(previous, dict)
                                       or previous.get('status') != 'captured'):
            return False
        if not require_sender_restart and previous is not None:
            return False
    except (AttributeError, KeyError, TypeError, ValueError):
        return False
    return True


def group_prepared(report, result, terminal, group):
    """Bind selected role preparation to this host transport and final cleanup."""
    if (group not in ('output-symlink', 'output-fifo', 'output-hardlink',
                      'output-flood', 'output-replacement', 'role-boundary',
                      'authority', 'network-app', 'cancellation',
                      'controller-restart', 'deadline',
                      'revocation-running', 'setsid-double-fork',
                      'observer-death', 'lost-start-response',
                      'resource-exhaustion', 'stuck-output', 'late-child',
                      'cleanup-race',
                      'role-readiness-diagnostic')
            or not isinstance(report, dict) or not isinstance(result, dict)):
        return False
    host = report.get('hostVerifiedIdentity')
    identity = result.get('identity')
    return (report.get('mode') == 'workload-positive'
            and report.get('workloadPurpose') == ('selected-group'
                if group in ('output-symlink', 'output-fifo', 'output-hardlink',
                             'output-flood', 'output-replacement',
                             'role-boundary', 'authority', 'network-app',
                             'cancellation', 'controller-restart', 'deadline',
                             'revocation-running', 'setsid-double-fork',
                             'observer-death', 'lost-start-response',
                             'resource-exhaustion', 'stuck-output', 'late-child',
                             'cleanup-race')
                else 'role-readiness-measurement')
            and report.get('status') == 'guest-report-retained'
            and report.get('guestStopped') is True and report.get('guestExitCode') == 0
            and isinstance(host, dict) and isinstance(identity, dict)
            and re.fullmatch('[0-9a-f]{64}', str(host.get('bundleIdentity'))) is not None
            and re.fullmatch('[0-9a-f]{40}', str(host.get('helperSourceCommit'))) is not None
            and identity.get('bundleIdentity') == host.get('bundleIdentity')
            and identity.get('sourceCommit') == host.get('helperSourceCommit')
            and result.get('groupPreparation') == group
            and result.get('contentRetrieval') == 'not-executed-group'
            and result.get('newEpoch') is False
            and result.get('topologyRoles') == 4
            and result.get('signedAppWorkers') == (
                3 if group in ('authority', 'network-app',
                               'resource-exhaustion') else 0)
            and (group not in ('authority', 'network-app',
                               'resource-exhaustion') or
                 isinstance(result.get('probeAppKernelProcess'), dict)
                 and result['probeAppKernelProcess'].get('provenance') ==
                     'controller-kernel-sample')
            and (group != 'network-app' or
                 isinstance(result.get('recipientMailAppKernelProcess'), dict)
                 and result['recipientMailAppKernelProcess'].get('provenance') ==
                     'controller-kernel-sample')
            and result.get('profile') == acceptance.PROFILE
            and _bounded_window(result.get('roleKernelRosterWindow'))
            and fixtures.runtime.canonical_digest(result.get('runtimePolicy'))
                == fixtures.runtime.canonical_digest(fixtures.preparation.launcher_policy())
            and acceptance._principals(result.get('roleKernelRoster'))
            and terminal_roster_matches(result['roleKernelRoster'], terminal,
                                        require_sender_restart=False)
            and result.get('workloadAcceptance') == (
                'incomplete-hostile-contract-not-executed'
                if group in ('output-symlink', 'output-fifo', 'output-hardlink',
                             'output-flood', 'output-replacement',
                             'role-boundary', 'authority', 'network-app',
                             'cancellation', 'controller-restart', 'deadline',
                             'revocation-running', 'setsid-double-fork',
                             'observer-death', 'lost-start-response',
                             'resource-exhaustion', 'stuck-output', 'late-child',
                             'cleanup-race')
                else 'not-executed-role-readiness-measurement')
            and result.get('protectedExecutionEnabled') is False)


def authority_epoch_views(report, result, terminal):
    """Project two real sender epochs without reassigning earlier case identity."""
    try:
        if (not isinstance(result, dict) or not isinstance(terminal, dict)
                or terminal.get('stalePidUidAudit', {}).get('status') != 'captured'
                or not acceptance._principals(result.get('roleKernelRoster'))
                or not acceptance._principals(
                    result.get('authorityFinalRoleRoster'))):
            return None
        audit = terminal['stalePidUidAudit']['record']
        first = next(row for row in result['roleKernelRoster']['roles']
                     if row['role'] == 'candidate-sender')
        last = next(row for row in result['authorityFinalRoleRoster']['roles']
                    if row['role'] == 'candidate-sender')
        previous = terminal['stopReceipts']['candidate-sender']['previous']
        current = terminal['stopReceipts']['candidate-sender']['current']
        old = audit['oldQuiescentAuthority']
        if (previous['status'] != 'captured'
                or current['status'] != 'captured'
                or audit['oldStopReceipt'] != previous['record']
                or old['state'] != 'quiescent'
                or any(old[key] != previous['record'][key] for key in
                       ('generation', 'bootId', 'managerInvocation',
                        'cgroupIdentity'))
                or audit['oldSenderInvocation'] != first['invocationId']
                or audit['newSenderInvocation'] != last['invocationId']
                or first['invocationId'] == last['invocationId']
                or current['record']['managerInvocation'] != last['invocationId']
                or first['bootId'] != last['bootId']):
            return None
        early = copy.deepcopy(terminal)
        early['controllerRecords']['candidate-sender'] = {
            'status': 'captured', 'record': old}
        early['stopReceipts']['candidate-sender'] = {'current': previous}
        final = copy.deepcopy(terminal)
        final['stopReceipts']['candidate-sender'] = {'current': current}
        final_result = {**result,
            'roleKernelRoster': result['authorityFinalRoleRoster'],
            'roleKernelRosterWindow': result['authorityFinalRosterWindow']}
        if (not group_prepared(report, result, early, 'authority')
                or not group_prepared(report, final_result, final,
                                      'authority')):
            return None
        return early, final_result, final
    except (AttributeError, KeyError, TypeError, ValueError, IndexError,
            StopIteration):
        return None


def partial_launch_prepared(report, result, terminal):
    """Admit only the deliberate two-role setup and its final owned cleanup."""
    if (not isinstance(report, dict) or not isinstance(result, dict)
            or not isinstance(terminal, dict)):
        return False
    host = report.get('hostVerifiedIdentity')
    roles = result.get('partialRoleRoster')
    return (report.get('mode') == 'workload-positive'
        and report.get('workloadPurpose') == 'selected-group'
        and report.get('status') == 'guest-report-retained'
        and report.get('guestExitCode') == 0
        and report.get('guestStopped') is True
        and isinstance(host, dict)
        and result.get('identity', {}).get('sourceCommit') ==
            host.get('helperSourceCommit')
        and result.get('groupPreparation') == 'partial-launch'
        and result.get('topologyRoles') == 2
        and result.get('signedAppWorkers') == 0
        and result.get('newEpoch') is False
        and result.get('contentRetrieval') == 'not-executed-group'
        and isinstance(roles, list) and len(roles) == 2
        and [row.get('role') for row in roles] ==
            ['candidate-sender', 'candidate-recipient']
        and 'roleKernelRoster' not in result
        and _bounded_window(result.get('roleKernelRosterWindow'))
        and terminal.get('cleanupReportedByCaller') is True
        and terminal.get('sentinel', {}).get('status') == 'matched'
        and result.get('protectedExecutionEnabled') is False)


def retired_authority_provenance(report, result, terminal, retained):
    """Verify a real stopped predecessor handle without exporting its bytes."""
    try:
        if (not group_prepared(report, result, terminal,
                               'role-readiness-diagnostic')
                or not isinstance(retained, dict)
                or set(retained) != {'schemaVersion', 'kind', 'sourceCommit',
                    'campaignGeneration', 'bootId', 'senderHandle', 'senderUid',
                    'senderInvocation', 'senderProcessEpoch',
                    'stopReceiptDigests'}
                or retained['schemaVersion'] != 1
                or retained['kind'] != 'pr315-retired-authority-input'
                or retained['sourceCommit'] !=
                    report['hostVerifiedIdentity']['helperSourceCommit']
                or re.fullmatch('[0-9a-f]{64}', retained['senderHandle']) is None
                or retained['campaignGeneration'] != terminal['controllerRecords']
                    ['campaign']['record']['generation']
                or retained['bootId'] != terminal['controllerRecords']
                    ['campaign']['record']['bootId']
                or set(retained['stopReceiptDigests']) != set(acceptance.ROLES)):
            return None
        sender = next(row for row in result['roleKernelRoster']['roles']
                      if row['role'] == 'candidate-sender')
        if (retained['senderUid'] != sender['uid']
                or retained['senderInvocation'] != sender['invocationId']
                or retained['senderProcessEpoch'] != sender['processEpoch']
                or retained['bootId'].replace('-', '').lower() != sender['bootId']):
            return None
        for role in acceptance.ROLES:
            receipt = terminal['stopReceipts'][role]['current']
            digest = hashlib.sha256(json.dumps(receipt['record'],
                sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            if (receipt['status'] != 'captured'
                    or receipt['record']['membership'] != 'only-stop-helper'
                    or receipt['record']['descendantCgroups'] != 0
                    or digest != retained['stopReceiptDigests'][role]):
                return None
        return {'schemaVersion': 1,
            'kind': 'pr315-retired-authority-host-provenance',
            'sourceCommit': retained['sourceCommit'],
            'bootId': retained['bootId'],
            'campaignGeneration': retained['campaignGeneration'],
            'senderHandleDigest': hashlib.sha256(
                retained['senderHandle'].encode()).hexdigest(),
            'inputDigest': hashlib.sha256(json.dumps(retained,
                sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'guestStopped': True}
    except (AttributeError, KeyError, TypeError, ValueError, IndexError,
            StopIteration):
        return None


def verified_retired_authority_input(campaign_plan, envelope, public_key,
                                     retained):
    """Require a Mac-sealed stopped predecessor before copying its raw handle."""
    handoff = campaign_seal.verify_authority_handoff(
        campaign_plan, envelope, public_key)
    if (not isinstance(retained, dict)
            or set(retained) != {'schemaVersion', 'kind', 'sourceCommit',
                'campaignGeneration', 'bootId', 'senderHandle', 'senderUid',
                'senderInvocation', 'senderProcessEpoch',
                'stopReceiptDigests'}
            or retained['schemaVersion'] != 1
            or retained['kind'] != 'pr315-retired-authority-input'
            or retained['sourceCommit'] != handoff['sourceCommit']
            or retained['bootId'] != handoff['retiredBootId']
            or retained['campaignGeneration'] != handoff['retiredGeneration']
            or re.fullmatch('[0-9a-f]{64}',
                str(retained['senderHandle'])) is None
            or hashlib.sha256(retained['senderHandle'].encode()).hexdigest()
                != handoff['senderHandleDigest']
            or hashlib.sha256(json.dumps(retained, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest() !=
                handoff['privateInputDigest']):
        raise ValueError('workload-retired-authority-input-untrusted')
    return handoff


def stale_handle_attempt(report, result, terminal, diagnostics, handoff,
                         retired_input, source):
    """Verify the signed old handle against three real observer socket calls."""
    try:
        if (not group_prepared(report, result, terminal, 'authority')
                or not isinstance(handoff, dict)
                or not isinstance(retired_input, dict)
                or not isinstance(diagnostics, dict)
                or diagnostics.get('staleHandle', {}).get('status') != 'captured'
                or terminal.get('staleHandleAudit', {}).get('status') != 'captured'):
            return None
        audit = terminal['staleHandleAudit']['record']
        actor = audit['observerActor']
        controller_before = audit['controllerBefore']
        controller_after = audit['controllerAfter']
        target_before = audit['targetBefore']
        target_after = audit['targetAfter']
        replies = audit['replies']
        host = report['hostVerifiedIdentity']
        sender = next(row for row in result['roleKernelRoster']['roles']
                      if row['role'] == 'candidate-sender')
        receipt = terminal['stopReceipts']['candidate-sender']['current']['record']
        audit_digest = hashlib.sha256(json.dumps(audit, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        old_request = json.dumps({'method': 'observe',
            'handle': retired_input['senderHandle']},
            separators=(',', ':')).encode() + b'\n'
        denied = b'{"error":"restricted-workload-request-failed"}\n'
        stable_controller = ('pid', 'uid', 'startTicks', 'bootId',
                             'invocationId', 'cgroupIdentity')
        stable_target = ('state', 'generation', 'managerInvocation',
                         'bootId', 'cgroupIdentity', 'stateDigest')
        expected_target = {key: target_before[key] for key in stable_target}
        source_digest = reference.sha256(Path(source) /
            'tools/release-certification/restricted/pr314_workload_driver.py')
        if (audit['schemaVersion'] != 1
                or audit['kind'] != 'pr315-administrator-stale-handle-denial'
                or audit['caseId'] != 'stale-handle'
                or audit_digest != diagnostics['staleHandle']['auditDigest']
                or audit['sourceCommit'] != host['helperSourceCommit']
                or audit['sourceCommit'] != handoff['sourceCommit']
                or result['identity']['sourceCommit'] != handoff['sourceCommit']
                or report.get('retiredAuthorityInputDigest') !=
                    handoff['privateInputDigest']
                or audit['retiredInputDigest'] != handoff['privateInputDigest']
                or audit['retiredHandleDigest'] != handoff['senderHandleDigest']
                or audit['retiredBootId'] != handoff['retiredBootId']
                or audit['successorBootId'].replace('-', '').lower() !=
                    sender['bootId']
                or audit['retiredBootId'] == audit['successorBootId']
                or actor.get('kind') != 'installed-observer-process'
                or actor.get('uid') != result['roleKernelRoster']['observerUid']
                or actor.get('sourceDigest') != source_digest
                or actor.get('bootId', '').replace('-', '').lower() !=
                    sender['bootId']
                or type(actor.get('pid')) is not int or actor['pid'] <= 1
                or type(actor.get('startTicks')) is not int
                or actor['startTicks'] <= 0
                or not isinstance(actor.get('namespaces'), dict)
                or set(actor['namespaces']) != {'pid', 'net', 'mnt', 'user'}
                or any(type(value) is not int or value <= 0
                       for value in actor['namespaces'].values())
                or any(controller_before[key] != controller_after[key]
                       for key in stable_controller)
                or controller_before['uid'] != 0
                or controller_before['pid'] <= 1
                or controller_before['startTicks'] <= 0
                or re.fullmatch('[0-9a-f]{32}',
                    str(controller_before['invocationId'])) is None
                or controller_before['bootId'].replace('-', '').lower() !=
                    sender['bootId']
                or any(target_before[key] != target_after[key]
                       for key in stable_target)
                or target_before['state'] != 'running'
                or target_before['managerInvocation'] != sender['invocationId']
                or target_before['bootId'].replace('-', '').lower() !=
                    sender['bootId']
                or fixtures.runtime.canonical_digest({
                    'role': 'candidate-sender',
                    'identity': target_before['cgroupIdentity']})[7:] !=
                    sender['cgroupDigest']
                or not isinstance(replies, list) or len(replies) != 3
                or [row['label'] for row in replies] != [
                    'current-before', 'retired-denied', 'current-after']
                or replies[0]['target'] != expected_target
                or replies[1]['target'] is not None
                or replies[2]['target'] != expected_target
                or any(row['exchange']['method'] != 'observe'
                       or re.fullmatch('[0-9a-f]{64}',
                           str(row['exchange']['requestDigest'])) is None
                       or re.fullmatch('[0-9a-f]{64}',
                           str(row['exchange']['responseDigest'])) is None
                       for row in replies)
                or replies[0]['exchange']['requestDigest'] !=
                    replies[2]['exchange']['requestDigest']
                or replies[1]['exchange']['requestDigest'] !=
                    hashlib.sha256(old_request).hexdigest()
                or replies[1]['exchange']['requestDigest'] ==
                    replies[0]['exchange']['requestDigest']
                or replies[1]['exchange']['responseDigest'] !=
                    hashlib.sha256(denied).hexdigest()
                or not controller_before['observedMonotonicNs']
                    < target_before['observedMonotonicNs']
                    < actor['observedMonotonicNs']
                    < replies[0]['startedMonotonicNs']
                    < replies[0]['finishedMonotonicNs']
                    < replies[1]['startedMonotonicNs']
                    < replies[1]['finishedMonotonicNs']
                    < replies[2]['startedMonotonicNs']
                    < replies[2]['finishedMonotonicNs']
                    < target_after['observedMonotonicNs']
                    < controller_after['observedMonotonicNs']
                    < audit['finishedMonotonicNs']
                    < receipt['startedMonotonicNs']
                or receipt['managerInvocation'] != sender['invocationId']
                or receipt['membership'] != 'only-stop-helper'
                or receipt['descendantCgroups'] != 0):
            return None
        controller_digest = fixtures.runtime.canonical_digest({
            'role': 'workload-controller',
            'identity': controller_before['cgroupIdentity']})[7:]
        return {'contract': campaign.CONTRACT, 'caseId': 'stale-handle',
            'status': 'passed', 'actorEpoch': actor,
            'targetEpoch': {'kind': 'installed-controller-instance',
                'pid': controller_before['pid'], 'uid': 0,
                'startTicks': controller_before['startTicks'],
                'bootId': sender['bootId'],
                'systemdInvocation': controller_before['invocationId'],
                'cgroupDigest': controller_digest,
                'currentRoleInvocation': sender['invocationId'],
                'retiredBootId': audit['retiredBootId'],
                'retiredHandleDigest': audit['retiredHandleDigest'],
                'handoffDigest': campaign_seal._digest(handoff)},
            'operationWindow': {
                'startedMonotonicNs': replies[0]['startedMonotonicNs'],
                'finishedMonotonicNs': replies[2]['finishedMonotonicNs']},
            'attackDigest': replies[1]['exchange']['requestDigest'],
            'hostVerifiedIdentity': host, 'guestStopped': True,
            'stopReceiptObservedNs': receipt['observedMonotonicNs']}
    except (AttributeError, KeyError, TypeError, ValueError, IndexError,
            StopIteration, OSError):
        return None


def stale_pid_uid_attempt(report, result, terminal, diagnostics, source):
    """Verify an old observer rejects a real replacement sender invocation."""
    try:
        views = authority_epoch_views(report, result, terminal)
        if (views is None or not isinstance(diagnostics, dict)
                or diagnostics.get('stalePidUid', {}).get('status') != 'captured'):
            return None
        audit = terminal['stalePidUidAudit']['record']
        first_roster = result['roleKernelRoster']
        last_roster = result['authorityFinalRoleRoster']
        first = next(row for row in first_roster['roles']
                     if row['role'] == 'candidate-sender')
        last = next(row for row in last_roster['roles']
                    if row['role'] == 'candidate-sender')
        old_actor = audit['oldObserver']
        old_after = audit['oldObserverAfter']
        new_actor = audit['newObserver']
        old_first = audit['oldObserverFirst']
        rejected = audit['oldObserverRejected']
        new_result = audit['newObserverResult']
        previous = terminal['stopReceipts']['candidate-sender']['previous']['record']
        current = terminal['stopReceipts']['candidate-sender']['current']['record']
        host = report['hostVerifiedIdentity']
        audit_digest = hashlib.sha256(json.dumps(audit, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        source_digest = reference.sha256(Path(source) /
            'tools/release-certification/restricted/pr314_workload_driver.py')
        stable_actor = ('kind', 'pid', 'uid', 'startTicks', 'bootId',
                        'cgroupIdentity', 'namespaces', 'sourceDigest')
        early_roles = {row['role']: row for row in first_roster['roles']}
        late_roles = {row['role']: row for row in last_roster['roles']}
        if (audit['schemaVersion'] != 1
                or audit['kind'] != 'pr315-administrator-stale-pid-uid-denial'
                or audit['caseId'] != 'stale-pid-uid'
                or audit_digest != diagnostics['stalePidUid']['auditDigest']
                or host['helperSourceCommit'] != result['identity']['sourceCommit']
                or any(old_actor[key] != old_after[key]
                       for key in stable_actor)
                or old_actor['kind'] != 'installed-observer-process'
                or new_actor['kind'] != 'installed-observer-process'
                or old_actor['uid'] != first_roster['observerUid']
                or new_actor['uid'] != first_roster['observerUid']
                or old_actor['sourceDigest'] != source_digest
                or new_actor['sourceDigest'] != source_digest
                or old_actor['bootId'].replace('-', '').lower() != first['bootId']
                or new_actor['bootId'].replace('-', '').lower() != last['bootId']
                or old_actor['pid'] == new_actor['pid']
                or old_actor['startTicks'] <= 0
                or new_actor['startTicks'] <= 0
                or first_roster['observerUid'] != last_roster['observerUid']
                or first_roster['runnerUid'] != last_roster['runnerUid']
                or any(early_roles[role] != late_roles[role]
                       for role in acceptance.ROLES if role != 'candidate-sender')
                or audit['oldSenderInvocation'] != first['invocationId']
                or audit['newSenderInvocation'] != last['invocationId']
                or first['invocationId'] == last['invocationId']
                or first['uid'] != last['uid']
                or first['bootId'] != last['bootId']
                or audit['oldSenderCgroup'] != previous['cgroupIdentity']
                or audit['newSenderCgroup'] != current['cgroupIdentity']
                or audit['oldStopReceipt'] != previous
                or audit['oldQuiescentAuthority']['managerInvocation'] !=
                    previous['managerInvocation']
                or previous['membership'] != 'only-stop-helper'
                or previous['descendantCgroups'] != 0
                or current['membership'] != 'only-stop-helper'
                or current['descendantCgroups'] != 0
                or audit['oldSenderState'] != audit['newSenderState']
                or terminal['sentinel']['status'] != 'matched'
                or terminal['sentinel']['observedDigest'] !=
                    'sha256:' + audit['newSenderState']
                or old_first['target']['managerInvocation'] !=
                    first['invocationId']
                or new_result['target']['managerInvocation'] !=
                    last['invocationId']
                or rejected['target'] != new_result['target']
                or rejected['reason'] != 'workload-role-invocation-changed'
                or old_first['daemon']['managerInvocation'] !=
                    first['invocationId']
                or new_result['daemon']['managerInvocation'] !=
                    last['invocationId']
                or old_first['daemon']['startTicks'] !=
                    first['processEpoch']
                or new_result['daemon']['startTicks'] !=
                    last['processEpoch']
                or (old_first['daemon']['hostPid'],
                    old_first['daemon']['startTicks']) == (
                    new_result['daemon']['hostPid'],
                    new_result['daemon']['startTicks'])
                or not all(row['exchange']['method'] == 'observe'
                    and re.fullmatch('[0-9a-f]{64}',
                        str(row['exchange']['requestDigest'])) is not None
                    and re.fullmatch('[0-9a-f]{64}',
                        str(row['exchange']['responseDigest'])) is not None
                    for row in (old_first, rejected, new_result))
                or len({row['exchange']['requestDigest'] for row in
                    (old_first, rejected, new_result)}) != 1
                or not old_actor['observedMonotonicNs']
                    < old_first['startedMonotonicNs']
                    < old_first['finishedMonotonicNs']
                    < audit['stopStartedNs']
                    < previous['startedMonotonicNs']
                    < previous['observedMonotonicNs']
                    < audit['restartStartedNs']
                    < audit['newFcpControlledNs']
                    < old_after['observedMonotonicNs']
                    < new_actor['observedMonotonicNs']
                    < new_result['startedMonotonicNs']
                    < new_result['finishedMonotonicNs']
                    < rejected['startedMonotonicNs']
                    < rejected['finishedMonotonicNs']
                    < audit['rosterWindow']['startedMonotonicNs']
                    < audit['rosterWindow']['finishedMonotonicNs']
                    < audit['finishedMonotonicNs']
                    < current['startedMonotonicNs']
                or audit['rosterWindow'] != result['authorityFinalRosterWindow']
                or re.fullmatch('[0-9a-f]{64}',
                    str(audit['newFcpControlDigest'])) is None):
            return None
        controller_digest = fixtures.runtime.canonical_digest({
            'role': 'candidate-sender',
            'identity': audit['newSenderCgroup']})[7:]
        if controller_digest != last['cgroupDigest']:
            return None
        return {'contract': campaign.CONTRACT,
            'caseId': 'stale-pid-uid', 'status': 'passed',
            'actorEpoch': old_actor,
            'targetEpoch': {'kind': 'installed-process-observer-epoch-check',
                'oldObserverPid': old_actor['pid'],
                'newObserverPid': new_actor['pid'],
                'oldSenderInvocation': first['invocationId'],
                'newSenderInvocation': last['invocationId'],
                'oldDaemonPid': old_first['daemon']['hostPid'],
                'newDaemonPid': new_result['daemon']['hostPid'],
                'newDaemonStartTicks': new_result['daemon']['startTicks'],
                'uid': first['uid'], 'bootId': first['bootId'],
                'cgroupDigest': last['cgroupDigest'],
                'newFcpControlDigest': audit['newFcpControlDigest']},
            'operationWindow': {
                'startedMonotonicNs': old_first['startedMonotonicNs'],
                'finishedMonotonicNs': rejected['finishedMonotonicNs']},
            'attackDigest': audit_digest,
            'hostVerifiedIdentity': host, 'guestStopped': True,
            'stopReceiptObservedNs': current['observedMonotonicNs']}
    except (AttributeError, KeyError, TypeError, ValueError, IndexError,
            StopIteration, OSError):
        return None


def cleanup_race_attempt(report, result, terminal, diagnostics, source):
    """Require a real replaced manager, rejected old stop and exact cleanup."""
    try:
        if (not group_prepared(report, result, terminal, 'cleanup-race')
                or not selected_probe_started('cleanup-race', diagnostics)
                or terminal.get('cleanupRaceAudit', {}).get('status') !=
                    'captured'
                or diagnostics.get('cleanupRace', {}).get('status') !=
                    'captured'):
            return None
        audit = terminal['cleanupRaceAudit']['record']
        host = report['hostVerifiedIdentity']
        sender = next(row for row in result['roleKernelRoster']['roles']
                      if row['role'] == 'candidate-sender')
        admin = audit['administratorBefore']
        admin_after = audit['administratorAfter']
        observer = audit['stopActor']
        phase = audit['stopPhase']
        before = audit['managerBefore']
        replacement = audit['managerReplacement']
        reset = audit['managerReset']
        denied = audit['observerDenial']
        record = audit['reconciliationState']
        receipt = terminal['stopReceipts']['candidate-sender']['current']['record']
        source_digest = reference.sha256(Path(source) /
            'tools/release-certification/restricted/pr314_workload_driver.py')
        barrier_digest = reference.sha256(Path(source) /
            'tools/release-certification/protected/restricted_workload_lifecycle_barrier.py')
        audit_digest = hashlib.sha256(json.dumps(audit, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        stable_admin = ('pid', 'uid', 'startTicks', 'bootId',
                        'cgroupIdentity', 'cgroupDigest',
                        'invocationId', 'sourceDigest')
        stable_sibling = ('role', 'managerInvocation', 'bootId',
                          'cgroupIdentity', 'stateDigest')
        if (audit['schemaVersion'] != 1
                or audit['kind'] != 'pr315-administrator-cleanup-race'
                or audit['caseId'] != 'cleanup-race'
                or audit_digest != diagnostics['cleanupRace']['auditDigest']
                or audit['barrierSourceDigest'] != barrier_digest
                or re.fullmatch('[0-9a-f]{64}',
                    str(audit['nonceDigest'])) is None
                or any(admin[key] != admin_after[key]
                       for key in stable_admin)
                or admin['uid'] != 0 or admin['pid'] <= 1
                or admin['sourceDigest'] != source_digest
                or admin['bootId'].replace('-', '').lower() != sender['bootId']
                or observer['kind'] != 'installed-observer-process'
                or observer['uid'] != result['roleKernelRoster']['observerUid']
                or observer['sourceDigest'] != source_digest
                or observer['bootId'].replace('-', '').lower() !=
                    sender['bootId']
                or before['InvocationID'] != sender['invocationId']
                or before['ActiveState'] != 'active'
                or before['SubState'] != 'running'
                or before['ControlGroup'] !=
                    '/system.slice/cryptad-workload@candidate-sender.service'
                or replacement['InvocationID'] == before['InvocationID']
                or replacement['ActiveState'] == 'active'
                or replacement['MainPID'] != '0'
                or audit['replacementCgroupIdentity'] ==
                    audit['senderBefore']['cgroupIdentity']
                or (audit['replacementCgroupIdentity'] is not None
                    and (not isinstance(audit['replacementCgroupIdentity'], list)
                         or len(audit['replacementCgroupIdentity']) != 2
                         or any(type(value) is not int or value <= 0
                                for value in
                                audit['replacementCgroupIdentity'])))
                or reset['ActiveState'] not in ('inactive', 'failed')
                or reset['MainPID'] != '0'
                or phase['caseId'] != 'cleanup-race'
                or phase['nonceDigest'] != audit['nonceDigest']
                or phase['managerInvocation'] != sender['invocationId']
                or phase['cgroupIdentity'] !=
                    audit['senderBefore']['cgroupIdentity']
                or phase['bootId'].replace('-', '').lower() != sender['bootId']
                or audit['senderBefore']['managerInvocation'] !=
                    sender['invocationId']
                or fixtures.runtime.canonical_digest({
                    'role': 'candidate-sender',
                    'identity': audit['senderBefore']['cgroupIdentity']})[7:]
                    != sender['cgroupDigest']
                or audit['senderBefore']['stateDigest'] !=
                    terminal['sentinel']['observedDigest'].removeprefix('sha256:')
                or denied['status'] != 'rejected'
                or denied['reason'] != 'workload-controller-request-rejected'
                or denied['exchange']['method'] != 'stop'
                or denied['exchange']['responseDigest'] != hashlib.sha256(
                    b'{"error":"restricted-workload-request-failed"}\n').hexdigest()
                or record['state'] != 'reconciliation-required'
                or record['managerInvocation'] != sender['invocationId']
                or record['cgroupIdentity'] !=
                    audit['senderBefore']['cgroupIdentity']
                or audit['oldStopReceipt'] != receipt
                or audit['finalStopReceipt'] != receipt
                or receipt['managerInvocation'] != sender['invocationId']
                or receipt['membership'] != 'only-stop-helper'
                or receipt['descendantCgroups'] != 0
                or not isinstance(audit['siblingsBefore'], list)
                or len(audit['siblingsBefore']) != 3
                or not isinstance(audit['siblingsAfter'], list)
                or len(audit['siblingsAfter']) != 3
                or any(any(first[key] != last[key]
                           for key in stable_sibling)
                       for first, last in zip(audit['siblingsBefore'],
                                              audit['siblingsAfter']))
                or not diagnostics['probeStart']['startedMonotonicNs']
                    < audit['senderBefore']['observedMonotonicNs']
                    < audit['siblingsBefore'][-1]['controlObservedNs']
                    < observer['observedMonotonicNs']
                    < phase['observedMonotonicNs']
                    < audit['restart']['startedMonotonicNs']
                    < receipt['startedMonotonicNs']
                    <= receipt['observedMonotonicNs']
                    < audit['restart']['finishedMonotonicNs']
                    < audit['releasePublishedNs']
                    < denied['finishedMonotonicNs']
                    < audit['siblingsAfter'][0]['observedMonotonicNs']
                    < admin_after['observedMonotonicNs']
                    < audit['finishedMonotonicNs']
                or host['helperSourceCommit'] != result['identity']['sourceCommit']):
            return None
        return {'contract': campaign.CONTRACT,
            'caseId': 'cleanup-race', 'status': 'passed',
            'actorEpoch': {**admin, 'kind': 'administrator-test-kit'},
            'targetEpoch': {'kind': 'owned-roles-reconciled-after-manager-replacement',
                'roles': result['roleKernelRoster']['roles'],
                'oldInvocation': sender['invocationId'],
                'replacementInvocation': replacement['InvocationID'],
                'oldStopReceiptDigest': hashlib.sha256(json.dumps(
                    receipt, sort_keys=True,
                    separators=(',', ':')).encode()).hexdigest()},
            'operationWindow': {
                'startedMonotonicNs': phase['observedMonotonicNs'],
                'finishedMonotonicNs': audit['finishedMonotonicNs']},
            'attackDigest': audit_digest,
            'hostVerifiedIdentity': host, 'guestStopped': True,
            'stopReceiptObservedNs': max(
                terminal['stopReceipts'][row['role']]['current']
                    ['record']['observedMonotonicNs']
                for row in result['roleKernelRoster']['roles'])}
    except (AttributeError, KeyError, TypeError, ValueError, IndexError,
            StopIteration, OSError):
        return None


def _bounded_window(value):
    return (isinstance(value, dict) and set(value) == {'startedMonotonicNs', 'finishedMonotonicNs'}
            and type(value['startedMonotonicNs']) is int
            and type(value['finishedMonotonicNs']) is int
            and 0 < value['startedMonotonicNs'] < value['finishedMonotonicNs'])


def _app_case(result, identity, principals):
    raw, window = result.get('appKernelProcess'), result.get('appKernelWindow')
    if not isinstance(raw, dict) or not _bounded_window(window):
        return None
    if (set(raw) != {'role', 'provider', 'hostPid', 'namespacePid', 'processEpoch',
                     'invocationId', 'javaHostPid', 'javaStartTicks', 'provenance'}
            or raw['provenance'] != 'controller-kernel-sample'
            or type(raw['javaHostPid']) is not int or raw['javaHostPid'] <= 1
            or type(raw['processEpoch']) is not int
            or type(raw['javaStartTicks']) is not int
            or raw['javaStartTicks'] < raw['processEpoch']):
        return None
    witness = {key: raw[key] for key in ('role', 'provider', 'hostPid', 'namespacePid',
        'processEpoch', 'invocationId')}
    witness['installedAppDigest'] = identity['admittedAppDigest']
    if not acceptance._app_process(witness, identity, principals):
        return None
    return witness, window


def _resource_case(diagnostics, principals):
    if not isinstance(diagnostics, dict):
        return None
    measurements, windows = [], []
    try:
        services = diagnostics['during']['services']
        for row in principals['roles']:
            service = services['cryptad-workload@' + row['role'] + '.service']
            sample, window = service['lastObserved'], service['lastObservedWindow']
            if (not _bounded_window(window)
                    or row['cgroupDigest'] != fixtures.runtime.canonical_digest({
                        'role': row['role'], 'identity': sample['cgroupIdentity']})[7:]):
                return None
            measurements.append({key: row[key] for key in
                ('role', 'invocationId', 'processEpoch', 'bootId', 'cgroupDigest')} | {
                'memoryCurrentBytes': sample['memory.current'],
                'pidsCurrent': sample['pids.current'],
                'cpuUsageUsec': sample['cpu.stat']['usage_usec']})
            windows.append(window)
    except (KeyError, TypeError, ValueError):
        return None
    witness = {'source': 'cgroup-v2', 'measurements': measurements}
    if not acceptance._resources(witness, principals):
        return None
    return witness, {'startedMonotonicNs': min(w['startedMonotonicNs'] for w in windows),
                     'finishedMonotonicNs': max(w['finishedMonotonicNs'] for w in windows)}


def _exchange_case(case_id, result, terminal, principals):
    methods = {'own-management': 'connect-fcp', 'dynamic-app-bootstrap': 'bootstrap-mail'}
    observed = result.get('controlExchanges')
    audits = terminal.get('exchangeAudits') if isinstance(terminal, dict) else None
    if not isinstance(observed, dict) or not isinstance(audits, dict):
        return None
    sent, retained = observed.get(case_id), audits.get(case_id)
    if (not isinstance(sent, dict) or not isinstance(retained, dict)
            or retained.get('status') != 'captured'
            or not isinstance(retained.get('record'), dict)):
        return None
    audit = retained['record']
    sender = next((row for row in principals['roles'] if row['role'] == 'candidate-sender'), None)
    if (set(audit) != EXCHANGE_AUDIT_FIELDS
            or set(sent) != {'method', 'requestDigest', 'responseDigest'}
            or sender is None
            or any(type(audit[key]) is not str for key in
                   ('kind', 'caseId', 'method', 'role', 'managerInvocation', 'bootId',
                    'requestDigest', 'responseDigest'))
            or any(type(sent[key]) is not str for key in
                   ('method', 'requestDigest', 'responseDigest'))
            or not isinstance(audit['cgroupIdentity'], list)
            or len(audit['cgroupIdentity']) != 2
            or any(type(part) is not int or part < 1 for part in audit['cgroupIdentity'])
            or audit['schemaVersion'] != 1 or audit['kind'] != 'pr315-fixed-exchange-audit'
            or audit['caseId'] != case_id or audit['method'] != methods[case_id]
            or sent['method'] != audit['method'] or audit['role'] != 'candidate-sender'
            or audit['managerInvocation'] != sender['invocationId']
            or audit['bootId'].replace('-', '').lower() != sender['bootId']
            or sender['cgroupDigest'] != fixtures.runtime.canonical_digest({
                'role': 'candidate-sender', 'identity': audit['cgroupIdentity']})[7:]
            or any(re.fullmatch('[0-9a-f]{64}', value) is None for value in
                   (audit['requestDigest'], audit['responseDigest']))
            or sent['requestDigest'] != audit['requestDigest']
            or sent['responseDigest'] != audit['responseDigest']
            or type(audit['serverRequests']) is not int or audit['serverRequests'] != 1):
        return None
    window = {'startedMonotonicNs': audit['startedMonotonicNs'],
              'finishedMonotonicNs': audit['finishedMonotonicNs']}
    if not _bounded_window(window):
        return None
    root_witness = {'caseId': case_id, 'operationDigest': '',
        'requestDigest': audit['requestDigest'],
        'expectedResponseDigest': audit['responseDigest'],
        'responseDigest': audit['responseDigest'],
        'serverInvocationId': audit['managerInvocation'],
        'serverRequests': audit['serverRequests']}
    commitment = acceptance.payload_commitment(case_id, root_witness)
    witness = dict(root_witness, responseDigest=sent['responseDigest'], operationDigest=commitment)
    if acceptance.payload_commitment(case_id, witness) != commitment:
        return None
    return witness, window, commitment


def _restart_case(result, terminal, principals):
    context, window = result.get('restartContext'), result.get('restartWindow')
    if not _bounded_window(window) or not isinstance(context, dict) or not isinstance(terminal, dict):
        return None
    try:
        if not acceptance._restart_context(context, principals):
            return None
        before, after = context['before'], context['after']
        earlier = terminal['stopReceipts']['candidate-sender']['previous']
        current = terminal['stopReceipts']['candidate-sender']['current']
        campaign = terminal['controllerRecords']['campaign']
        sentinel = terminal['sentinel']
        if (earlier['status'] != 'captured' or current['status'] != 'captured'
                or campaign['status'] != 'captured' or sentinel['status'] != 'matched'
                or any(not window['startedMonotonicNs'] <= snapshot['observedMonotonicNs']
                       <= window['finishedMonotonicNs'] for snapshot in (before, after))
                or campaign['record']['deadlineMonotonicNs'] != before['deadlineNs']
                or before['deadlineNs'] != after['deadlineNs']
                or sentinel['observedDigest'] != 'sha256:' + before['stateDigest']
                or before['stateDigest'] != after['stateDigest']):
            return None
        for snapshot, receipt in ((before, earlier['record']), (after, current['record'])):
            role = snapshot['roleIdentity']
            if (role['invocationId'] != receipt['managerInvocation']
                    or role['bootId'] != receipt['bootId'].replace('-', '').lower()
                    or role['cgroupDigest'] != fixtures.runtime.canonical_digest({
                        'role': 'candidate-sender', 'identity': receipt['cgroupIdentity']})[7:]):
                return None
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
    old, new = before['roleIdentity'], after['roleIdentity']
    witness = {'role': 'candidate-sender', 'beforeInvocationId': old['invocationId'],
        'afterInvocationId': new['invocationId'], 'beforeEpoch': old['processEpoch'],
        'afterEpoch': new['processEpoch'], 'beforeStateDigest': before['stateDigest'],
        'afterStateDigest': after['stateDigest'], 'deadlineUnchanged': True}
    return witness, window, context


def _fcp_fields(lines):
    fields = {}
    for line in lines:
        if '=' not in line:
            return None
        key, value = line.split('=', 1)
        if not key or len(key) > 64 or len(value) > 4096 or key in fields:
            return None
        fields[key] = value
    return fields


def _recipient_content_from_tail(terminal, operation):
    try:
        captured = terminal['observerFcpLogs']['candidate-recipient']
        if captured['status'] != 'captured':
            return None
        raw = base64.b64decode(captured['tailBase64'], validate=True)
        if len(raw) != captured['tailBytes'] or len(raw) > 2048:
            return None
        transcript = raw.decode('utf-8')
        selected = []
        for match in re.finditer(r'\] SEND ClientGet\n(.*?)EndMessage\n', transcript, re.S):
            fields = _fcp_fields(match[1].splitlines())
            if fields is not None and fields.get('Identifier') == operation + '-fetch':
                selected.append((fields, match.end()))
        if len(selected) != 1:
            return None
        fields, end = selected[0]
        uri = fields.get('URI', '')
        if (not uri.startswith('CHK@') or fields != fixtures.runtime.interop.build_client_get_fields(
                operation + '-fetch', uri, ignore_ds=True)):
            return None
        later = transcript[end:]
        data_at = later.find('] RECV AllData\n')
        if data_at < 0 or '] RECV GetFailed\n' in later[:data_at]:
            return None
        body = later[data_at + len('] RECV AllData\n'):]
        header, separator, payload_section = body.partition('\nData\n')
        if not separator:
            return None
        values = _fcp_fields(header.splitlines())
        payload_fields = _fcp_fields(payload_section.splitlines()[:2])
        if (values is None or payload_fields is None
                or values.get('Identifier') != operation + '-fetch'
                or not values.get('DataLength', '').isdigit()
                or not payload_fields.get('PayloadLength', '').isdigit()
                or set(payload_fields) != {'PayloadLength', 'PayloadBase64'}):
            return None
        payload = base64.b64decode(payload_fields['PayloadBase64'], validate=True)
        if (not 1 <= len(payload) <= 1024 * 1024
                or len(payload) != int(values['DataLength'])
                or len(payload) != int(payload_fields['PayloadLength'])):
            return None
        return {'requestDigest': fixtures.runtime.canonical_digest(fields)[7:],
                'responseDigest': hashlib.sha256(payload).hexdigest(),
                'referenceDigest': hashlib.sha256(uri.encode()).hexdigest(),
                'bytes': len(payload)}
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError):
        return None


def _fnp_case(result, terminal, identity, principals):
    content = result.get('contentEvidence')
    observed_pair = result.get('fnpCounterPair')
    if (not isinstance(content, dict) or not isinstance(observed_pair, dict)
            or not isinstance(terminal, dict)):
        return None
    try:
        operation = content['operation']
        if (not isinstance(operation, str) or re.fullmatch('op-[0-9a-f]{32}', operation) is None
                or content['source'] != 'candidate-sender'
                or content['recipient'] != 'candidate-recipient'):
            return None
        root_bytes = _recipient_content_from_tail(terminal, operation)
        expected = fixtures.runtime.fixed_pr315_payload(identity['helperSourceCommit'], operation)
        expected_digest = hashlib.sha256(expected).hexdigest()
        if (root_bytes is None or root_bytes['bytes'] != len(expected)
                or any(content[key] != root_bytes[key] for key in
                       ('requestDigest', 'responseDigest', 'referenceDigest', 'bytes'))
                or any(content[key] != expected_digest for key in
                       ('payloadDigest', 'sourceControlDigest', 'responseDigest'))):
            return None
        retained = terminal['fnpCounterPair']
        if retained['status'] != 'captured':
            return None
        pair = retained['record']
        recipient = next(row for row in principals['roles'] if row['role'] == 'candidate-recipient')
        if (pair.get('kind') != 'pr315-administrator-fnp-counter-pair'
                or pair['caseId'] != 'fnp-content-retrieval' or pair['role'] != 'candidate-recipient'
                or pair['managerInvocation'] != recipient['invocationId']
                or set(observed_pair) != {'before', 'after'}):
            return None
        before, after = pair['before'], pair['after']
        for phase, sample in (('before', before), ('after', after)):
            observed = observed_pair[phase]
            if (not isinstance(observed, dict)
                    or observed != {'phase': phase, 'managerInvocation': recipient['invocationId'],
                                    'snapshot': sample}
                    or sample['policyDigest'] != hashlib.sha256(
                        workload_network.switch_rules().encode()).hexdigest()
                    or sample['bootId'].replace('-', '').lower() != recipient['bootId']):
                return None
        window = {'startedMonotonicNs': before['observedMonotonicNs'],
                  'finishedMonotonicNs': after['observedMonotonicNs']}
        if (not _bounded_window(window)
                or not window['startedMonotonicNs'] < content['startedMonotonicNs']
                    < content['finishedMonotonicNs'] < window['finishedMonotonicNs']):
            return None
        for link in (('candidate-recipient', 'relay-no-apps'),
                     ('relay-no-apps', 'candidate-sender'),
                     ('candidate-sender', 'relay-no-apps'),
                     ('relay-no-apps', 'candidate-recipient')):
            name = workload_network.FNP_COUNTERS[link]
            if any(after['counters'][name][key] <= before['counters'][name][key]
                   for key in ('packets', 'bytes')):
                return None
    except (AttributeError, KeyError, StopIteration, TypeError, ValueError):
        return None
    root_witness = {'caseId': 'fnp-content-retrieval', 'operationDigest': '',
        'requestDigest': root_bytes['requestDigest'],
        'expectedResponseDigest': expected_digest,
        'responseDigest': root_bytes['responseDigest'],
        'serverInvocationId': recipient['invocationId'], 'serverRequests': 1}
    commitment = acceptance.payload_commitment('fnp-content-retrieval', root_witness)
    witness = dict(root_witness, requestDigest=content['requestDigest'],
                   responseDigest=content['responseDigest'], operationDigest=commitment)
    if acceptance.payload_commitment('fnp-content-retrieval', witness) != commitment:
        return None
    return witness, window, commitment


def _lost_start_case(report, result, diagnostics, terminal, principals):
    """Bind a dropped response to the original live invocation before retry."""
    if (not isinstance(diagnostics, dict) or not isinstance(terminal, dict)
            or report.get('guestStopped') is not True
            or terminal.get('cleanupReportedByCaller') is not True
            or diagnostics.get('cleanup') != 'completed'):
        return None
    context = diagnostics.get('lostStartResponse')
    marker = diagnostics.get('probeStart')
    try:
        if (not isinstance(context, dict) or set(context) != {
                'schemaVersion', 'kind', 'before', 'requestDigest', 'first',
                'droppedRequest', 'retry'}
                or context['schemaVersion'] != 1
                or context['kind'] != 'pr315-administrator-lost-start-intent'
                or not isinstance(marker, dict) or set(marker) != {
                'schemaVersion', 'kind', 'caseId', 'startedMonotonicNs'}
                or marker['schemaVersion'] != 1
                or marker['kind'] != 'pr315-workload-probe-start'
                or marker['caseId'] != 'lost-start-response'
                or not _bounded_window({'startedMonotonicNs': marker['startedMonotonicNs'],
                                        'finishedMonotonicNs': diagnostics['cleanupFinishedNs']})
                or not isinstance(context['before'], dict)
                or not isinstance(context['first'], dict)
                or not isinstance(context['retry'], dict)
                or not isinstance(context['droppedRequest'], dict)
                or context['before'] != diagnostics['lostStartBefore']
                or context['requestDigest'] != context['droppedRequest']['requestDigest']
                or re.fullmatch('[0-9a-f]{64}', context['requestDigest']) is None):
            return None
        before, first, retry, dropped = (context[key] for key in
            ('before', 'first', 'retry', 'droppedRequest'))
        stable = ('role', 'generation', 'managerInvocation', 'bootId',
                  'cgroupIdentity', 'mainPid')
        if (set(before) != {'role', 'state', 'generation', 'managerInvocation',
                            'cgroupIdentity', 'bootId', 'mainPid', 'observedMonotonicNs'}
                or set(first) != set(stable) | {'observedMonotonicNs'}
                or set(retry) != set(first)
                or set(dropped) != {'requestDigest', 'sendStartedNs', 'sendFinishedNs'}
                or before['role'] != 'candidate-sender' or before['state'] != 'prepared'
                or any(before[key] is not None for key in
                       ('generation', 'managerInvocation', 'cgroupIdentity'))
                or before['mainPid'] != 0
                or first['role'] != 'candidate-sender'
                or any(first[key] != retry[key] for key in stable)
                or before['bootId'] != first['bootId']
                or re.fullmatch('[0-9a-f]{64}', first['generation']) is None
                or re.fullmatch('[0-9a-f]{32}', first['managerInvocation']) is None
                or type(first['mainPid']) is not int or first['mainPid'] <= 1
                or not isinstance(first['cgroupIdentity'], list)
                or len(first['cgroupIdentity']) != 2
                or any(type(part) is not int or part < 1
                       for part in first['cgroupIdentity'])):
            return None
        roster_window = result['roleKernelRosterWindow']
        if (not _bounded_window(roster_window)
                or not 0 < before['observedMonotonicNs']
                    < marker['startedMonotonicNs']
                    < dropped['sendStartedNs'] < dropped['sendFinishedNs']
                    < first['observedMonotonicNs'] < roster_window['startedMonotonicNs']
                    < roster_window['finishedMonotonicNs'] < retry['observedMonotonicNs']
                    < diagnostics['cleanupFinishedNs']):
            return None
        sender = next(row for row in principals['roles']
                      if row['role'] == 'candidate-sender')
        if (sender['invocationId'] != first['managerInvocation']
                or sender['bootId'] != first['bootId'].replace('-', '').lower()
                or sender['cgroupDigest'] != fixtures.runtime.canonical_digest({
                    'role': 'candidate-sender',
                    'identity': first['cgroupIdentity']})[7:]):
            return None
        campaign_record = terminal['controllerRecords']['campaign']
        if (campaign_record['status'] != 'captured'
                or campaign_record['record']['state'] != 'terminalizing'
                or campaign_record['record']['deadlineMonotonicNs'] !=
                    result['campaignDeadlineMonotonicNs']
                or first['observedMonotonicNs'] >= result['campaignDeadlineMonotonicNs']):
            return None
        for row in principals['roles']:
            receipt = terminal['stopReceipts'][row['role']]['current']
            if (receipt['status'] != 'captured'
                    or receipt['record']['managerInvocation'] != row['invocationId']
                    or receipt['record']['membership'] != 'only-stop-helper'
                    or receipt['record']['descendantCgroups'] != 0
                    or not retry['observedMonotonicNs'] <
                        receipt['record']['startedMonotonicNs']
                        <= receipt['record']['observedMonotonicNs']
                        < diagnostics['cleanupFinishedNs']):
                return None
    except (AttributeError, KeyError, StopIteration, TypeError, ValueError):
        return None
    event = {'kind': 'lost-start-response',
             'requestDigest': context['requestDigest'],
             'firstInvocation': first['managerInvocation'],
             'firstGeneration': first['generation'],
             'firstCgroupIdentity': first['cgroupIdentity'],
             'retryObservedNs': retry['observedMonotonicNs']}
    witness = {'caseId': 'lost-start-response', 'triggerDigest': '',
        'trigger': {'kind': 'lost-start-response',
                    'eventDigest': fixtures.runtime.canonical_digest(event)[7:]},
        'triggerStartedNs': marker['startedMonotonicNs'],
        'terminalObservedNs': diagnostics['cleanupFinishedNs'],
        'roles': principals['roles'], 'populatedCgroups': [],
        'remainingDescendants': 0, 'retention': 'retained'}
    commitment = acceptance.payload_commitment('lost-start-response', witness)
    witness['triggerDigest'] = commitment
    return witness, {'startedMonotonicNs': marker['startedMonotonicNs'],
                     'finishedMonotonicNs': diagnostics['cleanupFinishedNs']}, commitment


def _cancellation_case(report, result, diagnostics, terminal, principals):
    """Require the administrator's active-role trigger and exact stopped-role receipts."""
    if (not isinstance(diagnostics, dict) or not isinstance(terminal, dict)
            or report.get('guestStopped') is not True
            or terminal.get('cleanupReportedByCaller') is not True):
        return None
    context = diagnostics.get('cancellation')
    try:
        if (not isinstance(context, dict)
                or set(context) != {'schemaVersion', 'kind', 'triggerStartedNs',
                                    'triggerEventDigest', 'campaignDeadlineNs', 'preRoles',
                                    'terminalObservedNs', 'populatedCgroups',
                                    'remainingDescendants', 'retention'}
                or context['schemaVersion'] != 1
                or context['kind'] != 'pr315-administrator-cancellation'
                or context['populatedCgroups'] != [] or context['remainingDescendants'] != 0
                or context['retention'] != 'retained'
                or not _bounded_window({'startedMonotonicNs': context['triggerStartedNs'],
                                        'finishedMonotonicNs': context['terminalObservedNs']})
                or context['triggerStartedNs'] >= context['campaignDeadlineNs']
                or len(context['preRoles']) != len(acceptance.ROLES)):
            return None
        campaign = terminal['controllerRecords']['campaign']
        if (campaign['status'] != 'captured'
                or campaign['record']['state'] != 'terminalizing'
                or campaign['record']['deadlineMonotonicNs'] != context['campaignDeadlineNs']):
            return None
        rows = context['preRoles']
        if (not all(isinstance(row, dict) and
                    set(row) == {'role', 'managerInvocation', 'bootId', 'cgroupIdentity', 'mainPid'}
                    for row in rows)
                or {row['role'] for row in rows} != set(acceptance.ROLES)
                or len({row['mainPid'] for row in rows}) != len(rows)):
            return None
        expected_event = {'kind': 'cancellation', 'roles': rows,
                          'campaignDeadlineNs': context['campaignDeadlineNs']}
        if context['triggerEventDigest'] != fixtures.runtime.canonical_digest(expected_event)[7:]:
            return None
        for row in rows:
            role = row['role']
            principal = next(item for item in principals['roles'] if item['role'] == role)
            receipt = terminal['stopReceipts'][role]['current']
            if (type(row['mainPid']) is not int or row['mainPid'] <= 0
                    or row['managerInvocation'] != principal['invocationId']
                    or row['bootId'].replace('-', '').lower() != principal['bootId']
                    or fixtures.runtime.canonical_digest({
                        'role': role, 'identity': row['cgroupIdentity']})[7:] != principal['cgroupDigest']
                    or receipt['status'] != 'captured'):
                return None
            stopped = receipt['record']
            if (any(stopped[key] != row[key] for key in
                    ('role', 'managerInvocation', 'bootId', 'cgroupIdentity'))
                    or stopped['membership'] != 'only-stop-helper'
                    or stopped['descendantCgroups'] != 0
                    or not context['triggerStartedNs'] < stopped['startedMonotonicNs']
                        <= stopped['observedMonotonicNs'] <= context['terminalObservedNs']):
                return None
    except (AttributeError, KeyError, StopIteration, TypeError, ValueError):
        return None
    witness = {'caseId': 'cancellation', 'triggerDigest': '',
        'trigger': {'kind': 'cancellation', 'eventDigest': context['triggerEventDigest']},
        'triggerStartedNs': context['triggerStartedNs'],
        'terminalObservedNs': context['terminalObservedNs'],
        'roles': principals['roles'], 'populatedCgroups': [],
        'remainingDescendants': 0, 'retention': 'retained'}
    commitment = acceptance.payload_commitment('cancellation', witness)
    witness['triggerDigest'] = commitment
    return witness, {'startedMonotonicNs': context['triggerStartedNs'],
                     'finishedMonotonicNs': context['terminalObservedNs']}, commitment


def _deadline_heartbeat_proof(context, diagnostics, principals):
    """Require real fixed-observer activity through the original wait, not a timer claim."""
    beats = context.get('observerHeartbeats')
    if (context.get('observerHeartbeatPolicy') != 'fixed-observer-deadline-60s-v1'
            or not isinstance(beats, list) or not 1 <= len(beats) <= 64):
        return None
    source = diagnostics['lifecycleActorBefore']['sourceDigest']
    deadline = context['campaignDeadlineNs']
    previous = context['armedMonotonicNs']
    first_controller = None
    request_digest = None
    for beat in beats:
        fields = {'actor', 'requestDigest', 'responseDigest', 'requestStartedNs',
            'responseObservedNs', 'exitStartedNs', 'exitObservedNs', 'pidfdUsed',
            'exitStatus', 'controllerInvocation', 'controllerPid', 'controllerStartTicks'}
        if not isinstance(beat, dict) or set(beat) != fields:
            return None
        actor = beat['actor']
        controller = (beat['controllerInvocation'], beat['controllerPid'], beat['controllerStartTicks'])
        if (not isinstance(actor, dict) or actor.get('kind') != 'installed-observer-process'
                or actor.get('uid') != principals['observerUid']
                or type(actor.get('pid')) is not int or actor['pid'] <= 1
                or type(actor.get('startTicks')) is not int or actor['startTicks'] <= 0
                or actor.get('sourceDigest') != source
                or actor.get('bootId', '').replace('-', '').lower() != principals['roles'][0]['bootId']
                or not isinstance(actor.get('namespaces'), dict)
                or set(actor['namespaces']) != {'pid', 'net', 'mnt', 'user'}
                or any(type(value) is not int or value <= 0 for value in actor['namespaces'].values())
                or beat['pidfdUsed'] is not True or beat['exitStatus'] != 0
                or re.fullmatch('[0-9a-f]{64}', str(beat['requestDigest'])) is None
                or re.fullmatch('[0-9a-f]{64}', str(beat['responseDigest'])) is None
                or re.fullmatch('[0-9a-f]{32}', str(beat['controllerInvocation'])) is None
                or type(beat['controllerPid']) is not int or beat['controllerPid'] <= 1
                or type(beat['controllerStartTicks']) is not int or beat['controllerStartTicks'] <= 0
                or any(type(beat[key]) is not int for key in ('requestStartedNs',
                    'responseObservedNs', 'exitStartedNs', 'exitObservedNs'))
                or not previous <= beat['requestStartedNs'] < beat['responseObservedNs']
                    < beat['exitStartedNs'] < beat['exitObservedNs'] < deadline
                or beat['responseObservedNs'] - previous >= 240 * 10**9):
            return None
        if first_controller is None:
            first_controller, request_digest = controller, beat['requestDigest']
        elif controller != first_controller or beat['requestDigest'] != request_digest:
            return None
        previous = beat['responseObservedNs']
    if deadline - previous >= 240 * 10**9:
        return None
    return {'policy': context['observerHeartbeatPolicy'], 'count': len(beats),
        'recordsDigest': fixtures.runtime.canonical_digest(beats)[7:],
        'firstObserver': beats[0]['actor'], 'lastObserver': beats[-1]['actor'],
        'firstResponseNs': beats[0]['responseObservedNs'], 'lastResponseNs': previous,
        'controllerInvocation': first_controller[0], 'controllerPid': first_controller[1],
        'controllerStartTicks': first_controller[2]}


def _deadline_case(report, diagnostics, terminal, principals):
    """Require each role's own stop receipt after the unmodified campaign deadline."""
    if (not isinstance(diagnostics, dict) or not isinstance(terminal, dict)
            or report.get('guestStopped') is not True
            or terminal.get('cleanupReportedByCaller') is not True):
        return None
    context = diagnostics.get('deadline')
    try:
        if (not isinstance(context, dict) or set(context) != {
                'schemaVersion', 'kind', 'armedMonotonicNs', 'triggerEventDigest',
                'campaignDeadlineNs', 'preRoles', 'terminalObservedNs',
                'roleStops', 'populatedCgroups', 'remainingDescendants', 'retention',
                'observerHeartbeatPolicy', 'observerHeartbeats'}
                or context['schemaVersion'] != 1
                or context['kind'] != 'pr315-administrator-deadline'
                or context['populatedCgroups'] != []
                or context['remainingDescendants'] != 0
                or context['retention'] != 'retained'
                or not 0 < context['armedMonotonicNs'] < context['campaignDeadlineNs']
                    < context['terminalObservedNs']
                or len(context['preRoles']) != len(acceptance.ROLES)
                or len(context['roleStops']) != len(acceptance.ROLES)):
            return None
        if _deadline_heartbeat_proof(context, diagnostics, principals) is None:
            return None
        campaign = terminal['controllerRecords']['campaign']
        if (campaign['status'] != 'captured'
                or campaign['record']['state'] != 'terminalizing'
                or campaign['record']['deadlineMonotonicNs'] !=
                    context['campaignDeadlineNs']):
            return None
        rows = context['preRoles']
        stops = context['roleStops']
        if (not all(isinstance(row, dict) and set(row) == {
                'role', 'managerInvocation', 'bootId', 'cgroupIdentity', 'mainPid'}
                for row in rows)
                or {row['role'] for row in rows} != set(acceptance.ROLES)
                or not all(isinstance(row, dict) and set(row) == {
                    'role', 'managerInvocation', 'receiptStartedNs',
                    'receiptObservedNs'} for row in stops)
                or {row['role'] for row in stops} != set(acceptance.ROLES)):
            return None
        event = {'kind': 'deadline', 'roles': rows,
                 'campaignDeadlineNs': context['campaignDeadlineNs']}
        if context['triggerEventDigest'] != fixtures.runtime.canonical_digest(event)[7:]:
            return None
        for row in rows:
            role = row['role']
            principal = next(item for item in principals['roles']
                             if item['role'] == role)
            stop = next(item for item in stops if item['role'] == role)
            receipt = terminal['stopReceipts'][role]['current']
            if (type(row['mainPid']) is not int or row['mainPid'] <= 0
                    or row['managerInvocation'] != principal['invocationId']
                    or row['bootId'].replace('-', '').lower() != principal['bootId']
                    or fixtures.runtime.canonical_digest({
                        'role': role, 'identity': row['cgroupIdentity']})[7:] !=
                        principal['cgroupDigest']
                    or receipt['status'] != 'captured'):
                return None
            retained = receipt['record']
            if (any(retained[key] != row[key] for key in
                    ('role', 'managerInvocation', 'bootId', 'cgroupIdentity'))
                    or retained['membership'] != 'only-stop-helper'
                    or retained['descendantCgroups'] != 0
                    or stop['managerInvocation'] != row['managerInvocation']
                    or stop['receiptStartedNs'] != retained['startedMonotonicNs']
                    or stop['receiptObservedNs'] != retained['observedMonotonicNs']
                    or not context['campaignDeadlineNs'] <= retained['startedMonotonicNs']
                        <= retained['observedMonotonicNs']
                        <= context['terminalObservedNs']):
                return None
    except (AttributeError, KeyError, StopIteration, TypeError, ValueError):
        return None
    witness = {'caseId': 'deadline', 'triggerDigest': '',
        'trigger': {'kind': 'deadline', 'eventDigest': context['triggerEventDigest']},
        'triggerStartedNs': context['campaignDeadlineNs'],
        'terminalObservedNs': context['terminalObservedNs'],
        'roles': principals['roles'], 'populatedCgroups': [],
        'remainingDescendants': 0, 'retention': 'retained'}
    commitment = acceptance.payload_commitment('deadline', witness)
    witness['triggerDigest'] = commitment
    return witness, {'startedMonotonicNs': context['campaignDeadlineNs'],
                     'finishedMonotonicNs': context['terminalObservedNs']}, commitment


def _revocation_case(report, diagnostics, terminal, principals, source=None):
    """Validate the measured accepted-request revocation witness."""
    from pr315_revocation_evidence import case
    return case(sys.modules[__name__], report, diagnostics, terminal, principals,
                source or Path(__file__).resolve().parents[3])


def _setsid_case(report, diagnostics, terminal, principals, source):
    """Bind the detached actual role descendant to installed owner shutdown."""
    if (not isinstance(diagnostics, dict) or not isinstance(terminal, dict)
            or report.get('guestStopped') is not True
            or terminal.get('cleanupReportedByCaller') is not True):
        return None
    retained = diagnostics.get('setsidDoubleFork')
    try:
        if (not isinstance(retained, dict) or retained.get('status') != 'captured'
                or not isinstance(retained.get('record'), dict)):
            return None
        audit = retained['record']
        sender = next(row for row in principals['roles']
                      if row['role'] == 'candidate-sender')
        actor, actor_after = audit['actorBefore'], audit['actorAfter']
        child = audit['childEpoch']
        receipt = terminal['stopReceipts']['candidate-sender']['current']
        stable = ('hostPid', 'hostParentPid', 'startTicks', 'namespacePids',
                  'pidNamespace', 'networkNamespaceIdentity',
                  'mountNamespaceIdentity', 'userNamespaceIdentity',
                  'executableDigest', 'noNewPrivileges',
                  'effectiveCapabilities')
        source_digest = reference.sha256(source /
            'tools/release-certification/restricted/pr315_role_probe.py')
        if (audit['schemaVersion'] != 1
                or audit['kind'] != 'pr315-administrator-setsid-double-fork'
                or audit['caseId'] != 'setsid-double-fork'
                or audit['sourceDigest'] != source_digest
                or audit['actorUid'] != sender['uid']
                or any(actor[key] != actor_after[key] for key in stable)
                or actor['hostPid'] <= 1 or actor['startTicks'] <= 0
                or actor['noNewPrivileges'] is not True
                or actor['effectiveCapabilities'] != 0
                or audit['roleInvocation'] != sender['invocationId']
                or sender['cgroupDigest'] != fixtures.runtime.canonical_digest({
                    'role': 'candidate-sender',
                    'identity': audit['roleCgroupIdentity']})[7:]
                or child['hostPid'] <= 1 or child['startTicks'] < actor['startTicks']
                or child['hostParentPid'] == actor['hostPid']
                or child['noNewPrivileges'] is not True
                or child['effectiveCapabilities'] != 0
                or child['networkNamespaceIdentity'] != actor['networkNamespaceIdentity']
                or child['mountNamespaceIdentity'] != actor['mountNamespaceIdentity']
                or child['userNamespaceIdentity'] != actor['userNamespaceIdentity']
                or not isinstance(child['namespacePids'], list)
                or len(child['namespacePids']) < 2
                or audit['childSession'] <= 0 or audit['parentSession'] <= 0
                or audit['childSession'] == audit['parentSession']
                or receipt['status'] != 'captured'):
            return None
        stopped = receipt['record']
        if (stopped['managerInvocation'] != sender['invocationId']
                or stopped['cgroupIdentity'] != audit['roleCgroupIdentity']
                or stopped['membership'] != 'only-stop-helper'
                or stopped['descendantCgroups'] != 0
                or audit['stopReceiptObservedNs'] != stopped['observedMonotonicNs']
                or not audit['triggerMonotonicNs'] < audit['attackStartedNs']
                    < audit['attackFinishedNs'] < audit['stopStartedNs']
                    < stopped['startedMonotonicNs']
                    <= stopped['observedMonotonicNs'] <= audit['stopFinishedNs']
                    < audit['childAbsentObservedNs']
                    < diagnostics['cleanupFinishedNs']
                or set(audit['otherRolesBefore']) !=
                    set(acceptance.ROLES) - {'candidate-sender'}
                or set(audit['otherRolesAfter']) !=
                    set(acceptance.ROLES) - {'candidate-sender'}):
            return None
        for role, before in audit['otherRolesBefore'].items():
            after = audit['otherRolesAfter'][role]
            if (any(before[key] != after[key] for key in
                    ('InvocationID', 'ActiveState', 'SubState', 'MainPID'))
                    or before['ActiveState'] != 'active'
                    or before['SubState'] != 'running'
                    or not before['MainPID'].isdecimal()
                    or int(before['MainPID']) <= 0):
                return None
            other = terminal['stopReceipts'][role]['current']
            if (other['status'] != 'captured'
                    or other['record']['managerInvocation'] !=
                        next(row['invocationId'] for row in principals['roles']
                             if row['role'] == role)
                    or other['record']['startedMonotonicNs'] <=
                        audit['childAbsentObservedNs']
                    or other['record']['observedMonotonicNs'] >
                        diagnostics['cleanupFinishedNs']):
                return None
    except (AttributeError, KeyError, StopIteration, TypeError, ValueError):
        return None
    event = {'kind': 'setsid-double-fork',
             'roleInvocation': audit['roleInvocation'],
             'roleCgroupIdentity': audit['roleCgroupIdentity'],
             'childHostPid': child['hostPid'],
             'childStartTicks': child['startTicks'],
             'childSession': audit['childSession']}
    witness = {'caseId': 'setsid-double-fork', 'triggerDigest': '',
        'trigger': {'kind': 'setsid-double-fork',
                    'eventDigest': fixtures.runtime.canonical_digest(event)[7:]},
        'triggerStartedNs': audit['triggerMonotonicNs'],
        'terminalObservedNs': diagnostics['cleanupFinishedNs'],
        'roles': principals['roles'], 'populatedCgroups': [],
        'remainingDescendants': 0, 'retention': 'retained'}
    commitment = acceptance.payload_commitment('setsid-double-fork', witness)
    witness['triggerDigest'] = commitment
    return witness, {'startedMonotonicNs': audit['triggerMonotonicNs'],
                     'finishedMonotonicNs': diagnostics['cleanupFinishedNs']}, commitment


def _observer_death_case(report, diagnostics, terminal, principals):
    """Require the actual observer loss interval and owner-driven role termination."""
    if (not isinstance(diagnostics, dict) or not isinstance(terminal, dict)
            or report.get('guestStopped') is not True
            or terminal.get('cleanupReportedByCaller') is not True):
        return None
    context = diagnostics.get('observerDeath')
    try:
        fields = {'schemaVersion', 'kind', 'triggerStartedNs',
            'triggerEventDigest', 'campaignDeadlineNs', 'preRoles',
            'controllerBefore', 'controllerActiveAfterRequest', 'controllerAfter',
            'policySeconds', 'policyThresholdNs', 'stopObservations',
            'terminalObservedNs', 'populatedCgroups', 'remainingDescendants',
            'retention', 'actor', 'requestDigest', 'responseDigest',
            'requestStartedNs', 'responseObservedNs', 'killStartedNs',
            'killFinishedNs', 'pidfdUsed'}
        if (not isinstance(context, dict) or set(context) != fields
                or context['schemaVersion'] != 1
                or context['kind'] != 'pr315-administrator-observer-death'
                or context['policySeconds'] != 240
                or context['policyThresholdNs'] !=
                    context['responseObservedNs'] + 240 * 10**9
                or context['populatedCgroups'] != []
                or context['remainingDescendants'] != 0
                or context['retention'] != 'retained'
                or context['pidfdUsed'] is not True
                or context['triggerStartedNs'] != context['killStartedNs']
                or not context['requestStartedNs'] < context['responseObservedNs']
                    < context['killStartedNs'] < context['killFinishedNs']
                    < context['policyThresholdNs']
                    <= context['terminalObservedNs'] < context['campaignDeadlineNs']
                or re.fullmatch('[0-9a-f]{64}', context['requestDigest']) is None
                or re.fullmatch('[0-9a-f]{64}', context['responseDigest']) is None
                or len(context['preRoles']) != len(acceptance.ROLES)
                or len(context['stopObservations']) != len(acceptance.ROLES)):
            return None
        campaign = terminal['controllerRecords']['campaign']
        if (campaign['status'] != 'captured'
                or campaign['record']['state'] != 'terminalizing'
                or campaign['record']['deadlineMonotonicNs'] !=
                    context['campaignDeadlineNs']):
            return None
        actor = context['actor']
        before = context['controllerBefore']
        active = context['controllerActiveAfterRequest']
        after = context['controllerAfter']
        stable = ('invocationId', 'cgroupIdentity', 'bootId', 'mainPid',
                  'mainStartTicks')
        if (actor['uid'] != principals['observerUid']
                or type(actor['pid']) is not int or actor['pid'] <= 1
                or type(actor['startTicks']) is not int or actor['startTicks'] <= 0
                or any(before[key] != active[key] for key in stable)
                or after['activeState'] not in {'inactive', 'failed'}
                or after['subState'] not in {'dead', 'failed'}
                or after['mainPid'] != '0'
                or after['invocationId'] not in ('', before['invocationId'])
                or not before['observedMonotonicNs']
                    < context['requestStartedNs']
                    < context['responseObservedNs']
                    < context['killStartedNs'] < context['killFinishedNs']
                    < active['observedMonotonicNs']
                    < context['policyThresholdNs']
                    <= after['observedMonotonicNs']
                    <= context['terminalObservedNs']):
            return None
        rows, stops = context['preRoles'], context['stopObservations']
        if (not all(isinstance(row, dict) and set(row) == {
                'role', 'managerInvocation', 'bootId', 'cgroupIdentity', 'mainPid'}
                for row in rows)
                or {row['role'] for row in rows} != set(acceptance.ROLES)
                or not all(isinstance(row, dict) and set(row) == {
                    'role', 'managerInvocation', 'receiptStartedNs',
                    'receiptObservedNs'} for row in stops)
                or {row['role'] for row in stops} != set(acceptance.ROLES)):
            return None
        event = {'kind': 'observer-death', 'roles': rows,
                 'observerPid': actor['pid'],
                 'observerStartTicks': actor['startTicks'],
                 'campaignDeadlineNs': context['campaignDeadlineNs'],
                 'policySeconds': 240}
        if context['triggerEventDigest'] != fixtures.runtime.canonical_digest(event)[7:]:
            return None
        for row in rows:
            role = row['role']
            principal = next(item for item in principals['roles']
                             if item['role'] == role)
            stop = next(item for item in stops if item['role'] == role)
            receipt = terminal['stopReceipts'][role]['current']
            record = terminal['controllerRecords'][role]
            if (type(row['mainPid']) is not int or row['mainPid'] <= 0
                    or row['managerInvocation'] != principal['invocationId']
                    or row['bootId'].replace('-', '').lower() != principal['bootId']
                    or fixtures.runtime.canonical_digest({
                        'role': role, 'identity': row['cgroupIdentity']})[7:] !=
                        principal['cgroupDigest']
                    or receipt['status'] != 'captured'
                    or record['status'] != 'captured'
                    or record['record']['stopReason'] != 'controller-reconciliation'):
                return None
            retained = receipt['record']
            if (any(retained[key] != row[key] for key in
                    ('role', 'managerInvocation', 'bootId', 'cgroupIdentity'))
                    or retained['membership'] != 'only-stop-helper'
                    or retained['descendantCgroups'] != 0
                    or stop['managerInvocation'] != row['managerInvocation']
                    or stop['receiptStartedNs'] != retained['startedMonotonicNs']
                    or stop['receiptObservedNs'] != retained['observedMonotonicNs']
                    or not context['policyThresholdNs'] <=
                        retained['startedMonotonicNs']
                        <= retained['observedMonotonicNs']
                        <= context['terminalObservedNs']):
                return None
    except (AttributeError, KeyError, StopIteration, TypeError, ValueError):
        return None
    witness = {'caseId': 'observer-death', 'triggerDigest': '',
        'trigger': {'kind': 'observer-death',
                    'eventDigest': context['triggerEventDigest']},
        'triggerStartedNs': context['killStartedNs'],
        'terminalObservedNs': context['terminalObservedNs'],
        'roles': principals['roles'], 'populatedCgroups': [],
        'remainingDescendants': 0, 'retention': 'retained'}
    commitment = acceptance.payload_commitment('observer-death', witness)
    witness['triggerDigest'] = commitment
    return witness, {'startedMonotonicNs': context['killStartedNs'],
                     'finishedMonotonicNs': context['terminalObservedNs']}, commitment


def _controller_restart_kernel_valid(epoch, state, boot):
    """Validate the administrator's closed, independently sampled live unit epoch."""
    fields = {'kind', 'pid', 'uid', 'gid', 'startTicks', 'bootId', 'invocationId',
              'cgroupPath', 'cgroupIdentity', 'namespacePids', 'namespaces',
              'pidfdObserved', 'observedMonotonicNs'}
    return (isinstance(epoch, dict) and set(epoch) == fields
        and epoch['kind'] == 'fixed-controller-kernel-epoch-v1'
        and type(epoch['pid']) is int and epoch['pid'] > 1
        and epoch['pid'] == int(state['MainPID'])
        and type(epoch['uid']) is int and epoch['uid'] == 0
        and type(epoch['gid']) is int and epoch['gid'] == 0
        and type(epoch['startTicks']) is int and epoch['startTicks'] > 0
        and isinstance(epoch['bootId'], str)
        and epoch['bootId'].replace('-', '').lower() == boot
        and epoch['invocationId'] == state['InvocationID']
        and epoch['cgroupPath'] == '/system.slice/cryptad-workload-controller.service'
        and isinstance(epoch['cgroupIdentity'], list)
        and len(epoch['cgroupIdentity']) == 2
        and all(type(value) is int and value > 0 for value in epoch['cgroupIdentity'])
        and isinstance(epoch['namespacePids'], list)
        and 1 <= len(epoch['namespacePids']) <= 32
        and epoch['namespacePids'][0] == epoch['pid']
        and all(type(value) is int and value > 0 for value in epoch['namespacePids'])
        and isinstance(epoch['namespaces'], dict)
        and set(epoch['namespaces']) == {'pid', 'net', 'mnt', 'user'}
        and all(type(value) is int and value > 0 for value in epoch['namespaces'].values())
        and epoch['pidfdObserved'] is True
        and type(epoch['observedMonotonicNs']) is int and epoch['observedMonotonicNs'] > 0)


def _controller_restart_case(report, diagnostics, terminal, principals):
    """Bind actual controller invocation replacement to all four terminal role receipts."""
    if (not isinstance(diagnostics, dict) or not isinstance(terminal, dict)
            or report.get('guestStopped') is not True
            or terminal.get('cleanupReportedByCaller') is not True):
        return None
    context = diagnostics.get('controllerRestart')
    try:
        if (not isinstance(context, dict)
                or set(context) != {'schemaVersion', 'kind', 'triggerStartedNs',
                                    'triggerEventDigest', 'campaignDeadlineNs', 'preRoles',
                                    'beforeController', 'beforeControllerKernel',
                                    'killReturnCode', 'preStartBoundRoles',
                                    'newControllerStartRequestedNs', 'startReturnCode',
                                    'afterController', 'afterControllerKernel',
                                    'terminalObservedNs', 'populatedCgroups',
                                    'remainingDescendants', 'retention'}
                or context['schemaVersion'] != 1
                or context['kind'] != 'pr315-administrator-controller-restart'
                or context['populatedCgroups'] != [] or context['remainingDescendants'] != 0
                or context['retention'] != 'retained'
                or context['killReturnCode'] != 0 or context['startReturnCode'] != 0
                or type(context['newControllerStartRequestedNs']) is not int
                or not _bounded_window({'startedMonotonicNs': context['triggerStartedNs'],
                                        'finishedMonotonicNs': context['terminalObservedNs']})
                or not context['triggerStartedNs'] < context['newControllerStartRequestedNs']
                    < context['terminalObservedNs']
                or context['triggerStartedNs'] >= context['campaignDeadlineNs']
                or len(context['preRoles']) != len(acceptance.ROLES)):
            return None
        before, after = context['beforeController'], context['afterController']
        fields = {'InvocationID', 'ActiveState', 'SubState', 'MainPID', 'Result'}
        if (not isinstance(before, dict) or not isinstance(after, dict)
                or set(before) != fields or set(after) != fields
                or re.fullmatch('[0-9a-f]{32}', before['InvocationID']) is None
                or re.fullmatch('[0-9a-f]{32}', after['InvocationID']) is None
                or before['InvocationID'] == after['InvocationID']
                or before['ActiveState'] != 'active' or before['SubState'] != 'running'
                or not before['MainPID'].isdecimal() or int(before['MainPID']) <= 1
                or after['ActiveState'] != 'active' or after['SubState'] != 'running'
                or not after['MainPID'].isdecimal() or int(after['MainPID']) <= 1):
            return None
        before_kernel = context['beforeControllerKernel']
        after_kernel = context['afterControllerKernel']
        boot = principals['roles'][0]['bootId']
        if (not _controller_restart_kernel_valid(before_kernel, before, boot)
                or not _controller_restart_kernel_valid(after_kernel, after, boot)
                or (before_kernel['pid'], before_kernel['startTicks']) ==
                   (after_kernel['pid'], after_kernel['startTicks'])
                or not before_kernel['observedMonotonicNs'] < context['triggerStartedNs']
                or not context['newControllerStartRequestedNs'] <=
                       after_kernel['observedMonotonicNs'] < context['terminalObservedNs']):
            return None
        campaign = terminal['controllerRecords']['campaign']
        if (campaign['status'] != 'captured'
                or campaign['record']['state'] != 'terminalizing'
                or campaign['record']['deadlineMonotonicNs'] != context['campaignDeadlineNs']):
            return None
        rows = context['preRoles']
        bound = context['preStartBoundRoles']
        if (not all(isinstance(row, dict) and
                    set(row) == {'role', 'managerInvocation', 'bootId', 'cgroupIdentity', 'mainPid'}
                    for row in rows)
                or {row['role'] for row in rows} != set(acceptance.ROLES)
                or not isinstance(bound, list) or len(bound) != len(rows)
                or not all(isinstance(row, dict) and
                    set(row) == {'role', 'activeState', 'subState', 'mainPid',
                                 'receiptObservedMonotonicNs'} for row in bound)
                or {row['role'] for row in bound} != set(acceptance.ROLES)):
            return None
        expected_event = {'kind': 'controller-restart', 'roles': rows,
            'campaignDeadlineNs': context['campaignDeadlineNs'],
            'oldControllerInvocation': before['InvocationID']}
        if context['triggerEventDigest'] != fixtures.runtime.canonical_digest(expected_event)[7:]:
            return None
        for row in rows:
            role = row['role']
            principal = next(item for item in principals['roles'] if item['role'] == role)
            receipt = terminal['stopReceipts'][role]['current']
            role_record = terminal['controllerRecords'][role]
            bound_role = next(item for item in bound if item['role'] == role)
            if (type(row['mainPid']) is not int or row['mainPid'] <= 0
                    or row['managerInvocation'] != principal['invocationId']
                    or row['bootId'].replace('-', '').lower() != principal['bootId']
                    or fixtures.runtime.canonical_digest({
                        'role': role, 'identity': row['cgroupIdentity']})[7:] != principal['cgroupDigest']
                    or receipt['status'] != 'captured' or role_record['status'] != 'captured'
                    or role_record['record']['stopReason'] != 'controller-reconciliation'
                    or bound_role['activeState'] not in {'inactive', 'failed'}
                    or bound_role['subState'] not in {'dead', 'failed'}
                    or bound_role['mainPid'] != 0):
                return None
            stopped = receipt['record']
            if (any(stopped[key] != row[key] for key in
                    ('role', 'managerInvocation', 'bootId', 'cgroupIdentity'))
                    or stopped['membership'] != 'only-stop-helper'
                    or stopped['descendantCgroups'] != 0
                    or not context['triggerStartedNs'] < stopped['startedMonotonicNs']
                        <= stopped['observedMonotonicNs']
                        == bound_role['receiptObservedMonotonicNs']
                        <= context['newControllerStartRequestedNs']):
                return None
    except (AttributeError, KeyError, StopIteration, TypeError, ValueError):
        return None
    witness = {'caseId': 'controller-restart', 'triggerDigest': '',
        'trigger': {'kind': 'controller-restart', 'eventDigest': context['triggerEventDigest']},
        'triggerStartedNs': context['triggerStartedNs'],
        'terminalObservedNs': context['terminalObservedNs'],
        'roles': principals['roles'], 'populatedCgroups': [],
        'remainingDescendants': 0, 'retention': 'retained'}
    commitment = acceptance.payload_commitment('controller-restart', witness)
    witness['triggerDigest'] = commitment
    return witness, {'startedMonotonicNs': context['triggerStartedNs'],
                     'finishedMonotonicNs': context['terminalObservedNs']}, commitment


def positive_case_attempt(report, result, fixture, host_started_ns, host_finished_ns,
                          diagnostics=None, terminal=None):
    """Build only cases backed by actual host, app and kernel observations."""
    host = report['hostVerifiedIdentity']
    window = result['roleKernelRosterWindow']
    if (type(host_started_ns) is not int or type(host_finished_ns) is not int
            or not 0 < host_started_ns < host_finished_ns
            or not _bounded_window(window)
            or not isinstance(fixture['mailDigest'], str)
            or re.fullmatch('sha256:[0-9a-f]{64}', fixture['mailDigest']) is None):
        raise ValueError('workload-positive-case-window-invalid')
    identity = {key: host[key] for key in ('helperSourceCommit', 'helperSourceTree',
        'bundleIdentity', 'testKitDigest', 'profileDigest', 'bootClosureDigest',
        'preparedImageDigest', 'fixtureManifestDigest')}
    identity['productSelectionDigest'] = host['productDigest']
    identity['admittedAppDigest'] = fixture['mailDigest'][7:]
    principals = result['roleKernelRoster']
    cases = ['installed-ready', 'four-role-start']
    commitments = {}
    observations = []
    for case_id, started, finished, witness in (
            ('installed-ready', host_started_ns, host_finished_ns,
             {'profile': acceptance.PROFILE, 'bundleIdentity': identity['bundleIdentity'],
              'testKitDigest': identity['testKitDigest']}),
            ('four-role-start', window['startedMonotonicNs'], window['finishedMonotonicNs'],
             {'observerUid': principals['observerUid'], 'roles': principals['roles']})):
        case = acceptance.CASES[case_id]
        observations.append({'caseId': case_id, 'status': 'passed', 'actor': case.actor,
            'target': case.target, 'outcome': case.outcome,
            'startedMonotonicNs': started, 'finishedMonotonicNs': finished,
            'witness': witness})
    app_process = None
    app = _app_case(result, identity, principals)
    if app is not None:
        app_process, app_window = app
        case = acceptance.CASES['signed-apphost-child']
        cases.append('signed-apphost-child')
        observations.append({'caseId': 'signed-apphost-child', 'status': 'passed',
            'actor': case.actor, 'target': case.target, 'outcome': case.outcome,
            **app_window, 'witness': app_process})
    for case_id in ('own-management', 'dynamic-app-bootstrap'):
        exchange = _exchange_case(case_id, result, terminal, principals)
        if exchange is None:
            continue
        witness, exchange_window, commitments[case_id] = exchange
        case = acceptance.CASES[case_id]
        cases.append(case_id)
        observations.append({'caseId': case_id, 'status': 'passed',
            'actor': case.actor, 'target': case.target, 'outcome': case.outcome,
            **exchange_window, 'witness': witness})
    fnp = _fnp_case(result, terminal, identity, principals)
    if fnp is not None:
        witness, fnp_window, commitments['fnp-content-retrieval'] = fnp
        case = acceptance.CASES['fnp-content-retrieval']
        cases.append('fnp-content-retrieval')
        observations.append({'caseId': 'fnp-content-retrieval', 'status': 'passed',
            'actor': case.actor, 'target': case.target, 'outcome': case.outcome,
            **fnp_window, 'witness': witness})
    resources = _resource_case(diagnostics, principals)
    if resources is not None:
        resource_witness, resource_window = resources
        case = acceptance.CASES['kernel-resource-scope']
        cases.append('kernel-resource-scope')
        observations.append({'caseId': 'kernel-resource-scope', 'status': 'passed',
            'actor': case.actor, 'target': case.target, 'outcome': case.outcome,
            **resource_window, 'witness': resource_witness})
    restart_context = None
    restart = _restart_case(result, terminal, principals)
    if restart is not None:
        restart_witness, restart_window, restart_context = restart
        case = acceptance.CASES['restart-durable-state']
        cases.append('restart-durable-state')
        observations.append({'caseId': 'restart-durable-state', 'status': 'passed',
            'actor': case.actor, 'target': case.target, 'outcome': case.outcome,
            **restart_window, 'witness': restart_witness})
    cancellation = _cancellation_case(report, result, diagnostics, terminal, principals)
    if cancellation is not None:
        witness, cancellation_window, commitments['cancellation'] = cancellation
        case = acceptance.CASES['cancellation']
        cases.append('cancellation')
        observations.append({'caseId': 'cancellation', 'status': 'passed',
            'actor': case.actor, 'target': case.target, 'outcome': case.outcome,
            **cancellation_window, 'witness': witness})
    controller_restart = _controller_restart_case(report, diagnostics, terminal, principals)
    if controller_restart is not None:
        witness, restart_window, commitments['controller-restart'] = controller_restart
        case = acceptance.CASES['controller-restart']
        cases.append('controller-restart')
        observations.append({'caseId': 'controller-restart', 'status': 'passed',
            'actor': case.actor, 'target': case.target, 'outcome': case.outcome,
            **restart_window, 'witness': witness})
    attempt = {'contract': acceptance.CONTRACT, 'identity': identity,
        'declaredCases': cases, 'observations': observations,
        'guestStopped': report['guestStopped'], 'attemptCompleted': True,
        'principals': principals, 'targets': {}, 'caseCommitments': commitments,
        'appProcess': app_process, 'restartContext': restart_context}
    return identity, attempt


def _lifecycle_group_attempt(group, report, result, fixture, diagnostics,
                             terminal, source):
    """Bind one real controller transition to its root test-kit process epoch."""
    if group not in ('lost-start-response', 'cancellation', 'controller-restart', 'deadline',
                     'revocation-running', 'setsid-double-fork',
                     'observer-death'):
        return None
    try:
        if (not group_prepared(report, result, terminal, group)
                or fixture.get('schemaVersion') != 4
                or not isinstance(diagnostics, dict)):
            return None
        host = report['hostVerifiedIdentity']
        principals = result['roleKernelRoster']
        context = diagnostics[{'lost-start-response': 'lostStartResponse',
                               'cancellation': 'cancellation',
                               'controller-restart': 'controllerRestart',
                               'deadline': 'deadline',
                               'revocation-running': 'revocationRunning',
                               'setsid-double-fork': 'setsidDoubleFork',
                               'observer-death': 'observerDeath'}[group]]
        if group == 'setsid-double-fork':
            if context.get('status') != 'captured':
                return None
            context = context['record']
        case = (_lost_start_case(report, result, diagnostics, terminal, principals)
                if group == 'lost-start-response' else
                _cancellation_case(report, result, diagnostics, terminal, principals)
                if group == 'cancellation' else
                _controller_restart_case(report, diagnostics, terminal, principals)
                if group == 'controller-restart' else
                _deadline_case(report, diagnostics, terminal, principals)
                if group == 'deadline' else
                _revocation_case(report, diagnostics, terminal, principals, source)
                if group == 'revocation-running' else
                _setsid_case(report, diagnostics, terminal, principals, source)
                if group == 'setsid-double-fork' else
                _observer_death_case(report, diagnostics, terminal, principals))
        if case is None:
            return None
        import pr315_case_v10 as current_case
        daemon_epochs = current_case.role_daemon_bindings(
            principals['roles'], result.get('roleDaemonEpochs'))
        witness, window, commitment = case
        if any(epoch['observedMonotonicNs'] >= window['finishedMonotonicNs']
               or (group != 'lost-start-response' and
                   epoch['observedMonotonicNs'] >= window['startedMonotonicNs'])
               for epoch in daemon_epochs.values()):
            return None
        before, after = (diagnostics['lifecycleActorBefore'],
                         diagnostics['lifecycleActorAfter'])
        stable = ('pid', 'uid', 'gid', 'startTicks', 'bootId', 'cgroupIdentity',
                  'namespaces', 'namespacePids',
                  'cgroupDigest', 'invocationId', 'sourceDigest')
        source_digest = reference.sha256(source /
            'tools/release-certification/restricted/pr314_workload_driver.py')
        cgroup_digest = fixtures.runtime.canonical_digest({
            'role': 'lifecycle-administrator',
            'identity': before['cgroupIdentity']})[7:]
        invocation = hashlib.sha256(json.dumps({
            'bootId': before['bootId'], 'pid': before['pid'],
            'startTicks': before['startTicks'],
            'cgroupIdentity': before['cgroupIdentity'],
            'sourceDigest': source_digest}, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()[:32]
        if (any(before[key] != after[key] for key in stable)
                or before['pid'] <= 1 or before['uid'] != 0
                or before['startTicks'] <= 0 or before['gid'] != 0
                or not isinstance(before['namespaces'], dict)
                or set(before['namespaces']) != {'pid', 'net', 'mnt', 'user'}
                or any(type(value) is not int or value <= 0
                       for value in before['namespaces'].values())
                or not isinstance(before['namespacePids'], list)
                or not before['namespacePids'] or before['namespacePids'][0] != before['pid']
                or before['sourceDigest'] != source_digest
                or before['cgroupDigest'] != cgroup_digest
                or before['invocationId'] != invocation
                or not isinstance(before['cgroupIdentity'], list)
                or len(before['cgroupIdentity']) != 2
                or any(type(part) is not int or part <= 0
                       for part in before['cgroupIdentity'])
                or any(row['bootId'] != before['bootId'].replace('-', '').lower()
                       for row in principals['roles'])
                or not before['observedMonotonicNs'] < window['startedMonotonicNs']
                    < window['finishedMonotonicNs'] < after['observedMonotonicNs']):
            return None
        identity = {key: host[key] for key in ('helperSourceCommit',
            'helperSourceTree', 'bundleIdentity', 'testKitDigest',
            'profileDigest', 'bootClosureDigest', 'preparedImageDigest',
            'fixtureManifestDigest')}
        identity['productSelectionDigest'] = host['productDigest']
        identity['admittedAppDigest'] = fixture['mailDigest'][7:]
        spec = acceptance.CASES[group]
        observation = {'caseId': group, 'status': 'passed', 'actor': spec.actor,
                       'target': spec.target, 'outcome': spec.outcome,
                       **window, 'witness': witness}
        attempt = {'contract': acceptance.CONTRACT, 'identity': identity,
                   'declaredCases': [group], 'observations': [observation],
                   'guestStopped': True, 'attemptCompleted': True,
                   'principals': principals, 'targets': {},
                   'caseCommitments': {group: commitment},
                   'appProcess': None, 'restartContext': None}
        receipts = [terminal['stopReceipts'][role]['current']['record']
                    for role in acceptance.ROLES]
        sidecar = {'contract': campaign.CONTRACT, 'caseId': group,
                   'status': 'passed',
                   'actorEpoch': {'kind': 'administrator-test-kit',
                                  'pid': before['pid'], 'uid': before['uid'], 'gid': before['gid'],
                                  'startTicks': before['startTicks'],
                                  'bootId': before['bootId'],
                                  'namespaces': before['namespaces'],
                                  'namespacePids': before['namespacePids'],
                                  'cgroupDigest': cgroup_digest,
                                  'systemdInvocation': None,
                                  'testKitInvocation': invocation,
                                  'sourceDigest': source_digest},
                   'targetEpoch': {'roles': principals['roles'],
                                   'daemonEpochs': daemon_epochs,
                                   'controllerBefore': context.get('beforeController', context.get('controllerBefore')),
                                   'controllerAfter': context.get('afterController', context.get('controllerAfter')),
                                   'controllerKernelBefore': context.get('beforeControllerKernel'),
                                   'controllerKernelAfter': context.get('afterControllerKernel'),
                                   'roleStops': context.get('roleStops'),
                                   'revocationMarkerDigest': context.get('markerDigest'),
                                   'revocationActor': context.get('actor'),
                                   'revocationRequestDigest': context.get('requestDigest'),
                                   'revocationSynchronization': context.get('controllerSynchronization'),
                                   'detachedChildEpoch': context.get('childEpoch'),
                                   'detachedChildSession': context.get('childSession'),
                                   'originalParentSession': context.get('parentSession'),
                                   'observerEpoch': context.get('actor')
                                       if group == 'observer-death' else None,
                                   'observerPolicyThresholdNs': context.get(
                                       'policyThresholdNs'),
                                   'deadlineHeartbeat': _deadline_heartbeat_proof(context,
                                       diagnostics, principals) if group == 'deadline' else None,
                                   'lostStartBefore': context.get('before'),
                                   'lostStartFirst': context.get('first'),
                                   'lostStartRetry': context.get('retry'),
                                   'lostStartDroppedRequest': context.get('droppedRequest')},
                   'operationWindow': window,
                   'triggerDigest': commitment,
                   'stopReceiptObservedNs': max(row['observedMonotonicNs']
                                                for row in receipts),
                   'hostVerifiedIdentity': host, 'guestStopped': True}
        return identity, attempt, sidecar
    except (AttributeError, KeyError, TypeError, ValueError, IndexError, StopIteration,
            OSError):
        return None


def probe_denial_attempt(report, fixture, terminal):
    """Admit one installed app-origin denial from three independently retained records."""
    if (report.get('guestStopped') is not True or not isinstance(terminal, dict)
            or terminal.get('cleanupReportedByCaller') is not True
            or fixture.get('schemaVersion') != 4):
        return None
    try:
        selected = [terminal[key] for key in ('probeKernelCheckpoint',
                    'probeAdministratorRecord', 'probeAppFirstResult')]
        if any(row['status'] != 'captured' for row in selected):
            return None
        checkpoint, admin, result = (row['record'] for row in selected)
        if (checkpoint['bundleDigest'] != fixture['probeDigest']
                or admin['bundleDigest'] != fixture['probeDigest']
                or checkpoint['administratorRecordDigest'] != hashlib.sha256(json.dumps(
                    admin, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                or admin['firstResultDigest'] != hashlib.sha256(json.dumps(
                    result, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                or not acceptance._principals(checkpoint['roleKernelRoster'])
                or not _bounded_window(checkpoint['roleKernelRosterWindow'])):
            return None
        principals = checkpoint['roleKernelRoster']
        sender = next(row for row in principals['roles'] if row['role'] == 'candidate-sender')
        worker, measured = checkpoint['probeWorker'], admin['worker']
        outer, leader = admin['outer'], admin['sandboxLeader']
        observer_leader = worker['sandboxLeader']
        namespace = result['namespaceInodes']
        attack = result['mountEscape']
        if (admin['role'] != 'candidate-sender' or admin['senderUid'] != sender['uid']
                or result['uid'] != sender['uid'] or result['gid'] != sender['gid']
                or admin['managerInvocation'] != sender['invocationId']
                or admin['bootId'].replace('-', '').lower() != sender['bootId']
                or sender['cgroupDigest'] != fixtures.runtime.canonical_digest({
                    'role': 'candidate-sender', 'identity': admin['cgroupIdentity']})[7:]
                or not isinstance(admin['verifiedTree'], dict)
                or set(admin['verifiedTree']) != {'digest', 'fileCount', 'sizeBytes'}
                or not re.fullmatch('sha256:[0-9a-f]{64}', str(admin['verifiedTree']['digest']))
                or any(type(admin['verifiedTree'][key]) is not int
                       or admin['verifiedTree'][key] < 1 for key in ('fileCount', 'sizeBytes'))
                or admin['stateBefore'] != checkpoint['senderStateBefore']
                or admin['stateAfter'] != admin['stateBefore']
                or terminal['sentinel']['status'] != 'matched'
                or terminal['sentinel']['observedDigest'] != 'sha256:' + admin['stateAfter']
                or worker['hostPid'] != measured['hostPid']
                or worker['startTicks'] != measured['startTicks']
                or worker['namespacePids'] != measured['namespacePids']
                or worker['mountNamespaceIdentity'] != measured['mountNamespaceIdentity']
                or worker['userNamespaceIdentity'] != measured['userNamespaceIdentity']
                or worker['networkNamespaceIdentity'] != measured['networkNamespaceIdentity']
                or worker['executableDigest'] != measured['executableDigest']
                or measured['hostParentPid'] != leader['hostPid']
                or observer_leader['hostPid'] != leader['hostPid']
                or observer_leader['startTicks'] != leader['startTicks']
                or observer_leader['namespacePids'] != leader['namespacePids']
                or observer_leader['executableDigest'] != leader['executableDigest']
                or observer_leader['mountNamespaceIdentity'] != leader['mountNamespaceIdentity']
                or observer_leader['userNamespaceIdentity'] != leader['userNamespaceIdentity']
                or observer_leader['networkNamespaceIdentity'] != leader['networkNamespaceIdentity']
                or observer_leader['pidNamespaceIdentity'] != namespace['pid']
                or leader['namespacePids'][-1] != 1
                or measured['namespacePids'][-1] != 2
                or leader['namespacePids'][1] != worker['namespacePid']
                or leader['pidNamespace'] != measured['pidNamespace']
                or leader['mountNamespaceIdentity'] != measured['mountNamespaceIdentity']
                or worker['managerInvocation'] != sender['invocationId']
                or worker['cgroupIdentity'] != admin['cgroupIdentity']
                or measured['noNewPrivileges'] is not True
                or measured['effectiveCapabilities'] != 0
                or measured['namespacePids'][-1] != result['pid']
                or measured['mountNamespaceIdentity'][-1] != namespace['mnt']
                or measured['userNamespaceIdentity'][-1] != namespace['user']
                or measured['networkNamespaceIdentity'][-1] != namespace['net']
                or measured['pidNamespace'] != 'pid:[' + str(namespace['pid']) + ']'
                or outer['mountNamespaceIdentity'] != worker['outerMountNamespaceIdentity']
                or outer['mountNamespaceIdentity'] == measured['mountNamespaceIdentity']
                or attack['operation'] != 'unshare-mount' or attack['returnCode'] != -1
                or attack['errno'] != 'EPERM'
                or not checkpoint['roleKernelRosterWindow']['finishedMonotonicNs']
                    < result['startedMonotonicNs'] <= attack['startedMonotonicNs']
                    < attack['finishedMonotonicNs'] < worker['observedMonotonicNs']
                    <= admin['activeBeforeNs'] < admin['activeAfterNs']):
            return None
        receipts = terminal['stopReceipts']['candidate-sender']
        matching = [entry['record'] for entry in receipts.values()
                    if isinstance(entry, dict) and entry.get('status') == 'captured'
                    and isinstance(entry.get('record'), dict)
                    and entry['record'].get('managerInvocation') == sender['invocationId']]
        if (len(matching) != 1
                or matching[0]['bootId'].replace('-', '').lower() != sender['bootId']
                or matching[0]['cgroupIdentity'] != admin['cgroupIdentity']
                or matching[0]['membership'] != 'only-stop-helper'
                or matching[0]['descendantCgroups'] != 0
                or admin['activeAfterNs'] >= matching[0]['startedMonotonicNs']):
            return None
        host = report['hostVerifiedIdentity']
        identity = {key: host[key] for key in ('helperSourceCommit', 'helperSourceTree',
            'bundleIdentity', 'testKitDigest', 'profileDigest', 'bootClosureDigest',
            'preparedImageDigest', 'fixtureManifestDigest')}
        identity['productSelectionDigest'] = host['productDigest']
        identity['admittedAppDigest'] = fixture['mailDigest'][7:]
        case_id = 'namespace-mount-escape'
        control_digest = hashlib.sha256(json.dumps(admin, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        target = {'caseId': case_id, 'target': 'outer-role', 'role': 'candidate-sender',
                  'invocationId': sender['invocationId'], 'cgroupDigest': sender['cgroupDigest'],
                  'bootId': sender['bootId'], 'controlResponseDigest': control_digest,
                  'probeDigest': ''}
        witness = {'actorUid': sender['uid'], 'attackDigest': admin['firstResultDigest'],
                   'attackStartedNs': attack['startedMonotonicNs'],
                   'targetActiveBeforeNs': checkpoint['roleKernelRosterWindow']['finishedMonotonicNs'],
                   'targetActiveAfterNs': admin['activeAfterNs'],
                   'controlResponseDigest': control_digest, 'denialSource': 'kernel',
                   'denialCode': 'EPERM', 'unrelatedStateBefore': admin['stateBefore'],
                   'unrelatedStateAfter': admin['stateAfter'], 'targetIdentity': target}
        target['probeDigest'] = acceptance.payload_commitment(case_id, witness)
        case = acceptance.CASES[case_id]
        observation = {'caseId': case_id, 'status': 'passed', 'actor': case.actor,
                       'target': case.target, 'outcome': case.outcome,
                       'startedMonotonicNs': checkpoint['roleKernelRosterWindow']['startedMonotonicNs'],
                       'finishedMonotonicNs': admin['activeAfterNs'], 'witness': witness}
        attempt = {'contract': acceptance.CONTRACT, 'identity': identity,
                   'declaredCases': [case_id], 'observations': [observation],
                   'guestStopped': True, 'attemptCompleted': True, 'principals': principals,
                   'targets': {case_id: target}, 'caseCommitments': {},
                   'appProcess': None, 'restartContext': None}
        return identity, attempt
    except (AttributeError, KeyError, TypeError, ValueError, IndexError, StopIteration):
        return None


def _v10_legacy_sidecar(case_id, report, fixture, terminal, diagnostics,
                        identity, attempt):
    """Carry four previously v8-only root proofs into the prospective v10 record."""
    if case_id not in ('namespace-mount-escape', 'runner-control',
                       'observer-control', 'arbitrary-endpoint'):
        return None
    try:
        if (report.get('guestStopped') is not True
                or attempt['declaredCases'] != [case_id]
                or attempt['identity'] != identity
                or not isinstance(diagnostics, dict)):
            return None
        sender = next(row for row in attempt['principals']['roles']
                      if row['role'] == 'candidate-sender')
        stop = terminal['stopReceipts']['candidate-sender']['current']
        if (stop['status'] != 'captured'
                or stop['record']['managerInvocation'] != sender['invocationId']
                or stop['record']['membership'] != 'only-stop-helper'
                or stop['record']['descendantCgroups'] != 0):
            return None
        if case_id == 'namespace-mount-escape':
            admin = terminal['probeAdministratorRecord']['record']
            first = terminal['probeAppFirstResult']['record']
            checkpoint = terminal['probeKernelCheckpoint']['record']
            worker = admin['worker']
            actor = {'kind': 'normally-signed-apphost-child',
                'uid': sender['uid'], 'hostPid': worker['hostPid'],
                'startTicks': worker['startTicks'],
                'namespacePids': worker['namespacePids'],
                'sandboxLeader': checkpoint['probeWorker']['sandboxLeader'],
                'bundleDigest': fixture['probeDigest'],
                'systemdInvocation': sender['invocationId'],
                'cgroupDigest': sender['cgroupDigest']}
            target = {'kind': 'installed-outer-role-mount-boundary',
                'role': 'candidate-sender', 'bootId': sender['bootId'],
                'systemdInvocation': sender['invocationId'],
                'cgroupDigest': sender['cgroupDigest'],
                'outerMountNamespaceIdentity': checkpoint['probeWorker'][
                    'outerMountNamespaceIdentity'],
                'sandboxLeader': actor['sandboxLeader']}
            window = {'startedMonotonicNs': first['mountEscape']['startedMonotonicNs'],
                'finishedMonotonicNs': first['mountEscape']['finishedMonotonicNs']}
        else:
            field = {'runner-control': 'runnerControlAudit',
                     'observer-control': 'observerControlAudit',
                     'arbitrary-endpoint': 'arbitraryEndpointAudit'}[case_id]
            audit = terminal[field]['record']
            observed = audit['actor']
            actor = (diagnostics['runnerControl']['actorEpoch']
                     if case_id == 'runner-control' else
                     diagnostics['authorityObserverEpoch'])
            if (actor['pid'] != observed['pid']
                    or actor['uid'] != observed['uid']
                    or actor['startTicks'] != observed['startTicks']):
                return None
            target = {'kind': 'active-installed-controller',
                'before': audit['targetBefore'],
                'after': audit['targetAfter']}
            if case_id == 'arbitrary-endpoint':
                target['recipientBefore'] = audit['recipientBefore']
                target['recipientAfter'] = audit['recipientAfter']
                target['endpointSelection'] = audit['endpointSelection']
            window = ({'startedMonotonicNs': audit['requestStartedNs'],
                       'finishedMonotonicNs': audit['responseObservedNs']}
                      if case_id == 'runner-control' else
                      {'startedMonotonicNs': audit['requestObservedNs'],
                       'finishedMonotonicNs': audit['responseSentNs']}
                      if case_id == 'observer-control' else
                      {'startedMonotonicNs': audit['attackStartedNs'],
                       'finishedMonotonicNs': audit['attackFinishedNs']})
        if not _bounded_window(window) or window['finishedMonotonicNs'] >= stop['record']['observedMonotonicNs']:
            return None
        return {'contract': campaign.CONTRACT, 'caseId': case_id,
            'status': 'passed', 'actorEpoch': actor, 'targetEpoch': target,
            'operationWindow': window,
            'attackDigest': attempt['observations'][0]['witness']['attackDigest'],
            'hostVerifiedIdentity': report['hostVerifiedIdentity'],
            'guestStopped': True,
            'stopReceiptObservedNs': stop['record']['observedMonotonicNs']}
    except (AttributeError, KeyError, TypeError, ValueError, IndexError, StopIteration):
        return None


def observer_control_denial_attempt(report, fixture, terminal):
    """Bind a real forbidden observer request to its root serving process and role epoch."""
    if (report.get('guestStopped') is not True or not isinstance(terminal, dict)
            or terminal.get('cleanupReportedByCaller') is not True
            or fixture.get('schemaVersion') != 4):
        return None
    try:
        retained = terminal['observerControlCheckpoint']
        audited = terminal['observerControlAudit']
        if retained['status'] != 'captured' or audited['status'] != 'captured':
            return None
        observer, root = retained['record'], audited['record']
        principals = observer['roleKernelRoster']
        window = observer['roleKernelRosterWindow']
        if not acceptance._principals(principals) or not _bounded_window(window):
            return None
        sender = next(row for row in principals['roles'] if row['role'] == 'candidate-sender')
        actor = root['actor']
        before, after = root['targetBefore'], root['targetAfter']
        fixed_response = b'{"error":"restricted-workload-request-failed"}\n'
        if (root['caseId'] != 'observer-control' or observer['caseId'] != 'observer-control'
                or actor != {'pid': observer['actorPid'],
                             'uid': principals['observerUid'],
                             'startTicks': observer['actorStartTicks']}
                or root['requestDigest'] != observer['requestDigest']
                or root['responseDigest'] != observer['responseDigest']
                or root['responseDigest'] != hashlib.sha256(fixed_response).hexdigest()
                or root['senderManagerInvocation'] != sender['invocationId']
                or sender['cgroupDigest'] != fixtures.runtime.canonical_digest({
                    'role': 'candidate-sender', 'identity': root['senderCgroupIdentity']})[7:]
                or root['senderStateBefore'] != observer['senderStateBefore']
                or root['senderStateBefore'] != root['senderStateAfter']
                or terminal['sentinel']['status'] != 'matched'
                or terminal['sentinel']['observedDigest'] != 'sha256:' + root['senderStateAfter']
                or before['invocationId'] != after['invocationId']
                or before['cgroupIdentity'] != after['cgroupIdentity']
                or before['bootId'] != after['bootId']
                or before['bootId'].replace('-', '').lower() != sender['bootId']
                or re.fullmatch('[0-9a-f]{32}', str(before['invocationId'])) is None
                or not isinstance(before['cgroupIdentity'], list)
                or len(before['cgroupIdentity']) != 2
                or any(type(part) is not int or part <= 0
                       for part in before['cgroupIdentity'])
                or not window['finishedMonotonicNs']
                    < before['observedMonotonicNs'] < root['requestObservedNs']
                    < root['responseSentNs'] < after['observedMonotonicNs']):
            return None
        receipt = terminal['stopReceipts']['candidate-sender']
        matching = [entry['record'] for entry in receipt.values()
                    if isinstance(entry, dict) and entry.get('status') == 'captured'
                    and isinstance(entry.get('record'), dict)
                    and entry['record'].get('managerInvocation') == sender['invocationId']]
        if (len(matching) != 1 or matching[0]['bootId'].replace('-', '').lower() != sender['bootId']
                or matching[0]['cgroupIdentity'] != root['senderCgroupIdentity']
                or matching[0]['membership'] != 'only-stop-helper'
                or matching[0]['descendantCgroups'] != 0
                or after['observedMonotonicNs'] >= matching[0]['startedMonotonicNs']):
            return None
        host = report['hostVerifiedIdentity']
        identity = {key: host[key] for key in ('helperSourceCommit', 'helperSourceTree',
            'bundleIdentity', 'testKitDigest', 'profileDigest', 'bootClosureDigest',
            'preparedImageDigest', 'fixtureManifestDigest')}
        identity['productSelectionDigest'] = host['productDigest']
        identity['admittedAppDigest'] = fixture['mailDigest'][7:]
        case_id = 'observer-control'
        target = {'caseId': case_id, 'target': 'manager', 'role': None,
                  'invocationId': before['invocationId'],
                  'cgroupDigest': fixtures.runtime.canonical_digest({
                      'role': 'controller', 'identity': before['cgroupIdentity']})[7:],
                  'bootId': sender['bootId'], 'probeDigest': '',
                  'controlResponseDigest': root['responseDigest']}
        witness = {'actorUid': principals['observerUid'], 'attackDigest': root['requestDigest'],
                   'attackStartedNs': root['requestObservedNs'],
                   'targetActiveBeforeNs': before['observedMonotonicNs'],
                   'targetActiveAfterNs': after['observedMonotonicNs'],
                   'controlResponseDigest': root['responseDigest'],
                   'denialSource': 'controller', 'denialCode': 'policy-rejected',
                   'unrelatedStateBefore': root['senderStateBefore'],
                   'unrelatedStateAfter': root['senderStateAfter'], 'targetIdentity': target}
        target['probeDigest'] = acceptance.payload_commitment(case_id, witness)
        case = acceptance.CASES[case_id]
        observation = {'caseId': case_id, 'status': 'passed', 'actor': case.actor,
                       'target': case.target, 'outcome': case.outcome,
                       'startedMonotonicNs': window['startedMonotonicNs'],
                       'finishedMonotonicNs': after['observedMonotonicNs'], 'witness': witness}
        return identity, {'contract': acceptance.CONTRACT, 'identity': identity,
            'declaredCases': [case_id], 'observations': [observation],
            'guestStopped': True, 'attemptCompleted': True, 'principals': principals,
            'targets': {case_id: target}, 'caseCommitments': {},
            'appProcess': None, 'restartContext': None}
    except (AttributeError, KeyError, TypeError, ValueError, IndexError, StopIteration):
        return None


def arbitrary_endpoint_denial_attempt(report, result, fixture, terminal):
    """Bind an observer's rejected selector to a live sibling FCP control."""
    if (report.get('guestStopped') is not True or not isinstance(terminal, dict)
            or terminal.get('cleanupReportedByCaller') is not True
            or fixture.get('schemaVersion') != 4
            or not (positive_executed(report, result, terminal)
                    or group_prepared(report, result, terminal, 'authority'))):
        return None
    try:
        checkpoint = terminal['arbitraryEndpointCheckpoint']
        audit = terminal['arbitraryEndpointAudit']
        if checkpoint['status'] != 'captured' or audit['status'] != 'captured':
            return None
        observer, root = checkpoint['record'], audit['record']
        principals = observer['roleKernelRoster']
        window = observer['roleKernelRosterWindow']
        if not acceptance._principals(principals) or not _bounded_window(window):
            return None
        sender = next(row for row in principals['roles'] if row['role'] == 'candidate-sender')
        recipient = next(row for row in principals['roles'] if row['role'] == 'candidate-recipient')
        controller_before, controller_after = root['targetBefore'], root['targetAfter']
        fixed_response = b'{"error":"restricted-workload-request-failed"}\n'
        if (root['caseId'] != 'arbitrary-endpoint'
                or observer['caseId'] != 'arbitrary-endpoint'
                or root['actor'] != {'pid': observer['actorPid'],
                                     'uid': principals['observerUid'],
                                     'startTicks': observer['actorStartTicks']}
                or root['requestDigest'] != observer['requestDigest']
                or root['responseDigest'] != observer['responseDigest']
                or root['responseDigest'] != hashlib.sha256(fixed_response).hexdigest()
                or root['endpointSelection'] != 'sibling-fcp'
                or root['denial'] != 'restricted-workload-network-rejected'
                or any(re.fullmatch('[0-9a-f]{64}', root[key]) is None for key in
                       ('requestDigest', 'recipientControlBeforeDigest',
                        'recipientControlAfterDigest'))
                or any(controller_before[key] != controller_after[key] for key in
                       ('invocationId', 'cgroupIdentity', 'bootId'))
                or re.fullmatch('[0-9a-f]{32}', controller_before['invocationId']) is None
                or controller_before['bootId'].replace('-', '').lower() != sender['bootId']
                or terminal['sentinel']['status'] != 'matched'
                or terminal['sentinel']['observedDigest'] !=
                    'sha256:' + root['senderAfter']['stateDigest']):
            return None
        for role, principal in (('sender', sender), ('recipient', recipient)):
            before, after = root[role + 'Before'], root[role + 'After']
            if (any(before[key] != after[key] for key in
                    ('managerInvocation', 'cgroupIdentity', 'bootId'))
                    or before['stateDigest'] != after['stateDigest']
                    or before['managerInvocation'] != principal['invocationId']
                    or before['bootId'].replace('-', '').lower() != principal['bootId']
                    or fixtures.runtime.canonical_digest({
                        'role': principal['role'],
                        'identity': before['cgroupIdentity']})[7:] != principal['cgroupDigest']):
                return None
            if (role == 'sender' and re.fullmatch('[0-9a-f]{64}',
                    before['stateDigest']) is None):
                return None
            if role == 'recipient' and before['stateDigest'] is not None:
                return None
            receipt = terminal['stopReceipts'][principal['role']]
            matching = [entry['record'] for entry in receipt.values()
                        if isinstance(entry, dict) and entry.get('status') == 'captured'
                        and isinstance(entry.get('record'), dict)
                        and entry['record'].get('managerInvocation') == principal['invocationId']]
            if (len(matching) != 1
                    or matching[0]['bootId'].replace('-', '').lower() != principal['bootId']
                    or matching[0]['cgroupIdentity'] != before['cgroupIdentity']
                    or matching[0]['membership'] != 'only-stop-helper'
                    or matching[0]['descendantCgroups'] != 0
                    or after['observedMonotonicNs'] >= matching[0]['startedMonotonicNs']):
                return None
        if (not window['finishedMonotonicNs']
                    < controller_before['observedMonotonicNs']
                    < root['requestObservedNs']
                    < root['recipientBefore']['observedMonotonicNs']
                    < root['recipientControlBeforeNs']
                    < root['attackStartedNs'] < root['attackFinishedNs']
                    < root['responseSentNs']
                    < root['recipientAfter']['observedMonotonicNs']
                    < root['recipientControlAfterNs']
                    < controller_after['observedMonotonicNs']):
            return None
        host = report['hostVerifiedIdentity']
        if host['helperSourceCommit'] != result['identity']['sourceCommit']:
            return None
        identity = {key: host[key] for key in ('helperSourceCommit', 'helperSourceTree',
            'bundleIdentity', 'testKitDigest', 'profileDigest', 'bootClosureDigest',
            'preparedImageDigest', 'fixtureManifestDigest')}
        identity['productSelectionDigest'] = host['productDigest']
        identity['admittedAppDigest'] = fixture['mailDigest'][7:]
        case_id = 'arbitrary-endpoint'
        target = {'caseId': case_id, 'target': 'connector', 'role': None,
                  'invocationId': controller_before['invocationId'],
                  'cgroupDigest': fixtures.runtime.canonical_digest({
                      'role': 'controller',
                      'identity': controller_before['cgroupIdentity']})[7:],
                  'bootId': sender['bootId'], 'probeDigest': '',
                  'controlResponseDigest': root['responseDigest']}
        attack_digest = hashlib.sha256(json.dumps(root, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        witness = {'actorUid': principals['observerUid'], 'attackDigest': attack_digest,
                   'attackStartedNs': root['attackStartedNs'],
                   'targetActiveBeforeNs': controller_before['observedMonotonicNs'],
                   'targetActiveAfterNs': controller_after['observedMonotonicNs'],
                   'controlResponseDigest': root['responseDigest'],
                   'denialSource': 'controller', 'denialCode': 'policy-rejected',
                   'unrelatedStateBefore': root['senderBefore']['stateDigest'],
                   'unrelatedStateAfter': root['senderAfter']['stateDigest'],
                   'targetIdentity': target}
        target['probeDigest'] = acceptance.payload_commitment(case_id, witness)
        case = acceptance.CASES[case_id]
        observation = {'caseId': case_id, 'status': 'passed', 'actor': case.actor,
                       'target': case.target, 'outcome': case.outcome,
                       'startedMonotonicNs': window['startedMonotonicNs'],
                       'finishedMonotonicNs': controller_after['observedMonotonicNs'],
                       'witness': witness}
        attempt = {'contract': acceptance.CONTRACT, 'identity': identity,
                   'declaredCases': [case_id], 'observations': [observation],
                   'guestStopped': True, 'attemptCompleted': True,
                   'principals': principals, 'targets': {case_id: target},
                   'caseCommitments': {}, 'appProcess': None, 'restartContext': None}
        sidecar = {'contract': campaign.CONTRACT, 'caseId': case_id,
                   'status': 'passed', 'hostVerifiedIdentity': host,
                   'actorPid': root['actor']['pid'],
                   'actorUid': root['actor']['uid'],
                   'actorStartTicks': root['actor']['startTicks'],
                   'controllerBefore': controller_before,
                   'controllerAfter': controller_after,
                   'recipientBefore': root['recipientBefore'],
                   'recipientAfter': root['recipientAfter'],
                   'recipientControlBeforeDigest': root['recipientControlBeforeDigest'],
                   'recipientControlAfterDigest': root['recipientControlAfterDigest'],
                   'operationWindow': {'startedMonotonicNs': root['attackStartedNs'],
                                       'finishedMonotonicNs': root['attackFinishedNs']},
                   'attackDigest': attack_digest, 'guestStopped': True}
        return identity, attempt, sidecar
    except (AttributeError, KeyError, TypeError, ValueError, IndexError, StopIteration):
        return None


def runner_control_denial_attempt(report, result, fixture, terminal):
    """Bind a real vmadmin systemd refusal to a live controller and sender epoch."""
    if (report.get('guestStopped') is not True or not isinstance(result, dict)
            or not isinstance(terminal, dict)
            or terminal.get('cleanupReportedByCaller') is not True
            or fixture.get('schemaVersion') != 4):
        return None
    try:
        retained = terminal['runnerControlAudit']
        if retained['status'] != 'captured':
            return None
        root = retained['record']
        principals, window = root['roleKernelRoster'], root['roleKernelRosterWindow']
        before, after = root['targetBefore'], root['targetAfter']
        sender = next(row for row in principals['roles'] if row['role'] == 'candidate-sender')
        actor = root['actor']
        request = ['/usr/bin/systemctl', '--no-ask-password', 'stop',
                   'cryptad-workload-controller.service']
        request_digest = hashlib.sha256(json.dumps(request, separators=(',', ':')).encode()).hexdigest()
        response = base64.b64decode(root['responseBase64'], validate=True)
        if (not acceptance._principals(principals) or not _bounded_window(window)
                or result['roleKernelRoster'] != principals
                or result['roleKernelRosterWindow'] != window
                or actor['uid'] != principals['runnerUid']
                or any(type(actor[key]) is not int or actor[key] <= 1
                       for key in ('pid', 'startTicks'))
                or root['requestDigest'] != request_digest
                or root['responseDigest'] != hashlib.sha256(response).hexdigest()
                or not any(marker in response for marker in
                           (b'Interactive authentication required', b'Access denied'))
                or root['exitCode'] == 0 or root['stdoutBytes'] != 0
                or any(before[key] != after[key] for key in
                       ('invocationId', 'cgroupIdentity', 'bootId', 'mainPid', 'mainStartTicks'))
                or before['bootId'].replace('-', '').lower() != sender['bootId']
                or root['senderManagerInvocation'] != sender['invocationId']
                or sender['cgroupDigest'] != fixtures.runtime.canonical_digest({
                    'role': 'candidate-sender', 'identity': root['senderCgroupIdentity']})[7:]
                or root['senderStateBefore'] != root['senderStateAfter']
                or terminal['sentinel']['status'] != 'matched'
                or terminal['sentinel']['observedDigest'] != 'sha256:' + root['senderStateAfter']
                or not window['finishedMonotonicNs'] < before['observedMonotonicNs']
                    < root['requestStartedNs'] < root['responseObservedNs']
                    < after['observedMonotonicNs']):
            return None
        receipt = terminal['stopReceipts']['candidate-sender']
        matching = [entry['record'] for entry in receipt.values()
                    if isinstance(entry, dict) and entry.get('status') == 'captured'
                    and isinstance(entry.get('record'), dict)
                    and entry['record'].get('managerInvocation') == sender['invocationId']]
        if (len(matching) != 1 or matching[0]['cgroupIdentity'] != root['senderCgroupIdentity']
                or matching[0]['bootId'].replace('-', '').lower() != sender['bootId']
                or matching[0]['membership'] != 'only-stop-helper'
                or matching[0]['descendantCgroups'] != 0
                or after['observedMonotonicNs'] >= matching[0]['startedMonotonicNs']):
            return None
        host = report['hostVerifiedIdentity']
        identity = {key: host[key] for key in ('helperSourceCommit', 'helperSourceTree',
            'bundleIdentity', 'testKitDigest', 'profileDigest', 'bootClosureDigest',
            'preparedImageDigest', 'fixtureManifestDigest')}
        identity['productSelectionDigest'] = host['productDigest']
        identity['admittedAppDigest'] = fixture['mailDigest'][7:]
        case_id = 'runner-control'
        target = {'caseId': case_id, 'target': 'manager', 'role': None,
                  'invocationId': before['invocationId'],
                  'cgroupDigest': fixtures.runtime.canonical_digest({
                      'role': 'controller', 'identity': before['cgroupIdentity']})[7:],
                  'bootId': sender['bootId'], 'probeDigest': '',
                  'controlResponseDigest': root['responseDigest']}
        witness = {'actorUid': principals['runnerUid'], 'attackDigest': root['requestDigest'],
                   'attackStartedNs': root['requestStartedNs'],
                   'targetActiveBeforeNs': before['observedMonotonicNs'],
                   'targetActiveAfterNs': after['observedMonotonicNs'],
                   'controlResponseDigest': root['responseDigest'],
                   'denialSource': 'server', 'denialCode': 'policy-rejected',
                   'unrelatedStateBefore': root['senderStateBefore'],
                   'unrelatedStateAfter': root['senderStateAfter'], 'targetIdentity': target}
        target['probeDigest'] = acceptance.payload_commitment(case_id, witness)
        case = acceptance.CASES[case_id]
        observation = {'caseId': case_id, 'status': 'passed', 'actor': case.actor,
                       'target': case.target, 'outcome': case.outcome,
                       'startedMonotonicNs': window['startedMonotonicNs'],
                       'finishedMonotonicNs': after['observedMonotonicNs'], 'witness': witness}
        return identity, {'contract': acceptance.CONTRACT, 'identity': identity,
            'declaredCases': [case_id], 'observations': [observation],
            'guestStopped': True, 'attemptCompleted': True, 'principals': principals,
            'targets': {case_id: target}, 'caseCommitments': {},
            'appProcess': None, 'restartContext': None}
    except (AttributeError, KeyError, TypeError, ValueError, IndexError, StopIteration,
            binascii.Error):
        return None


def public_result(status, positive=False, reasons=(), statuses=None):
    return {'schemaVersion': 1, 'kind': 'pr315-workload-suite', 'contract': acceptance.CONTRACT,
            'profile': acceptance.PROFILE, 'status': status, 'reasons': list(reasons),
            'runtimePolicy': fixtures.preparation.launcher_policy()['revision'],
            'implementationCoverage': 'incomplete', 'installedPositiveExecuted': positive,
            'installedWorkloadAcceptanceSatisfied': False, 'finiteNativeAcceptance': False,
            'protectedExecutionEnabled': False, 'phaseComplete': False,
            # Aggregate success is not sufficient for any individual v8 assertion.
            'cases': acceptance.inventory(statuses)}


def selected_public_result(group, status, positive=False, reasons=(), statuses=None):
    """Project a development run onto only its exclusive declared group."""
    cases = selected_cases(group)
    if cases is None:
        return public_result(status, positive, reasons, statuses)
    owned = {case: value for case, value in (statuses or {}).items() if case in cases}
    return public_result('partial-execution' if status == 'implementation-incomplete' else status,
                         positive and group == 'positive', reasons, owned)


def prospective_campaign_result(result, frozen_campaign):
    """Version a partial public result without granting campaign acceptance."""
    if frozen_campaign is None:
        return result
    if (result.get('schemaVersion') != 1
            or result.get('installedWorkloadAcceptanceSatisfied') is not False
            or frozen_campaign.get('kind') != campaign_seal.CAMPAIGN):
        raise ValueError('workload-campaign-public-result-invalid')
    return {**result, 'schemaVersion': 2,
            'contract': campaign_seal.CONTRACT,
            'campaignPlanDigest': frozen_campaign['planDigest'],
            'campaignNonce': frozen_campaign['campaignNonce'],
            'hostKeyFingerprint': frozen_campaign['hostKeyFingerprint']}


def _host_runner_epoch():
    """Sample this still-running CT102 verifier, including its own boot domain."""
    pid = os.getpid()
    fields = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
    if (pid <= 1 or len(fields) <= 19 or not fields[19].isdecimal()
            or os.geteuid() <= 0):
        raise ValueError('workload-host-runner-epoch-invalid')
    return {'kind': 'host-runner-process', 'pid': pid, 'uid': os.geteuid(),
        'startTicks': int(fields[19]),
        'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'sourceDigest': reference.sha256(__file__),
        'observedMonotonicNs': time.monotonic_ns()}


def selected_terminal_status(group, report, positive):
    """Keep a failed guest operation distinct from partial case execution."""
    if group is None or positive:
        return 'implementation-incomplete'
    return ('guest-operation-failed' if report.get('status') == 'guest-operation-failed'
            else 'verification-inconclusive')


def selected_probe_started(group, diagnostics):
    """Classify a selected probe from the fixed administrator's private start marker."""
    if not isinstance(diagnostics, dict):
        return False
    marker = diagnostics.get('probeStart')
    return (isinstance(marker, dict) and set(marker) == {
        'schemaVersion', 'kind', 'caseId', 'startedMonotonicNs'}
        and marker['schemaVersion'] == 1
        and marker['kind'] == 'pr315-workload-probe-start'
        and marker['caseId'] == group
        and type(marker['startedMonotonicNs']) is int
        and marker['startedMonotonicNs'] > 0)


def _v9_actor_epoch(observed, role):
    """Carry the administrator's actual child and role epoch into each private case."""
    return {'hostPid': observed['hostPid'], 'hostParentPid': observed['hostParentPid'],
            'namespacePids': observed['namespacePids'], 'uid': role['uid'],
            'gid': role['gid'], 'startTicks': observed['startTicks'],
            'bootId': role['bootId'], 'systemdInvocation': role['invocationId'],
            'cgroupDigest': role['cgroupDigest'],
            'pidNamespace': observed['pidNamespace'],
            'networkNamespaceIdentity': observed['networkNamespaceIdentity'],
            'mountNamespaceIdentity': observed['mountNamespaceIdentity'],
            'userNamespaceIdentity': observed['userNamespaceIdentity'],
            'executableDigest': observed['executableDigest'],
            'noNewPrivileges': observed['noNewPrivileges'],
            'effectiveCapabilities': observed['effectiveCapabilities']}


def _observer_private_attempt(case_id, report, result, fixture, terminal, source):
    """Bind one fixed role file operation and active canary to host transport."""
    try:
        audit_field = {'observer-private-read': 'observerPrivateReadAudit',
                       'observer-private-write': 'observerPrivateWriteAudit'}[case_id]
        host = report['hostVerifiedIdentity']
        roster = result['roleKernelRoster']
        sender = next(row for row in roster['roles'] if row['role'] == 'candidate-sender')
        root = terminal[audit_field]['record']
        receipt = terminal['stopReceipts']['candidate-sender']['current']['record']
        before, after = root['actorBefore'], root['actorAfter']
        stable = ('hostPid', 'hostParentPid', 'startTicks', 'namespacePids', 'pidNamespace',
                  'networkNamespaceIdentity', 'mountNamespaceIdentity',
                  'userNamespaceIdentity', 'executableDigest', 'noNewPrivileges',
                  'effectiveCapabilities')
        source_digest = reference.sha256(source / 'tools/release-certification/restricted/pr315_role_probe.py')
        if (not (positive_executed(report, result, terminal)
                 or group_prepared(report, result, terminal, 'role-boundary'))
                or fixture.get('schemaVersion') != 4 or 'probeDigest' not in fixture
                or terminal[audit_field]['status'] != 'captured'
                or root['schemaVersion'] != 1
                or root['kind'] != 'pr315-administrator-' + case_id
                or root['caseId'] != case_id
                or root['sourceDigest'] != source_digest
                or root['actorUid'] != sender['uid']
                or any(before[key] != after[key] for key in stable)
                or before['hostPid'] <= 1 or before['startTicks'] <= 0
                or len(before['namespacePids']) < 2
                or before['networkNamespaceIdentity'][1] != sender['networkNamespace']
                or before['noNewPrivileges'] is not True
                or before['effectiveCapabilities'] != 0
                or root['roleInvocationBefore'] != sender['invocationId']
                or root['roleInvocationAfter'] != sender['invocationId']
                or root['targetDigestBefore'] != root['targetDigestAfter']
                or re.fullmatch('[0-9a-f]{64}', root['targetDigestBefore']) is None
                or root['kernelOpenResult'] != {'opened': False, 'errno': 'ENOENT'}
                or (group_prepared(report, result, terminal, 'role-boundary')
                    and result['roleKernelRosterWindow']['finishedMonotonicNs'] >=
                    root['controllerObservedBeforeNs'])
                or not root['controllerObservedBeforeNs'] < root['triggerMonotonicNs']
                    < root['attackStartedNs'] < root['attackFinishedNs']
                    < root['controllerObservedAfterNs'] < receipt['startedMonotonicNs']
                or receipt['managerInvocation'] != sender['invocationId']
                or receipt['membership'] != 'only-stop-helper'
                or receipt['descendantCgroups'] != 0
                or host['helperSourceCommit'] != result['identity']['sourceCommit']):
            return None
        return {'contract': campaign.CONTRACT, 'caseId': case_id,
                'status': 'passed', 'actorUid': sender['uid'],
                'actorHostPid': before['hostPid'], 'actorStartTicks': before['startTicks'],
                'roleInvocation': sender['invocationId'],
                'actorEpoch': _v9_actor_epoch(before, sender),
                'operationWindow': {'startedMonotonicNs': root['attackStartedNs'],
                                    'finishedMonotonicNs': root['attackFinishedNs']},
                'targetEpoch': {'kind': 'observer-private-canary',
                                'controlDigest': root['targetDigestBefore'],
                                'controllerObservedBeforeNs': root['controllerObservedBeforeNs'],
                                'controllerObservedAfterNs': root['controllerObservedAfterNs']},
                'targetControlDigest': root['targetDigestBefore'],
                'attackDigest': hashlib.sha256(json.dumps(root, sort_keys=True,
                    separators=(',', ':')).encode()).hexdigest(),
                'hostVerifiedIdentity': host, 'guestStopped': True,
                'stopReceiptObservedNs': receipt['observedMonotonicNs']}
    except (AttributeError, KeyError, TypeError, ValueError, StopIteration, OSError):
        return None


def observer_private_read_attempt(report, result, fixture, terminal, source):
    return _observer_private_attempt('observer-private-read', report, result, fixture, terminal, source)


def observer_private_write_attempt(report, result, fixture, terminal, source):
    return _observer_private_attempt('observer-private-write', report, result, fixture, terminal, source)


def _fixed_claim_attempt(case_id, report, result, fixture, terminal, source):
    """Bind one false candidate claim to current kernel observer measurements."""
    try:
        field = {'forged-runtime-identity': 'forgedRuntimeIdentityAudit',
                 'forged-counters': 'forgedCountersAudit'}[case_id]
        host = report['hostVerifiedIdentity']
        roster = result['roleKernelRoster']
        sender = next(row for row in roster['roles'] if row['role'] == 'candidate-sender')
        audit = terminal[field]['record']
        receipt = terminal['stopReceipts']['candidate-sender']['current']['record']
        before, after = audit['actorBefore'], audit['actorAfter']
        stable = ('hostPid', 'hostParentPid', 'startTicks', 'namespacePids', 'pidNamespace',
                  'networkNamespaceIdentity', 'mountNamespaceIdentity',
                  'userNamespaceIdentity', 'executableDigest', 'noNewPrivileges',
                  'effectiveCapabilities')
        source_digest = reference.sha256(source /
            'tools/release-certification/restricted/pr315_role_probe.py')
        cgroup_digest = fixtures.runtime.canonical_digest({'role': 'candidate-sender',
            'identity': audit['cgroupIdentityBefore']})[7:]
        if (not (positive_executed(report, result, terminal)
                 or group_prepared(report, result, terminal, 'authority'))
                or fixture.get('schemaVersion') != 4 or 'probeDigest' not in fixture
                or terminal[field]['status'] != 'captured'
                or audit['schemaVersion'] != 1
                or audit['kind'] != 'pr315-administrator-' + case_id
                or audit['caseId'] != case_id
                or audit['sourceDigest'] != source_digest
                or audit['denial'] != 'kernel-mismatch-observed'
                or audit['actorUid'] != sender['uid']
                or any(before[key] != after[key] for key in stable)
                or before['hostPid'] <= 1 or before['startTicks'] <= 0
                or len(before['namespacePids']) < 2
                or before['networkNamespaceIdentity'][1] != sender['networkNamespace']
                or before['noNewPrivileges'] is not True
                or before['effectiveCapabilities'] != 0
                or audit['roleInvocationBefore'] != sender['invocationId']
                or audit['roleInvocationAfter'] != sender['invocationId']
                or audit['cgroupIdentityBefore'] != audit['cgroupIdentityAfter']
                or cgroup_digest != sender['cgroupDigest']
                or not audit['targetActiveBeforeNs'] < audit['attackStartedNs']
                    < audit['attackFinishedNs'] < audit['targetActiveAfterNs']
                    < receipt['startedMonotonicNs']
                or receipt['managerInvocation'] != sender['invocationId']
                or receipt['membership'] != 'only-stop-helper'
                or receipt['descendantCgroups'] != 0
                or host['helperSourceCommit'] != result['identity']['sourceCommit']):
            return None
        if case_id == 'forged-runtime-identity':
            if (type(audit['claimedHostPid']) is not int or audit['claimedHostPid'] != 1
                    or type(audit['claimedHostUid']) is not int or audit['claimedHostUid'] != 0
                    or audit['actualHostPid'] != before['hostPid']
                    or audit['actualHostUid'] != sender['uid']):
                return None
        elif (type(audit['claimedMemoryCurrentBytes']) is not int
                or audit['claimedMemoryCurrentBytes'] != 0
                or type(audit['claimedTasksCurrent']) is not int
                or audit['claimedTasksCurrent'] != 0
                or any(type(audit[key]) is not int or audit[key] <= 0 for key in
                       ('actualMemoryBefore', 'actualTasksBefore',
                        'actualMemoryAfter', 'actualTasksAfter'))):
            return None
        target_digest = hashlib.sha256(json.dumps({key: audit[key] for key in audit
            if key.startswith('actual') or key.startswith('cgroupIdentity')},
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        return {'contract': campaign.CONTRACT, 'caseId': case_id, 'status': 'passed',
                'actorUid': sender['uid'], 'actorHostPid': before['hostPid'],
                'actorStartTicks': before['startTicks'],
                'roleInvocation': sender['invocationId'],
                'actorEpoch': _v9_actor_epoch(before, sender),
                'operationWindow': {'startedMonotonicNs': audit['attackStartedNs'],
                                    'finishedMonotonicNs': audit['attackFinishedNs']},
                'targetEpoch': {'kind': 'administrator-kernel-observation',
                                'bootId': sender['bootId'],
                                'systemdInvocation': sender['invocationId'],
                                'cgroupDigest': sender['cgroupDigest'],
                                'activeBeforeNs': audit['targetActiveBeforeNs'],
                                'activeAfterNs': audit['targetActiveAfterNs']},
                'targetControlDigest': target_digest,
                'attackDigest': hashlib.sha256(json.dumps(audit, sort_keys=True,
                    separators=(',', ':')).encode()).hexdigest(),
                'hostVerifiedIdentity': host, 'guestStopped': True,
                'stopReceiptObservedNs': receipt['observedMonotonicNs']}
    except (AttributeError, KeyError, TypeError, ValueError, StopIteration, OSError):
        return None


def _fixed_role_access_attempt(case_id, report, result, fixture, terminal, source):
    """Bind a fixed candidate syscall to an independently active installed target."""
    cases = {'sibling-data': ('siblingDataAudit', 'candidate-recipient'),
             'package-expectation': ('packageExpectationAudit', 'candidate-sender'),
             'cgroup-migration': ('cgroupMigrationAudit', 'candidate-recipient')}
    try:
        field, target_role = cases[case_id]
        host = report['hostVerifiedIdentity']
        roster = result['roleKernelRoster']['roles']
        sender = next(row for row in roster if row['role'] == 'candidate-sender')
        target = next(row for row in roster if row['role'] == target_role)
        audit = terminal[field]['record']
        before, after = audit['actorBefore'], audit['actorAfter']
        first, last = audit['targetBefore'], audit['targetAfter']
        sender_receipt = terminal['stopReceipts']['candidate-sender']['current']['record']
        target_receipt = terminal['stopReceipts'][target_role]['current']['record']
        stable = ('hostPid', 'hostParentPid', 'startTicks', 'namespacePids', 'pidNamespace',
                  'networkNamespaceIdentity', 'mountNamespaceIdentity',
                  'userNamespaceIdentity', 'executableDigest', 'noNewPrivileges',
                  'effectiveCapabilities')
        source_digest = reference.sha256(source /
            'tools/release-certification/restricted/pr315_role_probe.py')
        actor_cgroup_digest = fixtures.runtime.canonical_digest({
            'role': 'candidate-sender', 'identity': audit['actorCgroupBefore']})[7:]
        target_cgroup_digest = fixtures.runtime.canonical_digest({
            'role': target_role, 'identity': first['cgroupIdentity']})[7:]
        if (not (positive_executed(report, result, terminal)
                 or group_prepared(report, result, terminal, 'role-boundary'))
                or fixture.get('schemaVersion') != 4 or 'probeDigest' not in fixture
                or terminal[field]['status'] != 'captured'
                or audit['schemaVersion'] != 1
                or audit['kind'] != 'pr315-administrator-fixed-role-access-denial'
                or audit['caseId'] != case_id
                or audit['sourceDigest'] != source_digest
                or audit['actorUid'] != sender['uid']
                or any(before[key] != after[key] for key in stable)
                or before['hostPid'] <= 1 or before['startTicks'] <= 0
                or len(before['namespacePids']) < 2
                or before['networkNamespaceIdentity'][1] != sender['networkNamespace']
                or before['noNewPrivileges'] is not True
                or before['effectiveCapabilities'] != 0
                or audit['actorInvocationBefore'] != sender['invocationId']
                or audit['actorInvocationAfter'] != sender['invocationId']
                or audit['actorCgroupBefore'] != audit['actorCgroupAfter']
                or actor_cgroup_digest != sender['cgroupDigest']
                or first['role'] != target_role or last['role'] != target_role
                or first['managerInvocation'] != target['invocationId']
                or last['managerInvocation'] != target['invocationId']
                or first['cgroupIdentity'] != last['cgroupIdentity']
                or target_cgroup_digest != target['cgroupDigest']
                or first['controlDigest'] != last['controlDigest']
                or (group_prepared(report, result, terminal, 'role-boundary')
                    and result['roleKernelRosterWindow']['finishedMonotonicNs'] >=
                    first['observedMonotonicNs'])
                or audit['writtenBytes'] != 0
                or not first['observedMonotonicNs'] < audit['attackStartedNs']
                    < audit['attackFinishedNs'] < last['observedMonotonicNs']
                    < target_receipt['startedMonotonicNs']
                or sender_receipt['managerInvocation'] != sender['invocationId']
                or target_receipt['managerInvocation'] != target['invocationId']
                or any(receipt['membership'] != 'only-stop-helper'
                       or receipt['descendantCgroups'] != 0
                       for receipt in (sender_receipt, target_receipt))
                or host['helperSourceCommit'] != result['identity']['sourceCommit']):
            return None
        if case_id == 'package-expectation':
            outcome = audit['kernelOpenResult']
            if (not isinstance(outcome, dict) or set(outcome) != {'opened', 'errno'}
                    or outcome['opened'] is not False
                    or outcome['errno'] not in ('EACCES', 'EPERM', 'EROFS')
                    or first['controlDigest'] != fixture['products']['candidate'][
                        'daemonDigest'].removeprefix('sha256:')):
                return None
        elif audit['kernelOpenResult'] != {'opened': False, 'errno': 'ENOENT'}:
            return None
        if case_id == 'cgroup-migration':
            control = hashlib.sha256(json.dumps({'role': target_role,
                'managerInvocation': first['managerInvocation'],
                'cgroupIdentity': first['cgroupIdentity']},
                sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            if first['controlDigest'] != control:
                return None
        return {'contract': campaign.CONTRACT, 'caseId': case_id, 'status': 'passed',
                'actorUid': sender['uid'], 'actorHostPid': before['hostPid'],
                'actorStartTicks': before['startTicks'],
                'roleInvocation': sender['invocationId'],
                'actorEpoch': _v9_actor_epoch(before, sender),
                'operationWindow': {'startedMonotonicNs': audit['attackStartedNs'],
                                    'finishedMonotonicNs': audit['attackFinishedNs']},
                'targetEpoch': {'kind': 'installed-role-or-package',
                                'role': target_role, 'uid': target['uid'],
                                'bootId': target['bootId'],
                                'systemdInvocation': target['invocationId'],
                                'cgroupDigest': target['cgroupDigest'],
                                'controlDigest': first['controlDigest'],
                                'activeBeforeNs': first['observedMonotonicNs'],
                                'activeAfterNs': last['observedMonotonicNs']},
                'targetInvocation': target['invocationId'],
                'targetControlDigest': first['controlDigest'],
                'attackDigest': hashlib.sha256(json.dumps(audit, sort_keys=True,
                    separators=(',', ':')).encode()).hexdigest(),
                'hostVerifiedIdentity': host, 'guestStopped': True,
                'stopReceiptObservedNs': target_receipt['observedMonotonicNs']}
    except (AttributeError, KeyError, TypeError, ValueError, StopIteration, OSError):
        return None


def _resolver_authority_attempt(report, result, fixture, terminal, source):
    """Bind a real role syscall to the active installed resolver's root canary."""
    case_id = 'resolver-authority'
    try:
        if (not (positive_executed(report, result, terminal)
                 or group_prepared(report, result, terminal, 'authority'))
                or fixture.get('schemaVersion') != 4
                or terminal['resolverAuthorityAudit']['status'] != 'captured'):
            return None
        audit = terminal['resolverAuthorityAudit']['record']
        sender = next(row for row in result['roleKernelRoster']['roles']
                      if row['role'] == 'candidate-sender')
        first, last = audit['targetBefore'], audit['targetAfter']
        before, after = audit['actorBefore'], audit['actorAfter']
        receipt = terminal['stopReceipts']['candidate-sender']['current']['record']
        host = report['hostVerifiedIdentity']
        stable_actor = ('hostPid', 'hostParentPid', 'startTicks', 'namespacePids',
                        'pidNamespace', 'networkNamespaceIdentity',
                        'mountNamespaceIdentity', 'userNamespaceIdentity',
                        'executableDigest', 'noNewPrivileges',
                        'effectiveCapabilities')
        target_stable = ('role', 'managerInvocation', 'bootId', 'cgroupIdentity',
                         'mainPid', 'mainStartTicks', 'canaryIdentity',
                         'controlDigest')
        actor_group = fixtures.runtime.canonical_digest({
            'role': 'candidate-sender', 'identity': audit['actorCgroupBefore']})[7:]
        target_group = fixtures.runtime.canonical_digest({
            'role': 'resolver', 'identity': first['cgroupIdentity']})[7:]
        if (audit['schemaVersion'] != 1
                or audit['kind'] != 'pr315-administrator-resolver-authority-denial'
                or audit['caseId'] != case_id
                or audit['sourceDigest'] != reference.sha256(source /
                    'tools/release-certification/restricted/pr315_role_probe.py')
                or audit['actorUid'] != sender['uid']
                or any(before[key] != after[key] for key in stable_actor)
                or before['hostPid'] <= 1 or before['startTicks'] <= 0
                or len(before['namespacePids']) < 2
                or before['networkNamespaceIdentity'][1] != sender['networkNamespace']
                or before['noNewPrivileges'] is not True
                or before['effectiveCapabilities'] != 0
                or audit['actorInvocationBefore'] != sender['invocationId']
                or audit['actorInvocationAfter'] != sender['invocationId']
                or audit['actorCgroupBefore'] != audit['actorCgroupAfter']
                or actor_group != sender['cgroupDigest']
                or audit['actorStateBefore'] != audit['actorStateAfter']
                or terminal['sentinel']['status'] != 'matched'
                or terminal['sentinel']['observedDigest'] !=
                    'sha256:' + audit['actorStateBefore']
                or any(first[key] != last[key] for key in target_stable)
                or first['role'] is not None
                or first['bootId'].replace('-', '').lower() != sender['bootId']
                or first['managerInvocation'] in {row['invocationId']
                    for row in result['roleKernelRoster']['roles']}
                or target_group in {row['cgroupDigest']
                    for row in result['roleKernelRoster']['roles']}
                or first['mainPid'] <= 1 or first['mainStartTicks'] <= 0
                or re.fullmatch('[0-9a-f]{64}', first['controlDigest']) is None
                or audit['targetPathDigest'] != hashlib.sha256(
                    b'/var/lib/cryptad-restricted/resolver/pr315-workload-canary').hexdigest()
                or audit['kernelOpenResult'] not in (
                    {'opened': False, 'errno': 'ENOENT'},
                    {'opened': False, 'errno': 'EACCES'},
                    {'opened': False, 'errno': 'EPERM'})
                or not first['observedMonotonicNs'] < audit['attackStartedNs']
                    < audit['attackFinishedNs'] < last['observedMonotonicNs']
                    < receipt['startedMonotonicNs']
                or receipt['managerInvocation'] != sender['invocationId']
                or receipt['membership'] != 'only-stop-helper'
                or receipt['descendantCgroups'] != 0
                or host['helperSourceCommit'] != result['identity']['sourceCommit']):
            return None
        identity = {key: host[key] for key in ('helperSourceCommit', 'helperSourceTree',
            'bundleIdentity', 'testKitDigest', 'profileDigest', 'bootClosureDigest',
            'preparedImageDigest', 'fixtureManifestDigest')}
        identity['productSelectionDigest'] = host['productDigest']
        identity['admittedAppDigest'] = fixture['mailDigest'][7:]
        attack_digest = hashlib.sha256(json.dumps(audit, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        target = {'caseId': case_id, 'target': acceptance.CASES[case_id].target,
                  'role': None, 'invocationId': first['managerInvocation'],
                  'cgroupDigest': target_group, 'bootId': sender['bootId'],
                  'probeDigest': '', 'controlResponseDigest': first['controlDigest']}
        code = audit['kernelOpenResult']['errno']
        witness = {'actorUid': sender['uid'], 'attackDigest': attack_digest,
                   'attackStartedNs': audit['attackStartedNs'],
                   'targetActiveBeforeNs': first['observedMonotonicNs'],
                   'targetActiveAfterNs': last['observedMonotonicNs'],
                   'controlResponseDigest': first['controlDigest'],
                   'denialSource': 'kernel',
                   'denialCode': 'policy-rejected' if code == 'ENOENT' else code,
                   'unrelatedStateBefore': audit['actorStateBefore'],
                   'unrelatedStateAfter': audit['actorStateAfter'],
                   'targetIdentity': target}
        target['probeDigest'] = acceptance.payload_commitment(case_id, witness)
        case = acceptance.CASES[case_id]
        observation = {'caseId': case_id, 'status': 'passed', 'actor': case.actor,
                       'target': case.target, 'outcome': case.outcome,
                       'startedMonotonicNs': first['observedMonotonicNs'],
                       'finishedMonotonicNs': last['observedMonotonicNs'],
                       'witness': witness}
        attempt = {'contract': acceptance.CONTRACT, 'identity': identity,
                   'declaredCases': [case_id], 'observations': [observation],
                   'guestStopped': True, 'attemptCompleted': True,
                   'principals': result['roleKernelRoster'], 'targets': {case_id: target},
                   'caseCommitments': {}, 'appProcess': None, 'restartContext': None}
        sidecar = {'contract': campaign.CONTRACT, 'caseId': case_id,
                   'status': 'passed', 'actorEpoch': _v9_actor_epoch(before, sender),
                   'targetEpoch': {'kind': 'installed-resolver-service',
                                   'bootId': sender['bootId'],
                                   'systemdInvocation': first['managerInvocation'],
                                   'cgroupDigest': target_group,
                                   'mainPid': first['mainPid'],
                                   'mainStartTicks': first['mainStartTicks'],
                                   'canaryIdentity': first['canaryIdentity'],
                                   'controlDigestBefore': first['controlDigest'],
                                   'controlDigestAfter': last['controlDigest']},
                   'operationWindow': {'startedMonotonicNs': audit['attackStartedNs'],
                                       'finishedMonotonicNs': audit['attackFinishedNs']},
                   'attackDigest': attack_digest, 'hostVerifiedIdentity': host,
                   'guestStopped': True,
                   'stopReceiptObservedNs': receipt['observedMonotonicNs']}
        return identity, attempt, sidecar
    except (AttributeError, KeyError, TypeError, ValueError, IndexError, StopIteration,
            OSError):
        return None


def _hostile_origin_attempt(report, result, fixture, terminal, source, diagnostics):
    """Bind a candidate-role Origin refusal to the live signed Mail AppHost."""
    case_id = 'hostile-app-origin'
    try:
        if (not group_prepared(report, result, terminal, 'authority')
                or fixture.get('schemaVersion') != 4
                or not isinstance(diagnostics, dict)
                or terminal['hostileAppOriginAudit']['status'] != 'captured'):
            return None
        audit = terminal['hostileAppOriginAudit']['record']
        sender = next(row for row in result['roleKernelRoster']['roles']
                      if row['role'] == 'candidate-sender')
        before, after = audit['actorBefore'], audit['actorAfter']
        first, last = audit['targetBefore'], audit['targetAfter']
        receipt = terminal['stopReceipts']['candidate-sender']['current']['record']
        worker = result['mailAppKernelProcess']
        host = report['hostVerifiedIdentity']
        stable_actor = ('hostPid', 'hostParentPid', 'startTicks', 'namespacePids',
                        'pidNamespace', 'networkNamespaceIdentity',
                        'mountNamespaceIdentity', 'userNamespaceIdentity',
                        'executableDigest', 'noNewPrivileges',
                        'effectiveCapabilities')
        stable_target = ('role', 'managerInvocation', 'bootId', 'cgroupIdentity',
                         'workerHostPid', 'workerStartTicks',
                         'javaHostPid', 'javaStartTicks')
        actor_group = fixtures.runtime.canonical_digest({
            'role': 'candidate-sender', 'identity': audit['actorCgroupBefore']})[7:]
        if (audit['schemaVersion'] != 1
                or audit['kind'] != 'pr315-administrator-hostile-app-origin-denial'
                or audit['caseId'] != case_id
                or audit['sourceDigest'] != reference.sha256(source /
                    'tools/release-certification/restricted/pr315_role_probe.py')
                or audit['actorUid'] != sender['uid']
                or any(before[key] != after[key] for key in stable_actor)
                or before['hostPid'] <= 1 or before['startTicks'] <= 0
                or len(before['namespacePids']) < 2
                or before['networkNamespaceIdentity'][1] != sender['networkNamespace']
                or before['noNewPrivileges'] is not True
                or before['effectiveCapabilities'] != 0
                or audit['actorInvocationBefore'] != sender['invocationId']
                or audit['actorInvocationAfter'] != sender['invocationId']
                or audit['actorCgroupBefore'] != audit['actorCgroupAfter']
                or actor_group != sender['cgroupDigest']
                or audit['actorStateBefore'] != audit['actorStateAfter']
                or terminal['sentinel']['status'] != 'matched'
                or terminal['sentinel']['observedDigest'] !=
                    'sha256:' + audit['actorStateBefore']
                or any(first[key] != last[key] for key in stable_target)
                or first['role'] != 'candidate-sender'
                or first['managerInvocation'] != sender['invocationId']
                or first['bootId'].replace('-', '').lower() != sender['bootId']
                or fixtures.runtime.canonical_digest({
                    'role': 'candidate-sender',
                    'identity': first['cgroupIdentity']})[7:] != sender['cgroupDigest']
                or type(first['workerHostPid']) is not int
                or type(first['workerStartTicks']) is not int
                or first['workerHostPid'] <= 1 or first['workerStartTicks'] <= 0
                or worker['provenance'] != 'controller-kernel-sample'
                or worker['hostPid'] != first['workerHostPid']
                or worker['startTicks'] != first['workerStartTicks']
                or worker['javaHostPid'] != first['javaHostPid']
                or worker['javaStartTicks'] != first['javaStartTicks']
                or worker['managerInvocation'] != sender['invocationId']
                or worker['bootId'] != first['bootId']
                or type(worker['javaHostPid']) is not int
                or worker['javaHostPid'] <= 1
                or type(worker['javaStartTicks']) is not int
                or worker['javaStartTicks'] < worker['startTicks']
                or audit['sessionDigest'] != diagnostics['hostileOriginSessionDigest']
                or audit['expectedOriginDigest'] != result['mailUiOriginDigest']
                or audit['hostileOriginDigest'] != hashlib.sha256(
                    b'http://127.0.0.1:1').hexdigest()
                or audit['targetEndpointDigest'] != hashlib.sha256(
                    b'/api/v1/app-data/status').hexdigest()
                or audit['denialStatus'] != 403
                or audit['denialCode'] != 'origin_mismatch'
                or any(audit[key]['status'] != 200
                       or audit[key]['errorCode'] is not None
                       for key in ('controlBefore', 'controlAfter'))
                or not first['observedMonotonicNs']
                    < audit['controlBefore']['startedMonotonicNs']
                    < audit['controlBefore']['finishedMonotonicNs']
                    < audit['attackStartedNs'] < audit['attackFinishedNs']
                    < audit['controlAfter']['startedMonotonicNs']
                    < audit['controlAfter']['finishedMonotonicNs']
                    < last['observedMonotonicNs'] < receipt['startedMonotonicNs']
                or receipt['managerInvocation'] != sender['invocationId']
                or receipt['membership'] != 'only-stop-helper'
                or receipt['descendantCgroups'] != 0
                or host['helperSourceCommit'] != result['identity']['sourceCommit']):
            return None
        identity = {key: host[key] for key in ('helperSourceCommit',
            'helperSourceTree', 'bundleIdentity', 'testKitDigest',
            'profileDigest', 'bootClosureDigest', 'preparedImageDigest',
            'fixtureManifestDigest')}
        identity['productSelectionDigest'] = host['productDigest']
        identity['admittedAppDigest'] = fixture['mailDigest'][7:]
        attack_digest = hashlib.sha256(json.dumps(audit, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        target = {'caseId': case_id, 'target': acceptance.CASES[case_id].target,
                  'role': 'candidate-sender',
                  'invocationId': sender['invocationId'],
                  'cgroupDigest': sender['cgroupDigest'], 'bootId': sender['bootId'],
                  'probeDigest': '',
                  'controlResponseDigest': first['controlResponseDigest']}
        witness = {'actorUid': sender['uid'], 'attackDigest': attack_digest,
                   'attackStartedNs': audit['attackStartedNs'],
                   'targetActiveBeforeNs': first['observedMonotonicNs'],
                   'targetActiveAfterNs': last['observedMonotonicNs'],
                   'controlResponseDigest': first['controlResponseDigest'],
                   'denialSource': 'server', 'denialCode': 'policy-rejected',
                   'unrelatedStateBefore': audit['actorStateBefore'],
                   'unrelatedStateAfter': audit['actorStateAfter'],
                   'targetIdentity': target}
        target['probeDigest'] = acceptance.payload_commitment(case_id, witness)
        case = acceptance.CASES[case_id]
        observation = {'caseId': case_id, 'status': 'passed',
            'actor': case.actor, 'target': case.target, 'outcome': case.outcome,
            'startedMonotonicNs': first['observedMonotonicNs'],
            'finishedMonotonicNs': last['observedMonotonicNs'],
            'witness': witness}
        attempt = {'contract': acceptance.CONTRACT, 'identity': identity,
            'declaredCases': [case_id], 'observations': [observation],
            'guestStopped': True, 'attemptCompleted': True,
            'principals': result['roleKernelRoster'],
            'targets': {case_id: target}, 'caseCommitments': {},
            'appProcess': None, 'restartContext': None}
        sidecar = {'contract': campaign.CONTRACT, 'caseId': case_id,
            'status': 'passed', 'actorEpoch': _v9_actor_epoch(before, sender),
            'targetEpoch': {'kind': 'normally-signed-mail-apphost',
                'role': 'candidate-sender',
                'bootId': sender['bootId'],
                'systemdInvocation': sender['invocationId'],
                'cgroupDigest': sender['cgroupDigest'],
                'installedAppDigest': fixture['mailDigest'][7:],
                'workerHostPid': first['workerHostPid'],
                'workerStartTicks': first['workerStartTicks'],
                'javaHostPid': first['javaHostPid'],
                'javaStartTicks': first['javaStartTicks'],
                'expectedOriginDigest': audit['expectedOriginDigest'],
                'sessionDigest': audit['sessionDigest'],
                'controlBeforeDigest': first['controlResponseDigest'],
                'controlAfterDigest': last['controlResponseDigest']},
            'operationWindow': {'startedMonotonicNs': audit['attackStartedNs'],
                                'finishedMonotonicNs': audit['attackFinishedNs']},
            'attackDigest': attack_digest,
            'denialCode': 'origin_mismatch',
            'hostVerifiedIdentity': host, 'guestStopped': True,
            'stopReceiptObservedNs': receipt['observedMonotonicNs']}
        return identity, attempt, sidecar
    except (AttributeError, KeyError, TypeError, ValueError, IndexError,
            StopIteration, OSError):
        return None


def _provider_authority_attempt(*args, **kwargs):
    """Delegate the measured case verifier without changing callers."""
    from pr315_installed_case_validators import _provider_authority_attempt as verify
    return verify(*args, **kwargs)


def _sibling_app_attempt(*args, **kwargs):
    """Delegate the measured case verifier without changing callers."""
    from pr315_installed_case_validators import _sibling_app_attempt as verify
    return verify(*args, **kwargs)


def _resource_child_provenance(record, audit, actor, uid):
    """Cross-check root-owned child epochs and exit observation against the audit."""
    if (not isinstance(record, dict) or set(record) != {
            'schemaVersion', 'kind', 'caseId', 'actorHostPid',
            'actorStartTicks', 'roleCgroupIdentity', 'observedMonotonicNs',
            'exitedMonotonicNs', 'children'}
            or record['schemaVersion'] != 1
            or record['kind'] != 'pr315-administrator-resource-child-epochs'
            or record['caseId'] != 'resource-exhaustion'
            or record['actorHostPid'] != actor['hostPid']
            or record['actorStartTicks'] != actor['startTicks']
            or record['roleCgroupIdentity'] != audit['roleDuring']['cgroupIdentity']
            or record['observedMonotonicNs'] != audit['childEpochsObservedNs']
            or record['exitedMonotonicNs'] != audit['childExitObservedNs']
            or not isinstance(record['children'], list)
            or len(record['children']) != audit['childEpochCount']
            or len(record['children']) != audit['ready']['spawnedCount']
            or not 1 <= len(record['children']) <= 600
            or hashlib.sha256(json.dumps(record, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest() !=
                audit['childEpochDigest']):
        return False
    pids = set()
    for child in record['children']:
        if (not isinstance(child, dict) or set(child) != {
                'pid', 'parentPid', 'startTicks', 'uid',
                'namespacePid', 'pidNamespace'}
                or type(child['pid']) is not int or child['pid'] <= 1
                or child['pid'] in pids
                or child['parentPid'] != actor['hostPid']
                or type(child['startTicks']) is not int
                or child['startTicks'] < actor['startTicks']
                or child['uid'] != uid
                or type(child['namespacePid']) is not int
                or child['namespacePid'] <= actor['namespacePids'][-1]
                or child['pidNamespace'] != actor['pidNamespaceIdentity']):
            return False
        pids.add(child['pid'])
    return True


def _resource_exhaustion_attempt(*args, **kwargs):
    """Delegate the measured case verifier without changing callers."""
    from pr315_installed_case_validators import _resource_exhaustion_attempt as verify
    return verify(*args, **kwargs)


def _partial_launch_record(campaign_plan, attempt_id, report, result,
                           terminal, diagnostics, source, raw_digests):
    """Verify the intentionally partial roster and genuine failed launch."""
    try:
        if (campaign_plan.get('kind') != campaign_seal.CAMPAIGN
                or not isinstance(attempt_id, str)
                or campaign_seal._ATTEMPT_ID.fullmatch(attempt_id) is None
                or report.get('mode') != 'workload-positive'
                or report.get('workloadPurpose') != 'selected-group'
                or report.get('status') != 'guest-report-retained'
                or report.get('guestExitCode') != 0
                or report.get('guestStopped') is not True
                or result.get('groupPreparation') != 'partial-launch'
                or result.get('topologyRoles') != 2
                or result.get('signedAppWorkers') != 0
                or result.get('contentRetrieval') != 'not-executed-group'
                or result.get('newEpoch') is not False
                or 'roleKernelRoster' in result
                or result.get('identity', {}).get('sourceCommit') !=
                   campaign_plan['identity']['helperSourceCommit']
                or fixtures.runtime.canonical_digest(result['runtimePolicy']) !=
                   fixtures.runtime.canonical_digest(
                       fixtures.preparation.launcher_policy())
                or diagnostics.get('partialLaunch', {}).get('status') != 'captured'
                or not selected_probe_started('partial-launch', diagnostics)
                or terminal.get('cleanupReportedByCaller') is not True
                or terminal.get('sentinel', {}).get('status') != 'matched'
                or terminal.get('partialLaunchAudit', {}).get('status') != 'captured'
                or not isinstance(raw_digests, dict)
                or set(raw_digests) != {'guestReport', 'volatile', 'hostMonitor'}
                or any(re.fullmatch('[0-9a-f]{64}', str(digest)) is None
                       for digest in raw_digests.values())):
            return None
        host = report['hostVerifiedIdentity']
        identity = campaign_plan['identity']
        if (host['helperSourceCommit'] != identity['helperSourceCommit']
                or host['testKitDigest'] != identity['testKitDigest']
                or host['bundleIdentity'] != identity['bundleIdentity']):
            return None
        roles = result['partialRoleRoster']
        fields = {'role', 'uid', 'gid', 'invocationId', 'processEpoch',
                  'bootId', 'cgroupDigest', 'networkNamespace'}
        if (not isinstance(roles, list) or len(roles) != 2
                or [row['role'] for row in roles] !=
                    ['candidate-sender', 'candidate-recipient']
                or any(set(row) != fields or row['uid'] <= 0
                       or row['gid'] <= 0 or row['processEpoch'] <= 0
                       or row['networkNamespace'] <= 0
                       or re.fullmatch('[0-9a-f]{32}', row['invocationId']) is None
                       or re.fullmatch('[0-9a-f]{64}', row['cgroupDigest']) is None
                       for row in roles)
                or roles[0]['bootId'] != roles[1]['bootId']):
            return None
        audit = terminal['partialLaunchAudit']['record']
        if terminal['sentinel'].get('observedDigest') != (
                'sha256:' + audit['senderAfter']['stateDigest']):
            return None
        audit_digest = hashlib.sha256(json.dumps(audit, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        marker = audit['previousStartMarker']
        fault = audit['previousFault']
        actor = audit['previousActor']
        observer = audit['observerActor']
        administrator = audit['administratorBefore']
        administrator_after = audit['administratorAfter']
        previous_receipt = audit['previousStopReceipt']
        if (audit['schemaVersion'] != 2
                or audit['kind'] != 'pr315-administrator-partial-launch'
                or audit.get('synchronizationPolicy') != 'pr315-partial-launch-start-response-v2'
                or audit['caseId'] != 'partial-launch'
                or audit_digest != diagnostics['partialLaunch']['auditDigest']
                or audit['launcherSourceDigest'] != reference.sha256(source /
                    'tools/release-certification/protected/restricted_workload_launcher.py')
                or administrator['uid'] != 0
                or administrator['pid'] <= 1
                or administrator['sourceDigest'] != reference.sha256(source /
                    'tools/release-certification/restricted/pr314_workload_driver.py')
                or any(administrator[key] != administrator_after[key]
                       for key in ('pid', 'uid', 'startTicks', 'bootId',
                                   'cgroupIdentity', 'cgroupDigest',
                                   'invocationId', 'sourceDigest'))
                or administrator['bootId'].replace('-', '').lower() != roles[0]['bootId']
                or observer['uid'] != audit['observerUid']
                or observer['kind'] != 'installed-observer-process'
                or observer['sourceDigest'] != reference.sha256(source /
                    'tools/release-certification/restricted/pr314_workload_driver.py')
                or observer['bootId'].replace('-', '').lower() != roles[0]['bootId']
                or actor['hostPid'] != fault['pid']
                or actor['startTicks'] != fault['startTicks']
                or actor['cgroupIdentity'] != marker['cgroupIdentity']
                or actor['executableDigest'].startswith('sha256:') is not True
                or hashlib.sha256(fault['nonce'].encode()).hexdigest() !=
                    audit['nonceDigest']
                or fault['sourceDigest'] != audit['launcherSourceDigest']
                or audit['previousBefore']['state'] != 'prepared'
                or audit['previousBefore']['generation'] is not None
                or audit['previousBefore']['bootId'] != marker['bootId']
                or audit['relayBefore'] != audit['relayAfter']
                or audit['relayBefore']['state'] != 'prepared'
                or audit['relayBefore']['generation'] is not None
                or audit['relayBefore']['bootId'] != marker['bootId']
                or previous_receipt['managerInvocation'] != marker['managerInvocation']
                or previous_receipt['cgroupIdentity'] != marker['cgroupIdentity']
                or previous_receipt['membership'] != 'only-stop-helper'
                or previous_receipt['descendantCgroups'] != 0
                or audit['controllerResponse'] not in (
                    'controller-rejected-launch', 'transient-start-response')
                or not audit['probeStartedNs'] <= audit['startResponseStartedNs']
                    < audit['startResponseObservedNs'] <= audit['faultWaitStartedNs']
                    < actor['observedMonotonicNs'] < audit['faultWaitUntilNs']
                or not 0 < audit['faultWaitUntilNs']-audit['faultWaitStartedNs']
                    <= 9*10**9
                or not diagnostics['probeStart']['startedMonotonicNs']
                    <= administrator['observedMonotonicNs']
                    < audit['probeStartedNs'] < fault['observedMonotonicNs']
                    <= actor['observedMonotonicNs'] < audit['releasePublishedNs']
                    < previous_receipt['observedMonotonicNs']
                    < administrator_after['observedMonotonicNs']
                    < audit['terminalObservedNs']):
            return None
        for row, key in zip(roles, ('sender', 'recipient')):
            first, last = audit[key + 'Before'], audit[key + 'After']
            receipt = terminal['stopReceipts'][row['role']]['current']
            if (first['managerInvocation'] != row['invocationId']
                    or last['managerInvocation'] != row['invocationId']
                    or first['stateDigest'] != last['stateDigest']
                    or first['cgroupIdentity'] != last['cgroupIdentity']
                    or fixtures.runtime.canonical_digest({'role': row['role'],
                        'identity': first['cgroupIdentity']})[7:] != row['cgroupDigest']
                    or receipt['status'] != 'captured'
                    or receipt['record']['managerInvocation'] != row['invocationId']
                    or receipt['record']['membership'] != 'only-stop-helper'
                    or receipt['record']['descendantCgroups'] != 0
                    or last['observedMonotonicNs'] >=
                        receipt['record']['startedMonotonicNs']):
                return None
        previous_terminal = terminal['stopReceipts']['previous']['current']
        relay_terminal = terminal['stopReceipts']['relay-no-apps']['current']
        if (previous_terminal['status'] != 'captured'
                or previous_terminal['record'] != previous_receipt
                or relay_terminal['status'] == 'captured'
                or terminal['controllerRecords']['previous']['status'] != 'captured'
                or terminal['controllerRecords']['previous']['record']['state'] != 'quiescent'
                or terminal['controllerRecords']['previous']['record']['managerInvocation']
                    != marker['managerInvocation']
                or terminal['controllerRecords']['relay-no-apps']['status'] != 'captured'
                or terminal['controllerRecords']['relay-no-apps']['record']['state'] != 'prepared'
                or terminal['controllerRecords']['relay-no-apps']['record']['generation'] is not None
                or terminal['controllerRecords']['relay-no-apps']['record']['managerInvocation']
                    is not None):
            return None
        stop_ns = max(terminal['stopReceipts'][row['role']]['current']
            ['record']['observedMonotonicNs'] for row in roles)
        stop_ns = max(stop_ns, previous_receipt['observedMonotonicNs'])
        record = {'schemaVersion': 10, 'kind': case_v10.KIND,
            'contract': campaign_seal.CONTRACT,
            'campaignPlanDigest': campaign_plan['planDigest'],
            'campaignNonce': campaign_plan['campaignNonce'],
            'attemptId': attempt_id, 'groupId': 'partial-launch',
            'caseId': 'partial-launch', 'status': 'passed',
            'sourceCommit': identity['helperSourceCommit'],
            'actorEpoch': administrator,
            'targetEpoch': {'startedRoles': roles,
                'observerEpoch': observer,
                'previousLauncher': actor, 'previousStartMarker': marker,
                'previousStopReceipt': previous_receipt,
                'relayNeverStarted': True},
            'operationWindow': {'startedMonotonicNs': audit['probeStartedNs'],
                'finishedMonotonicNs': audit['terminalObservedNs']},
            'operationTimeDomain': 'guest:' + roles[0]['bootId'],
            'v8AttemptDigest': None, 'v8ObservationDigest': None,
            'v9SidecarDigest': audit_digest,
            'hostIdentityDigest': case_v10._digest(host),
            'rawEvidenceDigests': raw_digests,
            'stopReceiptObservedNs': stop_ns,
            'classification': 'private-host-verified-candidate-not-standalone-acceptance'}
        return record
    except (AttributeError, KeyError, TypeError, ValueError, IndexError, StopIteration):
        return None


def _stuck_output_record(campaign_plan, attempt_id, report, result,
                         terminal, diagnostics, source, raw_digests):
    """Bind the installed collector timeout to a live role writer and stop."""
    try:
        if (not group_prepared(report, result, terminal, 'stuck-output')
                or campaign_plan.get('kind') != campaign_seal.CAMPAIGN
                or campaign_seal._ATTEMPT_ID.fullmatch(attempt_id) is None
                or not selected_probe_started('stuck-output', diagnostics)
                or diagnostics.get('stuckOutput', {}).get('status') != 'captured'
                or terminal.get('stuckOutputAudit', {}).get('status') != 'captured'
                or not isinstance(raw_digests, dict)
                or set(raw_digests) != {'guestReport', 'volatile', 'hostMonitor'}
                or any(re.fullmatch('[0-9a-f]{64}', str(digest)) is None
                       for digest in raw_digests.values())):
            return None
        host = report['hostVerifiedIdentity']
        identity = campaign_plan['identity']
        sender = next(row for row in result['roleKernelRoster']['roles']
                      if row['role'] == 'candidate-sender')
        audit = terminal['stuckOutputAudit']['record']
        digest = hashlib.sha256(json.dumps(audit, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        administrator = audit['administratorBefore']
        administrator_after = audit['administratorAfter']
        actor = audit['actor']
        writer = audit['writer']
        collector = audit['collector']
        stop_actor = audit['observerStopActor']
        receipt = audit['senderStopReceipt']
        final = terminal['stopReceipts']['candidate-sender']['current']
        if (host['helperSourceCommit'] != identity['helperSourceCommit']
                or host['testKitDigest'] != identity['testKitDigest']
                or digest != diagnostics['stuckOutput']['auditDigest']
                or audit['schemaVersion'] != 1
                or audit['kind'] != 'pr315-administrator-stuck-output'
                or audit['caseId'] != 'stuck-output'
                or audit['sourceDigest'] != reference.sha256(source /
                    'tools/release-certification/restricted/pr315_role_probe.py')
                or audit['collectorDenial'] != 'bounded_process_deadline_exceeded'
                or audit['collectorOutputDigest'] != hashlib.sha256(
                    b'pr315-stuck-output\n').hexdigest()
                or administrator['uid'] != 0 or administrator['pid'] <= 1
                or administrator['sourceDigest'] != reference.sha256(source /
                    'tools/release-certification/restricted/pr314_workload_driver.py')
                or any(administrator[key] != administrator_after[key]
                       for key in ('pid', 'uid', 'startTicks', 'bootId',
                                   'cgroupIdentity', 'cgroupDigest',
                                   'invocationId', 'sourceDigest'))
                or administrator['bootId'].replace('-', '').lower() != sender['bootId']
                or actor['hostPid'] <= 1 or actor['startTicks'] <= 0
                or actor['networkNamespaceIdentity'][1] != sender['networkNamespace']
                or audit['roleBefore']['managerInvocation'] != sender['invocationId']
                or fixtures.runtime.canonical_digest({'role': 'candidate-sender',
                    'identity': audit['roleBefore']['cgroupIdentity']})[7:]
                    != sender['cgroupDigest']
                or audit['roleBefore']['stateDigest'] !=
                    terminal['sentinel']['observedDigest'].removeprefix('sha256:')
                or writer['hostParentPid'] != actor['hostPid']
                or writer['hostPid'] <= 1 or writer['startTicks'] < actor['startTicks']
                or writer['namespacePids'][-1] <= actor['namespacePids'][-1]
                or collector['uid'] != 0 or collector['pid'] <= 1
                or collector['session'] != collector['pid']
                or collector['startTicks'] <= 0
                or collector['cgroupIdentity'] == audit['roleBefore']['cgroupIdentity']
                or re.fullmatch('[0-9a-f]{64}', collector['executableDigest']) is None
                or not isinstance(audit['fifoIdentity'], list)
                or len(audit['fifoIdentity']) != 2
                or stop_actor['kind'] != 'installed-observer-process'
                or stop_actor['uid'] != result['roleKernelRoster']['observerUid']
                or stop_actor['sourceDigest'] != administrator['sourceDigest']
                or audit['observerStopResponse']['state'] != 'quiescent'
                or audit['observerStopResponse']['managerInvocation'] != sender['invocationId']
                or final['status'] != 'captured'
                or final['record'] != receipt
                or receipt['managerInvocation'] != sender['invocationId']
                or receipt['membership'] != 'only-stop-helper'
                or receipt['descendantCgroups'] != 0):
            return None
        if (len(audit['siblingsBefore']) != 3
                or len(audit['siblingsAfter']) != 3
                or [row['role'] for row in audit['siblingsBefore']] !=
                    ['candidate-recipient', 'previous', 'relay-no-apps']):
            return None
        for first, last in zip(audit['siblingsBefore'], audit['siblingsAfter']):
            principal = next(row for row in result['roleKernelRoster']['roles']
                             if row['role'] == first['role'])
            if (first['role'] != last['role']
                    or first['managerInvocation'] != last['managerInvocation']
                    or first['managerInvocation'] != principal['invocationId']
                    or first['stateDigest'] != last['stateDigest']
                    or re.fullmatch('[0-9a-f]{64}', first['controlDigest']) is None
                    or re.fullmatch('[0-9a-f]{64}', last['controlDigest']) is None):
                return None
        if not (diagnostics['probeStart']['startedMonotonicNs']
                <= administrator['observedMonotonicNs']
                < audit['collectorStartedNs'] < collector['observedMonotonicNs']
                < audit['collectorStartedNs'] + 5 * 10**9
                < audit['collectorFinishedNs']
                < receipt['startedMonotonicNs']
                < receipt['observedMonotonicNs']
                < administrator_after['observedMonotonicNs']
                < audit['terminalObservedNs']):
            return None
        if audit['collectorFinishedNs'] - audit['collectorStartedNs'] > 16 * 10**9:
            return None
        return {'schemaVersion': 10, 'kind': case_v10.KIND,
            'contract': campaign_seal.CONTRACT,
            'campaignPlanDigest': campaign_plan['planDigest'],
            'campaignNonce': campaign_plan['campaignNonce'],
            'attemptId': attempt_id, 'groupId': 'stuck-output',
            'caseId': 'stuck-output', 'status': 'passed',
            'sourceCommit': identity['helperSourceCommit'],
            'actorEpoch': administrator,
            'targetEpoch': {'role': sender,
                'writer': writer, 'collector': collector,
                'fifoIdentity': audit['fifoIdentity'],
                'observerStopActor': stop_actor,
                'senderStopReceipt': receipt},
            'operationWindow': {'startedMonotonicNs': audit['collectorStartedNs'],
                'finishedMonotonicNs': audit['terminalObservedNs']},
            'operationTimeDomain': 'guest:' + sender['bootId'],
            'v8AttemptDigest': None, 'v8ObservationDigest': None,
            'v9SidecarDigest': digest,
            'hostIdentityDigest': case_v10._digest(host),
            'rawEvidenceDigests': raw_digests,
            'stopReceiptObservedNs': receipt['observedMonotonicNs'],
            'classification': 'private-host-verified-candidate-not-standalone-acceptance'}
    except (AttributeError, KeyError, TypeError, ValueError, IndexError,
            StopIteration, OSError):
        return None


def _late_child_record(campaign_plan, attempt_id, report, result,
                       terminal, diagnostics, source, raw_digests):
    """Bind one child created after real stop intent to its exact killed role."""
    try:
        if (not group_prepared(report, result, terminal, 'late-child')
                or campaign_plan.get('kind') != campaign_seal.CAMPAIGN
                or campaign_seal._ATTEMPT_ID.fullmatch(attempt_id) is None
                or not selected_probe_started('late-child', diagnostics)
                or diagnostics.get('lateChild', {}).get('status') != 'captured'
                or terminal.get('lateChildAudit', {}).get('status') != 'captured'
                or not isinstance(raw_digests, dict)
                or set(raw_digests) != {'guestReport', 'volatile', 'hostMonitor'}
                or any(re.fullmatch('[0-9a-f]{64}', str(digest)) is None
                       for digest in raw_digests.values())):
            return None
        host = report['hostVerifiedIdentity']
        identity = campaign_plan['identity']
        sender = next(row for row in result['roleKernelRoster']['roles']
                      if row['role'] == 'candidate-sender')
        audit = terminal['lateChildAudit']['record']
        digest = hashlib.sha256(json.dumps(audit, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        administrator = audit['administratorBefore']
        administrator_after = audit['administratorAfter']
        actor = audit['actor']
        child = audit['childRecord']
        child_actor = audit['childActor']
        phase = audit['phase']
        receipt = audit['stopReceipt']
        final = terminal['stopReceipts']['candidate-sender']['current']
        if (host['helperSourceCommit'] != identity['helperSourceCommit']
                or host['testKitDigest'] != identity['testKitDigest']
                or digest != diagnostics['lateChild']['auditDigest']
                or audit['schemaVersion'] != 1
                or audit['kind'] != 'pr315-administrator-late-child'
                or audit['caseId'] != 'late-child'
                or audit['sourceDigest'] != reference.sha256(source /
                    'tools/release-certification/restricted/pr315_lifecycle_role_probe.py')
                or audit['barrierSourceDigest'] != reference.sha256(source /
                    'tools/release-certification/protected/restricted_workload_lifecycle_barrier.py')
                or administrator['uid'] != 0 or administrator['pid'] <= 1
                or administrator['sourceDigest'] != reference.sha256(source /
                    'tools/release-certification/restricted/pr314_workload_driver.py')
                or any(administrator[key] != administrator_after[key]
                       for key in ('pid', 'uid', 'startTicks', 'bootId',
                                   'cgroupIdentity', 'cgroupDigest',
                                   'invocationId', 'sourceDigest'))
                or administrator['bootId'].replace('-', '').lower() != sender['bootId']
                or actor['hostPid'] <= 1 or actor['startTicks'] <= 0
                or actor['networkNamespaceIdentity'][1] != sender['networkNamespace']
                or audit['roleBefore']['managerInvocation'] != sender['invocationId']
                or fixtures.runtime.canonical_digest({'role': 'candidate-sender',
                    'identity': audit['roleBefore']['cgroupIdentity']})[7:]
                    != sender['cgroupDigest']
                or audit['roleBefore']['stateDigest'] !=
                    terminal['sentinel']['observedDigest'].removeprefix('sha256:')
                or phase['kind'] != 'pr315-fixed-stop-phase'
                or phase['caseId'] != 'late-child'
                or phase['managerInvocation'] != sender['invocationId']
                or phase['cgroupIdentity'] != audit['roleBefore']['cgroupIdentity']
                or phase['nonceDigest'] != audit['nonceDigest']
                or child['kind'] != 'pr315-candidate-late-child-created'
                or child['parentPid'] != actor['namespacePids'][-1]
                or hashlib.sha256(child['nonce'].encode()).hexdigest() !=
                    audit['nonceDigest']
                or child_actor['hostParentPid'] != actor['hostPid']
                or child_actor['namespacePids'][-1] != child['childPid']
                or child_actor['cgroupIdentity'] != phase['cgroupIdentity']
                or child_actor['startTicks'] < actor['startTicks']
                or child_actor['networkNamespaceIdentity'] != actor['networkNamespaceIdentity']
                or child_actor['mountNamespaceIdentity'] != actor['mountNamespaceIdentity']
                or child_actor['userNamespaceIdentity'] != actor['userNamespaceIdentity']
                or child_actor['noNewPrivileges'] is not True
                or child_actor['effectiveCapabilities'] != 0
                or audit['observerStopActor']['kind'] != 'installed-observer-process'
                or audit['observerStopActor']['uid'] !=
                    result['roleKernelRoster']['observerUid']
                or audit['observerStopActor']['sourceDigest'] !=
                    administrator['sourceDigest']
                or final['status'] != 'captured' or final['record'] != receipt
                or receipt['managerInvocation'] != sender['invocationId']
                or receipt['cgroupIdentity'] != phase['cgroupIdentity']
                or receipt['membership'] != 'only-stop-helper'
                or receipt['descendantCgroups'] != 0):
            return None
        if (len(audit['siblingsBefore']) != 3
                or len(audit['siblingsAfter']) != 3
                or [row['role'] for row in audit['siblingsBefore']] !=
                    ['candidate-recipient', 'previous', 'relay-no-apps']):
            return None
        for first, last in zip(audit['siblingsBefore'], audit['siblingsAfter']):
            principal = next(row for row in result['roleKernelRoster']['roles']
                             if row['role'] == first['role'])
            if (first['role'] != last['role']
                    or first['managerInvocation'] != last['managerInvocation']
                    or first['managerInvocation'] != principal['invocationId']
                    or first['stateDigest'] != last['stateDigest']
                    or re.fullmatch('[0-9a-f]{64}', first['controlDigest']) is None
                    or re.fullmatch('[0-9a-f]{64}', last['controlDigest']) is None):
                return None
        if not (diagnostics['probeStart']['startedMonotonicNs']
                <= administrator['observedMonotonicNs']
                < phase['observedMonotonicNs']
                < audit['triggerPublishedNs'] < child['startedMonotonicNs']
                < child_actor['observedMonotonicNs']
                < audit['releasePublishedNs']
                < receipt['startedMonotonicNs']
                < receipt['observedMonotonicNs']
                <= audit['childExitObservedNs']
                < administrator_after['observedMonotonicNs']
                < audit['terminalObservedNs']):
            return None
        return {'schemaVersion': 10, 'kind': case_v10.KIND,
            'contract': campaign_seal.CONTRACT,
            'campaignPlanDigest': campaign_plan['planDigest'],
            'campaignNonce': campaign_plan['campaignNonce'],
            'attemptId': attempt_id, 'groupId': 'late-child',
            'caseId': 'late-child', 'status': 'passed',
            'sourceCommit': identity['helperSourceCommit'],
            'actorEpoch': administrator,
            'targetEpoch': {'role': sender, 'probeActor': actor,
                'child': child_actor, 'stopPhase': phase,
                'stopReceipt': receipt},
            'operationWindow': {'startedMonotonicNs': phase['observedMonotonicNs'],
                'finishedMonotonicNs': audit['terminalObservedNs']},
            'operationTimeDomain': 'guest:' + sender['bootId'],
            'v8AttemptDigest': None, 'v8ObservationDigest': None,
            'v9SidecarDigest': digest,
            'hostIdentityDigest': case_v10._digest(host),
            'rawEvidenceDigests': raw_digests,
            'stopReceiptObservedNs': receipt['observedMonotonicNs'],
            'classification': 'private-host-verified-candidate-not-standalone-acceptance'}
    except (AttributeError, KeyError, TypeError, ValueError, IndexError,
            StopIteration, OSError):
        return None


def _output_artifact_attempt(*args, **kwargs):
    """Delegate the measured case verifier without changing callers."""
    from pr315_installed_case_validators import _output_artifact_attempt as verify
    return verify(*args, **kwargs)


def _output_symlink_attempt(report, result, fixture, terminal, source):
    return _output_artifact_attempt(report, result, fixture, terminal, source,
                                    'output-symlink')


def _output_fifo_attempt(report, result, fixture, terminal, source):
    return _output_artifact_attempt(report, result, fixture, terminal, source,
                                    'output-fifo')


def _output_hardlink_attempt(report, result, fixture, terminal, source):
    return _output_artifact_attempt(report, result, fixture, terminal, source,
                                    'output-hardlink')


def _output_flood_attempt(report, result, fixture, terminal, source):
    return _output_artifact_attempt(report, result, fixture, terminal, source,
                                    'output-flood')


def _output_replacement_attempt(report, result, fixture, terminal, source):
    return _output_artifact_attempt(report, result, fixture, terminal, source,
                                    'output-replacement')


def _sibling_network_attempt(case_id, report, result, fixture, terminal, source):
    """Bind one role TCP denial to active recipient controls and exact nft DROP."""
    cases = {'sibling-fcp': ('siblingFcpAudit', workload_network.FCP_PORT),
             'sibling-http': ('siblingHttpAudit', workload_network.HTTP_PORT)}
    try:
        field, port = cases[case_id]
        if (not (positive_executed(report, result, terminal)
                 or group_prepared(report, result, terminal, 'network-app'))
                or fixture.get('schemaVersion') != 4
                or terminal[field]['status'] != 'captured'):
            return None
        audit = terminal[field]['record']
        sender, recipient = (next(row for row in result['roleKernelRoster']['roles']
                                  if row['role'] == role)
                             for role in ('candidate-sender', 'candidate-recipient'))
        before, after = audit['actorBefore'], audit['actorAfter']
        first, last = audit['targetBefore'], audit['targetAfter']
        counter_before, counter_after = audit['counterBefore'], audit['counterAfter']
        stable = ('hostPid', 'hostParentPid', 'startTicks', 'namespacePids',
                  'pidNamespace', 'networkNamespaceIdentity', 'mountNamespaceIdentity',
                  'userNamespaceIdentity', 'executableDigest', 'noNewPrivileges',
                  'effectiveCapabilities')
        counter_name = workload_network.SIBLING_DROP_COUNTERS[case_id]
        policy = hashlib.sha256(workload_network.role_rules('candidate-sender').encode()).hexdigest()
        target_digest = hashlib.sha256(
            f'{workload_network.address("candidate-recipient")}:{port}'.encode()).hexdigest()
        recipient_group = fixtures.runtime.canonical_digest({
            'role': 'candidate-recipient', 'identity': first['cgroupIdentity']})[7:]
        sender_group = fixtures.runtime.canonical_digest({
            'role': 'candidate-sender', 'identity': audit['senderCgroupBefore']})[7:]
        sender_receipt = terminal['stopReceipts']['candidate-sender']['current']['record']
        recipient_receipt = terminal['stopReceipts']['candidate-recipient']['current']['record']
        host = report['hostVerifiedIdentity']
        if (audit['schemaVersion'] != 1
                or audit['kind'] != 'pr315-administrator-sibling-network-denial'
                or audit['caseId'] != case_id
                or audit['sourceDigest'] != reference.sha256(source /
                    'tools/release-certification/restricted/pr315_role_probe.py')
                or audit['actorUid'] != sender['uid']
                or any(before[key] != after[key] for key in stable)
                or before['hostPid'] <= 1 or before['startTicks'] <= 0
                or len(before['namespacePids']) < 2
                or before['networkNamespaceIdentity'][1] != sender['networkNamespace']
                or before['noNewPrivileges'] is not True
                or before['effectiveCapabilities'] != 0
                or audit['senderInvocationBefore'] != sender['invocationId']
                or audit['senderInvocationAfter'] != sender['invocationId']
                or audit['senderCgroupBefore'] != audit['senderCgroupAfter']
                or sender_group != sender['cgroupDigest']
                or audit['senderStateBefore'] != audit['senderStateAfter']
                or terminal['sentinel']['status'] != 'matched'
                or terminal['sentinel']['observedDigest'] !=
                    'sha256:' + audit['senderStateBefore']
                or first['role'] != 'candidate-recipient'
                or last['role'] != 'candidate-recipient'
                or first['managerInvocation'] != recipient['invocationId']
                or last['managerInvocation'] != recipient['invocationId']
                or first['cgroupIdentity'] != last['cgroupIdentity']
                or recipient_group != recipient['cgroupDigest']
                or first['bootId'].replace('-', '').lower() != recipient['bootId']
                or last['bootId'] != first['bootId']
                or re.fullmatch('[0-9a-f]{64}', first['controlDigest']) is None
                or re.fullmatch('[0-9a-f]{64}', last['controlDigest']) is None
                or audit['targetEndpointDigest'] != target_digest
                or audit['counterName'] != counter_name
                or audit['kernelConnectResult'] not in (
                    {'connected': False, 'errno': 'ETIMEDOUT'},
                    {'connected': False, 'errno': 'EHOSTUNREACH'},
                    {'connected': False, 'errno': 'ENETUNREACH'},
                    {'connected': False, 'errno': 'EACCES'})
                or host['helperSourceCommit'] != result['identity']['sourceCommit']):
            return None
        names = set(workload_network.SIBLING_DROP_COUNTERS.values())
        for row in (counter_before, counter_after):
            if (row['schemaVersion'] != 1
                    or row['kind'] != 'pr315-fixed-sibling-drop-counters'
                    or row['policyDigest'] != policy
                    or row['roleNamespaceIdentity'] != before['networkNamespaceIdentity']
                    or row['bootId'].replace('-', '').lower() != sender['bootId']
                    or set(row['counters']) != names
                    or any(set(value) != {'packets', 'bytes'}
                           or any(type(value[key]) is not int or value[key] < 0
                                  for key in ('packets', 'bytes'))
                           for value in row['counters'].values())):
                return None
        old, new = counter_before['counters'][counter_name], counter_after['counters'][counter_name]
        if (not 1 <= new['packets'] - old['packets'] <= 8
                or not 1 <= new['bytes'] - old['bytes'] <= 8192
                or any(counter_before['counters'][name] != counter_after['counters'][name]
                       for name in names if name != counter_name)
                or not first['observedMonotonicNs'] < first['controlObservedNs']
                    < counter_before['observedMonotonicNs']
                    < audit['triggerMonotonicNs'] < audit['attackStartedNs']
                    < audit['attackFinishedNs'] < counter_after['observedMonotonicNs']
                    < last['observedMonotonicNs'] < last['controlObservedNs']
                    < recipient_receipt['startedMonotonicNs']
                or sender_receipt['managerInvocation'] != sender['invocationId']
                or recipient_receipt['managerInvocation'] != recipient['invocationId']
                or sender_receipt['membership'] != 'only-stop-helper'
                or recipient_receipt['membership'] != 'only-stop-helper'
                or sender_receipt['descendantCgroups'] != 0
                or recipient_receipt['descendantCgroups'] != 0):
            return None
        identity = {key: host[key] for key in ('helperSourceCommit', 'helperSourceTree',
            'bundleIdentity', 'testKitDigest', 'profileDigest', 'bootClosureDigest',
            'preparedImageDigest', 'fixtureManifestDigest')}
        identity['productSelectionDigest'] = host['productDigest']
        identity['admittedAppDigest'] = fixture['mailDigest'][7:]
        attack_digest = hashlib.sha256(json.dumps(audit, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        target = {'caseId': case_id, 'target': acceptance.CASES[case_id].target,
                  'role': 'candidate-recipient',
                  'invocationId': recipient['invocationId'],
                  'cgroupDigest': recipient['cgroupDigest'], 'bootId': recipient['bootId'],
                  'probeDigest': '', 'controlResponseDigest': last['controlDigest']}
        witness = {'actorUid': sender['uid'], 'attackDigest': attack_digest,
                   'attackStartedNs': audit['attackStartedNs'],
                   'targetActiveBeforeNs': first['controlObservedNs'],
                   'targetActiveAfterNs': last['controlObservedNs'],
                   'controlResponseDigest': last['controlDigest'],
                   'denialSource': 'kernel', 'denialCode': 'policy-rejected',
                   'unrelatedStateBefore': audit['senderStateBefore'],
                   'unrelatedStateAfter': audit['senderStateAfter'],
                   'targetIdentity': target}
        target['probeDigest'] = acceptance.payload_commitment(case_id, witness)
        case = acceptance.CASES[case_id]
        observation = {'caseId': case_id, 'status': 'passed', 'actor': case.actor,
                       'target': case.target, 'outcome': case.outcome,
                       'startedMonotonicNs': first['observedMonotonicNs'],
                       'finishedMonotonicNs': last['controlObservedNs'],
                       'witness': witness}
        attempt = {'contract': acceptance.CONTRACT, 'identity': identity,
                   'declaredCases': [case_id], 'observations': [observation],
                   'guestStopped': True, 'attemptCompleted': True,
                   'principals': result['roleKernelRoster'], 'targets': {case_id: target},
                   'caseCommitments': {}, 'appProcess': None, 'restartContext': None}
        sidecar = {'contract': campaign.CONTRACT, 'caseId': case_id,
                   'status': 'passed', 'actorEpoch': _v9_actor_epoch(before, sender),
                   'targetEpoch': {'role': 'candidate-recipient',
                                   'bootId': recipient['bootId'],
                                   'systemdInvocation': recipient['invocationId'],
                                   'cgroupDigest': recipient['cgroupDigest'],
                                   'controlDigestBefore': first['controlDigest'],
                                   'controlDigestAfter': last['controlDigest']},
                   'counterName': counter_name,
                   'counterBefore': counter_before,
                   'counterAfter': counter_after,
                   'operationWindow': {'startedMonotonicNs': audit['attackStartedNs'],
                                       'finishedMonotonicNs': audit['attackFinishedNs']},
                   'attackDigest': attack_digest, 'hostVerifiedIdentity': host,
                   'guestStopped': True,
                   'stopReceiptObservedNs': recipient_receipt['observedMonotonicNs']}
        return identity, attempt, sidecar
    except (AttributeError, KeyError, TypeError, ValueError, IndexError, StopIteration, OSError):
        return None


def _host_network_attempt(*args, **kwargs):
    """Delegate the measured case verifier without changing callers."""
    from pr315_installed_case_validators import _host_network_attempt as verify
    return verify(*args, **kwargs)


def verify_campaign_runtime_inputs(args, frozen_campaign):
    """Bind v2 plan policy/app/product claims before any VM is allocated."""
    source = Path(args.source)
    tree = subprocess.run(['git', '-C', str(source),
        'rev-parse', 'HEAD^{tree}'], check=True, capture_output=True,
        text=True, timeout=10).stdout.strip()
    fixture_plan = fixtures.verify(args.prepared_fixtures,
        args.fixture_manifest_digest, source, args.product_source_commit)
    candidate_jar = source / 'build/cryptad-dist/lib/cryptad.jar'
    identity = frozen_campaign['identity']
    if (fixture_plan.get('schemaVersion') != 4
            or identity['helperSourceTree'] != tree
            or fixture_plan['sourceCommit'] !=
                identity['helperSourceCommit']
            or identity['preparedImageDigest'] !=
                args.prepared_image_digest
            or identity['fixtureManifestDigest'] !=
                args.fixture_manifest_digest
            or identity['productSelectionDigest'] !=
                reference.sha256(candidate_jar)
            or identity['admittedAppDigest'] !=
                fixture_plan['mailDigest'][7:]
            or frozen_campaign['runtimePolicyDigest'] !=
                campaign_seal._digest(
                    fixtures.preparation.launcher_policy())
            or frozen_campaign['probeDigest'] !=
                fixture_plan['probeDigest'][7:]):
        raise ValueError('workload-campaign-frozen-input-mismatch')
    return fixture_plan


def run(args):
    if os.geteuid() == 0:
        raise ValueError('reference-unprivileged-host-required')
    if args.profile != 'tcg-multi':
        raise ValueError('workload-accepted-tcg-profile-required')
    group = getattr(args, 'case_group', None)
    selected_cases(group)
    output_group = group in ('output-symlink', 'output-fifo',
                             'output-hardlink', 'output-flood', 'output-replacement')
    selected_preparation = output_group or group in (
        'role-boundary', 'authority', 'network-app',
        'cancellation', 'controller-restart', 'deadline', 'revocation-running',
        'setsid-double-fork', 'observer-death', 'lost-start-response',
        'resource-exhaustion', 'partial-launch', 'stuck-output',
        'late-child', 'cleanup-race')
    role_measurement = getattr(args, 'role_readiness_measurement', False)
    retired_preparation = getattr(args, 'retired_authority_preparation', False)
    retired_input_paths = tuple(getattr(args, name, None) for name in (
        'retired_authority_input', 'retired_authority_handoff',
        'campaign_public_key'))
    if any(path is not None for path in retired_input_paths) and (
            group != 'authority' or not all(
                path is not None for path in retired_input_paths)
            or getattr(args, 'campaign_plan', None) is None):
        raise ValueError('workload-retired-authority-input-selection-invalid')
    if (retired_preparation and
            (not role_measurement or group is not None
             or getattr(args, 'campaign_plan', None) is None)):
        raise ValueError('workload-retired-authority-selection-invalid')
    if (group is not None and (getattr(args, 'startup_measurement', False)
                               or role_measurement)) or (
            role_measurement and getattr(args, 'startup_measurement', False)):
        raise ValueError('workload-measurement-group-incompatible')
    scenario = (group if group in ('cancellation', 'controller-restart',
                                  'deadline', 'revocation-running',
                                  'setsid-double-fork', 'observer-death') else
                'none' if selected_preparation or role_measurement or group == 'positive' else
                getattr(args, 'lifecycle_scenario', 'cancellation'))
    requires_none = (selected_preparation and group not in
                     ('cancellation', 'controller-restart', 'deadline',
                      'revocation-running', 'setsid-double-fork',
                      'observer-death')) or role_measurement or group == 'positive'
    if (requires_none != (scenario == 'none')
            or (group in ('cancellation', 'controller-restart', 'deadline',
                          'revocation-running', 'setsid-double-fork',
                          'observer-death')
                and scenario != group)):
        raise ValueError('workload-group-lifecycle-invalid')
    for module in (reference, native_runner, acceptance, fixtures):
        expected = args.source / 'tools/release-certification/restricted' / Path(module.__file__).name
        if reference.sha256(module.__file__) != reference.sha256(expected):
            raise ValueError('executing-workload-source-mismatch')
    if reference.sha256(__file__) != reference.sha256(
            args.source / 'tools/release-certification/restricted' / Path(__file__).name):
        raise ValueError('executing-workload-source-mismatch')
    campaign_plan_path = getattr(args, 'campaign_plan', None)
    frozen_campaign = None
    if campaign_plan_path is not None:
        for module in (campaign_seal, case_v10):
            expected = (args.source / 'tools/release-certification/restricted' /
                        Path(module.__file__).name)
            if reference.sha256(module.__file__) != reference.sha256(expected):
                raise ValueError('executing-campaign-source-mismatch')
        fingerprint = getattr(args, 'campaign_key_fingerprint', None)
        if (not isinstance(fingerprint, str)
                or re.fullmatch('[0-9a-f]{64}', fingerprint) is None):
            raise ValueError('campaign-key-fingerprint-required')
    host_policy = getattr(args, 'host_memory_policy', 'legacy-physical-admission')
    if retired_preparation and host_policy != host_admission.POLICY:
        raise ValueError('workload-retired-authority-host-policy-required')
    if host_policy == host_admission.POLICY:
        relative = 'tools/release-certification/restricted'
        if (args.profile != 'tcg-multi'
                or reference.sha256(host_admission.__file__) != reference.sha256(
                    args.source / relative / 'pr315_pve_host_admission.py')
                or reference.sha256(pressure_watch.__file__) != reference.sha256(
                    args.source / relative / 'pr315_pve_pressure_watch.py')):
            raise ValueError('pve-tcg-admission-source-or-profile-mismatch')
    os.umask(0o077)
    output = args.output.absolute()
    root = native_runner.storage_policy(args, output)
    for name in ('prepared_image', 'prepared_fixtures', 'qemu_root', 'seed', 'ssh_key', 'known_hosts'):
        if not getattr(args, name).resolve(strict=False).is_relative_to(root):
            raise ValueError('workload-input-outside-task-storage-budget')
    if campaign_plan_path is not None:
        campaign_plan_path = campaign_plan_path.absolute()
        if not campaign_plan_path.is_relative_to(root):
            raise ValueError('workload-campaign-plan-outside-task-root')
        info = campaign_plan_path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1
                or not 0 < info.st_size <= 16384):
            raise ValueError('workload-campaign-plan-file-invalid')
        frozen_campaign = native_runner.private_json(campaign_plan_path)
        campaign_seal._check_plan(frozen_campaign,
            subprocess.run(['git', '-C', str(args.source), 'rev-parse', 'HEAD'],
                check=True, capture_output=True, text=True,
                timeout=10).stdout.strip(), fingerprint)
        verify_campaign_runtime_inputs(args, frozen_campaign)
    if all(path is not None for path in retired_input_paths):
        for index, (path, limit) in enumerate(zip(retired_input_paths,
                                                   (8192, 8192, 512))):
            path = path.absolute()
            if (not path.is_relative_to(root)
                    or not path.resolve(strict=True).is_relative_to(
                        root.resolve(strict=True))):
                raise ValueError('workload-retired-authority-input-outside-task-root')
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_nlink != 1
                    or not 0 < info.st_size <= limit
                    or (index != 2
                        and info.st_mode & 0o077)):
                raise ValueError('workload-retired-authority-input-file-invalid')
        envelope = native_runner.private_json(retired_input_paths[1])
        raw_input = native_runner.private_json(retired_input_paths[0])
        retired_handoff = verified_retired_authority_input(frozen_campaign,
            envelope, retired_input_paths[2].read_bytes(), raw_input)
    else:
        retired_handoff = None
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
        retired_input_snapshot = None
        if retired_handoff is not None:
            retired_input_snapshot = output / 'retired-authority-input.private.json'
            descriptor = os.open(retired_input_snapshot,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(campaign_seal._canonical(raw_input))
            if (reference.sha256(retired_input_snapshot) !=
                    retired_handoff['privateInputDigest']):
                raise ValueError('workload-retired-authority-snapshot-changed')
        native_runner._save(output / 'plan.private.json', {
            'contract': acceptance.CONTRACT, 'profile': acceptance.PROFILE,
            'runtimePolicy': fixtures.preparation.launcher_policy(),
            'hostAdmissionPolicy': host_policy,
            'executionPurpose': ('retired-authority-preparation' if retired_preparation
                                 else 'startup-measurement' if getattr(args, 'startup_measurement', False)
                                 else 'role-readiness-measurement' if role_measurement
                                 else 'group-development' if group is not None else 'positive'),
            'selectedGroup': group, 'lifecycleScenario': scenario,
            'retiredAuthorityHandoffDigest': (
                campaign_seal._digest(retired_handoff)
                if retired_handoff is not None else None),
            'startupMeasurementCeilingSeconds': STARTUP_MEASUREMENT_SECONDS if getattr(args, 'startup_measurement', False) else None,
            'groups': [{'group': name, 'declaredCases': cases} for name, cases in groups()],
            'storageBudgetBytes': args.storage_budget_bytes, 'minimumFreeBytes': args.min_free_bytes,
            'memoryBudgetBytes': args.memory_budget_bytes, 'minimumHostMemoryBytes': args.min_host_memory_bytes,
            'guestMemoryBytes': GUEST_MEMORY, 'roleMemoryMaxBytes': ROLE_MEMORY,
            'roleSwapMaxBytes': 0, 'roleTasksMax': 512, 'roleTmpfsMaxBytes': ROLE_TMPFS,
            'roleTmpfsMaxInodes': 32768, 'tmpfsAccounting': 'allocated-pages-charge-memory',
            'cpuModel': reference.CPU_MODEL, 'accelerator': args.profile,
            'retention': 'all-attempts-private-no-automatic-deletion'})
        if (group is None and not getattr(args, 'startup_measurement', False)
                and not role_measurement
                and SUPPORTED_GROUPS != frozenset(name for name, _ in campaign.GROUPS)):
            result = public_result('implementation-incomplete',
                reasons=('full-campaign-emitter-unavailable',))
            result = prospective_campaign_result(result, frozen_campaign)
            native_runner._save(output / 'assessment.json', result)
            print(json.dumps(result, sort_keys=True))
            return 78
        if group is not None and group not in SUPPORTED_GROUPS and not getattr(args, 'probe', False):
            result = selected_public_result(group, 'group-emitter-unavailable',
                reasons=('group-emitter-unavailable',))
            result = prospective_campaign_result(result, frozen_campaign)
            native_runner._save(output / 'assessment.json', result)
            print(json.dumps(result, sort_keys=True))
            return 78
        if group in ('partial-launch', 'stuck-output', 'late-child',
                     'cleanup-race') and campaign_plan_path is None and not getattr(args, 'probe', False):
            result = selected_public_result(group, 'group-v10-plan-required',
                reasons=(group + '-v10-plan-required',))
            native_runner._save(output / 'assessment.json', result)
            print(json.dumps(result, sort_keys=True))
            return 78
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
        host_commit = None
        if host_policy == host_admission.POLICY:
            try:
                host_commit = subprocess.run(['git', '-C', str(args.source), 'rev-parse', 'HEAD'],
                    check=True, capture_output=True, text=True, timeout=10).stdout.strip()
                receipt = host_admission.verify_receipt(
                    root / 'host-admission' / (output.name + '.json'), output.name, host_commit)
                measured['pveHost'] = receipt['observation']
                if not getattr(args, 'probe', False):
                    watch_ready = pressure_watch.wait_ready(output.name, host_commit)
            except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError,
                    subprocess.SubprocessError):
                reasons.append('pve-host-admission-unavailable')
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
            selected_args = dict(vars(args))
            selected_args.update(attempt=output / 'attempt-01', mode='workload-positive',
                                 case_group=None, fault_case=None, lifecycle_scenario=scenario,
                                 retired_authority_input=retired_input_snapshot,
                                 retired_authority_input_digest=(
                                     retired_handoff['privateInputDigest']
                                     if retired_handoff is not None else None),
                                 workload_group=('role-readiness-diagnostic' if role_measurement
                                                 else group if selected_preparation or group == 'positive'
                                                 else None))
            selected = SimpleNamespace(**selected_args)
            with (output / 'transport.private.log').open('x') as log, redirect_stdout(log):
                reference.run(selected)
            if host_policy == host_admission.POLICY:
                until = time.monotonic() + 20
                while True:
                    try:
                        monitor = pressure_watch.verify_finished(output.name, host_commit, watch_ready)
                        native_runner._save(output / 'host-monitor.private.json', monitor)
                        break
                    except (OSError, ValueError):
                        if time.monotonic() >= until:
                            result, code = public_result('monitor-incomplete',
                                reasons=('pve-host-monitor-incomplete',)), 2
                            result = prospective_campaign_result(result, frozen_campaign)
                            native_runner._save(output / 'assessment.json', result)
                            print(json.dumps(result, sort_keys=True))
                            return code
                        time.sleep(.25)
            report = native_runner.private_json(selected.attempt / 'attempt.private.json')
            observation = selected.attempt / 'pr314-workload-observation.private.json'
            value = native_runner.private_json(observation) if observation.exists() and observation.stat().st_size else None
            terminal_path = selected.attempt / 'pr315-workload-volatile.private.json'
            terminal = (native_runner.private_json(terminal_path)
                        if terminal_path.exists() and terminal_path.stat().st_size else None)
            startup_measurement = getattr(args, 'startup_measurement', False)
            diagnostic_mode = startup_measurement or role_measurement
            positive = not diagnostic_mode and positive_executed(report, value, terminal)
            authority_views = (authority_epoch_views(report, value, terminal)
                if group == 'authority' and isinstance(terminal, dict)
                and terminal.get('stalePidUidAudit', {}).get('status') == 'captured'
                else None)
            group_ready = (not diagnostic_mode and selected_preparation
                           and (partial_launch_prepared(report, value, terminal)
                                if group == 'partial-launch' else
                                authority_views is not None
                                if group == 'authority' else
                                group_prepared(report, value, terminal, group)))
            role_boundary_ready = group == 'role-boundary' and group_ready
            authority_ready = group == 'authority' and group_ready
            authority_terminal = (authority_views[0]
                if authority_views is not None else terminal)
            network_app_ready = group == 'network-app' and group_ready
            diagnostic = selected.attempt / 'pr315-workload-memory.private.json'
            resources = (native_runner.private_json(diagnostic)
                         if diagnostic.exists() and diagnostic.stat().st_size else None)
            retired_proof = None
            if retired_preparation and report.get('guestExitCode') == 0:
                retained_path = selected.attempt / 'pr315-retired-authority.private.json'
                info = retained_path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or info.st_mode & 0o077 or info.st_nlink != 1
                        or not 0 < info.st_size <= 8192):
                    raise ValueError('workload-retired-authority-file-invalid')
                retired_proof = retired_authority_provenance(report, value,
                    terminal, native_runner.private_json(retained_path))
                if retired_proof is None:
                    raise ValueError('workload-retired-authority-proof-invalid')
                native_runner._save(output /
                    'retired-authority-v2-provenance.private.json', retired_proof)
            v10_raw_digests = None
            def save_v9_case(path, sidecar, case_id, *, identity=None,
                             case_attempt=None, roster=None):
                nonlocal v10_raw_digests
                native_runner._save(path, sidecar)
                if campaign_plan_path is None or case_id not in case_v10.GENERIC:
                    return
                if host_policy != host_admission.POLICY:
                    raise ValueError('workload-v10-host-policy-required')
                if v10_raw_digests is None:
                    v10_raw_digests = {
                        'guestReport': reference.sha256(
                            selected.attempt / 'attempt.private.json'),
                        'volatile': reference.sha256(terminal_path),
                        'hostMonitor': reference.sha256(
                            output / 'host-monitor.private.json')}
                record = case_v10.generic_case_record(frozen_campaign,
                    output.name, identity or frozen_campaign['identity'],
                    case_attempt, sidecar, args.source, v10_raw_digests,
                    roster=roster)
                native_runner._save(output /
                    (case_id + '-v10-evidence.private.json'), record)
            reached = (selected_probe_started(group, resources) if selected_preparation
                       else resources is not None)
            # A reached aggregate without per-case witnesses is inconclusive. An
            # installation failure is setup-failed; neither is an observed denial.
            statuses = ({case: 'inconclusive' if reached else 'setup-failed'
                         for case in selected_cases(group)}
                        if selected_preparation else
                        {case: 'inconclusive' if reached else 'setup-failed'
                         for case in groups()[0][1]})
            if group_ready:
                fixture = fixtures.verify(args.prepared_fixtures, args.fixture_manifest_digest,
                    args.source, args.product_source_commit)
                host = report['hostVerifiedIdentity']
                checked = reference.verified_attempt_identity(report, selected.attempt,
                    host['bundleIdentity'], host['testKitDigest'])
                if checked != host:
                    raise ValueError('workload-group-host-identity-changed')
            if (group in ('lost-start-response', 'cancellation', 'controller-restart', 'deadline',
                          'revocation-running', 'setsid-double-fork',
                          'observer-death') and group_ready
                    and isinstance(terminal, dict)):
                lifecycle = _lifecycle_group_attempt(group, report, value, fixture,
                                                     resources, terminal, args.source)
                if lifecycle is None:
                    raise ValueError('workload-lifecycle-group-verification-failed')
                identity, case_attempt, sidecar = lifecycle
                checked_cases = acceptance.verify_attempts(identity, [case_attempt])
                if (checked_cases['recordContractValid'] is not True
                        or next(row['status'] for row in checked_cases['cases']
                                if row['caseId'] == group) != 'passed'
                        or checked_cases['installedWorkloadAcceptanceSatisfied'] is not False):
                    raise ValueError('workload-lifecycle-group-case-invalid')
                native_runner._save(output / (group + '-v8-evidence.private.json'),
                    {'attempt': case_attempt, 'assessment': checked_cases})
                save_v9_case(output / (group + '-v9-evidence.private.json'),
                    sidecar, group, identity=identity, case_attempt=case_attempt)
                statuses[group] = 'passed'
            if group == 'partial-launch' and group_ready:
                if host_policy != host_admission.POLICY:
                    raise ValueError('workload-partial-launch-host-policy-required')
                raw_digests = {
                    'guestReport': reference.sha256(selected.attempt / 'attempt.private.json'),
                    'volatile': reference.sha256(terminal_path),
                    'hostMonitor': reference.sha256(output / 'host-monitor.private.json')}
                record = _partial_launch_record(frozen_campaign, output.name,
                    report, value, terminal, resources, args.source, raw_digests)
                if record is None:
                    raise ValueError('workload-partial-launch-verification-failed')
                native_runner._save(output / 'partial-launch-v10-evidence.private.json', record)
                statuses['partial-launch'] = 'passed'
            if group == 'stuck-output' and group_ready:
                if host_policy != host_admission.POLICY:
                    raise ValueError('workload-stuck-output-host-policy-required')
                raw_digests = {
                    'guestReport': reference.sha256(selected.attempt / 'attempt.private.json'),
                    'volatile': reference.sha256(terminal_path),
                    'hostMonitor': reference.sha256(output / 'host-monitor.private.json')}
                record = _stuck_output_record(frozen_campaign, output.name,
                    report, value, terminal, resources, args.source, raw_digests)
                if record is None:
                    raise ValueError('workload-stuck-output-verification-failed')
                native_runner._save(output / 'stuck-output-v10-evidence.private.json', record)
                statuses['stuck-output'] = 'passed'
            if group == 'late-child' and group_ready:
                if host_policy != host_admission.POLICY:
                    raise ValueError('workload-late-child-host-policy-required')
                raw_digests = {
                    'guestReport': reference.sha256(selected.attempt / 'attempt.private.json'),
                    'volatile': reference.sha256(terminal_path),
                    'hostMonitor': reference.sha256(output / 'host-monitor.private.json')}
                record = _late_child_record(frozen_campaign, output.name,
                    report, value, terminal, resources, args.source, raw_digests)
                if record is None:
                    raise ValueError('workload-late-child-verification-failed')
                native_runner._save(output / 'late-child-v10-evidence.private.json', record)
                statuses['late-child'] = 'passed'
            if group == 'cleanup-race' and group_ready:
                case = cleanup_race_attempt(report, value, terminal,
                    resources, args.source)
                if case is None:
                    raise ValueError('workload-cleanup-race-verification-failed')
                save_v9_case(output / 'cleanup-race-v9-evidence.private.json',
                    case, 'cleanup-race', roster=value['roleKernelRoster'])
                statuses['cleanup-race'] = 'passed'
            if positive and not output_group:
                host_started = time.monotonic_ns()
                fixture = fixtures.verify(args.prepared_fixtures, args.fixture_manifest_digest,
                    args.source, args.product_source_commit)
                host = report['hostVerifiedIdentity']
                checked = reference.verified_attempt_identity(report, selected.attempt,
                    host['bundleIdentity'], host['testKitDigest'])
                host_finished = time.monotonic_ns()
                if checked != host:
                    raise ValueError('workload-host-identity-changed')
                identity, case_attempt = positive_case_attempt(
                    report, value, fixture, host_started, host_finished, resources, terminal)
                checked_cases = acceptance.verify_attempts(identity, [case_attempt])
                expected = set(case_attempt['declaredCases'])
                if isinstance(resources, dict) and 'cancellation' in resources:
                    statuses['cancellation'] = 'inconclusive'
                if isinstance(resources, dict) and 'controllerRestart' in resources:
                    statuses['controller-restart'] = 'inconclusive'
                passed = {row['caseId'] for row in checked_cases['cases'] if row['status'] == 'passed'}
                if (not {'installed-ready', 'four-role-start'} <= expected
                        or checked_cases['recordContractValid'] is not True or passed != expected
                        or checked_cases['installedWorkloadAcceptanceSatisfied'] is not False):
                    raise ValueError('workload-positive-case-verification-failed')
                native_runner._save(output / 'positive-v8-evidence.private.json',
                    {'attempt': case_attempt, 'assessment': checked_cases})
                if group == 'positive' and campaign_plan_path is not None:
                    if host_policy != host_admission.POLICY:
                        raise ValueError('workload-v10-host-policy-required')
                    raw_digests = {
                        'guestReport': reference.sha256(selected.attempt / 'attempt.private.json'),
                        'volatile': reference.sha256(terminal_path),
                        'hostMonitor': reference.sha256(output / 'host-monitor.private.json')}
                    records = case_v10.positive_records(frozen_campaign,
                        output.name, identity, case_attempt, report, value,
                        terminal, resources, _host_runner_epoch(),
                        args.source, raw_digests)
                    for case_id, record in records.items():
                        native_runner._save(output /
                            (case_id + '-v10-evidence.private.json'), record)
                statuses.update({case: 'passed' for case in expected})
            if (network_app_ready and isinstance(terminal, dict)
                    and terminal.get('probeKernelCheckpoint', {}).get('status') == 'captured'):
                fixture = fixtures.verify(args.prepared_fixtures, args.fixture_manifest_digest,
                    args.source, args.product_source_commit)
                host = report.get('hostVerifiedIdentity')
                if not isinstance(host, dict):
                    raise ValueError('workload-denial-host-identity-unavailable')
                checked = reference.verified_attempt_identity(report, selected.attempt,
                    host['bundleIdentity'], host['testKitDigest'])
                if checked != host:
                    raise ValueError('workload-denial-host-identity-changed')
                denial = probe_denial_attempt(report, fixture, terminal)
                if denial is not None:
                    identity, case_attempt = denial
                    checked_cases = acceptance.verify_attempts(identity, [case_attempt])
                    if (checked_cases['recordContractValid'] is not True
                            or next(row['status'] for row in checked_cases['cases']
                                    if row['caseId'] == 'namespace-mount-escape') != 'passed'
                            or checked_cases['installedWorkloadAcceptanceSatisfied'] is not False):
                        raise ValueError('workload-denial-case-verification-failed')
                    native_runner._save(output / 'denial-v8-evidence.private.json',
                        {'attempt': case_attempt, 'assessment': checked_cases})
                    if campaign_plan_path is not None:
                        sidecar = _v10_legacy_sidecar('namespace-mount-escape',
                            report, fixture, terminal, resources, identity, case_attempt)
                        if sidecar is None:
                            raise ValueError('workload-namespace-v10-epoch-unavailable')
                        save_v9_case(output / 'namespace-mount-escape-v9-evidence.private.json',
                            sidecar, 'namespace-mount-escape', identity=identity,
                            case_attempt=case_attempt)
                    statuses['namespace-mount-escape'] = 'passed'
            if (authority_ready and isinstance(terminal, dict)
                    and terminal.get('observerControlCheckpoint', {}).get('status') == 'captured'):
                fixture = fixtures.verify(args.prepared_fixtures, args.fixture_manifest_digest,
                    args.source, args.product_source_commit)
                host = report.get('hostVerifiedIdentity')
                if not isinstance(host, dict):
                    raise ValueError('workload-observer-control-host-identity-unavailable')
                checked = reference.verified_attempt_identity(report, selected.attempt,
                    host['bundleIdentity'], host['testKitDigest'])
                if checked != host:
                    raise ValueError('workload-observer-control-host-identity-changed')
                denial = observer_control_denial_attempt(report, fixture,
                    authority_terminal)
                if denial is not None:
                    identity, case_attempt = denial
                    checked_cases = acceptance.verify_attempts(identity, [case_attempt])
                    if (checked_cases['recordContractValid'] is not True
                            or next(row['status'] for row in checked_cases['cases']
                                    if row['caseId'] == 'observer-control') != 'passed'
                            or checked_cases['installedWorkloadAcceptanceSatisfied'] is not False):
                        raise ValueError('workload-observer-control-verification-failed')
                    native_runner._save(output / 'observer-control-v8-evidence.private.json',
                        {'attempt': case_attempt, 'assessment': checked_cases})
                    if campaign_plan_path is not None:
                        sidecar = _v10_legacy_sidecar('observer-control',
                            report, fixture, authority_terminal, resources,
                            identity, case_attempt)
                        if sidecar is None:
                            raise ValueError('workload-observer-control-v10-epoch-unavailable')
                        save_v9_case(output / 'observer-control-v9-evidence.private.json',
                            sidecar, 'observer-control', identity=identity,
                            case_attempt=case_attempt)
                    statuses['observer-control'] = 'passed'
            if (authority_ready and isinstance(terminal, dict)
                    and terminal.get('arbitraryEndpointCheckpoint', {}).get('status') == 'captured'
                    and terminal.get('arbitraryEndpointAudit', {}).get('status') == 'captured'):
                denial = arbitrary_endpoint_denial_attempt(report, value,
                    fixture, authority_terminal)
                if denial is None:
                    raise ValueError('workload-arbitrary-endpoint-verification-failed')
                identity, case_attempt, sidecar = denial
                checked_cases = acceptance.verify_attempts(identity, [case_attempt])
                if (checked_cases['recordContractValid'] is not True
                        or next(row['status'] for row in checked_cases['cases']
                                if row['caseId'] == 'arbitrary-endpoint') != 'passed'
                        or checked_cases['installedWorkloadAcceptanceSatisfied'] is not False):
                    raise ValueError('workload-arbitrary-endpoint-case-invalid')
                native_runner._save(output / 'arbitrary-endpoint-v8-evidence.private.json',
                    {'attempt': case_attempt, 'assessment': checked_cases})
                if campaign_plan_path is not None:
                    sidecar = _v10_legacy_sidecar('arbitrary-endpoint',
                        report, fixture, authority_terminal, resources,
                        identity, case_attempt)
                    if sidecar is None:
                        raise ValueError('workload-arbitrary-endpoint-v10-epoch-unavailable')
                save_v9_case(output / 'arbitrary-endpoint-v9-evidence.private.json',
                    sidecar, 'arbitrary-endpoint', identity=identity,
                    case_attempt=case_attempt)
                statuses['arbitrary-endpoint'] = 'passed'
            if (authority_ready and isinstance(terminal, dict)
                    and terminal.get('runnerControlAudit', {}).get('status') == 'captured'):
                denial = runner_control_denial_attempt(report, value, fixture,
                    authority_terminal)
                if denial is not None:
                    identity, case_attempt = denial
                    checked_cases = acceptance.verify_attempts(identity, [case_attempt])
                    if (checked_cases['recordContractValid'] is not True
                            or next(row['status'] for row in checked_cases['cases']
                                    if row['caseId'] == 'runner-control') != 'passed'
                            or checked_cases['installedWorkloadAcceptanceSatisfied'] is not False):
                        raise ValueError('workload-runner-control-verification-failed')
                    native_runner._save(output / 'runner-control-v8-evidence.private.json',
                        {'attempt': case_attempt, 'assessment': checked_cases})
                    if campaign_plan_path is not None:
                        sidecar = _v10_legacy_sidecar('runner-control',
                            report, fixture, authority_terminal, resources,
                            identity, case_attempt)
                        if sidecar is None:
                            raise ValueError('workload-runner-control-v10-epoch-unavailable')
                        save_v9_case(output / 'runner-control-v9-evidence.private.json',
                            sidecar, 'runner-control', identity=identity,
                            case_attempt=case_attempt)
                    statuses['runner-control'] = 'passed'
            if (role_boundary_ready and isinstance(terminal, dict)
                    and terminal.get('observerPrivateReadAudit', {}).get('status') == 'captured'):
                case = observer_private_read_attempt(report, value, fixture, terminal, args.source)
                if case is None:
                    raise ValueError('workload-observer-private-read-verification-failed')
                save_v9_case(output / 'observer-private-read-v9-evidence.private.json',
                    case, 'observer-private-read', roster=value['roleKernelRoster'])
                statuses['observer-private-read'] = 'passed'
            if (role_boundary_ready and isinstance(terminal, dict)
                    and terminal.get('observerPrivateWriteAudit', {}).get('status') == 'captured'):
                case = observer_private_write_attempt(report, value, fixture, terminal, args.source)
                if case is None:
                    raise ValueError('workload-observer-private-write-verification-failed')
                save_v9_case(output / 'observer-private-write-v9-evidence.private.json',
                    case, 'observer-private-write', roster=value['roleKernelRoster'])
                statuses['observer-private-write'] = 'passed'
            for case_id, field in (('forged-runtime-identity', 'forgedRuntimeIdentityAudit'),
                                   ('forged-counters', 'forgedCountersAudit')):
                if (authority_ready and isinstance(terminal, dict)
                        and terminal.get(field, {}).get('status') == 'captured'):
                    case = _fixed_claim_attempt(case_id, report, value, fixture,
                        authority_terminal, args.source)
                    if case is None:
                        raise ValueError('workload-fixed-claim-verification-failed')
                    save_v9_case(output / (case_id + '-v9-evidence.private.json'),
                        case, case_id, roster=value['roleKernelRoster'])
                    statuses[case_id] = 'passed'
            for case_id, field in (('sibling-data', 'siblingDataAudit'),
                                   ('package-expectation', 'packageExpectationAudit'),
                                   ('cgroup-migration', 'cgroupMigrationAudit')):
                if (role_boundary_ready and isinstance(terminal, dict)
                        and terminal.get(field, {}).get('status') == 'captured'):
                    case = _fixed_role_access_attempt(
                        case_id, report, value, fixture, terminal, args.source)
                    if case is None:
                        raise ValueError('workload-fixed-role-access-verification-failed')
                    save_v9_case(output / (case_id + '-v9-evidence.private.json'),
                        case, case_id, roster=value['roleKernelRoster'])
                    statuses[case_id] = 'passed'
            if (network_app_ready and isinstance(terminal, dict)
                    and terminal.get('providerAuthorityAudit', {}).get('status') == 'captured'
                    and terminal.get('providerAppResult', {}).get('status') == 'captured'):
                denial = _provider_authority_attempt(report, value, fixture, terminal)
                if denial is None:
                    raise ValueError('workload-provider-authority-verification-failed')
                identity, case_attempt, sidecar = denial
                checked_cases = acceptance.verify_attempts(identity, [case_attempt])
                if (checked_cases['recordContractValid'] is not True
                        or next(row['status'] for row in checked_cases['cases']
                                if row['caseId'] == 'provider-authority') != 'passed'
                        or checked_cases['installedWorkloadAcceptanceSatisfied'] is not False):
                    raise ValueError('workload-provider-authority-case-invalid')
                native_runner._save(output / 'provider-authority-v8-evidence.private.json',
                    {'attempt': case_attempt, 'assessment': checked_cases})
                save_v9_case(output / 'provider-authority-v9-evidence.private.json',
                    sidecar, 'provider-authority', identity=identity,
                    case_attempt=case_attempt)
                statuses['provider-authority'] = 'passed'
            if (network_app_ready and isinstance(terminal, dict)
                    and terminal.get('siblingAppAudit', {}).get('status') == 'captured'
                    and terminal.get('siblingAppResult', {}).get('status') == 'captured'):
                denial = _sibling_app_attempt(report, value, fixture, terminal)
                if denial is None:
                    raise ValueError('workload-sibling-app-verification-failed')
                identity, case_attempt, sidecar = denial
                checked_cases = acceptance.verify_attempts(identity, [case_attempt])
                if (checked_cases['recordContractValid'] is not True
                        or next(row['status'] for row in checked_cases['cases']
                                if row['caseId'] == 'sibling-app') != 'passed'
                        or checked_cases['installedWorkloadAcceptanceSatisfied'] is not False):
                    raise ValueError('workload-sibling-app-case-invalid')
                native_runner._save(output / 'sibling-app-v8-evidence.private.json',
                    {'attempt': case_attempt, 'assessment': checked_cases})
                save_v9_case(output / 'sibling-app-v9-evidence.private.json',
                    sidecar, 'sibling-app', identity=identity,
                    case_attempt=case_attempt)
                statuses['sibling-app'] = 'passed'
            if (group == 'resource-exhaustion' and group_ready
                    and isinstance(terminal, dict)):
                children_path = (selected.attempt /
                    'pr315-resource-children.private.json')
                child_file = children_path.lstat()
                if (not stat.S_ISREG(child_file.st_mode)
                        or child_file.st_uid != os.geteuid()
                        or child_file.st_mode & 0o077
                        or child_file.st_nlink != 1
                        or not 0 < child_file.st_size <= 131072):
                    raise ValueError('workload-resource-children-file-invalid')
                children = native_runner.private_json(children_path)
                denial = _resource_exhaustion_attempt(
                    report, value, fixture, terminal, resources, children)
                if denial is None:
                    raise ValueError('workload-resource-exhaustion-verification-failed')
                identity, case_attempt, sidecar = denial
                checked_cases = acceptance.verify_attempts(identity, [case_attempt])
                if (checked_cases['recordContractValid'] is not True
                        or next(row['status'] for row in checked_cases['cases']
                                if row['caseId'] == group) != 'passed'
                        or checked_cases['installedWorkloadAcceptanceSatisfied'] is not False):
                    raise ValueError('workload-resource-exhaustion-case-invalid')
                native_runner._save(output / (group + '-v8-evidence.private.json'),
                    {'attempt': case_attempt, 'assessment': checked_cases})
                save_v9_case(output / (group + '-v9-evidence.private.json'),
                    sidecar, group, identity=identity, case_attempt=case_attempt)
                statuses[group] = 'passed'
            for case_id, field in (('sibling-fcp', 'siblingFcpAudit'),
                                   ('sibling-http', 'siblingHttpAudit')):
                if (network_app_ready and isinstance(terminal, dict)
                        and terminal.get(field, {}).get('status') == 'captured'):
                    denial = _sibling_network_attempt(
                        case_id, report, value, fixture, terminal, args.source)
                    if denial is None:
                        raise ValueError('workload-sibling-network-verification-failed')
                    identity, case_attempt, sidecar = denial
                    checked_cases = acceptance.verify_attempts(identity, [case_attempt])
                    if (checked_cases['recordContractValid'] is not True
                            or next(row['status'] for row in checked_cases['cases']
                                    if row['caseId'] == case_id) != 'passed'
                            or checked_cases['installedWorkloadAcceptanceSatisfied'] is not False):
                        raise ValueError('workload-sibling-network-case-invalid')
                    native_runner._save(output / (case_id + '-v8-evidence.private.json'),
                        {'attempt': case_attempt, 'assessment': checked_cases})
                    save_v9_case(output / (case_id + '-v9-evidence.private.json'),
                        sidecar, case_id, identity=identity,
                        case_attempt=case_attempt)
                    statuses[case_id] = 'passed'
            if (network_app_ready and isinstance(terminal, dict)
                    and terminal.get('hostNetworkAudit', {}).get('status') == 'captured'):
                denial = _host_network_attempt(
                    report, value, fixture, terminal, args.source)
                if denial is None:
                    raise ValueError('workload-host-network-verification-failed')
                identity, case_attempt, sidecar = denial
                checked_cases = acceptance.verify_attempts(identity, [case_attempt])
                if (checked_cases['recordContractValid'] is not True
                        or next(row['status'] for row in checked_cases['cases']
                                if row['caseId'] == 'host-network') != 'passed'
                        or checked_cases['installedWorkloadAcceptanceSatisfied'] is not False):
                    raise ValueError('workload-host-network-case-invalid')
                native_runner._save(output / 'host-network-v8-evidence.private.json',
                    {'attempt': case_attempt, 'assessment': checked_cases})
                save_v9_case(output / 'host-network-v9-evidence.private.json',
                    sidecar, 'host-network', identity=identity,
                    case_attempt=case_attempt)
                statuses['host-network'] = 'passed'
            if (authority_ready and isinstance(terminal, dict)
                    and terminal.get('resolverAuthorityAudit', {}).get('status') == 'captured'):
                denial = _resolver_authority_attempt(
                    report, value, fixture, authority_terminal, args.source)
                if denial is None:
                    raise ValueError('workload-resolver-authority-verification-failed')
                identity, case_attempt, sidecar = denial
                checked_cases = acceptance.verify_attempts(identity, [case_attempt])
                if (checked_cases['recordContractValid'] is not True
                        or next(row['status'] for row in checked_cases['cases']
                                if row['caseId'] == 'resolver-authority') != 'passed'
                        or checked_cases['installedWorkloadAcceptanceSatisfied'] is not False):
                    raise ValueError('workload-resolver-authority-case-invalid')
                native_runner._save(output / 'resolver-authority-v8-evidence.private.json',
                    {'attempt': case_attempt, 'assessment': checked_cases})
                save_v9_case(output / 'resolver-authority-v9-evidence.private.json',
                    sidecar, 'resolver-authority', identity=identity,
                    case_attempt=case_attempt)
                statuses['resolver-authority'] = 'passed'
            if authority_ready and retired_handoff is not None:
                if (not isinstance(terminal, dict)
                        or terminal.get('staleHandleAudit', {}).get('status') !=
                            'captured'):
                    raise ValueError('workload-stale-handle-audit-unavailable')
                case = stale_handle_attempt(report, value, authority_terminal,
                    resources, retired_handoff, raw_input, args.source)
                if case is None:
                    raise ValueError('workload-stale-handle-verification-failed')
                save_v9_case(output / 'stale-handle-v9-evidence.private.json',
                    case, 'stale-handle', roster=value['roleKernelRoster'])
                statuses['stale-handle'] = 'passed'
            if authority_ready:
                case = stale_pid_uid_attempt(report, value, terminal,
                    resources, args.source)
                if case is None:
                    raise ValueError('workload-stale-pid-uid-verification-failed')
                save_v9_case(output / 'stale-pid-uid-v9-evidence.private.json',
                    case, 'stale-pid-uid', roster=value['roleKernelRoster'])
                statuses['stale-pid-uid'] = 'passed'
            if (authority_ready and isinstance(terminal, dict)
                    and terminal.get('hostileAppOriginAudit', {}).get('status') == 'captured'):
                denial = _hostile_origin_attempt(
                    report, value, fixture, authority_terminal,
                    args.source, resources)
                if denial is None:
                    raise ValueError('workload-hostile-origin-verification-failed')
                identity, case_attempt, sidecar = denial
                checked_cases = acceptance.verify_attempts(identity, [case_attempt])
                if (checked_cases['recordContractValid'] is not True
                        or next(row['status'] for row in checked_cases['cases']
                                if row['caseId'] == 'hostile-app-origin') != 'passed'
                        or checked_cases['installedWorkloadAcceptanceSatisfied'] is not False):
                    raise ValueError('workload-hostile-origin-case-invalid')
                native_runner._save(output / 'hostile-app-origin-v8-evidence.private.json',
                    {'attempt': case_attempt, 'assessment': checked_cases})
                save_v9_case(output / 'hostile-app-origin-v9-evidence.private.json',
                    sidecar, 'hostile-app-origin', identity=identity,
                    case_attempt=case_attempt)
                statuses['hostile-app-origin'] = 'passed'
            if (output_group and group_ready and isinstance(terminal, dict)
                    and terminal.get({'output-symlink': 'outputSymlinkAudit',
                                      'output-fifo': 'outputFifoAudit',
                                      'output-hardlink': 'outputHardlinkAudit',
                                      'output-flood': 'outputFloodAudit',
                                      'output-replacement': 'outputReplacementAudit'}[group],
                                     {}).get('status') == 'captured'):
                denial = _output_artifact_attempt(report, value, fixture, terminal,
                                                  args.source, group)
                if denial is None:
                    raise ValueError('workload-output-artifact-verification-failed')
                identity, case_attempt, sidecar = denial
                checked_cases = acceptance.verify_attempts(identity, [case_attempt])
                if (checked_cases['recordContractValid'] is not True
                        or next(row['status'] for row in checked_cases['cases']
                                if row['caseId'] == group) != 'passed'
                        or checked_cases['installedWorkloadAcceptanceSatisfied'] is not False):
                    raise ValueError('workload-output-artifact-case-invalid')
                native_runner._save(output / (group + '-v8-evidence.private.json'),
                    {'attempt': case_attempt, 'assessment': checked_cases})
                save_v9_case(output / (group + '-v9-evidence.private.json'),
                    sidecar, group, identity=identity, case_attempt=case_attempt)
                if group == 'output-symlink' and campaign_plan_path is not None:
                    if host_policy != host_admission.POLICY:
                        raise ValueError('workload-v10-host-policy-required')
                    raw_digests = {
                        'guestReport': reference.sha256(selected.attempt / 'attempt.private.json'),
                        'volatile': reference.sha256(terminal_path),
                        'hostMonitor': reference.sha256(output / 'host-monitor.private.json')}
                    v10 = case_v10.output_symlink_record(frozen_campaign,
                        output.name, identity, case_attempt, sidecar, raw_digests)
                    native_runner._save(output / 'output-symlink-v10-evidence.private.json', v10)
                statuses[group] = 'passed'
            if diagnostic_mode:
                statuses = None  # No workload case was invoked by this diagnostic.
            result, code = selected_public_result(group,
                ('retired-authority-preparation-executed' if retired_preparation
                    and retired_proof is not None else
                 'role-readiness-measurement-executed' if role_measurement
                    and group_prepared(report, value, terminal, 'role-readiness-diagnostic') else
                    'implementation-incomplete' if group_ready and
                    all(statuses.get(case) == 'passed' for case in selected_cases(group)) else
                    selected_terminal_status(group, report, positive)), positive,
                statuses=statuses,
                reasons=(('startup-measurement-not-workload-execution',)
                         if startup_measurement else
                         ('role-readiness-measurement-not-workload-execution',)
                         if role_measurement else ())), 2
        result = prospective_campaign_result(result, frozen_campaign)
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
    parser.add_argument('--role-readiness-measurement', action='store_true',
        help='Observe four real role FCP readiness operations without workload case credit.')
    parser.add_argument('--retired-authority-preparation', action='store_true',
        help='Retain a private stopped prior handle for a separately sealed successor guest.')
    parser.add_argument('--lifecycle-scenario', choices=LIFECYCLE_SCENARIOS,
                        default='cancellation')
    parser.add_argument('--case-group', choices=tuple(name for name, _ in campaign.GROUPS),
                        help='Development run restricted to one predeclared 45-case group.')
    for name in ('source', 'output', 'prepared-image', 'qemu-root', 'seed', 'ssh-key', 'known-hosts',
                 'prepared-fixtures', 'storage-root'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('product-source-commit', 'prepared-image-digest', 'fixture-manifest-digest'):
        parser.add_argument('--' + name)
    for name in ('storage-budget-bytes', 'min-free-bytes', 'memory-budget-bytes', 'min-host-memory-bytes'):
        parser.add_argument('--' + name, required=True, type=int)
    parser.add_argument('--profile', choices=tuple(reference.PROFILES), required=True)
    parser.add_argument('--host-memory-policy',
                        choices=('legacy-physical-admission', host_admission.POLICY),
                        default='legacy-physical-admission')
    parser.add_argument('--port', type=int, default=23112)
    parser.add_argument('--timeout', type=int, default=3600)
    parser.add_argument('--development-snapshot', action='store_true')
    parser.add_argument('--host-key-pin-origin', required=True,
        choices=('preselected-host-key', 'administrator-preparation-tofu'))
    parser.add_argument('--campaign-plan', type=Path,
        help='Pinned private v2 campaign plan for prospective installed case records.')
    parser.add_argument('--campaign-key-fingerprint',
        help='Host-pinned Ed25519 public key fingerprint for the campaign plan.')
    parser.add_argument('--retired-authority-input', type=Path,
        help='Private old authority input from the stopped preparation guest.')
    parser.add_argument('--retired-authority-handoff', type=Path,
        help='Mac-sealed proof binding the old authority input and stop/archive receipts.')
    parser.add_argument('--campaign-public-key', type=Path,
        help='Frozen Mac campaign public key, used only to authenticate the handoff.')
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
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        code = str(error) if str(error) in {
            'workload-lifecycle-group-verification-failed',
            'workload-lifecycle-group-case-invalid',
            'workload-stuck-output-verification-failed',
            'workload-stuck-output-host-policy-required',
            'workload-cleanup-race-verification-failed',
            'pr315-v10-generic-lifecycle-target-invalid',
            'workload-group-host-identity-changed'} else None
        print(json.dumps({'kind': 'pr315-private-host-assessment-failure',
            'exceptionType': type(error).__name__[:128], 'privateErrorCode': code,
            'classification': 'private-diagnostic-not-acceptance'}), file=sys.stderr)
        print(json.dumps(public_result('setup-or-execution-failed')))
        exit_code = 2
    raise SystemExit(exit_code)
