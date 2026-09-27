#!/usr/bin/env python3
"""Mac-owned sealed PR-315 archive verification and complete campaign verdict.

This module authenticates only receipts produced by the live host coordinator.
An imported JSON record, synthetic fixture, or partial group never grants
installed acceptance on its own.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

import pr314_acceptance as acceptance
import pr315_campaign_seal as seal
import pr315_case_v10 as cases
import pr315_case_registry as registry
import pr315_workload_campaign as groups
import pr315_workload_runner as runner

_NAME = re.compile(r'[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*\Z')
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_MANDATORY = ('assessment.json', 'attempt-01/attempt.private.json',
    'attempt-01/pr314-workload-observation.private.json',
    'attempt-01/pr315-workload-volatile.private.json',
    'attempt-01/pr315-workload-memory.private.json',
    'host-monitor.private.json', 'host-stop.private.json')
_RECONSTRUCTIBLE = ('attempt-01/cryptad', 'attempt-01/expected-bundle',
    'attempt-01/boot-runtime', 'attempt-01/tools')
_DISKS = ('attempt-01/guest.qcow2', 'attempt-01/prepared.qcow2')


def _read(root: Path, relative: str, limit=1024 * 1024):
    if not isinstance(relative, str) or _NAME.fullmatch(relative) is None:
        raise ValueError('pr315-owner-relative-path-invalid')
    current = root
    for name in relative.split('/')[:-1]:
        current = current / name
        info = current.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077):
            raise ValueError('pr315-owner-directory-invalid')
    path = root / relative
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077
                or not 0 <= info.st_size <= limit):
            raise ValueError('pr315-owner-file-invalid')
        raw = bytearray()
        while len(raw) < info.st_size:
            block = os.read(descriptor, min(1024 * 1024, info.st_size - len(raw)))
            if not block:
                raise ValueError('pr315-owner-file-short-read')
            raw.extend(block)
        if os.fstat(descriptor).st_size != info.st_size:
            raise ValueError('pr315-owner-file-changed')
        return bytes(raw)
    finally:
        os.close(descriptor)


def _json(root, relative, limit=1024 * 1024):
    return json.loads(_read(root, relative, limit))


def tracked_byte_digest(source_root):
    """Independently hash tracked working bytes, including Git-tracked links."""
    source_root = Path(source_root).resolve(strict=True)
    listed = subprocess.run(['git', '-C', str(source_root),
        'ls-files', '-z'], check=True, capture_output=True,
        timeout=20).stdout.split(b'\0')
    selected = [os.fsdecode(name) for name in listed if name]
    if not selected or len(selected) > 100000 or len(selected) != len(set(selected)):
        raise ValueError('pr315-owner-tracked-roster-invalid')
    checksum = hashlib.sha256()
    for relative in sorted(selected):
        path = source_root / relative
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raw = os.fsencode(os.readlink(path))
            kind = b'link'
        elif stat.S_ISREG(info.st_mode):
            kind = b'file'
            raw = path.read_bytes()
            if len(raw) != info.st_size or len(raw) > 512 * 1024 * 1024:
                raise ValueError('pr315-owner-tracked-file-changed')
        else:
            raise ValueError('pr315-owner-tracked-type-invalid')
        after = path.lstat()
        if (info.st_dev, info.st_ino, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('pr315-owner-tracked-bytes-raced')
        checksum.update(os.fsencode(relative) + b'\0' + kind + b'\0'
                        + str(len(raw)).encode() + b'\0' + raw)
    return checksum.hexdigest()


def _hash_file(root, relative, limit):
    if not isinstance(relative, str) or _NAME.fullmatch(relative) is None:
        raise ValueError('pr315-owner-relative-path-invalid')
    current = root
    for name in relative.split('/')[:-1]:
        current = current / name
        info = current.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077):
            raise ValueError('pr315-owner-directory-invalid')
    descriptor = os.open(root / relative,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077
                or not 0 <= info.st_size <= limit):
            raise ValueError('pr315-owner-file-invalid')
        checksum = hashlib.sha256()
        remaining = info.st_size
        while remaining:
            block = os.read(descriptor, min(4 * 1024 * 1024, remaining))
            if not block:
                raise ValueError('pr315-owner-file-short-read')
            checksum.update(block)
            remaining -= len(block)
        after = os.fstat(descriptor)
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                info.st_ctime_ns) != (after.st_dev, after.st_ino,
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('pr315-owner-file-changed')
        return checksum.hexdigest(), info.st_size
    finally:
        os.close(descriptor)


def _archive_manifest(archive: Path, campaign: dict, receipt: dict):
    manifest = _json(archive, 'archive.private.json', 1024 * 1024)
    if (not isinstance(manifest, dict) or set(manifest) != {
            'schemaVersion', 'kind', 'planDigest', 'campaignNonce',
            'groupId', 'attemptId', 'sourceCommit', 'files',
            'copyVerified', 'excludedReconstructible', 'guestStopped'}
            or manifest['schemaVersion'] != 1
            or manifest['kind'] != 'pr315-mac-private-archive-v1'
            or manifest['planDigest'] != campaign['planDigest']
            or manifest['campaignNonce'] != campaign['campaignNonce']
            or manifest['groupId'] != receipt['groupId']
            or manifest['attemptId'] != receipt['attemptId']
            or manifest['sourceCommit'] != receipt['sourceCommit']
            or manifest['copyVerified'] is not True
            or manifest['guestStopped'] is not True
            or manifest['excludedReconstructible'] != list(_RECONSTRUCTIBLE) + (
                [] if set(_DISKS) <= set(manifest['files']) else list(_DISKS))
            or seal._digest(manifest) != receipt['archiveDigest']
            or not isinstance(manifest['files'], dict)
            or len(manifest['files']) > 256
            or len(set(_DISKS) & set(manifest['files'])) == 1
            or not set(_MANDATORY) <= set(manifest['files'])):
        raise ValueError('pr315-owner-archive-manifest-invalid')
    expected = set(manifest['files'])
    actual = set()
    for directory, directories, files in os.walk(archive, followlinks=False):
        base = Path(directory)
        if any((base / name).is_symlink() for name in (*directories, *files)):
            raise ValueError('pr315-owner-archive-link-invalid')
        for name in files:
            path = base / name
            relative = path.relative_to(archive).as_posix()
            if relative != 'archive.private.json':
                actual.add(relative)
    if actual != expected:
        raise ValueError('pr315-owner-archive-file-set-changed')
    for relative, metadata in manifest['files'].items():
        if (not isinstance(metadata, dict)
                or set(metadata) != {'sha256', 'sizeBytes'}
                or _HEX.fullmatch(str(metadata['sha256'])) is None
                or type(metadata['sizeBytes']) is not int
                or not 0 <= metadata['sizeBytes'] <= 512 * 1024 * 1024):
            raise ValueError('pr315-owner-archive-file-metadata-invalid')
        checked, size = _hash_file(archive, relative, 512 * 1024 * 1024)
        if (size != metadata['sizeBytes']
                or checked != metadata['sha256']):
            raise ValueError('pr315-owner-archive-file-digest-changed')
    return manifest


def create_archive_manifest(archive, campaign, group_id, attempt_id,
                            rsync_verification):
    """Record an exact Mac copy only after rsync reports no changed paths."""
    archive = seal._private_directory(archive)
    if (group_id not in dict(groups.GROUPS)
            or not isinstance(attempt_id, str)
            or seal._ATTEMPT_ID.fullmatch(attempt_id) is None
            or rsync_verification.returncode != 0
            or rsync_verification.stdout or rsync_verification.stderr
            or (archive / 'archive.private.json').exists()):
        raise ValueError('pr315-owner-archive-copy-unverified')
    rows = {}
    for directory, directories, files in os.walk(archive, followlinks=False):
        base = Path(directory)
        if any((base / name).is_symlink() for name in (*directories, *files)):
            raise ValueError('pr315-owner-archive-link-invalid')
        for name in files:
            path = base / name
            relative = path.relative_to(archive).as_posix()
            checksum, size = _hash_file(archive, relative,
                                       512 * 1024 * 1024)
            rows[relative] = {'sha256': checksum, 'sizeBytes': size}
            if len(rows) > 256:
                raise ValueError('pr315-owner-archive-file-limit')
    if not set(_MANDATORY) <= set(rows):
        raise ValueError('pr315-owner-archive-evidence-incomplete')
    if len(set(_DISKS) & set(rows)) == 1:
        raise ValueError('pr315-owner-archive-disk-pair-incomplete')
    value = {'schemaVersion': 1,
        'kind': 'pr315-mac-private-archive-v1',
        'planDigest': campaign['planDigest'],
        'campaignNonce': campaign['campaignNonce'],
        'groupId': group_id, 'attemptId': attempt_id,
        'sourceCommit': campaign['identity']['helperSourceCommit'],
        'files': rows, 'copyVerified': True,
        'excludedReconstructible': list(_RECONSTRUCTIBLE) + (
            [] if set(_DISKS) <= set(rows) else list(_DISKS)),
        'guestStopped': True}
    raw = seal._canonical(value)
    fd = os.open(archive / 'archive.private.json',
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, raw) != len(raw):
            raise ValueError('pr315-owner-archive-manifest-short-write')
        os.fsync(fd)
    finally:
        os.close(fd)
    return seal._digest(value)


def _v8_attempts(archive, files):
    found = {}
    for relative in files:
        if relative.endswith('-v8-evidence.private.json'):
            value = _json(archive, relative)
            attempt = value.get('attempt') if isinstance(value, dict) else None
            if isinstance(attempt, dict):
                found[seal._digest(attempt)] = attempt
    return found


def _rebuild_cases(archive, campaign, receipt, source, raw_digests, report,
                   result, terminal, diagnostics, files):
    v8 = _v8_attempts(archive, files)
    records = {}
    identity = campaign['identity']
    if receipt['groupId'] == 'resource-exhaustion':
        children = _json(archive,
            'attempt-01/pr315-resource-children.private.json', 131072)
        audit = terminal['resourceAudit']['record']
        sender = next(row for row in result['roleKernelRoster']['roles']
                      if row['role'] == 'candidate-sender')
        if not runner._resource_child_provenance(children, audit,
                audit['actorBefore'], sender['uid']):
            raise ValueError('pr315-owner-resource-child-proof-changed')
    if receipt['groupId'] == 'positive':
        attempt = _json(archive, 'positive-v8-evidence.private.json')['attempt']
        ready = _json(archive, 'installed-ready-v10-evidence.private.json')
        rebuilt = cases.positive_records(campaign, receipt['attemptId'],
            attempt['identity'], attempt, report, result, terminal, diagnostics,
            ready['actorEpoch'], source, raw_digests)
        return rebuilt
    for case_id in dict(groups.GROUPS)[receipt['groupId']]:
        observed = _json(archive, case_id + '-v10-evidence.private.json')
        if case_id == 'output-symlink':
            attempt = v8.get(observed['v8AttemptDigest'])
            sidecar = _json(archive, case_id + '-v9-evidence.private.json')
            if attempt is None:
                raise ValueError('pr315-owner-v8-attempt-unavailable')
            rebuilt = cases.output_symlink_record(campaign,
                receipt['attemptId'], attempt['identity'], attempt,
                sidecar, raw_digests)
        elif case_id in ('partial-launch', 'stuck-output', 'late-child'):
            producer = {'partial-launch': runner._partial_launch_record,
                'stuck-output': runner._stuck_output_record,
                'late-child': runner._late_child_record}[case_id]
            rebuilt = producer(campaign, receipt['attemptId'], report,
                result, terminal, diagnostics, source, raw_digests)
            if rebuilt is None:
                raise ValueError('pr315-owner-special-case-invalid')
        else:
            sidecar = _json(archive, case_id + '-v9-evidence.private.json')
            attempt = (v8.get(observed['v8AttemptDigest'])
                       if observed.get('v8AttemptDigest') is not None else None)
            selected_identity = attempt['identity'] if attempt is not None else identity
            rebuilt = cases.generic_case_record(campaign,
                receipt['attemptId'], selected_identity, attempt,
                sidecar, source, raw_digests,
                roster=result.get('roleKernelRoster'))
        records[case_id] = rebuilt
    return records


def _authority_preparation(campaign, receipt, archive, history, root):
    """Join the signed old guest, private handle, and successor case group."""
    if history is None or root is None:
        raise ValueError('pr315-owner-retired-authority-history-required')
    envelope = _json(archive, 'retired-authority-handoff.private.json', 8192)
    public = _read(archive, 'campaign-public-key.pub', 512)
    retained = _json(archive, 'retired-authority-input.private.json', 8192)
    handoff = runner.verified_retired_authority_input(
        campaign, envelope, public, retained)
    selected = [row for row in history
                if row['attemptId'] == handoff['preparationAttemptId']
                and row['groupId'] == 'authority'
                and row['status'] == 'preparation-completed']
    if (len(selected) != 1
            or selected[0]['sequence'] >= receipt['sequence']
            or selected[0]['evidenceDigest'] !=
                handoff['privateInputDigest']
            or selected[0]['stopDigest'] != handoff['stopDigest']
            or selected[0]['archiveDigest'] != handoff['archiveDigest']):
        raise ValueError('pr315-owner-retired-authority-receipt-unbound')
    precursor = Path(root) / 'attempts' / handoff['preparationAttemptId']
    _archive_manifest(precursor, campaign, selected[0])
    proof = _json(precursor,
        'retired-authority-v2-provenance.private.json', 8192)
    if (proof.get('sourceCommit') != handoff['sourceCommit']
            or proof.get('bootId') != handoff['retiredBootId']
            or proof.get('senderHandleDigest') !=
                handoff['senderHandleDigest']
            or proof.get('inputDigest') !=
                handoff['privateInputDigest']
            or proof.get('guestStopped') is not True):
        raise ValueError('pr315-owner-retired-authority-proof-changed')
    return handoff


def verify_completed_archive(campaign, receipt, archive, source, *,
                             history=None, campaign_root=None):
    """Rebuild every case from signed, byte-verified private observation files."""
    archive = seal._private_directory(archive)
    source = Path(source)
    if (receipt.get('status') != 'completed'
            or not stat.S_ISDIR(source.lstat().st_mode)):
        raise ValueError('pr315-owner-complete-archive-required')
    manifest = _archive_manifest(archive, campaign, receipt)
    files = manifest['files']
    report = _json(archive, 'attempt-01/attempt.private.json')
    result = _json(archive,
        'attempt-01/pr314-workload-observation.private.json')
    terminal = _json(archive,
        'attempt-01/pr315-workload-volatile.private.json')
    diagnostics = _json(archive,
        'attempt-01/pr315-workload-memory.private.json')
    assessment = _json(archive, 'assessment.json')
    monitor = _json(archive, 'host-monitor.private.json')
    stopped = _json(archive, 'host-stop.private.json')
    identity = report.get('hostVerifiedIdentity')
    watch_source = hashlib.sha256((source /
        'tools/release-certification/restricted/'
        'pr315_pve_pressure_watch.py').read_bytes()).hexdigest()
    if (report.get('mode') != 'workload-positive'
            or report.get('status') != 'guest-report-retained'
            or report.get('guestStopped') is not True
            or report.get('guestExitCode') != 0
            or report.get('helperSourceCommit') != receipt['sourceCommit']
            or not isinstance(identity, dict)
            or any(identity.get(key) != campaign['identity'][key] for key in (
                'helperSourceCommit', 'helperSourceTree', 'bundleIdentity',
                'testKitDigest', 'profileDigest', 'bootClosureDigest',
                'preparedImageDigest', 'fixtureManifestDigest'))
            or identity.get('productDigest') !=
                campaign['identity']['productSelectionDigest']
            or assessment.get('schemaVersion') != 2
            or assessment.get('contract') != seal.CONTRACT
            or assessment.get('status') != 'partial-execution'
            or assessment.get('reasons') != []
            or assessment.get('campaignPlanDigest') != campaign['planDigest']
            or assessment.get('campaignNonce') != campaign['campaignNonce']
            or assessment.get('hostKeyFingerprint') !=
                campaign['hostKeyFingerprint']
            or assessment.get('installedPositiveExecuted') is not (
                receipt['groupId'] == 'positive')
            or assessment.get('installedWorkloadAcceptanceSatisfied') is not False
            or monitor.get('schemaVersion') != 1
            or monitor.get('kind') != 'pr315-pve-watch-finished'
            or monitor.get('action') != 'completed'
            or monitor.get('seenTaskQemu') is not True
            or monitor.get('suite') != receipt['attemptId']
            or monitor.get('sourceCommit') != receipt['sourceCommit']
            or monitor.get('moduleDigest') != watch_source
            or stopped.get('kind') != 'pr315-pve-task-qemu-stopped-v1'
            or stopped.get('attemptId') != receipt['attemptId']
            or stopped.get('sourceCommit') != receipt['sourceCommit']
            or stopped.get('taskQemuProcesses') != []
            or stopped.get('watcherFinishedMonotonicNs') !=
                monitor.get('finishedMonotonicNs')
            or type(stopped.get('observedMonotonicNs')) is not int
            or stopped['observedMonotonicNs'] <=
                monitor['finishedMonotonicNs']
            or files['host-monitor.private.json']['sha256'] !=
                receipt['monitorDigest']
            or files['host-stop.private.json']['sha256'] !=
                receipt['stopDigest']):
        raise ValueError('pr315-owner-installed-premise-invalid')
    if (terminal.get('cleanupReportedByCaller') is not True
            or terminal.get('sentinel', {}).get('status') != 'matched'):
        raise ValueError('pr315-owner-terminal-cleanup-unavailable')
    if receipt['groupId'] == 'authority':
        _authority_preparation(campaign, receipt, archive,
                               history, campaign_root)
    if receipt['groupId'] != 'partial-launch':
        roles = result.get('roleKernelRoster', {}).get('roles', [])
        if len(roles) != 4:
            raise ValueError('pr315-owner-four-role-roster-missing')
        for row in roles:
            entry = terminal['stopReceipts'][row['role']]['current']
            record = entry.get('record') if isinstance(entry, dict) else None
            if (entry.get('status') != 'captured'
                    or not isinstance(record, dict)
                    or record.get('membership') != 'only-stop-helper'
                    or record.get('descendantCgroups') != 0):
                raise ValueError('pr315-owner-owned-stop-incomplete')
        if receipt['groupId'] == 'authority' and terminal[
                'stopReceipts']['candidate-sender'].get('previous', {}).get(
                    'status') != 'captured':
            raise ValueError('pr315-owner-early-authority-stop-missing')
    raw_digests = {'guestReport': files[
        'attempt-01/attempt.private.json']['sha256'],
        'volatile': files[
        'attempt-01/pr315-workload-volatile.private.json']['sha256'],
        'hostMonitor': files['host-monitor.private.json']['sha256']}
    rebuilt = _rebuild_cases(archive, campaign, receipt, source,
        raw_digests, report, result, terminal, diagnostics, files)
    case_digests = {}
    for case_id, record in rebuilt.items():
        retained = _json(archive, case_id + '-v10-evidence.private.json')
        if (retained != record or retained.get('caseId') != case_id
                or retained.get('status') != 'passed'
                or retained.get('rawEvidenceDigests') != raw_digests):
            raise ValueError('pr315-owner-case-changed:' + case_id)
        case_digests[case_id] = seal._digest(record)
    if (case_digests != receipt['caseDigests']
            or seal._digest({'caseDigests': case_digests,
                'rawEvidenceDigests': raw_digests}) !=
                receipt['evidenceDigest']):
        raise ValueError('pr315-owner-case-receipt-changed')
    listed = assessment.get('cases', [])
    statuses = {row['caseId']: row['status'] for row in listed}
    if (len(listed) != 45 or len(statuses) != 45
            or set(statuses) != set(acceptance.CASES)
            or any(statuses.get(case) != 'passed'
            for case in dict(groups.GROUPS)[receipt['groupId']])):
        raise ValueError('pr315-owner-public-case-status-invalid')
    return case_digests


def prepared_completed_receipt(campaign, group_id, attempt_id,
                               archive, source, *, history=None,
                               campaign_root=None, sequence=1,
                               previous_digest='0' * 64):
    """Construct one sealable receipt only after rebuilding its installed cases."""
    archive = Path(archive)
    manifest = _json(archive, 'archive.private.json', 1024 * 1024)
    if (group_id not in dict(groups.GROUPS)
            or manifest.get('groupId') != group_id
            or manifest.get('attemptId') != attempt_id):
        raise ValueError('pr315-owner-group-selection-invalid')
    files = manifest['files']
    selected = tuple(dict(groups.GROUPS)[group_id])
    case_digests = {case_id: seal._digest(_json(archive,
        case_id + '-v10-evidence.private.json')) for case_id in selected}
    raw_digests = {'guestReport': files[
        'attempt-01/attempt.private.json']['sha256'],
        'volatile': files[
        'attempt-01/pr315-workload-volatile.private.json']['sha256'],
        'hostMonitor': files['host-monitor.private.json']['sha256']}
    receipt = seal.attempt_receipt(campaign, group_id, attempt_id,
        campaign['identity']['helperSourceCommit'], 'completed', True,
        case_digests,
        seal._digest({'caseDigests': case_digests,
                      'rawEvidenceDigests': raw_digests}),
        files['host-stop.private.json']['sha256'],
        files['host-monitor.private.json']['sha256'],
        seal._digest(manifest), sequence=sequence,
        previous_digest=previous_digest)
    verify_completed_archive(campaign, receipt, archive, source,
        history=history, campaign_root=campaign_root)
    return receipt


def recovered_campaign_verdict(root, source, *, expected_plan_digest,
                               expected_key_fingerprint):
    """Recover only fully signed and byte-reverified installed group receipts."""
    root = seal._private_directory(root)
    source = Path(source)
    campaign = _json(root, 'campaign-plan.private.json', 16384)
    startup = _json(root, 'start.private.json', 8192)
    commit = subprocess.run(['git', '-C', str(source), 'rev-parse', 'HEAD'],
        check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    tree = subprocess.run(['git', '-C', str(source),
        'rev-parse', 'HEAD^{tree}'], check=True,
        capture_output=True, text=True, timeout=10).stdout.strip()
    dirty = subprocess.run(['git', '-C', str(source), 'status',
        '--porcelain', '--untracked-files=normal'], check=True,
        capture_output=True, timeout=10).stdout
    if (dirty or startup.get('schemaVersion') != 1
            or startup.get('kind') != 'pr315-frozen-campaign-start-v1'
            or startup.get('groupCount') != 21
            or startup.get('planDigest') != expected_plan_digest
            or startup.get('sourceCommit') != commit
            or startup.get('sourceTree') != tree
            or startup.get('trackedByteDigest') !=
                tracked_byte_digest(source)
            or startup.get('hostKeyFingerprint') !=
                expected_key_fingerprint
            or startup.get('fixtureManifestDigest') !=
                campaign.get('identity', {}).get('fixtureManifestDigest')
            or startup.get('productSelectionDigest') !=
                campaign.get('identity', {}).get('productSelectionDigest')
            or startup.get('hostAdmissionPolicy') !=
                'pve-tcg-swap-admission-v1'
            or startup.get('remoteKnownHostsDigest') !=
                hashlib.sha256(_read(root,
                    'remote-known-hosts.private', 16384)).hexdigest()
            or campaign.get('planDigest') != expected_plan_digest
            or campaign.get('hostKeyFingerprint') != expected_key_fingerprint
            or campaign.get('identity', {}).get('helperSourceCommit') != commit):
        raise ValueError('pr315-owner-frozen-source-or-startup-pin-changed')
    seal._check_plan(campaign, commit, expected_key_fingerprint)
    envelope = _json(root, 'start-seal.private.json', 8192)
    if seal.verify_start(root, campaign, envelope) != startup:
        raise ValueError('pr315-owner-frozen-start-signature-changed')
    history = seal.load_verified_history(root, campaign,
        pinned_source_commit=commit,
        pinned_fingerprint=expected_key_fingerprint)
    by_group = {name: [] for name, _ in groups.GROUPS}
    for receipt in history:
        by_group[receipt['groupId']].append(receipt)
    selected = {}
    statuses = {}
    blockers = []
    for group_id, owned in groups.GROUPS:
        attempts = by_group[group_id]
        if not attempts or len(attempts) > 3:
            blockers.append(group_id + ':missing-or-excess-attempts')
            continue
        last = attempts[-1]
        preparation = [row for row in attempts[:-1]
                       if row['status'] == 'preparation-completed']
        if (last['status'] != 'completed'
                or (group_id == 'authority'
                    and len(preparation) != 1)
                or (group_id != 'authority' and preparation)
                or any(row['status'] not in
                       ('setup-failed', 'preparation-completed')
                       for row in attempts[:-1])):
            blockers.append(group_id + ':not-completed')
            continue
        archive = root / 'attempts' / last['attemptId']
        observed = verify_completed_archive(campaign, last, archive, source,
            history=history, campaign_root=root)
        if set(observed) != set(owned):
            raise ValueError('pr315-owner-group-case-set-changed')
        selected[group_id] = last['attemptId']
        statuses.update({case: 'passed' for case in owned})
    positive_executed = (selected.get('positive') is not None
        and all(statuses.get(case) == 'passed'
                for case in dict(groups.GROUPS)['positive']))
    complete = (not blockers and len(selected) == len(groups.GROUPS)
                and len(statuses) == 45)
    coverage = registry.implementation_coverage(source)
    accepted = complete and coverage == 'complete'
    if coverage != 'complete':
        blockers.append('emitter-registry-incomplete')
    return {'schemaVersion': 2, 'kind': 'pr315-workload-suite',
        'contract': seal.CONTRACT,
        'campaignPlanDigest': campaign['planDigest'],
        'campaignNonce': campaign['campaignNonce'],
        'hostKeyFingerprint': campaign['hostKeyFingerprint'],
        'selectedAttemptIds': selected,
        'implementationCoverage': coverage,
        'installedPositiveExecuted': positive_executed,
        'installedWorkloadAcceptanceSatisfied': accepted,
        'finiteNativeAcceptance': False,
        'protectedExecutionEnabled': False,
        'phaseComplete': False,
        'status': 'installed-accepted' if accepted else 'incomplete',
        'reasons': blockers,
        'cases': acceptance.inventory(statuses)}
