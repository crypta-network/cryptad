"""Finite private supervisor attempt ledger for one predeclared runtime reference campaign.

This root-owned accounting prevents omission of started attempts. Original journal, product and
approval authentication remain with the existing baseline admission owner.
"""
from __future__ import annotations

from contextlib import contextmanager
import datetime as dt
import os
from pathlib import Path
import stat

try:
    import fcntl
except ImportError:
    fcntl = None

import runtime_baseline_admission as admission
import runtime_baseline_approval as approvals


class LedgerError(ValueError):
    """Fixed public code without private experiment coordinates."""


def _read(path, maximum=admission.MAX_BYTES):
    approvals._private_directory(path.parent)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise LedgerError('runtime-reference-ledger-private-record-unavailable') from None
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o400 or info.st_size > maximum):
            raise LedgerError('runtime-reference-ledger-private-record-invalid')
        raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise LedgerError('runtime-reference-ledger-budget-exceeded')
    return admission.decode(raw)


def _write_new(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(admission.encode(value))
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), 0o400)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


@contextmanager
def _campaign(campaign, *, policy=None, create=False):
    if fcntl is None or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        raise LedgerError('runtime-reference-ledger-root-required')
    if (not isinstance(campaign, dict) or not isinstance(campaign.get('campaignId'), str)
            or not admission.baseline.LABEL.fullmatch(campaign['campaignId'])):
        raise LedgerError('runtime-reference-ledger-campaign-invalid')
    if policy is not None:
        admission.validate_campaign(campaign, policy)
    root = approvals._private_directory(approvals.PRIVATE_STORE)
    parent = root / 'campaigns'
    directory = parent / campaign['campaignId']
    if create:
        parent.mkdir(mode=0o700, exist_ok=True)
        approvals._private_directory(parent)
        directory.mkdir(mode=0o700, exist_ok=True)
    approvals._private_directory(directory)
    descriptor = os.open(directory / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise LedgerError('runtime-reference-ledger-lock-invalid')
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        frozen_path = directory / 'campaign.json'
        if not frozen_path.exists() and create:
            _write_new(frozen_path, {'schemaVersion': 1, 'campaign': campaign, 'policy': policy})
        frozen = _read(frozen_path, 65536)
        if (not isinstance(frozen, dict) or set(frozen) != {'schemaVersion', 'campaign', 'policy'}
                or type(frozen['schemaVersion']) is not int or frozen['schemaVersion'] != 1
                or frozen['campaign'] != campaign or policy is not None and frozen['policy'] != policy):
            raise LedgerError('runtime-reference-ledger-campaign-substituted')
        admission.validate_campaign(campaign, frozen['policy'])
        allowed = {'campaign.json', 'lock'} | {f'attempt-{index:02d}.json' for index in range(len(campaign['attempts']))}
        if any(path.name not in allowed for path in directory.iterdir()):
            raise LedgerError('runtime-reference-ledger-unexpected-record')
        yield directory, frozen['policy']
    finally:
        os.close(descriptor)


def _started(directory, campaign):
    markers = []
    missing = False
    for index, experiment in enumerate(campaign['attempts']):
        path = directory / f'attempt-{index:02d}.json'
        if not path.exists():
            missing = True
            continue
        if missing:
            raise LedgerError('runtime-reference-ledger-nonprefix-attempts')
        marker = _read(path, 2048)
        if (not isinstance(marker, dict) or set(marker) != {'schemaVersion', 'kind', 'campaignDigest', 'index', 'experimentId', 'startedAt'}
                or type(marker['schemaVersion']) is not int or marker['schemaVersion'] != 1
                or marker['kind'] != 'runtime-reference-attempt-started'
                or marker['campaignDigest'] != admission.digest(campaign)
                or type(marker['index']) is not int or marker['index'] != index or marker['experimentId'] != experiment):
            raise LedgerError('runtime-reference-ledger-marker-substituted')
        admission.baseline._time(marker['startedAt'])
        markers.append(marker)
    return markers


def _outcomes(markers, campaign, policy):
    accepted = replacements = 0
    for marker in markers:
        if accepted >= campaign['requiredRepetitions']:
            raise LedgerError('runtime-reference-ledger-extra-attempt')
        path = approvals.PRIVATE_STORE / 'observations' / (marker['experimentId'] + '.json')
        if not path.exists():
            raise LedgerError('runtime-reference-ledger-attempt-pending')
        capsule = _read(path)
        if (not isinstance(capsule, dict) or capsule.get('plan', {}).get('experimentId') != marker['experimentId']
                or capsule.get('authorization', {}).get('runtimeReference') != campaign
                or not isinstance(capsule.get('checkpoint'), dict)
                or not isinstance(capsule.get('events'), list) or not capsule['events']):
            raise LedgerError('runtime-reference-ledger-terminal-capsule-invalid')
        events = capsule['events']
        if (admission.baseline._time(events[0]['wallTime']) < admission.baseline._time(marker['startedAt'])
                or admission.baseline._time(events[-1]['wallTime']) < admission.baseline._time(events[0]['wallTime'])
                or admission.baseline._time(events[-1]['wallTime']) > dt.datetime.now(dt.timezone.utc)):
            raise LedgerError('runtime-reference-ledger-terminal-clock-invalid')
        attachments = [event['runtimeEvidence'] for event in events if 'runtimeEvidence' in event]
        if len(attachments) > 1:
            raise LedgerError('runtime-reference-ledger-terminal-capsule-invalid')
        evidence = attachments[0] if attachments else None
        try:
            outcome = admission.terminal_outcome(events, capsule['checkpoint'])
        except admission.AdmissionError:
            raise LedgerError('runtime-reference-ledger-terminal-capsule-invalid') from None
        valid = False
        if evidence is not None:
            series = evidence['series']
            if (evidence['policy'] != policy or series['fingerprint'] != campaign['referenceFingerprint']
                    or series['evidenceClass'] != campaign['evidenceClass']):
                raise LedgerError('runtime-reference-ledger-applicability-mismatch')
            valid = (admission.baseline.assess(series, policy)['status'] == 'valid'
                     and outcome == 'pass'
                     and not any(event.get('outcome') == 'fail' for event in events))
        disposition = ('accepted' if valid else outcome if outcome in {'failed', 'cancelled'}
                       else 'invalid' if evidence else 'failed')
        if valid:
            accepted += 1
        else:
            replacements += 1
            if disposition not in campaign['replacementOutcomes'] or replacements > campaign['maximumReplacements']:
                raise LedgerError('runtime-reference-ledger-replacement-not-planned')
    return accepted


def begin(campaign, experiment_id, policy):
    """Durably mark the next fixed attempt before the supervisor starts candidate processes."""
    with _campaign(campaign, policy=policy, create=True) as (directory, frozen_policy):
        if admission.baseline._time(campaign['plannedAt']) > dt.datetime.now(dt.timezone.utc):
            raise LedgerError('runtime-reference-ledger-plan-in-future')
        markers = _started(directory, campaign)
        accepted = _outcomes(markers, campaign, frozen_policy)
        if (accepted >= campaign['requiredRepetitions'] or len(markers) >= len(campaign['attempts'])
                or experiment_id != campaign['attempts'][len(markers)]):
            raise LedgerError('runtime-reference-ledger-next-attempt-invalid')
        marker = {'schemaVersion': 1, 'kind': 'runtime-reference-attempt-started',
                  'campaignDigest': admission.digest(campaign), 'index': len(markers),
                  'experimentId': experiment_id, 'startedAt': dt.datetime.now(dt.timezone.utc).isoformat()}
        _write_new(directory / f'attempt-{len(markers):02d}.json', marker)


def verify_complete(campaign, expected_attempt_ids):
    """Require the complete root-observed attempt roster, including every allowed replacement."""
    with _campaign(campaign) as (directory, policy):
        markers = _started(directory, campaign)
        if (not isinstance(expected_attempt_ids, list)
                or expected_attempt_ids != [marker['experimentId'] for marker in markers]):
            raise LedgerError('runtime-reference-ledger-attempt-roster-mismatch')
        if _outcomes(markers, campaign, policy) != campaign['requiredRepetitions']:
            raise LedgerError('runtime-reference-ledger-repetitions-incomplete')
