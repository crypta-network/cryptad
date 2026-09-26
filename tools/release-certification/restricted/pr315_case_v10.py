"""Closed prospective PR-315 case record, initially for output-symlink.

Only the pinned host owner may call this after it has reverified an installed
attempt. The record is private evidence and cannot authenticate its own origin.
"""
from __future__ import annotations

import hashlib
import json
import re

import pr314_acceptance as acceptance
import pr315_campaign_seal as seal
import pr315_workload_campaign as historical

KIND = 'pr315-installed-case-v10'
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_RAW_FIELDS = frozenset(('guestReport', 'volatile', 'hostMonitor'))


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(',', ':'), ensure_ascii=True,
        allow_nan=False).encode('ascii')).hexdigest()


def output_symlink_record(campaign, attempt_id, identity, attempt, sidecar,
                          raw_evidence_digests):
    """Bind one real installed descriptor denial to pinned host observations."""
    case_id = 'output-symlink'
    group_id = historical.CASE_TO_GROUP[case_id]
    if (not isinstance(campaign, dict) or campaign.get('kind') != seal.CAMPAIGN
            or campaign.get('contract') != seal.CONTRACT
            or not isinstance(attempt_id, str)
            or seal._ATTEMPT_ID.fullmatch(attempt_id) is None
            or not isinstance(identity, dict) or not isinstance(attempt, dict)
            or not isinstance(sidecar, dict)
            or not isinstance(raw_evidence_digests, dict)
            or set(raw_evidence_digests) != _RAW_FIELDS
            or any(_DIGEST.fullmatch(str(value)) is None
                   for value in raw_evidence_digests.values())
            or attempt.get('declaredCases') != [case_id]
            or attempt.get('identity') != identity
            or attempt.get('guestStopped') is not True
            or attempt.get('attemptCompleted') is not True
            or sidecar.get('contract') != historical.CONTRACT
            or sidecar.get('caseId') != case_id
            or sidecar.get('status') != 'passed'
            or sidecar.get('guestStopped') is not True):
        raise ValueError('pr315-v10-case-input-invalid')
    expected_identity = campaign['identity']
    if (identity != expected_identity
            or sidecar.get('hostVerifiedIdentity', {}).get('helperSourceCommit') !=
                expected_identity['helperSourceCommit']
            or sidecar['hostVerifiedIdentity'].get('testKitDigest') !=
                expected_identity['testKitDigest']):
        raise ValueError('pr315-v10-case-campaign-identity-mismatch')
    checked = acceptance.verify_attempts(identity, [attempt])
    if (checked['recordContractValid'] is not True
            or next((row['status'] for row in checked['cases']
                     if row['caseId'] == case_id), None) != 'passed'
            or checked['installedWorkloadAcceptanceSatisfied'] is not False):
        raise ValueError('pr315-v10-case-v8-verification-failed')
    actor = sidecar.get('actorEpoch')
    target = sidecar.get('targetEpoch')
    window = sidecar.get('operationWindow')
    principals = attempt.get('principals', {}).get('roles', [])
    sender = next((row for row in principals
                   if isinstance(row, dict)
                   and row.get('role') == 'candidate-sender'), None)
    if (not isinstance(actor, dict) or not isinstance(target, dict)
            or not isinstance(window, dict) or not isinstance(sender, dict)
            or actor.get('uid') != sender['uid']
            or actor.get('gid') != sender['gid']
            or actor.get('bootId') != sender['bootId']
            or actor.get('systemdInvocation') != sender['invocationId']
            or actor.get('cgroupDigest') != sender['cgroupDigest']
            or type(actor.get('hostPid')) is not int or actor['hostPid'] <= 1
            or type(actor.get('startTicks')) is not int or actor['startTicks'] <= 0
            or not isinstance(actor.get('namespacePids'), list)
            or len(actor['namespacePids']) < 2
            or target.get('kind') != 'administrator-descriptor-collector'
            or type(target.get('pid')) is not int or target['pid'] <= 1
            or target.get('uid') != 0
            or type(target.get('startTicks')) is not int or target['startTicks'] <= 0
            or target.get('bootId') != sender['bootId']
            or _DIGEST.fullmatch(str(target.get('cgroupDigest'))) is None
            or not isinstance(target.get('testKitInvocation'), str)
            or re.fullmatch('[0-9a-f]{32}', target['testKitInvocation']) is None
            or type(window.get('startedMonotonicNs')) is not int
            or type(window.get('finishedMonotonicNs')) is not int
            or not 0 < window['startedMonotonicNs'] < window['finishedMonotonicNs']
            or type(sidecar.get('stopReceiptObservedNs')) is not int
            or window['finishedMonotonicNs'] >= sidecar['stopReceiptObservedNs']):
        raise ValueError('pr315-v10-case-epoch-invalid')
    record = {'schemaVersion': 10, 'kind': KIND,
        'contract': seal.CONTRACT, 'campaignPlanDigest': campaign['planDigest'],
        'campaignNonce': campaign['campaignNonce'],
        'attemptId': attempt_id, 'groupId': group_id, 'caseId': case_id,
        'status': 'passed', 'sourceCommit': expected_identity['helperSourceCommit'],
        'actorEpoch': actor, 'targetEpoch': target, 'operationWindow': window,
        'v8AttemptDigest': _digest(attempt), 'v9SidecarDigest': _digest(sidecar),
        'hostIdentityDigest': _digest(sidecar['hostVerifiedIdentity']),
        'rawEvidenceDigests': raw_evidence_digests,
        'stopReceiptObservedNs': sidecar['stopReceiptObservedNs'],
        'classification': 'private-host-verified-candidate-not-standalone-acceptance'}
    if len(json.dumps(record, sort_keys=True, separators=(',', ':'))) > 32768:
        raise ValueError('pr315-v10-case-record-limit')
    return record


def verify_output_symlink_record(campaign, attempt_id, identity, attempt,
                                 sidecar, raw_evidence_digests, record):
    """Reconstruct exact bytes from trusted inputs; never import a verdict."""
    expected = output_symlink_record(campaign, attempt_id, identity, attempt,
                                     sidecar, raw_evidence_digests)
    if record != expected:
        raise ValueError('pr315-v10-case-record-changed')
    return _digest(expected)
