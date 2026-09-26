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
import pr315_workload_fixtures as fixtures

KIND = 'pr315-installed-case-v10'
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_RAW_FIELDS = frozenset(('guestReport', 'volatile', 'hostMonitor'))
POSITIVE = tuple(dict(historical.GROUPS)['positive'])
SPECIAL_LIFECYCLE = frozenset(('partial-launch', 'stuck-output', 'late-child'))
GENERIC = frozenset((
    *dict(historical.GROUPS)['role-boundary'],
    'resolver-authority', 'hostile-app-origin',
    'forged-runtime-identity', 'forged-counters',
    'provider-authority', 'sibling-fcp', 'sibling-http',
    'sibling-app', 'host-network', 'namespace-mount-escape',
    'runner-control', 'observer-control', 'arbitrary-endpoint',
    'output-fifo', 'output-hardlink', 'output-flood',
    'output-replacement', 'resource-exhaustion',
    'lost-start-response', 'observer-death', 'controller-restart',
    'setsid-double-fork', 'deadline', 'revocation-running',
    'cancellation', 'stale-handle', 'stale-pid-uid',
    'cleanup-race'))
SIDECAR_ONLY = frozenset((
    'observer-private-read', 'observer-private-write',
    'sibling-data', 'package-expectation', 'cgroup-migration',
    'forged-runtime-identity', 'forged-counters', 'stale-handle',
    'stale-pid-uid', 'cleanup-race'))


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
        'operationTimeDomain': 'guest:' + sender['bootId'],
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


def generic_case_record(campaign, attempt_id, identity, attempt, sidecar,
                        source_root, raw_evidence_digests, *, roster=None):
    """Normalize one already verified v9 case without granting acceptance."""
    from pathlib import Path
    from pr312_reference_vm import sha256

    if (not isinstance(campaign, dict) or campaign.get('kind') != seal.CAMPAIGN
            or campaign.get('contract') != seal.CONTRACT
            or not isinstance(attempt_id, str)
            or seal._ATTEMPT_ID.fullmatch(attempt_id) is None
            or not isinstance(sidecar, dict)
            or not isinstance(raw_evidence_digests, dict)
            or set(raw_evidence_digests) != _RAW_FIELDS
            or any(_DIGEST.fullmatch(str(value)) is None
                   for value in raw_evidence_digests.values())):
        raise ValueError('pr315-v10-generic-input-invalid')
    case_id = sidecar.get('caseId')
    expected_identity = campaign.get('identity')
    if case_id == 'resource-exhaustion' and isinstance(expected_identity, dict):
        # V8 names the probed signed app in this case. The campaign separately
        # pins both normally signed Mail and probe bytes; retain V8 semantics.
        expected_identity = {**expected_identity,
            'admittedAppDigest': campaign.get('probeDigest')}
    if (case_id not in GENERIC or identity != expected_identity
            or sidecar.get('contract') != historical.CONTRACT
            or sidecar.get('status') != 'passed'
            or sidecar.get('guestStopped') is not True
            or not isinstance(sidecar.get('actorEpoch'), dict)
            or not isinstance(sidecar.get('targetEpoch'), dict)
            or not sidecar['targetEpoch']
            or not isinstance(sidecar.get('operationWindow'), dict)):
        raise ValueError('pr315-v10-generic-contract-invalid')
    if attempt is None:
        if (case_id not in SIDECAR_ONLY or not acceptance._principals(roster)):
            raise ValueError('pr315-v10-generic-sidecar-source-invalid')
        principals = roster['roles']
        observation = None
    else:
        if (not isinstance(attempt, dict)
                or attempt.get('identity') != identity
                or attempt.get('declaredCases') != [case_id]
                or attempt.get('guestStopped') is not True
                or attempt.get('attemptCompleted') is not True):
            raise ValueError('pr315-v10-generic-v8-input-invalid')
        checked = acceptance.verify_attempts(identity, [attempt])
        if (checked['recordContractValid'] is not True
                or next((row['status'] for row in checked['cases']
                         if row['caseId'] == case_id), None) != 'passed'
                or checked['installedWorkloadAcceptanceSatisfied'] is not False):
            raise ValueError('pr315-v10-generic-v8-verification-failed')
        principals = attempt['principals']['roles']
        observation = attempt['observations'][0]
    host = sidecar.get('hostVerifiedIdentity')
    if (not isinstance(host, dict)
            or host.get('helperSourceCommit') != identity['helperSourceCommit']
            or host.get('testKitDigest') != identity['testKitDigest']):
        raise ValueError('pr315-v10-generic-host-identity-invalid')
    sender = next((row for row in principals if row['role'] == 'candidate-sender'), None)
    if sender is None:
        raise ValueError('pr315-v10-generic-sender-unavailable')
    actor = sidecar['actorEpoch']
    spec = acceptance.CASES[case_id]
    if spec.actor == 'candidate':
        if (actor.get('uid') != sender['uid']
                or actor.get('bootId') != sender['bootId']
                or actor.get('systemdInvocation') != sender['invocationId']
                or actor.get('cgroupDigest') != sender['cgroupDigest']
                or type(actor.get('hostPid')) is not int or actor['hostPid'] <= 1
                or type(actor.get('startTicks')) is not int or actor['startTicks'] <= 0):
            raise ValueError('pr315-v10-generic-candidate-epoch-invalid')
    elif spec.actor == 'app':
        if (actor.get('kind') != 'normally-signed-apphost-child'
                or actor.get('uid') != sender['uid']
                or actor.get('systemdInvocation') != sender['invocationId']
                or actor.get('cgroupDigest') != sender['cgroupDigest']
                or actor.get('bundleDigest') != 'sha256:' + campaign['probeDigest']
                or type(actor.get('hostPid')) is not int or actor['hostPid'] <= 1
                or type(actor.get('startTicks')) is not int or actor['startTicks'] <= 0):
            raise ValueError('pr315-v10-generic-signed-app-epoch-invalid')
    elif spec.actor == 'administrator':
        source_digest = sha256(Path(source_root) /
            'tools/release-certification/restricted/pr314_workload_driver.py')
        if (actor.get('kind') != 'administrator-test-kit'
                or actor.get('uid') != 0
                or actor.get('bootId', '').replace('-', '').lower() != sender['bootId']
                or actor.get('sourceDigest') != source_digest
                or type(actor.get('pid')) is not int or actor['pid'] <= 1
                or type(actor.get('startTicks')) is not int or actor['startTicks'] <= 0):
            raise ValueError('pr315-v10-generic-administrator-epoch-invalid')
    elif spec.actor in ('observer', 'runner'):
        expected_uid = (attempt['principals']['observerUid']
                        if spec.actor == 'observer' else
                        attempt['principals']['runnerUid'])
        expected_kind = ('installed-observer-process' if spec.actor == 'observer'
                         else 'installed-runner-process')
        source_digest = sha256(Path(source_root) /
            'tools/release-certification/restricted/pr314_workload_driver.py')
        if (actor.get('kind') != expected_kind
                or actor.get('uid') != expected_uid
                or actor.get('sourceDigest') != source_digest
                or actor.get('bootId', '').replace('-', '').lower() != sender['bootId']
                or not isinstance(actor.get('namespaces'), dict)
                or set(actor['namespaces']) != {'pid', 'net', 'mnt', 'user'}
                or type(actor.get('pid')) is not int or actor['pid'] <= 1
                or type(actor.get('startTicks')) is not int or actor['startTicks'] <= 0):
            raise ValueError('pr315-v10-generic-observer-epoch-invalid')
    else:
        raise ValueError('pr315-v10-generic-actor-unsupported')
    window = sidecar['operationWindow']
    stop_ns = sidecar.get('stopReceiptObservedNs')
    if (type(window.get('startedMonotonicNs')) is not int
            or type(window.get('finishedMonotonicNs')) is not int
            or type(stop_ns) is not int
            or not 0 < window['startedMonotonicNs'] < window['finishedMonotonicNs']
            or stop_ns <= 0):
        raise ValueError('pr315-v10-generic-window-invalid')
    if spec.witness == 'lifecycle':
        if (stop_ns > window['finishedMonotonicNs']
                or sidecar['targetEpoch'].get('roles') != principals):
            raise ValueError('pr315-v10-generic-lifecycle-target-invalid')
    elif window['finishedMonotonicNs'] >= stop_ns:
        raise ValueError('pr315-v10-generic-stop-window-invalid')
    record = {'schemaVersion': 10, 'kind': KIND,
        'contract': seal.CONTRACT, 'campaignPlanDigest': campaign['planDigest'],
        'campaignNonce': campaign['campaignNonce'], 'attemptId': attempt_id,
        'groupId': historical.CASE_TO_GROUP[case_id], 'caseId': case_id,
        'status': 'passed', 'sourceCommit': identity['helperSourceCommit'],
        'actorEpoch': actor, 'targetEpoch': sidecar['targetEpoch'],
        'operationWindow': window,
        'operationTimeDomain': 'guest:' + sender['bootId'],
        'v8AttemptDigest': _digest(attempt) if attempt is not None else None,
        'v8ObservationDigest': _digest(observation) if observation is not None else None,
        'v9SidecarDigest': _digest(sidecar),
        'hostIdentityDigest': _digest(host),
        'rawEvidenceDigests': raw_evidence_digests,
        'stopReceiptObservedNs': stop_ns,
        'classification': 'private-host-verified-candidate-not-standalone-acceptance'}
    if len(json.dumps(record, sort_keys=True, separators=(',', ':'))) > 32768:
        raise ValueError('pr315-v10-generic-record-limit')
    return record


def _positive_roles(attempt, result):
    principals = attempt['principals']['roles']
    epochs = result['roleDaemonEpochs']
    if (set(epochs) != set(acceptance.ROLES)
            or {row['role'] for row in principals} != set(acceptance.ROLES)):
        raise ValueError('pr315-v10-positive-roster-invalid')
    roles = {row['role']: row for row in principals}
    for role, principal in roles.items():
        epoch = epochs[role]
        if (epoch['managerInvocation'] != principal['invocationId']
                or epoch['startTicks'] != principal['processEpoch']
                or epoch['hostPid'] <= 1
                or epoch['executableDigest'].startswith('sha256:') is not True
                or epoch['networkNamespaceIdentity'][1] != principal['networkNamespace']
                or fixtures.runtime.canonical_digest({
                    'role': role, 'identity': epoch['cgroupIdentity']})[7:]
                    != principal['cgroupDigest']):
            raise ValueError('pr315-v10-positive-role-epoch-invalid')
    return roles, epochs


def _positive_target(case_id, observation, identity, roles, epochs, attempt, result):
    witness = observation['witness']
    if case_id == 'installed-ready':
        return {'kind': 'installed-source-and-test-kit',
            'sourceCommit': identity['helperSourceCommit'],
            'bundleIdentity': identity['bundleIdentity'],
            'testKitDigest': identity['testKitDigest'],
            'preparedImageDigest': identity['preparedImageDigest']}
    if case_id == 'four-role-start':
        return {'kind': 'installed-four-role-roster',
            'roles': roles, 'daemonEpochs': epochs}
    if case_id == 'signed-apphost-child':
        if (witness != attempt['appProcess']
                or witness['hostPid'] != result['appKernelProcess']['hostPid']
                or witness['processEpoch'] != result['appKernelProcess']['processEpoch']):
            raise ValueError('pr315-v10-positive-app-epoch-invalid')
        return {'kind': 'normally-signed-mail-apphost',
            'bundleDigest': identity['admittedAppDigest'],
            'worker': result['appKernelProcess'],
            'senderDaemon': epochs['candidate-sender']}
    if case_id in ('own-management', 'dynamic-app-bootstrap',
                   'fnp-content-retrieval'):
        role = acceptance.CASES[case_id].server_role
        if witness['serverInvocationId'] != roles[role]['invocationId']:
            raise ValueError('pr315-v10-positive-server-epoch-invalid')
        value = {'kind': 'current-installed-role-server', 'role': role,
                 'principal': roles[role], 'daemonEpoch': epochs[role]}
        if case_id == 'dynamic-app-bootstrap':
            value['mailWorker'] = result['appKernelProcess']
        if case_id == 'fnp-content-retrieval':
            value['fnpCounterPairDigest'] = _digest(result['fnpCounterPair'])
        return value
    if case_id == 'kernel-resource-scope':
        if witness['source'] != 'cgroup-v2':
            raise ValueError('pr315-v10-positive-resource-source-invalid')
        return {'kind': 'four-owned-role-cgroups',
                'measurements': witness['measurements'], 'daemonEpochs': epochs}
    if case_id == 'restart-durable-state':
        context = attempt['restartContext']
        old, new = result['restartDaemonEpochs']['before'], result['restartDaemonEpochs']['after']
        if (old['managerInvocation'] != context['before']['roleIdentity']['invocationId']
                or new['managerInvocation'] != context['after']['roleIdentity']['invocationId']
                or old['startTicks'] != context['before']['roleIdentity']['processEpoch']
                or new['startTicks'] != context['after']['roleIdentity']['processEpoch']
                or old['hostPid'] <= 1 or new['hostPid'] <= 1
                or old['managerInvocation'] == new['managerInvocation']):
            raise ValueError('pr315-v10-positive-restart-epoch-invalid')
        return {'kind': 'restarted-installed-sender',
                'beforeDaemon': old, 'afterDaemon': new,
                'beforeRole': context['before']['roleIdentity'],
                'afterRole': context['after']['roleIdentity']}
    raise ValueError('pr315-v10-positive-case-unsupported')


def positive_records(campaign, attempt_id, identity, attempt, report,
                     result, terminal, diagnostics, host_runner_epoch,
                     source_root, raw_evidence_digests):
    """Produce eight separate candidate records after the complete installed verifier."""
    from pathlib import Path
    from pr312_reference_vm import sha256

    if (not isinstance(campaign, dict) or campaign.get('kind') != seal.CAMPAIGN
            or campaign.get('contract') != seal.CONTRACT
            or not isinstance(attempt_id, str)
            or seal._ATTEMPT_ID.fullmatch(attempt_id) is None
            or identity != campaign.get('identity')
            or attempt.get('identity') != identity
            or attempt.get('guestStopped') is not True
            or report.get('guestStopped') is not True
            or not isinstance(attempt.get('declaredCases'), list)
            or len(attempt['declaredCases']) != len(POSITIVE)
            or set(attempt['declaredCases']) != set(POSITIVE)
            or not isinstance(raw_evidence_digests, dict)
            or set(raw_evidence_digests) != _RAW_FIELDS
            or any(_DIGEST.fullmatch(str(value)) is None
                   for value in raw_evidence_digests.values())):
        raise ValueError('pr315-v10-positive-input-invalid')
    checked = acceptance.verify_attempts(identity, [attempt])
    if (checked['recordContractValid'] is not True
            or {row['caseId'] for row in checked['cases'] if row['status'] == 'passed'}
                != set(POSITIVE)
            or checked['installedWorkloadAcceptanceSatisfied'] is not False):
        raise ValueError('pr315-v10-positive-v8-verification-failed')
    roles, epochs = _positive_roles(attempt, result)
    source_digest = sha256(Path(source_root) /
        'tools/release-certification/restricted/pr314_workload_driver.py')
    runner_digest = sha256(Path(source_root) /
        'tools/release-certification/restricted/pr315_workload_runner.py')
    before = diagnostics['positiveAdministratorBefore']
    after = diagnostics['positiveAdministratorAfter']
    observer = diagnostics['positiveObserverEpoch']
    checkpoint = terminal['observerControlCheckpoint']
    if (checkpoint['status'] != 'captured'
            or observer['kind'] != 'installed-observer-process'
            or observer['uid'] != attempt['principals']['observerUid']
            or observer['pid'] != checkpoint['record']['actorPid']
            or observer['startTicks'] != checkpoint['record']['actorStartTicks']
            or observer['bootId'].replace('-', '').lower() != roles['candidate-sender']['bootId']
            or observer['sourceDigest'] != source_digest
            or not isinstance(observer.get('namespaces'), dict)
            or set(observer['namespaces']) != {'pid', 'net', 'mnt', 'user'}
            or any(type(value) is not int or value <= 0
                   for value in observer['namespaces'].values())
            or before['uid'] != after['uid'] or before['uid'] != 0
            or any(before[key] != after[key] for key in
                   ('pid', 'startTicks', 'bootId', 'cgroupIdentity',
                    'cgroupDigest', 'invocationId', 'sourceDigest'))
            or before['bootId'].replace('-', '').lower() != roles['candidate-sender']['bootId']
            or before['sourceDigest'] != source_digest
            or type(before['observedMonotonicNs']) is not int
            or type(after['observedMonotonicNs']) is not int
            or before['observedMonotonicNs'] >= after['observedMonotonicNs']
            or host_runner_epoch['kind'] != 'host-runner-process'
            or host_runner_epoch['sourceDigest'] != runner_digest
            or host_runner_epoch['uid'] <= 0
            or host_runner_epoch['pid'] <= 1
            or host_runner_epoch['startTicks'] <= 0):
        raise ValueError('pr315-v10-positive-actor-epoch-invalid')
    receipts = terminal['stopReceipts']
    stopped = []
    for role, principal in roles.items():
        row = receipts[role]['current']
        if (row['status'] != 'captured'
                or row['record']['managerInvocation'] != principal['invocationId']
                or row['record']['membership'] != 'only-stop-helper'
                or row['record']['descendantCgroups'] != 0):
            raise ValueError('pr315-v10-positive-stop-invalid')
        stopped.append(row['record']['observedMonotonicNs'])
    stop_ns = max(stopped)
    observations = {row['caseId']: row for row in attempt['observations']}
    if set(observations) != set(POSITIVE):
        raise ValueError('pr315-v10-positive-observations-invalid')
    records = {}
    for case_id in POSITIVE:
        row = observations[case_id]
        started, finished = row['startedMonotonicNs'], row['finishedMonotonicNs']
        if (row['status'] != 'passed' or type(started) is not int
                or type(finished) is not int or not 0 < started < finished):
            raise ValueError('pr315-v10-positive-window-invalid')
        actor = (host_runner_epoch if case_id == 'installed-ready' else
                 before if case_id == 'kernel-resource-scope' else observer)
        time_domain = ('host:' + host_runner_epoch['bootId']
                       if case_id == 'installed-ready' else
                       'guest:' + roles['candidate-sender']['bootId'])
        if (case_id == 'installed-ready' and
                host_runner_epoch['observedMonotonicNs'] <= finished):
            raise ValueError('pr315-v10-positive-host-window-invalid')
        if case_id != 'installed-ready' and (
                actor['observedMonotonicNs'] >= started or finished >= stop_ns):
            raise ValueError('pr315-v10-positive-guest-window-invalid')
        target = _positive_target(case_id, row, identity, roles, epochs, attempt, result)
        records[case_id] = {'schemaVersion': 10, 'kind': KIND,
            'contract': seal.CONTRACT, 'campaignPlanDigest': campaign['planDigest'],
            'campaignNonce': campaign['campaignNonce'], 'attemptId': attempt_id,
            'groupId': 'positive', 'caseId': case_id, 'status': 'passed',
            'sourceCommit': identity['helperSourceCommit'],
            'actorEpoch': actor, 'targetEpoch': target,
            'operationWindow': {'startedMonotonicNs': started,
                                'finishedMonotonicNs': finished},
            'operationTimeDomain': time_domain,
            'v8AttemptDigest': _digest(attempt),
            'v8ObservationDigest': _digest(row), 'v9SidecarDigest': None,
            'hostIdentityDigest': _digest(report['hostVerifiedIdentity']),
            'rawEvidenceDigests': raw_evidence_digests,
            'stopReceiptObservedNs': stop_ns,
            'classification': 'private-host-verified-candidate-not-standalone-acceptance'}
        if len(json.dumps(records[case_id], sort_keys=True,
                          separators=(',', ':'))) > 32768:
            raise ValueError('pr315-v10-positive-record-limit')
    return records
