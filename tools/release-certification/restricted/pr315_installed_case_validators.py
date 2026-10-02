#!/usr/bin/python3
"""Closed host-side validators for installed PR-315 network and artifact cases.

The runner facade stays the fixed external API. Lazily bound helper calls read
the runner's current patched/tested hooks while source and test-kit identity
remain pinned to the same commit.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

import installation
import pr315_workload_runner as runner

acceptance = runner.acceptance
campaign = runner.campaign
fixtures = runner.fixtures
reference = runner.reference
workload_network = runner.workload_network


def group_prepared(*args, **kwargs):
    return runner.group_prepared(*args, **kwargs)


def probe_denial_attempt(*args, **kwargs):
    return runner.probe_denial_attempt(*args, **kwargs)


def _v9_actor_epoch(*args, **kwargs):
    return runner._v9_actor_epoch(*args, **kwargs)


def _resource_child_provenance(*args, **kwargs):
    return runner._resource_child_provenance(*args, **kwargs)



def _provider_authority_attempt(report, result, fixture, terminal):
    """Bind the signed AppHost syscall to real installed Worker credential ingress."""
    case_id = 'provider-authority'
    try:
        if (not group_prepared(report, result, terminal, 'network-app')
                or fixture.get('schemaVersion') != 4
                or terminal['providerAuthorityAudit']['status'] != 'captured'
                or terminal['providerAppResult']['status'] != 'captured'):
            return None
        normal = probe_denial_attempt(report, fixture, terminal)
        if normal is None:
            return None
        normal_identity, normal_attempt = normal
        checked = acceptance.verify_attempts(normal_identity, [normal_attempt])
        if (checked['recordContractValid'] is not True
                or next(row['status'] for row in checked['cases']
                        if row['caseId'] == 'namespace-mount-escape') != 'passed'):
            return None
        audit = terminal['providerAuthorityAudit']['record']
        app_result = terminal['providerAppResult']['record']
        admin = terminal['probeAdministratorRecord']['record']
        checkpoint = terminal['probeKernelCheckpoint']['record']
        sender = next(row for row in result['roleKernelRoster']['roles']
                      if row['role'] == 'candidate-sender')
        before, after = audit['actorBefore'], audit['actorAfter']
        first, last = audit['targetBefore'], audit['targetAfter']
        worker_before = audit['workerControlBefore']
        worker_after = audit['workerControlAfter']
        receipt = terminal['stopReceipts']['candidate-sender']['current']['record']
        host = report['hostVerifiedIdentity']
        stable_actor = ('role', 'hostPid', 'namespacePid', 'namespacePids',
            'startTicks', 'executableDigest', 'mountNamespaceIdentity',
            'outerMountNamespaceIdentity', 'userNamespaceIdentity',
            'pidNamespaceIdentity', 'managerInvocation', 'cgroupIdentity',
            'networkNamespaceIdentity', 'stateDigest', 'sandboxLeader',
            'provenance')
        stable_target = ('role', 'managerInvocation', 'bootId',
            'cgroupIdentity', 'mainPid', 'mainStartTicks',
            'resolverCanaryIdentity', 'resolverControlDigest',
            'providerCanaryIdentity', 'controlDigest',
            'credentialIdentity', 'credentialDigest')
        provider_group = fixtures.runtime.canonical_digest({
            'role': 'original-provider', 'identity': first['cgroupIdentity']})[7:]
        worker = result['probeAppKernelProcess']
        measured = admin['worker']
        installed_worker_digest = hashlib.sha256((Path(__file__).resolve().parents[3] /
            'tools/release-certification/protected/restricted_worker.py').read_bytes()).hexdigest()
        worker_fields = {'kind', 'ordinal', 'workerSourceDigest',
            'jobAuthentication',
            'credentialDigest', 'registrationDigest', 'resultDigest',
            'handleDigest', 'bundleIdentity', 'callerUid',
            'startedMonotonicNs', 'finishedMonotonicNs'}
        if (audit['schemaVersion'] != 2
                or audit['kind'] != 'pr315-administrator-provider-authority-denial'
                or audit['caseId'] != case_id
                or audit['bundleDigest'] != fixture['probeDigest']
                or admin['bundleDigest'] != fixture['probeDigest']
                or audit['actorUid'] != sender['uid']
                or app_result['uid'] != sender['uid']
                or app_result['gid'] != sender['gid']
                or app_result['pid'] != before['namespacePids'][-1]
                or audit['nonceDigest'] != hashlib.sha256(
                    app_result['nonce'].encode()).hexdigest()
                or audit['appResultDigest'] != hashlib.sha256(json.dumps(
                    app_result, sort_keys=True,
                    separators=(',', ':')).encode()).hexdigest()
                or audit['targetPathDigest'] != hashlib.sha256(
                    b'/etc/cryptad-certification/restricted-provider.json').hexdigest()
                or any(not isinstance(proof, dict)
                    or set(proof) != worker_fields
                    or proof['kind'] !=
                        'pr315-installed-worker-synthetic-provider-control-v2'
                    or proof['jobAuthentication'] !=
                        'installed-policy-fixed-no-network-provider-stub'
                    or proof['ordinal'] != ordinal
                    or proof['workerSourceDigest'] != installed_worker_digest
                    or proof['credentialDigest'] != first['credentialDigest']
                    or proof['bundleIdentity'] != host['bundleIdentity']
                    # Registration authenticates cryptad-runner; the workload
                    # roster's runner identifies the separate vmadmin actor.
                    or proof['callerUid'] != installation.REFERENCE_RUNNER_UID
                    or any(re.fullmatch('[0-9a-f]{64}',
                        str(proof[key])) is None for key in (
                        'registrationDigest', 'resultDigest',
                        'handleDigest'))
                    or type(proof['startedMonotonicNs']) is not int
                    or type(proof['finishedMonotonicNs']) is not int
                    or not 0 < proof['startedMonotonicNs'] <
                        proof['finishedMonotonicNs']
                    for ordinal, proof in ((1, worker_before),
                                           (2, worker_after)))
                or worker_before['handleDigest'] == worker_after['handleDigest']
                or not worker_before['finishedMonotonicNs']
                    < first['observedMonotonicNs']
                or not last['observedMonotonicNs']
                    < worker_after['startedMonotonicNs']
                or app_result['targetPathDigest'] != audit['targetPathDigest']
                or app_result['outcome'] != audit['kernelOpenResult']
                or app_result['startedMonotonicNs'] != audit['attackStartedNs']
                or app_result['finishedMonotonicNs'] != audit['attackFinishedNs']
                or any(before[key] != after[key] for key in stable_actor)
                or before['role'] != 'candidate-sender'
                or before['managerInvocation'] != sender['invocationId']
                or before['hostPid'] != worker['hostPid']
                or before['startTicks'] != worker['startTicks']
                or before['hostPid'] != measured['hostPid']
                or before['startTicks'] != measured['startTicks']
                or before['hostPid'] != checkpoint['probeWorker']['hostPid']
                or before['startTicks'] != checkpoint['probeWorker']['startTicks']
                or before['sandboxLeader'] != worker['sandboxLeader']
                or before['cgroupIdentity'] != admin['cgroupIdentity']
                or fixtures.runtime.canonical_digest({
                    'role': 'candidate-sender',
                    'identity': before['cgroupIdentity']})[7:] != sender['cgroupDigest']
                or before['networkNamespaceIdentity'][1] != sender['networkNamespace']
                or audit['senderStateBefore'] != audit['senderStateAfter']
                or audit['senderStateBefore'] != before['stateDigest']
                or terminal['sentinel']['status'] != 'matched'
                or terminal['sentinel']['observedDigest'] !=
                    'sha256:' + audit['senderStateAfter']
                or any(first[key] != last[key] for key in stable_target)
                or first['role'] is not None
                or first['managerInvocation'] in {row['invocationId']
                    for row in result['roleKernelRoster']['roles']}
                or provider_group in {row['cgroupDigest']
                    for row in result['roleKernelRoster']['roles']}
                or first['bootId'].replace('-', '').lower() != sender['bootId']
                or first['mainPid'] <= 1 or first['mainStartTicks'] <= 0
                or audit['kernelOpenResult'] not in (
                    {'opened': False, 'errno': 'ENOENT'},
                    {'opened': False, 'errno': 'EACCES'},
                    {'opened': False, 'errno': 'EPERM'})
                or not first['observedMonotonicNs']
                    < before['observedMonotonicNs']
                    < audit['attackStartedNs'] < audit['attackFinishedNs']
                    < after['observedMonotonicNs']
                    < last['observedMonotonicNs']
                    < receipt['startedMonotonicNs']
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
        attack_digest = audit['appResultDigest']
        target = {'caseId': case_id,
            'target': acceptance.CASES[case_id].target,
            'role': None, 'invocationId': first['managerInvocation'],
            'cgroupDigest': provider_group, 'bootId': sender['bootId'],
            'probeDigest': '', 'controlResponseDigest': first['controlDigest']}
        code = audit['kernelOpenResult']['errno']
        witness = {'actorUid': sender['uid'], 'attackDigest': attack_digest,
            'attackStartedNs': audit['attackStartedNs'],
            'targetActiveBeforeNs': first['observedMonotonicNs'],
            'targetActiveAfterNs': last['observedMonotonicNs'],
            'controlResponseDigest': first['controlDigest'],
            'denialSource': 'kernel',
            'denialCode': 'policy-rejected' if code == 'ENOENT' else code,
            'unrelatedStateBefore': audit['senderStateBefore'],
            'unrelatedStateAfter': audit['senderStateAfter'],
            'targetIdentity': target}
        target['probeDigest'] = acceptance.payload_commitment(case_id, witness)
        spec = acceptance.CASES[case_id]
        observation = {'caseId': case_id, 'status': 'passed',
            'actor': spec.actor, 'target': spec.target, 'outcome': spec.outcome,
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
            'status': 'passed',
            'actorEpoch': {'kind': 'normally-signed-apphost-child',
                'uid': sender['uid'], 'hostPid': before['hostPid'],
                'startTicks': before['startTicks'],
                'namespacePids': before['namespacePids'],
                'sandboxLeader': before['sandboxLeader'],
                'bundleDigest': fixture['probeDigest'],
                'systemdInvocation': sender['invocationId'],
                'cgroupDigest': sender['cgroupDigest']},
            'targetEpoch': {'kind': 'installed-worker-synthetic-provider-credential',
                'bootId': sender['bootId'],
                'credentialIdentity': first['credentialIdentity'],
                'credentialDigest': first['credentialDigest'],
                'installedWorkerBefore': worker_before,
                'installedWorkerAfter': worker_after,
                'auxiliaryResolverEpoch': {
                    'systemdInvocation': first['managerInvocation'],
                    'cgroupDigest': provider_group,
                    'mainPid': first['mainPid'],
                    'mainStartTicks': first['mainStartTicks'],
                    'canaryIdentity': first['providerCanaryIdentity'],
                    'canaryDigest': first['controlDigest']}},
            'operationWindow': {'startedMonotonicNs': audit['attackStartedNs'],
                                'finishedMonotonicNs': audit['attackFinishedNs']},
            'attackDigest': attack_digest,
            'hostVerifiedIdentity': host, 'guestStopped': True,
            'stopReceiptObservedNs': receipt['observedMonotonicNs']}
        return identity, attempt, sidecar
    except (AttributeError, KeyError, TypeError, ValueError, IndexError,
            StopIteration, OSError):
        return None


def _sibling_app_attempt(report, result, fixture, terminal):
    """Bind a real signed AppHost SYN to active Mail and its own DROP counter."""
    case_id = 'sibling-app'
    try:
        if (not group_prepared(report, result, terminal, 'network-app')
                or fixture.get('schemaVersion') != 4
                or terminal['siblingAppAudit']['status'] != 'captured'
                or terminal['siblingAppResult']['status'] != 'captured'):
            return None
        normal = probe_denial_attempt(report, fixture, terminal)
        if normal is None:
            return None
        checked = acceptance.verify_attempts(normal[0], [normal[1]])
        if (checked['recordContractValid'] is not True
                or next(row['status'] for row in checked['cases']
                        if row['caseId'] == 'namespace-mount-escape') != 'passed'):
            return None
        audit = terminal['siblingAppAudit']['record']
        app_result = terminal['siblingAppResult']['record']
        admin = terminal['probeAdministratorRecord']['record']
        checkpoint = terminal['probeKernelCheckpoint']['record']
        sender, recipient = (next(row for row in result['roleKernelRoster']['roles']
                                  if row['role'] == role)
                             for role in ('candidate-sender', 'candidate-recipient'))
        before, after = audit['actorBefore'], audit['actorAfter']
        first, last = audit['targetBefore'], audit['targetAfter']
        counter_before, counter_after = audit['counterBefore'], audit['counterAfter']
        sender_receipt = terminal['stopReceipts']['candidate-sender']['current']['record']
        recipient_receipt = terminal['stopReceipts']['candidate-recipient']['current']['record']
        probe_worker = result['probeAppKernelProcess']
        mail_worker = result['recipientMailAppKernelProcess']
        host = report['hostVerifiedIdentity']
        stable_actor = ('role', 'hostPid', 'namespacePid', 'namespacePids',
            'startTicks', 'executableDigest', 'mountNamespaceIdentity',
            'outerMountNamespaceIdentity', 'userNamespaceIdentity',
            'pidNamespaceIdentity', 'managerInvocation', 'cgroupIdentity',
            'networkNamespaceIdentity', 'stateDigest', 'sandboxLeader',
            'provenance')
        stable_target = ('role', 'managerInvocation', 'bootId',
            'cgroupIdentity', 'workerHostPid', 'workerStartTicks',
            'javaHostPid', 'javaStartTicks', 'appUiOriginDigest')
        policy = hashlib.sha256(workload_network.role_rules(
            'candidate-sender').encode()).hexdigest()
        names = set(workload_network.SIBLING_DROP_COUNTERS.values())
        selected = workload_network.SIBLING_DROP_COUNTERS['sibling-app']
        target_digest = hashlib.sha256(b'10.231.0.2:19402').hexdigest()
        if (audit['schemaVersion'] != 1
                or audit['kind'] != 'pr315-administrator-sibling-app-denial'
                or audit['caseId'] != case_id
                or audit['bundleDigest'] != fixture['probeDigest']
                or admin['bundleDigest'] != fixture['probeDigest']
                or audit['actorUid'] != sender['uid']
                or app_result['uid'] != sender['uid']
                or app_result['gid'] != sender['gid']
                or app_result['pid'] != before['namespacePids'][-1]
                or audit['nonceDigest'] != hashlib.sha256(
                    app_result['nonce'].encode()).hexdigest()
                or audit['appResultDigest'] != hashlib.sha256(json.dumps(
                    app_result, sort_keys=True,
                    separators=(',', ':')).encode()).hexdigest()
                or audit['sourcePort'] != workload_network.SIBLING_APP_SOURCE_PORT
                or app_result['sourcePort'] != audit['sourcePort']
                or audit['targetEndpointDigest'] != target_digest
                or app_result['targetEndpointDigest'] != target_digest
                or app_result['outcome'] != audit['kernelConnectResult']
                or app_result['startedMonotonicNs'] != audit['attackStartedNs']
                or app_result['finishedMonotonicNs'] != audit['attackFinishedNs']
                or any(before[key] != after[key] for key in stable_actor)
                or before['role'] != 'candidate-sender'
                or before['hostPid'] != probe_worker['hostPid']
                or before['startTicks'] != probe_worker['startTicks']
                or before['hostPid'] != admin['worker']['hostPid']
                or before['startTicks'] != admin['worker']['startTicks']
                or before['hostPid'] != checkpoint['probeWorker']['hostPid']
                or before['sandboxLeader'] != probe_worker['sandboxLeader']
                or before['managerInvocation'] != sender['invocationId']
                or fixtures.runtime.canonical_digest({
                    'role': 'candidate-sender',
                    'identity': before['cgroupIdentity']})[7:] != sender['cgroupDigest']
                or before['networkNamespaceIdentity'][1] != sender['networkNamespace']
                or audit['senderStateBefore'] != audit['senderStateAfter']
                or audit['senderStateBefore'] != before['stateDigest']
                or terminal['sentinel']['status'] != 'matched'
                or terminal['sentinel']['observedDigest'] !=
                    'sha256:' + audit['senderStateAfter']
                or any(first[key] != last[key] for key in stable_target)
                or first['role'] != 'candidate-recipient'
                or first['managerInvocation'] != recipient['invocationId']
                or first['bootId'].replace('-', '').lower() != recipient['bootId']
                or fixtures.runtime.canonical_digest({
                    'role': 'candidate-recipient',
                    'identity': first['cgroupIdentity']})[7:] != recipient['cgroupDigest']
                or first['workerHostPid'] != mail_worker['hostPid']
                or first['workerStartTicks'] != mail_worker['startTicks']
                or first['javaHostPid'] != mail_worker['javaHostPid']
                or first['javaStartTicks'] != mail_worker['javaStartTicks']
                or first['appUiOriginDigest'] != result['recipientMailUiOriginDigest']
                or mail_worker['provenance'] != 'controller-kernel-sample'
                or first['workerHostPid'] <= 1 or first['workerStartTicks'] <= 0
                or first['controlDigest'] != last['controlDigest']
                or audit['counterName'] != selected
                or audit['kernelConnectResult'] not in (
                    {'connected': False, 'phase': 'connect', 'errno': 'ETIMEDOUT'},
                    {'connected': False, 'phase': 'connect', 'errno': 'EHOSTUNREACH'},
                    {'connected': False, 'phase': 'connect', 'errno': 'ENETUNREACH'},
                    {'connected': False, 'phase': 'connect', 'errno': 'EACCES'})
                or host['helperSourceCommit'] != result['identity']['sourceCommit']):
            return None
        for row in (counter_before, counter_after):
            if (row['schemaVersion'] != 1
                    or row['kind'] != 'pr315-fixed-sibling-drop-counters'
                    or row['policyDigest'] != policy
                    or row['roleNamespaceIdentity'] !=
                        before['networkNamespaceIdentity']
                    or row['bootId'].replace('-', '').lower() != sender['bootId']
                    or set(row['counters']) != names
                    or any(set(value) != {'packets', 'bytes'}
                           or any(type(value[key]) is not int or value[key] < 0
                                  for key in ('packets', 'bytes'))
                           for value in row['counters'].values())):
                return None
        old = counter_before['counters'][selected]
        new = counter_after['counters'][selected]
        if (not 1 <= new['packets'] - old['packets'] <= 8
                or not 1 <= new['bytes'] - old['bytes'] <= 8192
                or any(counter_before['counters'][name] != counter_after['counters'][name]
                       for name in names if name != selected)
                or not before['observedMonotonicNs']
                    < first['controlObservedNs']
                    < first['observedMonotonicNs']
                    < counter_before['observedMonotonicNs']
                    < audit['triggerMonotonicNs']
                    < audit['attackStartedNs'] < audit['attackFinishedNs']
                    < counter_after['observedMonotonicNs']
                    < after['observedMonotonicNs']
                    < last['controlObservedNs']
                    < last['observedMonotonicNs']
                    < recipient_receipt['startedMonotonicNs']
                or sender_receipt['managerInvocation'] != sender['invocationId']
                or recipient_receipt['managerInvocation'] != recipient['invocationId']
                or any(row['membership'] != 'only-stop-helper'
                       or row['descendantCgroups'] != 0
                       for row in (sender_receipt, recipient_receipt))):
            return None
        identity = {key: host[key] for key in ('helperSourceCommit',
            'helperSourceTree', 'bundleIdentity', 'testKitDigest',
            'profileDigest', 'bootClosureDigest', 'preparedImageDigest',
            'fixtureManifestDigest')}
        identity['productSelectionDigest'] = host['productDigest']
        identity['admittedAppDigest'] = fixture['mailDigest'][7:]
        attack_digest = audit['appResultDigest']
        target = {'caseId': case_id,
            'target': acceptance.CASES[case_id].target,
            'role': 'candidate-recipient',
            'invocationId': recipient['invocationId'],
            'cgroupDigest': recipient['cgroupDigest'],
            'bootId': recipient['bootId'], 'probeDigest': '',
            'controlResponseDigest': first['controlDigest']}
        code = audit['kernelConnectResult']['errno']
        witness = {'actorUid': sender['uid'], 'attackDigest': attack_digest,
            'attackStartedNs': audit['attackStartedNs'],
            'targetActiveBeforeNs': first['observedMonotonicNs'],
            'targetActiveAfterNs': last['observedMonotonicNs'],
            'controlResponseDigest': first['controlDigest'],
            'denialSource': 'kernel',
            'denialCode': 'policy-rejected' if code in
                ('ETIMEDOUT', 'EHOSTUNREACH', 'ENETUNREACH') else code,
            'unrelatedStateBefore': audit['senderStateBefore'],
            'unrelatedStateAfter': audit['senderStateAfter'],
            'targetIdentity': target}
        target['probeDigest'] = acceptance.payload_commitment(case_id, witness)
        spec = acceptance.CASES[case_id]
        observation = {'caseId': case_id, 'status': 'passed',
            'actor': spec.actor, 'target': spec.target, 'outcome': spec.outcome,
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
            'status': 'passed',
            'actorEpoch': {'kind': 'normally-signed-apphost-child',
                'uid': sender['uid'], 'hostPid': before['hostPid'],
                'startTicks': before['startTicks'],
                'namespacePids': before['namespacePids'],
                'sandboxLeader': before['sandboxLeader'],
                'bundleDigest': fixture['probeDigest'],
                'systemdInvocation': sender['invocationId'],
                'cgroupDigest': sender['cgroupDigest']},
            'targetEpoch': {'kind': 'active-recipient-mail-runtime-api',
                'role': 'candidate-recipient',
                'bootId': recipient['bootId'],
                'systemdInvocation': recipient['invocationId'],
                'cgroupDigest': recipient['cgroupDigest'],
                'installedAppDigest': fixture['mailDigest'][7:],
                'workerHostPid': first['workerHostPid'],
                'workerStartTicks': first['workerStartTicks'],
                'javaHostPid': first['javaHostPid'],
                'javaStartTicks': first['javaStartTicks'],
                'appUiOriginDigest': first['appUiOriginDigest'],
                'controlDigestBefore': first['controlDigest'],
                'controlDigestAfter': last['controlDigest']},
            'counterName': selected,
            'counterBefore': old, 'counterAfter': new,
            'operationWindow': {'startedMonotonicNs': audit['attackStartedNs'],
                                'finishedMonotonicNs': audit['attackFinishedNs']},
            'attackDigest': attack_digest,
            'hostVerifiedIdentity': host, 'guestStopped': True,
            'stopReceiptObservedNs': max(sender_receipt['observedMonotonicNs'],
                                        recipient_receipt['observedMonotonicNs'])}
        return identity, attempt, sidecar
    except (AttributeError, KeyError, TypeError, ValueError, IndexError,
            StopIteration, OSError):
        return None


def _resource_exhaustion_attempt(report, result, fixture, terminal, diagnostics,
                                 children):
    """Bind signed app pids.max pressure to live sibling FCP and exact cleanup."""
    case_id = 'resource-exhaustion'
    try:
        if (not group_prepared(report, result, terminal, case_id)
                or fixture.get('schemaVersion') != 4
                or not isinstance(diagnostics, dict)
                or diagnostics.get('resourceExhaustion', {}).get('status') != 'captured'
                or terminal['resourceAudit']['status'] != 'captured'
                or terminal['resourceAppReady']['status'] != 'captured'
                or terminal['resourceAppResult']['status'] != 'captured'):
            return None
        normal = probe_denial_attempt(report, fixture, terminal)
        if normal is None:
            return None
        checked = acceptance.verify_attempts(normal[0], [normal[1]])
        if (checked['recordContractValid'] is not True
                or next(row['status'] for row in checked['cases']
                        if row['caseId'] == 'namespace-mount-escape') != 'passed'):
            return None
        audit = terminal['resourceAudit']['record']
        ready = terminal['resourceAppReady']['record']
        app_result = terminal['resourceAppResult']['record']
        admin = terminal['probeAdministratorRecord']['record']
        checkpoint = terminal['probeKernelCheckpoint']['record']
        principals = result['roleKernelRoster']['roles']
        sender = next(row for row in principals if row['role'] == 'candidate-sender')
        before, after = audit['actorBefore'], audit['actorAfter']
        if not _resource_child_provenance(children, audit, before, sender['uid']):
            return None
        role_before, role_during, role_after = (audit[key] for key in
            ('roleBefore', 'roleDuring', 'roleAfter'))
        siblings_before, siblings_during, siblings_after = (audit[key] for key in
            ('siblingsBefore', 'siblingsDuring', 'siblingsAfter'))
        host = report['hostVerifiedIdentity']
        worker = result['probeAppKernelProcess']
        stable_actor = ('role', 'hostPid', 'namespacePid', 'namespacePids',
            'startTicks', 'executableDigest', 'mountNamespaceIdentity',
            'outerMountNamespaceIdentity', 'userNamespaceIdentity',
            'pidNamespaceIdentity', 'managerInvocation', 'cgroupIdentity',
            'networkNamespaceIdentity', 'stateDigest', 'sandboxLeader',
            'provenance')
        stable_role = ('role', 'managerInvocation', 'bootId', 'cgroupIdentity',
                       'pidsMax', 'memoryMaxBytes')
        audit_digest = hashlib.sha256(json.dumps(audit, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        if (audit['schemaVersion'] != 1
                or audit['kind'] != 'pr315-administrator-resource-exhaustion-denial'
                or audit['caseId'] != case_id
                or audit_digest != diagnostics['resourceExhaustion']['auditDigest']
                or audit['bundleDigest'] != fixture['probeDigest']
                or admin['bundleDigest'] != fixture['probeDigest']
                or audit['actorUid'] != sender['uid']
                or app_result['uid'] != sender['uid']
                or app_result['gid'] != sender['gid']
                or app_result['pid'] != before['namespacePids'][-1]
                or ready['pid'] != app_result['pid']
                or ready['uid'] != app_result['uid']
                or ready['nonce'] != app_result['nonce']
                or audit['nonceDigest'] != hashlib.sha256(
                    app_result['nonce'].encode()).hexdigest()
                or audit['ready'] != ready
                or audit['appResultDigest'] != hashlib.sha256(json.dumps(
                    app_result, sort_keys=True,
                    separators=(',', ':')).encode()).hexdigest()
                or app_result['forkErrno'] != 'EAGAIN'
                or ready['forkErrno'] != 'EAGAIN'
                or app_result['forkLimit'] != 600
                or not 1 <= app_result['spawnedCount'] <= 600
                or app_result['reapedCount'] != app_result['spawnedCount']
                or ready['spawnedCount'] != app_result['spawnedCount']
                or app_result['forcedKillCount'] != 0
                or app_result['abnormalExitCount'] != 0
                or app_result['startedMonotonicNs'] != ready['startedMonotonicNs']
                or app_result['finishedMonotonicNs'] != ready['limitReachedNs']
                or app_result['barrierReadyNs'] != ready['limitReachedNs']
                or audit['kernelLimit'] != 'pids.max'
                or audit['limitEventDelta'] !=
                    role_during['pidsMaxEvents'] - role_before['pidsMaxEvents']
                or audit['limitEventDelta'] < 1
                or any(before[key] != after[key] for key in stable_actor)
                or before['role'] != 'candidate-sender'
                or before['hostPid'] != worker['hostPid']
                or before['startTicks'] != worker['startTicks']
                or before['hostPid'] != admin['worker']['hostPid']
                or before['startTicks'] != admin['worker']['startTicks']
                or before['hostPid'] != checkpoint['probeWorker']['hostPid']
                or before['sandboxLeader'] != worker['sandboxLeader']
                or before['managerInvocation'] != sender['invocationId']
                or fixtures.runtime.canonical_digest({
                    'role': 'candidate-sender',
                    'identity': before['cgroupIdentity']})[7:] != sender['cgroupDigest']
                or before['networkNamespaceIdentity'][1] != sender['networkNamespace']
                or audit['senderStateBefore'] != audit['senderStateAfter']
                or audit['senderStateBefore'] != before['stateDigest']
                or terminal['sentinel']['status'] != 'matched'
                or terminal['sentinel']['observedDigest'] !=
                    'sha256:' + audit['senderStateAfter']
                or any(role_before[key] != role_during[key]
                       or role_before[key] != role_after[key]
                       for key in stable_role)
                or role_before['role'] != 'candidate-sender'
                or role_before['managerInvocation'] != sender['invocationId']
                or role_before['bootId'].replace('-', '').lower() != sender['bootId']
                or fixtures.runtime.canonical_digest({
                    'role': 'candidate-sender',
                    'identity': role_before['cgroupIdentity']})[7:] != sender['cgroupDigest']
                or any(row['pidsMax'] != 512
                       or row['memoryMaxBytes'] != 1024**3
                       for row in (role_before, role_during, role_after))
                or role_during['pidsCurrent'] < 504
                or role_after['pidsCurrent'] > role_before['pidsCurrent'] + 64
                or not role_before['memoryOomKills'] ==
                    role_during['memoryOomKills'] == role_after['memoryOomKills']
                or role_after['pidsMaxEvents'] < role_during['pidsMaxEvents']
                or audit['ready'] != ready
                or audit['attackStartedNs'] != app_result['startedMonotonicNs']
                or audit['attackFinishedNs'] != app_result['finishedMonotonicNs']
                or audit['childCleanupFinishedNs'] != app_result['cleanupFinishedNs']
                or not ready['limitReachedNs']
                    < audit['roleDuring']['observedMonotonicNs']
                    < audit['childEpochsObservedNs']
                    < audit['siblingsDuring'][0]['observedMonotonicNs']
                or not app_result['cleanupFinishedNs']
                    < after['observedMonotonicNs']
                    < audit['childExitObservedNs']
                or not before['observedMonotonicNs']
                    < role_before['observedMonotonicNs']
                    < siblings_before[-1]['controlObservedNs']
                    < audit['triggerMonotonicNs']
                    < ready['startedMonotonicNs']
                    < ready['limitReachedNs']
                    < role_during['observedMonotonicNs']
                    < siblings_during[0]['observedMonotonicNs']
                    < siblings_during[-1]['controlObservedNs']
                    < audit['releasePublishedNs']
                    < app_result['releaseObservedNs']
                    < app_result['cleanupFinishedNs']
                    < siblings_after[0]['observedMonotonicNs']
                    < role_after['observedMonotonicNs']
                    < after['observedMonotonicNs']
                or host['helperSourceCommit'] != result['identity']['sourceCommit']):
            return None
        if (not isinstance(siblings_before, list)
                or not isinstance(siblings_during, list)
                or not isinstance(siblings_after, list)
                or any(len(rows) != 3 for rows in
                       (siblings_before, siblings_during, siblings_after))):
            return None
        for previous, during, current in zip(
                siblings_before, siblings_during, siblings_after):
            role = previous['role']
            principal = next(row for row in principals if row['role'] == role)
            stable = ('role', 'managerInvocation', 'bootId',
                      'cgroupIdentity', 'stateDigest')
            if (role not in ('candidate-recipient', 'previous', 'relay-no-apps')
                    or any(previous[key] != during[key]
                           or previous[key] != current[key] for key in stable)
                    or previous['managerInvocation'] != principal['invocationId']
                    or previous['bootId'].replace('-', '').lower() != principal['bootId']
                    or fixtures.runtime.canonical_digest({
                        'role': role,
                        'identity': previous['cgroupIdentity']})[7:] !=
                        principal['cgroupDigest']
                    or any(re.fullmatch('[0-9a-f]{64}',
                       str(row['controlDigest'])) is None
                       for row in (previous, during, current))
                    or not previous['controlObservedNs']
                        < audit['triggerMonotonicNs']
                        < during['observedMonotonicNs']
                        < during['controlObservedNs']
                        < audit['releasePublishedNs']
                        < current['observedMonotonicNs']
                        < current['controlObservedNs']):
                return None
        if {row['role'] for row in siblings_before} != {
                'candidate-recipient', 'previous', 'relay-no-apps'}:
            return None
        receipts = [terminal['stopReceipts'][row['role']]['current']
                    for row in principals]
        if any(receipt['status'] != 'captured'
               or receipt['record']['managerInvocation'] != row['invocationId']
               or receipt['record']['membership'] != 'only-stop-helper'
               or receipt['record']['descendantCgroups'] != 0
               or receipt['record']['startedMonotonicNs'] <=
                    audit['childExitObservedNs']
               for receipt, row in zip(receipts, principals)):
            return None
        identity = {key: host[key] for key in ('helperSourceCommit',
            'helperSourceTree', 'bundleIdentity', 'testKitDigest',
            'profileDigest', 'bootClosureDigest', 'preparedImageDigest',
            'fixtureManifestDigest')}
        identity['productSelectionDigest'] = host['productDigest']
        identity['admittedAppDigest'] = fixture['probeDigest'][7:]
        attack_digest = audit['appResultDigest']
        controls_digest = hashlib.sha256(json.dumps(
            [row['controlDigest'] for row in siblings_during],
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        target = {'caseId': case_id,
                  'target': acceptance.CASES[case_id].target,
                  'role': 'candidate-sender',
                  'invocationId': sender['invocationId'],
                  'cgroupDigest': sender['cgroupDigest'],
                  'bootId': sender['bootId'], 'probeDigest': '',
                  'controlResponseDigest': controls_digest}
        witness = {'actorUid': sender['uid'], 'attackDigest': attack_digest,
                   'attackStartedNs': audit['attackStartedNs'],
                   'targetActiveBeforeNs': role_before['observedMonotonicNs'],
                   'targetActiveAfterNs': role_after['observedMonotonicNs'],
                   'controlResponseDigest': controls_digest,
                   'denialSource': 'kernel', 'denialCode': 'resource-limit',
                   'unrelatedStateBefore': audit['senderStateBefore'],
                   'unrelatedStateAfter': audit['senderStateAfter'],
                   'targetIdentity': target}
        target['probeDigest'] = acceptance.payload_commitment(case_id, witness)
        spec = acceptance.CASES[case_id]
        observation = {'caseId': case_id, 'status': 'passed',
            'actor': spec.actor, 'target': spec.target, 'outcome': spec.outcome,
            'startedMonotonicNs': role_before['observedMonotonicNs'],
            'finishedMonotonicNs': role_after['observedMonotonicNs'],
            'witness': witness}
        attempt = {'contract': acceptance.CONTRACT, 'identity': identity,
            'declaredCases': [case_id], 'observations': [observation],
            'guestStopped': True, 'attemptCompleted': True,
            'principals': result['roleKernelRoster'],
            'targets': {case_id: target}, 'caseCommitments': {},
            'appProcess': None, 'restartContext': None}
        sidecar = {'contract': campaign.CONTRACT, 'caseId': case_id,
            'status': 'passed',
            'actorEpoch': {'kind': 'normally-signed-apphost-child',
                'uid': sender['uid'], 'hostPid': before['hostPid'],
                'startTicks': before['startTicks'],
                'namespacePids': before['namespacePids'],
                'sandboxLeader': before['sandboxLeader'],
                'bundleDigest': fixture['probeDigest'],
                'systemdInvocation': sender['invocationId'],
                'cgroupDigest': sender['cgroupDigest']},
            'targetEpoch': {'kind': 'bounded-role-cgroup-pids-limit',
                'bootId': sender['bootId'],
                'systemdInvocation': sender['invocationId'],
                'cgroupDigest': sender['cgroupDigest'],
                'pidsMax': role_before['pidsMax'],
                'pidsMaxEventsBefore': role_before['pidsMaxEvents'],
                'pidsMaxEventsDuring': role_during['pidsMaxEvents'],
                'childEpochCount': audit['childEpochCount'],
                'childEpochDigest': audit['childEpochDigest'],
                'childExitObservedNs': audit['childExitObservedNs'],
                'siblingControlDigest': controls_digest},
            'operationWindow': {'startedMonotonicNs': audit['attackStartedNs'],
                                'finishedMonotonicNs': audit['childCleanupFinishedNs']},
            'attackDigest': attack_digest, 'hostVerifiedIdentity': host,
            'guestStopped': True,
            'stopReceiptObservedNs': max(row['record']['observedMonotonicNs']
                                          for row in receipts)}
        return identity, attempt, sidecar
    except (AttributeError, KeyError, TypeError, ValueError, IndexError,
            StopIteration, OSError):
        return None


def _output_artifact_attempt(report, result, fixture, terminal, source, case_id):
    """Bind one role-created artifact to the real bounded descriptor reader."""
    if case_id not in ('output-symlink', 'output-fifo',
                       'output-hardlink', 'output-flood', 'output-replacement'):
        return None
    try:
        field = {'output-symlink': 'outputSymlinkAudit',
                 'output-fifo': 'outputFifoAudit',
                 'output-hardlink': 'outputHardlinkAudit',
                 'output-flood': 'outputFloodAudit',
                 'output-replacement': 'outputReplacementAudit'}[case_id]
        if (not group_prepared(report, result, terminal, case_id)
                or fixture.get('schemaVersion') != 4
                or terminal[field]['status'] != 'captured'):
            return None
        audit = terminal[field]['record']
        sender = next(row for row in result['roleKernelRoster']['roles']
                      if row['role'] == 'candidate-sender')
        before, after = audit['actorBefore'], audit['actorAfter']
        collector, collector_after = audit['collectorBefore'], audit['collectorAfter']
        target_before, target_after = audit['targetBefore'], audit['targetAfter']
        receipt = terminal['stopReceipts']['candidate-sender']['current']['record']
        host = report['hostVerifiedIdentity']
        actor_stable = ('hostPid', 'hostParentPid', 'startTicks', 'namespacePids',
                        'pidNamespace', 'networkNamespaceIdentity',
                        'mountNamespaceIdentity', 'userNamespaceIdentity',
                        'executableDigest', 'noNewPrivileges',
                        'effectiveCapabilities')
        collector_stable = ('pid', 'uid', 'gid', 'startTicks', 'bootId', 'cgroupIdentity',
                            'namespaces', 'namespacePids',
                            'cgroupDigest', 'invocationId', 'sourceDigest')
        actor_group = fixtures.runtime.canonical_digest({
            'role': 'candidate-sender', 'identity': audit['actorCgroupBefore']})[7:]
        collector_group = fixtures.runtime.canonical_digest({
            'role': 'output-collector', 'identity': collector['cgroupIdentity']})[7:]
        collector_invocation = hashlib.sha256(json.dumps({
            'bootId': collector['bootId'], 'pid': collector['pid'],
            'startTicks': collector['startTicks'],
            'cgroupIdentity': collector['cgroupIdentity'],
            'sourceDigest': collector['sourceDigest']},
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:32]
        if (audit['schemaVersion'] != 1
                or audit['kind'] != 'pr315-administrator-' + case_id + '-denial'
                or audit['caseId'] != case_id
                or audit['sourceDigest'] != reference.sha256(source /
                    'tools/release-certification/restricted/pr315_role_probe.py')
                or audit['actorUid'] != sender['uid']
                or any(before[key] != after[key] for key in actor_stable)
                or before['hostPid'] <= 1 or before['startTicks'] <= 0
                or len(before['namespacePids']) < 2
                or before['networkNamespaceIdentity'][1] != sender['networkNamespace']
                or before['noNewPrivileges'] is not True
                or before['effectiveCapabilities'] != 0
                or audit['actorInvocationBefore'] != sender['invocationId']
                or audit['actorInvocationAfter'] != sender['invocationId']
                or audit['actorCgroupBefore'] != audit['actorCgroupAfter']
                or actor_group != sender['cgroupDigest']
                or audit['senderStateBefore'] != audit['senderStateAfter']
                or terminal['sentinel']['status'] != 'matched'
                or terminal['sentinel']['observedDigest'] !=
                    'sha256:' + audit['senderStateBefore']
                or any(collector[key] != collector_after[key]
                       for key in collector_stable)
                or collector['pid'] <= 1 or collector['uid'] != 0
                or collector['startTicks'] <= 0
                or collector['bootId'].replace('-', '').lower() != sender['bootId']
                or collector['sourceDigest'] != reference.sha256(source /
                    'tools/release-certification/restricted/pr314_workload_driver.py')
                or collector['cgroupDigest'] != collector_group
                or collector['invocationId'] != collector_invocation
                or collector['invocationId'] in {row['invocationId']
                    for row in result['roleKernelRoster']['roles']}
                or collector_group in {row['cgroupDigest']
                    for row in result['roleKernelRoster']['roles']}
                or target_before['controlDigest'] != target_after['controlDigest']
                or (case_id != 'output-hardlink' and
                    target_before['fileIdentity'] != target_after['fileIdentity'])
                or (case_id == 'output-hardlink' and
                    (target_before['fileIdentity'][:4] != target_after['fileIdentity'][:4]
                     or target_after['fileIdentity'][4] < target_before['fileIdentity'][4]
                     or type(target_before['linkCount']) is not int
                     or type(target_after['linkCount']) is not int
                     or target_before['linkCount'] != 1
                     or target_after['linkCount'] != 2
                     or audit['artifactIdentity'] != target_after['fileIdentity'][:2]))
                or not result['roleKernelRosterWindow']['finishedMonotonicNs']
                    < target_before['observedMonotonicNs']
                or not isinstance(target_before['fileIdentity'], list)
                or len(target_before['fileIdentity']) != 5
                or any(type(part) is not int or part < 0
                       for part in target_before['fileIdentity'])
                or re.fullmatch('[0-9a-f]{64}', target_before['controlDigest']) is None
                or audit['artifactOwnerUid'] != sender['uid']
                or not isinstance(audit['artifactIdentity'], list)
                or len(audit['artifactIdentity']) != 2
                or any(type(part) is not int or part <= 0
                       for part in audit['artifactIdentity'])
                or (case_id == 'output-symlink' and audit['linkTargetDigest'] !=
                    hashlib.sha256(b'/node/tmp/pr315-output-target-canary').hexdigest())
                or (case_id == 'output-fifo' and
                    (audit['artifactType'] != 'fifo' or audit['artifactMode'] != 0o600))
                or (case_id == 'output-hardlink' and
                    (audit['artifactType'] != 'hardlink'
                     or audit['artifactMode'] != 0o600
                     or audit['artifactLinkCount'] != 2))
                or (case_id == 'output-flood' and
                    (audit['artifactType'] != 'regular'
                     or audit['artifactMode'] != 0o600
                     or type(audit['artifactSize']) is not int
                     or audit['artifactSize'] != 65537
                     or audit['artifactDigest'] != hashlib.sha256(
                         b'F' * 65537).hexdigest()))
                or (case_id == 'output-replacement' and
                    (audit['artifactType'] != 'replacement'
                     or audit['artifactMode'] != 0o600
                     or not isinstance(audit['replacementIdentity'], list)
                     or len(audit['replacementIdentity']) != 2
                     or any(type(part) is not int or part <= 0
                            for part in audit['replacementIdentity'])
                     or audit['replacementIdentity'][0] != audit['artifactIdentity'][0]
                     or audit['replacementIdentity'][1] == audit['artifactIdentity'][1]
                     or audit['initialDigest'] != hashlib.sha256(b'A' * 32).hexdigest()
                     or audit['replacementDigest'] != hashlib.sha256(b'B' * 32).hexdigest()
                     or not audit['attackFinishedNs'] < audit['collectorStartedNs']
                         < audit['swapTriggerNs'] < audit['swapStartedNs']
                         < audit['swapFinishedNs'] < audit['collectorFinishedNs']))
                or audit['collectorDenial'] != ('workload-snapshot-changed'
                    if case_id == 'output-replacement' else 'workload-snapshot-file-invalid')
                or not target_before['observedMonotonicNs']
                    < collector['observedMonotonicNs'] < audit['triggerMonotonicNs']
                    < audit['attackStartedNs'] < audit['attackFinishedNs']
                    < audit['collectorStartedNs'] < audit['collectorFinishedNs']
                    < target_after['observedMonotonicNs']
                    < collector_after['observedMonotonicNs']
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
                  'role': None, 'invocationId': collector_invocation,
                  'cgroupDigest': collector_group, 'bootId': sender['bootId'],
                  'probeDigest': '',
                  'controlResponseDigest': target_before['controlDigest']}
        witness = {'actorUid': sender['uid'], 'attackDigest': attack_digest,
                   'attackStartedNs': audit['attackStartedNs'],
                   'targetActiveBeforeNs': collector['observedMonotonicNs'],
                   'targetActiveAfterNs': collector_after['observedMonotonicNs'],
                   'controlResponseDigest': target_before['controlDigest'],
                   'denialSource': 'controller', 'denialCode': 'policy-rejected',
                   'unrelatedStateBefore': audit['senderStateBefore'],
                   'unrelatedStateAfter': audit['senderStateAfter'],
                   'targetIdentity': target}
        target['probeDigest'] = acceptance.payload_commitment(case_id, witness)
        case = acceptance.CASES[case_id]
        observation = {'caseId': case_id, 'status': 'passed', 'actor': case.actor,
                       'target': case.target, 'outcome': case.outcome,
                       'startedMonotonicNs': collector['observedMonotonicNs'],
                       'finishedMonotonicNs': collector_after['observedMonotonicNs'],
                       'witness': witness}
        attempt = {'contract': acceptance.CONTRACT, 'identity': identity,
                   'declaredCases': [case_id], 'observations': [observation],
                   'guestStopped': True, 'attemptCompleted': True,
                   'principals': result['roleKernelRoster'], 'targets': {case_id: target},
                   'caseCommitments': {}, 'appProcess': None, 'restartContext': None}
        sidecar = {'contract': campaign.CONTRACT, 'caseId': case_id,
                   'status': 'passed', 'actorEpoch': _v9_actor_epoch(before, sender),
                   'targetEpoch': {'kind': 'administrator-descriptor-collector',
                                   'bootId': sender['bootId'],
                                   'testKitInvocation': collector_invocation,
                                   'systemdInvocation': None,
                                   'pid': collector['pid'], 'uid': collector['uid'],
                                   'gid': collector['gid'],
                                   'namespaces': collector['namespaces'],
                                   'namespacePids': collector['namespacePids'],
                                   'startTicks': collector['startTicks'],
                                   'cgroupDigest': collector_group,
                                   'canaryDigestBefore': target_before['controlDigest'],
                                   'canaryDigestAfter': target_after['controlDigest'],
                                   'artifactIdentity': audit['artifactIdentity']},
                   'operationWindow': {'startedMonotonicNs': audit['attackStartedNs'],
                                       'finishedMonotonicNs': audit['collectorFinishedNs']},
                   'attackDigest': attack_digest, 'hostVerifiedIdentity': host,
                   'guestStopped': True,
                   'stopReceiptObservedNs': receipt['observedMonotonicNs']}
        if case_id == 'output-fifo':
            sidecar['targetEpoch']['artifactType'] = 'fifo'
            sidecar['targetEpoch']['artifactMode'] = audit['artifactMode']
        if case_id == 'output-hardlink':
            sidecar['targetEpoch']['artifactType'] = 'hardlink'
            sidecar['targetEpoch']['artifactMode'] = audit['artifactMode']
            sidecar['targetEpoch']['artifactLinkCount'] = audit['artifactLinkCount']
        if case_id == 'output-flood':
            sidecar['targetEpoch']['artifactType'] = 'regular'
            sidecar['targetEpoch']['artifactMode'] = audit['artifactMode']
            sidecar['targetEpoch']['artifactSize'] = audit['artifactSize']
            sidecar['targetEpoch']['artifactDigest'] = audit['artifactDigest']
        if case_id == 'output-replacement':
            sidecar['targetEpoch']['artifactType'] = 'replacement'
            sidecar['targetEpoch']['artifactMode'] = audit['artifactMode']
            sidecar['targetEpoch']['replacementIdentity'] = audit['replacementIdentity']
            sidecar['targetEpoch']['initialDigest'] = audit['initialDigest']
            sidecar['targetEpoch']['replacementDigest'] = audit['replacementDigest']
            sidecar['targetEpoch']['swapTriggerNs'] = audit['swapTriggerNs']
            sidecar['targetEpoch']['swapFinishedNs'] = audit['swapFinishedNs']
        return identity, attempt, sidecar
    except (AttributeError, KeyError, TypeError, ValueError, IndexError, StopIteration,
            OSError):
        return None


def _host_network_attempt(report, result, fixture, terminal, source):
    """Bind an actual role SYN and DROP to a live guest host-namespace canary."""
    case_id = 'host-network'
    try:
        if (not group_prepared(report, result, terminal, 'network-app')
                or fixture.get('schemaVersion') != 4
                or terminal['hostNetworkAudit']['status'] != 'captured'):
            return None
        audit = terminal['hostNetworkAudit']['record']
        sender = next(row for row in result['roleKernelRoster']['roles']
                      if row['role'] == 'candidate-sender')
        before, after = audit['actorBefore'], audit['actorAfter']
        first, last = audit['targetBefore'], audit['targetAfter']
        counter_before, counter_after = audit['counterBefore'], audit['counterAfter']
        host = report['hostVerifiedIdentity']
        receipt = terminal['stopReceipts']['candidate-sender']['current']['record']
        counter_name = workload_network.SIBLING_DROP_COUNTERS[case_id]
        policy = hashlib.sha256(workload_network.role_rules(
            'candidate-sender').encode()).hexdigest()
        endpoint = hashlib.sha256((workload_network.HOST_CANARY_ADDRESS + ':' +
            str(workload_network.HOST_CANARY_PORT)).encode()).hexdigest()
        source_digest = reference.sha256(source /
            'tools/release-certification/restricted/pr314_workload_driver.py')
        source_probe = reference.sha256(source /
            'tools/release-certification/restricted/pr315_role_probe.py')
        target_group = fixtures.runtime.canonical_digest({
            'role': 'guest-host-canary',
            'identity': first['cgroupIdentity']})[7:]
        target_invocation = hashlib.sha256(json.dumps({
            'bootId': first['bootId'], 'pid': first['pid'],
            'startTicks': first['startTicks'],
            'cgroupIdentity': first['cgroupIdentity'],
            'sourceDigest': source_digest},
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:32]
        stable_actor = ('hostPid', 'hostParentPid', 'startTicks',
            'namespacePids', 'pidNamespace', 'networkNamespaceIdentity',
            'mountNamespaceIdentity', 'userNamespaceIdentity',
            'executableDigest', 'noNewPrivileges', 'effectiveCapabilities')
        stable_target = ('pid', 'uid', 'startTicks', 'bootId',
            'cgroupIdentity', 'networkNamespace', 'initNetworkNamespace',
            'addressBinding', 'sourceDigest',
            'invocationId', 'controlDigest')
        expected_control = hashlib.sha256(
            b'pr315-host-probe\0pr315-host-ready').hexdigest()
        if (audit['schemaVersion'] != 1
                or audit['kind'] != 'pr315-administrator-host-network-denial'
                or audit['caseId'] != case_id
                or audit['sourceDigest'] != source_probe
                or audit['actorUid'] != sender['uid']
                or any(before[key] != after[key] for key in stable_actor)
                or before['hostPid'] <= 1 or before['startTicks'] <= 0
                or len(before['namespacePids']) < 2
                or before['networkNamespaceIdentity'][1] != sender['networkNamespace']
                or before['noNewPrivileges'] is not True
                or before['effectiveCapabilities'] != 0
                or audit['senderInvocationBefore'] != sender['invocationId']
                or audit['senderInvocationAfter'] != sender['invocationId']
                or audit['senderCgroupBefore'] != audit['senderCgroupAfter']
                or fixtures.runtime.canonical_digest({'role': 'candidate-sender',
                    'identity': audit['senderCgroupBefore']})[7:] != sender['cgroupDigest']
                or audit['senderStateBefore'] != audit['senderStateAfter']
                or terminal['sentinel']['status'] != 'matched'
                or terminal['sentinel']['observedDigest'] !=
                    'sha256:' + audit['senderStateBefore']
                or any(first[key] != last[key] for key in stable_target)
                or first['pid'] <= 1 or first['uid'] != 0
                or first['startTicks'] <= 0
                or first['sourceDigest'] != source_digest
                or first['invocationId'] != target_invocation
                or first['bootId'].replace('-', '').lower() != sender['bootId']
                or first['networkNamespace'] == sender['networkNamespace']
                or first['networkNamespace'] != first['initNetworkNamespace']
                or not isinstance(first['addressBinding'], dict)
                or set(first['addressBinding']) != {'ifindex', 'ifname', 'address'}
                or type(first['addressBinding']['ifindex']) is not int
                or first['addressBinding']['ifindex'] <= 0
                or re.fullmatch('[a-zA-Z0-9_.-]{1,15}',
                    str(first['addressBinding']['ifname'])) is None
                or first['addressBinding']['address'] !=
                    workload_network.HOST_CANARY_ADDRESS
                or first['controlDigest'] != expected_control
                or target_group in {row['cgroupDigest']
                                    for row in result['roleKernelRoster']['roles']}
                or audit['targetEndpointDigest'] != endpoint
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
                    or set(row['counters']) != names):
                return None
        old = counter_before['counters'][counter_name]
        new = counter_after['counters'][counter_name]
        if (not 1 <= new['packets'] - old['packets'] <= 8
                or not 1 <= new['bytes'] - old['bytes'] <= 8192
                or any(counter_before['counters'][name] !=
                       counter_after['counters'][name]
                       for name in names if name != counter_name)
                or not first['observedMonotonicNs']
                    < counter_before['observedMonotonicNs']
                    < audit['triggerMonotonicNs']
                    < audit['attackStartedNs'] < audit['attackFinishedNs']
                    < counter_after['observedMonotonicNs']
                    < last['observedMonotonicNs']
                    < receipt['startedMonotonicNs']
                or receipt['managerInvocation'] != sender['invocationId']
                or receipt['membership'] != 'only-stop-helper'
                or receipt['descendantCgroups'] != 0):
            return None
        identity = {key: host[key] for key in ('helperSourceCommit',
            'helperSourceTree', 'bundleIdentity', 'testKitDigest',
            'profileDigest', 'bootClosureDigest', 'preparedImageDigest',
            'fixtureManifestDigest')}
        identity['productSelectionDigest'] = host['productDigest']
        identity['admittedAppDigest'] = fixture['mailDigest'][7:]
        attack_digest = hashlib.sha256(json.dumps(audit, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        target = {'caseId': case_id,
            'target': acceptance.CASES[case_id].target,
            'role': None, 'invocationId': target_invocation,
            'cgroupDigest': target_group, 'bootId': sender['bootId'],
            'probeDigest': '', 'controlResponseDigest': expected_control}
        witness = {'actorUid': sender['uid'], 'attackDigest': attack_digest,
            'attackStartedNs': audit['attackStartedNs'],
            'targetActiveBeforeNs': first['observedMonotonicNs'],
            'targetActiveAfterNs': last['observedMonotonicNs'],
            'controlResponseDigest': expected_control,
            'denialSource': 'kernel', 'denialCode': 'policy-rejected',
            'unrelatedStateBefore': audit['senderStateBefore'],
            'unrelatedStateAfter': audit['senderStateAfter'],
            'targetIdentity': target}
        target['probeDigest'] = acceptance.payload_commitment(case_id, witness)
        spec = acceptance.CASES[case_id]
        observation = {'caseId': case_id, 'status': 'passed',
            'actor': spec.actor, 'target': spec.target, 'outcome': spec.outcome,
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
            'targetEpoch': {'kind': 'active-guest-host-namespace-canary',
                'pid': first['pid'], 'uid': first['uid'],
                'startTicks': first['startTicks'],
                'bootId': sender['bootId'],
                'testKitInvocation': target_invocation,
                'cgroupDigest': target_group,
                'networkNamespace': first['networkNamespace'],
                'controlDigestBefore': first['controlDigest'],
                'controlDigestAfter': last['controlDigest']},
            'counterName': counter_name,
            'counterBefore': counter_before,
            'counterAfter': counter_after,
            'operationWindow': {'startedMonotonicNs': audit['attackStartedNs'],
                                'finishedMonotonicNs': audit['attackFinishedNs']},
            'attackDigest': attack_digest,
            'hostVerifiedIdentity': host, 'guestStopped': True,
            'stopReceiptObservedNs': receipt['observedMonotonicNs']}
        return identity, attempt, sidecar
    except (AttributeError, KeyError, TypeError, ValueError, IndexError,
            StopIteration, OSError):
        return None
