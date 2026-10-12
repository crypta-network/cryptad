#!/usr/bin/python3
"""Fixed test-kit fault emitters for real PR-315 role, output and lifecycle cases.

The administrator driver retains its public facade. These measured helpers
resolve current driver hooks at call time, so offline patches and installed
source identity remain bound to the same implementation epoch.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import select
import socket
import stat
import subprocess
import time

import pr314_workload_driver as driver


def _cgroup_control_digest(*args, **kwargs):
    return driver._cgroup_control_digest(*args, **kwargs)


def _fixed_role_target(*args, **kwargs):
    return driver._fixed_role_target(*args, **kwargs)


def _observer_canary_control(*args, **kwargs):
    return driver._observer_canary_control(*args, **kwargs)


def _publish_output_trigger(*args, **kwargs):
    return driver._publish_output_trigger(*args, **kwargs)


def _resolver_target_control(*args, **kwargs):
    return driver._resolver_target_control(*args, **kwargs)


def _role_probe_actor(*args, **kwargs):
    return driver._role_probe_actor(*args, **kwargs)


def _staged_package_digest(*args, **kwargs):
    return driver._staged_package_digest(*args, **kwargs)


def _validate_false_role_claims(*args, **kwargs):
    return driver._validate_false_role_claims(*args, **kwargs)


def _validate_fixed_role_accesses(*args, **kwargs):
    return driver._validate_fixed_role_accesses(*args, **kwargs)


def _validate_resolver_read(*args, **kwargs):
    return driver._validate_resolver_read(*args, **kwargs)


def _validate_role_probe_result(*args, **kwargs):
    return driver._validate_role_probe_result(*args, **kwargs)


def _validate_role_probe_write(*args, **kwargs):
    return driver._validate_role_probe_write(*args, **kwargs)


def _wait_output_record(*args, **kwargs):
    return driver._wait_output_record(*args, **kwargs)


def probe_sibling_network(*args, **kwargs):
    return driver.probe_sibling_network(*args, **kwargs)


def _administrator_collector_epoch(*args, **kwargs):
    return driver._administrator_collector_epoch(*args, **kwargs)


def _output_canary_control(*args, **kwargs):
    return driver._output_canary_control(*args, **kwargs)


def _mail_browser_control(*args, **kwargs):
    return driver._mail_browser_control(*args, **kwargs)


def _validate_hostile_origin(*args, **kwargs):
    return driver._validate_hostile_origin(*args, **kwargs)


def _partial_role_projection(*args, **kwargs):
    return driver._partial_role_projection(*args, **kwargs)


def _positive_observer_epoch(*args, **kwargs):
    return driver._positive_observer_epoch(*args, **kwargs)


def collect_child(*args, **kwargs):
    return driver.collect_child(*args, **kwargs)


def stop_child(*args, **kwargs):
    return driver.stop_child(*args, **kwargs)


def _provider_app_actor(*args, **kwargs):
    return driver._provider_app_actor(*args, **kwargs)


def _resource_cgroup_control(*args, **kwargs):
    return driver._resource_cgroup_control(*args, **kwargs)


def _resource_child_epochs(*args, **kwargs):
    return driver._resource_child_epochs(*args, **kwargs)


def _resource_children_exited(*args, **kwargs):
    return driver._resource_children_exited(*args, **kwargs)


def _resource_sibling_controls(*args, **kwargs):
    return driver._resource_sibling_controls(*args, **kwargs)


def _begin_installed_observer_stop(*args, **kwargs):
    return driver._begin_installed_observer_stop(*args, **kwargs)


def _finish_installed_observer_stop(*args, **kwargs):
    return driver._finish_installed_observer_stop(*args, **kwargs)


def _begin_cleanup_race_stop(*args, **kwargs):
    return driver._begin_cleanup_race_stop(*args, **kwargs)


def _stale_handle_controller_epoch(*args, **kwargs):
    return driver._stale_handle_controller_epoch(*args, **kwargs)


def _setsid_process_epoch(*args, **kwargs):
    return driver._setsid_process_epoch(*args, **kwargs)


def _stale_pid_observer_process(*args, **kwargs):
    return driver._stale_pid_observer_process(*args, **kwargs)


def _stale_pid_observer_reply(*args, **kwargs):
    return driver._stale_pid_observer_reply(*args, **kwargs)


def _installed_observer_stop(*args, **kwargs):
    return driver._installed_observer_stop(*args, **kwargs)



def probe_observer_private_read(workload, handoff, observer, source_digest,
                                sibling_digest, resolver_digest,
                                campaign_deadline_ns, case_group=None):
    """Measure a real role child opening an active observer-owned canary."""
    if case_group not in (None, 'role-boundary'):
        raise ValueError('workload-role-probe-group-invalid')
    role_boundary = case_group == 'role-boundary'
    actor_case = 'role-boundary' if role_boundary else 'observer-private-read'
    if time.monotonic_ns() >= campaign_deadline_ns:
        raise ValueError('workload-role-probe-campaign-expired')
    canary = Path('/var/lib/cryptad-cross-version/experiments/pr315-installed-workload/observer-private-canary')
    data = secrets.token_bytes(32)
    descriptor = os.open(canary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
        os.fchown(descriptor, observer.pw_uid, observer.pw_gid)
    finally:
        os.close(descriptor)
    expected = hashlib.sha256(data).hexdigest()
    if _observer_canary_control(canary, observer) != expected:
        raise ValueError('workload-observer-private-control-mismatch')
    nonce = secrets.token_hex(32)
    launch = workload.read(workload.ROOT / 'roles/candidate-sender/launch.json')
    request = {'schemaVersion': 1, 'caseId': actor_case, 'nonce': nonce,
               'bootId': workload.boot(), 'javaDigest': launch['javaDigest'],
               'sourceDigest': source_digest}
    workload.write(workload.ROOT / 'probe-requests/candidate-sender.json',
                   request, create=True, mode=0o444)
    role = 'candidate-sender'
    uid = workload.account(role).pw_uid
    probe_root = workload.ROOT / 'state/candidate-sender/tmp'
    ready_path = probe_root / ('pr315-role-boundary-ready.json' if role_boundary
                               else 'pr315-observer-private-read-ready.json')
    result_path = probe_root / ('pr315-role-boundary.json' if role_boundary
                                else 'pr315-observer-private-read.json')
    until = min(time.monotonic() + 25, campaign_deadline_ns / 1e9)
    ready = _wait_output_record(ready_path, uid, until,
                                'workload-role-probe-ready-timeout')
    if (not isinstance(ready, dict) or set(ready) != {
            'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'startedMonotonicNs'}
            or ready['schemaVersion'] != 1 or ready['kind'] != 'pr315-candidate-role-probe-ready'
            or ready['caseId'] != actor_case or ready['nonce'] != nonce):
        raise ValueError('workload-role-probe-ready-invalid')
    before = workload.observe(handoff['handles'][role])
    actor_before = _role_probe_actor(before, nonce, actor_case)
    if ready['pid'] != actor_before['namespacePids'][-1]:
        raise ValueError('workload-role-probe-pid-unbound')
    target_before = _observer_canary_control(canary, observer)
    if target_before != expected:
        raise ValueError('workload-role-probe-target-changed')
    sibling_path = workload.ROOT / 'state/candidate-recipient' / driver.SIBLING_CANARY
    recipient_user = workload.account('candidate-recipient')
    recipient_before = workload.observe(handoff['handles']['candidate-recipient'])
    sibling_before = _observer_canary_control(
        sibling_path, recipient_user, 'workload-sibling-data-control-failed')
    package_before = _staged_package_digest(workload)
    resolver_before = None if role_boundary else _resolver_target_control(resolver_digest)
    if sibling_before != sibling_digest:
        raise ValueError('workload-sibling-data-target-changed')
    trigger_ns = time.monotonic_ns()
    trigger_name = ('pr315-role-boundary-trigger.json' if role_boundary
                    else 'pr315-observer-private-read-trigger.json')
    _publish_output_trigger(probe_root, trigger_name, actor_case, nonce)
    result = _wait_output_record(result_path, uid, until,
                                 'workload-role-probe-result-timeout')
    resolver_after = None if role_boundary else _resolver_target_control(resolver_digest)
    after = workload.observe(handoff['handles'][role])
    actor_after = _role_probe_actor(after, nonce, actor_case)
    target_after = _observer_canary_control(canary, observer)
    recipient_after = workload.observe(handoff['handles']['candidate-recipient'])
    sibling_after = _observer_canary_control(
        sibling_path, recipient_user, 'workload-sibling-data-control-failed')
    package_after = _staged_package_digest(workload)
    _validate_role_probe_result(ready, before, actor_before, after, actor_after,
                                result, expected, target_after, nonce, trigger_ns)
    audit = {'schemaVersion': 1, 'kind': 'pr315-administrator-observer-private-read',
             'caseId': 'observer-private-read', 'sourceDigest': source_digest,
             'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
             'actorUid': uid,
             'actorBefore': actor_before, 'actorAfter': actor_after,
             'roleInvocationBefore': before['managerInvocation'],
             'roleInvocationAfter': after['managerInvocation'],
             'targetDigestBefore': target_before, 'targetDigestAfter': target_after,
             'triggerMonotonicNs': trigger_ns,
             'attackStartedNs': result['startedMonotonicNs'],
             'attackFinishedNs': result['finishedMonotonicNs'],
             'kernelOpenResult': result['outcome'],
             'controllerObservedBeforeNs': before['observedMonotonicNs'],
             'controllerObservedAfterNs': after['observedMonotonicNs']}
    workload.write(workload.ROOT / 'authority/observer-private-read-denial.json', audit, create=True)
    write = _validate_role_probe_write(result, after)
    write_audit = {**audit, 'kind': 'pr315-administrator-observer-private-write',
                   'caseId': 'observer-private-write',
                   'attackStartedNs': write['startedMonotonicNs'],
                   'attackFinishedNs': write['finishedMonotonicNs'],
                   'kernelOpenResult': write['outcome']}
    workload.write(workload.ROOT / 'authority/observer-private-write-denial.json',
                   write_audit, create=True)
    if role_boundary:
        if (recipient_before['managerInvocation'] != recipient_after['managerInvocation']
                or recipient_before['cgroupIdentity'] != recipient_after['cgroupIdentity']
                or sibling_before != sibling_digest or sibling_after != sibling_digest):
            raise ValueError('workload-sibling-data-target-changed')
        if package_before != package_after:
            raise ValueError('workload-package-target-changed')
        if before['cgroupIdentity'] != after['cgroupIdentity']:
            raise ValueError('workload-cgroup-target-changed')
        accesses = _validate_fixed_role_accesses(result, after, role_boundary=True)
        target_map = {
            'sibling-data': ('candidate-recipient', recipient_before, recipient_after,
                             sibling_before, sibling_after),
            'package-expectation': ('candidate-sender', before, after,
                                    package_before, package_after),
            'cgroup-migration': ('candidate-recipient', recipient_before, recipient_after,
                                 _cgroup_control_digest(recipient_before),
                                 _cgroup_control_digest(recipient_after))}
        fixed_audits = {}
        for selected_case, row in accesses.items():
            target_role, first, last, control_before, control_after = target_map[selected_case]
            target_first = _fixed_role_target(target_role, first, control_before)
            target_last = _fixed_role_target(target_role, last, control_after)
            if target_first['controlDigest'] != target_last['controlDigest']:
                raise ValueError('workload-' + selected_case + '-target-changed')
            fixed_audit = {'schemaVersion': 1,
                'kind': 'pr315-administrator-fixed-role-access-denial',
                'caseId': selected_case, 'sourceDigest': source_digest,
                'nonceDigest': audit['nonceDigest'], 'actorUid': uid,
                'actorBefore': actor_before, 'actorAfter': actor_after,
                'actorInvocationBefore': before['managerInvocation'],
                'actorInvocationAfter': after['managerInvocation'],
                'actorCgroupBefore': before['cgroupIdentity'],
                'actorCgroupAfter': after['cgroupIdentity'],
                'targetBefore': target_first, 'targetAfter': target_last,
                'attackStartedNs': row['startedMonotonicNs'],
                'attackFinishedNs': row['finishedMonotonicNs'],
                'kernelOpenResult': row['outcome'], 'writtenBytes': row['writtenBytes']}
            workload.write(workload.ROOT / 'authority' /
                           (selected_case + '-denial.json'), fixed_audit, create=True)
            fixed_audits[selected_case] = hashlib.sha256(json.dumps(fixed_audit,
                sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        return {'status': 'captured', 'caseId': 'role-boundary',
                'auditDigest': hashlib.sha256(json.dumps(audit, sort_keys=True,
                    separators=(',', ':')).encode()).hexdigest(),
                'writeStatus': 'captured',
                'writeAuditDigest': hashlib.sha256(json.dumps(write_audit,
                    sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                'fixedAccessAudits': fixed_audits}
    identity, counters = _validate_false_role_claims(result, before, after,
                                                     actor_before, uid)
    claim_base = {'schemaVersion': 1, 'sourceDigest': source_digest,
                  'nonceDigest': audit['nonceDigest'], 'actorUid': uid,
                  'actorBefore': actor_before, 'actorAfter': actor_after,
                  'roleInvocationBefore': before['managerInvocation'],
                  'roleInvocationAfter': after['managerInvocation'],
                  'cgroupIdentityBefore': before['cgroupIdentity'],
                  'cgroupIdentityAfter': after['cgroupIdentity'],
                  'targetActiveBeforeNs': before['observedMonotonicNs'],
                  'targetActiveAfterNs': after['observedMonotonicNs'],
                  'denial': 'kernel-mismatch-observed'}
    identity_audit = {**claim_base,
        'kind': 'pr315-administrator-forged-runtime-identity',
        'caseId': 'forged-runtime-identity',
        'attackStartedNs': identity['startedMonotonicNs'],
        'attackFinishedNs': identity['finishedMonotonicNs'],
        'claimedHostPid': identity['claimedHostPid'],
        'claimedHostUid': identity['claimedHostUid'],
        'actualHostPid': actor_before['hostPid'], 'actualHostUid': uid}
    workload.write(workload.ROOT / 'authority/forged-runtime-identity-denial.json',
                   identity_audit, create=True)
    counter_audit = {**claim_base, 'kind': 'pr315-administrator-forged-counters',
        'caseId': 'forged-counters',
        'attackStartedNs': counters['startedMonotonicNs'],
        'attackFinishedNs': counters['finishedMonotonicNs'],
        'claimedMemoryCurrentBytes': counters['claimedMemoryCurrentBytes'],
        'claimedTasksCurrent': counters['claimedTasksCurrent'],
        'actualMemoryBefore': before['cgroupMemoryBytes'],
        'actualTasksBefore': before['cgroupTasks'],
        'actualMemoryAfter': after['cgroupMemoryBytes'],
        'actualTasksAfter': after['cgroupTasks']}
    workload.write(workload.ROOT / 'authority/forged-counters-denial.json',
                   counter_audit, create=True)
    if (recipient_before['managerInvocation'] != recipient_after['managerInvocation']
            or recipient_before['cgroupIdentity'] != recipient_after['cgroupIdentity']
            or sibling_before != sibling_digest or sibling_after != sibling_digest):
        raise ValueError('workload-sibling-data-target-changed')
    if package_before != package_after:
        raise ValueError('workload-package-target-changed')
    if before['cgroupIdentity'] != after['cgroupIdentity']:
        raise ValueError('workload-cgroup-target-changed')
    accesses = _validate_fixed_role_accesses(result, after)
    resolver_read = _validate_resolver_read(
        result, before, after, resolver_before, resolver_after)
    fixed_audits = {}
    target_map = {
        'sibling-data': ('candidate-recipient', recipient_before, recipient_after,
                         sibling_before, sibling_after),
        'package-expectation': ('candidate-sender', before, after,
                                package_before, package_after),
        'cgroup-migration': ('candidate-recipient', recipient_before, recipient_after,
                             _cgroup_control_digest(recipient_before),
                             _cgroup_control_digest(recipient_after))}
    for case_id, row in accesses.items():
        target_role, first, last, control_before, control_after = target_map[case_id]
        target_first = _fixed_role_target(target_role, first, control_before)
        target_last = _fixed_role_target(target_role, last, control_after)
        if target_first['controlDigest'] != target_last['controlDigest']:
            raise ValueError('workload-' + case_id + '-target-changed')
        fixed_audit = {'schemaVersion': 1,
            'kind': 'pr315-administrator-fixed-role-access-denial', 'caseId': case_id,
            'sourceDigest': source_digest, 'nonceDigest': audit['nonceDigest'],
            'actorUid': uid, 'actorBefore': actor_before, 'actorAfter': actor_after,
            'actorInvocationBefore': before['managerInvocation'],
            'actorInvocationAfter': after['managerInvocation'],
            'actorCgroupBefore': before['cgroupIdentity'],
            'actorCgroupAfter': after['cgroupIdentity'],
            'targetBefore': target_first, 'targetAfter': target_last,
            'attackStartedNs': row['startedMonotonicNs'],
            'attackFinishedNs': row['finishedMonotonicNs'],
            'kernelOpenResult': row['outcome'], 'writtenBytes': row['writtenBytes']}
        workload.write(workload.ROOT / 'authority' / (case_id + '-denial.json'),
                       fixed_audit, create=True)
        fixed_audits[case_id] = hashlib.sha256(json.dumps(fixed_audit,
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    resolver_audit = {'schemaVersion': 1,
        'kind': 'pr315-administrator-resolver-authority-denial',
        'caseId': 'resolver-authority', 'sourceDigest': source_digest,
        'nonceDigest': audit['nonceDigest'], 'actorUid': uid,
        'actorBefore': actor_before, 'actorAfter': actor_after,
        'actorInvocationBefore': before['managerInvocation'],
        'actorInvocationAfter': after['managerInvocation'],
        'actorCgroupBefore': before['cgroupIdentity'],
        'actorCgroupAfter': after['cgroupIdentity'],
        'actorStateBefore': before['stateDigest'],
        'actorStateAfter': after['stateDigest'],
        'targetBefore': resolver_before, 'targetAfter': resolver_after,
        'targetPathDigest': resolver_read['targetPathDigest'],
        'attackStartedNs': resolver_read['startedMonotonicNs'],
        'attackFinishedNs': resolver_read['finishedMonotonicNs'],
        'kernelOpenResult': resolver_read['outcome']}
    workload.write(workload.ROOT / 'authority/resolver-authority-denial.json',
                   resolver_audit, create=True)
    resolver_audit_digest = hashlib.sha256(json.dumps(resolver_audit,
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    network_audits = probe_sibling_network(
        workload, handoff, nonce, source_digest, campaign_deadline_ns)
    return {'status': 'captured', 'caseId': 'observer-private-read',
            'auditDigest': hashlib.sha256(json.dumps(audit, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest(),
            'writeStatus': 'captured',
            'writeAuditDigest': hashlib.sha256(json.dumps(write_audit, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest(),
            'identityStatus': 'captured',
            'identityAuditDigest': hashlib.sha256(json.dumps(identity_audit, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest(),
            'counterStatus': 'captured',
            'counterAuditDigest': hashlib.sha256(json.dumps(counter_audit, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest(),
            'fixedAccessAudits': fixed_audits,
            'resolverAuditDigest': resolver_audit_digest,
            'networkAudits': network_audits}


def _probe_output_artifact(workload, handoff, source_digest, campaign_deadline_ns, case_id):
    """Trigger one fixed role-created object and the installed descriptor reader."""
    import runtime_snapshot as snapshot
    if case_id not in driver.OUTPUT_ARTIFACTS:
        raise ValueError('workload-output-case-invalid')
    artifact_name, ready_name, trigger_name, result_name = driver.OUTPUT_ARTIFACTS[case_id]
    role = 'candidate-sender'
    uid = workload.account(role).pw_uid
    gid = workload.account(role).pw_gid
    root = workload.ROOT / 'state/candidate-sender/tmp'
    canary = root / driver.OUTPUT_CANARY
    raw = secrets.token_bytes(32)
    fd = os.open(canary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchown(fd, uid, gid)
        if os.write(fd, raw) != len(raw):
            raise ValueError('workload-' + case_id + '-target-invalid')
        os.fsync(fd)
    finally:
        os.close(fd)
    digest = hashlib.sha256(raw).hexdigest()
    nonce = secrets.token_hex(32)
    launch = workload.read(workload.ROOT / 'roles/candidate-sender/launch.json')
    workload.write(workload.ROOT / 'probe-requests/candidate-sender.json',
        {'schemaVersion': 1, 'caseId': case_id, 'nonce': nonce,
         'bootId': workload.boot(), 'javaDigest': launch['javaDigest'],
         'sourceDigest': source_digest}, create=True, mode=0o444)
    ready_path = root / ready_name
    until = min(time.monotonic() + 25, campaign_deadline_ns / 1e9)
    ready = _wait_output_record(ready_path, uid, until,
                                'workload-' + case_id + '-ready-timeout')
    if (not isinstance(ready, dict) or set(ready) != {
            'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'startedMonotonicNs'}
            or ready['schemaVersion'] != 1
            or ready['kind'] != 'pr315-candidate-role-probe-ready'
            or ready['caseId'] != case_id or ready['nonce'] != nonce):
        raise ValueError('workload-' + case_id + '-actor-invalid')
    handle = handoff['handles'][role]
    before = workload.observe(handle)
    actor_before = _role_probe_actor(before, nonce, case_id)
    if ready['pid'] != actor_before['namespacePids'][-1]:
        raise ValueError('workload-' + case_id + '-actor-invalid')
    target_before = _output_canary_control(root, uid, digest, case_id)
    collector_before = _administrator_collector_epoch(case_id)
    trigger_ns = time.monotonic_ns()
    _publish_output_trigger(root, trigger_name, case_id, nonce)
    result_path = root / result_name
    result = _wait_output_record(result_path, uid, until,
                                 'workload-' + case_id + '-result-timeout')
    artifact = root / artifact_name
    info = artifact.lstat()
    if (info.st_uid != uid
            or info.st_nlink != (2 if case_id == 'output-hardlink' else 1)
            or (case_id == 'output-symlink' and
                (not stat.S_ISLNK(info.st_mode)
                 or os.readlink(artifact) != '/node/tmp/' + driver.OUTPUT_CANARY))
            or (case_id == 'output-fifo' and
                (not stat.S_ISFIFO(info.st_mode) or info.st_mode & 0o777 != 0o600))
            or (case_id == 'output-hardlink' and
                (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o777 != 0o600
                 or [info.st_dev, info.st_ino] != target_before['fileIdentity'][:2]))
            or (case_id == 'output-flood' and
                (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o777 != 0o600
                 or info.st_size != driver.OUTPUT_FLOOD_BYTES))
            or (case_id == 'output-replacement' and
                (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o777 != 0o600
                 or info.st_size != 32))):
        raise ValueError('workload-' + case_id + '-target-invalid')
    flood_digest = None
    initial_digest = None
    if case_id == 'output-flood':
        controlled = snapshot.read_file(root, artifact_name,
                                        maximum=driver.OUTPUT_FLOOD_BYTES, timeout=2)
        if controlled != b'F' * driver.OUTPUT_FLOOD_BYTES:
            raise ValueError('workload-output-flood-target-invalid')
        flood_digest = hashlib.sha256(controlled).hexdigest()
    if case_id == 'output-replacement':
        controlled = snapshot.read_file(root, artifact_name, maximum=32, timeout=2)
        if controlled != b'A' * 32:
            raise ValueError('workload-output-replacement-target-invalid')
        initial_digest = hashlib.sha256(controlled).hexdigest()
    swap_record = None
    swap_trigger_ns = None

    def after_pin():
        nonlocal swap_record, swap_trigger_ns
        swap_trigger_ns = time.monotonic_ns()
        _publish_output_trigger(root, driver.OUTPUT_REPLACEMENT_SWAP_TRIGGER, case_id, nonce)
        swap_path = root / driver.OUTPUT_REPLACEMENT_SWAP_RESULT
        swap_until = min(time.monotonic() + 20, campaign_deadline_ns / 1e9)
        swap_record = _wait_output_record(swap_path, uid, swap_until,
                                          'workload-output-replacement-swap-timeout')
        if (not isinstance(swap_record, dict) or set(swap_record) != {
                'schemaVersion', 'kind', 'caseId', 'nonce', 'pid',
                'startedMonotonicNs', 'finishedMonotonicNs'}
                or swap_record['schemaVersion'] != 1
                or swap_record['kind'] != 'pr315-candidate-output-replacement-swap'
                or swap_record['caseId'] != case_id or swap_record['nonce'] != nonce
                or swap_record['pid'] != actor_before['namespacePids'][-1]
                or not swap_trigger_ns < swap_record['startedMonotonicNs']
                    < swap_record['finishedMonotonicNs']):
            raise ValueError('workload-output-replacement-actor-invalid')
    started = time.monotonic_ns()
    try:
        snapshot.read_file(root, artifact_name, maximum=64,
            timeout=25 if case_id == 'output-replacement' else 2,
            pinned_hook=after_pin if case_id == 'output-replacement' else None)
    except snapshot.SnapshotError as error:
        denial = str(error)
    else:
        raise ValueError('workload-' + case_id + '-collector-invalid')
    finished = time.monotonic_ns()
    info_after = artifact.lstat()
    stable_file = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink',
                   'st_size', 'st_mtime_ns', 'st_ctime_ns')
    replacement_digest = None
    if case_id == 'output-replacement':
        if (info_after.st_dev != info.st_dev or info_after.st_ino == info.st_ino
                or not stat.S_ISREG(info_after.st_mode) or info_after.st_uid != uid
                or info_after.st_mode & 0o777 != 0o600
                or info_after.st_nlink != 1 or info_after.st_size != 32):
            raise ValueError('workload-output-replacement-target-invalid')
        controlled = snapshot.read_file(root, artifact_name, maximum=32, timeout=2)
        if controlled != b'B' * 32:
            raise ValueError('workload-output-replacement-target-invalid')
        replacement_digest = hashlib.sha256(controlled).hexdigest()
    elif any(getattr(info, key) != getattr(info_after, key) for key in stable_file):
        raise ValueError('workload-' + case_id + '-target-invalid')
    target_after = _output_canary_control(root, uid, digest, case_id,
        expected_links=2 if case_id == 'output-hardlink' else 1)
    collector_after = _administrator_collector_epoch(case_id)
    after = workload.observe(handle)
    actor_after = _role_probe_actor(after, nonce, case_id)
    stable_actor = ('hostPid', 'hostParentPid', 'startTicks', 'namespacePids',
                    'pidNamespace', 'networkNamespaceIdentity',
                    'mountNamespaceIdentity', 'userNamespaceIdentity',
                    'executableDigest', 'noNewPrivileges', 'effectiveCapabilities')
    stable_collector = ('pid', 'uid', 'startTicks', 'bootId', 'cgroupIdentity',
                        'cgroupDigest', 'invocationId', 'sourceDigest')
    if (not isinstance(result, dict) or set(result) != ({
            'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'uid', 'gid',
            'startedMonotonicNs', 'finishedMonotonicNs',
            'artifactPathDigest', 'targetPathDigest'} |
            ({'writtenBytes'} if case_id == 'output-flood' else set()))
            or result['schemaVersion'] != 1
            or result['kind'] != 'pr315-candidate-' + case_id
            or result['caseId'] != case_id or result['nonce'] != nonce
            or result['pid'] != actor_before['namespacePids'][-1]
            or result['uid'] != uid or result['gid'] != gid
            or result['artifactPathDigest'] != hashlib.sha256(
                os.fsencode(Path('/node/tmp') / artifact_name)).hexdigest()
            or result['targetPathDigest'] != hashlib.sha256(
                b'/node/tmp/pr315-output-target-canary').hexdigest()
            or (case_id == 'output-flood' and result['writtenBytes'] != driver.OUTPUT_FLOOD_BYTES)
            or denial != ('workload-snapshot-changed' if case_id == 'output-replacement'
                          else 'workload-snapshot-file-invalid')
            or any(actor_before[key] != actor_after[key] for key in stable_actor)
            or any(collector_before[key] != collector_after[key]
                   for key in stable_collector)
            or before['managerInvocation'] != after['managerInvocation']
            or before['cgroupIdentity'] != after['cgroupIdentity']
            or re.fullmatch('[0-9a-f]{64}', str(before['stateDigest'])) is None
            or before['stateDigest'] != after['stateDigest']
            or target_before['controlDigest'] != target_after['controlDigest']
            or (case_id != 'output-hardlink' and
                target_before['fileIdentity'] != target_after['fileIdentity'])
            or (case_id == 'output-hardlink' and
                (target_before['fileIdentity'][:4] != target_after['fileIdentity'][:4]
                 or target_after['fileIdentity'][4] < target_before['fileIdentity'][4]
                 or target_before['linkCount'] != 1 or target_after['linkCount'] != 2
                 or [info.st_dev, info.st_ino] != target_after['fileIdentity'][:2]))
            or (case_id == 'output-replacement' and
                (not isinstance(swap_record, dict) or swap_trigger_ns is None
                 or not result['finishedMonotonicNs'] < started
                    < swap_trigger_ns < swap_record['startedMonotonicNs']
                    < swap_record['finishedMonotonicNs'] < finished))
            or not before['observedMonotonicNs'] < target_before['observedMonotonicNs']
                < collector_before['observedMonotonicNs'] < trigger_ns
                < result['startedMonotonicNs'] < result['finishedMonotonicNs']
                < started < finished < target_after['observedMonotonicNs']
                < collector_after['observedMonotonicNs'] < after['observedMonotonicNs']):
        raise ValueError('workload-' + case_id + '-collector-invalid')
    audit = {'schemaVersion': 1,
        'kind': 'pr315-administrator-' + case_id + '-denial',
        'caseId': case_id, 'sourceDigest': source_digest,
        'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
        'actorUid': uid, 'actorBefore': actor_before, 'actorAfter': actor_after,
        'actorInvocationBefore': before['managerInvocation'],
        'actorInvocationAfter': after['managerInvocation'],
        'actorCgroupBefore': before['cgroupIdentity'],
        'actorCgroupAfter': after['cgroupIdentity'],
        'senderStateBefore': before['stateDigest'],
        'senderStateAfter': after['stateDigest'],
        'collectorBefore': collector_before, 'collectorAfter': collector_after,
        'collectorStartedNs': started, 'collectorFinishedNs': finished,
        'collectorDenial': denial, 'targetBefore': target_before,
        'targetAfter': target_after,
        'artifactIdentity': [info.st_dev, info.st_ino],
        'artifactOwnerUid': uid,
        'triggerMonotonicNs': trigger_ns,
        'attackStartedNs': result['startedMonotonicNs'],
        'attackFinishedNs': result['finishedMonotonicNs']}
    if case_id == 'output-symlink':
        audit['linkTargetDigest'] = hashlib.sha256(
            b'/node/tmp/pr315-output-target-canary').hexdigest()
    elif case_id == 'output-fifo':
        audit['artifactType'] = 'fifo'
        audit['artifactMode'] = info.st_mode & 0o777
    elif case_id == 'output-replacement':
        audit['artifactType'] = 'replacement'
        audit['artifactMode'] = info.st_mode & 0o777
        audit['replacementIdentity'] = [info_after.st_dev, info_after.st_ino]
        audit['initialDigest'] = initial_digest
        audit['replacementDigest'] = replacement_digest
        audit['swapTriggerNs'] = swap_trigger_ns
        audit['swapStartedNs'] = swap_record['startedMonotonicNs']
        audit['swapFinishedNs'] = swap_record['finishedMonotonicNs']
    else:
        audit['artifactType'] = 'hardlink' if case_id == 'output-hardlink' else 'regular'
        audit['artifactMode'] = info.st_mode & 0o777
        if case_id == 'output-hardlink':
            audit['artifactLinkCount'] = info.st_nlink
        else:
            audit['artifactSize'] = info.st_size
            audit['artifactDigest'] = flood_digest
    workload.write(workload.ROOT / 'authority' / (case_id + '-denial.json'),
                   audit, create=True)
    return hashlib.sha256(json.dumps(audit, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()


def probe_authority_claims(workload, handoff, source_digest, resolver_digest,
                           campaign_deadline_ns, hostile_secret=None,
                           expected_mail_worker=None):
    """Bind one fixed candidate authority probe to the live resolver and kernel."""
    if time.monotonic_ns() >= campaign_deadline_ns:
        raise ValueError('workload-role-probe-campaign-expired')
    if (not isinstance(hostile_secret, dict)
            or set(hostile_secret) != {'session', 'expectedOrigin'}
            or not isinstance(hostile_secret['session'], str)
            or not 1 <= len(hostile_secret['session']) <= 4096
            or not isinstance(hostile_secret['expectedOrigin'], str)
            or re.fullmatch(r'http://127\.0\.0\.1:[1-9][0-9]{3,4}',
                            hostile_secret['expectedOrigin']) is None):
        raise ValueError('workload-hostile-origin-session-unavailable')
    case_id = 'authority'
    nonce = secrets.token_hex(32)
    role = 'candidate-sender'
    launch = workload.read(workload.ROOT / 'roles/candidate-sender/launch.json')
    workload.write(workload.ROOT / 'probe-requests/candidate-sender.json',
        {'schemaVersion': 1, 'caseId': case_id, 'nonce': nonce,
         'bootId': workload.boot(), 'javaDigest': launch['javaDigest'],
         'sourceDigest': source_digest}, create=True, mode=0o444)
    account = workload.account(role)
    probe_root = workload.ROOT / 'state/candidate-sender/tmp'
    until = min(time.monotonic() + 45, campaign_deadline_ns / 1e9)
    ready = _wait_output_record(probe_root / 'pr315-authority-ready.json',
        account.pw_uid, until, 'workload-role-probe-ready-timeout')
    if (not isinstance(ready, dict) or set(ready) != {
            'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'startedMonotonicNs'}
            or ready['schemaVersion'] != 1
            or ready['kind'] != 'pr315-candidate-role-probe-ready'
            or ready['caseId'] != case_id or ready['nonce'] != nonce):
        raise ValueError('workload-role-probe-ready-invalid')
    handle = handoff['handles'][role]
    before = workload.observe(handle)
    actor_before = _role_probe_actor(before, nonce, case_id)
    if ready['pid'] != actor_before['namespacePids'][-1]:
        raise ValueError('workload-role-probe-pid-unbound')
    input_path = probe_root / 'pr315-hostile-origin-input.json'
    input_bytes = json.dumps({'caseId': 'hostile-app-origin', 'nonce': nonce,
        'session': hostile_secret['session'],
        'expectedOrigin': hostile_secret['expectedOrigin']},
        sort_keys=True, separators=(',', ':')).encode()
    if not 0 < len(input_bytes) <= 8192:
        raise ValueError('workload-hostile-origin-input-limit')
    descriptor = os.open(input_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchown(descriptor, account.pw_uid, account.pw_gid)
        if os.write(descriptor, input_bytes) != len(input_bytes):
            raise ValueError('workload-hostile-origin-input-short-write')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    input_digest = hashlib.sha256(input_bytes).hexdigest()
    try:
        resolver_before = _resolver_target_control(resolver_digest)
        mail_before = _mail_browser_control(workload, handoff,
            hostile_secret['session'], hostile_secret['expectedOrigin'],
            expected_mail_worker)
        trigger_ns = time.monotonic_ns()
        _publish_output_trigger(probe_root, 'pr315-authority-trigger.json', case_id, nonce)
        result = _wait_output_record(probe_root / 'pr315-authority.json',
            account.pw_uid, until, 'workload-role-probe-result-timeout')
        resolver_after = _resolver_target_control(resolver_digest)
        mail_after = _mail_browser_control(workload, handoff,
            hostile_secret['session'], hostile_secret['expectedOrigin'],
            expected_mail_worker)
    finally:
        input_path.unlink(missing_ok=True)
    after = workload.observe(handle)
    actor_after = _role_probe_actor(after, nonce, case_id)
    stable_actor = ('hostPid', 'hostParentPid', 'startTicks', 'namespacePids',
                    'pidNamespace', 'networkNamespaceIdentity',
                    'mountNamespaceIdentity', 'userNamespaceIdentity',
                    'executableDigest', 'noNewPrivileges', 'effectiveCapabilities')
    if (not isinstance(result, dict) or set(result) != {
            'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'uid', 'gid',
            'startedMonotonicNs', 'finishedMonotonicNs', 'identityClaim',
            'counterClaim', 'resolverRead', 'hostileOrigin'}
            or result['schemaVersion'] != 1
            or result['kind'] != 'pr315-candidate-authority-probe'
            or result['caseId'] != case_id or result['nonce'] != nonce
            or result['pid'] != actor_before['namespacePids'][-1]
            or result['uid'] != account.pw_uid or result['gid'] != account.pw_gid
            or any(actor_before[key] != actor_after[key] for key in stable_actor)
            or actor_before['noNewPrivileges'] is not True
            or actor_before['effectiveCapabilities'] != 0
            or before['managerInvocation'] != after['managerInvocation']
            or before['cgroupIdentity'] != after['cgroupIdentity']
            or before['stateDigest'] != after['stateDigest']
            or not ready['startedMonotonicNs'] < before['observedMonotonicNs']
                < resolver_before['observedMonotonicNs'] < trigger_ns
                < result['startedMonotonicNs'] < result['finishedMonotonicNs']
                < resolver_after['observedMonotonicNs']
                < mail_after['observedMonotonicNs'] < after['observedMonotonicNs']):
        raise ValueError('workload-authority-actor-or-window-invalid')
    identity, counters = _validate_false_role_claims(result, before, after,
        actor_before, account.pw_uid, authority_only=True)
    resolver_read = _validate_resolver_read(
        result, before, after, resolver_before, resolver_after)
    hostile = _validate_hostile_origin(result['hostileOrigin'], hostile_secret,
        mail_before, mail_after, trigger_ns)
    if not (counters['finishedMonotonicNs'] < resolver_read['startedMonotonicNs']
            < resolver_read['finishedMonotonicNs']
            < hostile['before']['startedMonotonicNs']
            < hostile['after']['finishedMonotonicNs']
            < result['finishedMonotonicNs']):
        raise ValueError('workload-authority-operation-order-invalid')
    nonce_digest = hashlib.sha256(nonce.encode()).hexdigest()
    claim_base = {'schemaVersion': 1, 'sourceDigest': source_digest,
                  'nonceDigest': nonce_digest, 'actorUid': account.pw_uid,
                  'actorBefore': actor_before, 'actorAfter': actor_after,
                  'roleInvocationBefore': before['managerInvocation'],
                  'roleInvocationAfter': after['managerInvocation'],
                  'cgroupIdentityBefore': before['cgroupIdentity'],
                  'cgroupIdentityAfter': after['cgroupIdentity'],
                  'targetActiveBeforeNs': before['observedMonotonicNs'],
                  'targetActiveAfterNs': after['observedMonotonicNs'],
                  'denial': 'kernel-mismatch-observed'}
    identity_audit = {**claim_base,
        'kind': 'pr315-administrator-forged-runtime-identity',
        'caseId': 'forged-runtime-identity',
        'attackStartedNs': identity['startedMonotonicNs'],
        'attackFinishedNs': identity['finishedMonotonicNs'],
        'claimedHostPid': identity['claimedHostPid'],
        'claimedHostUid': identity['claimedHostUid'],
        'actualHostPid': actor_before['hostPid'],
        'actualHostUid': account.pw_uid}
    counter_audit = {**claim_base,
        'kind': 'pr315-administrator-forged-counters',
        'caseId': 'forged-counters',
        'attackStartedNs': counters['startedMonotonicNs'],
        'attackFinishedNs': counters['finishedMonotonicNs'],
        'claimedMemoryCurrentBytes': counters['claimedMemoryCurrentBytes'],
        'claimedTasksCurrent': counters['claimedTasksCurrent'],
        'actualMemoryBefore': before['cgroupMemoryBytes'],
        'actualTasksBefore': before['cgroupTasks'],
        'actualMemoryAfter': after['cgroupMemoryBytes'],
        'actualTasksAfter': after['cgroupTasks']}
    resolver_audit = {'schemaVersion': 1,
        'kind': 'pr315-administrator-resolver-authority-denial',
        'caseId': 'resolver-authority', 'sourceDigest': source_digest,
        'nonceDigest': nonce_digest, 'actorUid': account.pw_uid,
        'actorBefore': actor_before, 'actorAfter': actor_after,
        'actorInvocationBefore': before['managerInvocation'],
        'actorInvocationAfter': after['managerInvocation'],
        'actorCgroupBefore': before['cgroupIdentity'],
        'actorCgroupAfter': after['cgroupIdentity'],
        'actorStateBefore': before['stateDigest'],
        'actorStateAfter': after['stateDigest'],
        'targetBefore': resolver_before, 'targetAfter': resolver_after,
        'targetPathDigest': resolver_read['targetPathDigest'],
        'attackStartedNs': resolver_read['startedMonotonicNs'],
        'attackFinishedNs': resolver_read['finishedMonotonicNs'],
        'kernelOpenResult': resolver_read['outcome']}
    hostile_audit = {'schemaVersion': 1,
        'kind': 'pr315-administrator-hostile-app-origin-denial',
        'caseId': 'hostile-app-origin', 'sourceDigest': source_digest,
        'nonceDigest': nonce_digest, 'actorUid': account.pw_uid,
        'actorBefore': actor_before, 'actorAfter': actor_after,
        'actorInvocationBefore': before['managerInvocation'],
        'actorInvocationAfter': after['managerInvocation'],
        'actorCgroupBefore': before['cgroupIdentity'],
        'actorCgroupAfter': after['cgroupIdentity'],
        'actorStateBefore': before['stateDigest'],
        'actorStateAfter': after['stateDigest'],
        'targetBefore': mail_before, 'targetAfter': mail_after,
        'inputDigest': input_digest,
        'sessionDigest': hostile['sessionDigest'],
        'expectedOriginDigest': hostile['expectedOriginDigest'],
        'hostileOriginDigest': hostile['hostileOriginDigest'],
        'targetEndpointDigest': hostile['endpointDigest'],
        'controlBefore': hostile['before'], 'controlAfter': hostile['after'],
        'attackStartedNs': hostile['attack']['startedMonotonicNs'],
        'attackFinishedNs': hostile['attack']['finishedMonotonicNs'],
        'attackResponseDigest': hostile['attack']['responseDigest'],
        'denialStatus': hostile['attack']['status'],
        'denialCode': hostile['attack']['errorCode']}
    for audit in (identity_audit, counter_audit, resolver_audit, hostile_audit):
        workload.write(workload.ROOT / 'authority' /
            (audit['caseId'] + '-denial.json'), audit, create=True)
    return {'identityAuditDigest': hashlib.sha256(json.dumps(identity_audit,
                sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'counterAuditDigest': hashlib.sha256(json.dumps(counter_audit,
                sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'resolverAuditDigest': hashlib.sha256(json.dumps(resolver_audit,
                sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'hostileOriginAuditDigest': hashlib.sha256(json.dumps(hostile_audit,
                sort_keys=True, separators=(',', ':')).encode()).hexdigest()}


def probe_partial_launch(workload, handoff, result, observer_uid,
                         campaign_deadline_ns):
    """Retain bounded failure phases without changing the installed operation."""
    from pr315_partial_launch_diagnostics import Trace
    trace = Trace(workload, campaign_deadline_ns)
    try:
        return _probe_partial_launch(workload, handoff, result, observer_uid,
                                     campaign_deadline_ns, trace)
    except Exception as error:
        try:
            trace.capture(error)
        except Exception:
            pass
        raise


def _probe_partial_launch(workload, handoff, result, observer_uid,
                          campaign_deadline_ns, trace):
    """Fail previous after its real start marker while two roles remain live."""
    import restricted_workload_launcher as launcher
    from pr315_partial_start_transport import POLICY, start, finish

    if (result.get('groupPreparation') != 'partial-launch'
            or result.get('topologyRoles') != 2
            or [row['role'] for row in result.get('partialRoleRoster', [])]
                != ['candidate-sender', 'candidate-recipient']):
        raise ValueError('workload-partial-launch-preparation-invalid')
    administrator_before = _administrator_collector_epoch('partial-launch')
    trace.administrator = administrator_before
    trace.step('sibling-controls')
    sender = _partial_role_projection(workload, handoff['handles']['candidate-sender'])
    recipient = _partial_role_projection(workload, handoff['handles']['candidate-recipient'])
    root = workload.ROOT
    previous = workload.read(root / 'authority/previous.json')
    relay = workload.read(root / 'authority/relay-no-apps.json')
    previous_state = workload.manager('previous', 'show')
    relay_state = workload.manager('relay-no-apps', 'show')
    if (any(row.get('state') != 'prepared' or row.get('generation') is not None
            or row.get('managerInvocation') is not None for row in (previous, relay))
            or any(row['ActiveState'] != 'inactive' or row['MainPID'] != '0'
                   for row in (previous_state, relay_state))
            or os.path.lexists(root / 'authority/previous-start.json')
            or os.path.lexists(root / 'authority/relay-no-apps-start.json')):
        raise ValueError('workload-partial-launch-roles-not-prepared')
    spec = workload.read(root / 'roles/previous/launch.json')
    nonce = secrets.token_hex(32)
    source_digest = hashlib.sha256(Path(launcher.__file__).read_bytes()).hexdigest()
    trace.step('request-publication')
    workload.write(launcher.PARTIAL_LAUNCH_REQUEST,
        {'schemaVersion': 1, 'caseId': 'partial-launch', 'nonce': nonce,
         'bootId': workload.boot(), 'javaDigest': spec['javaDigest'],
         'sourceDigest': source_digest}, create=True, mode=0o444)
    ready_ns = time.monotonic_ns()
    previous_uid = workload.account('previous').pw_uid
    observer = pwd.getpwnam('cryptad-soak')
    if observer.pw_uid != observer_uid or observer_uid <= 0:
        raise ValueError('workload-partial-launch-observer-invalid')
    trace.step('observer-start')
    trace.step('start-response')
    parent, pid, response, response_started_ns, response_ns = start(
        driver, observer, handoff['handles']['previous'], campaign_deadline_ns)
    actor = None
    observer_actor = None
    released_ns = None
    sample_error = None
    try:
        until = min(time.monotonic() + 9, campaign_deadline_ns / 1e9)
        fault_wait_started_ns = time.monotonic_ns()
        trace.step('fault-sampling', wait_until_ns=int(until * 1e9))
        fault = _wait_output_record(launcher.PARTIAL_LAUNCH_RECORD,
            previous_uid, until, 'workload-partial-launch-fault-timeout')
        marker = workload.read(root / 'authority/previous-start.json')
        current = workload.read(root / 'authority/previous.json')
        info = workload.group('previous').stat()
        actor = workload._process(fault['pid'], 'previous', previous_uid)
        actor['cgroupIdentity'] = [info.st_dev, info.st_ino]
        actor['observedMonotonicNs'] = time.monotonic_ns()
        trace.step('observer-sampling')
        observer_actor = _positive_observer_epoch(
            pid, observer_uid, campaign_deadline_ns)
        if (not isinstance(fault, dict) or set(fault) != {
                'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'uid',
                'startTicks', 'sourceDigest', 'observedMonotonicNs'}
                or fault['schemaVersion'] != 1
                or fault['kind'] != 'pr315-previous-launch-fault'
                or fault['caseId'] != 'partial-launch' or fault['nonce'] != nonce
                or fault['uid'] != previous_uid or fault['pid'] != actor['hostPid']
                or fault['startTicks'] != actor['startTicks']
                or fault['sourceDigest'] != source_digest
                or marker['generation'] != current['generation']
                or marker['bootId'] != current['bootId']
                or marker['cgroupIdentity'] != actor['cgroupIdentity']
                or current['state'] not in ('launching', 'running')
                or not ready_ns < fault['observedMonotonicNs']
                    <= actor['observedMonotonicNs']):
            raise ValueError('workload-partial-launch-fault-epoch-invalid')
    except BaseException as error:
        trace.failed()
        sample_error = error
    finally:
        try:
            trace.step('release')
            release = launcher.PARTIAL_LAUNCH_RELEASE
            pending = release.with_name('.pr315-partial-launch-release.pending')
            raw = json.dumps({'schemaVersion': 1,
                'kind': 'pr315-partial-launch-release', 'nonce': nonce},
                sort_keys=True, separators=(',', ':')).encode()
            descriptor = os.open(pending,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                os.O_CLOEXEC, 0o600)
            try:
                os.fchown(descriptor, previous_uid, workload.account('previous').pw_gid)
                if os.write(descriptor, raw) != len(raw):
                    raise ValueError('workload-partial-launch-release-short-write')
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if os.path.lexists(release):
                raise ValueError('workload-partial-launch-release-already-published')
            os.replace(pending, release)
            released_ns = time.monotonic_ns()
        except (OSError, ValueError):
            pass
    trace.step('response-collection')
    try:
        finish(driver, parent, pid, campaign_deadline_ns)
    except Exception:
        if sample_error is not None:
            raise sample_error
        raise
    if sample_error is not None:
        raise sample_error
    if (response.get('classification') not in (
            'controller-rejected-launch', 'transient-start-response')
            or released_ns is None or actor is None or observer_actor is None):
        raise ValueError('workload-partial-launch-transition-invalid')
    trace.step('previous-stop')
    stopped = workload.stop(handoff['handles']['previous'])
    current = workload.read(root / 'authority/previous.json')
    receipt = workload.stop_receipt('previous', current)
    trace.step('sibling-recheck')
    sender_after = _partial_role_projection(workload,
        handoff['handles']['candidate-sender'])
    recipient_after = _partial_role_projection(workload,
        handoff['handles']['candidate-recipient'])
    relay_after = workload.read(root / 'authority/relay-no-apps.json')
    if (stopped['state'] != 'quiescent' or current['state'] != 'quiescent'
            or current['generation'] != marker['generation']
            or current['managerInvocation'] != marker['managerInvocation']
            or receipt['managerInvocation'] != marker['managerInvocation']
            or receipt['cgroupIdentity'] != marker['cgroupIdentity']
            or receipt['membership'] != 'only-stop-helper'
            or receipt['descendantCgroups'] != 0
            or relay_after != relay
            or os.path.lexists(root / 'authority/relay-no-apps-start.json')
            or any(before[key] != after[key] for before, after in
                   ((sender, sender_after), (recipient, recipient_after))
                   for key in ('managerInvocation', 'cgroupIdentity',
                               'bootId', 'stateDigest'))):
        raise ValueError('workload-partial-launch-reconciliation-invalid')
    audit = {'schemaVersion': 2, 'kind': 'pr315-administrator-partial-launch',
        'caseId': 'partial-launch', 'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
        'administratorBefore': administrator_before,
        'administratorAfter': _administrator_collector_epoch('partial-launch'),
        'observerUid': observer_uid, 'senderBefore': sender,
        'observerActor': observer_actor,
        'senderAfter': sender_after, 'recipientBefore': recipient,
        'recipientAfter': recipient_after,
        'previousBefore': {key: previous[key] for key in
            ('state', 'generation', 'managerInvocation', 'cgroupIdentity', 'bootId')},
        'previousStartMarker': marker, 'previousFault': fault,
        'previousActor': actor, 'previousStopReceipt': receipt,
        'relayBefore': {key: relay[key] for key in
            ('state', 'generation', 'managerInvocation', 'cgroupIdentity', 'bootId')},
        'relayAfter': {key: relay_after[key] for key in
            ('state', 'generation', 'managerInvocation', 'cgroupIdentity', 'bootId')},
        'controllerResponse': response['classification'],
        'synchronizationPolicy': POLICY,
        'startResponseStartedNs': response_started_ns,
        'startResponseObservedNs': response_ns,
        'faultWaitStartedNs': fault_wait_started_ns,
        'faultWaitUntilNs': int(until*1e9),
        'probeStartedNs': ready_ns, 'releasePublishedNs': released_ns,
        'terminalObservedNs': time.monotonic_ns(),
        'launcherSourceDigest': source_digest}
    trace.step('audit-publication')
    workload.write(root / 'authority/partial-launch.json', audit, create=True)
    return hashlib.sha256(json.dumps(audit, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()


def probe_resource_exhaustion(workload, handoff, bundle_digest,
                              expected_worker, campaign_deadline_ns):
    """Drive finite signed-app pids pressure, then prove sibling progress."""
    if time.monotonic_ns() >= campaign_deadline_ns:
        raise ValueError('workload-resource-campaign-expired')
    account = workload.account('candidate-sender')
    root = workload.ROOT / 'state/candidate-sender/data/node/apps/data/pr315-probe'
    actor_before = _provider_app_actor(workload, handoff, expected_worker)
    role_before = _resource_cgroup_control(workload, handoff)
    siblings_before = _resource_sibling_controls(workload, handoff)
    nonce = secrets.token_hex(32)
    trigger = root / 'pr315-resource-trigger.json'
    encoded = json.dumps({'schemaVersion': 1,
        'kind': 'pr315-resource-trigger', 'nonce': nonce},
        sort_keys=True, separators=(',', ':')).encode()
    trigger_pending = root / '.pr315-resource-trigger.pending'
    descriptor = os.open(trigger_pending,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600)
    try:
        os.fchown(descriptor, account.pw_uid, account.pw_gid)
        if os.write(descriptor, encoded) != len(encoded):
            raise ValueError('workload-resource-trigger-short-write')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if trigger.exists():
        raise ValueError('workload-resource-trigger-already-published')
    os.replace(trigger_pending, trigger)
    trigger_ns = time.monotonic_ns()
    until = min(time.monotonic() + 300, campaign_deadline_ns / 1e9)
    release = root / 'pr315-resource-release.json'
    try:
        try:
            ready = _wait_output_record(root / 'pr315-resource-ready.json',
                account.pw_uid, until, 'workload-resource-ready-timeout')
            role_during = _resource_cgroup_control(workload, handoff)
            children, children_observed_ns = _resource_child_epochs(
                workload, actor_before, account.pw_uid)
            siblings_during = _resource_sibling_controls(workload, handoff)
        finally:
            release_ns = time.monotonic_ns()
            release_bytes = json.dumps({'schemaVersion': 1,
                'kind': 'pr315-resource-release', 'nonce': nonce},
                sort_keys=True, separators=(',', ':')).encode()
            release_pending = root / '.pr315-resource-release.pending'
            descriptor = os.open(release_pending,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600)
            try:
                os.fchown(descriptor, account.pw_uid, account.pw_gid)
                if os.write(descriptor, release_bytes) != len(release_bytes):
                    raise ValueError('workload-resource-release-short-write')
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if release.exists():
                raise ValueError('workload-resource-release-already-published')
            os.replace(release_pending, release)
        result = _wait_output_record(root / 'pr315-resource-result.json',
            account.pw_uid, until, 'workload-resource-result-timeout')
    finally:
        trigger.unlink(missing_ok=True)
        release.unlink(missing_ok=True)
    siblings_after = _resource_sibling_controls(workload, handoff)
    role_after = _resource_cgroup_control(workload, handoff)
    actor_after = _provider_app_actor(workload, handoff, expected_worker)
    children_exited_ns = _resource_children_exited(children)
    stable_actor = ('hostPid', 'namespacePid', 'namespacePids', 'startTicks',
                    'managerInvocation', 'cgroupIdentity', 'sandboxLeader',
                    'networkNamespaceIdentity')
    stable_role = ('role', 'managerInvocation', 'bootId', 'cgroupIdentity',
                   'pidsMax', 'memoryMaxBytes')
    if (not isinstance(ready, dict) or set(ready) != {
            'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'uid',
            'startedMonotonicNs', 'limitReachedNs', 'spawnedCount', 'forkErrno'}
            or ready['schemaVersion'] != 1
            or ready['kind'] != 'pr315-signed-resource-ready'
            or ready['caseId'] != 'resource-exhaustion'
            or ready['nonce'] != nonce
            or ready['pid'] != actor_before['namespacePids'][-1]
            or ready['uid'] != account.pw_uid
            or ready['forkErrno'] != 'EAGAIN'
            or not isinstance(result, dict) or set(result) != {
            'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'uid', 'gid',
            'startedMonotonicNs', 'finishedMonotonicNs', 'cleanupFinishedNs',
            'forkLimit', 'spawnedCount', 'reapedCount', 'forcedKillCount',
            'abnormalExitCount', 'forkErrno', 'barrierReadyNs',
            'releaseObservedNs'}
            or result['schemaVersion'] != 1
            or result['kind'] != 'pr315-signed-resource-exhaustion-probe'
            or result['caseId'] != 'resource-exhaustion'
            or result['nonce'] != nonce
            or result['pid'] != actor_before['namespacePids'][-1]
            or result['uid'] != account.pw_uid or result['gid'] != account.pw_gid
            or result['forkLimit'] != 600
            or result['forkErrno'] != 'EAGAIN'
            or ready['spawnedCount'] != result['spawnedCount']
            or len(children) != ready['spawnedCount']
            or ready['startedMonotonicNs'] != result['startedMonotonicNs']
            or ready['limitReachedNs'] != result['finishedMonotonicNs']
            or result['barrierReadyNs'] != ready['limitReachedNs']
            or type(result['spawnedCount']) is not int
            or not 1 <= result['spawnedCount'] <= 600
            or result['reapedCount'] != result['spawnedCount']
            or result['forcedKillCount'] != 0
            or result['abnormalExitCount'] != 0
            or any(actor_before[key] != actor_after[key] for key in stable_actor)
            or actor_before['stateDigest'] != actor_after['stateDigest']
            or any(role_before[key] != role_after[key] for key in stable_role)
            or any(role_before[key] != role_during[key] for key in stable_role)
            or role_during['pidsMaxEvents'] <= role_before['pidsMaxEvents']
            or role_during['pidsCurrent'] < role_during['pidsMax'] - 8
            or role_after['pidsMaxEvents'] < role_during['pidsMaxEvents']
            or role_after['pidsCurrent'] > role_before['pidsCurrent'] + 64
            or not role_before['memoryOomKills'] == role_during['memoryOomKills']
                == role_after['memoryOomKills']
            or not actor_before['observedMonotonicNs']
                < role_before['observedMonotonicNs']
                < siblings_before[-1]['controlObservedNs']
                < trigger_ns < result['startedMonotonicNs']
                < result['finishedMonotonicNs']
                < role_during['observedMonotonicNs']
                < children_observed_ns
                < siblings_during[0]['observedMonotonicNs']
                < siblings_during[-1]['controlObservedNs']
                < release_ns < result['releaseObservedNs']
                < result['cleanupFinishedNs']
                < siblings_after[0]['observedMonotonicNs']
                < role_after['observedMonotonicNs']
                < actor_after['observedMonotonicNs']
                < children_exited_ns):
        raise ValueError('workload-resource-actor-limit-or-window-invalid')
    for before, during, after in zip(siblings_before, siblings_during,
                                     siblings_after):
        stable = ('role', 'managerInvocation', 'bootId', 'cgroupIdentity',
                  'stateDigest')
        if (any(before[key] != during[key] or before[key] != after[key]
                for key in stable)
                or not before['controlObservedNs']
                    < trigger_ns < during['observedMonotonicNs']
                    < during['controlObservedNs'] < release_ns
                    < after['observedMonotonicNs']
                    < after['controlObservedNs']):
            raise ValueError('workload-resource-sibling-changed')
    children_record = {'schemaVersion': 1,
        'kind': 'pr315-administrator-resource-child-epochs',
        'caseId': 'resource-exhaustion',
        'actorHostPid': actor_before['hostPid'],
        'actorStartTicks': actor_before['startTicks'],
        'roleCgroupIdentity': role_during['cgroupIdentity'],
        'observedMonotonicNs': children_observed_ns,
        'exitedMonotonicNs': children_exited_ns,
        'children': children}
    workload.write(driver.RESOURCE_CHILDREN, children_record, create=True)
    children_digest = hashlib.sha256(json.dumps(children_record,
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    audit = {'schemaVersion': 1,
        'kind': 'pr315-administrator-resource-exhaustion-denial',
        'caseId': 'resource-exhaustion', 'bundleDigest': bundle_digest,
        'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
        'actorUid': account.pw_uid,
        'actorBefore': actor_before, 'actorAfter': actor_after,
        'senderStateBefore': actor_before['stateDigest'],
        'senderStateAfter': actor_after['stateDigest'],
        'roleBefore': role_before, 'roleDuring': role_during,
        'roleAfter': role_after,
        'siblingsBefore': siblings_before,
        'siblingsDuring': siblings_during,
        'siblingsAfter': siblings_after,
        'ready': ready, 'releasePublishedNs': release_ns,
        'triggerMonotonicNs': trigger_ns,
        'attackStartedNs': result['startedMonotonicNs'],
        'attackFinishedNs': result['finishedMonotonicNs'],
        'childCleanupFinishedNs': result['cleanupFinishedNs'],
        'childEpochCount': len(children),
        'childEpochDigest': children_digest,
        'childEpochsObservedNs': children_observed_ns,
        'childExitObservedNs': children_exited_ns,
        'kernelLimit': 'pids.max',
        'limitEventDelta': role_during['pidsMaxEvents'] - role_before['pidsMaxEvents'],
        'appResultDigest': hashlib.sha256(json.dumps(result,
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
    workload.write(workload.ROOT / 'authority/resource-exhaustion-denial.json',
                   audit, create=True)
    return hashlib.sha256(json.dumps(audit,
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def probe_late_child(workload, handoff, result, lifecycle_probe_digest,
                     campaign_deadline_ns):
    """Fork one owned child after real stop intent, then finish controller stop."""
    import pr315_lifecycle_role_probe as role_probe
    import restricted_workload_lifecycle_barrier as barrier

    if (result.get('groupPreparation') != 'late-child'
            or result.get('topologyRoles') != 4
            or time.monotonic_ns() >= campaign_deadline_ns):
        raise ValueError('workload-late-child-preparation-invalid')
    administrator_before = _administrator_collector_epoch('late-child')
    role = 'candidate-sender'
    handle = handoff['handles'][role]
    account = workload.account(role)
    launch = workload.read(workload.ROOT / 'roles/candidate-sender/launch.json')
    nonce = secrets.token_hex(32)
    workload.write(workload.ROOT / 'probe-requests/candidate-sender.json',
        {'schemaVersion': 1, 'caseId': 'late-child', 'nonce': nonce,
         'bootId': workload.boot(), 'javaDigest': launch['javaDigest'],
         'sourceDigest': lifecycle_probe_digest}, create=True, mode=0o444)
    state = workload.ROOT / 'state/candidate-sender/tmp'
    ready = _wait_output_record(state / role_probe.READY.name,
        account.pw_uid, min(time.monotonic() + 25, campaign_deadline_ns / 1e9),
        'workload-late-child-role-ready-timeout')
    before = workload.observe(handle)
    actor = _role_probe_actor(before, nonce, 'late-child')
    siblings_before = _resource_sibling_controls(workload, handoff)
    record = workload.read(workload.ROOT / 'authority/candidate-sender.json')
    if (ready['nonce'] != nonce
            or ready['pid'] != actor['namespacePids'][-1]
            or record['state'] != 'running'
            or record['managerInvocation'] != before['managerInvocation']
            or record['cgroupIdentity'] != before['cgroupIdentity']):
        raise ValueError('workload-late-child-actor-unavailable')
    source_digest = hashlib.sha256(Path(barrier.__file__).read_bytes()).hexdigest()
    selected = {'schemaVersion': 1, 'kind': 'pr315-fixed-stop-barrier',
        'caseId': 'late-child', 'role': role,
        'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
        'sourceDigest': source_digest,
        **{key: record[key] for key in ('campaign', 'generation',
            'managerInvocation', 'bootId', 'cgroupIdentity')}}
    workload.write(barrier.REQUEST, selected, create=True)
    started = _begin_installed_observer_stop(handle,
        pwd.getpwnam('cryptad-soak').pw_uid, campaign_deadline_ns)
    child_fd = None
    child_actor = None
    phase = None
    trigger_ns = None
    release_ns = None
    child_record = None
    sample_error = None
    try:
        phase = _wait_output_record(barrier.PHASE, 0,
            min(time.monotonic() + 8, campaign_deadline_ns / 1e9),
            'workload-late-child-stop-phase-timeout')
        stopping = workload.read(workload.ROOT / 'authority/candidate-sender.json')
        group = workload.group(role).stat()
        if (phase['caseId'] != 'late-child'
                or phase['nonceDigest'] != selected['nonceDigest']
                or stopping['state'] != 'stopping'
                or any(phase[key] != stopping[key] for key in
                       ('campaign', 'generation', 'managerInvocation',
                        'bootId', 'cgroupIdentity'))
                or phase['cgroupIdentity'] != [group.st_dev, group.st_ino]):
            raise ValueError('workload-late-child-stop-intent-invalid')
        trigger = state / role_probe.TRIGGER.name
        pending = trigger.with_name('.pr315-late-child-trigger.pending')
        raw = json.dumps({'schemaVersion': 1,
            'kind': 'pr315-late-child-trigger', 'nonce': nonce},
            sort_keys=True, separators=(',', ':')).encode()
        descriptor = os.open(pending,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
            os.O_CLOEXEC, 0o600)
        try:
            os.fchown(descriptor, account.pw_uid, account.pw_gid)
            if os.write(descriptor, raw) != len(raw):
                raise ValueError('workload-late-child-trigger-short-write')
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if os.path.lexists(trigger):
            raise ValueError('workload-late-child-trigger-reused')
        os.replace(pending, trigger)
        trigger_ns = time.monotonic_ns()
        child_record = _wait_output_record(state / role_probe.CHILD.name,
            account.pw_uid, min(time.monotonic() + 7, campaign_deadline_ns / 1e9),
            'workload-late-child-created-timeout')
        if (child_record['nonce'] != nonce
                or child_record['parentPid'] != actor['namespacePids'][-1]
                or child_record['uid'] != account.pw_uid
                or not phase['observedMonotonicNs'] < trigger_ns
                    < child_record['startedMonotonicNs']
                    < child_record['observedMonotonicNs']):
            raise ValueError('workload-late-child-record-invalid')
        pids = workload.group(role).joinpath('cgroup.procs').read_text().split()
        if len(pids) > 512:
            raise ValueError('workload-late-child-roster-limit')
        matching = []
        for raw_pid in pids:
            pid = int(raw_pid)
            path = Path('/proc') / raw_pid
            try:
                status = dict(line.split(':', 1) for line in
                    (path / 'status').read_text().splitlines() if ':' in line)
                if int(status['NSpid'].split()[-1]) == child_record['childPid']:
                    matching.append(pid)
            except (FileNotFoundError, ProcessLookupError):
                continue
        if len(matching) != 1:
            raise ValueError('workload-late-child-kernel-identity-unavailable')
        child_fd = os.pidfd_open(matching[0])
        child_actor = workload._process(matching[0], role, account.pw_uid)
        child_actor['cgroupIdentity'] = [group.st_dev, group.st_ino]
        child_actor['observedMonotonicNs'] = time.monotonic_ns()
        if (child_actor['hostParentPid'] != actor['hostPid']
                or child_actor['namespacePids'][-1] != child_record['childPid']
                or child_actor['startTicks'] < actor['startTicks']
                or child_actor['networkNamespaceIdentity'] != actor['networkNamespaceIdentity']
                or child_actor['mountNamespaceIdentity'] != actor['mountNamespaceIdentity']
                or child_actor['userNamespaceIdentity'] != actor['userNamespaceIdentity']
                or child_actor['noNewPrivileges'] is not True
                or child_actor['effectiveCapabilities'] != 0
                or select.select([child_fd], [], [], 0)[0]):
            raise ValueError('workload-late-child-kernel-ownership-invalid')
    except BaseException as error:
        sample_error = error
    finally:
        if not os.path.lexists(barrier.RELEASE):
            workload.write(barrier.RELEASE,
                {'schemaVersion': 1, 'kind': 'pr315-fixed-stop-release',
                 'caseId': 'late-child', 'nonce': nonce}, create=True)
            release_ns = time.monotonic_ns()
    try:
        stopped, observer_actor = _finish_installed_observer_stop(
            started, campaign_deadline_ns)
        if sample_error is not None:
            raise sample_error
        current = workload.read(workload.ROOT / 'authority/candidate-sender.json')
        receipt = workload.stop_receipt(role, current)
        if (stopped['state'] != 'quiescent'
                or stopped['managerInvocation'] != record['managerInvocation']
                or receipt['managerInvocation'] != record['managerInvocation']
                or receipt['cgroupIdentity'] != record['cgroupIdentity']
                or receipt['membership'] != 'only-stop-helper'
                or receipt['descendantCgroups'] != 0
                or child_fd is None or not select.select([child_fd], [], [], 0)[0]):
            raise ValueError('workload-late-child-terminal-invalid')
        child_exit_ns = time.monotonic_ns()
        siblings_after = _resource_sibling_controls(workload, handoff)
        if any(first['managerInvocation'] != last['managerInvocation']
               or first['stateDigest'] != last['stateDigest']
               for first, last in zip(siblings_before, siblings_after)):
            raise ValueError('workload-late-child-sibling-changed')
        audit = {'schemaVersion': 1,
            'kind': 'pr315-administrator-late-child',
            'caseId': 'late-child', 'sourceDigest': lifecycle_probe_digest,
            'barrierSourceDigest': source_digest,
            'nonceDigest': selected['nonceDigest'],
            'administratorBefore': administrator_before,
            'administratorAfter': _administrator_collector_epoch('late-child'),
            'observerStopActor': observer_actor,
            'roleBefore': {key: before[key] for key in
                ('managerInvocation', 'bootId', 'cgroupIdentity', 'stateDigest')},
            'actor': actor, 'phase': phase,
            'childRecord': child_record, 'childActor': child_actor,
            'childExitObservedNs': child_exit_ns,
            'triggerPublishedNs': trigger_ns, 'releasePublishedNs': release_ns,
            'stopReceipt': receipt,
            'siblingsBefore': siblings_before,
            'siblingsAfter': siblings_after,
            'terminalObservedNs': time.monotonic_ns()}
        workload.write(workload.ROOT / 'authority/late-child.json', audit, create=True)
        return hashlib.sha256(json.dumps(audit, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
    finally:
        if child_fd is not None:
            os.close(child_fd)


def probe_cleanup_race(workload, handoff, result, campaign_deadline_ns):
    """Replace the real manager epoch between stop intent and manager stop."""
    import restricted_workload_lifecycle_barrier as barrier
    if (result.get('groupPreparation') != 'cleanup-race'
            or time.monotonic_ns() >= campaign_deadline_ns):
        raise ValueError('workload-cleanup-race-preparation-invalid')
    role = 'candidate-sender'
    handle = handoff['handles'][role]
    observer = pwd.getpwnam('cryptad-soak')
    administrator_before = _administrator_collector_epoch('cleanup-race')
    sender_before = workload.observe(handle)
    siblings_before = _resource_sibling_controls(workload, handoff)
    record = workload.read(workload.ROOT / 'authority/candidate-sender.json')
    manager_before = workload.manager(role, 'show')
    if (record['state'] != 'running'
            or record['managerInvocation'] !=
                sender_before['managerInvocation']
            or record['cgroupIdentity'] !=
                sender_before['cgroupIdentity']):
        raise ValueError('workload-cleanup-race-old-instance-invalid')
    nonce = secrets.token_hex(32)
    source_digest = hashlib.sha256(Path(barrier.__file__).read_bytes()).hexdigest()
    selected = {'schemaVersion': 1, 'kind': 'pr315-fixed-stop-barrier',
        'caseId': 'cleanup-race', 'role': role,
        'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
        'sourceDigest': source_digest,
        **{key: record[key] for key in ('campaign', 'generation',
            'managerInvocation', 'bootId', 'cgroupIdentity')}}
    workload.write(barrier.REQUEST, selected, create=True)
    started = _begin_cleanup_race_stop(handle, observer,
                                       campaign_deadline_ns)
    parent, pid, stop_actor = started
    phase = None
    release_ns = None
    restart_result = None
    try:
        phase = _wait_output_record(barrier.PHASE, 0,
            min(time.monotonic() + 8, campaign_deadline_ns / 1e9),
            'workload-cleanup-race-stop-phase-timeout')
        stopping = workload.read(workload.ROOT /
            'authority/candidate-sender.json')
        if (phase['caseId'] != 'cleanup-race'
                or phase['nonceDigest'] != selected['nonceDigest']
                or stopping['state'] != 'stopping'
                or any(phase[key] != record[key] for key in (
                    'campaign', 'generation', 'managerInvocation',
                    'bootId', 'cgroupIdentity'))):
            raise ValueError('workload-cleanup-race-intent-invalid')
        restart_started = time.monotonic_ns()
        restarted = subprocess.run(['/usr/bin/systemctl', 'restart',
            'cryptad-workload@candidate-sender.service'],
            stdin=subprocess.DEVNULL, capture_output=True,
            env=driver.ENV, timeout=min(40, max(.001,
                campaign_deadline_ns / 1e9 - time.monotonic())))
        if len(restarted.stdout) > 8192 or len(restarted.stderr) > 8192:
            raise ValueError('workload-cleanup-race-manager-output-limit')
        manager_replacement = workload.manager(role, 'show')
        try:
            replacement_group = workload.group(role).stat()
            replacement_cgroup = [replacement_group.st_dev,
                                  replacement_group.st_ino]
        except FileNotFoundError:
            replacement_cgroup = None
        if (manager_replacement['InvocationID'] ==
                manager_before['InvocationID']
                or manager_replacement['ActiveState'] == 'active'
                or manager_replacement['MainPID'] != '0'
                or replacement_cgroup == record['cgroupIdentity']):
            raise ValueError('workload-cleanup-race-manager-not-replaced')
        restart_result = {'exitStatus': restarted.returncode,
            'startedMonotonicNs': restart_started,
            'finishedMonotonicNs': time.monotonic_ns()}
    except BaseException:
        parent.close()
        try:
            stop_child(pid)
        except ChildProcessError:
            pass
        raise
    finally:
        if not os.path.lexists(barrier.RELEASE):
            workload.write(barrier.RELEASE,
                {'schemaVersion': 1, 'kind': 'pr315-fixed-stop-release',
                 'caseId': 'cleanup-race', 'nonce': nonce}, create=True)
            release_ns = time.monotonic_ns()
    try:
        raw, status = collect_child(parent, pid,
            min(time.monotonic() + 50, campaign_deadline_ns / 1e9))
        pid = None
    finally:
        parent.close()
        if pid is not None:
            try:
                stop_child(pid)
            except ChildProcessError:
                pass
    if status != 0 or not 0 < len(raw) <= 1024 or restart_result is None:
        raise ValueError('workload-cleanup-race-stop-response-invalid')
    observer_denial = json.loads(raw)
    reconciled = workload.read(workload.ROOT /
        'authority/candidate-sender.json')
    old_receipt = workload.stop_receipt(role, reconciled)
    siblings_after = _resource_sibling_controls(workload, handoff)
    if (observer_denial['status'] != 'rejected'
            or observer_denial['reason'] !=
                'workload-controller-request-rejected'
            or observer_denial['exchange']['method'] != 'stop'
            or observer_denial['exchange']['responseDigest'] !=
                hashlib.sha256(
                    b'{"error":"restricted-workload-request-failed"}\n').hexdigest()
            or reconciled['state'] != 'reconciliation-required'
            or old_receipt['managerInvocation'] !=
                sender_before['managerInvocation']
            or old_receipt['membership'] != 'only-stop-helper'
            or old_receipt['descendantCgroups'] != 0
            or any(first['managerInvocation'] != last['managerInvocation']
                   or first['stateDigest'] != last['stateDigest']
                   for first, last in zip(siblings_before, siblings_after))):
        raise ValueError('workload-cleanup-race-rejection-invalid')
    subprocess.run(['/usr/bin/systemctl', 'reset-failed',
        'cryptad-workload@candidate-sender.service'],
        stdin=subprocess.DEVNULL, capture_output=True, check=True,
        timeout=10, env=driver.ENV)
    manager_reset = workload.manager(role, 'show')
    workload.reconcile()
    current = workload.read(workload.ROOT /
        'authority/candidate-sender.json')
    final_receipt = workload.stop_receipt(role, current)
    if (current['state'] != 'quiescent'
            or final_receipt != old_receipt
            or manager_reset['ActiveState'] not in ('inactive', 'failed')):
        raise ValueError('workload-cleanup-race-final-reconciliation-invalid')
    audit = {'schemaVersion': 1,
        'kind': 'pr315-administrator-cleanup-race',
        'caseId': 'cleanup-race',
        'administratorBefore': administrator_before,
        'administratorAfter': _administrator_collector_epoch('cleanup-race'),
        'senderBefore': {key: sender_before[key] for key in
            ('managerInvocation', 'bootId', 'cgroupIdentity', 'stateDigest',
             'observedMonotonicNs')},
        'managerBefore': manager_before,
        'managerReplacement': manager_replacement,
        'replacementCgroupIdentity': replacement_cgroup,
        'managerReset': manager_reset,
        'stopActor': stop_actor, 'stopPhase': phase,
        'restart': restart_result,
        'releasePublishedNs': release_ns,
        'observerDenial': observer_denial,
        'reconciliationState': {key: reconciled[key] for key in
            ('state', 'generation', 'managerInvocation',
             'bootId', 'cgroupIdentity')},
        'oldStopReceipt': old_receipt,
        'finalStopReceipt': final_receipt,
        'siblingsBefore': siblings_before,
        'siblingsAfter': siblings_after,
        'finishedMonotonicNs': time.monotonic_ns(),
        'barrierSourceDigest': source_digest,
        'nonceDigest': selected['nonceDigest']}
    workload.write(workload.ROOT / 'authority/cleanup-race.json',
                   audit, create=True)
    return hashlib.sha256(json.dumps(audit, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()


def probe_stale_handle(workload, handoff, retired, result,
                       campaign_deadline_ns):
    """Use one real observer to prove current, retired, current authority."""
    from cross_version_workload import WorkloadClient
    from cross_version_runtime import RuntimeFailure
    current = handoff['handles']['candidate-sender']
    campaign = workload.read(workload.ROOT / 'campaign.json')
    observer = pwd.getpwnam('cryptad-soak')
    if (not isinstance(retired, dict)
            or retired.get('sourceCommit') != result['identity']['sourceCommit']
            or retired.get('bootId') == campaign['bootId']
            or retired.get('senderHandle') == current
            or retired.get('senderUid') !=
                workload.account('candidate-sender').pw_uid
            or not isinstance(retired.get('senderHandle'), str)
            or re.fullmatch('[0-9a-f]{64}',
                retired['senderHandle']) is None
            or time.monotonic_ns() >= campaign_deadline_ns):
        raise ValueError('workload-stale-handle-preparation-invalid')
    controller_before = _stale_handle_controller_epoch(workload)
    target_before = workload.observe(current)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        pid = os.fork()
    except BaseException:
        parent.close()
        child.close()
        raise
    if pid == 0:
        parent.close()
        try:
            os.setgroups([])
            os.setgid(observer.pw_gid)
            os.setuid(observer.pw_uid)
            os.environ.clear()
            os.environ.update(driver.ENV)
            child.sendall(b'R')
            if child.recv(1) != b'G':
                raise ValueError('workload-stale-handle-start-invalid')
            replies = []
            for label, handle in (('current-before', current),
                                  ('retired-denied', retired['senderHandle']),
                                  ('current-after', current)):
                client = WorkloadClient()
                started = time.monotonic_ns()
                if label == 'retired-denied':
                    try:
                        client.request('observe', handle)
                    except RuntimeFailure as error:
                        if str(error) != 'workload-controller-request-rejected':
                            raise
                    else:
                        raise ValueError('workload-stale-handle-accepted')
                    projection = None
                else:
                    observed = client.request('observe', handle)
                    projection = {key: observed[key] for key in
                        ('state', 'generation', 'managerInvocation',
                         'bootId', 'cgroupIdentity', 'stateDigest')}
                    if projection['state'] != 'running':
                        raise ValueError('workload-stale-handle-current-inactive')
                finished = time.monotonic_ns()
                replies.append({'label': label, 'target': projection,
                    'exchange': client.last_exchange,
                    'startedMonotonicNs': started,
                    'finishedMonotonicNs': finished})
            child.sendall(json.dumps(replies, sort_keys=True,
                separators=(',', ':')).encode())
            child.close()
            os._exit(0)
        except BaseException:
            os._exit(1)
    child.close()
    try:
        parent.settimeout(min(5, max(.001,
            campaign_deadline_ns / 1e9 - time.monotonic())))
        if parent.recv(1) != b'R':
            raise ValueError('workload-stale-handle-observer-not-ready')
        actor = _positive_observer_epoch(pid, observer.pw_uid,
                                        campaign_deadline_ns)
        parent.sendall(b'G')
        raw, status = collect_child(parent, pid,
            min(time.monotonic() + 100, campaign_deadline_ns / 1e9))
    except BaseException:
        try:
            stop_child(pid)
        except ChildProcessError:
            pass
        raise
    finally:
        parent.close()
    if status != 0 or not 0 < len(raw) <= 4096:
        raise ValueError('workload-stale-handle-observer-failed')
    replies = json.loads(raw)
    target_after = workload.observe(current)
    controller_after = _stale_handle_controller_epoch(workload)
    stable = ('generation', 'managerInvocation', 'bootId',
              'cgroupIdentity', 'stateDigest')
    expected = {key: target_before[key] for key in
                ('state', *stable)}
    denied = b'{"error":"restricted-workload-request-failed"}\n'
    if (not isinstance(replies, list) or len(replies) != 3
            or [row.get('label') for row in replies] != [
                'current-before', 'retired-denied', 'current-after']
            or target_before['state'] != 'running'
            or target_after['state'] != 'running'
            or any(controller_before[key] != controller_after[key]
                   for key in ('pid', 'uid', 'startTicks', 'bootId',
                               'invocationId', 'cgroupIdentity'))
            or any(target_before[key] != target_after[key]
                   for key in stable)
            or replies[0]['target'] != expected
            or replies[1]['target'] is not None
            or replies[2]['target'] != expected
            or replies[1]['exchange']['responseDigest'] !=
                hashlib.sha256(denied).hexdigest()
            or not controller_before['observedMonotonicNs']
                < target_before['observedMonotonicNs']
                < replies[0]['startedMonotonicNs']
                < replies[0]['finishedMonotonicNs']
                < replies[1]['startedMonotonicNs']
                < replies[1]['finishedMonotonicNs']
                < replies[2]['startedMonotonicNs']
                < replies[2]['finishedMonotonicNs']
                < target_after['observedMonotonicNs']
                < controller_after['observedMonotonicNs']):
        raise ValueError('workload-stale-handle-sequence-invalid')
    for row, handle in zip(replies, (current, retired['senderHandle'], current)):
        request = json.dumps({'method': 'observe', 'handle': handle},
            separators=(',', ':')).encode() + b'\n'
        if (row['exchange']['method'] != 'observe'
                or row['exchange']['requestDigest'] !=
                    hashlib.sha256(request).hexdigest()):
            raise ValueError('workload-stale-handle-request-changed')
    audit = {'schemaVersion': 1,
        'kind': 'pr315-administrator-stale-handle-denial',
        'caseId': 'stale-handle',
        'sourceCommit': result['identity']['sourceCommit'],
        'retiredInputDigest': hashlib.sha256(json.dumps(retired,
            sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        'retiredBootId': retired['bootId'],
        'retiredHandleDigest': hashlib.sha256(
            retired['senderHandle'].encode()).hexdigest(),
        'successorBootId': campaign['bootId'],
        'observerActor': actor,
        'controllerBefore': controller_before,
        'controllerAfter': controller_after,
        'targetBefore': {key: target_before[key] for key in
            ('state', *stable, 'observedMonotonicNs')},
        'targetAfter': {key: target_after[key] for key in
            ('state', *stable, 'observedMonotonicNs')},
        'replies': replies,
        'finishedMonotonicNs': time.monotonic_ns()}
    workload.write(workload.ROOT / 'authority/stale-handle-denial.json',
                   audit, create=True)
    return hashlib.sha256(json.dumps(audit, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()


def probe_setsid_double_fork(workload, handoff, source_digest,
                             campaign_deadline_ns):
    """Stop one actual role after observing its detached cgroup descendant."""
    import cross_version_runtime as runtime
    if time.monotonic_ns() >= campaign_deadline_ns:
        raise ValueError('workload-role-probe-campaign-expired')
    role = 'candidate-sender'
    nonce = secrets.token_hex(32)
    launch = workload.read(workload.ROOT / 'roles/candidate-sender/launch.json')
    workload.write(workload.ROOT / 'probe-requests/candidate-sender.json',
        {'schemaVersion': 1, 'caseId': 'setsid-double-fork', 'nonce': nonce,
         'bootId': workload.boot(), 'javaDigest': launch['javaDigest'],
         'sourceDigest': source_digest}, create=True, mode=0o444)
    account = workload.account(role)
    root = workload.ROOT / 'state/candidate-sender/tmp'
    until = min(time.monotonic() + 25, campaign_deadline_ns / 1e9)
    ready = _wait_output_record(root / 'pr315-setsid-double-fork-ready.json',
        account.pw_uid, until, 'workload-role-probe-ready-timeout')
    handle = handoff['handles'][role]
    before = workload.observe(handle)
    actor_before = _role_probe_actor(before, nonce, 'setsid-double-fork')
    if (not isinstance(ready, dict) or set(ready) != {
            'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'startedMonotonicNs'}
            or ready['schemaVersion'] != 1
            or ready['kind'] != 'pr315-candidate-role-probe-ready'
            or ready['caseId'] != 'setsid-double-fork'
            or ready['nonce'] != nonce
            or ready['pid'] != actor_before['namespacePids'][-1]
            or ready['startedMonotonicNs'] >= before['observedMonotonicNs']):
        raise ValueError('workload-setsid-ready-invalid')
    other_roles = tuple(name for name in driver.ROLE_NAMES if name != role)
    others_before = {name: workload.manager(name, 'show') for name in other_roles}
    trigger_ns = time.monotonic_ns()
    _publish_output_trigger(root, 'pr315-setsid-double-fork-trigger.json',
                            'setsid-double-fork', nonce)
    result = _wait_output_record(root / 'pr315-setsid-double-fork-result.json',
        account.pw_uid, until, 'workload-role-probe-result-timeout')
    child_ready = _wait_output_record(root / 'pr315-setsid-double-fork-child.json',
        account.pw_uid, until, 'workload-role-probe-result-timeout')
    after = workload.observe(handle)
    actor_after = _role_probe_actor(after, nonce, 'setsid-double-fork')
    if (not isinstance(result, dict) or set(result) != {
            'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'uid', 'gid',
            'firstPid', 'startedMonotonicNs', 'finishedMonotonicNs'}
            or result['schemaVersion'] != 1
            or result['kind'] != 'pr315-candidate-setsid-double-fork'
            or result['caseId'] != 'setsid-double-fork'
            or result['nonce'] != nonce
            or result['pid'] != actor_before['namespacePids'][-1]
            or result['uid'] != account.pw_uid or result['gid'] != account.pw_gid
            or type(result['firstPid']) is not int or result['firstPid'] <= 1
            or not isinstance(child_ready, dict) or set(child_ready) != {
                'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'uid', 'gid',
                'startedMonotonicNs'}
            or child_ready['schemaVersion'] != 1
            or child_ready['kind'] != 'pr315-candidate-setsid-child'
            or child_ready['caseId'] != 'setsid-double-fork'
            or child_ready['nonce'] != nonce
            or child_ready['uid'] != account.pw_uid
            or child_ready['gid'] != account.pw_gid
            or actor_before['hostPid'] != actor_after['hostPid']
            or actor_before['startTicks'] != actor_after['startTicks']
            or before['managerInvocation'] != after['managerInvocation']
            or before['cgroupIdentity'] != after['cgroupIdentity']
            or not before['observedMonotonicNs'] < trigger_ns
                < result['startedMonotonicNs'] < result['finishedMonotonicNs']
                < after['observedMonotonicNs']
            or not result['startedMonotonicNs'] < child_ready['startedMonotonicNs']
                < after['observedMonotonicNs']):
        raise ValueError('workload-setsid-child-invalid')
    found = [row for row in after['processes']
             if isinstance(row.get('namespacePids'), list)
             and row['namespacePids'][-1] == child_ready['pid']]
    if len(found) != 1:
        raise ValueError('workload-setsid-child-invalid')
    child = found[0]
    child_pid = child['hostPid']
    descriptor = os.open(Path('/proc') / str(child_pid) / 'cmdline',
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        command = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    child_session = _setsid_process_epoch(child_pid)
    parent_session = _setsid_process_epoch(actor_before['hostPid'])
    if (command != (b'/usr/bin/python3\0-I\0-S\0-B\0/probe.py\0'
                   + nonce.encode() + b'\0setsid-child\0')
            or child['hostParentPid'] == actor_before['hostPid']
            or child['startTicks'] != child_session['startTicks']
            or child_session['session'] == parent_session['session']
            or child['executableDigest'] != runtime.digest_file('/usr/bin/python3')
            or child['networkNamespaceIdentity'] != actor_before['networkNamespaceIdentity']
            or child['mountNamespaceIdentity'] != actor_before['mountNamespaceIdentity']
            or child['userNamespaceIdentity'] != actor_before['userNamespaceIdentity']
            or child['noNewPrivileges'] is not True
            or child['effectiveCapabilities'] != 0
            or child['startTicks'] < actor_before['startTicks']):
        raise ValueError('workload-setsid-child-invalid')
    stop_started = time.monotonic_ns()
    stopped = workload.stop(handle)
    stop_finished = time.monotonic_ns()
    state = workload.manager(role, 'show')
    receipt = workload.read(workload.ROOT / 'authority/candidate-sender-stop.json')
    if (stopped.get('state') != 'quiescent'
            or state['ActiveState'] not in {'inactive', 'failed'}
            or state['SubState'] not in {'dead', 'failed'}
            or state['MainPID'] != '0' or not workload.quiescent(role)
            or receipt['managerInvocation'] != before['managerInvocation']
            or receipt['cgroupIdentity'] != before['cgroupIdentity']
            or receipt['membership'] != 'only-stop-helper'
            or receipt['descendantCgroups'] != 0
            or not stop_started < receipt['startedMonotonicNs']
                <= receipt['observedMonotonicNs'] <= stop_finished):
        raise ValueError('workload-setsid-stop-invalid')
    until = time.monotonic() + 10
    while time.monotonic() < until:
        try:
            current = _setsid_process_epoch(child_pid)
        except FileNotFoundError:
            break
        if current['startTicks'] != child['startTicks']:
            break
        time.sleep(.05)
    else:
        raise ValueError('workload-setsid-descendant-retained')
    others_after = {name: workload.manager(name, 'show') for name in other_roles}
    stable = ('InvocationID', 'ActiveState', 'SubState', 'MainPID')
    if any(others_before[name][key] != others_after[name][key]
           for name in other_roles for key in stable):
        raise ValueError('workload-setsid-sibling-changed')
    audit = {'schemaVersion': 1, 'kind': 'pr315-administrator-setsid-double-fork',
        'caseId': 'setsid-double-fork', 'sourceDigest': source_digest,
        'actorUid': account.pw_uid, 'actorBefore': actor_before,
        'actorAfter': actor_after, 'childEpoch': child,
        'childSession': child_session['session'],
        'parentSession': parent_session['session'],
        'roleInvocation': before['managerInvocation'],
        'roleCgroupIdentity': before['cgroupIdentity'],
        'triggerMonotonicNs': trigger_ns,
        'attackStartedNs': result['startedMonotonicNs'],
        'attackFinishedNs': child_ready['startedMonotonicNs'],
        'stopStartedNs': stop_started, 'stopFinishedNs': stop_finished,
        'stopReceiptObservedNs': receipt['observedMonotonicNs'],
        'childAbsentObservedNs': time.monotonic_ns(),
        'otherRolesBefore': others_before, 'otherRolesAfter': others_after}
    workload.write(workload.ROOT / 'authority/setsid-double-fork-denial.json',
                   audit, create=True)
    return audit


def _authority_probe_request_for_restart(workload, observation, source_digest):
    """Pin the fixed old probe request and its live role actor before restart."""
    role = 'candidate-sender'
    path = workload.ROOT / 'probe-requests/candidate-sender.json'
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o222 or info.st_nlink != 1
            or not 0 < info.st_size <= 4096):
        raise ValueError('workload-stale-pid-probe-request-invalid')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        current = os.fstat(descriptor)
        if (info.st_dev, info.st_ino, info.st_size) != (
                current.st_dev, current.st_ino, current.st_size):
            raise ValueError('workload-stale-pid-probe-request-invalid')
        raw = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    request = json.loads(raw)
    launch = workload.read(workload.ROOT / 'roles/candidate-sender/launch.json')
    if (not isinstance(request, dict) or set(request) != {
            'schemaVersion', 'caseId', 'nonce', 'bootId',
            'javaDigest', 'sourceDigest'}
            or request['schemaVersion'] != 1 or request['caseId'] != 'authority'
            or request['bootId'] != workload.boot()
            or request['javaDigest'] != launch['javaDigest']
            or request['sourceDigest'] != source_digest
            or re.fullmatch('[0-9a-f]{64}', str(request['nonce'])) is None):
        raise ValueError('workload-stale-pid-probe-request-invalid')
    ready_path = workload.ROOT / 'state/candidate-sender/tmp/pr315-authority-ready.json'
    ready_info = ready_path.lstat()
    if (not stat.S_ISREG(ready_info.st_mode)
            or ready_info.st_uid != workload.account(role).pw_uid
            or ready_info.st_mode & 0o077 or ready_info.st_nlink != 1
            or not 0 < ready_info.st_size <= 4096):
        raise ValueError('workload-stale-pid-probe-request-invalid')
    ready = driver._candidate_probe_file(ready_path, workload.account(role).pw_uid)
    actor = _role_probe_actor(observation, request['nonce'], 'authority')
    if (not isinstance(ready, dict) or set(ready) != {
            'schemaVersion', 'kind', 'caseId', 'nonce', 'pid',
            'startedMonotonicNs'}
            or ready['schemaVersion'] != 1
            or ready['kind'] != 'pr315-candidate-role-probe-ready'
            or ready['caseId'] != 'authority'
            or ready['nonce'] != request['nonce']
            or ready['pid'] != actor['namespacePids'][-1]
            or type(ready['startedMonotonicNs']) is not int
            or not 0 < ready['startedMonotonicNs']
                < observation['observedMonotonicNs']):
        raise ValueError('workload-stale-pid-probe-request-invalid')
    return path, (info.st_dev, info.st_ino, info.st_size), hashlib.sha256(raw).hexdigest()


def _retire_verified_probe_request(selection):
    """Remove only the pinned request after the old role has stopped."""
    path, identity, expected_digest = selection
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o222 or info.st_nlink != 1
                    or not 0 < info.st_size <= 4096
                    or (info.st_dev, info.st_ino, info.st_size) != identity):
                raise ValueError('workload-stale-pid-probe-request-changed')
            raw = os.read(descriptor, 4097)
            selected = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            if (len(raw) != info.st_size
                    or hashlib.sha256(raw).hexdigest() != expected_digest
                    or (selected.st_dev, selected.st_ino, selected.st_size,
                        selected.st_uid, selected.st_mode, selected.st_nlink) !=
                       (info.st_dev, info.st_ino, info.st_size,
                        info.st_uid, info.st_mode, info.st_nlink)):
                raise ValueError('workload-stale-pid-probe-request-changed')
        finally:
            os.close(descriptor)
        os.unlink(path.name, dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(directory)


def _quiescent_sender_audit(record):
    """Keep the first stopped epoch without inventing a preceding stop link."""
    fields = ('generation', 'bootId', 'state', 'managerInvocation',
              'cgroupIdentity', 'stopReason')
    value = {key: record[key] for key in fields}
    # The controller adds this link to the restarted record, after archiving
    # the first stop. It is absent from that first quiescent record.
    if 'previousStopGeneration' in record:
        value['previousStopGeneration'] = record['previousStopGeneration']
    return value


def probe_stale_pid_uid(workload, handoff, result, source_digest,
                        campaign_deadline_ns, phase_state=None):
    """Keep the old observer alive across a real sender manager restart."""
    from cross_version_workload import principal_row
    from restricted_workload_controller import _recipient_fcp_control
    role = 'candidate-sender'
    handle = handoff['handles'][role]
    expected_jdk = handoff['expectedJdkDigests'][role]
    observer = pwd.getpwnam('cryptad-soak')
    if phase_state is not None:
        phase_state['phase'] = 'old-observer'
    if time.monotonic_ns() >= campaign_deadline_ns:
        raise ValueError('workload-stale-pid-deadline')
    sender_before = workload.observe(handle)
    old_parent, old_pid = _stale_pid_observer_process(
        handle, expected_jdk, True, observer)
    new_parent = new_pid = None
    try:
        old_parent.settimeout(min(5, max(.001,
            campaign_deadline_ns / 1e9 - time.monotonic())))
        if old_parent.recv(1) != b'R':
            raise ValueError('workload-stale-pid-old-not-ready')
        old_actor = _positive_observer_epoch(old_pid, observer.pw_uid,
                                              campaign_deadline_ns)
        old_parent.sendall(b'G')
        old_first = _stale_pid_observer_reply(old_parent)
        if (old_first['target']['managerInvocation'] !=
                sender_before['managerInvocation']):
            raise ValueError('workload-stale-pid-old-instance-changed')
        if phase_state is not None:
            phase_state['phase'] = 'probe-request-retirement'
        old_probe = workload.observe(handle)
        if any(old_probe[key] != sender_before[key] for key in
               ('managerInvocation', 'cgroupIdentity', 'stateDigest')):
            raise ValueError('workload-stale-pid-old-instance-changed')
        request = _authority_probe_request_for_restart(
            workload, old_probe, source_digest)
        if phase_state is not None:
            phase_state['phase'] = 'sender-stop'
        stop_started = time.monotonic_ns()
        stopped = workload.stop(handle)
        old_quiescent = workload.read(workload.ROOT /
            'authority/candidate-sender.json')
        old_receipt = workload.stop_receipt(role, old_quiescent)
        _retire_verified_probe_request(request)
        if phase_state is not None:
            phase_state['phase'] = 'sender-start'
        restart_started = time.monotonic_ns()
        started = workload.start(handle)
        if phase_state is not None:
            phase_state['phase'] = 'new-fcp'
        until = min(time.monotonic() + 180, campaign_deadline_ns / 1e9)
        while True:
            try:
                ready, controlled_ns, control_digest = _recipient_fcp_control(handle)
                break
            except (OSError, ValueError):
                if time.monotonic() >= until:
                    raise ValueError('workload-stale-pid-new-fcp-unavailable') from None
                state = driver.restarted_sender_state(until)
                if state is not None and state['ActiveState'] in {'failed', 'inactive'}:
                    raise ValueError('workload-stale-pid-new-sender-exited') from None
                time.sleep(.2)
        sender_after = workload.observe(handle)
        if phase_state is not None:
            phase_state['phase'] = 'manager-transition'
        old_actor_after = _positive_observer_epoch(old_pid, observer.pw_uid,
                                                    campaign_deadline_ns)
        if (any(old_actor[key] != old_actor_after[key] for key in
                ('pid', 'uid', 'startTicks', 'bootId', 'cgroupIdentity',
                 'namespaces', 'sourceDigest'))
                or sender_after['managerInvocation'] ==
                    sender_before['managerInvocation']
                or old_receipt['managerInvocation'] !=
                    sender_before['managerInvocation']
                or old_receipt['membership'] != 'only-stop-helper'
                or old_receipt['descendantCgroups'] != 0
                or started['managerInvocation'] !=
                    sender_after['managerInvocation']):
            raise ValueError('workload-stale-pid-manager-transition-invalid')
        if phase_state is not None:
            phase_state['phase'] = 'new-observer'
        new_parent, new_pid = _stale_pid_observer_process(
            handle, expected_jdk, False, observer)
        new_parent.settimeout(min(5, max(.001,
            campaign_deadline_ns / 1e9 - time.monotonic())))
        if new_parent.recv(1) != b'R':
            raise ValueError('workload-stale-pid-new-not-ready')
        new_actor = _positive_observer_epoch(new_pid, observer.pw_uid,
                                              campaign_deadline_ns)
        new_parent.sendall(b'G')
        new_raw, new_status = collect_child(new_parent, new_pid,
            min(time.monotonic() + 50, campaign_deadline_ns / 1e9))
        new_pid = None
        if new_status != 0 or not 0 < len(new_raw) <= 4096:
            raise ValueError('workload-stale-pid-new-observer-failed')
        new_result = json.loads(new_raw)
        if phase_state is not None:
            phase_state['phase'] = 'old-rejection'
        old_parent.sendall(b'G')
        old_raw, old_status = collect_child(old_parent, old_pid,
            min(time.monotonic() + 50, campaign_deadline_ns / 1e9))
        old_pid = None
        if old_status != 0 or not 0 < len(old_raw) <= 4096:
            raise ValueError('workload-stale-pid-old-observer-failed')
        rejected = json.loads(old_raw)
        if phase_state is not None:
            phase_state['phase'] = 'final-roster'
        roster_started = time.monotonic_ns()
        samples = {selected_role: workload.observe(handoff['handles'][selected_role])
                   for selected_role in driver.ROLE_NAMES}
        roster_finished = time.monotonic_ns()
        final_roster = {'observerUid': result['roleKernelRoster']['observerUid'],
            'runnerUid': result['roleKernelRoster']['runnerUid'],
            'roles': [principal_row(selected_role, samples[selected_role],
                handoff['expectedJdkDigests'][selected_role])
                for selected_role in driver.ROLE_NAMES]}
        if (new_result['target']['managerInvocation'] !=
                sender_after['managerInvocation']
                or rejected['target'] != new_result['target']
                or old_first['target']['managerInvocation'] ==
                    new_result['target']['managerInvocation']
                or (old_first['daemon']['hostPid'],
                    old_first['daemon']['startTicks']) == (
                    new_result['daemon']['hostPid'],
                    new_result['daemon']['startTicks'])
                or old_actor['uid'] != new_actor['uid']
                or (old_actor['pid'], old_actor['startTicks']) == (
                    new_actor['pid'], new_actor['startTicks'])
                or final_roster['roles'][0]['invocationId'] !=
                    sender_after['managerInvocation']):
            raise ValueError('workload-stale-pid-observer-proof-invalid')
        result['authorityFinalRoleRoster'] = final_roster
        result['authorityFinalRosterWindow'] = {
            'startedMonotonicNs': roster_started,
            'finishedMonotonicNs': roster_finished}
        if phase_state is not None:
            phase_state['phase'] = 'audit'
        audit = {'schemaVersion': 1,
            'kind': 'pr315-administrator-stale-pid-uid-denial',
            'caseId': 'stale-pid-uid',
            'oldObserver': old_actor, 'oldObserverAfter': old_actor_after,
            'newObserver': new_actor,
            'oldObserverFirst': old_first,
            'oldObserverRejected': rejected,
            'newObserverResult': new_result,
            'oldSenderInvocation': sender_before['managerInvocation'],
            'newSenderInvocation': sender_after['managerInvocation'],
            'oldSenderCgroup': sender_before['cgroupIdentity'],
            'newSenderCgroup': sender_after['cgroupIdentity'],
            'oldQuiescentAuthority': _quiescent_sender_audit(old_quiescent),
            'oldStopReceipt': old_receipt,
            'oldSenderState': sender_before['stateDigest'],
            'newSenderState': sender_after['stateDigest'],
            'stopStartedNs': stop_started,
            'restartStartedNs': restart_started,
            'newFcpControlledNs': controlled_ns,
            'newFcpControlDigest': control_digest,
            'rosterWindow': result['authorityFinalRosterWindow'],
            'finishedMonotonicNs': time.monotonic_ns()}
        workload.write(workload.ROOT / 'authority/stale-pid-uid-denial.json',
                       audit, create=True)
        return hashlib.sha256(json.dumps(audit, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
    finally:
        for channel, pid in ((old_parent, old_pid), (new_parent, new_pid)):
            if channel is not None:
                channel.close()
            if pid is not None:
                try:
                    stop_child(pid)
                except ChildProcessError:
                    pass


def _stuck_output_actor(observation, child, nonce):
    """Disambiguate forked identical argv by the observed writer's kernel parent."""
    writer_pid = child.get('writerPid')
    if type(writer_pid) is not int or writer_pid <= 1:
        raise ValueError('workload-stuck-output-writer-invalid')
    writers = [row for row in observation['processes']
               if row['namespacePids'][-1] == writer_pid]
    if len(writers) != 1:
        raise ValueError('workload-stuck-output-writer-invalid')
    writer = writers[0]
    parents = [row for row in observation['processes']
               if row['hostPid'] == writer['hostParentPid']]
    actor = _role_probe_actor({'processes': parents}, nonce, 'stuck-output')
    return actor, writer


def probe_stuck_output(workload, handoff, result, role_probe_digest,
                       campaign_deadline_ns):
    """Keep the failing operation's phase before role tmpfs is reclaimed."""
    from pr315_stuck_output_diagnostics import Trace
    trace = Trace(workload, campaign_deadline_ns)
    try:
        return _probe_stuck_output(workload, handoff, result, role_probe_digest,
                                   campaign_deadline_ns, trace)
    except Exception as error:
        try:
            trace.capture(error)
        except Exception:
            pass
        raise


def _probe_stuck_output(workload, handoff, result, role_probe_digest,
                        campaign_deadline_ns, trace):
    """Time out the installed pipe collector while an owned role writer lives."""
    import pr315_role_probe as role_probe
    from bounded_process import run as bounded_run

    if (result.get('groupPreparation') != 'stuck-output'
            or result.get('topologyRoles') != 4
            or time.monotonic_ns() >= campaign_deadline_ns):
        raise ValueError('workload-stuck-output-preparation-invalid')
    administrator_before = _administrator_collector_epoch('stuck-output')
    trace.administrator = administrator_before
    role = 'candidate-sender'
    handle = handoff['handles'][role]
    account = workload.account(role)
    launch = workload.read(workload.ROOT / 'roles/candidate-sender/launch.json')
    nonce = secrets.token_hex(32)
    trace.step('request-publication')
    workload.write(workload.ROOT / 'probe-requests/candidate-sender.json',
        {'schemaVersion': 1, 'caseId': 'stuck-output', 'nonce': nonce,
         'bootId': workload.boot(), 'javaDigest': launch['javaDigest'],
         'sourceDigest': role_probe_digest}, create=True, mode=0o444)
    state = workload.ROOT / 'state/candidate-sender/tmp'
    trace.step('role-ready')
    ready = _wait_output_record(state / role_probe.STUCK_OUTPUT_READY.name,
        account.pw_uid, min(time.monotonic() + 25, campaign_deadline_ns / 1e9),
        'workload-stuck-output-role-ready-timeout')
    trace.step('child-ready')
    child = _wait_output_record(state / role_probe.STUCK_OUTPUT_CHILD.name,
        account.pw_uid, min(time.monotonic() + 25, campaign_deadline_ns / 1e9),
        'workload-stuck-output-child-ready-timeout')
    trace.step('actor-binding')
    before = workload.observe(handle)
    actor, writer = _stuck_output_actor(before, child, nonce)
    fifo = state / role_probe.STUCK_OUTPUT_FIFO.name
    info = fifo.lstat()
    if (not isinstance(ready, dict) or ready.get('nonce') != nonce
            or ready.get('pid') != actor['namespacePids'][-1]
            or not isinstance(child, dict)
            or child.get('kind') != 'pr315-candidate-stuck-output-child'
            or child.get('caseId') != 'stuck-output'
            or child.get('nonce') != nonce
            or child.get('parentPid') != ready['pid']
            or child.get('uid') != account.pw_uid
            or writer is None or writer['hostParentPid'] != actor['hostPid']
            or writer['startTicks'] < actor['startTicks']
            or not stat.S_ISFIFO(info.st_mode) or info.st_uid != account.pw_uid
            or info.st_mode & 0o777 != 0o600 or info.st_nlink != 1
            or child.get('fifoIdentity') != [info.st_dev, info.st_ino]):
        raise ValueError('workload-stuck-output-writer-invalid')
    trace.step('sibling-controls')
    siblings_before = _resource_sibling_controls(workload, handoff)
    writer_fd = os.pidfd_open(writer['hostPid'])
    collector_fd = None
    collector = None
    output = []
    started_ns = time.monotonic_ns()
    def on_start(pid):
        nonlocal collector_fd, collector
        trace.step('collector-epoch')
        collector_fd = os.pidfd_open(pid)
        collector = driver._stuck_collector_epoch(pid)

    def retain(stdout, stderr):
        output.append((stdout, stderr))

    try:
        if select.select([writer_fd], [], [], 0)[0]:
            raise ValueError('workload-stuck-output-writer-exited')
        try:
            trace.step('collector-start')
            bounded_run(['/usr/bin/cat', str(fifo)], environment=driver.ENV,
                timeout=5, output_limit=4096, diagnostic_sink=retain,
                start_observer=on_start)
        except ValueError as error:
            if str(error) != 'bounded_process_deadline_exceeded':
                raise
        else:
            raise ValueError('workload-stuck-output-collector-finished')
        finished_ns = time.monotonic_ns()
        trace.step('collector-proof')
        if (collector is None or collector_fd is None
                or not select.select([collector_fd], [], [], 0)[0]
                or select.select([writer_fd], [], [], 0)[0]
                or output != [(b'pr315-stuck-output\n', b'')]
                or not started_ns < collector['observedMonotonicNs']
                    < started_ns + 5 * 10**9 < finished_ns
                or finished_ns - started_ns > 16 * 10**9):
            raise ValueError('workload-stuck-output-collector-proof-invalid')
        trace.step('writer-recheck')
        after = workload.observe(handle)
        writer_after = next((row for row in after['processes']
            if row['hostPid'] == writer['hostPid']), None)
        if (writer_after is None
                or writer_after['startTicks'] != writer['startTicks']
                or before['managerInvocation'] != after['managerInvocation']
                or before['cgroupIdentity'] != after['cgroupIdentity']
                or before['stateDigest'] != after['stateDigest']):
            raise ValueError('workload-stuck-output-role-changed')
        trace.step('observer-stop')
        stopped, stop_actor = _installed_observer_stop(handle,
            pwd.getpwnam('cryptad-soak').pw_uid, campaign_deadline_ns)
        trace.step('stop-receipt')
        current = workload.read(workload.ROOT / 'authority/candidate-sender.json')
        receipt = workload.stop_receipt(role, current)
        if (stopped['state'] != 'quiescent'
                or stopped['managerInvocation'] != receipt['managerInvocation']
                or stopped['bootId'] != receipt['bootId']
                or receipt['membership'] != 'only-stop-helper'
                or receipt['descendantCgroups'] != 0
                or not select.select([writer_fd], [], [], 0)[0]):
            raise ValueError('workload-stuck-output-writer-not-stopped')
        trace.step('sibling-recheck')
        siblings_after = _resource_sibling_controls(workload, handoff)
        if any(first['managerInvocation'] != last['managerInvocation']
               or first['stateDigest'] != last['stateDigest']
               for first, last in zip(siblings_before, siblings_after)):
            raise ValueError('workload-stuck-output-sibling-changed')
        trace.step('audit-publication')
        audit = {'schemaVersion': 1,
            'kind': 'pr315-administrator-stuck-output',
            'caseId': 'stuck-output',
            'administratorBefore': administrator_before,
            'administratorAfter': _administrator_collector_epoch('stuck-output'),
            'sourceDigest': role_probe_digest,
            'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
            'roleBefore': {'managerInvocation': before['managerInvocation'],
                'bootId': before['bootId'],
                'cgroupIdentity': before['cgroupIdentity'],
                'stateDigest': before['stateDigest']},
            'actor': actor,
            'writer': {'hostPid': writer['hostPid'],
                'startTicks': writer['startTicks'],
                'hostParentPid': writer['hostParentPid'],
                'namespacePids': writer['namespacePids'],
                'executableDigest': writer['executableDigest']},
            'fifoIdentity': [info.st_dev, info.st_ino],
            'collector': collector,
            'collectorOutputDigest': hashlib.sha256(output[0][0]).hexdigest(),
            'collectorStartedNs': started_ns,
            'collectorFinishedNs': finished_ns,
            'collectorDenial': 'bounded_process_deadline_exceeded',
            'observerStopActor': stop_actor,
            'observerStopResponse': stopped,
            'senderStopReceipt': receipt,
            'siblingsBefore': siblings_before,
            'siblingsAfter': siblings_after,
            'terminalObservedNs': time.monotonic_ns()}
        workload.write(workload.ROOT / 'authority/stuck-output.json', audit, create=True)
        return hashlib.sha256(json.dumps(audit, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
    finally:
        os.close(writer_fd)
        if collector_fd is not None:
            os.close(collector_fd)
