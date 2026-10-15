"""Real signed process-owner cancellation through AppHost stop and native acknowledgment."""
from __future__ import annotations
import hashlib
import json
import os
import re
from pathlib import Path

import cross_version_installed_budgets as transport
import pr320_cancellation_contract as contract
import cross_version_installed_storage_budgets as storage

PRIVATE_FILE = 'pr320-owner-budget.private.json'
CHECKPOINT_FILE = 'pr320-owner-checkpoints.private.jsonl'


def _checkpoint(root, row):
    raw = json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    descriptor = os.open(Path(root) / CHECKPOINT_FILE,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(descriptor).st_size + len(raw) > 4 * 1024 * 1024:
            transport.fail('owner-checkpoint-budget-exhausted')
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _owner_case(adapter, handles, statement, administrator, checkpoint):
    primary_handle, contender_handle = handles[transport.APP_IDS[0]], handles[transport.APP_IDS[1]]
    key = transport._new_content_key(adapter)
    before = transport._with_graph(primary_handle, transport._snapshot(primary_handle))
    checkpoint({'phase': 'before', 'native': before})
    original = administrator('start', key['uri'])
    checkpoint({'phase': 'owner-start', 'receipt': original})
    active = transport._wait_for(adapter, primary_handle, before['work']['lastSequence'],
        lambda snapshot, events: any(e['kind'] == 'FETCH_INVOKED' for e in events)
        and snapshot['budget'].get('activeFamilyLeases', 0) > 0
        and not any(e['kind'] in {'FETCH_SUCCEEDED', 'FETCH_FAILED'} for e in events))
    if active is None:
        return None, {'status': 'not-observed', 'reason': 'native-owner-active-premise-unobserved'}, original
    checkpoint({'phase': 'active', 'native': active})
    code, value = primary_handle.request('POST', '/api/v1/apps/' + transport.APP_IDS[0] + '/stop')
    checkpoint({'phase': 'owner-stop', 'httpStatus': code})
    if code != 200:
        transport.fail('owner-app-stop-failed')
    death = administrator('stopped')
    checkpoint({'phase': 'owner-death', 'receipt': death})
    # A real AppHost process stop drives the registered native request owner. The
    # observer does not cancel a socket/thread or write any acknowledgment event.
    during = transport._with_graph(primary_handle, transport._snapshot(primary_handle))
    checkpoint({'phase': 'during', 'native': during})
    events = transport._events(during, before['work']['lastSequence'])
    if (not any(e['kind'] == 'FETCH_CANCEL_REQUESTED' for e in events)
            or not any(e['kind'] == 'FETCH_TERMINATION_UNKNOWN' for e in events)
            or any(e['kind'] == 'FETCH_TIMEOUT' for e in events)):
        return None, {'status': 'not-observed', 'reason': 'process-owner-cancel-unobserved'}, original
    if (during['budget'].get('activeFamilyLeases', 0) == 0
            or any(e['kind'] == 'FETCH_OWNER_TERMINATED' for e in events)):
        return None, {'status': 'not-observed', 'reason': 'delayed-owner-tail-not-observed'}, original
    task = {'method': 'POST', 'path': '/api/v1/trust-graph/import-uri', 'parameters': {'uri': key['uri']}}
    with transport._start_client(adapter, contender_handle.context, task) as contender:
        contender.release()
        result = contender.result()
    if result['status'] != 429:
        return None, {'status': 'not-observed', 'reason': 'retained-slot-not-denied'}, original
    acknowledged = transport._wait_for(adapter, primary_handle, before['work']['lastSequence'],
        lambda snapshot, events: snapshot['budget'].get('activeFamilyLeases') == 0
        and any(e['kind'] == 'FETCH_OWNER_TERMINATED' for e in events),
        maximum=transport._policy_seconds(adapter, 'ownerAcknowledgmentDeadlineMillis'))
    if acknowledged is None:
        return None, {'status': 'not-observed', 'reason': 'normal-owner-ack-unobserved'}, original
    recovery_task = {'method': 'POST', 'path': '/api/v1/trust-graph/import',
                     'parameters': {'document': statement.decode('utf-8')}}
    # Browser reads remain installed-app principals. This recovery deliberately
    # does not launch a replacement process or relabel a browser request as an owner.
    with transport._start_client(adapter, primary_handle.context, recovery_task) as recovery:
        recovery.release()
        recovery_result = recovery.result()
    if recovery_result['status'] != 200:
        return None, {'status': 'not-observed', 'reason': 'owner-recovery-failed'}, original
    after = transport._with_graph(primary_handle, transport._snapshot(primary_handle))
    checkpoint({'phase': 'after', 'native': after})
    events = transport._events(after, before['work']['lastSequence'])
    primary = transport._composed_parents(events, 'COMPOSED_URI_IMPORT_START')
    recovery = transport._composed_parents(events, 'COMPOSED_DIRECT_IMPORT_START')
    if len(primary) != 2 or len(recovery) != 1:
        return None, {'status': 'not-observed', 'reason': 'owner-operation-identities-unavailable'}, original
    roles = {}
    for operation, prefix in ((primary[0], 'primary'), (primary[1], 'contender'), (recovery[0], 'recovery')):
        roles.update(transport._roles_for_parent(events, operation, prefix))
    row = transport._causal_case('cancellation', before, during, after,
        operation_id=primary[0], roles=roles, request_outcome='cancelled', owner_outcome='normal-ack')
    row['nodeEpoch'] = adapter.journal.node_epochs[('', transport.ROLE)]
    return row, {'status': 'observed'}, original


def run_owner_lane(adapter, administrator, *, leave_running_for_administrator=False,
                   on_start_failure=None):
    if not contract.verify_selection_contract(adapter.plan, adapter.private, adapter.authorization):
        transport.fail('owner-selection-invalid')
    completed = False
    checkpoint = lambda row: _checkpoint(adapter.root, row)
    try:
        for role in transport.runtime.ROLES:
            adapter.start(role)
        adapter.connect()
        handles, statement = transport._bootstrap_apps(adapter)
        if transport._snapshot(handles[transport.APP_IDS[0]]).get('budgetConfiguration') != contract.NORMALIZED_CONFIGURATION['budgetConfiguration']:
            transport.fail('owner-effective-configuration-mismatch')
        contexts = {app: transport._context_evidence(handle.context) for app, handle in handles.items()}
        # Establish the normal directories and a selected duplicate recovery subject
        # through the real handler before the root-owned cancellation interval begins.
        if storage._request(adapter, handles[transport.APP_IDS[0]], statement) != 200:
            transport.fail('owner-seed-failed')
        row, attempt, receipt = _owner_case(adapter, handles, statement, administrator, checkpoint)
        final = transport._snapshot(handles[transport.APP_IDS[0]])
        checkpoint({'phase': 'final', 'native': final})
        node = next(n for n in adapter.plan['nodes'] if n['role'] == transport.ROLE)
        attachment = {'schemaVersion': 4, 'collectorEpoch': final['work']['collectorEpoch'],
            'nodeEpoch': adapter.journal.node_epochs[('', transport.ROLE)],
            'workloadDigest': adapter.plan['workloadInputs']['scheduler'],
            'productDigest': node['artifactDigest'], 'sourceCommit': node['sourceCommit'],
            'appCohortDigest': transport.pressure.baseline.digest(node['appDigests']),
            **adapter.plan['composedBudgetInputs'], 'segments': [],
            'causalCases': [] if row is None else [row], 'storageCases': []}
        coverage = transport.composed.derive(attachment,
            workload_digest=attachment['workloadDigest'], product_digest=node['artifactDigest'],
            source_commit=node['sourceCommit'], app_cohort_digest=attachment['appCohortDigest'],
            node_epoch=attachment['nodeEpoch'], collector_digest=attachment['collectorDigest'],
            configuration_digest=attachment['configurationDigest'])
        private = {'schemaVersion': 1, 'kind': 'pr320-private-owner-cancellation',
            'selectionDigest': adapter.authorization['selectionDigest'], 'contexts': contexts,
            'attempt': attempt, 'originalStimulus': receipt,
            'composedBudgetEvidence': attachment, 'composedBudgetCoverage': coverage}
        checkpoint({'phase': 'attempt-completed', 'attempt': attempt})
        raw = json.dumps(private, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if len(raw) > 4 * 1024 * 1024:
            transport.fail('owner-private-size-limit')
        descriptor = os.open(Path(adapter.root) / PRIVATE_FILE,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        from cryptad_certification.composed_budget_journal_member import append_member
        append_member(adapter.journal, 'legacy-attachment', json.dumps(
            attachment, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())
        completed = True
        return {'schemaVersion': 1, 'kind': 'pr320-installed-owner-cancellation',
            'executionClass': contract.EXECUTION_CLASS, 'selectionDigest': private['selectionDigest'],
            'privateEvidenceDigest': 'sha256:' + hashlib.sha256(raw).hexdigest(),
            'evidenceClass': 'installed-process-owner', 'status': attempt['status'],
            'observedCases': coverage['observedCases'], 'fullAppBudgets': 'not-observed',
            'releaseEligible': False, 'phaseComplete': False,
            'cleanupState': 'administrator-required' if leave_running_for_administrator else 'observer-owned'}
    except Exception:
        checkpoint({'phase': 'interrupted', 'status': 'unknown'})
        if getattr(adapter, 'active_start_role', None) is not None and on_start_failure is not None:
            on_start_failure(adapter.active_start_role, getattr(adapter, 'active_start_stage', 'unavailable'))
        raise
    finally:
        if (not completed or not leave_running_for_administrator) and adapter.cleanup() != 'complete':
            transport.fail('owner-cleanup-required')


def validate_guest_observation(value, expected_selection_digest=None):
    fields = {'schemaVersion', 'kind', 'executionClass', 'selectionDigest', 'privateEvidenceDigest',
              'evidenceClass', 'status', 'observedCases', 'fullAppBudgets', 'releaseEligible',
              'phaseComplete', 'cleanupState'}
    if (not isinstance(value, dict) or set(value) != fields or value['schemaVersion'] != 1
            or value['kind'] != 'pr320-installed-owner-cancellation'
            or value['executionClass'] != contract.EXECUTION_CLASS
            or value['evidenceClass'] != 'installed-process-owner'
            or any(re.fullmatch(r'sha256:[0-9a-f]{64}', str(value[key])) is None
                   for key in ('selectionDigest', 'privateEvidenceDigest'))
            or value['status'] not in {'observed', 'not-observed'}
            or value['observedCases'] != (['cancellation'] if value['status'] == 'observed' else [])
            or value['fullAppBudgets'] != 'not-observed' or value['releaseEligible'] is not False
            or value['phaseComplete'] is not False
            or value['cleanupState'] not in {'administrator-required', 'observer-owned', 'completed'}
            or expected_selection_digest is not None and value['selectionDigest'] != expected_selection_digest):
        transport.fail('owner-observation-invalid')
    return value


def attach_guest_context(value, identity, runtime_policy, campaign_deadline):
    validate_guest_observation(value)
    return {**value, 'identity': identity, 'runtimePolicy': runtime_policy,
        'campaignDeadlineMonotonicNs': campaign_deadline,
        'workloadAcceptance': 'incomplete-pr320-private-evidence-not-verified',
        'protectedExecutionEnabled': False}
