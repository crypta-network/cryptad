"""Offline accepting owner vectors and independent-original substitution regressions."""
from __future__ import annotations
import copy
import json
import unittest
from unittest.mock import patch

import pr320_cancellation_contract as contract
import pr320_owner_runtime_evidence as evidence
import pr320_installed_dispatch as dispatch
import restricted_workload_controller as controller
from cryptad_certification import composed_budget_evidence as oracle
from cryptad_certification import runtime_pressure_evidence as pressure
from cryptad_certification.tests.test_composed_budget_causal_evidence import deferred_owner_fixture, CausalFixture
from test_pr320_storage_installed import selected as storage_selected
from test_pr318_storage_installed import resign


def owner_selection():
    selected, fixture = storage_selected('window-crossing', 'available-capacity')
    plan, private, authorization = selected['plan'], selected['private'], selected['authorization']
    plan['experimentId'] = contract.EXPERIMENT
    private['root'] = '/var/lib/cryptad-cross-version/experiments/' + contract.EXPERIMENT
    authorization.update(executionClass=contract.EXECUTION_CLASS, experimentId=contract.EXPERIMENT, root=private['root'])
    budget = authorization['budgetSelection']
    tools = {name: 'sha256:' + 'd' * 64 for name in contract.TOOL_PATHS}
    budget.update(caseIds=['cancellation'], toolIdentities=tools,
        privateRootClass='controller-derived-' + contract.EXPERIMENT)
    plan['workloadInputs'] = {'scheduler': tools['installedDriver']}
    plan['composedBudgetInputs']['collectorDigest'] = contract.canonical_digest({key: tools[key] for key in
        ('installedDriver', 'localBudgetAdapter', 'schedulerRuntime', 'evidenceOracle',
         'storageOracle', 'administrator', 'roleClients', 'runtimeEvidence')})
    budget['composedBudgetInputs'] = dict(plan['composedBudgetInputs'])
    from cryptad_certification.composed_budget_journal_member import campaign_inputs
    plan['budgetCampaignInputs'] = campaign_inputs(plan, tools)
    resign(plan, authorization)
    return selected


def vector():
    """Expand a historical causal vector into real two-family write observations."""
    old = deferred_owner_fixture(True)['causalCases'][0]
    builder = CausalFixture('cancellation', [], 21, 'cancelled', 'normal-ack')
    builder.case['operations'] = copy.deepcopy(old['operations'])
    for source in old['events']:
        event = copy.deepcopy(source)
        if event['kind'] == 'CONCURRENCY_LIMIT_REACHED':
            event.update(operation='content_fetch_global', scope=1)
        additions = []
        if event['kind'] == 'RATE_CHARGED':
            additions.append({**event, 'kind': 'RATE_WRITE_ATTEMPT'})
        additions.append(event)
        if event['operationId'] == 23 and event['kind'] in {'RATE_CHARGED', 'CONCURRENCY_HELD', 'CONCURRENCY_RELEASED'}:
            global_event = {**event, 'operation': 'content_fetch_global', 'scope': 1}
            if event['kind'] == 'RATE_CHARGED':
                additions.append({**global_event, 'kind': 'RATE_WRITE_ATTEMPT'})
            additions.append(global_event)
        for item in additions:
            item.update(sequence=len(builder.events) + 2, elapsedNanos=len(builder.events))
            builder.events.append(item)
    value = builder.finish([(22, 'trust_graph_import', 3, 'concurrency'),
        (22, 'trust_graph_import', 1, 'concurrency'), (23, 'foreground_content_fetch', 3, 'concurrency'),
        (23, 'content_fetch_global', 1, 'concurrency')])
    value.update(schemaVersion=4, storageCases=[])
    value['causalCases'][0]['snapshots']['during']['holds'].sort(
        key=lambda row: (row['operationId'], row['operation'], row['scope'], row['kind']))
    return value


def originals_fixture():
    selected = owner_selection()
    plan, authorization = selected['plan'], selected['authorization']
    attachment = vector()
    epoch = 'sha256:' + attachment['nodeEpoch'] + 'a' * 32
    node = plan['nodes'][0]
    attachment.update(workloadDigest=plan['workloadInputs']['scheduler'], productDigest=node['artifactDigest'],
        sourceCommit=node['sourceCommit'], appCohortDigest=pressure.baseline.digest(node['appDigests']),
        **plan['composedBudgetInputs'])
    derived = oracle.derive(attachment, workload_digest=attachment['workloadDigest'], product_digest=attachment['productDigest'],
        source_commit=attachment['sourceCommit'], app_cohort_digest=attachment['appCohortDigest'],
        node_epoch=attachment['nodeEpoch'], collector_digest=attachment['collectorDigest'], configuration_digest=attachment['configurationDigest'])
    record = dict(roleEpochDigest=epoch, generation='b' * 64, managerInvocation='c' * 32, bootId='d' * 36, handle='e' * 32)
    worker, daemon = {'fixtureProcess': {'hostPid': 100, 'startTicks': 1}}, {'hostPid': 99, 'startTicks': 2}
    contexts = {app: dict(appId=app, role='candidate-sender', roleEpochDigest=epoch,
        workerEpochDigest=contract.canonical_digest(worker), daemonEpochDigest=contract.canonical_digest(daemon),
        **{key: 'sha256:' + 'a' * 64 for key in ('originDigest', 'sessionDigest', 'sessionExpiryDigest')})
        for app in contract.PERMISSIONS}
    base = dict(schemaVersion=1, kind='pr320-original-process-owner', selectionDigest=authorization['selectionDigest'],
        appId='feed-reader', **{key: record[key] for key in ('generation', 'managerInvocation', 'bootId', 'handle')},
        daemon=daemon, worker=worker, taskDigest='sha256:' + 'f' * 64)
    receipts = [{**base, 'status': status, 'observedMonotonicNs': time} for time, status in
        enumerate(('task-intent', 'request-written', 'worker-death-observed'), 1)]
    private = dict(schemaVersion=1, kind='pr320-private-owner-cancellation', selectionDigest=authorization['selectionDigest'],
        contexts=contexts, attempt={'status': 'observed'}, originalStimulus=receipts[1],
        composedBudgetEvidence=attachment, composedBudgetCoverage=derived)
    row = attachment['causalCases'][0]
    def native(phase):
        snapshot = row['snapshots'][phase]
        return dict(work=dict(collectorEpoch=row['collectorEpoch'], lastSequence=snapshot['sequence'], dropped=0,
            events=[event for event in row['events'] if event['sequence'] <= snapshot['sequence']]),
            budget=dict(valid=True, rates=snapshot['rates']), retainedStatements=0)
    checkpoints = [{'phase': phase, 'native': native('during' if phase == 'active' else 'after' if phase == 'final' else phase)}
        for phase in ('before', 'active', 'during', 'after', 'final')]
    checkpoints += [{'phase': 'owner-start', 'receipt': receipts[1]}, {'phase': 'owner-stop', 'httpStatus': 200},
        {'phase': 'owner-death', 'receipt': receipts[2]}, {'phase': 'attempt-completed', 'attempt': private['attempt']}]
    diagnostics = dict(ownerSelectionDigest=authorization['selectionDigest'], ownerOriginalCollection='complete',
        ownerBootstrapContext={'apps': contexts, **{key: record[key] for key in ('generation', 'managerInvocation', 'bootId', 'handle')}},
        ownerStimulusReceipts=receipts)
    store = dict(durableUsage=[], graphFacts=[], captureSource='administrator-fixed-file-store-readback', capturedMonotonicNs=1)
    original = dict(schemaVersion=1, kind='pr320-original-owner-native', selectionDigest=authorization['selectionDigest'],
        before={'native': native('before'), 'store': store}, after={'native': native('after'), 'store': store})
    return private, selected, diagnostics, {'controllerRecords': {'candidate-sender': {'record': record}}}, checkpoints, original


class OriginalOwnerTest(unittest.TestCase):
    def test_accepting_normal_ack_requires_actual_signed_worker_and_root_native_originals(self):
        args = originals_fixture()
        self.assertTrue(contract.verify_selection_contract(**args[1]))
        self.assertEqual(['cancellation'], evidence.decode_private(json.dumps(args[0]).encode())['composedBudgetCoverage']['observedCases'])
        evidence.decode_root_native(json.dumps(args[-1]).encode())
        with patch('pr316_mail_runtime_runner._terminal_cleanup_verified', return_value=True):
            self.assertEqual(['cancellation'], evidence.validate_originals(*args)['observedCases'])
        self.assertEqual(5, len(dispatch.capture_members(contract.EXECUTION_CLASS)))

    def test_worker_death_bootstrap_root_event_and_charge_substitutions_reject(self):
        for fault in ('worker', 'death', 'bootstrap', 'native', 'cleanup', 'checkpoint'):
            args = json.loads(json.dumps(originals_fixture()))
            private, _selected, diagnostics, _terminal, checkpoints, original = args
            if fault == 'worker': diagnostics['ownerStimulusReceipts'][1]['worker']['fixtureProcess']['startTicks'] += 1
            elif fault == 'death': diagnostics['ownerStimulusReceipts'].pop()
            elif fault == 'bootstrap': diagnostics['ownerBootstrapContext']['apps']['feed-reader']['sessionDigest'] = 'sha256:' + 'e' * 64
            elif fault == 'native': original['after']['native']['work']['events'][-1]['kind'] = 'REQUEST_FAILED'
            elif fault == 'cleanup': diagnostics['ownerOriginalCollection'] = 'incomplete'
            else: checkpoints[2]['native']['budget']['rates'][0]['count'] += 1
            with self.subTest(fault=fault), patch('pr316_mail_runtime_runner._terminal_cleanup_verified', return_value=True), self.assertRaises(ValueError):
                evidence.validate_originals(*args)

    def test_missing_tail_remains_incomplete_without_cancellation_credit(self):
        private = originals_fixture()[0]
        private['composedBudgetEvidence']['causalCases'] = []
        private['attempt'] = {'status': 'not-observed', 'reason': 'delayed-owner-tail-not-observed'}
        attachment = private['composedBudgetEvidence']
        private['composedBudgetCoverage'] = oracle.derive(attachment, workload_digest=attachment['workloadDigest'],
            product_digest=attachment['productDigest'], source_commit=attachment['sourceCommit'],
            app_cohort_digest=attachment['appCohortDigest'], node_epoch=attachment['nodeEpoch'],
            collector_digest=attachment['collectorDigest'], configuration_digest=attachment['configurationDigest'])
        evidence.decode_private(json.dumps(private).encode())
        self.assertEqual('incomplete', evidence.public_projection(private, source_identity_digest='sha256:' + 'a' * 64,
            originals_verified=True, privacy_verified=True, watcher_finished=True, guest_stopped=True)['status'])


class ScopeTransportTest(unittest.TestCase):
    def test_operator_snapshots_use_host_port_and_each_session_uses_own_origin_listener(self):
        contexts = {app: {'origin': 'http://127.0.0.1:' + str(20000 + index), 'session': 'private'}
                    for index, app in enumerate(contract.PERMISSIONS)}
        calls, sequence = [], 0
        def http(port, path, _headers, **kwargs):
            nonlocal sequence
            calls.append((port, path, kwargs))
            if path.endswith('/import-uri'):
                sequence += 1
                return (400 if sequence <= 2 else 403), {}, b'{}'
            index = min(sequence, 3)
            start = sum(2 if item < 2 else 3 for item in range(sequence))
            kinds = [] if sequence == 0 else (['COMPOSED_URI_IMPORT_START', 'REQUEST_FAILED'] if sequence <= 2
                else ['COMPOSED_URI_IMPORT_START', 'CAPABILITY_DENIED', 'REQUEST_FAILED'])
            events = [{'sequence': start - len(kinds) + item + 1, 'kind': kind, 'scope': sequence + 2}
                      for item, kind in enumerate(kinds)]
            return 200, {}, json.dumps({'work': {'collectorEpoch': 'a', 'lastSequence': start, 'dropped': 0, 'events': events},
                'budget': {'rates': [], 'activeFamilyLeases': 0, 'reservedFamilyRates': 0, 'valid': True}}).encode()
        with patch('restricted_workload_network._connect_port', side_effect=lambda _role, port: port), patch.object(controller, '_http', side_effect=http):
            bindings, _controls = controller._route_scope_controls('candidate-sender', contexts)
        self.assertEqual([3, 4, 5, 6], [row['scope'] for row in bindings])
        self.assertEqual([20000, 20001, 20002, 20003], [port for port, path, _ in calls if path.endswith('/import-uri')])
        self.assertEqual({19402}, {port for port, path, _ in calls if path.endswith('/runtime-observation')})


if __name__ == '__main__':
    unittest.main()
