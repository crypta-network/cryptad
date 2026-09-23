"""Offline orchestration regression tests; they do not execute installed acceptance."""
import base64
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import installation
import pr315_workload_runner as runner


def synthetic_role_kernel_roster():
    """Offline schema fixture only; never an installed observation."""
    return {'observerUid': 987, 'runnerUid': 1000,
            'roles': [{'role': role, 'uid': 983 + index, 'gid': 983 + index,
                       'invocationId': format(index + 1, '032x'),
                       'processEpoch': 100 + index, 'bootId': 'a' * 32,
                       'cgroupDigest': runner.fixtures.runtime.canonical_digest({
                           'role': role, 'identity': [1, 99 + index]})[7:],
                       'networkNamespace': 200 + index}
                      for index, role in enumerate(runner.acceptance.ROLES)]}


def synthetic_terminal_roster(roster):
    """Offline cross-check fixture, never a captured administrator record."""
    records, receipts = {}, {}
    for index, row in enumerate(roster['roles']):
        role = row['role']
        record = {'state': 'quiescent', 'generation': 'c' * 64,
                  'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                  'managerInvocation': row['invocationId'], 'cgroupIdentity': [1, 99 + index]}
        records[role] = {'status': 'captured', 'record': record}
        receipts[role] = {'current': {'status': 'captured', 'record': {
            **record, 'membership': 'only-stop-helper', 'descendantCgroups': 0}}}
    receipts['candidate-sender']['previous'] = {'status': 'captured'}
    return {'schemaVersion': 1, 'kind': 'pr315-private-volatile-diagnostics',
            'cleanupReportedByCaller': True, 'sentinel': {'status': 'matched'},
            'controllerRecords': records, 'stopReceipts': receipts}


def synthetic_host_identity():
    return {'helperSourceCommit': 'b' * 40, 'helperSourceTree': 'c' * 40,
            'productSourceCommit': 'd' * 40, 'productDigest': 'e' * 64,
            'bundleIdentity': 'a' * 64, 'testKitDigest': 'f' * 64,
            'profileDigest': '1' * 64, 'bootClosureDigest': '2' * 64,
            'preparedImageDigest': '3' * 64, 'fixtureManifestDigest': '4' * 64}


def synthetic_resource_diagnostics(roster):
    return {'during': {'services': {
        'cryptad-workload@' + row['role'] + '.service': {
            'lastObserved': {'cgroupIdentity': [1, 99 + index],
                             'memory.current': 1024 + index,
                             'pids.current': 2 + index,
                             'cpu.stat': {'usage_usec': 100 + index}},
            'lastObservedWindow': {'startedMonotonicNs': 50 + index * 10,
                                   'finishedMonotonicNs': 51 + index * 10}}
        for index, row in enumerate(roster['roles'])}}}


def synthetic_exchange_audits(roster):
    """Synthetic root/observer copies with matching digests for offline verifier tests."""
    audits, observed = {}, {}
    for index, (case, method) in enumerate((('own-management', 'connect-fcp'),
                                            ('dynamic-app-bootstrap', 'bootstrap-mail'))):
        request = format(100 + index, '064x')
        response = format(200 + index, '064x')
        audits[case] = {'status': 'captured', 'record': {
            'schemaVersion': 1, 'kind': 'pr315-fixed-exchange-audit',
            'caseId': case, 'method': method, 'role': 'candidate-sender',
            'managerInvocation': roster['roles'][0]['invocationId'],
            'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            'cgroupIdentity': [1, 99], 'requestDigest': request,
            'responseDigest': response, 'startedMonotonicNs': 50 + index * 10,
            'finishedMonotonicNs': 51 + index * 10, 'serverRequests': 1}}
        observed[case] = {'method': method, 'requestDigest': request,
                          'responseDigest': response}
    return audits, observed


def synthetic_fnp_observation(roster, helper_commit):
    """Offline fixed CHK transcript and six-link root counter pair only."""
    operation = 'op-' + 'c' * 32
    uri = 'CHK@synthetic-fixed-reference'
    payload = runner.fixtures.runtime.fixed_pr315_payload(helper_commit, operation)
    fields = runner.fixtures.runtime.interop.build_client_get_fields(
        operation + '-fetch', uri, ignore_ds=True)
    text = ('[synthetic] SEND ClientGet\n'
            + ''.join(f'{key}={value}\n' for key, value in fields.items())
            + 'EndMessage\n[synthetic] RECV AllData\n'
            + f'Identifier={operation}-fetch\nDataLength={len(payload)}\nData\n'
            + f'PayloadLength={len(payload)}\nPayloadBase64={base64.b64encode(payload).decode()}\n')
    recipient = roster['roles'][1]
    names = runner.workload_network.FNP_COUNTERS
    before = {'schemaVersion': 1, 'kind': 'pr315-fixed-fnp-counters',
              'policyDigest': hashlib.sha256(runner.workload_network.switch_rules().encode()).hexdigest(),
              'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
              'switchNamespaceIdentity': [1, 42], 'observedMonotonicNs': 10,
              'counters': {name: {'packets': 1, 'bytes': 100} for name in names.values()}}
    after = copy.deepcopy(before)
    after['observedMonotonicNs'] = 100
    for link in (('candidate-recipient', 'relay-no-apps'),
                 ('relay-no-apps', 'candidate-sender'),
                 ('candidate-sender', 'relay-no-apps'),
                 ('relay-no-apps', 'candidate-recipient')):
        after['counters'][names[link]] = {'packets': 2, 'bytes': 200}
    root = {'schemaVersion': 1, 'kind': 'pr315-administrator-fnp-counter-pair',
            'caseId': 'fnp-content-retrieval', 'role': 'candidate-recipient',
            'managerInvocation': recipient['invocationId'], 'before': before, 'after': after}
    observed = {phase: {'phase': phase, 'managerInvocation': recipient['invocationId'],
                        'snapshot': snapshot} for phase, snapshot in (('before', before), ('after', after))}
    content = {'source': 'candidate-sender', 'recipient': 'candidate-recipient',
               'operation': operation, 'referenceDigest': hashlib.sha256(uri.encode()).hexdigest(),
               'requestDigest': runner.fixtures.runtime.canonical_digest(fields)[7:],
               'payloadDigest': hashlib.sha256(payload).hexdigest(),
               'sourceControlDigest': hashlib.sha256(payload).hexdigest(),
               'responseDigest': hashlib.sha256(payload).hexdigest(), 'bytes': len(payload),
               'startedMonotonicNs': 20, 'finishedMonotonicNs': 80}
    return root, observed, content, text


class RunnerTests(unittest.TestCase):
    def test_predeclared_groups_partition_exact_historical_inventory(self):
        groups = runner.groups()
        self.assertEqual([8, 26, 11], [len(names) for _, names in groups])
        names = [name for _, group in groups for name in group]
        self.assertEqual(45, len(set(names)))
        self.assertEqual(set(runner.acceptance.CASES), set(names))

    def test_test_kit_entries_cannot_export_to_production(self):
        for name in ('fixtures', 'guest', 'runner', 'evidence'):
            self.assertFalse(installation.production_member(Path(
                'tools/release-certification/restricted/pr315_workload_' + name + '.py')))

    def test_memory_admission_accounts_for_guest_overhead_and_host_reserve(self):
        args = SimpleNamespace(memory_budget_bytes=runner.GUEST_MEMORY + runner.HOST_OVERHEAD,
                               min_host_memory_bytes=1024**3)
        required = runner.GUEST_MEMORY + runner.HOST_OVERHEAD + args.min_host_memory_bytes
        self.assertIsNone(runner.memory_reason(args, {'effectiveAvailableBytes': required}))
        self.assertEqual('host-memory-reserve-unavailable',
            runner.memory_reason(args, {'effectiveAvailableBytes': required - 1}))
        args.memory_budget_bytes -= 1
        self.assertEqual('memory-budget-insufficient',
            runner.memory_reason(args, {'effectiveAvailableBytes': required}))

    def test_positive_requires_exact_identity_owned_stop_and_successful_cleanup_result(self):
        identity = {'bundleIdentity': 'a' * 64, 'helperSourceCommit': 'b' * 40}
        report = {'hostVerifiedIdentity': identity, 'mode': 'workload-positive',
                  'guestStopped': True, 'status': 'guest-report-retained', 'guestExitCode': 0}
        result = {'identity': {'bundleIdentity': 'a' * 64, 'sourceCommit': 'b' * 40},
            'runtimePolicy': runner.fixtures.preparation.launcher_policy(),
            'contentRetrieval': 'observed', 'newEpoch': True, 'profile': runner.acceptance.PROFILE,
            'topologyRoles': 4, 'signedAppWorkers': 2, 'protectedExecutionEnabled': False,
            'roleKernelRoster': synthetic_role_kernel_roster(),
            'workloadAcceptance': 'incomplete-hostile-contract-not-executed'}
        terminal = synthetic_terminal_roster(result['roleKernelRoster'])
        self.assertTrue(runner.positive_executed(report, result, terminal))
        for policy in (None, {}, {'revision': 'old'},
                       dict(result['runtimePolicy'], wrapperStartupTimeoutSeconds={
                           role: 60.0 if role == 'previous' else 30 for role in runner.acceptance.ROLES})):
            with self.subTest(policy=policy):
                self.assertFalse(runner.positive_executed(report, dict(result, runtimePolicy=policy), terminal))
        for field, value in (('guestStopped', False), ('guestExitCode', 1), ('hostVerifiedIdentity', {}),
                             ('workloadPurpose', 'startup-measurement')):
            changed = copy.deepcopy(report)
            changed[field] = value
            self.assertFalse(runner.positive_executed(changed, result, terminal))
        report['hostVerifiedIdentity'] = {}
        result['identity'] = {}
        self.assertFalse(runner.positive_executed(report, result, terminal))
        report['hostVerifiedIdentity'] = identity
        result['identity'] = {'bundleIdentity': 'a' * 64, 'sourceCommit': 'b' * 40}
        for roster in (None, {}, dict(result['roleKernelRoster'], runnerUid=987)):
            with self.subTest(roster=roster):
                self.assertFalse(runner.positive_executed(report, dict(result, roleKernelRoster=roster), terminal))
        for changed in (None, {}, dict(terminal, cleanupReportedByCaller=False),
                        dict(terminal, sentinel=None)):
            self.assertFalse(runner.positive_executed(report, result, changed))
        changed = copy.deepcopy(terminal)
        changed['stopReceipts']['relay-no-apps']['current']['record']['cgroupIdentity'] = [1, 999]
        self.assertFalse(runner.positive_executed(report, result, changed))

    def test_public_result_never_promotes_positive_aggregate_to_case_acceptance(self):
        result = runner.public_result('implementation-incomplete', True)
        self.assertTrue(result['installedPositiveExecuted'])
        self.assertFalse(result['installedWorkloadAcceptanceSatisfied'])
        self.assertFalse(result['finiteNativeAcceptance'])
        self.assertFalse(result['phaseComplete'])
        self.assertEqual({'not-executed'}, {row['status'] for row in result['cases']})

    def test_real_verifier_accepts_only_two_well_bound_positive_records(self):
        roster = synthetic_role_kernel_roster()
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        result = {'roleKernelRoster': roster,
                  'roleKernelRosterWindow': {'startedMonotonicNs': 10, 'finishedMonotonicNs': 20}}
        identity, attempt = runner.positive_case_attempt(report, result,
            {'mailDigest': 'sha256:' + '5' * 64}, 30, 40)
        checked = runner.acceptance.verify_attempts(identity, [attempt])
        self.assertTrue(checked['recordContractValid'])
        self.assertEqual({'installed-ready', 'four-role-start'},
                         {row['caseId'] for row in checked['cases'] if row['status'] == 'passed'})
        self.assertFalse(checked['installedWorkloadAcceptanceSatisfied'])
        invalid = copy.deepcopy(result)
        invalid['roleKernelRosterWindow']['finishedMonotonicNs'] = 10
        with self.assertRaisesRegex(ValueError, 'case-window-invalid'):
            runner.positive_case_attempt(report, invalid, {'mailDigest': 'sha256:' + '5' * 64}, 30, 40)

    def test_app_and_resource_cases_require_actual_scoped_samples(self):
        roster = synthetic_role_kernel_roster()
        sender = roster['roles'][0]
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        result = {'roleKernelRoster': roster,
            'roleKernelRosterWindow': {'startedMonotonicNs': 10, 'finishedMonotonicNs': 20},
            'appKernelProcess': {'role': 'candidate-sender', 'provider': 'bubblewrap',
                'hostPid': 101, 'namespacePid': 3, 'processEpoch': 201,
                'invocationId': sender['invocationId'], 'javaHostPid': 102,
                'javaStartTicks': 202, 'provenance': 'controller-kernel-sample'},
            'appKernelWindow': {'startedMonotonicNs': 30, 'finishedMonotonicNs': 40}}
        diagnostics = synthetic_resource_diagnostics(roster)
        selected = {'mailDigest': 'sha256:' + '5' * 64}
        identity, attempt = runner.positive_case_attempt(report, result, selected, 90, 100,
                                                          diagnostics)
        checked = runner.acceptance.verify_attempts(identity, [attempt])
        self.assertTrue(checked['recordContractValid'])
        self.assertEqual({'installed-ready', 'four-role-start', 'signed-apphost-child',
                          'kernel-resource-scope'},
                         {row['caseId'] for row in checked['cases'] if row['status'] == 'passed'})
        self.assertFalse(checked['installedWorkloadAcceptanceSatisfied'])
        changed = copy.deepcopy(diagnostics)
        changed['during']['services']['cryptad-workload@relay-no-apps.service'][
            'lastObserved']['cgroupIdentity'] = [1, 999]
        _, without_resources = runner.positive_case_attempt(report, result, selected, 90, 100,
                                                             changed)
        self.assertNotIn('kernel-resource-scope', without_resources['declaredCases'])
        changed_result = copy.deepcopy(result)
        changed_result['appKernelProcess']['provenance'] = 'candidate-api'
        _, without_app = runner.positive_case_attempt(report, changed_result, selected, 90, 100,
                                                      diagnostics)
        self.assertNotIn('signed-apphost-child', without_app['declaredCases'])

    def test_controller_exchange_commitments_require_matching_root_and_observer_bytes(self):
        roster = synthetic_role_kernel_roster()
        audits, observed = synthetic_exchange_audits(roster)
        terminal = synthetic_terminal_roster(roster)
        terminal['exchangeAudits'] = audits
        result = {'roleKernelRoster': roster,
                  'roleKernelRosterWindow': {'startedMonotonicNs': 10, 'finishedMonotonicNs': 20},
                  'controlExchanges': observed}
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        selection = {'mailDigest': 'sha256:' + '5' * 64}
        identity, attempt = runner.positive_case_attempt(report, result, selection, 90, 100,
                                                         terminal=terminal)
        checked = runner.acceptance.verify_attempts(identity, [attempt])
        self.assertTrue(checked['recordContractValid'])
        self.assertEqual({'own-management', 'dynamic-app-bootstrap'},
                         set(attempt['caseCommitments']))
        changed = copy.deepcopy(result)
        changed['controlExchanges']['dynamic-app-bootstrap']['responseDigest'] = '0' * 64
        _, rejected = runner.positive_case_attempt(report, changed, selection, 90, 100,
                                                   terminal=terminal)
        self.assertNotIn('dynamic-app-bootstrap', rejected['declaredCases'])
        changed_root = copy.deepcopy(terminal)
        changed_root['exchangeAudits']['own-management']['record']['managerInvocation'] = 'f' * 32
        _, rejected = runner.positive_case_attempt(report, result, selection, 90, 100,
                                                   terminal=changed_root)
        self.assertNotIn('own-management', rejected['declaredCases'])

    def test_restart_case_requires_real_prior_group_and_same_durable_state(self):
        roster = synthetic_role_kernel_roster()
        sender = roster['roles'][0]
        old = dict(sender, invocationId='f' * 32, processEpoch=50,
            cgroupDigest=runner.fixtures.runtime.canonical_digest({
                'role': 'candidate-sender', 'identity': [1, 98]})[7:])
        context = {
            'before': {'roleIdentity': old, 'stateDigest': '5' * 64,
                       'deadlineNs': 1000, 'observedMonotonicNs': 70},
            'after': {'roleIdentity': sender, 'stateDigest': '5' * 64,
                      'deadlineNs': 1000, 'observedMonotonicNs': 80}}
        result = {'roleKernelRoster': roster,
                  'roleKernelRosterWindow': {'startedMonotonicNs': 10, 'finishedMonotonicNs': 20},
                  'restartContext': context,
                  'restartWindow': {'startedMonotonicNs': 60, 'finishedMonotonicNs': 90}}
        terminal = synthetic_terminal_roster(roster)
        terminal['controllerRecords']['campaign'] = {'status': 'captured',
            'record': {'deadlineMonotonicNs': 1000}}
        terminal['sentinel']['observedDigest'] = 'sha256:' + '5' * 64
        terminal['stopReceipts']['candidate-sender']['previous']['record'] = {
            'managerInvocation': old['invocationId'],
            'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            'cgroupIdentity': [1, 98]}
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        identity, attempt = runner.positive_case_attempt(report, result,
            {'mailDigest': 'sha256:' + '5' * 64}, 100, 110, terminal=terminal)
        checked = runner.acceptance.verify_attempts(identity, [attempt])
        self.assertTrue(checked['recordContractValid'])
        self.assertIn('restart-durable-state', attempt['declaredCases'])
        self.assertFalse(checked['installedWorkloadAcceptanceSatisfied'])
        changed = copy.deepcopy(terminal)
        changed['stopReceipts']['candidate-sender']['previous']['record']['cgroupIdentity'] = [1, 97]
        _, rejected = runner.positive_case_attempt(report, result,
            {'mailDigest': 'sha256:' + '5' * 64}, 100, 110, terminal=changed)
        self.assertNotIn('restart-durable-state', rejected['declaredCases'])

    def test_fnp_case_requires_actual_payload_and_all_four_directional_counter_deltas(self):
        roster = synthetic_role_kernel_roster()
        host = synthetic_host_identity()
        root, observed, content, transcript = synthetic_fnp_observation(roster,
                                                                          host['helperSourceCommit'])
        terminal = synthetic_terminal_roster(roster)
        terminal['fnpCounterPair'] = {'status': 'captured', 'record': root}
        terminal['observerFcpLogs'] = {'candidate-recipient': {'status': 'captured',
            'tailBase64': base64.b64encode(transcript.encode()).decode(),
            'tailBytes': len(transcript.encode())}}
        result = {'roleKernelRoster': roster,
                  'roleKernelRosterWindow': {'startedMonotonicNs': 1, 'finishedMonotonicNs': 2},
                  'fnpCounterPair': observed, 'contentEvidence': content}
        report = {'hostVerifiedIdentity': host, 'guestStopped': True}
        selected = {'mailDigest': 'sha256:' + '5' * 64}
        identity, attempt = runner.positive_case_attempt(report, result, selected, 110, 120,
                                                          terminal=terminal)
        checked = runner.acceptance.verify_attempts(identity, [attempt])
        self.assertTrue(checked['recordContractValid'])
        self.assertIn('fnp-content-retrieval', attempt['declaredCases'])
        self.assertFalse(checked['installedWorkloadAcceptanceSatisfied'])
        wrong_origin = copy.deepcopy(terminal)
        wrong_origin['fnpCounterPair']['record']['kind'] = 'pr315-fnp-counter-pair'
        _, rejected = runner.positive_case_attempt(report, result, selected, 110, 120,
                                                   terminal=wrong_origin)
        self.assertNotIn('fnp-content-retrieval', rejected['declaredCases'])
        bad_route = copy.deepcopy(terminal)
        name = runner.workload_network.FNP_COUNTERS[('relay-no-apps', 'candidate-sender')]
        bad_route['fnpCounterPair']['record']['after']['counters'][name] = {'packets': 1, 'bytes': 100}
        matched_bad_route = copy.deepcopy(result)
        matched_bad_route['fnpCounterPair']['after']['snapshot']['counters'][name] = {
            'packets': 1, 'bytes': 100}
        _, rejected = runner.positive_case_attempt(report, matched_bad_route, selected, 110, 120,
                                                   terminal=bad_route)
        self.assertNotIn('fnp-content-retrieval', rejected['declaredCases'])
        changed = copy.deepcopy(result)
        changed['contentEvidence']['responseDigest'] = '0' * 64
        _, rejected = runner.positive_case_attempt(report, changed, selected, 110, 120,
                                                   terminal=terminal)
        self.assertNotIn('fnp-content-retrieval', rejected['declaredCases'])

    def test_installed_transport_path_reaches_six_cases_but_never_full_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            args = SimpleNamespace(source=Path(runner.__file__).resolve().parents[3],
                output=root / 'suite', storage_root=root, startup_measurement=False,
                prepared_fixtures=root / 'fixtures', qemu_root=root / 'qemu',
                prepared_image=root / 'image', seed=root / 'seed', ssh_key=root / 'key',
                known_hosts=root / 'pin', storage_budget_bytes=40 * 1024**3,
                min_free_bytes=8 * 1024**3, memory_budget_bytes=7 * 1024**3,
                min_host_memory_bytes=1024**3, profile='tcg-single',
                fixture_manifest_digest='4' * 64, product_source_commit='d' * 40)
            host = synthetic_host_identity()
            report = {'mode': 'workload-positive', 'workloadPurpose': 'positive',
                'guestStopped': True, 'status': 'guest-report-retained', 'guestExitCode': 0,
                'hostVerifiedIdentity': host}
            roster = synthetic_role_kernel_roster()
            observation = {'identity': {'bundleIdentity': host['bundleIdentity'],
                    'sourceCommit': host['helperSourceCommit']},
                'runtimePolicy': runner.fixtures.preparation.launcher_policy(),
                'contentRetrieval': 'observed', 'newEpoch': True, 'profile': runner.acceptance.PROFILE,
                'topologyRoles': 4, 'signedAppWorkers': 2, 'protectedExecutionEnabled': False,
                'roleKernelRoster': roster,
                'roleKernelRosterWindow': {'startedMonotonicNs': 10, 'finishedMonotonicNs': 20},
                'appKernelProcess': {'role': 'candidate-sender', 'provider': 'bubblewrap',
                    'hostPid': 101, 'namespacePid': 3, 'processEpoch': 201,
                    'invocationId': roster['roles'][0]['invocationId'],
                    'javaHostPid': 102, 'javaStartTicks': 202,
                    'provenance': 'controller-kernel-sample'},
                'appKernelWindow': {'startedMonotonicNs': 30, 'finishedMonotonicNs': 40},
                'workloadAcceptance': 'incomplete-hostile-contract-not-executed'}
            terminal = synthetic_terminal_roster(roster)
            terminal['exchangeAudits'], observation['controlExchanges'] = synthetic_exchange_audits(roster)
            def fake_transport(selected):
                selected.attempt.mkdir(mode=0o700)
                for name, value in (('attempt.private.json', report),
                    ('pr314-workload-observation.private.json', observation),
                    ('pr315-workload-volatile.private.json', terminal),
                    ('pr315-workload-memory.private.json', synthetic_resource_diagnostics(roster))):
                    runner.native_runner._save(selected.attempt / name, value)
                return 0
            with patch.object(runner, 'prerequisites', return_value=[]), \
                    patch.object(runner, 'memory_snapshot', return_value={'effectiveAvailableBytes': 9 * 1024**3}), \
                    patch.object(runner.native_runner, 'required_attempt_bytes', return_value=1), \
                    patch.object(runner.native_runner, 'capacity_reason', return_value=None), \
                    patch.object(runner.reference, 'run', side_effect=fake_transport), \
                    patch.object(runner.reference, 'verified_attempt_identity', return_value=host), \
                    patch.object(runner.fixtures, 'verify', return_value={'mailDigest': 'sha256:' + '5' * 64}), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(2, runner.run(args))
            assessment = json.loads((args.output / 'assessment.json').read_text())
            self.assertTrue(assessment['installedPositiveExecuted'])
            self.assertFalse(assessment['installedWorkloadAcceptanceSatisfied'])
            self.assertEqual({'installed-ready', 'four-role-start', 'signed-apphost-child',
                              'own-management', 'dynamic-app-bootstrap', 'kernel-resource-scope'},
                             {row['caseId'] for row in assessment['cases'] if row['status'] == 'passed'})
            self.assertTrue((args.output / 'positive-v8-evidence.private.json').is_file())

    def test_workload_reference_projection_omits_private_guest_and_source_fields(self):
        report = runner.reference.public_report({'mode': 'workload-positive', 'executed': True,
            'status': 'guest-report-retained', 'guestStopped': True,
            'guestSummary': {'secret': 'private-token'}, 'productDigest': 'private-product',
            'preparedImageDigest': 'private-image', 'helperSourceCommit': 'private-commit'})
        self.assertNotIn('private-', json.dumps(report))
        self.assertFalse(report['installedWorkloadAcceptanceSatisfied'])

    def test_missing_inputs_return_78_without_reference_allocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            source = Path(__file__).resolve().parents[3]
            args = SimpleNamespace(source=source, output=root / 'suite', storage_root=root,
                prepared_fixtures=root / 'absent-fixtures', qemu_root=root / 'absent-qemu',
                prepared_image=root / 'absent-image', seed=root / 'absent-seed',
                ssh_key=root / 'absent-key', known_hosts=root / 'absent-pin',
                storage_budget_bytes=40 * 1024**3, min_free_bytes=8 * 1024**3,
                memory_budget_bytes=7 * 1024**3, min_host_memory_bytes=1024**3,
                profile='tcg-single')
            with patch.object(runner.os, 'geteuid', return_value=os.getuid()), \
                    patch.object(runner, 'memory_snapshot', return_value={'effectiveAvailableBytes': 9 * 1024**3}), \
                    patch.object(runner.reference, 'run') as launch, redirect_stdout(io.StringIO()):
                self.assertEqual(78, runner.run(args))
            launch.assert_not_called()
            value = json.loads((args.output / 'assessment.json').read_text())
            self.assertEqual('setup-blocked', value['status'])
            self.assertEqual(45, len(value['cases']))
            self.assertFalse((args.output / 'attempt-01').exists())


class StartupPurposeTests(unittest.TestCase):
    def test_host_startup_selection_rejects_forged_successful_guest_aggregate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            args = SimpleNamespace(source=Path(runner.__file__).resolve().parents[3],
                output=root / 'suite', storage_root=root, startup_measurement=True,
                prepared_fixtures=root / 'fixtures', qemu_root=root / 'qemu',
                prepared_image=root / 'image', seed=root / 'seed', ssh_key=root / 'key',
                known_hosts=root / 'pin', storage_budget_bytes=40 * 1024**3,
                min_free_bytes=8 * 1024**3, memory_budget_bytes=7 * 1024**3,
                min_host_memory_bytes=1024**3, profile='tcg-single')
            report = {'mode': 'workload-positive', 'workloadPurpose': 'positive',
                'guestStopped': True, 'status': 'guest-report-retained', 'guestExitCode': 0,
                'hostVerifiedIdentity': {'bundleIdentity': 'a' * 64, 'helperSourceCommit': 'b' * 40}}
            forged = {'identity': {'bundleIdentity': 'a' * 64, 'sourceCommit': 'b' * 40},
                'runtimePolicy': runner.fixtures.preparation.launcher_policy(),
                'contentRetrieval': 'observed', 'newEpoch': True, 'profile': runner.acceptance.PROFILE,
                'topologyRoles': 4, 'signedAppWorkers': 2, 'protectedExecutionEnabled': False,
                'roleKernelRoster': synthetic_role_kernel_roster(),
                'workloadAcceptance': 'incomplete-hostile-contract-not-executed'}
            terminal = synthetic_terminal_roster(forged['roleKernelRoster'])
            self.assertTrue(runner.positive_executed(report, forged, terminal))
            selections = []
            def fake_transport(selected):
                selections.append(selected)
                selected.attempt.mkdir(mode=0o700)
                for name, value in (('attempt.private.json', report),
                    ('pr314-workload-observation.private.json', forged),
                    ('pr315-workload-volatile.private.json', terminal)):
                    runner.native_runner._save(selected.attempt / name, value)
                return 0
            with patch.object(runner, 'prerequisites', return_value=[]), \
                    patch.object(runner, 'memory_snapshot', return_value={'effectiveAvailableBytes': 9 * 1024**3}), \
                    patch.object(runner.native_runner, 'required_attempt_bytes', return_value=1), \
                    patch.object(runner.native_runner, 'capacity_reason', return_value=None), \
                    patch.object(runner.reference, 'run', side_effect=fake_transport), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(2, runner.run(args))
            self.assertTrue(selections[0].startup_measurement)
            value = json.loads((args.output / 'assessment.json').read_text())
            self.assertFalse(value['installedPositiveExecuted'])
            self.assertFalse(value['installedWorkloadAcceptanceSatisfied'])
            self.assertEqual({'not-executed'}, {row['status'] for row in value['cases']})


if __name__ == '__main__':
    unittest.main()
