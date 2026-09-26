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
        record = {'role': role, 'state': 'quiescent', 'generation': 'c' * 64,
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


def synthetic_lifecycle_actor(source, observed_ns):
    """Offline root test-kit epoch fixture; never an installed identity."""
    boot = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    cgroup = [1, 50]
    digest = runner.reference.sha256(source /
        'tools/release-certification/restricted/pr314_workload_driver.py')
    invocation = hashlib.sha256(json.dumps({'bootId': boot, 'pid': 500,
        'startTicks': 33, 'cgroupIdentity': cgroup,
        'sourceDigest': digest}, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()[:32]
    return {'pid': 500, 'uid': 0, 'startTicks': 33, 'bootId': boot,
            'cgroupIdentity': cgroup, 'cgroupDigest':
                runner.fixtures.runtime.canonical_digest({
                    'role': 'lifecycle-administrator', 'identity': cgroup})[7:],
            'invocationId': invocation, 'sourceDigest': digest,
            'observedMonotonicNs': observed_ns}


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
    def test_lost_start_requires_first_invocation_before_retry_and_exact_stop(self):
        roster = synthetic_role_kernel_roster()
        terminal = synthetic_terminal_roster(roster)
        del terminal['stopReceipts']['candidate-sender']['previous']
        terminal['controllerRecords']['campaign'] = {'status': 'captured', 'record': {
            'state': 'terminalizing', 'deadlineMonotonicNs': 1000}}
        for index, row in enumerate(roster['roles']):
            receipt = terminal['stopReceipts'][row['role']]['current']['record']
            receipt['startedMonotonicNs'] = 800 + index
            receipt['observedMonotonicNs'] = 820 + index
        sender = roster['roles'][0]
        boot = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        before = {'role': 'candidate-sender', 'state': 'prepared',
            'generation': None, 'managerInvocation': None,
            'cgroupIdentity': None, 'bootId': boot, 'mainPid': 0,
            'observedMonotonicNs': 5}
        first = {'role': 'candidate-sender', 'generation': 'b' * 64,
            'managerInvocation': sender['invocationId'], 'bootId': boot,
            'cgroupIdentity': [1, 99], 'mainPid': 123,
            'observedMonotonicNs': 50}
        retry = dict(first, observedMonotonicNs=700)
        dropped = {'requestDigest': 'd' * 64, 'sendStartedNs': 30,
                   'sendFinishedNs': 40}
        context = {'schemaVersion': 1,
            'kind': 'pr315-administrator-lost-start-intent',
            'before': before, 'requestDigest': dropped['requestDigest'],
            'first': first, 'droppedRequest': dropped, 'retry': retry}
        source = Path(__file__).resolve().parents[3]
        private = {'cleanup': 'completed', 'cleanupFinishedNs': 900,
            'probeStart': {'schemaVersion': 1, 'kind': 'pr315-workload-probe-start',
                'caseId': 'lost-start-response', 'startedMonotonicNs': 20},
            'lostStartBefore': before, 'lostStartResponse': context,
            'lifecycleActorBefore': synthetic_lifecycle_actor(source, 10),
            'lifecycleActorAfter': synthetic_lifecycle_actor(source, 950)}
        report = {'hostVerifiedIdentity': synthetic_host_identity(),
                  'guestStopped': True}
        result = {'roleKernelRoster': roster,
            'roleKernelRosterWindow': {'startedMonotonicNs': 100,
                                       'finishedMonotonicNs': 600},
            'campaignDeadlineMonotonicNs': 1000}
        fixture = {'schemaVersion': 4, 'mailDigest': 'sha256:' + '5' * 64}
        with patch.object(runner, 'group_prepared', return_value=True):
            identity, selected, sidecar = runner._lifecycle_group_attempt(
                'lost-start-response', report, result, fixture, private, terminal, source)
            self.assertEqual('passed', next(row['status'] for row in
                runner.acceptance.verify_attempts(identity, [selected])['cases']
                if row['caseId'] == 'lost-start-response'))
            self.assertEqual(first, sidecar['targetEpoch']['lostStartFirst'])
            changed = copy.deepcopy(private)
            changed['lostStartResponse']['retry']['managerInvocation'] = 'f' * 32
            self.assertIsNone(runner._lifecycle_group_attempt(
                'lost-start-response', report, result, fixture, changed, terminal, source))
            changed = copy.deepcopy(private)
            changed['lostStartResponse']['droppedRequest']['sendFinishedNs'] = 55
            self.assertIsNone(runner._lifecycle_group_attempt(
                'lost-start-response', report, result, fixture, changed, terminal, source))
            changed = copy.deepcopy(private)
            changed['lifecycleActorBefore']['uid'] = roster['observerUid']
            self.assertIsNone(runner._lifecycle_group_attempt(
                'lost-start-response', report, result, fixture, changed, terminal, source))
            changed_terminal = copy.deepcopy(terminal)
            changed_terminal['stopReceipts']['candidate-sender']['current'][
                'record']['startedMonotonicNs'] = 650
            self.assertIsNone(runner._lifecycle_group_attempt(
                'lost-start-response', report, result, fixture, private,
                changed_terminal, source))

    def test_wrong_port_for_pinned_host_key_stops_before_guest_allocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            for name in ('fixtures', 'qemu'):
                (root / name).mkdir()
            for name in ('image', 'seed', 'key'):
                (root / name).write_bytes(b'fixed-input')
            wire = (len(b'ssh-ed25519').to_bytes(4, 'big') + b'ssh-ed25519'
                    + (32).to_bytes(4, 'big') + b'K' * 32)
            pin = root / 'pin'
            pin.write_bytes(b'[127.0.0.1]:23112 ssh-ed25519 '
                            + base64.b64encode(wire) + b' pr312-reference\n')
            pin.chmod(0o600)
            args = SimpleNamespace(source=Path(runner.__file__).resolve().parents[3],
                output=root / 'suite', storage_root=root, case_group='positive',
                prepared_fixtures=root / 'fixtures', qemu_root=root / 'qemu',
                prepared_image=root / 'image', seed=root / 'seed', ssh_key=root / 'key',
                known_hosts=pin, port=23112, storage_budget_bytes=40 * 1024**3,
                min_free_bytes=8 * 1024**3, memory_budget_bytes=7 * 1024**3,
                min_host_memory_bytes=1024**3, profile='tcg-multi')
            self.assertEqual([], runner.prerequisites(args))
            args.port = 23113
            self.assertEqual(['known-hosts-port-pin-invalid'], runner.prerequisites(args))
            with patch.object(runner, 'memory_snapshot', return_value={
                    'effectiveAvailableBytes': 9 * 1024**3}), \
                    patch.object(runner.reference, 'run') as launch, \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(78, runner.run(args))
            launch.assert_not_called()
            self.assertFalse((args.output / 'attempt-01').exists())
            self.assertEqual(['known-hosts-port-pin-invalid'], json.loads(
                (args.output / 'assessment.json').read_text())['reasons'])
            args.port = 23112
            self.assertTrue(runner.known_hosts_matches_port(pin, args.port))
            pin.write_bytes(pin.read_bytes() + pin.read_bytes())
            self.assertFalse(runner.known_hosts_matches_port(pin, args.port))

    def test_output_group_preparation_requires_four_bound_roles_without_restarting_sender(self):
        roster = synthetic_role_kernel_roster()
        terminal = synthetic_terminal_roster(roster)
        del terminal['stopReceipts']['candidate-sender']['previous']
        report = {'mode': 'workload-positive', 'workloadPurpose': 'selected-group',
                  'status': 'guest-report-retained',
                  'guestStopped': True, 'guestExitCode': 0,
                  'hostVerifiedIdentity': synthetic_host_identity()}
        result = {'identity': {'sourceCommit': 'b' * 40, 'bundleIdentity': 'a' * 64},
                  'groupPreparation': 'output-symlink',
                  'contentRetrieval': 'not-executed-group', 'newEpoch': False,
                  'topologyRoles': 4, 'signedAppWorkers': 0,
                  'profile': runner.acceptance.PROFILE,
                  'runtimePolicy': runner.fixtures.preparation.launcher_policy(),
                  'roleKernelRoster': roster,
                  'roleKernelRosterWindow': {'startedMonotonicNs': 1,
                                             'finishedMonotonicNs': 5},
                  'workloadAcceptance': 'incomplete-hostile-contract-not-executed',
                  'protectedExecutionEnabled': False}
        self.assertTrue(runner.group_prepared(report, result, terminal, 'output-symlink'))
        self.assertTrue(runner.group_prepared(report,
            {**result, 'groupPreparation': 'output-fifo'}, terminal, 'output-fifo'))
        self.assertTrue(runner.group_prepared(report,
            {**result, 'groupPreparation': 'output-hardlink'}, terminal,
            'output-hardlink'))
        self.assertTrue(runner.group_prepared(report,
            {**result, 'groupPreparation': 'output-flood'}, terminal,
            'output-flood'))
        self.assertTrue(runner.group_prepared(report,
            {**result, 'groupPreparation': 'output-replacement'}, terminal,
            'output-replacement'))
        self.assertTrue(runner.group_prepared(report,
            {**result, 'groupPreparation': 'role-boundary'}, terminal,
            'role-boundary'))
        authority = {**result, 'groupPreparation': 'authority',
                     'signedAppWorkers': 3,
                     'probeAppKernelProcess': {'provenance': 'controller-kernel-sample'}}
        self.assertTrue(runner.group_prepared(report, authority, terminal,
                                              'authority'))
        self.assertFalse(runner.group_prepared(report,
            {**authority, 'signedAppWorkers': 0}, terminal, 'authority'))
        network = {**result, 'groupPreparation': 'network-app',
                   'signedAppWorkers': 3,
                   'probeAppKernelProcess': {'provenance': 'controller-kernel-sample'}}
        self.assertTrue(runner.group_prepared(report, network, terminal, 'network-app'))
        self.assertFalse(runner.group_prepared(report,
            {**network, 'signedAppWorkers': 0}, terminal, 'network-app'))
        for lifecycle in ('cancellation', 'controller-restart', 'deadline',
                          'revocation-running', 'setsid-double-fork',
                          'observer-death'):
            self.assertTrue(runner.group_prepared(report,
                {**result, 'groupPreparation': lifecycle}, terminal, lifecycle))
        diagnostic = dict(result, groupPreparation='role-readiness-diagnostic',
            workloadAcceptance='not-executed-role-readiness-measurement')
        self.assertTrue(runner.group_prepared({**report,
            'workloadPurpose': 'role-readiness-measurement'}, diagnostic, terminal,
            'role-readiness-diagnostic'))
        self.assertFalse(runner.group_prepared({**report, 'workloadPurpose': 'positive'},
            result, terminal, 'output-symlink'))
        terminal['stopReceipts']['candidate-sender']['previous'] = {'status': 'captured'}
        self.assertFalse(runner.group_prepared(report, result, terminal, 'output-symlink'))
        del terminal['stopReceipts']['candidate-sender']['previous']
        self.assertFalse(runner.group_prepared(report,
            {**result, 'contentRetrieval': 'observed'}, terminal, 'output-symlink'))
        self.assertFalse(runner.group_prepared({**report, 'guestStopped': False},
            result, terminal, 'output-symlink'))

    def test_private_kvm_diagnostic_cannot_enter_tcg_case_runner(self):
        with self.assertRaisesRegex(ValueError, 'accepted-tcg-profile-required'):
            runner.run(SimpleNamespace(profile='kvm-diagnostic'))

    def test_observer_private_read_requires_bound_role_child_and_active_canary(self):
        roster = synthetic_role_kernel_roster()
        sender = roster['roles'][0]
        source = Path(__file__).resolve().parents[3]
        actor = {'hostPid': 123, 'hostParentPid': 100, 'startTicks': 45,
                 'pidNamespace': 'pid:[4026532603]',
                 'namespacePids': [123, 2], 'networkNamespaceIdentity': [1, 200],
                 'mountNamespaceIdentity': [1, 300], 'userNamespaceIdentity': [1, 400],
                 'executableDigest': 'sha256:' + 'a' * 64, 'noNewPrivileges': True,
                 'effectiveCapabilities': 0}
        audit = {'schemaVersion': 1, 'kind': 'pr315-administrator-observer-private-read',
                 'caseId': 'observer-private-read',
                 'sourceDigest': runner.reference.sha256(source /
                     'tools/release-certification/restricted/pr315_role_probe.py'),
                 'nonceDigest': 'b' * 64, 'actorUid': sender['uid'],
                 'actorBefore': actor, 'actorAfter': dict(actor),
                 'roleInvocationBefore': sender['invocationId'],
                 'roleInvocationAfter': sender['invocationId'],
                 'targetDigestBefore': 'c' * 64, 'targetDigestAfter': 'c' * 64,
                 'triggerMonotonicNs': 50, 'attackStartedNs': 60,
                 'attackFinishedNs': 70, 'controllerObservedBeforeNs': 40,
                 'controllerObservedAfterNs': 80,
                 'kernelOpenResult': {'opened': False, 'errno': 'ENOENT'}}
        terminal = synthetic_terminal_roster(roster)
        receipt = terminal['stopReceipts']['candidate-sender']['current']['record']
        receipt.update(startedMonotonicNs=100, observedMonotonicNs=110)
        terminal['observerPrivateReadAudit'] = {'status': 'captured', 'record': audit}
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        value = {'identity': {'sourceCommit': 'b' * 40}, 'roleKernelRoster': roster,
                 'roleKernelRosterWindow': {'startedMonotonicNs': 1,
                                            'finishedMonotonicNs': 5}}
        fixture = {'schemaVersion': 4, 'probeDigest': 'sha256:' + 'd' * 64}
        with patch.object(runner, 'positive_executed', return_value=True):
            case = runner.observer_private_read_attempt(report, value, fixture, terminal, source)
            self.assertEqual('passed', case['status'])
            self.assertEqual(sender['invocationId'], case['actorEpoch']['systemdInvocation'])
            self.assertEqual(sender['bootId'], case['actorEpoch']['bootId'])
            self.assertEqual('pid:[4026532603]', case['actorEpoch']['pidNamespace'])
            self.assertEqual({'startedMonotonicNs': 60, 'finishedMonotonicNs': 70},
                             case['operationWindow'])
            self.assertEqual({'controllerObservedBeforeNs': 40, 'controllerObservedAfterNs': 80},
                             {key: case['targetEpoch'][key] for key in
                              ('controllerObservedBeforeNs', 'controllerObservedAfterNs')})
            for mutate in (
                    lambda row: row['actorAfter'].update(startTicks=46),
                    lambda row: row['actorAfter'].update(pidNamespace='pid:[4026539999]'),
                    lambda row: row.update(targetDigestAfter='d' * 64),
                    lambda row: row.update(kernelOpenResult={'opened': True, 'errno': None}),
                    lambda row: row.update(roleInvocationAfter='e' * 32)):
                changed = copy.deepcopy(terminal)
                mutate(changed['observerPrivateReadAudit']['record'])
                self.assertIsNone(runner.observer_private_read_attempt(
                    report, value, fixture, changed, source))
            write_audit = dict(audit, kind='pr315-administrator-observer-private-write',
                               caseId='observer-private-write', attackStartedNs=71,
                               attackFinishedNs=75)
            terminal['observerPrivateWriteAudit'] = {'status': 'captured', 'record': write_audit}
            write_case = runner.observer_private_write_attempt(
                report, value, fixture, terminal, source)
            self.assertEqual('passed', write_case['status'])
            self.assertEqual('observer-private-write', write_case['caseId'])
            self.assertNotEqual(case['attackDigest'], write_case['attackDigest'])
            invalid = copy.deepcopy(terminal)
            invalid['observerPrivateWriteAudit']['record']['actorAfter']['startTicks'] = 46
            self.assertIsNone(runner.observer_private_write_attempt(
                report, value, fixture, invalid, source))
        with patch.object(runner, 'positive_executed', return_value=False), \
                patch.object(runner, 'group_prepared', return_value=True):
            self.assertEqual('passed', runner.observer_private_read_attempt(
                report, value, fixture, terminal, source)['status'])
            self.assertEqual('passed', runner.observer_private_write_attempt(
                report, value, fixture, terminal, source)['status'])
            late = copy.deepcopy(value)
            late['roleKernelRosterWindow']['finishedMonotonicNs'] = 40
            self.assertIsNone(runner.observer_private_read_attempt(
                report, late, fixture, terminal, source))

    def test_false_claims_need_actual_role_kernel_identity_and_metrics(self):
        roster = synthetic_role_kernel_roster()
        sender = roster['roles'][0]
        source = Path(__file__).resolve().parents[3]
        actor = {'hostPid': 123, 'hostParentPid': 100, 'startTicks': 45,
                 'pidNamespace': 'pid:[4026532603]',
                 'namespacePids': [123, 2], 'networkNamespaceIdentity': [1, 200],
                 'mountNamespaceIdentity': [1, 300], 'userNamespaceIdentity': [1, 400],
                 'executableDigest': 'sha256:' + 'a' * 64, 'noNewPrivileges': True,
                 'effectiveCapabilities': 0}
        common = {'schemaVersion': 1,
                  'sourceDigest': runner.reference.sha256(source /
                      'tools/release-certification/restricted/pr315_role_probe.py'),
                  'nonceDigest': 'b' * 64, 'actorUid': sender['uid'],
                  'actorBefore': actor, 'actorAfter': dict(actor),
                  'roleInvocationBefore': sender['invocationId'],
                  'roleInvocationAfter': sender['invocationId'],
                  'cgroupIdentityBefore': [1, 99], 'cgroupIdentityAfter': [1, 99],
                  'targetActiveBeforeNs': 40, 'targetActiveAfterNs': 80,
                  'denial': 'kernel-mismatch-observed'}
        identity_audit = {**common,
            'kind': 'pr315-administrator-forged-runtime-identity',
            'caseId': 'forged-runtime-identity', 'attackStartedNs': 76,
            'attackFinishedNs': 77, 'claimedHostPid': 1, 'claimedHostUid': 0,
            'actualHostPid': 123, 'actualHostUid': sender['uid']}
        counter_audit = {**common, 'kind': 'pr315-administrator-forged-counters',
            'caseId': 'forged-counters', 'attackStartedNs': 78,
            'attackFinishedNs': 79, 'claimedMemoryCurrentBytes': 0,
            'claimedTasksCurrent': 0, 'actualMemoryBefore': 200,
            'actualTasksBefore': 3, 'actualMemoryAfter': 210,
            'actualTasksAfter': 3}
        terminal = synthetic_terminal_roster(roster)
        terminal['stopReceipts']['candidate-sender']['current']['record'].update(
            startedMonotonicNs=100, observedMonotonicNs=110)
        terminal['forgedRuntimeIdentityAudit'] = {'status': 'captured', 'record': identity_audit}
        terminal['forgedCountersAudit'] = {'status': 'captured', 'record': counter_audit}
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        result = {'identity': {'sourceCommit': 'b' * 40}, 'roleKernelRoster': roster}
        fixture = {'schemaVersion': 4, 'probeDigest': 'sha256:' + 'd' * 64}
        with patch.object(runner, 'positive_executed', return_value=True):
            first = runner._fixed_claim_attempt(
                'forged-runtime-identity', report, result, fixture, terminal, source)
            second = runner._fixed_claim_attempt(
                'forged-counters', report, result, fixture, terminal, source)
            self.assertEqual('passed', first['status'])
            self.assertEqual('passed', second['status'])
            self.assertEqual(sender['cgroupDigest'], first['actorEpoch']['cgroupDigest'])
            self.assertEqual({'startedMonotonicNs': 78, 'finishedMonotonicNs': 79},
                             second['operationWindow'])
            self.assertNotEqual(first['attackDigest'], second['attackDigest'])
            for field, key, value in (
                    ('forgedRuntimeIdentityAudit', 'claimedHostPid', 2),
                    ('forgedCountersAudit', 'actualMemoryAfter', 0),
                    ('forgedCountersAudit', 'cgroupIdentityAfter', [1, 100])):
                changed = copy.deepcopy(terminal)
                changed[field]['record'][key] = value
                case_id = ('forged-runtime-identity' if field == 'forgedRuntimeIdentityAudit'
                           else 'forged-counters')
                self.assertIsNone(runner._fixed_claim_attempt(
                    case_id, report, result, fixture, changed, source))
        with patch.object(runner, 'positive_executed', return_value=False), \
                patch.object(runner, 'group_prepared', return_value=True):
            for case_id in ('forged-runtime-identity', 'forged-counters'):
                self.assertEqual('passed', runner._fixed_claim_attempt(
                    case_id, report, result, fixture, terminal, source)['status'])

    def test_fixed_role_access_needs_active_sibling_or_package_and_stop_receipt(self):
        roster = synthetic_role_kernel_roster()
        sender, recipient = roster['roles'][:2]
        source = Path(__file__).resolve().parents[3]
        actor = {'hostPid': 123, 'hostParentPid': 100, 'startTicks': 45,
                 'pidNamespace': 'pid:[4026532603]',
                 'namespacePids': [123, 2], 'networkNamespaceIdentity': [1, 200],
                 'mountNamespaceIdentity': [1, 300], 'userNamespaceIdentity': [1, 400],
                 'executableDigest': 'sha256:' + 'a' * 64, 'noNewPrivileges': True,
                 'effectiveCapabilities': 0}
        common = {'schemaVersion': 1,
                  'kind': 'pr315-administrator-fixed-role-access-denial',
                  'sourceDigest': runner.reference.sha256(source /
                      'tools/release-certification/restricted/pr315_role_probe.py'),
                  'nonceDigest': 'b' * 64, 'actorUid': sender['uid'],
                  'actorBefore': actor, 'actorAfter': dict(actor),
                  'actorInvocationBefore': sender['invocationId'],
                  'actorInvocationAfter': sender['invocationId'],
                  'actorCgroupBefore': [1, 99], 'actorCgroupAfter': [1, 99]}
        terminal = synthetic_terminal_roster(roster)
        for role in ('candidate-sender', 'candidate-recipient'):
            terminal['stopReceipts'][role]['current']['record'].update(
                startedMonotonicNs=150, observedMonotonicNs=160)
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        result = {'identity': {'sourceCommit': 'b' * 40}, 'roleKernelRoster': roster,
                  'roleKernelRosterWindow': {'startedMonotonicNs': 1,
                                             'finishedMonotonicNs': 5}}
        fixture = {'schemaVersion': 4, 'probeDigest': 'sha256:' + 'd' * 64,
                   'products': {'candidate': {'daemonDigest': 'sha256:' + 'f' * 64}}}
        cases = (
            ('sibling-data', 'siblingDataAudit', recipient, [1, 100], 'e' * 64, 'ENOENT', 60),
            ('package-expectation', 'packageExpectationAudit', sender, [1, 99], 'f' * 64,
             'EACCES', 71),
            ('cgroup-migration', 'cgroupMigrationAudit', recipient, [1, 100], None,
             'ENOENT', 81))
        found = []
        with patch.object(runner, 'positive_executed', return_value=True):
            for case_id, field, target, group, digest, errno_code, start in cases:
                if digest is None:
                    digest = hashlib.sha256(json.dumps({'role': target['role'],
                        'managerInvocation': target['invocationId'],
                        'cgroupIdentity': group}, sort_keys=True,
                        separators=(',', ':')).encode()).hexdigest()
                snapshot = {'role': target['role'],
                            'managerInvocation': target['invocationId'],
                            'cgroupIdentity': group,
                            'observedMonotonicNs': 40, 'controlDigest': digest}
                audit = {**common, 'caseId': case_id,
                    'targetBefore': snapshot,
                    'targetAfter': dict(snapshot, observedMonotonicNs=120),
                    'attackStartedNs': start, 'attackFinishedNs': start + 1,
                    'kernelOpenResult': {'opened': False, 'errno': errno_code},
                    'writtenBytes': 0}
                terminal[field] = {'status': 'captured', 'record': audit}
                case = runner._fixed_role_access_attempt(
                    case_id, report, result, fixture, terminal, source)
                self.assertEqual('passed', case['status'])
                self.assertEqual(sender['invocationId'], case['actorEpoch']['systemdInvocation'])
                self.assertEqual(target['invocationId'], case['targetEpoch']['systemdInvocation'])
                self.assertEqual(target['cgroupDigest'], case['targetEpoch']['cgroupDigest'])
                self.assertEqual({'startedMonotonicNs': start,
                                  'finishedMonotonicNs': start + 1}, case['operationWindow'])
                found.append(case['attackDigest'])
                changed = copy.deepcopy(terminal)
                changed[field]['record']['targetAfter']['cgroupIdentity'] = [1, 999]
                self.assertIsNone(runner._fixed_role_access_attempt(
                    case_id, report, result, fixture, changed, source))
            self.assertEqual(3, len(set(found)))
            changed = copy.deepcopy(terminal)
            changed['packageExpectationAudit']['record']['targetBefore']['controlDigest'] = '0' * 64
            self.assertIsNone(runner._fixed_role_access_attempt(
                'package-expectation', report, result, fixture, changed, source))
        with patch.object(runner, 'positive_executed', return_value=False), \
                patch.object(runner, 'group_prepared', return_value=True):
            for case_id, *_ in cases:
                self.assertEqual('passed', runner._fixed_role_access_attempt(
                    case_id, report, result, fixture, terminal, source)['status'])
            late = copy.deepcopy(result)
            late['roleKernelRosterWindow']['finishedMonotonicNs'] = 40
            self.assertIsNone(runner._fixed_role_access_attempt(
                'sibling-data', report, late, fixture, terminal, source))

    def test_resolver_denial_needs_real_role_epoch_active_service_and_stable_canary(self):
        roster = synthetic_role_kernel_roster()
        sender = roster['roles'][0]
        source = Path(__file__).resolve().parents[3]
        actor = {'hostPid': 123, 'hostParentPid': 100, 'startTicks': 45,
                 'pidNamespace': 'pid:[4026532603]', 'namespacePids': [123, 2],
                 'networkNamespaceIdentity': [1, 200],
                 'mountNamespaceIdentity': [1, 300],
                 'userNamespaceIdentity': [1, 400],
                 'executableDigest': 'sha256:' + 'a' * 64,
                 'noNewPrivileges': True, 'effectiveCapabilities': 0}
        target = {'role': None, 'managerInvocation': '9' * 32,
                  'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                  'cgroupIdentity': [3, 5], 'mainPid': 211,
                  'mainStartTicks': 42, 'canaryIdentity': [3, 6],
                  'observedMonotonicNs': 40, 'controlDigest': 'e' * 64}
        audit = {'schemaVersion': 1,
                 'kind': 'pr315-administrator-resolver-authority-denial',
                 'caseId': 'resolver-authority',
                 'sourceDigest': runner.reference.sha256(source /
                     'tools/release-certification/restricted/pr315_role_probe.py'),
                 'nonceDigest': 'b' * 64, 'actorUid': sender['uid'],
                 'actorBefore': actor, 'actorAfter': dict(actor),
                 'actorInvocationBefore': sender['invocationId'],
                 'actorInvocationAfter': sender['invocationId'],
                 'actorCgroupBefore': [1, 99], 'actorCgroupAfter': [1, 99],
                 'actorStateBefore': 'd' * 64, 'actorStateAfter': 'd' * 64,
                 'targetBefore': target,
                 'targetAfter': dict(target, observedMonotonicNs=100),
                 'targetPathDigest': hashlib.sha256(
                     b'/var/lib/cryptad-restricted/resolver/pr315-workload-canary').hexdigest(),
                 'attackStartedNs': 60, 'attackFinishedNs': 70,
                 'kernelOpenResult': {'opened': False, 'errno': 'ENOENT'}}
        terminal = synthetic_terminal_roster(roster)
        terminal['sentinel']['observedDigest'] = 'sha256:' + 'd' * 64
        terminal['stopReceipts']['candidate-sender']['current']['record'].update(
            startedMonotonicNs=150, observedMonotonicNs=160)
        terminal['resolverAuthorityAudit'] = {'status': 'captured', 'record': audit}
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        result = {'identity': {'sourceCommit': 'b' * 40}, 'roleKernelRoster': roster}
        fixture = {'schemaVersion': 4, 'mailDigest': 'sha256:' + '5' * 64}
        with patch.object(runner, 'positive_executed', return_value=True):
            identity, attempt, sidecar = runner._resolver_authority_attempt(
                report, result, fixture, terminal, source)
            checked = runner.acceptance.verify_attempts(identity, [attempt])
            self.assertTrue(checked['recordContractValid'])
            self.assertEqual('passed', next(row['status'] for row in checked['cases']
                             if row['caseId'] == 'resolver-authority'))
            self.assertEqual('9' * 32, sidecar['targetEpoch']['systemdInvocation'])
            for mutate in (
                    lambda row: row['resolverAuthorityAudit']['record']['actorAfter'].update(
                        startTicks=46),
                    lambda row: row['resolverAuthorityAudit']['record']['targetAfter'].update(
                        managerInvocation='8' * 32),
                    lambda row: row['resolverAuthorityAudit']['record']['targetAfter'].update(
                        controlDigest='f' * 64),
                    lambda row: row['resolverAuthorityAudit']['record'].update(
                        kernelOpenResult={'opened': True, 'errno': None}),
                    lambda row: row['stopReceipts']['candidate-sender']['current'][
                        'record'].update(descendantCgroups=1)):
                changed = copy.deepcopy(terminal)
                mutate(changed)
                self.assertIsNone(runner._resolver_authority_attempt(
                    report, result, fixture, changed, source))
        with patch.object(runner, 'positive_executed', return_value=False), \
                patch.object(runner, 'group_prepared', return_value=True):
            identity, attempt, _sidecar = runner._resolver_authority_attempt(
                report, result, fixture, terminal, source)
            self.assertEqual('passed', next(row['status'] for row in
                runner.acceptance.verify_attempts(identity, [attempt])['cases']
                if row['caseId'] == 'resolver-authority'))

    def test_hostile_origin_needs_candidate_actor_live_signed_app_and_root_controls(self):
        roster = synthetic_role_kernel_roster()
        sender = roster['roles'][0]
        source = Path(__file__).resolve().parents[3]
        actor = {'hostPid': 123, 'hostParentPid': 100, 'startTicks': 45,
                 'pidNamespace': 'pid:[4026532603]', 'namespacePids': [123, 2],
                 'networkNamespaceIdentity': [1, 200],
                 'mountNamespaceIdentity': [1, 300],
                 'userNamespaceIdentity': [1, 400],
                 'executableDigest': 'sha256:' + 'a' * 64,
                 'noNewPrivileges': True, 'effectiveCapabilities': 0}
        target = {'role': 'candidate-sender',
                  'managerInvocation': sender['invocationId'],
                  'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                  'cgroupIdentity': [1, 99], 'workerHostPid': 211,
                  'workerStartTicks': 42, 'javaHostPid': 212,
                  'javaStartTicks': 43, 'observedMonotonicNs': 40,
                  'controlResponseDigest': 'e' * 64}
        control = {'status': 200, 'errorCode': None,
                   'responseDigest': 'c' * 64,
                   'startedMonotonicNs': 50, 'finishedMonotonicNs': 55}
        audit = {'schemaVersion': 1,
                 'kind': 'pr315-administrator-hostile-app-origin-denial',
                 'caseId': 'hostile-app-origin',
                 'sourceDigest': runner.reference.sha256(source /
                     'tools/release-certification/restricted/pr315_role_probe.py'),
                 'nonceDigest': 'b' * 64, 'actorUid': sender['uid'],
                 'actorBefore': actor, 'actorAfter': dict(actor),
                 'actorInvocationBefore': sender['invocationId'],
                 'actorInvocationAfter': sender['invocationId'],
                 'actorCgroupBefore': [1, 99], 'actorCgroupAfter': [1, 99],
                 'actorStateBefore': 'd' * 64, 'actorStateAfter': 'd' * 64,
                 'targetBefore': target,
                 'targetAfter': dict(target, observedMonotonicNs=100),
                 'inputDigest': 'a' * 64, 'sessionDigest': 'f' * 64,
                 'expectedOriginDigest': 'g' * 64,
                 'hostileOriginDigest': hashlib.sha256(
                     b'http://127.0.0.1:1').hexdigest(),
                 'targetEndpointDigest': hashlib.sha256(
                     b'/api/v1/app-data/status').hexdigest(),
                 'controlBefore': control,
                 'controlAfter': dict(control, startedMonotonicNs=75,
                                      finishedMonotonicNs=80),
                 'attackStartedNs': 60, 'attackFinishedNs': 70,
                 'attackResponseDigest': '9' * 64,
                 'denialStatus': 403, 'denialCode': 'origin_mismatch'}
        terminal = synthetic_terminal_roster(roster)
        del terminal['stopReceipts']['candidate-sender']['previous']
        terminal['sentinel']['observedDigest'] = 'sha256:' + 'd' * 64
        terminal['stopReceipts']['candidate-sender']['current']['record'].update(
            startedMonotonicNs=150, observedMonotonicNs=160)
        terminal['hostileAppOriginAudit'] = {'status': 'captured', 'record': audit}
        report = {'hostVerifiedIdentity': synthetic_host_identity(),
                  'guestStopped': True}
        worker = {'provenance': 'controller-kernel-sample',
                  'hostPid': 211, 'startTicks': 42,
                  'managerInvocation': sender['invocationId'],
                  'cgroupIdentity': [1, 99],
                  'javaHostPid': 212, 'javaStartTicks': 43}
        result = {'identity': {'sourceCommit': 'b' * 40},
                  'roleKernelRoster': roster,
                  'mailAppKernelProcess': worker,
                  'mailUiOriginDigest': 'g' * 64}
        fixture = {'schemaVersion': 4, 'mailDigest': 'sha256:' + '5' * 64}
        diagnostics = {'hostileOriginSessionDigest': 'f' * 64}
        with patch.object(runner, 'group_prepared', return_value=True):
            identity, attempt, sidecar = runner._hostile_origin_attempt(
                report, result, fixture, terminal, source, diagnostics)
            checked = runner.acceptance.verify_attempts(identity, [attempt])
            self.assertTrue(checked['recordContractValid'])
            self.assertEqual('passed', next(row['status'] for row in checked['cases']
                             if row['caseId'] == 'hostile-app-origin'))
            self.assertEqual('origin_mismatch', sidecar['denialCode'])
            for mutate in (
                    lambda row: row['hostileAppOriginAudit']['record'][
                        'actorAfter'].update(startTicks=46),
                    lambda row: row['hostileAppOriginAudit']['record'][
                        'targetAfter'].update(workerStartTicks=43),
                    lambda row: row['hostileAppOriginAudit']['record'].update(
                        denialCode='invalid_app_browser_session'),
                    lambda row: row['stopReceipts']['candidate-sender']['current'][
                        'record'].update(descendantCgroups=1)):
                changed = copy.deepcopy(terminal)
                mutate(changed)
                self.assertIsNone(runner._hostile_origin_attempt(
                    report, result, fixture, changed, source, diagnostics))
            self.assertIsNone(runner._hostile_origin_attempt(
                report, result, fixture, terminal, source,
                {'hostileOriginSessionDigest': '0' * 64}))

    def test_provider_authority_requires_signed_app_child_live_root_canary_and_stop(self):
        roster = synthetic_role_kernel_roster()
        sender = roster['roles'][0]
        leader = {'hostPid': 300, 'namespacePids': [300, 20, 1],
            'startTicks': 40, 'executableDigest': 'sha256:' + 'b' * 64,
            'mountNamespaceIdentity': [1, 3], 'userNamespaceIdentity': [1, 4],
            'networkNamespaceIdentity': [1, 200], 'pidNamespaceIdentity': 5}
        actor = {'role': 'candidate-sender', 'hostPid': 301,
            'namespacePid': 20, 'namespacePids': [301, 20, 2],
            'startTicks': 45, 'executableDigest': 'sha256:' + 'a' * 64,
            'mountNamespaceIdentity': [1, 3],
            'outerMountNamespaceIdentity': [1, 7],
            'userNamespaceIdentity': [1, 4], 'pidNamespaceIdentity': 5,
            'managerInvocation': sender['invocationId'],
            'cgroupIdentity': [1, 99],
            'networkNamespaceIdentity': [1, 200], 'stateDigest': 'd' * 64,
            'observedMonotonicNs': 60, 'sandboxLeader': leader,
            'provenance': 'controller-kernel-sample'}
        target = {'role': None, 'managerInvocation': '9' * 32,
            'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            'cgroupIdentity': [3, 5], 'mainPid': 211,
            'mainStartTicks': 42, 'resolverCanaryIdentity': [3, 6],
            'resolverControlDigest': 'a' * 64,
            'providerCanaryIdentity': [3, 7],
            'observedMonotonicNs': 40, 'controlDigest': 'b' * 64}
        nonce = 'c' * 64
        app_result = {'schemaVersion': 1,
            'kind': 'pr315-signed-provider-authority-probe',
            'caseId': 'provider-authority', 'nonce': nonce,
            'pid': 2, 'uid': sender['uid'], 'gid': sender['gid'],
            'startedMonotonicNs': 70, 'finishedMonotonicNs': 80,
            'targetPathDigest': hashlib.sha256(
                b'/var/lib/cryptad-restricted/pr315-provider/pr315-provider-canary').hexdigest(),
            'outcome': {'opened': False, 'errno': 'ENOENT'}}
        audit = {'schemaVersion': 1,
            'kind': 'pr315-administrator-provider-authority-denial',
            'caseId': 'provider-authority',
            'bundleDigest': 'sha256:' + '8' * 64,
            'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
            'actorUid': sender['uid'],
            'actorBefore': actor,
            'actorAfter': dict(actor, observedMonotonicNs=100),
            'senderStateBefore': 'd' * 64, 'senderStateAfter': 'd' * 64,
            'targetBefore': target,
            'targetAfter': dict(target, observedMonotonicNs=120),
            'targetPathDigest': app_result['targetPathDigest'],
            'attackStartedNs': 70, 'attackFinishedNs': 80,
            'kernelOpenResult': app_result['outcome'],
            'appResultDigest': hashlib.sha256(json.dumps(app_result,
                sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
        terminal = synthetic_terminal_roster(roster)
        del terminal['stopReceipts']['candidate-sender']['previous']
        terminal['sentinel']['observedDigest'] = 'sha256:' + 'd' * 64
        terminal['stopReceipts']['candidate-sender']['current']['record'].update(
            startedMonotonicNs=150, observedMonotonicNs=160)
        terminal['providerAuthorityAudit'] = {'status': 'captured', 'record': audit}
        terminal['providerAppResult'] = {'status': 'captured', 'record': app_result}
        terminal['probeAdministratorRecord'] = {'status': 'captured', 'record': {
            'bundleDigest': 'sha256:' + '8' * 64,
            'worker': {'hostPid': 301, 'startTicks': 45},
            'cgroupIdentity': [1, 99]}}
        terminal['probeKernelCheckpoint'] = {'status': 'captured', 'record': {
            'probeWorker': {'hostPid': 301, 'startTicks': 45}}}
        report = {'hostVerifiedIdentity': synthetic_host_identity(),
                  'guestStopped': True}
        result = {'identity': {'sourceCommit': 'b' * 40},
                  'roleKernelRoster': roster,
                  'probeAppKernelProcess': dict(actor)}
        fixture = {'schemaVersion': 4, 'mailDigest': 'sha256:' + '5' * 64,
                   'probeDigest': 'sha256:' + '8' * 64}
        normal_checked = {'recordContractValid': True,
            'cases': [{'caseId': 'namespace-mount-escape', 'status': 'passed'}]}
        with patch.object(runner, 'group_prepared', return_value=True), \
                patch.object(runner, 'probe_denial_attempt', return_value=({}, {})), \
                patch.object(runner.acceptance, 'verify_attempts',
                             return_value=normal_checked):
            identity, attempt, sidecar = runner._provider_authority_attempt(
                report, result, fixture, terminal)
            self.assertEqual('normally-signed-apphost-child', sidecar['actorEpoch']['kind'])
            for mutate in (
                    lambda row: row['providerAuthorityAudit']['record'].update(
                        bundleDigest='sha256:' + '0' * 64),
                    lambda row: row['providerAuthorityAudit']['record'][
                        'actorAfter'].update(startTicks=46),
                    lambda row: row['providerAuthorityAudit']['record'][
                        'targetAfter'].update(managerInvocation='8' * 32),
                    lambda row: row['providerAppResult']['record'].update(
                        outcome={'opened': True, 'errno': None}),
                    lambda row: row['stopReceipts']['candidate-sender']['current'][
                        'record'].update(descendantCgroups=1)):
                changed = copy.deepcopy(terminal)
                mutate(changed)
                self.assertIsNone(runner._provider_authority_attempt(
                    report, result, fixture, changed))
        checked = runner.acceptance.verify_attempts(identity, [attempt])
        self.assertTrue(checked['recordContractValid'])
        self.assertEqual('passed', next(row['status'] for row in checked['cases']
                         if row['caseId'] == 'provider-authority'))

    def test_output_symlink_requires_role_artifact_and_actual_collector_epoch(self):
        roster = synthetic_role_kernel_roster()
        sender = roster['roles'][0]
        source = Path(__file__).resolve().parents[3]
        actor = {'hostPid': 123, 'hostParentPid': 100, 'startTicks': 45,
                 'pidNamespace': 'pid:[4026532603]', 'namespacePids': [123, 2],
                 'networkNamespaceIdentity': [1, 200],
                 'mountNamespaceIdentity': [1, 300],
                 'userNamespaceIdentity': [1, 400],
                 'executableDigest': 'sha256:' + 'a' * 64,
                 'noNewPrivileges': True, 'effectiveCapabilities': 0}
        boot = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        cgroup = [3, 5]
        source_digest = runner.reference.sha256(source /
            'tools/release-certification/restricted/pr314_workload_driver.py')
        invocation = hashlib.sha256(json.dumps({'bootId': boot, 'pid': 211,
            'startTicks': 42, 'cgroupIdentity': cgroup,
            'sourceDigest': source_digest}, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()[:32]
        collector = {'pid': 211, 'uid': 0, 'startTicks': 42, 'bootId': boot,
                     'cgroupIdentity': cgroup,
                     'cgroupDigest': runner.fixtures.runtime.canonical_digest({
                         'role': 'output-collector', 'identity': cgroup})[7:],
                     'invocationId': invocation, 'sourceDigest': source_digest,
                     'observedMonotonicNs': 20}
        target = {'controlDigest': 'e' * 64,
                  'fileIdentity': [3, 6, 32, 100, 101],
                  'observedMonotonicNs': 10}
        audit = {'schemaVersion': 1,
                 'kind': 'pr315-administrator-output-symlink-denial',
                 'caseId': 'output-symlink',
                 'sourceDigest': runner.reference.sha256(source /
                     'tools/release-certification/restricted/pr315_role_probe.py'),
                 'nonceDigest': 'b' * 64, 'actorUid': sender['uid'],
                 'actorBefore': actor, 'actorAfter': dict(actor),
                 'actorInvocationBefore': sender['invocationId'],
                 'actorInvocationAfter': sender['invocationId'],
                 'actorCgroupBefore': [1, 99], 'actorCgroupAfter': [1, 99],
                 'senderStateBefore': 'd' * 64, 'senderStateAfter': 'd' * 64,
                 'collectorBefore': collector,
                 'collectorAfter': dict(collector, observedMonotonicNs=90),
                 'collectorStartedNs': 60, 'collectorFinishedNs': 70,
                 'collectorDenial': 'workload-snapshot-file-invalid',
                 'targetBefore': target,
                 'targetAfter': dict(target, observedMonotonicNs=80),
                 'artifactIdentity': [3, 7], 'artifactOwnerUid': sender['uid'],
                 'linkTargetDigest': hashlib.sha256(
                     b'/node/tmp/pr315-output-target-canary').hexdigest(),
                 'triggerMonotonicNs': 30, 'attackStartedNs': 40,
                 'attackFinishedNs': 50}
        terminal = synthetic_terminal_roster(roster)
        terminal['sentinel']['observedDigest'] = 'sha256:' + 'd' * 64
        terminal['stopReceipts']['candidate-sender']['current']['record'].update(
            startedMonotonicNs=150, observedMonotonicNs=160)
        terminal['outputSymlinkAudit'] = {'status': 'captured', 'record': audit}
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        result = {'identity': {'sourceCommit': 'b' * 40}, 'roleKernelRoster': roster,
                  'roleKernelRosterWindow': {'startedMonotonicNs': 1,
                                             'finishedMonotonicNs': 5}}
        fixture = {'schemaVersion': 4, 'mailDigest': 'sha256:' + '5' * 64}
        with patch.object(runner, 'group_prepared', return_value=True):
            identity, attempt, sidecar = runner._output_symlink_attempt(
                report, result, fixture, terminal, source)
            checked = runner.acceptance.verify_attempts(identity, [attempt])
            self.assertTrue(checked['recordContractValid'])
            self.assertEqual('passed', next(row['status'] for row in checked['cases']
                             if row['caseId'] == 'output-symlink'))
            self.assertEqual(invocation, sidecar['targetEpoch']['testKitInvocation'])
            for mutate in (
                    lambda row: row['outputSymlinkAudit']['record']['actorAfter'].update(
                        startTicks=46),
                    lambda row: row['outputSymlinkAudit']['record']['collectorAfter'].update(
                        pid=212),
                    lambda row: row['outputSymlinkAudit']['record'].update(
                        collectorDenial='workload-snapshot-deadline'),
                    lambda row: row['outputSymlinkAudit']['record']['targetAfter'].update(
                        controlDigest='f' * 64),
                    lambda row: row['stopReceipts']['candidate-sender']['current'][
                        'record'].update(descendantCgroups=1)):
                changed = copy.deepcopy(terminal)
                mutate(changed)
                self.assertIsNone(runner._output_symlink_attempt(
                    report, result, fixture, changed, source))
            late_roster = copy.deepcopy(result)
            late_roster['roleKernelRosterWindow']['finishedMonotonicNs'] = 10
            self.assertIsNone(runner._output_symlink_attempt(
                report, late_roster, fixture, terminal, source))
            fifo_terminal = copy.deepcopy(terminal)
            fifo_audit = fifo_terminal.pop('outputSymlinkAudit')['record']
            fifo_audit['kind'] = 'pr315-administrator-output-fifo-denial'
            fifo_audit['caseId'] = 'output-fifo'
            del fifo_audit['linkTargetDigest']
            fifo_audit['artifactType'] = 'fifo'
            fifo_audit['artifactMode'] = 0o600
            fifo_terminal['outputFifoAudit'] = {'status': 'captured', 'record': fifo_audit}
            fifo_identity, fifo_attempt, fifo_sidecar = runner._output_fifo_attempt(
                report, result, fixture, fifo_terminal, source)
            self.assertEqual('passed', next(row['status'] for row in
                runner.acceptance.verify_attempts(fifo_identity,
                    [fifo_attempt])['cases'] if row['caseId'] == 'output-fifo'))
            self.assertEqual('fifo', fifo_sidecar['targetEpoch']['artifactType'])
            fifo_audit['artifactMode'] = 0o666
            self.assertIsNone(runner._output_fifo_attempt(
                report, result, fixture, fifo_terminal, source))
            hardlink_terminal = copy.deepcopy(terminal)
            hardlink_audit = hardlink_terminal.pop('outputSymlinkAudit')['record']
            hardlink_audit['kind'] = 'pr315-administrator-output-hardlink-denial'
            hardlink_audit['caseId'] = 'output-hardlink'
            del hardlink_audit['linkTargetDigest']
            hardlink_audit['artifactType'] = 'hardlink'
            hardlink_audit['artifactMode'] = 0o600
            hardlink_audit['artifactLinkCount'] = 2
            hardlink_audit['artifactIdentity'] = target['fileIdentity'][:2]
            hardlink_audit['targetBefore']['linkCount'] = 1
            hardlink_audit['targetAfter']['linkCount'] = 2
            hardlink_audit['targetAfter']['fileIdentity'] = list(
                hardlink_audit['targetBefore']['fileIdentity'])
            hardlink_audit['targetAfter']['fileIdentity'][4] = 102
            hardlink_terminal['outputHardlinkAudit'] = {
                'status': 'captured', 'record': hardlink_audit}
            hardlink_identity, hardlink_attempt, hardlink_sidecar = (
                runner._output_hardlink_attempt(report, result, fixture,
                                                hardlink_terminal, source))
            self.assertEqual('passed', next(row['status'] for row in
                runner.acceptance.verify_attempts(hardlink_identity,
                    [hardlink_attempt])['cases'] if row['caseId'] == 'output-hardlink'))
            self.assertEqual(2, hardlink_sidecar['targetEpoch']['artifactLinkCount'])
            hardlink_audit['targetAfter']['linkCount'] = 1
            self.assertIsNone(runner._output_hardlink_attempt(
                report, result, fixture, hardlink_terminal, source))
            flood_terminal = copy.deepcopy(terminal)
            flood_audit = flood_terminal.pop('outputSymlinkAudit')['record']
            flood_audit['kind'] = 'pr315-administrator-output-flood-denial'
            flood_audit['caseId'] = 'output-flood'
            del flood_audit['linkTargetDigest']
            flood_audit['artifactType'] = 'regular'
            flood_audit['artifactMode'] = 0o600
            flood_audit['artifactSize'] = 65537
            flood_audit['artifactDigest'] = hashlib.sha256(b'F' * 65537).hexdigest()
            flood_terminal['outputFloodAudit'] = {'status': 'captured',
                                                  'record': flood_audit}
            flood_identity, flood_attempt, flood_sidecar = runner._output_flood_attempt(
                report, result, fixture, flood_terminal, source)
            self.assertEqual('passed', next(row['status'] for row in
                runner.acceptance.verify_attempts(flood_identity,
                    [flood_attempt])['cases'] if row['caseId'] == 'output-flood'))
            self.assertEqual(65537, flood_sidecar['targetEpoch']['artifactSize'])
            flood_audit['artifactSize'] = 65536
            self.assertIsNone(runner._output_flood_attempt(
                report, result, fixture, flood_terminal, source))
            replacement_terminal = copy.deepcopy(terminal)
            replacement_audit = replacement_terminal.pop('outputSymlinkAudit')['record']
            replacement_audit['kind'] = 'pr315-administrator-output-replacement-denial'
            replacement_audit['caseId'] = 'output-replacement'
            del replacement_audit['linkTargetDigest']
            replacement_audit['artifactType'] = 'replacement'
            replacement_audit['artifactMode'] = 0o600
            replacement_audit['collectorDenial'] = 'workload-snapshot-changed'
            replacement_audit['replacementIdentity'] = [3, 8]
            replacement_audit['initialDigest'] = hashlib.sha256(b'A' * 32).hexdigest()
            replacement_audit['replacementDigest'] = hashlib.sha256(b'B' * 32).hexdigest()
            replacement_audit['swapTriggerNs'] = 62
            replacement_audit['swapStartedNs'] = 63
            replacement_audit['swapFinishedNs'] = 64
            replacement_terminal['outputReplacementAudit'] = {
                'status': 'captured', 'record': replacement_audit}
            replaced_identity, replaced_attempt, replaced_sidecar = (
                runner._output_replacement_attempt(report, result, fixture,
                                                   replacement_terminal, source))
            self.assertEqual('passed', next(row['status'] for row in
                runner.acceptance.verify_attempts(replaced_identity,
                    [replaced_attempt])['cases']
                    if row['caseId'] == 'output-replacement'))
            self.assertEqual([3, 8],
                replaced_sidecar['targetEpoch']['replacementIdentity'])
            replacement_audit['swapStartedNs'] = 61
            self.assertIsNone(runner._output_replacement_attempt(
                report, result, fixture, replacement_terminal, source))

    def test_sibling_fcp_denial_needs_named_drop_active_target_and_exact_role_epoch(self):
        roster = synthetic_role_kernel_roster()
        sender, recipient = roster['roles'][:2]
        source = Path(__file__).resolve().parents[3]
        actor = {'hostPid': 123, 'hostParentPid': 100, 'startTicks': 45,
                 'pidNamespace': 'pid:[4026532603]', 'namespacePids': [123, 2],
                 'networkNamespaceIdentity': [1, 200],
                 'mountNamespaceIdentity': [1, 300],
                 'userNamespaceIdentity': [1, 400],
                 'executableDigest': 'sha256:' + 'a' * 64,
                 'noNewPrivileges': True, 'effectiveCapabilities': 0}
        target = {'role': 'candidate-recipient',
                  'managerInvocation': recipient['invocationId'],
                  'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                  'cgroupIdentity': [1, 100], 'observedMonotonicNs': 40,
                  'controlObservedNs': 45, 'controlDigest': 'e' * 64}
        names = runner.workload_network.SIBLING_DROP_COUNTERS
        counter = {'schemaVersion': 1, 'kind': 'pr315-fixed-sibling-drop-counters',
                   'policyDigest': hashlib.sha256(runner.workload_network.role_rules(
                       'candidate-sender').encode()).hexdigest(),
                   'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                   'roleNamespaceIdentity': [1, 200], 'observedMonotonicNs': 60,
                   'counters': {name: {'packets': 0, 'bytes': 0}
                                for name in names.values()}}
        after_counter = copy.deepcopy(counter)
        after_counter['observedMonotonicNs'] = 170
        after_counter['counters'][names['sibling-fcp']] = {'packets': 1, 'bytes': 60}
        audit = {'schemaVersion': 1,
                 'kind': 'pr315-administrator-sibling-network-denial',
                 'caseId': 'sibling-fcp',
                 'sourceDigest': runner.reference.sha256(source /
                     'tools/release-certification/restricted/pr315_role_probe.py'),
                 'nonceDigest': 'b' * 64, 'actorUid': sender['uid'],
                 'actorBefore': actor, 'actorAfter': dict(actor),
                 'senderInvocationBefore': sender['invocationId'],
                 'senderInvocationAfter': sender['invocationId'],
                 'senderCgroupBefore': [1, 99], 'senderCgroupAfter': [1, 99],
                 'senderStateBefore': 'd' * 64, 'senderStateAfter': 'd' * 64,
                 'targetBefore': target,
                 'targetAfter': dict(target, observedMonotonicNs=180,
                                     controlObservedNs=190, controlDigest='f' * 64),
                 'counterBefore': counter, 'counterAfter': after_counter,
                 'triggerMonotonicNs': 70, 'attackStartedNs': 80,
                 'attackFinishedNs': 90,
                 'targetEndpointDigest': hashlib.sha256(b'10.231.0.2:19401').hexdigest(),
                 'kernelConnectResult': {'connected': False, 'errno': 'ETIMEDOUT'},
                 'counterName': names['sibling-fcp']}
        terminal = synthetic_terminal_roster(roster)
        terminal['sentinel']['observedDigest'] = 'sha256:' + 'd' * 64
        for role in ('candidate-sender', 'candidate-recipient'):
            terminal['stopReceipts'][role]['current']['record'].update(
                startedMonotonicNs=300, observedMonotonicNs=310)
        terminal['siblingFcpAudit'] = {'status': 'captured', 'record': audit}
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        result = {'identity': {'sourceCommit': 'b' * 40}, 'roleKernelRoster': roster}
        fixture = {'schemaVersion': 4, 'mailDigest': 'sha256:' + '5' * 64}
        with patch.object(runner, 'positive_executed', return_value=True):
            identity, attempt, sidecar = runner._sibling_network_attempt(
                'sibling-fcp', report, result, fixture, terminal, source)
            checked = runner.acceptance.verify_attempts(identity, [attempt])
            self.assertTrue(checked['recordContractValid'])
            self.assertEqual('passed', next(row['status'] for row in checked['cases']
                             if row['caseId'] == 'sibling-fcp'))
            self.assertEqual(names['sibling-fcp'], sidecar['counterName'])
            for mutate in (
                    lambda row: row['siblingFcpAudit']['record']['actorAfter'].update(
                        startTicks=46),
                    lambda row: row['siblingFcpAudit']['record']['counterAfter'][
                        'counters'][names['sibling-fcp']].update(packets=0),
                    lambda row: row['siblingFcpAudit']['record']['counterAfter'][
                        'counters'][names['sibling-http']].update(packets=1, bytes=60),
                    lambda row: row['siblingFcpAudit']['record']['targetAfter'].update(
                        managerInvocation='0' * 32),
                    lambda row: row['stopReceipts']['candidate-recipient']['current'][
                        'record'].update(descendantCgroups=1)):
                changed = copy.deepcopy(terminal)
                mutate(changed)
                self.assertIsNone(runner._sibling_network_attempt(
                    'sibling-fcp', report, result, fixture, changed, source))
        with patch.object(runner, 'positive_executed', return_value=False), \
                patch.object(runner, 'group_prepared', return_value=True):
            identity, attempt, _sidecar = runner._sibling_network_attempt(
                'sibling-fcp', report, result, fixture, terminal, source)
            self.assertEqual('passed', next(row['status'] for row in
                runner.acceptance.verify_attempts(identity, [attempt])['cases']
                if row['caseId'] == 'sibling-fcp'))

    def test_observer_control_denial_needs_root_controller_and_exact_actor_epoch(self):
        roster = synthetic_role_kernel_roster()
        sender = roster['roles'][0]
        state = 'd' * 64
        response = hashlib.sha256(b'{"error":"restricted-workload-request-failed"}\n').hexdigest()
        observer = {'schemaVersion': 1, 'kind': 'pr315-observer-control-denial-checkpoint',
                    'caseId': 'observer-control', 'actorPid': 123,
                    'actorStartTicks': 45, 'roleKernelRoster': roster,
                    'roleKernelRosterWindow': {'startedMonotonicNs': 10,
                                               'finishedMonotonicNs': 20},
                    'senderStateBefore': state, 'requestDigest': 'e' * 64,
                    'responseDigest': response}
        target = {'invocationId': 'f' * 32, 'cgroupIdentity': [1, 25],
                  'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                  'observedMonotonicNs': 30}
        root = {'schemaVersion': 1, 'kind': 'pr315-administrator-observer-control-denial',
                'caseId': 'observer-control',
                'actor': {'pid': 123, 'uid': roster['observerUid'], 'startTicks': 45},
                'targetBefore': target, 'targetAfter': dict(target, observedMonotonicNs=60),
                'senderManagerInvocation': sender['invocationId'],
                'senderCgroupIdentity': [1, 99], 'senderStateBefore': state,
                'senderStateAfter': state, 'requestObservedNs': 40,
                'responseSentNs': 50, 'requestDigest': observer['requestDigest'],
                'responseDigest': response}
        terminal = synthetic_terminal_roster(roster)
        terminal['sentinel']['observedDigest'] = 'sha256:' + state
        terminal['stopReceipts']['candidate-sender']['current']['record']['startedMonotonicNs'] = 80
        terminal['observerControlCheckpoint'] = {'status': 'captured', 'record': observer}
        terminal['observerControlAudit'] = {'status': 'captured', 'record': root}
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        fixture = {'schemaVersion': 4, 'mailDigest': 'sha256:' + '5' * 64}
        identity, attempt = runner.observer_control_denial_attempt(report, fixture, terminal)
        assessment = runner.acceptance.verify_attempts(identity, [attempt])
        self.assertTrue(assessment['recordContractValid'])
        self.assertEqual('passed', next(row['status'] for row in assessment['cases']
                         if row['caseId'] == 'observer-control'))
        for mutate in (
                lambda row: row['observerControlAudit']['record']['actor'].update(startTicks=46),
                lambda row: row['observerControlAudit']['record'].update(responseDigest='0' * 64),
                lambda row: row['observerControlAudit']['record']['targetAfter'].update(
                    observedMonotonicNs=81),
                lambda row: row['observerControlAudit']['record'].update(senderStateAfter='0' * 64)):
            changed = copy.deepcopy(terminal)
            mutate(changed)
            self.assertIsNone(runner.observer_control_denial_attempt(report, fixture, changed))

    def test_arbitrary_endpoint_needs_real_observer_denial_and_active_sibling_fcp(self):
        roster = synthetic_role_kernel_roster()
        sender, recipient = roster['roles'][:2]
        sender_state, recipient_state = 'd' * 64, None
        response = hashlib.sha256(b'{"error":"restricted-workload-request-failed"}\n').hexdigest()
        observer = {'schemaVersion': 1, 'kind': 'pr315-arbitrary-endpoint-denial-checkpoint',
                    'caseId': 'arbitrary-endpoint', 'actorPid': 123, 'actorStartTicks': 45,
                    'roleKernelRoster': roster,
                    'roleKernelRosterWindow': {'startedMonotonicNs': 10,
                                               'finishedMonotonicNs': 20},
                    'requestDigest': 'f' * 64, 'responseDigest': response}
        controller = {'invocationId': 'f' * 32, 'cgroupIdentity': [1, 25],
                      'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                      'observedMonotonicNs': 30}
        def role_record(principal, identity, state, observed):
            return {'managerInvocation': principal['invocationId'],
                    'cgroupIdentity': identity,
                    'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                    'stateDigest': state, 'observedMonotonicNs': observed}
        root = {'schemaVersion': 1,
                'kind': 'pr315-administrator-arbitrary-endpoint-denial',
                'caseId': 'arbitrary-endpoint',
                'actor': {'pid': 123, 'uid': roster['observerUid'], 'startTicks': 45},
                'targetBefore': controller,
                'targetAfter': dict(controller, observedMonotonicNs=70),
                'senderBefore': role_record(sender, [1, 99], sender_state, 42),
                'senderAfter': role_record(sender, [1, 99], sender_state, 67),
                'recipientBefore': role_record(recipient, [1, 100], recipient_state, 45),
                'recipientAfter': role_record(recipient, [1, 100], recipient_state, 60),
                'recipientControlBeforeNs': 50, 'recipientControlAfterNs': 65,
                'recipientControlBeforeDigest': '1' * 64,
                'recipientControlAfterDigest': '2' * 64,
                'endpointSelection': 'sibling-fcp',
                'denial': 'restricted-workload-network-rejected',
                'requestObservedNs': 40, 'attackStartedNs': 55,
                'attackFinishedNs': 56, 'responseSentNs': 57,
                'requestDigest': observer['requestDigest'], 'responseDigest': response}
        terminal = synthetic_terminal_roster(roster)
        terminal['sentinel']['observedDigest'] = 'sha256:' + sender_state
        for role in ('candidate-sender', 'candidate-recipient'):
            terminal['stopReceipts'][role]['current']['record']['startedMonotonicNs'] = 90
        terminal['arbitraryEndpointCheckpoint'] = {'status': 'captured', 'record': observer}
        terminal['arbitraryEndpointAudit'] = {'status': 'captured', 'record': root}
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        result = {'identity': {'sourceCommit': 'b' * 40}}
        fixture = {'schemaVersion': 4, 'mailDigest': 'sha256:' + '5' * 64}
        with patch.object(runner, 'positive_executed', return_value=True):
            identity, attempt, sidecar = runner.arbitrary_endpoint_denial_attempt(
                report, result, fixture, terminal)
            checked = runner.acceptance.verify_attempts(identity, [attempt])
            self.assertTrue(checked['recordContractValid'])
            self.assertEqual('passed', next(row['status'] for row in checked['cases']
                             if row['caseId'] == 'arbitrary-endpoint'))
            self.assertEqual(recipient['invocationId'],
                             sidecar['recipientBefore']['managerInvocation'])
            for mutate in (
                    lambda row: row['arbitraryEndpointAudit']['record']['actor'].update(
                        startTicks=46),
                    lambda row: row['arbitraryEndpointAudit']['record']['recipientAfter'].update(
                        managerInvocation='0' * 32),
                    lambda row: row['arbitraryEndpointAudit']['record']['recipientBefore'].update(
                        stateDigest='0' * 64),
                    lambda row: row['arbitraryEndpointAudit']['record'].update(
                        endpointSelection='host-fcp'),
                    lambda row: row['arbitraryEndpointAudit']['record'].update(
                        recipientControlAfterNs=54),
                    lambda row: row['stopReceipts']['candidate-recipient']['current']['record'].update(
                        descendantCgroups=1)):
                changed = copy.deepcopy(terminal)
                mutate(changed)
                self.assertIsNone(runner.arbitrary_endpoint_denial_attempt(
                    report, result, fixture, changed))
        with patch.object(runner, 'positive_executed', return_value=False), \
                patch.object(runner, 'group_prepared', return_value=True):
            identity, attempt, _sidecar = runner.arbitrary_endpoint_denial_attempt(
                report, result, fixture, terminal)
            self.assertEqual('passed', next(row['status'] for row in
                runner.acceptance.verify_attempts(identity, [attempt])['cases']
                if row['caseId'] == 'arbitrary-endpoint'))

    def test_runner_control_denial_requires_real_runner_and_unchanged_active_unit(self):
        roster = synthetic_role_kernel_roster()
        sender = roster['roles'][0]
        window = {'startedMonotonicNs': 10, 'finishedMonotonicNs': 20}
        response = b'Failed to stop cryptad-workload-controller.service: Interactive authentication required.\n'
        command = ['/usr/bin/systemctl', '--no-ask-password', 'stop',
                   'cryptad-workload-controller.service']
        target = {'invocationId': 'f' * 32, 'cgroupIdentity': [1, 25],
                  'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                  'mainPid': 200, 'mainStartTicks': 40, 'observedMonotonicNs': 30}
        audit = {'schemaVersion': 1, 'kind': 'pr315-administrator-runner-control-denial',
                 'caseId': 'runner-control',
                 'actor': {'pid': 300, 'uid': roster['runnerUid'], 'startTicks': 45},
                 'roleKernelRoster': roster, 'roleKernelRosterWindow': window,
                 'targetBefore': target, 'targetAfter': dict(target, observedMonotonicNs=60),
                 'senderManagerInvocation': sender['invocationId'],
                 'senderCgroupIdentity': [1, 99],
                 'senderStateBefore': 'd' * 64, 'senderStateAfter': 'd' * 64,
                 'requestStartedNs': 40, 'responseObservedNs': 50,
                 'requestDigest': hashlib.sha256(json.dumps(command,
                     separators=(',', ':')).encode()).hexdigest(),
                 'responseDigest': hashlib.sha256(response).hexdigest(),
                 'responseBase64': base64.b64encode(response).decode(),
                 'exitCode': 1, 'stdoutBytes': 0}
        terminal = synthetic_terminal_roster(roster)
        terminal['sentinel']['observedDigest'] = 'sha256:' + 'd' * 64
        terminal['stopReceipts']['candidate-sender']['current']['record']['startedMonotonicNs'] = 80
        terminal['runnerControlAudit'] = {'status': 'captured', 'record': audit}
        result = {'roleKernelRoster': roster, 'roleKernelRosterWindow': window}
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        fixture = {'schemaVersion': 4, 'mailDigest': 'sha256:' + '5' * 64}

        identity, attempt = runner.runner_control_denial_attempt(report, result, fixture, terminal)
        assessment = runner.acceptance.verify_attempts(identity, [attempt])
        self.assertTrue(assessment['recordContractValid'])
        self.assertEqual('passed', next(row['status'] for row in assessment['cases']
                         if row['caseId'] == 'runner-control'))
        for mutate in (
                lambda row: row['runnerControlAudit']['record']['actor'].update(uid=roster['observerUid']),
                lambda row: row['runnerControlAudit']['record'].update(responseDigest='0' * 64),
                lambda row: row['runnerControlAudit']['record']['targetAfter'].update(
                    invocationId='e' * 32),
                lambda row: row['runnerControlAudit']['record'].update(senderStateAfter='0' * 64),
                lambda row: row['runnerControlAudit']['record'].update(responseBase64='@@@')):
            changed = copy.deepcopy(terminal)
            mutate(changed)
            self.assertIsNone(runner.runner_control_denial_attempt(report, result, fixture, changed))

    def test_probe_denial_requires_live_root_actor_target_and_immutable_app_result(self):
        roster = synthetic_role_kernel_roster()
        sender = roster['roles'][0]
        fixture = {'schemaVersion': 4, 'mailDigest': 'sha256:' + '5' * 64,
                   'probeDigest': 'sha256:' + '6' * 64}
        result = {'schemaVersion': 1, 'kind': 'pr315-signed-apphost-probe',
                  'pid': 2, 'uid': sender['uid'], 'gid': sender['gid'],
                  'startedMonotonicNs': 25,
                  'namespaceInodes': {'mnt': 5, 'pid': 44, 'net': 7, 'user': 8},
                  'mountEscape': {'operation': 'unshare-mount', 'startedMonotonicNs': 30,
                                  'finishedMonotonicNs': 40, 'returnCode': -1, 'errno': 'EPERM'}}
        measured = {'hostPid': 300, 'hostParentPid': 299,
                    'namespacePids': [300, 20, 2], 'startTicks': 50,
                    'mountNamespaceIdentity': [1, 5], 'userNamespaceIdentity': [1, 8],
                    'networkNamespaceIdentity': [1, 7], 'pidNamespace': 'pid:[44]',
                    'executableDigest': 'sha256:' + '7' * 64,
                    'noNewPrivileges': True, 'effectiveCapabilities': 0}
        worker = {key: measured[key] for key in ('hostPid', 'namespacePids', 'startTicks',
                  'mountNamespaceIdentity', 'userNamespaceIdentity',
                  'networkNamespaceIdentity', 'executableDigest')}
        worker.update(managerInvocation=sender['invocationId'], cgroupIdentity=[1, 99],
                      outerMountNamespaceIdentity=[1, 6], observedMonotonicNs=50)
        leader = dict(measured, hostPid=299, hostParentPid=100,
                      namespacePids=[299, 19, 1], startTicks=40,
                      executableDigest='sha256:' + 'a' * 64)
        worker['namespacePid'] = 19
        worker['sandboxLeader'] = {key: leader[key] for key in ('hostPid', 'namespacePids',
            'startTicks', 'executableDigest', 'mountNamespaceIdentity',
            'userNamespaceIdentity', 'networkNamespaceIdentity')}
        worker['sandboxLeader']['pidNamespaceIdentity'] = 44
        state = '8' * 64
        admin = {'schemaVersion': 1, 'kind': 'pr315-administrator-probe-process',
                 'caseId': 'namespace-mount-escape', 'role': 'candidate-sender',
                 'bundleDigest': fixture['probeDigest'],
                 'verifiedTree': {'digest': 'sha256:' + '9' * 64,
                                  'fileCount': 3, 'sizeBytes': 1024},
                 'firstResultDigest': hashlib.sha256(json.dumps(result, sort_keys=True,
                     separators=(',', ':')).encode()).hexdigest(),
                 'senderUid': sender['uid'], 'senderGid': sender['gid'],
                 'managerInvocation': sender['invocationId'],
                 'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                 'cgroupIdentity': [1, 99], 'stateBefore': state, 'stateAfter': state,
                 'activeBeforeNs': 60, 'activeAfterNs': 70,
                 'worker': measured, 'sandboxLeader': leader,
                 'outer': {'mountNamespaceIdentity': [1, 6]}}
        checkpoint = {'bundleDigest': fixture['probeDigest'], 'roleKernelRoster': roster,
                      'roleKernelRosterWindow': {'startedMonotonicNs': 10,
                                                 'finishedMonotonicNs': 20},
                      'senderStateBefore': state, 'probeWorker': worker,
                      'administratorRecordDigest': hashlib.sha256(json.dumps(admin,
                          sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
        terminal = synthetic_terminal_roster(roster)
        terminal['sentinel']['observedDigest'] = 'sha256:' + state
        terminal['stopReceipts']['candidate-sender']['current']['record']['startedMonotonicNs'] = 80
        for name, record in (('probeKernelCheckpoint', checkpoint),
                             ('probeAdministratorRecord', admin), ('probeAppFirstResult', result)):
            terminal[name] = {'status': 'captured', 'record': record}
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        identity, attempt = runner.probe_denial_attempt(report, fixture, terminal)
        assessment = runner.acceptance.verify_attempts(identity, [attempt])
        self.assertTrue(assessment['recordContractValid'])
        self.assertEqual('passed', next(row['status'] for row in assessment['cases']
                         if row['caseId'] == 'namespace-mount-escape'))
        for mutate in (
                lambda row: row['probeAppFirstResult']['record'].update(uid=9999),
                lambda row: row['probeAdministratorRecord']['record'].update(activeAfterNs=81),
                lambda row: row['probeAdministratorRecord']['record']['worker'].update(hostPid=301),
                lambda row: row['probeKernelCheckpoint']['record'].update(senderStateBefore='0' * 64)):
            changed = copy.deepcopy(terminal)
            mutate(changed)
            self.assertIsNone(runner.probe_denial_attempt(report, fixture, changed))

    def test_cancellation_requires_active_administrator_trigger_and_exact_terminal_receipts(self):
        roster = synthetic_role_kernel_roster()
        terminal = synthetic_terminal_roster(roster)
        terminal['controllerRecords']['campaign'] = {'status': 'captured', 'record': {
            'state': 'terminalizing', 'deadlineMonotonicNs': 1000}}
        rows = []
        for index, principal in enumerate(roster['roles']):
            role = principal['role']
            rows.append({'role': role, 'managerInvocation': principal['invocationId'],
                         'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                         'cgroupIdentity': [1, 99 + index], 'mainPid': 1000 + index})
            receipt = terminal['stopReceipts'][role]['current']['record']
            receipt['startedMonotonicNs'] = 210 + index
            receipt['observedMonotonicNs'] = 220 + index
        event = {'kind': 'cancellation', 'roles': rows, 'campaignDeadlineNs': 1000}
        context = {'schemaVersion': 1, 'kind': 'pr315-administrator-cancellation',
                   'triggerStartedNs': 200, 'triggerEventDigest':
                       runner.fixtures.runtime.canonical_digest(event)[7:],
                   'campaignDeadlineNs': 1000, 'preRoles': rows,
                   'terminalObservedNs': 300, 'populatedCgroups': [],
                   'remainingDescendants': 0, 'retention': 'retained'}
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        result = {'roleKernelRoster': roster,
                  'roleKernelRosterWindow': {'startedMonotonicNs': 50, 'finishedMonotonicNs': 100}}
        fixture = {'mailDigest': 'sha256:' + '5' * 64}
        diagnostics = {'cancellation': context}
        identity, attempt = runner.positive_case_attempt(
            report, result, fixture, 10, 20, diagnostics, terminal)
        checked = runner.acceptance.verify_attempts(identity, [attempt])
        self.assertTrue(checked['recordContractValid'])
        self.assertIn('cancellation', attempt['declaredCases'])
        invalid = copy.deepcopy(terminal)
        invalid['stopReceipts']['previous']['current']['record']['observedMonotonicNs'] = 400
        _, rejected = runner.positive_case_attempt(
            report, result, fixture, 10, 20, diagnostics, invalid)
        self.assertNotIn('cancellation', rejected['declaredCases'])
        invalid_context = copy.deepcopy(context)
        invalid_context['preRoles'][0]['mainPid'] = 0
        _, rejected = runner.positive_case_attempt(
            report, result, fixture, 10, 20, {'cancellation': invalid_context}, terminal)
        self.assertNotIn('cancellation', rejected['declaredCases'])
        source = Path(__file__).resolve().parents[3]
        private = {'cancellation': context,
                   'lifecycleActorBefore': synthetic_lifecycle_actor(source, 150),
                   'lifecycleActorAfter': synthetic_lifecycle_actor(source, 350)}
        with patch.object(runner, 'group_prepared', return_value=True):
            identity, selected, sidecar = runner._lifecycle_group_attempt(
                'cancellation', report, result, dict(fixture, schemaVersion=4),
                private, terminal, source)
            self.assertEqual('passed', next(row['status'] for row in
                runner.acceptance.verify_attempts(identity, [selected])['cases']
                if row['caseId'] == 'cancellation'))
            self.assertEqual(private['lifecycleActorBefore']['invocationId'],
                             sidecar['actorEpoch']['testKitInvocation'])
            tampered = copy.deepcopy(private)
            tampered['lifecycleActorAfter']['pid'] = 501
            self.assertIsNone(runner._lifecycle_group_attempt(
                'cancellation', report, result, dict(fixture, schemaVersion=4),
                tampered, terminal, source))

    def test_controller_restart_requires_changed_invocation_and_reconciled_role_receipts(self):
        roster = synthetic_role_kernel_roster()
        terminal = synthetic_terminal_roster(roster)
        terminal['controllerRecords']['campaign'] = {'status': 'captured', 'record': {
            'state': 'terminalizing', 'deadlineMonotonicNs': 1000}}
        rows = []
        for index, principal in enumerate(roster['roles']):
            role = principal['role']
            rows.append({'role': role, 'managerInvocation': principal['invocationId'],
                         'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                         'cgroupIdentity': [1, 99 + index], 'mainPid': 1000 + index})
            terminal['controllerRecords'][role]['record']['stopReason'] = 'controller-reconciliation'
            receipt = terminal['stopReceipts'][role]['current']['record']
            receipt['startedMonotonicNs'] = 210 + index
            receipt['observedMonotonicNs'] = 220 + index
        before = {'InvocationID': 'b' * 32, 'ActiveState': 'active',
                  'SubState': 'running', 'MainPID': '100', 'Result': 'success'}
        after = dict(before, InvocationID='c' * 32, MainPID='200')
        event = {'kind': 'controller-restart', 'roles': rows,
                 'campaignDeadlineNs': 1000, 'oldControllerInvocation': before['InvocationID']}
        context = {'schemaVersion': 1, 'kind': 'pr315-administrator-controller-restart',
                   'triggerStartedNs': 200, 'triggerEventDigest':
                       runner.fixtures.runtime.canonical_digest(event)[7:],
                   'campaignDeadlineNs': 1000, 'preRoles': rows,
                   'beforeController': before, 'killReturnCode': 0,
                   'preStartBoundRoles': [{'role': role['role'], 'activeState': 'inactive',
                       'subState': 'dead', 'mainPid': 0,
                       'receiptObservedMonotonicNs': 220 + index}
                       for index, role in enumerate(rows)],
                   'newControllerStartRequestedNs': 240, 'startReturnCode': 0,
                   'afterController': after, 'terminalObservedNs': 300,
                   'populatedCgroups': [], 'remainingDescendants': 0, 'retention': 'retained'}
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        result = {'roleKernelRoster': roster,
                  'roleKernelRosterWindow': {'startedMonotonicNs': 50, 'finishedMonotonicNs': 100}}
        fixture = {'mailDigest': 'sha256:' + '5' * 64}
        identity, attempt = runner.positive_case_attempt(
            report, result, fixture, 10, 20, {'controllerRestart': context}, terminal)
        checked = runner.acceptance.verify_attempts(identity, [attempt])
        self.assertTrue(checked['recordContractValid'])
        self.assertIn('controller-restart', attempt['declaredCases'])
        invalid = copy.deepcopy(context)
        invalid['afterController']['InvocationID'] = before['InvocationID']
        _, rejected = runner.positive_case_attempt(
            report, result, fixture, 10, 20, {'controllerRestart': invalid}, terminal)
        self.assertNotIn('controller-restart', rejected['declaredCases'])
        source = Path(__file__).resolve().parents[3]
        private = {'controllerRestart': context,
                   'lifecycleActorBefore': synthetic_lifecycle_actor(source, 150),
                   'lifecycleActorAfter': synthetic_lifecycle_actor(source, 350)}
        with patch.object(runner, 'group_prepared', return_value=True):
            identity, selected, sidecar = runner._lifecycle_group_attempt(
                'controller-restart', report, result, dict(fixture, schemaVersion=4),
                private, terminal, source)
            self.assertEqual('passed', next(row['status'] for row in
                runner.acceptance.verify_attempts(identity, [selected])['cases']
                if row['caseId'] == 'controller-restart'))
            self.assertEqual(context['beforeController'],
                             sidecar['targetEpoch']['controllerBefore'])
            tampered = copy.deepcopy(private)
            tampered['lifecycleActorAfter']['cgroupIdentity'] = [1, 51]
            self.assertIsNone(runner._lifecycle_group_attempt(
                'controller-restart', report, result, dict(fixture, schemaVersion=4),
                tampered, terminal, source))
        invalid = copy.deepcopy(context)
        invalid['preStartBoundRoles'][0]['activeState'] = 'active'
        _, rejected = runner.positive_case_attempt(
            report, result, fixture, 10, 20, {'controllerRestart': invalid}, terminal)
        self.assertNotIn('controller-restart', rejected['declaredCases'])
        invalid_terminal = copy.deepcopy(terminal)
        invalid_terminal['controllerRecords']['relay-no-apps']['record']['stopReason'] = 'requested'
        _, rejected = runner.positive_case_attempt(
            report, result, fixture, 10, 20, {'controllerRestart': context}, invalid_terminal)
        self.assertNotIn('controller-restart', rejected['declaredCases'])

    def test_deadline_group_requires_original_expiry_and_each_prior_stop_receipt(self):
        roster = synthetic_role_kernel_roster()
        terminal = synthetic_terminal_roster(roster)
        terminal['controllerRecords']['campaign'] = {'status': 'captured', 'record': {
            'state': 'terminalizing', 'deadlineMonotonicNs': 1000}}
        rows, stops = [], []
        for index, principal in enumerate(roster['roles']):
            role = principal['role']
            rows.append({'role': role, 'managerInvocation': principal['invocationId'],
                         'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                         'cgroupIdentity': [1, 99 + index], 'mainPid': 1000 + index})
            receipt = terminal['stopReceipts'][role]['current']['record']
            receipt['startedMonotonicNs'] = 1010 + index
            receipt['observedMonotonicNs'] = 1020 + index
            stops.append({'role': role,
                          'managerInvocation': principal['invocationId'],
                          'receiptStartedNs': receipt['startedMonotonicNs'],
                          'receiptObservedNs': receipt['observedMonotonicNs']})
        event = {'kind': 'deadline', 'roles': rows, 'campaignDeadlineNs': 1000}
        context = {'schemaVersion': 1, 'kind': 'pr315-administrator-deadline',
                   'armedMonotonicNs': 900,
                   'triggerEventDigest': runner.fixtures.runtime.canonical_digest(event)[7:],
                   'campaignDeadlineNs': 1000, 'preRoles': rows,
                   'terminalObservedNs': 1100, 'roleStops': stops,
                   'populatedCgroups': [], 'remainingDescendants': 0,
                   'retention': 'retained'}
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        result = {'roleKernelRoster': roster,
                  'roleKernelRosterWindow': {'startedMonotonicNs': 50,
                                             'finishedMonotonicNs': 100}}
        source = Path(__file__).resolve().parents[3]
        private = {'deadline': context,
                   'lifecycleActorBefore': synthetic_lifecycle_actor(source, 850),
                   'lifecycleActorAfter': synthetic_lifecycle_actor(source, 1150)}
        fixture = {'schemaVersion': 4, 'mailDigest': 'sha256:' + '5' * 64}
        with patch.object(runner, 'group_prepared', return_value=True):
            identity, selected, sidecar = runner._lifecycle_group_attempt(
                'deadline', report, result, fixture, private, terminal, source)
            self.assertEqual('passed', next(row['status'] for row in
                runner.acceptance.verify_attempts(identity, [selected])['cases']
                if row['caseId'] == 'deadline'))
            self.assertEqual(stops, sidecar['targetEpoch']['roleStops'])
            early = copy.deepcopy(terminal)
            early['stopReceipts']['candidate-sender']['current']['record'][
                'startedMonotonicNs'] = 999
            self.assertIsNone(runner._lifecycle_group_attempt(
                'deadline', report, result, fixture, private, early, source))
            stale = copy.deepcopy(private)
            stale['lifecycleActorAfter']['startTicks'] = 34
            self.assertIsNone(runner._lifecycle_group_attempt(
                'deadline', report, result, fixture, stale, terminal, source))

    def test_revocation_group_needs_live_denial_and_owned_terminal_receipts(self):
        roster = synthetic_role_kernel_roster()
        terminal = synthetic_terminal_roster(roster)
        terminal['controllerRecords']['campaign'] = {'status': 'captured', 'record': {
            'state': 'terminalizing', 'deadlineMonotonicNs': 1000}}
        rows = []
        for index, principal in enumerate(roster['roles']):
            role = principal['role']
            rows.append({'role': role, 'managerInvocation': principal['invocationId'],
                         'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                         'cgroupIdentity': [1, 99 + index], 'mainPid': 1000 + index})
            terminal['controllerRecords'][role]['record'][
                'stopReason'] = 'controller-reconciliation'
            receipt = terminal['stopReceipts'][role]['current']['record']
            receipt['startedMonotonicNs'] = 250 + index
            receipt['observedMonotonicNs'] = 260 + index
        event = {'kind': 'revocation-running', 'roles': rows,
                 'campaignDeadlineNs': 1000, 'markerDigest': 'e' * 64}
        controller = {'invocationId': 'f' * 32, 'cgroupIdentity': [1, 30],
                      'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                      'mainPid': 100, 'mainStartTicks': 40,
                      'observedMonotonicNs': 190}
        context = {'schemaVersion': 1,
            'kind': 'pr315-administrator-revocation-running',
            'triggerStartedNs': 200,
            'triggerEventDigest': runner.fixtures.runtime.canonical_digest(event)[7:],
            'campaignDeadlineNs': 1000, 'preRoles': rows,
            'markerIdentity': [1, 55, 32], 'markerDigest': 'e' * 64,
            'controllerBefore': controller,
            'controllerAfter': dict(controller, observedMonotonicNs=240),
            'actor': {'pid': 501, 'uid': roster['observerUid'], 'startTicks': 45},
            'requestDigest': 'd' * 64,
            'responseDigest': hashlib.sha256(
                b'{"error":"restricted-workload-request-failed"}\n').hexdigest(),
            'requestStartedNs': 220, 'responseObservedNs': 230,
            'terminalObservedNs': 300, 'populatedCgroups': [],
            'remainingDescendants': 0, 'retention': 'retained'}
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        result = {'roleKernelRoster': roster,
                  'roleKernelRosterWindow': {'startedMonotonicNs': 50,
                                             'finishedMonotonicNs': 100}}
        source = Path(__file__).resolve().parents[3]
        private = {'revocationRunning': context,
                   'lifecycleActorBefore': synthetic_lifecycle_actor(source, 150),
                   'lifecycleActorAfter': synthetic_lifecycle_actor(source, 350)}
        fixture = {'schemaVersion': 4, 'mailDigest': 'sha256:' + '5' * 64}
        with patch.object(runner, 'group_prepared', return_value=True):
            identity, selected, sidecar = runner._lifecycle_group_attempt(
                'revocation-running', report, result, fixture, private, terminal, source)
            self.assertEqual('passed', next(row['status'] for row in
                runner.acceptance.verify_attempts(identity, [selected])['cases']
                if row['caseId'] == 'revocation-running'))
            self.assertEqual('e' * 64,
                             sidecar['targetEpoch']['revocationMarkerDigest'])
            forged = copy.deepcopy(private)
            forged['revocationRunning']['actor']['uid'] = 0
            self.assertIsNone(runner._lifecycle_group_attempt(
                'revocation-running', report, result, fixture, forged, terminal, source))
            early = copy.deepcopy(terminal)
            early['stopReceipts']['candidate-sender']['current'][
                'record']['startedMonotonicNs'] = 220
            self.assertIsNone(runner._lifecycle_group_attempt(
                'revocation-running', report, result, fixture, private, early, source))

    def test_setsid_group_binds_detached_child_and_preserves_siblings(self):
        roster = synthetic_role_kernel_roster()
        sender = roster['roles'][0]
        terminal = synthetic_terminal_roster(roster)
        actor = {'hostPid': 123, 'hostParentPid': 100, 'startTicks': 45,
                 'pidNamespace': 'pid:[4026532603]', 'namespacePids': [123, 2],
                 'networkNamespaceIdentity': [1, 200],
                 'mountNamespaceIdentity': [1, 300],
                 'userNamespaceIdentity': [1, 400],
                 'executableDigest': 'sha256:' + 'a' * 64,
                 'noNewPrivileges': True, 'effectiveCapabilities': 0}
        child = dict(actor, hostPid=124, hostParentPid=1, startTicks=50,
                     namespacePids=[124, 3], executableDigest='sha256:' + 'b' * 64)
        terminal['stopReceipts']['candidate-sender']['current']['record'].update(
            startedMonotonicNs=210, observedMonotonicNs=220)
        before, after = {}, {}
        for index, row in enumerate(roster['roles'][1:]):
            role = row['role']
            selected = {'InvocationID': row['invocationId'],
                        'ActiveState': 'active', 'SubState': 'running',
                        'MainPID': str(1000 + index)}
            before[role] = selected
            after[role] = dict(selected)
            terminal['stopReceipts'][role]['current']['record'].update(
                startedMonotonicNs=250 + index,
                observedMonotonicNs=260 + index)
        source = Path(__file__).resolve().parents[3]
        audit = {'schemaVersion': 1,
            'kind': 'pr315-administrator-setsid-double-fork',
            'caseId': 'setsid-double-fork',
            'sourceDigest': runner.reference.sha256(source /
                'tools/release-certification/restricted/pr315_role_probe.py'),
            'actorUid': sender['uid'], 'actorBefore': actor,
            'actorAfter': dict(actor), 'childEpoch': child,
            'childSession': 2, 'parentSession': 1,
            'roleInvocation': sender['invocationId'],
            'roleCgroupIdentity': [1, 99],
            'triggerMonotonicNs': 100, 'attackStartedNs': 110,
            'attackFinishedNs': 120, 'stopStartedNs': 130,
            'stopFinishedNs': 230, 'stopReceiptObservedNs': 220,
            'childAbsentObservedNs': 240,
            'otherRolesBefore': before, 'otherRolesAfter': after}
        private = {'setsidDoubleFork': {'status': 'captured', 'record': audit},
                   'lifecycleActorBefore': synthetic_lifecycle_actor(source, 90),
                   'lifecycleActorAfter': synthetic_lifecycle_actor(source, 350),
                   'cleanupFinishedNs': 300}
        report = {'hostVerifiedIdentity': synthetic_host_identity(), 'guestStopped': True}
        result = {'roleKernelRoster': roster,
                  'roleKernelRosterWindow': {'startedMonotonicNs': 50,
                                             'finishedMonotonicNs': 80}}
        fixture = {'schemaVersion': 4, 'mailDigest': 'sha256:' + '5' * 64}
        with patch.object(runner, 'group_prepared', return_value=True):
            identity, selected, sidecar = runner._lifecycle_group_attempt(
                'setsid-double-fork', report, result, fixture, private, terminal, source)
            self.assertEqual('passed', next(row['status'] for row in
                runner.acceptance.verify_attempts(identity, [selected])['cases']
                if row['caseId'] == 'setsid-double-fork'))
            self.assertEqual(child, sidecar['targetEpoch']['detachedChildEpoch'])
            reused = copy.deepcopy(private)
            reused['setsidDoubleFork']['record']['childSession'] = 1
            self.assertIsNone(runner._lifecycle_group_attempt(
                'setsid-double-fork', report, result, fixture, reused, terminal, source))
            missing = copy.deepcopy(terminal)
            missing['stopReceipts']['candidate-sender']['current'][
                'record']['descendantCgroups'] = 1
            self.assertIsNone(runner._lifecycle_group_attempt(
                'setsid-double-fork', report, result, fixture, private, missing, source))

    def test_observer_death_requires_real_240_second_loss_and_owner_receipts(self):
        unit = 10**9
        roster = synthetic_role_kernel_roster()
        terminal = synthetic_terminal_roster(roster)
        terminal['controllerRecords']['campaign'] = {'status': 'captured',
            'record': {'state': 'terminalizing',
                       'deadlineMonotonicNs': 1000 * unit}}
        rows, stops = [], []
        for index, principal in enumerate(roster['roles']):
            role = principal['role']
            rows.append({'role': role, 'managerInvocation': principal['invocationId'],
                         'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                         'cgroupIdentity': [1, 99 + index], 'mainPid': 1000 + index})
            terminal['controllerRecords'][role]['record'][
                'stopReason'] = 'controller-reconciliation'
            receipt = terminal['stopReceipts'][role]['current']['record']
            receipt['startedMonotonicNs'] = 253 * unit + index
            receipt['observedMonotonicNs'] = 254 * unit + index
            stops.append({'role': role,
                          'managerInvocation': principal['invocationId'],
                          'receiptStartedNs': receipt['startedMonotonicNs'],
                          'receiptObservedNs': receipt['observedMonotonicNs']})
        actor = {'pid': 501, 'uid': roster['observerUid'], 'startTicks': 45}
        event = {'kind': 'observer-death', 'roles': rows,
                 'observerPid': actor['pid'], 'observerStartTicks': actor['startTicks'],
                 'campaignDeadlineNs': 1000 * unit, 'policySeconds': 240}
        controller = {'invocationId': 'f' * 32, 'cgroupIdentity': [1, 30],
            'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            'mainPid': 100, 'mainStartTicks': 40,
            'observedMonotonicNs': 9 * unit}
        context = {'schemaVersion': 1,
            'kind': 'pr315-administrator-observer-death',
            'triggerStartedNs': 12 * unit,
            'triggerEventDigest': runner.fixtures.runtime.canonical_digest(event)[7:],
            'campaignDeadlineNs': 1000 * unit, 'preRoles': rows,
            'controllerBefore': controller,
            'controllerActiveAfterRequest': dict(controller,
                                                observedMonotonicNs=14 * unit),
            'controllerAfter': {'invocationId': controller['invocationId'],
                'activeState': 'failed', 'subState': 'failed', 'mainPid': '0',
                'observedMonotonicNs': 252 * unit},
            'policySeconds': 240, 'policyThresholdNs': 251 * unit,
            'stopObservations': stops, 'terminalObservedNs': 260 * unit,
            'populatedCgroups': [], 'remainingDescendants': 0,
            'retention': 'retained', 'actor': actor,
            'requestDigest': 'd' * 64, 'responseDigest': 'e' * 64,
            'requestStartedNs': 10 * unit, 'responseObservedNs': 11 * unit,
            'killStartedNs': 12 * unit, 'killFinishedNs': 13 * unit,
            'pidfdUsed': True}
        report = {'hostVerifiedIdentity': synthetic_host_identity(),
                  'guestStopped': True}
        result = {'roleKernelRoster': roster,
                  'roleKernelRosterWindow': {'startedMonotonicNs': 1 * unit,
                                             'finishedMonotonicNs': 5 * unit}}
        source = Path(__file__).resolve().parents[3]
        private = {'observerDeath': context,
                   'lifecycleActorBefore': synthetic_lifecycle_actor(source, 8 * unit),
                   'lifecycleActorAfter': synthetic_lifecycle_actor(source, 270 * unit)}
        fixture = {'schemaVersion': 4, 'mailDigest': 'sha256:' + '5' * 64}
        with patch.object(runner, 'group_prepared', return_value=True):
            identity, selected, sidecar = runner._lifecycle_group_attempt(
                'observer-death', report, result, fixture, private, terminal, source)
            self.assertEqual('passed', next(row['status'] for row in
                runner.acceptance.verify_attempts(identity, [selected])['cases']
                if row['caseId'] == 'observer-death'))
            self.assertEqual(251 * unit,
                             sidecar['targetEpoch']['observerPolicyThresholdNs'])
            premature = copy.deepcopy(private)
            premature['observerDeath']['controllerAfter'][
                'observedMonotonicNs'] = 250 * unit
            self.assertIsNone(runner._lifecycle_group_attempt(
                'observer-death', report, result, fixture, premature, terminal, source))
            early = copy.deepcopy(terminal)
            early['stopReceipts']['candidate-sender']['current'][
                'record']['startedMonotonicNs'] = 250 * unit
            self.assertIsNone(runner._lifecycle_group_attempt(
                'observer-death', report, result, fixture, private, early, source))

    def test_predeclared_groups_partition_exact_historical_inventory(self):
        groups = runner.groups()
        self.assertEqual(21, len(groups))
        self.assertEqual([len(cases) for _, cases in runner.campaign.GROUPS],
                         [len(names) for _, names in groups])
        names = [name for _, group in groups for name in group]
        self.assertEqual(45, len(set(names)))
        self.assertEqual(set(runner.acceptance.CASES), set(names))

    def test_partial_group_cannot_claim_other_cases_or_installed_acceptance(self):
        statuses = {'installed-ready': 'passed', 'resolver-authority': 'passed',
                    'cancellation': 'passed'}
        selected = runner.selected_public_result('authority', 'implementation-incomplete',
                                                positive=True, statuses=statuses)
        self.assertEqual('partial-execution', selected['status'])
        self.assertFalse(selected['installedPositiveExecuted'])
        self.assertFalse(selected['installedWorkloadAcceptanceSatisfied'])
        passed = {row['caseId'] for row in selected['cases'] if row['status'] == 'passed'}
        self.assertEqual({'resolver-authority'}, passed)
        positive = runner.selected_public_result('positive', 'implementation-incomplete',
                                                positive=True, statuses=statuses)
        self.assertTrue(positive['installedPositiveExecuted'])
        self.assertEqual({'installed-ready'}, {row['caseId'] for row in positive['cases']
                                               if row['status'] == 'passed'})
        with self.assertRaisesRegex(ValueError, 'group-selection-invalid'):
            runner.selected_cases('arbitrary-new-group')
        self.assertEqual('guest-operation-failed', runner.selected_terminal_status(
            'output-symlink', {'status': 'guest-operation-failed'}, False))
        failed = runner.selected_public_result('output-symlink',
            'guest-operation-failed', statuses={'output-symlink': 'inconclusive'})
        self.assertEqual('guest-operation-failed', failed['status'])
        self.assertFalse(failed['installedWorkloadAcceptanceSatisfied'])
        marker = {'schemaVersion': 1, 'kind': 'pr315-workload-probe-start',
                  'caseId': 'output-symlink', 'startedMonotonicNs': 123}
        self.assertFalse(runner.selected_probe_started('output-symlink', {'before': {}}))
        self.assertTrue(runner.selected_probe_started('output-symlink', {'probeStart': marker}))
        self.assertFalse(runner.selected_probe_started('output-fifo', {'probeStart': marker}))
        self.assertFalse(runner.selected_probe_started('output-symlink',
            {'probeStart': {**marker, 'startedMonotonicNs': True}}))

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
                case_group='positive',
                prepared_fixtures=root / 'fixtures', qemu_root=root / 'qemu',
                prepared_image=root / 'image', seed=root / 'seed', ssh_key=root / 'key',
                known_hosts=root / 'pin', storage_budget_bytes=40 * 1024**3,
                min_free_bytes=8 * 1024**3, memory_budget_bytes=7 * 1024**3,
                min_host_memory_bytes=1024**3, profile='tcg-multi',
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
                self.assertEqual('positive', selected.workload_group)
                self.assertEqual('none', selected.lifecycle_scenario)
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

    def test_default_full_campaign_stops_before_vm_while_emitters_are_missing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            args = SimpleNamespace(source=Path(__file__).resolve().parents[3],
                output=root / 'suite', storage_root=root,
                prepared_fixtures=root / 'fixtures', qemu_root=root / 'qemu',
                prepared_image=root / 'image', seed=root / 'seed', ssh_key=root / 'key',
                known_hosts=root / 'pin', storage_budget_bytes=40 * 1024**3,
                min_free_bytes=8 * 1024**3, memory_budget_bytes=7 * 1024**3,
                min_host_memory_bytes=1024**3, profile='tcg-multi')
            with patch.object(runner.os, 'geteuid', return_value=os.getuid()), \
                    patch.object(runner.reference, 'run') as launch, redirect_stdout(io.StringIO()):
                self.assertEqual(78, runner.run(args))
            launch.assert_not_called()
            result = json.loads((args.output / 'assessment.json').read_text())
            self.assertEqual('implementation-incomplete', result['status'])
            self.assertFalse(result['installedWorkloadAcceptanceSatisfied'])
            self.assertFalse((args.output / 'attempt-01').exists())
            args.output = root / 'probe'
            args.probe = True
            with patch.object(runner.os, 'geteuid', return_value=os.getuid()), \
                    patch.object(runner.reference, 'run') as launch, redirect_stdout(io.StringIO()):
                self.assertEqual(78, runner.run(args))
            launch.assert_not_called()
            self.assertEqual('implementation-incomplete',
                json.loads((args.output / 'assessment.json').read_text())['status'])

    def test_role_boundary_group_claims_only_its_five_started_cases(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            args = SimpleNamespace(source=Path(__file__).resolve().parents[3],
                output=root / 'suite', storage_root=root, case_group='role-boundary',
                fixture_manifest_digest='4' * 64, product_source_commit='d' * 40,
                prepared_fixtures=root / 'fixtures', qemu_root=root / 'qemu',
                prepared_image=root / 'image', seed=root / 'seed', ssh_key=root / 'key',
                known_hosts=root / 'pin', storage_budget_bytes=40 * 1024**3,
                min_free_bytes=8 * 1024**3, memory_budget_bytes=7 * 1024**3,
                min_host_memory_bytes=1024**3, profile='tcg-multi')
            host = synthetic_host_identity()
            roster = synthetic_role_kernel_roster()
            terminal = synthetic_terminal_roster(roster)
            del terminal['stopReceipts']['candidate-sender']['previous']
            observation = {'identity': {'sourceCommit': host['helperSourceCommit'],
                'bundleIdentity': host['bundleIdentity']},
                'groupPreparation': 'role-boundary',
                'contentRetrieval': 'not-executed-group', 'newEpoch': False,
                'topologyRoles': 4, 'signedAppWorkers': 0,
                'profile': runner.acceptance.PROFILE,
                'runtimePolicy': runner.fixtures.preparation.launcher_policy(),
                'roleKernelRoster': roster,
                'roleKernelRosterWindow': {'startedMonotonicNs': 1,
                                           'finishedMonotonicNs': 5},
                'workloadAcceptance': 'incomplete-hostile-contract-not-executed',
                'protectedExecutionEnabled': False}
            selected = []

            def fake_transport(attempt):
                selected.append(attempt)
                attempt.attempt.mkdir(mode=0o700)
                for name, value in (('attempt.private.json', {
                        'mode': 'workload-positive', 'workloadPurpose': 'selected-group',
                        'status': 'guest-report-retained', 'guestStopped': True,
                        'guestExitCode': 0, 'hostVerifiedIdentity': host}),
                    ('pr314-workload-observation.private.json', observation),
                    ('pr315-workload-volatile.private.json', terminal),
                    ('pr315-workload-memory.private.json', {'probeStart': {
                        'schemaVersion': 1, 'kind': 'pr315-workload-probe-start',
                        'caseId': 'role-boundary', 'startedMonotonicNs': 10}})):
                    runner.native_runner._save(attempt.attempt / name, value)
                return 0

            with patch.object(runner, 'prerequisites', return_value=[]), \
                    patch.object(runner, 'memory_snapshot', return_value={
                        'effectiveAvailableBytes': 9 * 1024**3}), \
                    patch.object(runner.native_runner, 'required_attempt_bytes', return_value=1), \
                    patch.object(runner.native_runner, 'capacity_reason', return_value=None), \
                    patch.object(runner.reference, 'run', side_effect=fake_transport), \
                    patch.object(runner.reference, 'verified_attempt_identity',
                                 return_value=host), \
                    patch.object(runner.fixtures, 'verify', return_value={
                        'schemaVersion': 4, 'mailDigest': 'sha256:' + '5' * 64}), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(2, runner.run(args))
            self.assertEqual('role-boundary', selected[0].workload_group)
            self.assertEqual('none', selected[0].lifecycle_scenario)
            report = json.loads((args.output / 'assessment.json').read_text())
            self.assertFalse(report['installedPositiveExecuted'])
            self.assertFalse(report['installedWorkloadAcceptanceSatisfied'])
            inconclusive = {row['caseId'] for row in report['cases']
                            if row['status'] == 'inconclusive'}
            self.assertEqual(set(dict(runner.campaign.GROUPS)['role-boundary']), inconclusive)
            self.assertEqual(40, sum(row['status'] == 'not-executed'
                                     for row in report['cases']))

    def test_missing_inputs_return_78_without_reference_allocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            source = Path(__file__).resolve().parents[3]
            args = SimpleNamespace(source=source, output=root / 'suite', storage_root=root,
                case_group='positive',
                prepared_fixtures=root / 'absent-fixtures', qemu_root=root / 'absent-qemu',
                prepared_image=root / 'absent-image', seed=root / 'absent-seed',
                ssh_key=root / 'absent-key', known_hosts=root / 'absent-pin',
                storage_budget_bytes=40 * 1024**3, min_free_bytes=8 * 1024**3,
                memory_budget_bytes=7 * 1024**3, min_host_memory_bytes=1024**3,
                profile='tcg-multi')
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
    def test_role_readiness_diagnostic_starts_no_case_or_positive_credit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            args = SimpleNamespace(source=Path(runner.__file__).resolve().parents[3],
                output=root / 'suite', storage_root=root,
                role_readiness_measurement=True, startup_measurement=False,
                prepared_fixtures=root / 'fixtures', qemu_root=root / 'qemu',
                prepared_image=root / 'image', seed=root / 'seed', ssh_key=root / 'key',
                known_hosts=root / 'pin', storage_budget_bytes=40 * 1024**3,
                min_free_bytes=8 * 1024**3, memory_budget_bytes=7 * 1024**3,
                min_host_memory_bytes=1024**3, profile='tcg-multi')
            selections = []
            roster = synthetic_role_kernel_roster()
            terminal = synthetic_terminal_roster(roster)
            del terminal['stopReceipts']['candidate-sender']['previous']

            def fake_transport(selected):
                selections.append(selected)
                selected.attempt.mkdir(mode=0o700)
                runner.native_runner._save(selected.attempt / 'attempt.private.json', {
                    'mode': 'workload-positive',
                    'workloadPurpose': 'role-readiness-measurement',
                    'status': 'guest-report-retained', 'guestStopped': True,
                    'guestExitCode': 0,
                    'hostVerifiedIdentity': synthetic_host_identity()})
                runner.native_runner._save(selected.attempt /
                    'pr314-workload-observation.private.json', {
                        'groupPreparation': 'role-readiness-diagnostic',
                        'identity': {'sourceCommit': 'b' * 40, 'bundleIdentity': 'a' * 64},
                        'contentRetrieval': 'not-executed-group', 'newEpoch': False,
                        'topologyRoles': 4, 'signedAppWorkers': 0,
                        'profile': runner.acceptance.PROFILE,
                        'runtimePolicy': runner.fixtures.preparation.launcher_policy(),
                        'roleKernelRoster': roster,
                        'roleKernelRosterWindow': {'startedMonotonicNs': 1,
                                                   'finishedMonotonicNs': 5},
                        'workloadAcceptance': 'not-executed-role-readiness-measurement',
                        'protectedExecutionEnabled': False})
                runner.native_runner._save(selected.attempt /
                    'pr315-workload-volatile.private.json', terminal)
                return 0

            with patch.object(runner, 'prerequisites', return_value=[]), \
                    patch.object(runner, 'memory_snapshot', return_value={
                        'effectiveAvailableBytes': 9 * 1024**3}), \
                    patch.object(runner.native_runner, 'required_attempt_bytes', return_value=1), \
                    patch.object(runner.native_runner, 'capacity_reason', return_value=None), \
                    patch.object(runner.reference, 'run', side_effect=fake_transport), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(2, runner.run(args))
            self.assertEqual('role-readiness-diagnostic', selections[0].workload_group)
            self.assertEqual('none', selections[0].lifecycle_scenario)
            result = json.loads((args.output / 'assessment.json').read_text())
            self.assertEqual('role-readiness-measurement-executed', result['status'])
            self.assertFalse(result['installedPositiveExecuted'])
            self.assertFalse(result['installedWorkloadAcceptanceSatisfied'])
            self.assertEqual({'not-executed'}, {row['status'] for row in result['cases']})

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
                min_host_memory_bytes=1024**3, profile='tcg-multi')
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
