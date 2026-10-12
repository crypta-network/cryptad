"""Offline tests for the distinct PR-316 copied-VM Mail host runner."""
from __future__ import annotations

import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import installation
import pr316_mail_runtime_evidence as evidence
import pr316_mail_runtime_runner as runner


def public_result(status='observed'):
    terminal = status == 'observed'
    return {
        'schemaVersion': 1, 'kind': evidence.PUBLIC_KIND,
        'contract': evidence.CONTRACT,
        'executionClass': evidence.EXECUTION_CLASS,
        'status': status, 'reasons': [] if terminal else ['setup-blocked'],
        'sourceIdentityDigest': 'sha256:' + '1' * 64 if terminal else None,
        'selectionDigest': 'sha256:' + '2' * 64 if terminal else None,
        'topologyRoles': 4,
        'namespaceTransportObserved': terminal,
        'installedMailFlowObserved': terminal,
        'insertFetchDecryptObserved': terminal,
        'wrongRecipientObserved': terminal,
        'duplicateBeforeWorkerRestart': terminal,
        'duplicateAfterWorkerRestart': terminal,
        'duplicateAfterRoleRestart': terminal,
        'workerRestartObserved': terminal,
        'roleRestartObserved': terminal,
        'replyObserved': terminal,
        'privacyCanarySurfacesObserved': terminal,
        'cleanupVerified': terminal, 'guestStopped': terminal,
        'watcherFinished': terminal,
        'historicalPr315AcceptanceTransferred': False,
        'installedWorkloadAcceptanceSatisfied': False,
        'finiteNativeAcceptance': False,
        'originalProtectedAuthority': False,
        'independentSecurityReview': False,
        'releaseEligible': False, 'phaseComplete': False}


def host_identity():
    return {
        'helperSourceCommit': 'a' * 40, 'helperSourceTree': 'b' * 40,
        'bundleIdentity': 'c' * 64, 'testKitDigest': 'd' * 64,
        'profileDigest': 'e' * 64, 'bootClosureDigest': 'f' * 64,
        'preparedImageDigest': '1' * 64,
        'fixtureManifestDigest': '2' * 64, 'productDigest': '3' * 64}


def driver_observation():
    return {
        'schemaVersion': 1,
        'kind': 'pr316-installed-mail-runtime-observation',
        'contract': evidence.CONTRACT,
        'executionClass': evidence.EXECUTION_CLASS,
        'selectionDigest': 'sha256:' + '2' * 64,
        'privateEvidenceDigest': 'sha256:' + '3' * 64,
        'evidenceClass': 'installed-four-role-private-observer',
        'topologyRoles': 4, 'namespaceTransportImplemented': True,
        'installedMailFlowObserved': True, 'observerMailFlowObserved': True,
        'ciphertextInsertionAndRecipientFetch': 'worker-observed',
        'wrongRecipientObserved': True, 'duplicateBeforeRestart': True,
        'duplicateAfterRestart': True, 'workerRestart': True,
        'roleRestart': True, 'replyObserved': True,
        'privacyCanarySurfacesObserved': True,
        'uncertainOperationState': False, 'cleanupState': 'completed',
        'installedWorkloadAcceptanceSatisfied': False,
        'historicalPr315AcceptanceTransferred': False,
        'finiteNativeAcceptance': False, 'originalProtectedAuthority': False,
        'independentSecurityReview': False, 'phaseComplete': False,
        'releaseEligible': False,
        'identity': {'sourceCommit': 'a' * 40, 'bundleIdentity': 'c' * 64},
        'runtimePolicy': {'revision': 'fixed'},
        'campaignDeadlineMonotonicNs': 1000,
        'workloadAcceptance': 'incomplete-pr316-private-evidence-not-verified',
        'protectedExecutionEnabled': False}


def terminal():
    records, receipts = {}, {}
    for index, role in enumerate(runner.fixtures.ROLES):
        record = {'role': role, 'state': 'quiescent', 'generation': '4' * 64,
                  'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                  'managerInvocation': format(index + 1, '032x'),
                  'cgroupIdentity': [1, 100 + index]}
        records[role] = {'status': 'captured', 'record': record}
        receipts[role] = {'current': {'status': 'captured', 'record': {
            **record, 'membership': 'only-stop-helper',
            'descendantCgroups': 0}}}
    return {'schemaVersion': 1,
            'kind': 'pr315-private-volatile-diagnostics',
            'cleanupReportedByCaller': True,
            'sentinel': {'status': 'matched',
                         'expectedDigest': 'sha256:' + '1' * 64,
                         'observedDigest': 'sha256:' + '1' * 64,
                         'sizeBytes': 32},
            'controllerRecords': records, 'stopReceipts': receipts}


def selected_fixture():
    return {'sourceCommit': 'a' * 40,
        'products': {
            'candidate': {'sourceCommit': '9' * 40,
                'artifactDigest': 'sha256:' + '5' * 64, 'artifactSize': 10,
                'packageTarget': 'linux-x64', 'contractVersion': 26},
            'previous': {'sourceCommit': '8' * 40,
                'artifactDigest': 'sha256:' + '6' * 64, 'artifactSize': 11,
                'packageTarget': 'linux-x64', 'contractVersion': 25}},
        'mailDigest': 'sha256:' + '4' * 64,
        'runtimeDigest': 'sha256:' + '7' * 64,
        'trustDigest': 'sha256:' + '8' * 64,
        'maxSeconds': 3600, 'maxOperations': 10000}


def mail_selection(root=Path('/fixtures')):
    mail = 'sha256:' + '4' * 64
    roles = runner.fixtures.ROLES
    fixture = selected_fixture()
    nodes = []
    for role in roles:
        product_name = 'previous' if role == 'previous' else 'candidate'
        product = fixture['products'][product_name]
        nodes.append({**product, 'role': role, 'product': 'cryptad',
            'runtimeDigest': fixture['runtimeDigest'],
            'configDigest': 'sha256:' + '9' * 64,
            'appDigests': [mail] if role.startswith('candidate-') else []})
    plan = {'schemaVersion': 1, 'kind': runner.fixtures.evidence.KIND,
            'experimentId': 'pr316-installed-mail-runtime',
            'profile': 'bounded-live',
            'topologyClass': 'single-host-independent-processes',
            'provenanceClass': 'source-build-comparison',
            'requestedSeconds': fixture['maxSeconds'], 'probeIntervalSeconds': 1,
            'policy': {'id': 'cross-version-observed-v1',
                       'minimumObservedSeconds': 0, 'maxGapSeconds': 600,
                       'maxEvents': 10000},
            'requiredScenarios': sorted(runner.fixtures.evidence.SCENARIOS),
            'producer': {'sourceCommit': fixture['sourceCommit'],
                         'runnerDigest': 'sha256:' + 'a' * 64,
                         'adapterDigest': 'sha256:' + 'b' * 64},
            'nodes': nodes}
    private = {'root':
        '/var/lib/cryptad-cross-version/experiments/pr316-installed-mail-runtime',
        'nodes': {role: {
            'archivePath': str(root / (('previous' if role == 'previous'
                                       else 'candidate') + '.tar.gz')),
            'javaHome': str(root / 'jdk'), 'fnpPort': 19400, 'fcpPort': 19401,
            'httpPort': 19402,
            'apps': ([{'appId': 'mail-prototype',
                       'bundlePath': str(root / 'mail.zip'),
                       'bundleDigest': mail}]
                     if role.startswith('candidate-') else []),
            'trustedKeysPath': str(root / 'trusted-app-keys.properties'),
            'trustedKeysDigest': fixture['trustDigest']}
                  for role in roles}}
    plan_digest = evidence.canonical_digest(plan)
    authorization = {'syntheticContent': True,
                     'experimentId': 'pr316-installed-mail-runtime',
                     'root': private['root'],
                     'maxSeconds': fixture['maxSeconds'],
                     'maxOperations': fixture['maxOperations'],
                     'executionClass': evidence.EXECUTION_CLASS,
                     'planDigest': plan_digest,
                     'selectionDigest': evidence.canonical_digest({
                         'executionClass': evidence.EXECUTION_CLASS,
                         'planDigest': plan_digest})}
    return {'plan': plan, 'private': private, 'authorization': authorization}


def args(root, *, probe=False):
    selected = SimpleNamespace(
        probe=probe, source=root / 'source', output=root / 'suite-1',
        prepared_image=root / 'prepared.qcow2', qemu_root=root / 'qemu',
        seed=root / 'seed.iso', ssh_key=root / 'key',
        known_hosts=root / 'known-hosts',
        prepared_fixtures=root / 'fixtures', storage_root=root,
        product_source_commit='a' * 40, prepared_image_digest='1' * 64,
        fixture_manifest_digest='2' * 64,
        storage_budget_bytes=32 * 1024**3,
        min_free_bytes=1024**3, memory_budget_bytes=7 * 1024**3,
        min_host_memory_bytes=1024**3)
    selected.source.mkdir()
    selected.qemu_root.mkdir()
    selected.prepared_fixtures.mkdir()
    for path in (selected.prepared_image, selected.seed, selected.ssh_key,
                 selected.known_hosts):
        path.write_bytes(b'x')
    return selected


class MailRuntimeRunnerTest(unittest.TestCase):
    def test_runner_is_an_explicit_installation_test_seam(self):
        self.assertIn(
            'tools/release-certification/restricted/pr316_mail_runtime_runner.py',
            installation.TEST_SEAMS)

    def test_cli_exposes_no_historical_selection_or_authority_options(self):
        options = {option for action in runner.parser()._actions
                   for option in action.option_strings}
        for forbidden in ('--case-group', '--campaign-plan',
                          '--campaign-key-fingerprint', '--lifecycle-scenario',
                          '--retired-authority-input', '--history'):
            self.assertNotIn(forbidden, options)
        self.assertNotIn('pr315_workload_campaign', Path(runner.__file__).read_text())
        self.assertNotIn('pr315_case_v10', Path(runner.__file__).read_text())
        self.assertNotIn('pr315_campaign_owner', Path(runner.__file__).read_text())

    def test_terminal_cleanup_requires_all_current_quiescent_roles(self):
        value = terminal()
        self.assertTrue(runner._terminal_cleanup_verified(value))
        mutations = []
        changed = copy.deepcopy(value)
        changed['cleanupReportedByCaller'] = False
        mutations.append(changed)
        changed = copy.deepcopy(value)
        del changed['stopReceipts']['relay-no-apps']
        mutations.append(changed)
        changed = copy.deepcopy(value)
        changed['stopReceipts']['candidate-recipient']['current']['record'][
            'descendantCgroups'] = 1
        mutations.append(changed)
        changed = copy.deepcopy(value)
        changed['controllerRecords']['candidate-sender']['record'][
            'managerInvocation'] = 'f' * 32
        mutations.append(changed)
        for invalid in mutations:
            with self.subTest(invalid=invalid):
                self.assertFalse(runner._terminal_cleanup_verified(invalid))

    def test_driver_observation_is_closed_and_never_accepts_uncertainty(self):
        self.assertEqual(driver_observation(),
                         runner._driver_observation(driver_observation()))
        for mutate in (
                lambda value: value.update(extra=True),
                lambda value: value.update(uncertainOperationState=True),
                lambda value: value.update(cleanupState='administrator-required'),
                lambda value: value.update(installedWorkloadAcceptanceSatisfied=True),
                lambda value: value.update(executionClass='other')):
            value = driver_observation()
            mutate(value)
            with self.assertRaisesRegex(ValueError,
                                        'pr316-driver-observation-invalid'):
                runner._driver_observation(value)

    def test_host_recomputes_selection_and_rejects_app_roster_tampering(self):
        selection = mail_selection()
        fixture = selected_fixture()
        self.assertEqual(selection['authorization']['selectionDigest'],
                         runner._mail_selection(selection, fixture,
                                                Path('/fixtures')))
        changed = copy.deepcopy(selection)
        changed['private']['nodes']['previous']['apps'] = [{
            'appId': 'mail-prototype', 'bundleDigest': fixture['mailDigest']}]
        with self.assertRaisesRegex(ValueError, 'selection-roster-invalid'):
            runner._mail_selection(changed, fixture, Path('/fixtures'))

    def test_retained_surface_scan_rejects_encoded_mail_payload_canary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            canary = evidence.SYNTHETIC_TEXTS[0]
            import base64
            import urllib.parse
            payload = json.dumps({'body': canary}, separators=(',', ':')).encode()
            encoded = urllib.parse.urlencode({
                'payloadBase64': base64.b64encode(payload).decode()})
            (root / 'driver.private.log').write_text(encoded)
            with self.assertRaisesRegex(ValueError, 'canary-exposure'):
                runner._scan_retained_privacy(root)
            (root / 'driver.private.log').write_text('{"safe":true}')
            self.assertEqual(1, runner._scan_retained_privacy(root)['filesScanned'])

    def test_retained_surface_scan_excludes_only_the_owned_source_clone(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            clone = root / 'attempt-01/cryptad'
            clone.mkdir(parents=True, mode=0o700)
            clone.chmod(0o700)
            (clone / 'two_node_demo.py').write_text(evidence.SYNTHETIC_TEXTS[0])
            retained = root / 'attempt-01/transport.private.log'
            retained.write_text('safe generated evidence')

            scanned = runner._scan_retained_privacy(
                root, exclude_source_clone=True)

            self.assertEqual(1, scanned['filesScanned'])
            self.assertTrue(scanned['sourceCloneExcluded'])
            retained.write_text(evidence.SYNTHETIC_TEXTS[0])
            with self.assertRaisesRegex(ValueError, 'canary-exposure'):
                runner._scan_retained_privacy(
                    root, exclude_source_clone=True)

    def test_retained_surface_scan_rejects_a_linked_source_clone(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            attempt = root / 'attempt-01'
            attempt.mkdir()
            target = root / 'outside'
            target.mkdir()
            (attempt / 'cryptad').symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'source-clone-invalid'):
                runner._scan_retained_privacy(
                    root, exclude_source_clone=True)

    def test_final_inventory_is_a_distinct_phase_bound_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / 'suite-1'
            output.mkdir()
            receipt = {'observation': {'activeTaskQemu': [],
                                       'observedMonotonicNs': 101}}
            with patch.object(runner.time, 'monotonic_ns', return_value=100), \
                    patch.object(runner.pve_inventory, 'verify_receipt',
                                 return_value=receipt) as verify:
                self.assertEqual(receipt, runner.wait_final_pve_inventory(
                    root, output, 'suite-1', 'a' * 40))
            verify.assert_called_once_with(
                root / 'host-inventory/suite-1-final.json',
                'suite-1', 'a' * 40, 'final')
            marker = json.loads((output /
                'awaiting-final-pve-inventory.private.json').read_text())
            self.assertEqual('pr316-awaiting-final-pve-inventory', marker['kind'])
            self.assertEqual(100, marker['notBeforeMonotonicNs'])

    def test_final_inventory_rejects_a_receipt_created_before_the_barrier(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / 'suite-1'
            output.mkdir()
            stale = {'observation': {'activeTaskQemu': [],
                                     'observedMonotonicNs': 99}}
            with patch.object(runner.time, 'monotonic_ns', return_value=100), \
                    patch.object(runner.time, 'sleep') as sleep, \
                    patch.object(runner.pve_inventory, 'verify_receipt',
                                 return_value=stale) as verify, \
                    self.assertRaisesRegex(
                        ValueError, 'pr316-final-pve-inventory-before-barrier'):
                runner.wait_final_pve_inventory(
                    root, output, 'suite-1', 'a' * 40)

            verify.assert_called_once_with(
                root / 'host-inventory/suite-1-final.json',
                'suite-1', 'a' * 40, 'final')
            sleep.assert_not_called()

    def test_final_pve_capacity_requires_host_budget_and_free_reserve(self):
        selected = SimpleNamespace(storage_budget_bytes=1000, min_free_bytes=200)
        self.assertIsNone(runner.validate_final_pve_capacity(selected, {
            'allocatedTaskBytes': 300, 'availableTaskBytes': 700}, 500))
        for observation in (
                {'allocatedTaskBytes': 501, 'availableTaskBytes': 700},
                {'allocatedTaskBytes': 300, 'availableTaskBytes': 699}):
            with self.subTest(observation=observation), self.assertRaisesRegex(
                    ValueError, 'pr316-final-pve-capacity-unavailable'):
                runner.validate_final_pve_capacity(selected, observation, 500)
        with self.assertRaisesRegex(ValueError, 'pr316-final-pve-capacity-invalid'):
            runner.validate_final_pve_capacity(
                selected, {'allocatedTaskBytes': 300, 'availableTaskBytes': True}, 500)

    def test_pressure_watcher_is_requested_only_at_the_prelaunch_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            ready = {'kind': 'pr315-pve-watch-ready'}
            with patch.object(runner.pressure_watch, 'verify_launch_ready',
                              side_effect=[FileNotFoundError(), ready]) as verify, \
                    patch.object(runner.time, 'monotonic', return_value=0), \
                    patch.object(runner.time, 'sleep') as sleep:
                self.assertEqual(ready, runner.wait_pressure_watcher(
                    output, 'suite-1', 'a' * 40))
            self.assertEqual(2, verify.call_count)
            sleep.assert_called_once_with(.25)
            marker = json.loads((output /
                'awaiting-pressure-watcher.private.json').read_text())
            self.assertEqual('pr316-awaiting-pressure-watcher', marker['kind'])

    def test_failed_watcher_reconciliation_accepts_authenticated_prelaunch_stop(self):
        ready = {'observedMonotonicNs': 100}
        stopped = {'action': 'stopped-before-launch', 'seenTaskQemu': False}
        with patch.object(runner.pressure_watch, 'verify_finished',
                          side_effect=ValueError('not-completed')) as finished, \
                patch.object(runner.pressure_watch, 'verify_stopped_before_launch',
                             return_value=stopped) as prelaunch:
            self.assertEqual(stopped, runner.reconcile_failed_watcher(
                'suite-1', 'a' * 40, ready))
        finished.assert_called_once_with('suite-1', 'a' * 40, ready)
        prelaunch.assert_called_once_with('suite-1', 'a' * 40, ready)

    def test_attempt_projection_uses_private_evidence_validator_and_terminal_proof(self):
        selected_args = SimpleNamespace(
            product_source_commit='9' * 40,
            prepared_image_digest='1' * 64,
            fixture_manifest_digest='2' * 64,
            prepared_fixtures=Path('/fixtures'))
        report = {'schemaVersion': 7, 'mode': 'workload-positive',
            'workloadPurpose': 'mail-runtime', 'status': 'guest-report-retained',
            'guestExitCode': 0, 'guestStopped': True,
            'helperSourceCommit': 'a' * 40,
            'helperSourceTree': 'b' * 40, 'productDigest': '3' * 64,
            'productSourceCommit': '9' * 40,
            'preparedImageDigest': '1' * 64,
            'fixtureManifestDigest': '2' * 64,
            'hostVerifiedIdentity': host_identity()}
        private = {'selectionDigest': 'sha256:' + '2' * 64}
        projected = public_result()
        fixture = selected_fixture()
        selection = mail_selection()
        private['selectionDigest'] = selection['authorization']['selectionDigest']
        observed = driver_observation()
        observed['selectionDigest'] = private['selectionDigest']
        observed['privateEvidenceDigest'] = evidence.canonical_digest(private)
        with patch.object(runner, '_private_json', side_effect=[
                observed, private, selection, terminal()]), \
                patch.object(runner.evidence, 'validate_private_observation',
                             return_value=private) as validate, \
                patch.object(runner.evidence, 'source_identity_digest',
                             return_value='sha256:' + '1' * 64) as source, \
                patch.object(runner.evidence, 'public_projection',
                             return_value=projected) as public:
            actual = runner._attempt_projection(selected_args, Path('/attempt'),
                report, fixture,
                'a' * 40, True)
        self.assertEqual(projected, actual)
        validate.assert_called_once_with(private)
        source.assert_called_once_with(host_identity())
        self.assertTrue(public.call_args.kwargs['cleanup_verified'])
        self.assertTrue(public.call_args.kwargs['guest_stopped'])
        self.assertTrue(public.call_args.kwargs['watcher_finished'])
        self.assertTrue(public.call_args.kwargs['privacy_verified'])

    def test_attempt_projection_rejects_incomplete_terminal_before_public_projection(self):
        selected_args = SimpleNamespace(
            product_source_commit='9' * 40,
            prepared_image_digest='1' * 64,
            fixture_manifest_digest='2' * 64,
            prepared_fixtures=Path('/fixtures'))
        report = {'schemaVersion': 7, 'mode': 'workload-positive',
            'workloadPurpose': 'mail-runtime', 'status': 'guest-report-retained',
            'guestExitCode': 0, 'guestStopped': True,
            'helperSourceCommit': 'a' * 40,
            'helperSourceTree': 'b' * 40, 'productDigest': '3' * 64,
            'productSourceCommit': '9' * 40,
            'preparedImageDigest': '1' * 64,
            'fixtureManifestDigest': '2' * 64,
            'hostVerifiedIdentity': host_identity()}
        invalid_terminal = terminal()
        invalid_terminal['cleanupReportedByCaller'] = False
        selection = mail_selection()
        private = {'selectionDigest': selection['authorization']['selectionDigest']}
        observed = driver_observation()
        observed['selectionDigest'] = private['selectionDigest']
        observed['privateEvidenceDigest'] = evidence.canonical_digest(private)
        with patch.object(runner, '_private_json', side_effect=[
                observed, private, selection, invalid_terminal]), \
                patch.object(runner.evidence, 'validate_private_observation',
                             return_value=private), \
                patch.object(runner.evidence, 'public_projection') as public:
            with self.assertRaisesRegex(ValueError,
                                        'pr316-terminal-cleanup-invalid'):
                runner._attempt_projection(selected_args, Path('/attempt'), report,
                    selected_fixture(), 'a' * 40, True)
        public.assert_not_called()

    def test_probe_checks_admission_and_capacity_but_never_allocates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            selected = args(root, probe=True)
            failed = public_result('failed')
            with patch.object(runner.reference, 'sha256', return_value='a'), \
                    patch.object(runner, 'task_vm_inventory', return_value={
                        'activeQemu': [], 'retained': [], 'allocatedBytes': 0}) as inventory, \
                    patch.object(runner, 'prerequisites', return_value=[]), \
                    patch.object(runner, 'memory_snapshot', return_value={
                        'effectiveAvailableBytes': 16 * 1024**3}), \
                    patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(
                        stdout='a' * 40)), \
                    patch.object(runner.host_admission, 'verify_receipt',
                                 return_value={'observation': {}}), \
                    patch.object(runner.pve_inventory, 'verify_receipt',
                                 return_value={'observation': {
                                     'activeTaskQemu': [],
                                     'allocatedTaskBytes': 0,
                                     'availableTaskBytes': 1}}), \
                    patch.object(runner, 'wait_final_pve_inventory',
                                 return_value={'observation': {
                                     'activeTaskQemu': [],
                                     'allocatedTaskBytes': 0,
                                     'availableTaskBytes': 2 * 1024**3}}), \
                    patch.object(runner.retained_runner, 'allocated_bytes',
                                 return_value=0), \
                    patch.object(runner.retained_runner, 'required_attempt_bytes',
                                 return_value=1024), \
                    patch.object(runner.retained_runner, 'capacity_reason',
                                 return_value=None), \
                    patch.object(runner.evidence, 'failed_projection',
                                 return_value=failed), \
                    patch.object(runner.reference, 'run') as execute:
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(78, runner.run(selected))
            execute.assert_not_called()
            self.assertEqual(1, inventory.call_count)
            self.assertEqual(root.resolve(), inventory.call_args.args[0])
            self.assertEqual(failed,
                json.loads((selected.output / 'assessment.json').read_bytes()))

    def test_success_forces_the_fixed_execution_class_and_one_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            selected = args(root)
            projected = public_result()
            captured, events = {}, []
            validate_capacity = runner.validate_final_pve_capacity

            def execute(call, *, before_guest_launch):
                captured['args'] = call
                call.attempt.mkdir()
                before_guest_launch()
                events.append('execute')

            def check_capacity(*values):
                events.append('pve-capacity')
                return validate_capacity(*values)

            with patch.object(runner.reference, 'sha256', return_value='a'), \
                    patch.object(runner, 'task_vm_inventory', return_value={
                        'activeQemu': [], 'retained': [], 'allocatedBytes': 0}) as inventory, \
                    patch.object(runner, 'prerequisites', return_value=[]), \
                    patch.object(runner, 'memory_snapshot', return_value={
                        'effectiveAvailableBytes': 16 * 1024**3}), \
                    patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(
                        stdout='a' * 40)), \
                    patch.object(runner.host_admission, 'verify_receipt',
                                 return_value={'observation': {}}), \
                    patch.object(runner.pve_inventory, 'verify_receipt',
                                 return_value={'observation': {
                                     'activeTaskQemu': [],
                                     'allocatedTaskBytes': 0,
                                     'availableTaskBytes': 1}}), \
                    patch.object(runner, 'wait_final_pve_inventory',
                                 return_value={'observation': {
                                     'activeTaskQemu': [],
                                     'allocatedTaskBytes': 0,
                                     'availableTaskBytes': 2 * 1024**3}}), \
                    patch.object(runner, 'validate_final_pve_capacity',
                                 side_effect=check_capacity) as pve_capacity, \
                    patch.object(runner.pressure_watch, 'wait_ready',
                                 side_effect=AssertionError('legacy early watcher wait')), \
                    patch.object(runner.pressure_watch, 'verify_launch_ready',
                                 return_value={'observedMonotonicNs': 1}) as watch_ready, \
                    patch.object(runner.pressure_watch, 'verify_finished',
                                 return_value={'action': 'completed'}), \
                    patch.object(runner.retained_runner, 'allocated_bytes',
                                 return_value=0), \
                    patch.object(runner.retained_runner, 'required_attempt_bytes',
                                 return_value=1024), \
                    patch.object(runner.retained_runner, 'capacity_reason',
                                 return_value=None), \
                    patch.object(runner.fixtures, 'verify', return_value={}), \
                    patch.object(runner.reference, 'run', side_effect=execute), \
                    patch.object(runner, '_private_json', return_value={}), \
                    patch.object(runner, '_attempt_projection',
                                 return_value=projected):
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(0, runner.run(selected))
            invoked = captured['args']
            self.assertEqual(evidence.EXECUTION_CLASS,
                             invoked.execution_class)
            self.assertEqual(runner.PROFILE, invoked.profile)
            self.assertEqual(runner.PORT, invoked.port)
            self.assertEqual('none', invoked.lifecycle_scenario)
            self.assertIsNone(invoked.workload_group)
            self.assertFalse(invoked.startup_measurement)
            self.assertEqual(selected.output / 'attempt-01', invoked.attempt)
            self.assertEqual(2, inventory.call_count)
            self.assertEqual(['pve-capacity', 'execute'], events)
            watch_ready.assert_called_once_with(selected.output.name, 'a' * 40)
            pve_capacity.assert_called_once_with(selected, {
                'activeTaskQemu': [], 'allocatedTaskBytes': 0,
                'availableTaskBytes': 2 * 1024**3}, 1024)

    def test_failed_private_reconciliation_still_emits_closed_assessment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            selected = args(root)

            def execute(call, *, before_guest_launch):
                call.attempt.mkdir()
                before_guest_launch()

            with patch.object(runner.reference, 'sha256', return_value='a'), \
                    patch.object(runner, 'task_vm_inventory', return_value={
                        'activeQemu': [], 'retained': [], 'allocatedBytes': 0}) as inventory, \
                    patch.object(runner, 'prerequisites', return_value=[]), \
                    patch.object(runner, 'memory_snapshot', return_value={
                        'effectiveAvailableBytes': 16 * 1024**3}), \
                    patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(
                        stdout='a' * 40)), \
                    patch.object(runner.host_admission, 'verify_receipt',
                                 return_value={'observation': {}}), \
                    patch.object(runner.pve_inventory, 'verify_receipt',
                                 return_value={'observation': {
                                     'activeTaskQemu': [],
                                     'allocatedTaskBytes': 0,
                                     'availableTaskBytes': 1}}), \
                    patch.object(runner, 'wait_final_pve_inventory',
                                 return_value={'observation': {
                                     'activeTaskQemu': [],
                                     'allocatedTaskBytes': 0,
                                     'availableTaskBytes': 2 * 1024**3}}), \
                    patch.object(runner.pressure_watch, 'wait_ready',
                                 side_effect=AssertionError('legacy early watcher wait')), \
                    patch.object(runner.pressure_watch, 'verify_launch_ready',
                                 return_value={'observedMonotonicNs': 1}), \
                    patch.object(runner.pressure_watch, 'verify_finished',
                                 return_value={'action': 'completed'}), \
                    patch.object(runner.retained_runner, 'allocated_bytes',
                                 return_value=0), \
                    patch.object(runner.retained_runner, 'required_attempt_bytes',
                                 return_value=1024), \
                    patch.object(runner.retained_runner, 'capacity_reason',
                                 return_value=None), \
                    patch.object(runner.fixtures, 'verify', return_value={}), \
                    patch.object(runner.reference, 'run', side_effect=execute), \
                    patch.object(runner, '_private_json', return_value={}), \
                    patch.object(runner, '_attempt_projection', side_effect=ValueError(
                        'pr316-private-evidence-binding-invalid')):
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(2, runner.run(selected))
            result = json.loads((selected.output / 'assessment.json').read_bytes())
            self.assertEqual('failed', result['status'])
            self.assertEqual(['pr316-private-evidence-binding-invalid'],
                             result['reasons'])
            self.assertFalse(result['installedMailFlowObserved'])
            retained = json.loads(
                (selected.output / 'failure.private.json').read_bytes())
            self.assertEqual('pr316-private-host-execution-failure',
                             retained['kind'])
            self.assertFalse(retained['installedMailFlowObserved'])
            self.assertEqual(2, inventory.call_count)


if __name__ == '__main__':
    unittest.main()
