"""Preparation contract regressions, never installed case records or verdicts."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pr315_preparation as preparation

DRIVER = 'c' * 64
PRODUCER = 'd' * 64
BOOT = '12345678-1234-1234-1234-123456789abc'


def fixture():
    epoch = {'pid': 20, 'uid': 0, 'gid': 0, 'startTicks': 10, 'bootId': BOOT,
        'namespacePids': [20], 'namespaces': {'pid': 1, 'net': 2, 'mnt': 3, 'user': 4},
        'cgroupIdentity': [1, 2],
        'cgroupDigest': preparation._digest({'role': 'preparation-administrator', 'identity': [1, 2]}),
        'invocationId': '1' * 32, 'sourceDigest': DRIVER, 'observedMonotonicNs': 100}
    ready = {'role': 'candidate-recipient', 'stage': 'fcp-get-node',
        'startRequestNs': 200, 'startResponseNs': 210, 'readinessDeadlineNs': 400,
        'attemptCount': 3, 'lastAttemptStartedNs': 390, 'failedAtNs': 450,
        'causeType': 'RuntimeFailure'}
    campaign = {'state': 'terminalizing', 'bootId': BOOT,
                'deadlineMonotonicNs': 2000, 'generation': '0' * 64}
    terminal = {'cleanupReportedByCaller': True, 'sentinel': {'status': 'matched'},
        'controllerRecords': {'campaign': {'status': 'captured', 'record': campaign}},
        'stopReceipts': {}}
    rows = {}
    for i, role in enumerate(preparation.ROLES):
        launched = i < 2
        authority = {'role': role, 'campaign': campaign['generation'], 'bootId': BOOT,
            'state': 'quiescent' if launched else 'prepared',
            'generation': str(i + 1) * 64 if launched else None,
            'managerInvocation': str(i + 1) * 32 if launched else None,
            'cgroupIdentity': [1, 10 + i] if launched else None}
        receipt = dict(authority, membership='only-stop-helper', descendantCgroups=0) if launched else None
        rows[role] = {'uid': 1001 + i, 'launched': launched, 'authority': authority,
            'campaignGeneration': campaign['generation'],
            'stopReceipt': receipt, 'manager': {'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0'},
            'cgroupPresent': False, 'cgroupPopulated': False}
        terminal['controllerRecords'][role] = {'status': 'captured', 'record': authority}
        terminal['stopReceipts'][role] = {'current': {'status': 'captured', 'record': receipt}
            if launched else {'status': 'unavailable-or-unsafe'}}
    requests = {'device': 1, 'inode': 10, 'uid': 0, 'mode': 0o755, 'entries': []}
    proof = {'schemaVersion': 1, 'kind': preparation.KIND, 'groupId': 'role-boundary',
        'phase': 'pre-probe-readiness-failure', 'probeStarted': False, 'preparationMode': 'group',
        'nonce': 'a' * 64, 'campaignDeadlineMonotonicNs': 2000, 'producerDigest': PRODUCER,
        'administratorBefore': epoch, 'administratorAtFailure': dict(epoch, observedMonotonicNs=500),
        'administratorAfterCleanup': dict(epoch, observedMonotonicNs=700),
        'observer': {'kind': 'installed-observer-process', 'uid': 2000, 'pid': 21,
                     'bootId': BOOT, 'sourceDigest': DRIVER, 'observedMonotonicNs': 150},
        'readiness': ready, 'requestsBefore': requests, 'requestsAtFailure': requests,
        'requestsAfterCleanup': requests,
        'termination': {'roles': rows, 'roleUidProcesses': [], 'campaign': campaign,
                        'observedMonotonicNs': 800}}
    diagnostics = {'cleanup': 'completed', 'readinessAtFailure': {'role': ready['role'], 'stage': ready['stage']},
        'observerFailure': {'privateTranscript': json.dumps({'observerFailure': 'RuntimeFailure',
            'privateDetail': 'workload-daemon-readiness-timeout', 'readinessDiagnostic': ready})}}
    return proof, diagnostics, terminal


class VerificationTest(unittest.TestCase):
    def verify(self, proof, diagnostics, terminal, **options):
        return preparation.verify_failure(proof, diagnostics, terminal,
            'role-boundary', DRIVER, PRODUCER, **options)

    def test_partial_initial_launch_requires_real_stops_only_for_started_roles(self):
        proof, diagnostics, terminal = fixture()
        self.assertTrue(self.verify(proof, diagnostics, terminal))
        self.assertIsNone(proof['termination']['roles']['previous']['stopReceipt'])
        self.assertIsNone(proof['termination']['roles']['relay-no-apps']['authority']['managerInvocation'])

    def test_sorted_json_role_order_preserves_the_initial_launch_prefix(self):
        proof, diagnostics, terminal = json.loads(json.dumps(fixture(), sort_keys=True))
        self.assertTrue(self.verify(proof, diagnostics, terminal))

    def test_missing_or_post_probe_witness_never_becomes_safe_preparation(self):
        proof, diagnostics, terminal = fixture()
        self.assertFalse(self.verify(None, diagnostics, terminal))
        diagnostics['probeStart'] = {'schemaVersion': 1, 'kind': 'pr315-workload-probe-start',
            'caseId': 'role-boundary', 'startedMonotonicNs': 220}
        self.assertFalse(self.verify(proof, diagnostics, terminal))

        proof['probeStarted'] = True
        diagnostics.pop('probeStart')
        self.assertFalse(self.verify(proof, diagnostics, terminal))

    def test_wrong_actor_instance_source_or_boot_is_rejected(self):
        for actor_key in ('administratorBefore', 'administratorAtFailure', 'administratorAfterCleanup'):
            for field, replacement in (('uid', 1001), ('pid', 99), ('startTicks', 11),
                                       ('bootId', '0' * 36), ('sourceDigest', 'f' * 64)):
                with self.subTest(actor=actor_key, field=field):
                    proof, diagnostics, terminal = copy.deepcopy(fixture())
                    proof[actor_key][field] = replacement
                    self.assertFalse(self.verify(proof, diagnostics, terminal))

    def test_probe_release_request_after_failure_cannot_be_erased_from_the_contract(self):
        for name in ('requestsBefore', 'requestsAtFailure', 'requestsAfterCleanup'):
            proof, diagnostics, terminal = copy.deepcopy(fixture())
            proof[name]['entries'] = ['candidate-sender.json']
            self.assertFalse(self.verify(proof, diagnostics, terminal))

    def test_unstarted_role_cannot_supply_an_invocation_or_stop_receipt(self):
        for field, value in (('managerInvocation', 'f' * 32), ('generation', 'f' * 64),
                             ('cgroupIdentity', [1, 90])):
            proof, diagnostics, terminal = copy.deepcopy(fixture())
            proof['termination']['roles']['previous']['authority'][field] = value
            self.assertFalse(self.verify(proof, diagnostics, terminal))
        proof, diagnostics, terminal = copy.deepcopy(fixture())
        proof['termination']['roles']['previous']['stopReceipt'] = {}
        self.assertFalse(self.verify(proof, diagnostics, terminal))

    def test_incomplete_fence_live_children_or_failed_cleanup_are_rejected(self):
        for change in ('live-process', 'populated', 'active', 'wrong-boot', 'not-fenced', 'cleanup'):
            proof, diagnostics, terminal = copy.deepcopy(fixture())
            if change == 'live-process':proof['termination']['roleUidProcesses'] = [90]
            elif change == 'populated':proof['termination']['roles']['candidate-sender']['cgroupPopulated'] = True
            elif change == 'active':proof['termination']['roles']['candidate-sender']['manager']['MainPID'] = '90'
            elif change == 'wrong-boot':proof['termination']['campaign']['bootId'] = '0' * 36
            elif change == 'not-fenced':proof['termination']['campaign']['state'] = 'running'
            else:diagnostics['cleanup'] = 'failed'
            self.assertFalse(self.verify(proof, diagnostics, terminal), change)

    def test_retired_authority_mode_and_overall_deadline_cannot_be_substituted(self):
        proof, diagnostics, terminal = fixture()
        self.assertFalse(self.verify(proof, diagnostics, terminal, retired=True))
        proof['campaignDeadlineMonotonicNs'] = proof['readiness']['failedAtNs']
        self.assertFalse(self.verify(proof, diagnostics, terminal))

    def test_target_role_must_belong_to_the_initial_started_prefix(self):
        proof, diagnostics, terminal = copy.deepcopy(fixture())
        row = proof['termination']['roles']['candidate-sender']
        row['launched'] = False
        row['authority'].update(state='prepared', generation=None, managerInvocation=None, cgroupIdentity=None)
        row['stopReceipt'] = None
        terminal['stopReceipts']['candidate-sender']['current'] = {'status': 'unavailable-or-unsafe'}
        self.assertFalse(self.verify(proof, diagnostics, terminal))


class ArchiveTest(unittest.TestCase):
    def test_missing_positive_phase_proof_cannot_create_a_retry_record(self):
        import pr315_workload_coordinator as coordinator
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(preparation, 'verify_received_stage', return_value=None):
                result = coordinator.archive_launched_preparation_failure(
                    root, {}, {}, 'suite-201', 'role-boundary', root/'stage', 'a'*64)
            self.assertIsNone(result)
            self.assertEqual([], list(root.iterdir()))

    def test_sealed_preparation_history_rejects_changed_proof_or_full_staging(self):
        import pr315_workload_coordinator as coordinator
        import pr315_campaign_seal as seal
        from test_pr315_campaign_seal import fixture_plan
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            (root/'attempts').mkdir(mode=0o700)
            stage = root/'full-attempt-staging/suite-201'
            stage.mkdir(parents=True, mode=0o700)
            plan, fingerprint = fixture_plan(root)
            config = {'sourceCommit': 'a'*40, 'hostKeyFingerprint': fingerprint}
            proof, _diagnostics, _terminal = fixture()
            manifest = {'files': {'host-stop.private.json': {'sha256': '1'*64},
                                  'host-monitor.private.json': {'sha256': '2'*64}}}
            with patch.object(preparation, 'verify_received_stage', return_value=proof), \
                    patch.object(coordinator, 'verify_full_staging_copy',
                        return_value=(stage, manifest, 'f'*64)) as staging:
                receipt = coordinator.archive_launched_preparation_failure(
                    root, config, plan, 'suite-201', 'role-boundary', stage, 'f'*64)
                self.assertEqual('setup-failed', receipt['status'])
                self.assertIs(receipt['probeStarted'], False)
                self.assertEqual({}, receipt['caseDigests'])
                history = seal.load_verified_history(root, plan,
                    pinned_source_commit='a'*40, pinned_fingerprint=fingerprint)
                self.assertEqual([receipt], history)
                coordinator.verify_preparation_archive(root, plan, receipt)
                staging.return_value = (stage, manifest, 'e'*64)
                with self.assertRaisesRegex(ValueError, 'proof-changed'):
                    coordinator.verify_preparation_archive(root, plan, receipt)
                staging.return_value = (stage, manifest, 'f'*64)
                path = root/'attempts/suite-201/preparation-proof.private.json'
                changed = dict(proof, nonce='e'*64)
                path.write_text(json.dumps(changed))
                path.chmod(0o600)
                with self.assertRaisesRegex(ValueError, 'proof-changed'):
                    coordinator.verify_preparation_archive(root, plan, receipt)


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                     'requires disposable Linux root for real preparation pidfd and request directory')
class AdministratorGateTest(unittest.TestCase):
    def test_real_pidfd_gate_latches_prepared_before_any_later_failure(self):
        import pr314_workload_driver as driver
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'probe-requests').mkdir(mode=0o755)
            gate = preparation.PreparationGate('role-boundary', SimpleNamespace(ROOT=root),
                lambda: driver._administrator_collector_epoch('preparation'), 10**30)
            try:
                self.assertEqual(os.getpid(), gate.before['pid'])
                self.assertEqual(0, gate.before['uid'])
                gate.prepared()
                with self.assertRaisesRegex(ValueError, 'probe-phase-not-established'):
                    gate.readiness_failed({}, {})
                self.assertIsNone(gate.after_cleanup())
            finally:gate.close()

    def test_root_request_release_is_observed_even_without_a_start_marker(self):
        import pr314_workload_driver as driver
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'probe-requests').mkdir(mode=0o755)
            gate = preparation.PreparationGate('role-boundary', SimpleNamespace(ROOT=root),
                lambda: driver._administrator_collector_epoch('preparation'), 10**30)
            try:
                (root / 'probe-requests/candidate-sender.json').write_text('{}')
                _proof, diagnostics, _terminal = fixture()
                with self.assertRaisesRegex(ValueError, 'probe-release-not-empty'):
                    gate.readiness_failed(diagnostics, {})
            finally:gate.close()

    def test_writable_request_directory_fails_without_leaking_the_pidfd(self):
        import pr314_workload_driver as driver
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'probe-requests').mkdir(mode=0o755)
            (root / 'probe-requests').chmod(0o777)
            count = len(list(Path('/proc/self/fd').iterdir()))
            with self.assertRaisesRegex(ValueError, 'probe-release-not-empty'):
                preparation.PreparationGate('role-boundary', SimpleNamespace(ROOT=root),
                    lambda: driver._administrator_collector_epoch('preparation'), 10**30)
            self.assertEqual(count, len(list(Path('/proc/self/fd').iterdir())))


if __name__ == '__main__':
    unittest.main()
