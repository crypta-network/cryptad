"""Native root preparation retries use synthetic original and systemd providers."""
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import cross_version_supervisor_authority as owner
import runtime_baseline_approval as approvals
import runtime_reference_ledger as ledger
from test_runtime_baseline_admission import vector
import test_maintenance_runtime_projection as fixtures


class ReferenceStartTest(unittest.TestCase):
    def setUp(self):
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            self.skipTest('isolated sudo invocation required for root start-intent checks')
        temporary = self.enterContext(tempfile.TemporaryDirectory(dir='/run'))
        self.root = Path(temporary)
        self.authority = self.root / 'authority'
        self.authority.mkdir(mode=0o755)
        self.store = self.root / 'store'
        self.store.mkdir(mode=0o700)
        self.campaign, _, self.policy = vector()
        self.plan = fixtures.MaintenanceRuntimeProjectionTest().scheduler_fixture()[0]
        self.plan['experimentId'] = 'reference-1'
        self.private = {'root': str(self.root / 'experiments/reference-1'), 'runtimePolicy': self.policy}
        self.authorization = {'runtimeReference': self.campaign, 'maxSeconds': 60}
        self.bindings = {'planDigest': owner.digest(self.plan), 'serviceDigest': 'sha256:' + 'a' * 64,
                         'privateConfigDigest': owner.digest(self.private), 'authorizationDigest': owner.digest(self.authorization)}
        self.enterContext(patch.object(owner, 'AUTHORITY', self.authority))
        self.enterContext(patch.object(owner, 'CONFIG', self.authority))
        self.enterContext(patch.object(owner, 'STATE', self.root))
        self.enterContext(patch.object(approvals, 'PRIVATE_STORE', self.store))
        self.enterContext(patch.object(owner, 'selected_inputs', side_effect=lambda: (
            self.plan, self.private, self.authorization, 0, self.bindings)))
        self.enterContext(patch.object(owner, 'run_identity', return_value=self.plan['producer']))
        self.enterContext(patch.object(owner, '_admit_product_rows', return_value=([], None)))
        self.enterContext(patch.object(owner.pwd, 'getpwnam', return_value=SimpleNamespace(pw_gid=0)))
        self.clock = 1000000000
        self.enterContext(patch.object(owner.time, 'monotonic_ns', side_effect=lambda: self.clock))
        self.state = 'stopped'
        self.launched_at = 0
        self.enterContext(patch.object(owner, '_service_state', side_effect=lambda: self.state))
        self.systemd = self.enterContext(patch.object(owner.subprocess, 'run', side_effect=self.systemctl))
        self.selection = owner._runtime_authorization(self.bindings, create=True)
        self.previous = {'schemaVersion': 5, 'operation': 'authorize', 'plan': self.plan,
            'planDigest': owner.digest(self.plan), 'producer': self.plan['producer'],
            'experimentId': self.plan['experimentId'], 'selectionDigest': self.selection,
            'admittedProductsDigest': owner.digest([])}
        self.enterContext(patch.object(owner, 'authenticate_report', side_effect=lambda *args: (self.previous, {'artifactId': 1})))
        owner._atomic(self.authority / 'cross-version-start.json', {}, 0o600)

    def systemctl(self, command, **kwargs):
        if command[1] == 'show':
            return SimpleNamespace(stdout='ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\n'
                f'ExecMainStartTimestampMonotonic={self.launched_at}\n')
        self.state = 'running'
        self.launched_at = self.clock // 1000
        return SimpleNamespace(returncode=0)

    def marker(self):
        return self.store / 'campaigns' / self.campaign['campaignId'] / 'attempt-00.json'

    def test_partial_root_write_resumes_exact_intent_marker_and_deadline(self):
        atomic = owner._atomic
        def fail_after_used(path, value, mode=0o600):
            atomic(path, value, mode)
            if path.name.startswith('used-'):
                raise OSError('synthetic preparation interruption')
        with patch.object(owner, '_atomic', side_effect=fail_after_used):
            with self.assertRaises(OSError):
                owner.control('start')
        marker = self.marker().read_bytes()
        intent = (self.authority / 'runtime-reference-start.json').read_bytes()
        self.clock += 1000000000
        result = owner.control('start')
        self.assertEqual('running', result['serviceState'])
        self.assertEqual(marker, self.marker().read_bytes())
        self.assertEqual(intent, (self.authority / 'activation.json').read_bytes())
        self.assertEqual(intent, (self.authority / 'runtime-reference-start.json').read_bytes())
        starts = sum(call.args[0][1] == 'start' for call in self.systemd.call_args_list)
        owner.control('start')  # Recover a lost start report without another service launch.
        self.assertEqual(starts, sum(call.args[0][1] == 'start' for call in self.systemd.call_args_list))
        with self.assertRaisesRegex(ledger.LedgerError, 'attempt-pending'):
            ledger.begin(self.campaign, 'reference-2', self.policy)

    def test_systemd_failure_before_launch_can_retry_without_new_attempt(self):
        def fail_start(command, **kwargs):
            if command[1] == 'start':
                raise subprocess.CalledProcessError(1, command)
            return self.systemctl(command, **kwargs)
        with patch.object(owner.subprocess, 'run', side_effect=fail_start):
            with self.assertRaises(subprocess.CalledProcessError):
                owner.control('start')
        marker = self.marker().read_bytes()
        activation = (self.authority / 'activation.json').read_bytes()
        self.assertEqual('running', owner.control('start')['serviceState'])
        self.assertEqual(marker, self.marker().read_bytes())
        self.assertEqual(activation, (self.authority / 'activation.json').read_bytes())

    def test_interruption_after_intent_before_marker_is_recoverable(self):
        with patch.object(ledger, 'begin', side_effect=OSError('synthetic ledger interruption')):
            with self.assertRaises(OSError):
                owner.control('start')
        intent = (self.authority / 'runtime-reference-start.json').read_bytes()
        self.assertFalse(self.marker().exists())
        self.clock += 10**9
        owner.control('start')
        self.assertEqual(intent, (self.authority / 'activation.json').read_bytes())
        marker = ledger._read(self.marker())
        self.assertEqual(owner.digest(owner.decode_json(intent)), marker['activationDigest'])

    def test_interruption_after_activation_publication_is_recoverable(self):
        atomic = owner._atomic
        def interrupted(path, value, mode=0o600):
            atomic(path, value, mode)
            if path.name == 'activation.json':
                raise OSError('synthetic activation interruption')
        with patch.object(owner, '_atomic', side_effect=interrupted):
            with self.assertRaises(OSError):
                owner.control('start')
        marker = self.marker().read_bytes()
        activation = (self.authority / 'activation.json').read_bytes()
        owner.control('start')
        self.assertEqual(activation, (self.authority / 'activation.json').read_bytes())
        self.assertEqual(marker, self.marker().read_bytes())

    def test_retry_rejects_another_original_authorization_and_transitioning_unit(self):
        with patch.object(owner, '_write_private_products', side_effect=OSError('synthetic interruption')):
            with self.assertRaises(OSError):
                owner.control('start')
        with patch.object(owner, 'authenticate_report', return_value=(self.previous, {'artifactId': 2})):
            with self.assertRaisesRegex(owner.AuthorityError, 'intent-substituted'):
                owner.control('start')
        with patch.object(owner.subprocess, 'run', return_value=SimpleNamespace(stdout=
                'ActiveState=activating\nSubState=start\nMainPID=0\nControlPID=0\nExecMainStartTimestampMonotonic=0\n')):
            with self.assertRaisesRegex(owner.AuthorityError, 'service-not-unlaunched'):
                owner.control('start')

    def test_changed_record_or_expired_activation_cannot_be_reselected(self):
        with patch.object(owner, '_write_private_products', side_effect=OSError('synthetic interruption')):
            with self.assertRaises(OSError):
                owner.control('start')
        path = self.authority / 'used-1.json'
        raw = path.read_bytes()
        path.write_bytes(raw + b' ')
        with self.assertRaisesRegex(owner.AuthorityError, 'record-substituted'):
            owner.control('start')
        path.write_bytes(raw)
        self.clock += 61 * 10**9
        with self.assertRaisesRegex(owner.AuthorityError, 'lifetime-invalid'):
            owner.control('start')

    def test_previously_launched_stopped_service_cannot_restart_with_deleted_roots(self):
        owner.control('start')
        self.state = 'stopped'
        with self.assertRaisesRegex(owner.AuthorityError, 'service-not-unlaunched'):
            owner.control('start')

    def test_stopped_terminal_recovery_retains_evidence_without_another_launch(self):
        owner.control('start')
        self.state = 'stopped'
        runtime = Path(self.private['root'])
        runtime.mkdir(mode=0o700, parents=True)
        (runtime / 'scheduler-observation').mkdir(mode=0o700)
        (self.root / 'selected').mkdir(mode=0o700)
        _, events, _, _ = fixtures.MaintenanceRuntimeProjectionTest().scheduler_fixture()
        for event in events:
            event['planDigest'] = owner.digest(self.plan)
        fixtures.rechain(events)
        checkpoint = fixtures.checkpoint_for(self.plan, events)
        for name, value in (('plan', self.plan), ('private-config', self.private),
                            ('authorization', self.authorization), ('service-selection', {})):
            owner._atomic(self.root / 'selected' / (name + '.json'), value)
        owner._atomic(runtime / 'checkpoint.json', checkpoint)
        owner._atomic(runtime / 'scheduler-observation/runtime-input-snapshot.json', {'synthetic': True})
        import json
        journal = runtime / 'journal.jsonl'
        journal.write_text(''.join(json.dumps(event) + '\n' for event in events))
        journal.chmod(0o600)
        with patch.object(owner.subprocess, 'run', return_value=SimpleNamespace(stdout=
                'ActiveState=deactivating\nSubState=stop\nMainPID=0\nControlPID=0\nExecMainStartTimestampMonotonic=1000000\n')):
            with self.assertRaisesRegex(owner.AuthorityError, 'service-not-unlaunched'):
                owner.control('start')
        self.assertFalse((self.store / 'observations/reference-1.json').exists())
        starts = sum(call.args[0][1] == 'start' for call in self.systemd.call_args_list)
        report = owner.control('start')
        self.assertEqual('stopped', report['serviceState'])
        self.assertEqual(starts, sum(call.args[0][1] == 'start' for call in self.systemd.call_args_list))
        capsule = ledger._read(self.store / 'observations/reference-1.json')
        self.assertEqual(events, capsule['events'])
        self.assertEqual(checkpoint, capsule['checkpoint'])


if __name__ == '__main__':
    unittest.main()
