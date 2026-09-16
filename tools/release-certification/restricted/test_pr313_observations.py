"""Causal observer contracts; synthetic records do not count as installed observations."""
from pathlib import Path
import hashlib
import json
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import pr313_observations as observations


class ObservationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = {'ActiveState': 'inactive', 'ControlGroup': ''}
        self.native = SimpleNamespace(ROOT=self.root, CGROUP='/pr313-offline-not-created',
            _manager=lambda _: self.state,
            _read_output=lambda path, maximum, allow_empty: path.read_bytes())
        self.enterContext(patch.dict(sys.modules, {'restricted_native': self.native}))

    def stage(self, name, *, operation='package-api', owner='a' * 64, manager='b' * 32, stdout=b'actual stdout', app_id=None):
        stage = self.root / name
        stage.mkdir()
        (stage / 'diagnostics').mkdir()
        (stage / 'diagnostics/stdout').write_bytes(stdout)
        (stage / 'invocation.json').write_text(json.dumps({'invocation': name,
            'owner': {'operationId': owner}, 'spec': {'operation': operation, 'options': {'--app-id': app_id}}}))
        (stage / 'manager.json').write_text(json.dumps({'invocationId': manager,
            'controlGroup': self.native.CGROUP}))
        return stage

    def test_only_new_invocation_and_actual_retained_stdout_are_bound(self):
        stale = self.stage('old', manager='c' * 32, stdout=b'old stdout')
        window = observations.InvocationWindow()
        self.stage('new', stdout=b'new output')
        # Touching the old record cannot make it the observed invocation.
        (stale / 'manager.json').touch()
        binding = window.finish('package-api')
        self.assertEqual('b' * 32, binding['managerInvocationId'])
        self.assertEqual(hashlib.sha256(b'new output').hexdigest(), binding['stdoutDigest'])
        row = observations.completed('package-api', 'package-api', 'owner-validated', binding)
        self.assertEqual(binding['stdoutDigest'], row['attackWitness']['stdoutDigest'])

    def test_no_new_native_or_an_ambiguous_operation_cannot_borrow_old_identity(self):
        self.stage('old')
        window = observations.InvocationWindow()
        with self.assertRaisesRegex(ValueError, 'unobserved'):
            window.finish('package-api')
        self.stage('first')
        self.stage('second')
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            window.finish('package-api')

    def test_cms_group_requires_exact_worker_operation_for_every_created_stage(self):
        window = observations.InvocationWindow()
        self.stage('package')
        self.stage('app', operation='app-projection', owner='d' * 64)
        with self.assertRaisesRegex(ValueError, 'substituted'):
            window.finish('package-api', owner_operation='a' * 64)
        (self.root / 'app/invocation.json').write_text(json.dumps({'invocation': 'app',
            'owner': {'operationId': 'a' * 64}, 'spec': {'operation': 'app-projection'}}))
        binding = window.finish('package-api', owner_operation='a' * 64)
        self.assertEqual('a' * 64, binding['operationId'])
        row = observations.completed('cms-five-member-context', 'maintenance-prepare', 'owner-validated', binding)
        self.assertEqual('b' * 32, row['managerInvocationId'])

    def test_wrong_operation_and_reused_interval_are_rejected(self):
        window = observations.InvocationWindow()
        self.stage('new')
        binding = window.finish('package-api')
        with self.assertRaisesRegex(ValueError, 'operation-substituted'):
            observations.completed('signed-app', 'app-projection', 'owner-validated', binding)
        row = observations.completed('package-api', 'package-api', 'owner-validated', binding)
        row['attackWitness']['startedMonotonicNs'] += 1
        with self.assertRaisesRegex(ValueError, 'interval-substituted'):
            observations.owner(row, binding)

    def test_baseline_does_not_claim_quiescence_with_active_record_or_running_unit(self):
        (self.root / 'active.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'quiescence-unobserved'):
            observations.baseline('bootstrap-ready', {})
        (self.root / 'active.json').unlink()
        self.state['ActiveState'] = 'active'
        with self.assertRaisesRegex(ValueError, 'quiescence-unobserved'):
            observations.quiescent()

    def consumer_stages(self, *, owner='a' * 64, prefix=''):
        manager_base = int(owner[:16], 16) * 16 if not prefix else len(list(self.root.iterdir())) * 16
        self.stage(prefix + 'package', owner=owner, manager=f'{manager_base:032x}')
        apps = ('queue-manager', 'publisher', 'site-publisher', 'profile-publisher',
                'social-inbox', 'feed-reader', 'trust-graph', 'mail-prototype', 'pr305-fixture')
        for index, app in enumerate(apps, 1):
            self.stage(prefix + app, operation='app-projection', app_id=app, owner=owner, manager=f'{manager_base + index:032x}')

    def test_consumer_phase_binds_every_real_stage_and_complete_signed_app_roster(self):
        self.stage('stale-worker', owner='c' * 64)
        window = observations.InvocationWindow()
        self.consumer_stages()
        result = window.consumer_phase('product-admission', 'a' * 64)
        self.assertEqual(10, len(result['invocations']))
        self.assertEqual('a' * 64, result['operationId'])
        self.assertFalse(result['quiescent']['activeRecordPresent'])
        self.assertNotIn('operationId', result['invocations'][0])

    def test_consumer_phase_rejects_missing_signed_app_and_prior_worker_owner(self):
        window = observations.InvocationWindow()
        self.consumer_stages()
        manifest = self.root / 'pr305-fixture/invocation.json'
        original = json.loads(manifest.read_bytes())
        changed = json.loads(manifest.read_bytes())
        changed['spec']['options']['--app-id'] = 'publisher'
        manifest.write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, 'roster-invalid'):
            window.consumer_phase('product-admission', 'a' * 64)
        original['owner']['operationId'] = 'c' * 64
        manifest.write_text(json.dumps(original))
        with self.assertRaisesRegex(ValueError, 'substituted'):
            window.consumer_phase('product-admission', 'a' * 64)

    def test_whole_consumer_phase_cannot_refresh_its_elapsed_budget(self):
        window = observations.InvocationWindow()
        self.consumer_stages()
        with patch.object(observations.time, 'monotonic_ns', return_value=window.started + 900_000_000_001):
            with self.assertRaisesRegex(ValueError, 'budget-expired'):
                window.consumer_phase('original-validation', 'a' * 64)

    def test_three_consumer_windows_each_bind_only_their_own_ten_invocations(self):
        phases = []
        for index, phase in enumerate(('product-admission', 'substituted-validation', 'original-validation')):
            window = observations.InvocationWindow()
            owner = f'{index + 1:064x}'
            self.consumer_stages(owner=owner, prefix=phase + '-')
            phases.append(window.consumer_phase(phase, owner))
        self.assertEqual(3, len({phase['operationId'] for phase in phases}))
        for phase in phases:
            self.assertEqual(1, sum(row['operation'] == 'package-api' for row in phase['invocations']))
            self.assertEqual(9, sum(row['operation'] == 'app-projection' for row in phase['invocations']))
        for first, second in zip(phases, phases[1:]):
            self.assertLess(first['finishedMonotonicNs'], second['startedMonotonicNs'])
