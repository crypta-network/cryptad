"""Offline tests of the disposable fixture contract, never kernel acceptance."""
from pathlib import Path
import sys
import json
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import installation
import pr312_native_faults as fixtures

PROTECTED = Path(__file__).resolve().parents[1] / 'protected'
sys.path.insert(0, str(PROTECTED))
import restricted_native


class NativeFixtureTest(unittest.TestCase):
    def test_deadline_before_candidate_marker_cannot_be_counted_as_timeout_attack(self):
        with patch.object(restricted_native, '_read_output', return_value=b''):
            with self.assertRaisesRegex(ValueError, 'attack-not-observed'):
                fixtures.validate_attack_marker(restricted_native, Path('/stage'), 'timeout')
        with patch.object(restricted_native, '_read_output', return_value=b'fixture-mode-started:timeout\n'):
            fixtures.validate_attack_marker(restricted_native, Path('/stage'), 'timeout')

    def test_descendant_requires_marker_after_actual_child_start(self):
        raw = b'fixture-mode-started:descendant\n'
        with patch.object(restricted_native, '_read_output', return_value=raw):
            with self.assertRaisesRegex(ValueError, 'descendant-not-observed'):
                fixtures.validate_attack_marker(restricted_native, Path('/stage'), 'descendant')
        with patch.object(restricted_native, '_read_output', return_value=raw + b'fixture-descendant-started\n'):
            fixtures.validate_attack_marker(restricted_native, Path('/stage'), 'descendant')

    def test_unexpected_output_requires_successful_write_before_roster_denial(self):
        entry = b'fixture-mode-started:unexpected-output\n'
        completed = entry + b'fixture-unexpected-output-written\n'
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            with patch.object(restricted_native, '_read_output', return_value=entry):
                with self.assertRaisesRegex(ValueError, 'output-roster-attack-not-observed'):
                    fixtures.validate_attack_marker(restricted_native, stage, 'unexpected-output')
            with patch.object(restricted_native, '_read_output', side_effect=[completed, b'fixture-pass\n']):
                fixtures.validate_attack_marker(restricted_native, stage, 'unexpected-output')
            # A marker followed by native timeout/failure is not the successful exporter exit
            # needed to isolate the launcher's output-roster rejection.
            (stage / 'output').mkdir()
            (stage / 'output/failure.json').write_text('{"stage":"deadline"}')
            with patch.object(restricted_native, '_read_output', side_effect=[completed, b'fixture-pass\n']):
                with self.assertRaisesRegex(ValueError, 'output-roster-attack-not-observed'):
                    fixtures.validate_attack_marker(restricted_native, stage, 'unexpected-output')

    def test_observer_records_exact_manager_diagnostics_and_fixed_case_contract(self):
        import hashlib
        import pr313_acceptance as acceptance
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            (stage / 'manager.json').write_text(json.dumps({'invocationId': 'a' * 32}))
            rows = []
            stdout, stderr = b'fixture-pass\n', b'fixture-mode-started:positive\n'
            with patch.object(restricted_native, '_read_output', side_effect=[stdout, stderr]), \
                    patch.object(restricted_native, '_manager', return_value={'ActiveState': 'inactive'}), \
                    patch.object(fixtures, '_quiescent'):
                fixtures.emit_observations(restricted_native, stage, ('hostile-setid',), 1, rows.append)
            self.assertEqual('a' * 32, rows[0]['managerInvocationId'])
            self.assertEqual(hashlib.sha256(len(stdout).to_bytes(8, 'big') + stdout + stderr).hexdigest(),
                             rows[0]['attackWitness']['stdoutDigest'])
            self.assertEqual('passed', acceptance.observation_status(rows[0], {}))

    def test_fixture_owner_is_physically_excluded_from_production_export(self):
        name = 'tools/release-certification/restricted/pr312_native_faults.py'
        self.assertIn(name, installation.TEST_SEAMS)
        self.assertFalse(installation.production_member(Path(name)))

    def test_driver_constructs_existing_closed_package_operation(self):
        spec, bindings = restricted_native._spec(fixtures._command(Path('/jdk-source'), Path('/work-source')),
                                                 'package-api')
        self.assertEqual({'operation': 'package-api', 'historicalJars': []}, spec)
        self.assertEqual({'jdk': Path('/jdk-source'), 'work': Path('/work-source')}, bindings)
        command = fixtures._command(Path('/jdk-source'), Path('/work-source'))
        command[-1] = 'untrusted.ArbitraryCommand'
        with self.assertRaises(restricted_native.NativeBoundaryError):
            restricted_native._spec(command, 'package-api')

    def test_openat2_probe_is_compilable_test_source_without_host_execution(self):
        compile(fixtures.OPENAT2_SOURCE, '<synthetic-openat2-probe>', 'exec')

    def test_development_import_cannot_claim_installed_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, 'requires-installed-guest'):
                fixtures.run(Path('/jdk'), Path(temporary) / 'faults', 'a' * 64)
            self.assertFalse((Path(temporary) / 'faults').exists())

    def test_synthetic_revocation_waits_for_exact_active_owned_java_invocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = {'InvocationID': 'b' * 32, 'ControlGroup': restricted_native.CGROUP,
                     'ActiveState': 'active', 'SubState': 'running'}
            native = SimpleNamespace(ROOT=root, CGROUP=restricted_native.CGROUP,
                                     _manager=lambda action: state)
            callback = fixtures._SyntheticRevocation(native, set())
            with patch.object(fixtures, '_owned_java_running', return_value=True) as running:
                callback()
                running.assert_not_called()
                stage = root / ('a' * 64)
                stage.mkdir()
                (stage / 'manager.json').write_text(json.dumps({'invocationId': 'c' * 32}))
                callback()
                self.assertFalse(callback.fired)
                running.assert_not_called()
                (stage / 'manager.json').write_text(json.dumps({'invocationId': 'b' * 32}))
                state['ActiveState'] = 'activating'
                callback()
                running.assert_not_called()
                state['ActiveState'] = 'active'
                running.return_value = False
                callback()
                self.assertFalse(callback.fired)
                running.return_value = True
                with self.assertRaisesRegex(ValueError, '^synthetic-native-revocation$'):
                    callback()
                self.assertTrue(callback.fired)
                self.assertEqual('b' * 32, callback.invocation_id)
                with self.assertRaisesRegex(ValueError, 'called-after-rejection'):
                    callback()

    def test_lost_start_response_calls_real_manager_and_preserves_cleanup_operations(self):
        calls = []
        def manager(action, **kwargs):
            calls.append((action, kwargs))
            if action == 'show':
                return {'InvocationID': 'a' * 32, 'ControlGroup': restricted_native.CGROUP,
                        'ActiveState': 'active'}
        native = SimpleNamespace(_manager=manager, CGROUP=restricted_native.CGROUP)
        transport = fixtures._LostStartResponse(native)
        with self.assertRaisesRegex(ValueError, '^synthetic-native-start-response-lost$'):
            transport('start', timeout=2)
        self.assertTrue(transport.fired)
        self.assertEqual('a' * 32, transport.invocation_id)
        transport('stop', timeout=20)
        self.assertEqual([('start', {'timeout': 2}), ('show', {}), ('stop', {'timeout': 20})], calls)

    def test_fixture_jdk_normalizes_internal_links_and_records_test_only_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'source', root / 'output'
            source.mkdir(); output.mkdir()
            (source / 'notice').write_bytes(b'vendor-notice')
            (source / 'linked-notice').symlink_to('notice')
            staged = fixtures._fixture_jdk(source, output)
            self.assertFalse((staged / 'linked-notice').is_symlink())
            self.assertEqual(b'vendor-notice', (staged / 'linked-notice').read_bytes())
            self.assertEqual('synthetic-reference-normalization-not-production-approval',
                             json.loads((output / 'jdk-identity.json').read_bytes())['provenance'])

    def test_fixture_jdk_rejects_external_links_before_native_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'source', root / 'output'
            source.mkdir(); output.mkdir()
            (root / 'private').write_bytes(b'private')
            (source / 'escape').symlink_to('../private')
            with self.assertRaisesRegex(ValueError, 'jdk-link-escape'):
                fixtures._fixture_jdk(source, output)
            self.assertFalse((output / 'jdk').exists())

    def test_quiescence_requires_no_active_handoff_and_stopped_manager(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(restricted_native, 'ROOT', Path(temporary)), patch.object(
                    restricted_native, '_manager', return_value={'ActiveState': 'active'}):
                with self.assertRaisesRegex(ValueError, 'not-quiescent'):
                    fixtures._quiescent(restricted_native)
            (Path(temporary) / 'active.json').write_text('{}')
            with patch.object(restricted_native, 'ROOT', Path(temporary)), patch.object(
                    restricted_native, '_manager', return_value={'ActiveState': 'inactive'}):
                with self.assertRaisesRegex(ValueError, 'not-quiescent'):
                    fixtures._quiescent(restricted_native)


if __name__ == '__main__':
    unittest.main()
