"""Offline contracts for a test-only hostile output fixture; no VM acceptance inferred."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import pr312_output_faults as fixture

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protected'))
import restricted_native as native


class OutputFixtureTest(unittest.TestCase):
    def test_exporter_is_fixed_compilable_source(self):
        compile(fixture.EXPORTER, '<synthetic-output-exporter>', 'exec')

    def test_command_uses_existing_closed_app_operation_without_new_production_switch(self):
        command = fixture._command(Path('/jdk'), Path('/tools'), Path('/work'), Path('/inputs'))
        spec, bindings = native._spec(command, 'app-projection')
        self.assertEqual('app-projection', spec['operation'])
        self.assertEqual('/tools/bin/crypta-app', spec['exporter'])
        self.assertEqual({'jdk', 'tools', 'work', 'inputs'}, set(bindings))
        command[-1] = '/work/arbitrary-output.json'
        with self.assertRaises(ValueError):
            native._spec(command, 'app-projection')

    def test_repository_import_cannot_claim_installed_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'fixture'
            with self.assertRaisesRegex(ValueError, 'requires-installed-guest'):
                fixture.run(target, 'a' * 64)
            self.assertFalse(target.exists())

    def test_setup_rejection_without_actual_attack_marker_is_not_hostile_acceptance(self):
        with patch.object(native, '_read_output', return_value=b''), self.assertRaisesRegex(
                ValueError, 'attack-not-observed'):
            fixture._validate_observation(native, 'fifo', Path('/stage'), Path('/work'), True, b'')

    def test_timeout_requires_actual_child_marker_and_deadline_record(self):
        stage = Path('/stage')
        for raw, failure in ((b'fixture-output-ready:race-timeout\n', b'{}'),
                (b'fixture-output-ready:race-timeout\nfixture-race-active\n',
                 b'{"invocation":"stage","stage":"native-failed"}')):
            with self.subTest(raw=raw), patch.object(native, '_read_output', side_effect=[raw, failure]), \
                    self.assertRaises(ValueError):
                fixture._validate_observation(native, 'race-timeout', stage, Path('/work'), True, b'')

    def test_hostile_regular_result_cannot_substitute_for_expected_rejection(self):
        with patch.object(native, '_read_output', return_value=b'fixture-output-ready:symlink\n'), \
                self.assertRaisesRegex(ValueError, 'hostile-output-accepted'):
            fixture._validate_observation(native, 'symlink', Path('/stage'), Path('/work'), False, b'{}')

    def test_control_checks_exact_untrusted_bytes_without_minting_app_authority(self):
        with patch.object(native, '_read_output', side_effect=[fixture.CONTROL_STDOUT, fixture.CONTROL_BYTES]):
            fixture._validate_observation(native, 'control', Path('/stage'), Path('/work'), False,
                                           fixture.CONTROL_STDOUT)
        with patch.object(native, '_read_output', side_effect=[fixture.CONTROL_STDOUT, b'{"accepted":true}']), \
                self.assertRaises(ValueError):
            fixture._validate_observation(native, 'control', Path('/stage'), Path('/work'), False,
                                           fixture.CONTROL_STDOUT)

    def test_control_without_observed_device_denial_cannot_claim_success(self):
        with patch.object(native, '_read_output', return_value=b'fixture-output-ready:control\n'), \
                self.assertRaisesRegex(ValueError, 'control-unavailable'):
            fixture._validate_observation(native, 'control', Path('/stage'), Path('/work'), False,
                                           fixture.CONTROL_STDOUT)

    def test_remaining_active_invocation_prevents_quiescence_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'active.json').write_text('{}')
            with patch.object(native, 'ROOT', root), patch.object(native, '_manager',
                    return_value={'ActiveState': 'inactive', 'ControlGroup': ''}), self.assertRaises(ValueError):
                fixture._quiescent(native)


if __name__ == '__main__':
    unittest.main()
