"""Offline artifact tests; these deliberately do not claim host isolation execution."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import subprocess
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('installation', Path(__file__).with_name('installation.py'))
installation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installation)


class InstallationArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'module.py').write_text('VALUE = 1\n')
        self.manifest = {'schemaVersion': 1, 'kind': 'cryptad-restricted-installation',
                         'sourceCommit': 'a' * 40, 'files': installation.inventory(self.root)}
        self.raw = installation.encode(self.manifest)
        (self.root / installation.MANIFEST).write_bytes(self.raw)
        self.identity = installation.digest(self.raw)

    def test_exact_bundle_survives_verification(self):
        result = installation.verify_bundle(self.root, self.identity, protected=False)
        self.assertEqual(self.manifest, result)

    def test_modified_import_is_rejected(self):
        (self.root / 'module.py').write_text('VALUE = 2\n')
        with self.assertRaises(installation.InstallationError):
            installation.verify_bundle(self.root, self.identity, protected=False)

    def test_unlisted_import_hook_is_rejected(self):
        (self.root / 'sitecustomize.py').write_text('raise RuntimeError()\n')
        with self.assertRaises(installation.InstallationError):
            installation.verify_bundle(self.root, self.identity, protected=False)

    def test_symlinked_dependency_is_rejected(self):
        (self.root / 'redirect.py').symlink_to(self.root / 'module.py')
        with self.assertRaises(OSError):
            installation.inventory(self.root)

    def test_symlink_directory_is_rejected(self):
        (self.root / 'linked').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(installation.InstallationError):
            installation.inventory(self.root)

    def test_manifest_replacement_does_not_change_approved_identity(self):
        changed = {**self.manifest, 'sourceCommit': 'b' * 40}
        (self.root / installation.MANIFEST).write_bytes(installation.encode(changed))
        with self.assertRaises(installation.InstallationError):
            installation.verify_bundle(self.root, self.identity, protected=False)

    def test_duplicate_json_members_rejected(self):
        path = self.root / 'duplicate.json'
        path.write_text('{"schemaVersion":1,"schemaVersion":2}')
        with self.assertRaises(installation.InstallationError):
            installation.read_json(path)

    def test_nonregular_bundle_member_rejected_without_blocking(self):
        import os
        os.mkfifo(self.root / 'fifo')
        with self.assertRaises(installation.InstallationError):
            installation.inventory(self.root)

    def test_plan_records_clean_committed_source(self):
        source = self.root / 'source'
        source.mkdir()
        (source / 'module.py').write_text('VALUE = 1\n')
        for arguments in (['init', '--quiet'], ['add', 'module.py'],
                          ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                           'commit', '--quiet', '-m', 'fixture']):
            subprocess.run(['git', *arguments], cwd=source, check=True, capture_output=True)
        output = self.root / 'bundle'
        result = installation.plan(source, output)
        verified = installation.verify_bundle(output, result['bundleIdentity'], protected=False)
        self.assertEqual(result['sourceCommit'], verified['sourceCommit'])
        self.assertEqual(b'VALUE = 1\n', (output / 'module.py').read_bytes())
        self.assertFalse((output / '.git').exists())

    def test_plan_rejects_dirty_source_before_output_creation(self):
        source = self.root / 'source'
        source.mkdir()
        subprocess.run(['git', 'init', '--quiet'], cwd=source, check=True, capture_output=True)
        (source / 'unreviewed.py').write_text('VALUE = 2\n')
        output = self.root / 'bundle'
        with self.assertRaises(installation.InstallationError):
            installation.plan(source, output)
        self.assertFalse(output.exists())


class ControllerCapabilityTests(unittest.TestCase):
    def test_shipped_unit_retains_only_the_required_controller_capabilities(self):
        unit = Path(__file__).parent / 'systemd/cryptad-restricted.service'
        value = next(line.split('=', 1)[1] for line in unit.read_text().splitlines()
                     if line.startswith('CapabilityBoundingSet='))
        installation.verify_controller_capabilities(value.lower())

    def test_missing_cleanup_capability_rejects_activation(self):
        value = ' '.join(installation.CONTROLLER_CAPABILITIES - {'cap_kill'})
        with self.assertRaises(installation.InstallationError):
            installation.verify_controller_capabilities(value)

    def test_unknown_or_extra_capabilities_reject_activation(self):
        for value in (None, '', ' '.join(installation.CONTROLLER_CAPABILITIES | {'cap_sys_ptrace'})):
            with self.subTest(value=value), self.assertRaises(installation.InstallationError):
                installation.verify_controller_capabilities(value)


class UpgradeShutdownTests(unittest.TestCase):
    def check_states(self, replacements=None):
        states = {'cryptad-restricted.socket': b'ActiveState=inactive\nSubState=dead\n',
                  'cryptad-restricted.service': b'ActiveState=inactive\nSubState=dead\nMainPID=0\n',
                  'cryptad-cross-version-soak.service': b'ActiveState=inactive\nSubState=dead\nMainPID=0\n'}
        states.update(replacements or {})
        def show(arguments, **kwargs):
            unit = arguments[2]
            properties = arguments[3]
            self.assertEqual('MainPID' in properties, unit.endswith('.service'))
            return subprocess.CompletedProcess(arguments, 0, stdout=states[unit])
        with patch.object(installation.subprocess, 'run', side_effect=show) as run:
            installation.require_stopped_units({'PATH': '/usr/bin:/bin', 'LANG': 'C'})
        self.assertEqual(run.call_count, 3)

    def test_inactive_socket_without_main_pid_and_stopped_services_are_accepted(self):
        self.check_states()

    def test_listening_or_transitioning_socket_is_rejected(self):
        for output in (b'ActiveState=active\nSubState=listening\n',
                       b'ActiveState=deactivating\nSubState=stop-pre\n', b''):
            with self.subTest(output=output), self.assertRaises(installation.InstallationError):
                self.check_states({'cryptad-restricted.socket': output})

    def test_services_require_inactive_dead_and_zero_main_pid(self):
        for unit in ('cryptad-restricted.service', 'cryptad-cross-version-soak.service'):
            for output in (b'ActiveState=inactive\nSubState=dead\nMainPID=123\n',
                           b'ActiveState=inactive\nSubState=dead\n',
                           b'ActiveState=active\nSubState=running\nMainPID=0\n'):
                with self.subTest(unit=unit, output=output), self.assertRaises(installation.InstallationError):
                    self.check_states({unit: output})

    def test_systemctl_failure_is_not_treated_as_stopped(self):
        with patch.object(installation.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'systemctl')):
            with self.assertRaises(subprocess.CalledProcessError):
                installation.require_stopped_units({})


if __name__ == '__main__':
    unittest.main()
