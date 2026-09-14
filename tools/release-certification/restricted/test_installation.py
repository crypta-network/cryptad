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

    def committed_source(self):
        source = self.root / 'source'
        source.mkdir()
        (source / 'module.py').write_text('VALUE = 1\n')
        for arguments in (['init', '--quiet'], ['add', 'module.py'],
                          ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                           'commit', '--quiet', '-m', 'fixture']):
            subprocess.run(['git', *arguments], cwd=source, check=True, capture_output=True)
        return source

    def test_plan_records_clean_committed_source(self):
        source = self.committed_source()
        output = self.root / 'bundle'
        result = installation.plan(source, output)
        verified = installation.verify_bundle(output, result['bundleIdentity'], protected=False)
        self.assertEqual(result['sourceCommit'], verified['sourceCommit'])
        self.assertEqual(b'VALUE = 1\n', (output / 'module.py').read_bytes())
        self.assertFalse((output / '.git').exists())

    def test_assume_unchanged_substitution_does_not_enter_bundle(self):
        source = self.committed_source()
        subprocess.run(['git', 'update-index', '--assume-unchanged', 'module.py'], cwd=source, check=True)
        (source / 'module.py').write_text('SUBSTITUTED = True\n')
        status = subprocess.run(['git', 'status', '--porcelain'], cwd=source, check=True, capture_output=True)
        self.assertEqual(b'', status.stdout)
        output = self.root / 'bundle'
        installation.plan(source, output)
        self.assertEqual(b'VALUE = 1\n', (output / 'module.py').read_bytes())

    def test_change_after_status_cannot_substitute_bytes_or_executable_mode(self):
        source = self.committed_source()
        original_run = subprocess.run
        def race(arguments, **kwargs):
            result = original_run(arguments, **kwargs)
            if arguments[1] == 'status':
                (source / 'module.py').write_text('SUBSTITUTED = True\n')
                (source / 'module.py').chmod(0o755)
            return result
        output = self.root / 'bundle'
        with patch.object(installation.subprocess, 'run', side_effect=race):
            installation.plan(source, output)
        self.assertEqual(b'VALUE = 1\n', (output / 'module.py').read_bytes())
        self.assertFalse((output / 'module.py').stat().st_mode & 0o111)

    def test_replacement_blob_is_ignored(self):
        source = self.committed_source()
        oid = subprocess.check_output(['git', 'rev-parse', 'HEAD:module.py'], cwd=source).decode().strip()
        replacement = subprocess.check_output(['git', 'hash-object', '-w', '--stdin'],
                                              cwd=source, input=b'SUBSTITUTED = True\n').decode().strip()
        subprocess.run(['git', 'replace', oid, replacement], cwd=source, check=True)
        output = self.root / 'bundle'
        installation.plan(source, output)
        self.assertEqual(b'VALUE = 1\n', (output / 'module.py').read_bytes())

    def test_head_movement_after_revision_capture_does_not_change_export(self):
        source = self.committed_source()
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source).decode().strip()
        original_run = subprocess.run
        def move_head(arguments, **kwargs):
            result = original_run(arguments, **kwargs)
            if arguments[1] == 'rev-parse':
                (source / 'module.py').write_text('NEXT_COMMIT = True\n')
                original_run(['git', 'add', 'module.py'], cwd=source, check=True)
                original_run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                              'commit', '--quiet', '-m', 'concurrent fixture commit'], cwd=source, check=True)
            return result
        output = self.root / 'bundle'
        with patch.object(installation.subprocess, 'run', side_effect=move_head):
            result = installation.plan(source, output)
        self.assertEqual(revision, result['sourceCommit'])
        self.assertEqual(b'VALUE = 1\n', (output / 'module.py').read_bytes())

    def test_committed_symlink_rejected_and_partial_export_removed(self):
        source = self.committed_source()
        (source / 'linked.py').symlink_to('module.py')
        subprocess.run(['git', 'add', 'linked.py'], cwd=source, check=True)
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '--quiet', '-m', 'link fixture'], cwd=source, check=True)
        output = self.root / 'bundle'
        with self.assertRaisesRegex(installation.InstallationError, 'source-entry-invalid'):
            installation.plan(source, output)
        self.assertFalse(output.exists())

    def test_plan_rejects_dirty_source_before_output_creation(self):
        source = self.root / 'source'
        source.mkdir()
        subprocess.run(['git', 'init', '--quiet'], cwd=source, check=True, capture_output=True)
        (source / 'unreviewed.py').write_text('VALUE = 2\n')
        output = self.root / 'bundle'
        with self.assertRaises(installation.InstallationError):
            installation.plan(source, output)
        self.assertFalse(output.exists())


class ProvisioningDependencyTests(unittest.TestCase):
    def test_tls_inventory_detects_certificate_addition_replacement_and_new_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, fallback = root / 'certs', root / 'fallback.pem'
            store.mkdir()
            store.chmod(0o755)
            certificate = store / 'ca.pem'
            certificate.write_bytes(b'original trust')
            certificate.chmod(0o644)
            with patch.object(installation, 'DEPENDENCY_ROOTS', ()), \
                    patch.object(installation, 'DEPENDENCY_FILES', ()), \
                    patch.object(installation, 'TLS_ROOT_PATHS', (str(store), str(fallback))), \
                    patch.object(installation, 'secured', side_effect=lambda path: path):
                # Only ownership is a seam; directory contents and file hashes are real.
                original_lstat = Path.lstat
                def owned(path):
                    info = original_lstat(path)
                    from types import SimpleNamespace
                    return SimpleNamespace(st_uid=0, st_mode=info.st_mode)
                with patch.object(Path, 'lstat', owned):
                    baseline = installation.dependency_inventory()
                    self.assertEqual({'absent': True}, baseline[str(fallback)])
                    certificate.write_bytes(b'replaced trust')
                    self.assertNotEqual(baseline, installation.dependency_inventory())
                    certificate.write_bytes(b'original trust')
                    (store / 'added.pem').write_bytes(b'additional CA')
                    (store / 'added.pem').chmod(0o644)
                    self.assertNotEqual(baseline, installation.dependency_inventory())
                    (store / 'added.pem').unlink()
                    fallback.write_bytes(b'new fallback CA')
                    fallback.chmod(0o644)
                    self.assertNotEqual(baseline, installation.dependency_inventory())

    def test_provisioning_binaries_and_resolved_targets_are_inventoried(self):
        names = ('/usr/bin/systemd-sysusers', '/usr/bin/systemd-tmpfiles')
        self.assertTrue(set(names) <= set(installation.DEPENDENCY_FILES))
        with patch.object(installation, 'DEPENDENCY_ROOTS', ()), \
                patch.object(installation, 'DEPENDENCY_FILES', names):
            records = installation.dependency_inventory()
        for name in names:
            self.assertIn(name, records)
            self.assertIn(str(Path(name).resolve(strict=True)), records)

    def test_each_missing_provisioning_binary_rejects_dependency_approval(self):
        for name in ('/usr/bin/systemd-sysusers', '/usr/bin/systemd-tmpfiles'):
            records = {key: {} for key in installation.DEPENDENCY_FILES if key != name}
            with self.subTest(name=name), self.assertRaisesRegex(installation.InstallationError, 'closure-incomplete'):
                installation.dependencies({'dependencies': records})


class HostAssetTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bundle = self.root / 'current'
        self.targets = []
        for source, target in installation.host_assets(self.bundle):
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(b'approved asset\n')
            installed = self.root / target.relative_to('/')
            installed.parent.mkdir(parents=True, exist_ok=True)
            installed.write_bytes(source.read_bytes())
            self.targets.append((source, installed))
        secured = patch.object(installation, 'secured',
            side_effect=lambda path: self.root / Path(path).relative_to('/'))
        secured.start()
        self.addCleanup(secured.stop)

    def test_exact_installed_assets_pass_verification_and_upgrade_precondition(self):
        installation.verify_host_assets(self.bundle)
        installation.verify_host_assets(self.bundle, upgrading=True)

    def test_modified_or_missing_sysusers_and_tmpfiles_fail_verification(self):
        for source, target in self.targets[:2]:
            with self.subTest(asset=target.name, directory=target.parent.name):
                target.write_bytes(b'unapproved permissions\n')
                with patch.object(installation, 'PREFIX', self.root), \
                        patch.object(installation.subprocess, 'run') as systemctl:
                    with self.assertRaisesRegex(installation.InstallationError, 'host-asset-content-mismatch'):
                        installation.verify_units()
                    systemctl.assert_not_called()
                target.unlink()
                with self.assertRaises(OSError):
                    installation.verify_host_assets(self.bundle)
                target.write_bytes(source.read_bytes())

    def test_changed_bundle_assets_require_administrator_replacement_before_upgrade(self):
        for source, target in self.targets:
            with self.subTest(asset=source.name):
                source.write_bytes(b'new approved definition\n')
                with self.assertRaisesRegex(installation.InstallationError, 'host-asset-replacement-required'):
                    installation.verify_host_assets(self.bundle, upgrading=True)
                target.write_bytes(source.read_bytes())
                installation.verify_host_assets(self.bundle, upgrading=True)


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
