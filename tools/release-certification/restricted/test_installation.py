"""Offline artifact tests; these deliberately do not claim host isolation execution."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import subprocess
from unittest.mock import Mock, mock_open, patch

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

    def test_historical_manifest_with_test_seam_remains_readable_but_cannot_be_deployed(self):
        (self.root / 'test_legacy.py').write_text('LEGACY = True\n')
        manifest = {**self.manifest, 'files': installation.inventory(self.root)}
        raw = installation.encode(manifest)
        (self.root / installation.MANIFEST).write_bytes(raw)
        verified = installation.verify_bundle(self.root, installation.digest(raw), protected=False)
        self.assertEqual(manifest, verified)
        with self.assertRaisesRegex(installation.InstallationError, 'production-export-policy-required'):
            installation.required_entrypoints(verified)

    def test_current_manifest_cannot_admit_a_declared_test_seam(self):
        for name in sorted(installation.TEST_SEAMS | {'test_hook.py', 'package/tests/helper.py',
                                                       'tools/probe/test/helper.py'}):
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir=self.root) as temporary:
                bundle = Path(temporary)
                member = bundle / name
                member.parent.mkdir(parents=True, exist_ok=True)
                member.write_text('SYNTHETIC_PROVIDER = True\n')
                manifest = {'schemaVersion': 2, 'kind': 'cryptad-restricted-installation',
                            'exportPolicy': installation.EXPORT_POLICY, 'sourceCommit': 'a' * 40,
                            'files': installation.inventory(bundle)}
                raw = installation.encode(manifest)
                (bundle / installation.MANIFEST).write_bytes(raw)
                with self.assertRaisesRegex(installation.InstallationError, 'production-export-policy-required'):
                    installation.verify_bundle(bundle, installation.digest(raw), protected=False)

    def test_current_manifest_rejects_unknown_export_policy(self):
        manifest = {**self.manifest, 'schemaVersion': 2, 'exportPolicy': 'include-test-seams'}
        raw = installation.encode(manifest)
        (self.root / installation.MANIFEST).write_bytes(raw)
        with self.assertRaisesRegex(installation.InstallationError, 'production-export-policy-required'):
            installation.verify_bundle(self.root, installation.digest(raw), protected=False)

    def test_install_and_upgrade_reject_historical_bundle_before_host_mutation(self):
        config = {'bundleIdentity': self.identity}
        for operation in (installation.install, installation.upgrade):
            with self.subTest(operation=operation.__name__), \
                    patch.object(installation.os, 'geteuid', return_value=0), \
                    patch.object(installation, 'configuration', return_value=config), \
                    patch.object(installation, 'dependencies'), \
                    patch.object(installation, 'verify_profile'), \
                    patch.object(installation, 'host_assets') as assets:
                with self.assertRaisesRegex(installation.InstallationError, 'production-export-policy-required'):
                    operation(self.root)
                assets.assert_not_called()

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

    def test_plan_excludes_committed_test_seams_without_changing_selected_blob_bytes(self):
        source = self.committed_source()
        excluded = sorted(installation.TEST_SEAMS | {'test_module.py', 'package/tests/helper.py',
                                                      'tools/example/test/provider.py'})
        resource = 'platform-devtools/src/test/resources/runtime.db'
        for name in [*excluded, resource]:
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'REVIEWED-FIXTURE\x00\xff')
        subprocess.run(['git', 'add', '.'], cwd=source, check=True)
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '--quiet', '-m', 'seam fixtures'], cwd=source, check=True)
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source).decode().strip()
        # A clean-looking working-tree substitution must not enter the selected production blob.
        subprocess.run(['git', 'update-index', '--assume-unchanged', 'module.py'], cwd=source, check=True)
        (source / 'module.py').write_bytes(b'UNREVIEWED')
        output = self.root / 'bundle'
        result = installation.plan(source, output)
        manifest = installation.verify_bundle(output, result['bundleIdentity'], protected=False)
        self.assertEqual(2, manifest['schemaVersion'])
        self.assertEqual(installation.EXPORT_POLICY, manifest['exportPolicy'])
        self.assertEqual(revision, manifest['sourceCommit'])
        self.assertEqual({'module.py', resource}, set(manifest['files']))
        self.assertEqual(b'VALUE = 1\n', (output / 'module.py').read_bytes())
        self.assertEqual(b'REVIEWED-FIXTURE\x00\xff', (output / resource).read_bytes())
        for name in excluded:
            self.assertFalse((output / name).exists(), name)

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
    def setUp(self):
        # These tests select one closure component; unrelated host inputs have separate tests.
        for name, value in (('OPTIONAL_DEPENDENCY_PATHS', ()), ('LIBRARY_ALIASES', {})):
            change = patch.object(installation, name, value)
            change.start()
            self.addCleanup(change.stop)

    def test_native_launcher_interpreter_utilities_and_targets_are_inventoried(self):
        names = ('/usr/bin/sh', '/usr/bin/ls', '/usr/bin/uname', '/usr/bin/xargs',
                 '/usr/bin/echo', '/usr/bin/sed', '/usr/bin/tr')
        self.assertTrue(set(names) <= set(installation.DEPENDENCY_FILES))
        with patch.object(installation, 'DEPENDENCY_ROOTS', ()), \
                patch.object(installation, 'DEPENDENCY_FILES', names), \
                patch.object(installation, 'TLS_ROOT_PATHS', ()):
            records = installation.dependency_inventory()
        for name in names:
            with self.subTest(name=name):
                self.assertIn(name, records)
                target = Path(name).resolve(strict=True)
                self.assertEqual(installation.file_record(target), records[str(target)])

    def test_missing_or_modified_launcher_dependencies_reject_approval(self):
        records = {name: {} for name in installation.DEPENDENCY_FILES}
        records.update({'/usr/lib/python3.13/os.py': {}, '/lib/ld-linux-fixture': {}})
        for name in installation.NATIVE_LAUNCHER_FILES:
            with self.subTest(name=name):
                incomplete = {key: value for key, value in records.items() if key != name}
                with self.assertRaisesRegex(installation.InstallationError, 'closure-incomplete'):
                    installation.dependencies({'dependencies': incomplete})
                changed = {**records, name: {'sha256': 'changed'}}
                with patch.object(installation, 'dependency_inventory', return_value=changed):
                    with self.assertRaisesRegex(installation.InstallationError, 'closure-changed'):
                        installation.dependencies({'dependencies': records})

    def test_openssl_configuration_and_resolved_target_are_required_and_inventoried(self):
        names = ('/usr/lib/ssl/openssl.cnf', '/etc/ssl/openssl.cnf')
        self.assertTrue(set(names) <= set(installation.DEPENDENCY_FILES))
        with patch.object(installation, 'DEPENDENCY_ROOTS', ()), \
                patch.object(installation, 'DEPENDENCY_FILES', names), \
                patch.object(installation, 'TLS_ROOT_PATHS', ()):
            records = installation.dependency_inventory()
        for name in names:
            self.assertIn(name, records)
            self.assertEqual(installation.file_record(Path(name).resolve(strict=True)),
                             records[str(Path(name).resolve(strict=True))])
            incomplete = {key: {} for key in installation.DEPENDENCY_FILES if key != name}
            with self.assertRaisesRegex(installation.InstallationError, 'closure-incomplete'):
                installation.dependencies({'dependencies': incomplete})

    def test_changed_openssl_configuration_identity_rejects_approved_inventory(self):
        records = {key: {} for key in installation.DEPENDENCY_FILES}
        records.update({'/usr/lib/python3.13/os.py': {}, '/lib/ld-linux-fixture': {}})
        changed = {**records, '/etc/ssl/openssl.cnf': {'sha256': 'changed'}}
        with patch.object(installation, 'dependency_inventory', return_value=changed):
            with self.assertRaisesRegex(installation.InstallationError, 'closure-changed'):
                installation.dependencies({'dependencies': records})

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
                patch.object(installation, 'DEPENDENCY_FILES', names), \
                patch.object(installation, 'TLS_ROOT_PATHS', ()):
            records = installation.dependency_inventory()
        for name in names:
            self.assertIn(name, records)
            self.assertIn(str(Path(name).resolve(strict=True)), records)

    def test_each_missing_provisioning_binary_rejects_dependency_approval(self):
        for name in ('/usr/bin/systemd-sysusers', '/usr/bin/systemd-tmpfiles'):
            records = {key: {} for key in installation.DEPENDENCY_FILES if key != name}
            with self.subTest(name=name), self.assertRaisesRegex(installation.InstallationError, 'closure-incomplete'):
                installation.dependencies({'dependencies': records})


class StartupDependencyTests(unittest.TestCase):
    def setUp(self):
        from types import SimpleNamespace
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.plugins = self.root / 'sudo'
        self.plugins.mkdir(mode=0o755)
        self.zip = self.root / 'python313.zip'
        self.config = self.root / 'sudo.conf'
        original_lstat = Path.lstat
        def owned(path):
            info = original_lstat(path)
            return SimpleNamespace(st_uid=0, st_mode=info.st_mode)
        for change in (patch.object(installation, 'DEPENDENCY_ROOTS', (str(self.plugins),)),
                       patch.object(installation, 'DEPENDENCY_FILES', ()),
                       patch.object(installation, 'TLS_ROOT_PATHS', ()),
                       patch.object(installation, 'OPTIONAL_DEPENDENCY_PATHS', (str(self.zip), str(self.config))),
                       patch.object(installation, 'LIBRARY_ALIASES', {}),
                       patch.object(installation, 'secured', side_effect=lambda path: path),
                       patch.object(Path, 'lstat', owned)):
            change.start()
            self.addCleanup(change.stop)

    def write(self, path, raw):
        path.write_bytes(raw)
        path.chmod(0o644)

    def test_zip_absence_addition_and_replacement_change_inventory(self):
        absent = installation.dependency_inventory()
        self.assertEqual({'absent': True}, absent['/etc/ld.so.preload'])
        self.assertEqual({'absent': True}, absent[str(self.zip)])
        self.write(self.zip, b'synthetic zip bytes')
        present = installation.dependency_inventory()
        self.assertNotEqual(absent, present)
        self.assertEqual(installation.file_record(self.zip), present[str(self.zip)])
        self.write(self.zip, b'replacement zip bytes')
        self.assertNotEqual(present, installation.dependency_inventory())

    def test_sudo_plugin_runtime_and_configuration_changes_are_bound(self):
        baseline = installation.dependency_inventory()
        for name in ('sudoers.so', 'libsudo_util.so'):
            path = self.plugins / name
            self.write(path, b'original plugin')
            present = installation.dependency_inventory()
            self.assertNotEqual(baseline, present)
            self.write(path, b'modified plugin')
            self.assertNotEqual(present, installation.dependency_inventory())
        self.assertEqual({'absent': True}, baseline[str(self.config)])
        self.write(self.config, b'Plugin sudoers_policy sudoers.so\n')
        configured = installation.dependency_inventory()
        self.write(self.config, b'changed plugin configuration\n')
        self.assertNotEqual(configured, installation.dependency_inventory())

    def test_polkit_vendor_rule_and_authority_mutations_change_inventory(self):
        vendor = self.root / 'vendor'
        vendor.mkdir(mode=0o755)
        runtime = self.root / 'polkitd'
        self.write(runtime, b'reviewed daemon')
        rule = vendor / '50-default.rules'
        self.write(rule, b'reviewed vendor rule')
        with patch.object(installation, 'DEPENDENCY_ROOTS', (str(vendor),)), \
                patch.object(installation, 'DEPENDENCY_FILES', (str(runtime),)):
            approved = installation.dependency_inventory()
            self.write(rule, b'grant manage-units to runner')
            self.assertNotEqual(approved, installation.dependency_inventory())
            self.write(rule, b'reviewed vendor rule')
            self.assertEqual(approved, installation.dependency_inventory())
            self.write(runtime, b'replacement authority')
            self.assertNotEqual(approved, installation.dependency_inventory())
            self.write(runtime, b'reviewed daemon')
            self.write(vendor / '99-grant.rules', b'new grant')
            self.assertNotEqual(approved, installation.dependency_inventory())

    def test_redirected_library_alias_rejects_before_accepting_target_bytes(self):
        target = self.root / 'lib'
        target.mkdir(mode=0o755)
        alias = self.root / 'alias'
        alias.symlink_to(target)
        with patch.object(installation, 'LIBRARY_ALIASES', {str(alias): str(target)}):
            approved = installation.dependency_inventory()
            self.assertEqual({'link': str(target), 'target': str(target)}, approved[str(alias)])
            self.assertEqual({'directory': True}, approved[str(target)])
            alternate = self.root / 'alternate'
            alternate.mkdir(mode=0o755)
            alias.unlink()
            alias.symlink_to(alternate)
            with self.assertRaisesRegex(installation.InstallationError, 'library-alias-unreviewed'):
                installation.dependency_inventory()


class SudoPolicyDenialTests(unittest.TestCase):
    def test_selected_role_denial_is_bound_to_exact_account(self):
        for user in ('cryptad-soak', 'cryptad-wl-candidate-sender', 'cryptad-wl-candidate-recipient',
                     'cryptad-wl-previous', 'cryptad-wl-relay-no-apps'):
            message = ('User ' + user + ' is not allowed to run sudo on pr311-disposable.\n').encode()
            result = subprocess.CompletedProcess([], 0, message, b'')
            with self.subTest(user=user):
                installation.verify_sudo_denial(result, user=user)
                with self.assertRaises(installation.InstallationError):
                    installation.verify_sudo_denial(result)
                with self.assertRaises(installation.InstallationError):
                    installation.verify_sudo_denial(result, user='cryptad-wl-other')

    def test_expected_account_cannot_be_a_pattern_or_malformed_name(self):
        result = subprocess.CompletedProcess([], 0,
            b'User cryptad-runner is not allowed to run sudo on pr311-disposable.\n', b'')
        for user in ('cryptad-.*', '', None, 'x' * 32, 'cryptad-runner\n'):
            with self.subTest(user=user), self.assertRaises(installation.InstallationError):
                installation.verify_sudo_denial(result, user=user)

    def test_explicit_denial_survives_administrator_listing_exit_status_difference(self):
        message = b'User cryptad-runner is not allowed to run sudo on pr311-disposable.\n'
        for status in (0, 1):
            with self.subTest(status=status):
                installation.verify_sudo_denial(subprocess.CompletedProcess([], status, message, b''))

    def test_success_grants_mixed_output_and_unknown_failures_are_not_denials(self):
        message = b'User cryptad-runner is not allowed to run sudo on pr311-disposable.\n'
        for status, output, error in ((0, b'', b''), (1, b'', message), (2, message, b''),
                (0, message + b'    (ALL) NOPASSWD: ALL\n', b''),
                (0, b'User cryptad-runner may run the following commands\n', b''),
                (0, message, b'sudo: policy error\n'), (0, b'\xff', b''),
                (0, message.replace(b'cryptad-runner', b'other-user'), b'')):
            with self.subTest(status=status, output=output, error=error), \
                    self.assertRaisesRegex(installation.InstallationError, 'sudo-or-policy-unknown'):
                installation.verify_sudo_denial(subprocess.CompletedProcess([], status, output, error))


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


class RoleGroupTests(unittest.TestCase):
    def setUp(self):
        from types import SimpleNamespace
        names = ('cryptad-runner', 'cryptad-native', 'cryptad-workload', 'cryptad-soak')
        self.roles = [SimpleNamespace(pw_name=name, pw_uid=62001 + i, pw_gid=62001 + i)
                      for i, name in enumerate(names)]
        self.groups = {role.pw_name: {role.pw_gid} for role in self.roles}
        self.groups['cryptad-runner'].add(62005)
        self.config = {'runnerUid': 62001, 'runnerGroups': [62001, 62005]}
        ids = {role.pw_name: role.pw_gid for role in self.roles}
        ids['cryptad-control'] = 62005
        group_lookup = patch('grp.getgrnam', side_effect=lambda name: SimpleNamespace(gr_gid=ids[name]))
        memberships = patch.object(installation.os, 'getgrouplist', side_effect=lambda name, gid: list(self.groups[name]))
        for change in (group_lookup, memberships):
            change.start()
            self.addCleanup(change.stop)

    def test_exact_provisioned_groups_pass_for_all_roles(self):
        allowed = installation.verify_role_groups(self.roles, self.config)
        self.assertEqual({role.pw_uid: self.groups[role.pw_name] for role in self.roles}, allowed)

    def test_extra_groups_reject_every_role_including_unknown_host_control_groups(self):
        for role in self.roles:
            for extra in (0, 998, 999, 62005):
                if extra in self.groups[role.pw_name]:
                    continue
                with self.subTest(role=role.pw_name, extra=extra):
                    self.groups[role.pw_name].add(extra)
                    with self.assertRaisesRegex(installation.InstallationError, 'groups-unreviewed'):
                        installation.verify_role_groups(self.roles, self.config)
                    self.groups[role.pw_name].remove(extra)

    def test_nonprovisioned_primary_group_rejects_service_role(self):
        self.roles[-1].pw_gid = 999
        with self.assertRaisesRegex(installation.InstallationError, 'groups-unreviewed'):
            installation.verify_role_groups(self.roles, self.config)

    def test_running_processes_cannot_retain_removed_group_membership(self):
        allowed = installation.verify_role_groups(self.roles, self.config)
        for role in self.roles:
            base = f'Uid:\t{role.pw_uid} {role.pw_uid} {role.pw_uid} {role.pw_uid}\n'
            base += f'Gid:\t{role.pw_gid} {role.pw_gid} {role.pw_gid} {role.pw_gid}\n'
            with patch.object(Path, 'iterdir', return_value=[Path('/proc/123')]):
                with patch.object(Path, 'read_text', return_value=base + f'Groups:\t{role.pw_gid}\n'):
                    installation.verify_role_processes(self.roles, allowed)
                with patch.object(Path, 'read_text', return_value=base + f'Groups:\t{role.pw_gid} 999\n'):
                    with self.assertRaisesRegex(installation.InstallationError, 'process-groups-unreviewed'):
                        installation.verify_role_processes(self.roles, allowed)


class UnitLoadPathTests(unittest.TestCase):
    UNITS = ('cryptad-restricted.service', 'cryptad-restricted-native.service', 'cryptad-restricted.socket', 'cryptad-cross-version-soak.service')

    def verify(self, *, override=None, properties=None, ambient='cap_setuid'):
        def show(arguments, **kwargs):
            unit = arguments[2]
            if arguments[3] == '--property=FragmentPath,DropInPaths':
                values = {'FragmentPath': '/etc/systemd/system/' + unit, 'DropInPaths': ''}
                if properties is not None and unit == properties[0]:
                    values = properties[1]
            else:
                values = {'User': 'root', 'Group': 'root', 'NoNewPrivileges': 'yes',
                    'ProtectSystem': 'strict', 'ProtectHome': 'yes', 'PrivateTmp': 'yes',
                    'PrivateDevices': 'yes', 'LimitCORE': '0',
                    'FragmentPath': '/etc/systemd/system/cryptad-restricted.service',
                    'CapabilityBoundingSet': ' '.join(installation.CONTROLLER_CAPABILITIES),
                    'AmbientCapabilities': ambient, 'Type': 'notify', 'NotifyAccess': 'main',
                    'TimeoutStartUSec': '3min'}
            return subprocess.CompletedProcess(arguments, 0,
                stdout=''.join(key + '=' + value + '\n' for key, value in values.items()).encode())
        with patch.object(installation, 'verify_host_assets'), \
                patch.object(installation, 'verify_native_unit'), \
                patch.object(Path, 'exists', lambda path: str(path) == override), \
                patch.object(installation.subprocess, 'run', side_effect=show):
            installation.verify_units()

    def test_exact_loaded_fragments_without_dropins_pass(self):
        self.verify()

    def test_missing_or_extra_controller_ambient_authority_is_rejected(self):
        for value in ('', 'cap_setuid cap_sys_ptrace', 'cap_setpcap'):
            with self.subTest(value=value), self.assertRaisesRegex(
                    installation.InstallationError, 'effective-unit-mismatch'):
                self.verify(ambient=value)

    def test_persistent_and_runtime_control_overrides_reject_every_unit(self):
        for unit in self.UNITS:
            for directory in ('/etc/systemd/system.control', '/run/systemd/system.control'):
                with self.subTest(unit=unit, directory=directory):
                    with self.assertRaisesRegex(installation.InstallationError, 'dropin-unreviewed'):
                        self.verify(override=directory + '/' + unit + '.d')

    def test_loaded_dropins_wrong_fragments_and_unknown_state_reject_every_unit(self):
        for unit in self.UNITS:
            for values in ({'FragmentPath': '/etc/systemd/system/' + unit,
                            'DropInPaths': '/run/systemd/generator/' + unit + '.d/override.conf'},
                           {'FragmentPath': '/run/systemd/transient/' + unit, 'DropInPaths': ''},
                           {'FragmentPath': '/etc/systemd/system/' + unit}):
                with self.subTest(unit=unit, values=values):
                    with self.assertRaisesRegex(installation.InstallationError, 'load-path-unreviewed'):
                        self.verify(properties=(unit, values))


class ControllerCapabilityTests(unittest.TestCase):
    def test_shipped_unit_retains_only_the_required_controller_capabilities(self):
        unit = Path(__file__).parent / 'systemd/cryptad-restricted.service'
        value = next(line.split('=', 1)[1] for line in unit.read_text().splitlines()
                     if line.startswith('CapabilityBoundingSet='))
        installation.verify_controller_capabilities(value.lower())

    def test_shipped_controller_retains_only_setuid_in_ambient(self):
        unit = Path(__file__).parent / 'systemd/cryptad-restricted.service'
        values = [line for line in unit.read_text().splitlines() if line.startswith('AmbientCapabilities=')]
        self.assertEqual(['AmbientCapabilities=CAP_SETUID'], values)

    def kernel_state(self, **changes):
        fields = {'Name': 'python3', 'Uid': '0 0 0 0', 'Gid': '0 0 0 0', 'NoNewPrivs': '1',
                  'CapEff': '00000000000001eb', 'CapPrm': '00000000000001eb',
                  'CapBnd': '00000000000001eb', 'CapAmb': '0000000000000080',
                  'CapInh': '0000000000000180'}
        fields.update(changes)
        return ''.join(name + ':\t' + value + '\n' for name, value in fields.items()).encode()

    def test_observed_reference_kernel_state_is_accepted(self):
        with patch('builtins.open', mock_open(read_data=self.kernel_state())) as opened:
            installation.verify_controller_process()
        opened.assert_called_once_with('/proc/self/status', 'rb')
        opened().read.assert_called_once_with(65537)

    def test_bounding_only_authority_and_altered_kernel_credentials_are_rejected(self):
        for changes in ({'CapEff': '000000000000016b'}, {'CapPrm': '000000000000016b'},
                {'CapBnd': '00000000002001eb'}, {'CapAmb': '0000000000000000'},
                {'CapInh': '0000000000000080'}, {'Uid': '0 62001 0 0'},
                {'Gid': '0 62001 0 0'}, {'NoNewPrivs': '0'}):
            with self.subTest(changes=changes), \
                    patch('builtins.open', mock_open(read_data=self.kernel_state(**changes))), \
                    self.assertRaisesRegex(installation.InstallationError, 'kernel-state-invalid'):
                installation.verify_controller_process()

    def test_malformed_duplicate_and_oversized_kernel_state_is_rejected(self):
        for raw in (b'', b'x' * 65537, b'\xff', self.kernel_state() + b'Uid: 0 0 0 0\n'):
            with self.subTest(size=len(raw)), patch('builtins.open', mock_open(read_data=raw)), \
                    self.assertRaisesRegex(installation.InstallationError, 'kernel-state-invalid'):
                installation.verify_controller_process()

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
        states = {'cryptad-restricted-native.service': b'ActiveState=inactive\nSubState=dead\nMainPID=0\n',
                  'cryptad-restricted.socket': b'ActiveState=inactive\nSubState=dead\n',
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
        self.assertEqual(run.call_count, 4)

    def test_inactive_socket_without_main_pid_and_stopped_services_are_accepted(self):
        self.check_states()

    def test_listening_or_transitioning_socket_is_rejected(self):
        for output in (b'ActiveState=active\nSubState=listening\n',
                       b'ActiveState=deactivating\nSubState=stop-pre\n', b''):
            with self.subTest(output=output), self.assertRaises(installation.InstallationError):
                self.check_states({'cryptad-restricted.socket': output})

    def test_services_require_inactive_dead_and_zero_main_pid(self):
        for unit in ('cryptad-restricted.service', 'cryptad-restricted-native.service', 'cryptad-cross-version-soak.service'):
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


class PolkitTests(unittest.TestCase):
    def setUp(self):
        from types import SimpleNamespace
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.policy = self.root / 'systemd.policy'
        self.policy.write_text('<policyconfig><action id="org.freedesktop.systemd1.manage-units"/>'
                               '<action id="org.freedesktop.systemd1.manage-unit-files"/></policyconfig>')
        self.runner = SimpleNamespace(pw_uid=62001, pw_gid=62001)
        for change in (patch.object(installation, 'POLKIT_POLICY', self.policy),):
            change.start()
            self.addCleanup(change.stop)

    def probe(self, code, *, readiness=b'R', changed_subject=False, query_error=None):
        import grp
        from types import SimpleNamespace
        authority = subprocess.CompletedProcess([], 0, b'ActiveState=active\nMainPID=123\nExecStart={ path=/usr/lib/polkit-1/polkitd ; }\n')
        process = Mock(pid=4321)
        process.poll.return_value = None
        process.stdout.fileno.return_value = 42
        self.process = process
        self.queries = []
        def dispatch(args, **kwargs):
            if args[0] == '/usr/bin/systemctl':
                return authority
            self.assertEqual('/usr/bin/pkcheck', args[0])
            self.assertEqual(['--process', '4321,12345,62001'], args[1:3])
            self.assertNotIn('--allow-user-interaction', args)
            self.assertLessEqual(kwargs['timeout'], 5)
            self.queries.append(args)
            if query_error:
                raise query_error
            return subprocess.CompletedProcess(args, code)
        subjects = ['4321,12345,62001', '4321,12346,62001'] if changed_subject else None
        with patch.object(installation.os, 'geteuid', return_value=0), \
                patch.object(installation.os, 'getgrouplist', return_value=[62001, 62005]), \
                patch.object(grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=62005)), \
                patch.object(installation.subprocess, 'Popen', return_value=process) as launch, \
                patch.object(installation.subprocess, 'run', side_effect=dispatch), \
                patch.object(installation.select, 'select', return_value=([process.stdout], [], [])), \
                patch.object(installation.os, 'read', return_value=readiness), \
                patch.object(installation, 'polkit_owned_subject', side_effect=subjects,
                             return_value='4321,12345,62001'):
            try:
                installation.verify_polkit(self.runner)
            finally:
                process.stdin.close.assert_called_once_with()
                process.wait.assert_called_once_with(timeout=2)
                process.stdout.close.assert_called_once_with()
                command = launch.call_args.args[0]
                self.assertEqual('/usr/bin/setpriv', command[0])
                self.assertIn('--reuid=62001', command)
                self.assertIn('--groups=62001,62005', command)
                self.assertIn('--bounding-set=-all', command)
                self.assertNotIn('/usr/bin/pkcheck', command)

    def test_authority_denial_and_authentication_required_pass_without_interaction(self):
        for code in (1, 2):
            with self.subTest(code=code):
                self.probe(code)

    def test_grant_and_unknown_authority_responses_reject_activation(self):
        for code in (0, 3, 126, 127):
            with self.subTest(code=code), self.assertRaisesRegex(
                    installation.InstallationError, 'polkit-or-authority-unknown'):
                self.probe(code)

    def test_stopped_or_replaced_authority_rejects(self):
        for output in (b'ActiveState=inactive\nMainPID=0\n', b'ActiveState=active\nMainPID=123\nExecStart={ path=/unreviewed/polkitd ; }\n'):
            with patch.object(installation.os, 'geteuid', return_value=0), \
                    patch.object(installation.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output)), \
                    self.assertRaisesRegex(installation.InstallationError, 'authority-unreviewed'):
                installation.verify_polkit(self.runner)

    def test_readiness_failure_reaps_subject_before_any_query(self):
        with self.assertRaisesRegex(installation.InstallationError, 'polkit-or-authority-unknown'):
            self.probe(2, readiness=b'')
        self.assertEqual([], self.queries)

    def test_changed_subject_is_rejected_before_query(self):
        with self.assertRaisesRegex(installation.InstallationError, 'polkit-or-authority-unknown'):
            self.probe(2, changed_subject=True)
        self.assertEqual([], self.queries)

    def test_query_exception_reaps_subject(self):
        with self.assertRaisesRegex(installation.InstallationError, 'polkit-or-authority-unknown'):
            self.probe(2, query_error=subprocess.TimeoutExpired('pkcheck', 5))

    def test_overall_deadline_rejects_before_queries_and_reaps_subject(self):
        with patch.object(installation.time, 'monotonic', side_effect=[0, 61]), \
                self.assertRaisesRegex(installation.InstallationError, 'polkit-or-authority-unknown'):
            self.probe(2)
        self.assertEqual([], self.queries)

    def test_nonroot_caller_rejected_before_starting_process(self):
        with patch.object(installation.os, 'geteuid', return_value=62001), \
                patch.object(installation.subprocess, 'Popen') as launch, \
                self.assertRaisesRegex(installation.InstallationError, 'trusted-caller-required'):
            installation.verify_polkit(self.runner)
        launch.assert_not_called()

    def subject(self, *, uid=62001, after_ticks='12345', live=True):
        process = Mock(pid=4321)
        process.poll.return_value = None if live else 0
        status = f'Uid: {uid} {uid} {uid} {uid}\nGid: 62001 62001 62001 62001\nGroups: 62001 62005\nNoNewPrivs: 1\n'
        status += ''.join(field + ': 0000000000000000\n' for field in
                          ('CapEff', 'CapPrm', 'CapAmb', 'CapInh', 'CapBnd'))
        def stat(ticks):
            return '4321 (python3) ' + ' '.join(['S', *(['0'] * 18), ticks])
        with patch.object(Path, 'read_text', side_effect=[stat('12345'), status, stat(after_ticks)]):
            return installation.polkit_owned_subject(process, self.runner, {62001, 62005})

    def test_kernel_subject_binds_owned_pid_ticks_and_runner_uid(self):
        self.assertEqual('4321,12345,62001', self.subject())
        for options in ({'uid': 0}, {'after_ticks': '12346'}, {'live': False}):
            with self.subTest(options=options), self.assertRaises(installation.InstallationError):
                self.subject(**options)

    def test_subject_cleanup_escalates_only_owned_process_after_timeout(self):
        process = Mock()
        process.wait.side_effect = [subprocess.TimeoutExpired('subject', 2), 0]
        installation.stop_polkit_subject(process)
        process.kill.assert_called_once_with()
        self.assertEqual(2, process.wait.call_count)
        process.stdout.close.assert_called_once_with()


class ExecutionPublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o755)
        self.public = self.root / 'installation'
        self.public.mkdir(mode=0o755)
        self.private = self.root / 'private-config'
        self.private.mkdir(mode=0o700)
        self.execution = self.public / 'restricted-execution.json'
        self.result = {'bundleIdentity': 'a' * 64, 'sourceCommit': 'b' * 40}
        self.config = {'dependencies': {'fixture': {'sha256': 'c' * 64}}}
        for change in (patch.object(installation, 'EXECUTION', self.execution),
                       patch.object(installation, 'APPROVAL', self.private / 'approval.json'),
                       patch.object(installation, 'secured', side_effect=lambda path: path)):
            change.start()
            self.addCleanup(change.stop)

    def test_publication_preserves_private_directory_and_exact_verification(self):
        installation.publish_execution_identity(self.result, self.config)
        self.assertEqual(0o700, self.private.stat().st_mode & 0o777)
        self.assertEqual(0o444, self.execution.stat().st_mode & 0o777)
        with patch.object(installation, 'verify_bundle', return_value={'sourceCommit': 'b' * 40}), \
                patch.object(installation, 'dependencies', side_effect=installation.InstallationError(
                    'restricted-image-dependency-closure-changed')) as dependencies:
            with self.assertRaisesRegex(installation.InstallationError, 'closure-changed'):
                installation.verify_execution()
        self.assertEqual(self.config['dependencies'], dependencies.call_args.args[0]['dependencies'])

    def test_private_publication_parent_rejects_without_widening_permissions(self):
        self.public.chmod(0o700)
        with self.assertRaisesRegex(installation.InstallationError, 'parent-not-traversable'):
            installation.publish_execution_identity(self.result, self.config)
        self.assertFalse(self.execution.exists())
        self.assertEqual(0o700, self.public.stat().st_mode & 0o777)


class LoaderPreloadTests(unittest.TestCase):
    def test_absence_passes_but_regular_and_dangling_entries_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ld.so.preload'
            installation.require_no_loader_preload(path)
            path.write_bytes(b'loader config')
            with self.assertRaisesRegex(installation.InstallationError, 'preload-unsupported'):
                installation.require_no_loader_preload(path)
            path.unlink()
            target = Path(directory) / 'runner-controlled'
            path.symlink_to(target)
            self.assertFalse(path.exists())
            with self.assertRaisesRegex(installation.InstallationError, 'preload-unsupported'):
                installation.require_no_loader_preload(path)
            target.write_bytes(b'later-created config')
            with self.assertRaisesRegex(installation.InstallationError, 'preload-unsupported'):
                installation.require_no_loader_preload(path)


class RevocationApprovalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.approval = self.root / 'approval.json'
        self.state = self.root / 'state'
        self.state.mkdir()
        self.config = {'schemaVersion': 1, 'bundleIdentity': 'a' * 64, 'dependencies': {},
                       'profile': 'debian13-systemd257-dedicated-v1', 'runnerUid': 62001,
                       'runnerGroups': [62001, 62005], 'revokedVersions': []}
        for change in (patch.object(installation, 'APPROVAL', self.approval),
                       patch.object(installation, 'STATE', self.state),
                       patch.object(installation, 'secured', side_effect=lambda path, **kwargs: path)):
            change.start()
            self.addCleanup(change.stop)

    def save(self):
        self.approval.write_bytes(installation.encode(self.config))

    def test_empty_and_valid_digest_lists_are_accepted(self):
        for value in ([], ['b' * 64], ['b' * 64, '0123456789abcdef' * 4]):
            self.config['revokedVersions'] = value
            self.save()
            self.assertEqual(value, installation.configuration()['revokedVersions'])

    def test_malformed_approval_rejects_before_installation_or_history_write(self):
        for value in ('b' * 64, [None], [True], [1], [{}], [[]], [''], ['b' * 63],
                      ['b' * 65], ['B' * 64], ['g' * 64], ['b' * 64 + '\n']):
            self.config['revokedVersions'] = value
            self.save()
            with self.subTest(value=value), patch.object(installation.os, 'geteuid', return_value=0), \
                    patch.object(installation, 'verify_bundle') as bundle, \
                    self.assertRaisesRegex(installation.InstallationError, 'approval-invalid'):
                installation.install(self.root / 'unexamined-bundle')
            bundle.assert_not_called()
            self.assertFalse((self.state / 'revocations.json').exists())

    def test_malformed_history_rejects_with_closed_diagnostic(self):
        self.save()
        for value in ([{}], ['B' * 64], [None], 'b' * 64):
            (self.state / 'revocations.json').write_bytes(installation.encode(value))
            with self.subTest(value=value), self.assertRaisesRegex(
                    installation.InstallationError, 'security-history-rollback'):
                installation.configuration()

    def test_revoked_current_bundle_and_removed_history_remain_rejected(self):
        self.config['revokedVersions'] = ['a' * 64]
        self.save()
        with self.assertRaisesRegex(installation.InstallationError, 'helper-revoked'):
            installation.configuration()
        self.config['revokedVersions'] = []
        self.save()
        (self.state / 'revocations.json').write_bytes(installation.encode(['b' * 64]))
        with self.assertRaisesRegex(installation.InstallationError, 'security-history-rollback'):
            installation.configuration()


class VersionHistoryCapacityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.versions = self.root / 'versions'
        self.versions.mkdir()
        for number in range(128):
            (self.versions / f'{number:064x}').mkdir()

    def test_existing_version_at_limit_can_be_reused(self):
        installation.require_version_capacity(self.versions, f'{0:064x}')

    def test_last_free_slot_accepts_new_version(self):
        (self.versions / f'{0:064x}').rmdir()
        installation.require_version_capacity(self.versions, 'f' * 64)

    def test_full_and_overfull_history_reject_without_deleting_entries(self):
        with self.assertRaisesRegex(installation.InstallationError, 'version-history-limit'):
            installation.require_version_capacity(self.versions, 'f' * 64)
        (self.versions / '.interrupted-stage').mkdir()
        with self.assertRaisesRegex(installation.InstallationError, 'version-history-limit'):
            installation.require_version_capacity(self.versions, f'{0:064x}')
        self.assertEqual(129, len(list(self.versions.iterdir())))

    def test_upgrade_at_limit_rejects_before_staging_or_mutating_history(self):
        current = self.root / 'current'
        current.mkdir()
        raw = b'previous manifest'
        (current / installation.MANIFEST).write_bytes(raw)
        previous = installation.digest(raw)
        state = self.root / 'state'
        state.mkdir()
        history = state / 'revocations.json'
        history.write_bytes(b'[]')
        config = {'bundleIdentity': 'f' * 64, 'revokedVersions': [previous]}
        with patch.object(installation, 'PREFIX', self.root), \
                patch.object(installation, 'STATE', state), \
                patch.object(installation.os, 'geteuid', return_value=0), \
                patch.object(installation, 'configuration', return_value=config), \
                patch.object(installation, 'dependencies'), \
                patch.object(installation, 'verify_profile'), \
                patch.object(installation, 'verify_bundle'), \
                patch.object(installation, 'required_entrypoints'), \
                patch.object(installation, 'require_stopped_units'), \
                patch.object(installation, 'secured', side_effect=lambda path: path), \
                patch.object(installation.tempfile, 'mkdtemp') as stage, \
                patch.object(installation, 'publish_execution_identity') as publish:
            with self.assertRaisesRegex(installation.InstallationError, 'version-history-limit'):
                installation.upgrade(self.root / 'candidate')
        stage.assert_not_called()
        publish.assert_not_called()
        self.assertEqual(raw, (current / installation.MANIFEST).read_bytes())
        self.assertEqual(b'[]', history.read_bytes())
        self.assertEqual(128, len(list(self.versions.iterdir())))


class NativeUnitProfileTests(unittest.TestCase):
    def test_missing_or_extra_native_authority_never_passes_effective_verification(self):
        # An empty/malformed reply is never equivalent to the selected keyless profile.
        for raw in (b'', b'User=cryptad-native\nNoNewPrivileges=yes\n',
                    b'CapabilityBoundingSet=cap_sys_admin\n',
                    b'User=root\nKillMode=process\n'):
            with self.subTest(raw=raw), patch.object(installation.subprocess, 'run',
                    return_value=subprocess.CompletedProcess([], 0, stdout=raw)):
                with self.assertRaisesRegex(installation.InstallationError, 'native-unit-mismatch'):
                    installation.verify_native_unit()

    def test_query_failure_is_not_native_profile_denial_evidence(self):
        with patch.object(installation.subprocess, 'run',
                side_effect=subprocess.CalledProcessError(1, 'systemctl')):
            with self.assertRaises(subprocess.CalledProcessError):
                installation.verify_native_unit()
