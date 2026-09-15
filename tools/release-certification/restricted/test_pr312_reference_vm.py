"""Offline orchestration contracts; no guest or installed acceptance is inferred."""
from pathlib import Path
import io
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import disposable_integration as integration
import pr312_reference_vm as driver


class ReferenceDriverTest(unittest.TestCase):
    def test_host_key_pin_replacement_cannot_change_opened_source_or_reported_bytes(self):
        import hashlib
        for kind in ('file', 'symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                original, replacement = root / 'original', root / 'replacement'
                original.write_bytes(b'original-host-key-pin\n')
                replacement.write_bytes(b'replacement-host-key-pin\n')
                source = root / 'selected'
                if kind == 'symlink':
                    source.symlink_to(original)
                else:
                    source.write_bytes(original.read_bytes())
                destination = root / 'private-pin'
                copy = driver.shutil.copyfileobj
                def replace_after_open(incoming, outgoing):
                    source.unlink()
                    source.symlink_to(replacement)
                    copy(incoming, outgoing)
                with patch.object(driver.shutil, 'copyfileobj', side_effect=replace_after_open):
                    digest = driver.copy_host_key_pin(source, destination)
                self.assertEqual(replacement.read_bytes(), source.read_bytes())
                self.assertEqual(original.read_bytes(), destination.read_bytes())
                self.assertEqual(hashlib.sha256(destination.read_bytes()).hexdigest(), digest)
                self.assertNotEqual(driver.sha256(source), digest)

    def test_host_key_pin_copy_never_overwrites_existing_private_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, destination = root / 'source', root / 'private-pin'
            source.write_bytes(b'new-pin')
            destination.write_bytes(b'existing-pin')
            with self.assertRaises(FileExistsError):
                driver.copy_host_key_pin(source, destination)
            self.assertEqual(b'existing-pin', destination.read_bytes())

    def test_guest_summary_exports_only_closed_stages_dimensions_and_digest(self):
        report = driver.public_report({'guestSummary': {'failedStage': 'native-cms-owning-consumer',
            'bundleIdentity': 'a' * 64, 'dimensions': ['installed-keyless-fixed-native-probe',
            'PRIVATE-CANARY', {'private': 'canary'}], 'private': 'PRIVATE-CANARY'}})
        self.assertEqual('native-cms-owning-consumer', report['guestFailedStage'])
        self.assertEqual('a' * 64, report['installedBundleIdentity'])
        self.assertEqual(['installed-keyless-fixed-native-probe'], report['completedDimensions'])
        self.assertNotIn('PRIVATE-CANARY', str(report))
        self.assertEqual({}, driver.guest_summary({'failedStage': ['bad'],
            'bundleIdentity': 'PRIVATE-CANARY', 'dimensions': ['bad'] * 129}))

    def test_setup_subprocess_diagnostics_stay_in_bounded_private_sink(self):
        import subprocess
        raw = io.BytesIO()
        integration.private_fixture_failure(integration.BoundedPrivateLog(raw, maximum=1024),
            subprocess.CalledProcessError(1, ['fixed-tool'], stderr=b'PRIVATE-CANARY' * 10000))
        self.assertLessEqual(len(raw.getvalue()), 1024)
        self.assertIn(b'PRIVATE-CANARY', raw.getvalue())

    def test_fixture_resources_use_canonical_bundle_without_moving_test_imports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / 'bundles' / 'exact'
            bundle.mkdir(parents=True)
            current = root / 'current'
            current.symlink_to(bundle, target_is_directory=True)
            fixture = SimpleNamespace(ROOT=root / 'test-kit', __file__=str(root / 'test-kit/test.py'))
            with patch.object(integration, 'INSTALLED', current):
                integration.installed_fixture_resources(fixture)
            self.assertEqual(bundle, fixture.ROOT)
            self.assertFalse(any(path.is_symlink() for path in (fixture.ROOT, *fixture.ROOT.parents)))
            self.assertEqual(str(root / 'test-kit/test.py'), fixture.__file__)

    def test_private_native_fixture_diagnostics_are_bounded_even_for_multibyte_output(self):
        stream = io.BytesIO()
        log = integration.BoundedPrivateLog(stream, maximum=8)
        log.write('\u20ac' * 100)
        log.write('PRIVATE-CANARY')
        log.flush()
        self.assertEqual(8, len(stream.getvalue()))
        self.assertNotIn(b'PRIVATE-CANARY', stream.getvalue())

    def test_diagnostic_classification_discards_raw_paths_tokens_and_multiline_errors(self):
        for error in (OSError('/root/private/secret'), ValueError('TOKEN=canary'),
                      ValueError('restricted-error\nPRIVATE-CANARY'),
                      ValueError('restricted-' + 'x' * 121)):
            with self.subTest(error=type(error).__name__):
                self.assertEqual('restricted-disposable-stage-failed', integration.failure_code(error))
        self.assertEqual('restricted-effective-unit-mismatch',
                         integration.failure_code(ValueError('restricted-effective-unit-mismatch')))

    def test_private_guest_material_cannot_enter_constructed_public_report(self):
        report = driver.public_report({'schemaVersion': 1, 'status': 'failed',
            'stage': 'installed-native-slice', 'rawException': 'PRIVATE-CANARY',
            'guestOutput': 'PRIVATE-CANARY', 'providerToken': 'PRIVATE-CANARY',
            'cpuModel': 'PRIVATE-CANARY', 'accelerator': 'PRIVATE-CANARY',
            'mandatoryIsolationTestSatisfied': True, 'productionAuthorityObserved': True,
            'installedKeylessNativeAcceptanceSatisfied': True})
        self.assertNotIn('PRIVATE-CANARY', str(report))
        self.assertFalse(report['mandatoryIsolationTestSatisfied'])
        self.assertFalse(report['productionAuthorityObserved'])
        self.assertFalse(report['installedKeylessNativeAcceptanceSatisfied'])
        self.assertEqual('qemu64', report['cpuModel'])
        self.assertEqual('tcg,thread=multi', report['accelerator'])

    def test_guest_has_only_restricted_loopback_ssh_and_no_management_or_host_share(self):
        arguments = driver.qemu_arguments(Path('/qemu'), Path('/fresh'), Path('/prepared'),
                                          Path('/seed.iso'), 23112)
        self.assertIn('user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:23112-:22', arguments)
        for forbidden in ('-fsdev', '-virtfs', '-qmp', '-chardev', '-enable-kvm'):
            self.assertNotIn(forbidden, arguments)
        self.assertIn('tcg,thread=multi', arguments)
        self.assertEqual('qemu64', arguments[arguments.index('-cpu') + 1])

    def test_simple_active_service_never_counts_as_bootstrap_readiness(self):
        output = b'Type=simple\nNotifyAccess=none\nActiveState=active\nSubState=running\nMainPID=42\n'
        with patch.object(integration, 'call', side_effect=[b'', output]):
            with self.assertRaisesRegex(ValueError, 'bootstrap-not-ready'):
                integration.bootstrap_readiness()

    def test_notify_completion_requires_running_main_process_and_main_only_notification(self):
        expected = b'Type=notify\nNotifyAccess=main\nActiveState=active\nSubState=running\nMainPID=42\n'
        for output in (expected.replace(b'MainPID=42', b'MainPID=0'),
                       expected.replace(b'NotifyAccess=main', b'NotifyAccess=all'),
                       expected.replace(b'ActiveState=active', b'ActiveState=activating')):
            with self.subTest(output=output), patch.object(integration, 'call', side_effect=[b'', output]):
                with self.assertRaises(ValueError):
                    integration.bootstrap_readiness()
        with patch.object(integration, 'call', side_effect=[b'', expected]):
            self.assertEqual(['installed-production-bootstrap-notify-ready'], integration.bootstrap_readiness())


class PreparedImageIdentityTest(unittest.TestCase):
    def test_nonstandalone_failure_is_reported_before_guest_boot(self):
        import json
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            product = root / 'build/cryptad-dist/lib/cryptad.jar'
            product.parent.mkdir(parents=True)
            product.write_bytes(b'synthetic-product')
            source = root / 'prepared.qcow2'
            source.write_bytes(b'synthetic-overlay')
            args = SimpleNamespace(attempt=root / 'attempt', source=root, qemu_root=root,
                mode='native-slice', development_snapshot=True, product_source_commit='a' * 40,
                prepared_image=source, prepared_image_digest=driver.sha256(source))
            with patch.object(driver, 'command', side_effect=[SimpleNamespace(stdout=b''),
                    SimpleNamespace(stdout=b'a' * 40), SimpleNamespace(stdout=b'b' * 40)]), \
                    patch.object(driver, 'require_standalone_image',
                        side_effect=ValueError('prepared-image-not-standalone')), \
                    patch.object(driver.subprocess, 'Popen') as guest, patch('builtins.print'):
                self.assertEqual(2, driver.run(args))
            guest.assert_not_called()
            report = json.loads((args.attempt / 'stage-report.json').read_text())
            self.assertEqual(3, report['schemaVersion'])
            self.assertEqual('prepared-image-identity', report['stage'])
            self.assertFalse(report['executed'])
            self.assertTrue(report['guestStopped'])
            self.assertFalse(report['installedKeylessNativeAcceptanceSatisfied'])

    def test_rejects_backing_and_external_data_metadata(self):
        import json
        for extra in ({'backing-filename': '/base'}, {'full-backing-filename': '/base'},
                      {'backing-filename-format': 'qcow2'},
                      {'format-specific': {'data': {'data-file': '/external'}}}):
            with self.subTest(extra=extra), patch.object(driver, 'command', return_value=
                    SimpleNamespace(stdout=json.dumps({'format': 'qcow2', **extra}).encode())):
                with self.assertRaisesRegex(ValueError, 'not-standalone'):
                    driver.require_standalone_image(Path('/image'), Path('/qemu-img'), {})

    def test_copy_is_verified_and_detached_from_later_source_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, destination = root / 'source', root / 'copy'
            source.write_bytes(b'expected-image')
            expected = driver.sha256(source)
            with patch.object(driver, 'require_standalone_image') as verify:
                driver.verified_image_copy(source, destination, expected, Path('/qemu-img'), {})
            verify.assert_called_once_with(destination, Path('/qemu-img'), {})
            source.write_bytes(b'replacement')
            self.assertEqual(expected, driver.sha256(destination))
            with patch.object(driver, 'require_standalone_image') as verify:
                with self.assertRaisesRegex(ValueError, 'identity-mismatch'):
                    driver.verified_image_copy(source, root / 'bad', expected, Path('/qemu-img'), {})
            verify.assert_not_called()

    def test_real_backing_substitution_and_flattened_image_independence(self):
        import os
        import shutil
        tool = os.environ.get('PR312_TEST_QEMU_IMG') or shutil.which('qemu-img')
        if not tool:
            self.skipTest('qemu-img unavailable; real storage test not executed')
        environment = dict(os.environ)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base, overlay, flat = root / 'base.raw', root / 'overlay.qcow2', root / 'flat.qcow2'
            original = b'A' * (1024 * 1024)
            base.write_bytes(original)
            driver.command([tool, 'create', '-f', 'qcow2', '-F', 'raw', '-b', str(base),
                            str(overlay)], env=environment, capture_output=True)
            overlay_digest = driver.sha256(overlay)
            import pr312_prepare_reference as prepare
            flat_digest = prepare.flatten_image(overlay, flat, Path(tool), environment,
                lambda arguments, **options: driver.command(arguments, env=environment,
                                                            capture_output=True, **options))
            base.write_bytes(b'B' * len(original))
            self.assertEqual(overlay_digest, driver.sha256(overlay))
            with self.assertRaisesRegex(ValueError, 'not-standalone'):
                driver.verified_image_copy(overlay, root / 'rejected.qcow2', overlay_digest,
                                           Path(tool), environment)
            verified = driver.verified_image_copy(flat, root / 'verified.qcow2', flat_digest,
                                                  Path(tool), environment)
            base.unlink()
            driver.command([tool, 'convert', '-f', 'qcow2', '-O', 'raw', str(verified),
                            str(root / 'guest.raw')], env=environment, capture_output=True)
            self.assertEqual(original, (root / 'guest.raw').read_bytes())
            external = root / 'external.qcow2'
            driver.command([tool, 'create', '-f', 'qcow2', '-o',
                            'data_file=' + str(root / 'external.raw'), str(external), '1M'],
                           env=environment, capture_output=True)
            with self.assertRaisesRegex(ValueError, 'not-standalone'):
                driver.require_standalone_image(external, Path(tool), environment)


if __name__ == '__main__':
    unittest.main()
