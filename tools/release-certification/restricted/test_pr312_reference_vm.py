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


if __name__ == '__main__':
    unittest.main()
