"""Offline preparation contracts; these tests neither boot guests nor provision a host."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import pr312_prepare_reference as prepare


class PreparationTest(unittest.TestCase):
    def test_flatten_failure_cannot_publish_prepared_digest(self):
        import subprocess
        for failure in ('conversion', 'verification'):
            with self.subTest(failure=failure), patch.object(prepare, 'digest') as digest, \
                    patch.object(prepare, 'require_standalone_image',
                        side_effect=ValueError('not-standalone') if failure == 'verification' else None):
                def call(*args, **kwargs):
                    if failure == 'conversion':
                        raise subprocess.CalledProcessError(1, 'qemu-img')
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    prepare.flatten_image(Path('/source'), Path('/prepared'),
                                          Path('/qemu-img'), {}, call)
                digest.assert_not_called()

    def test_preparation_uses_only_fresh_disk_and_loopback_control_without_host_shares(self):
        arguments = prepare.preparation_arguments(Path('/qemu'), Path('/new-attempt'),
            Path('/pinned-original'), Path('/private-seed.iso'), 23112)
        self.assertIn('file=/new-attempt/guest.qcow2,if=virtio,format=qcow2', arguments)
        self.assertNotIn('/pinned-original', arguments)
        self.assertIn('user,id=net0,hostfwd=tcp:127.0.0.1:23112-:22', arguments)
        self.assertIn('-no-user-config', arguments)
        for forbidden in ('-virtfs', '-fsdev', '-qmp', '-chardev', '-enable-kvm'):
            self.assertNotIn(forbidden, arguments)

    def test_ssh_authenticates_generated_guest_host_key_without_ambient_agent(self):
        arguments = prepare.ssh_arguments(Path('/private-attempt'), 23112)
        self.assertEqual('/dev/null', arguments[arguments.index('-F') + 1])
        for option in ('StrictHostKeyChecking=yes', 'ForwardAgent=no', 'ClearAllForwardings=yes',
                       'IdentitiesOnly=yes', 'BatchMode=yes'):
            self.assertIn(option, arguments)
        self.assertEqual('vmadmin@127.0.0.1', arguments[-1])

    def test_cloud_seed_contains_only_ephemeral_guest_access_and_blocks_passwords(self):
        public = 'ssh-ed25519 AAAATEST pr312-reference'
        private = '-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC-NOT-A-KEY\n-----END OPENSSH PRIVATE KEY-----\n'
        config = prepare.cloud_config(public, public, private)
        self.assertIn('ssh_pwauth: false', config)
        self.assertIn('disable_root: true', config)
        self.assertIn('package_upgrade: false', config)
        self.assertIn('    SYNTHETIC-NOT-A-KEY\n', config)
        with self.assertRaises(ValueError):
            prepare.cloud_config(public + '\nmalicious: true', public, private)

    def test_guest_provisioning_checks_actual_environment_and_pinned_tool_versions(self):
        script = prepare.guest_script()
        self.assertLess(script.index('systemd-detect-virt --vm'), script.index('apt-get update'))
        self.assertIn(prepare.JDK_SHA256, script)
        self.assertIn('systemctl start dbus.service polkit.service', script)
        self.assertIn('test ! -e /opt/pr312-jdk', script)
        for package, version in prepare.PACKAGE_PINS.items():
            self.assertIn("dpkg-query -W -f='${Version}' " + package, script)
            self.assertIn('= ' + version, script)

    def test_report_drops_private_keys_logs_paths_and_never_claims_acceptance(self):
        report = prepare.public_report({'schemaVersion': 1, 'status': 'prepared',
            'privateKey': 'PRIVATE-CANARY', 'serialOutput': 'PRIVATE-CANARY', 'path': 'PRIVATE-CANARY',
            'cpuModel': 'PRIVATE-CANARY', 'accelerator': 'PRIVATE-CANARY',
            'installedKeylessNativeAcceptanceSatisfied': True, 'productionAuthorityObserved': True})
        self.assertNotIn('PRIVATE-CANARY', str(report))
        self.assertFalse(report['installedKeylessNativeAcceptanceSatisfied'])
        self.assertFalse(report['productionAuthorityObserved'])
        self.assertFalse(report['mandatoryIsolationTestSatisfied'])
        self.assertEqual('qemu64', report['cpuModel'])
        self.assertEqual('tcg,thread=multi', report['accelerator'])

    def test_bad_image_fails_before_any_guest_or_key_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('image', 'jdk', 'genisoimage'):
                (root / name).write_bytes(b'not-the-pinned-input')
            args = SimpleNamespace(qemu_root=root, image=root / 'image', jdk=root / 'jdk',
                                   seed_tool=root / 'genisoimage', port=23112, output=root / 'attempt')
            with patch.object(prepare.os, 'geteuid', return_value=1000), \
                    patch.object(prepare.subprocess, 'run') as command, \
                    patch.object(prepare.subprocess, 'Popen') as guest, patch('builtins.print'):
                self.assertEqual(2, prepare.run(args))
            command.assert_not_called()
            guest.assert_not_called()
            self.assertTrue((args.output / 'preparation-report.json').exists())

    def test_existing_output_and_qemu_drive_option_injection_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'image,readonly=off'
            source.write_bytes(b'bytes')
            with self.assertRaises(ValueError):
                prepare.checked_path(source)
            with self.assertRaises(FileExistsError):
                prepare.run(SimpleNamespace(output=root))

    def test_host_root_cannot_start_administrative_preparation(self):
        with patch.object(prepare.os, 'geteuid', return_value=0), self.assertRaises(ValueError):
            prepare.validate_inputs(SimpleNamespace())


if __name__ == '__main__':
    unittest.main()
