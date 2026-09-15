"""Bootstrap ordering regressions; these do not model effective systemd execution."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import bootstrap


class BootstrapKernelAdmissionTests(unittest.TestCase):
    def exercise(self, *, rejected=False, installation_rejected=False, diagnostic_rejected=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            relative = 'tools/release-certification/restricted/installation.py'
            verifier = root / relative
            verifier.parent.mkdir(parents=True)
            verifier.write_bytes(b'# exact verifier fixture\n')
            manifest = {'files': {relative: {'sha256': hashlib.sha256(verifier.read_bytes()).hexdigest()}}}
            manifest_bytes = json.dumps(manifest).encode()
            (root / '.restricted-manifest.json').write_bytes(manifest_bytes)
            approval = root / 'approval.json'
            approval.write_text(json.dumps({'bundleIdentity': hashlib.sha256(manifest_bytes).hexdigest()}))
            approval.chmod(0o600)
            events = []
            def kernel():
                events.append('kernel')
                if rejected:
                    raise ValueError('restricted-controller-kernel-state-invalid')
            installation = Mock()
            installation.verify_controller_process.side_effect = kernel
            def verify():
                events.append('installation')
                if installation_rejected:
                    raise ValueError('restricted-installation-rejected')
                return {'bundleIdentity': 'a' * 64}
            installation.verify.side_effect = verify
            worker = Mock()
            def enter_worker(**kwargs):
                self.assertNotIn('NOTIFY_SOCKET', os.environ)
                self.assertNotIn('SECRET_CANARY', os.environ)
                events.append('worker')
                kwargs['ready']()
                with self.assertRaisesRegex(ValueError, 'notification-invalid'):
                    kwargs['ready']()
            worker.main.side_effect = enter_worker
            channel = Mock()
            channel.fileno.return_value = 12
            channel.send.side_effect = lambda raw: (events.append('ready') or len(raw))
            stages = Mock(fd=13)
            if diagnostic_rejected:
                def record(stage, status='entered'):
                    if stage == 'bootstrap-ready':
                        raise OSError('private diagnostic details')
                stages.record.side_effect = record
            with patch.object(bootstrap, 'Stages', return_value=stages), \
                    patch.object(bootstrap, 'notification_channel', return_value=channel), \
                    patch.object(bootstrap, 'ROOT', root), patch.object(bootstrap, 'APPROVAL', approval), \
                    patch.object(bootstrap, 'trusted', side_effect=lambda path: path), \
                    patch.object(sys, 'flags', SimpleNamespace(isolated=True, no_site=True)), \
                    patch.object(sys, 'path', list(sys.path)), patch.object(sys, 'dont_write_bytecode', True), \
                    patch.object(os, 'geteuid', return_value=0), patch.object(os, 'listdir', return_value=['3', '12', '13', '14']), \
                    patch.object(os, 'close') as close_fd, \
                    patch.object(os, 'set_inheritable'), patch.object(os, 'chdir'), \
                    patch.dict(os.environ, {'LISTEN_PID': str(os.getpid()), 'LISTEN_FDS': '1',
                        'NOTIFY_SOCKET': '/run/systemd/notify', 'SECRET_CANARY': 'private'}, clear=True), \
                    patch.dict(sys.modules, {'installation': installation, 'restricted_worker': worker}):
                if diagnostic_rejected:
                    with self.assertRaises(OSError):
                        bootstrap.main()
                    channel.send.assert_not_called()
                elif rejected or installation_rejected:
                    with self.assertRaisesRegex(ValueError, 'kernel-state-invalid|installation-rejected'):
                        bootstrap.main()
                else:
                    bootstrap.main()
            close_fd.assert_called_once_with(14)
            return events, installation, worker

    def test_kernel_authority_precedes_profile_probes_and_worker(self):
        events, _installation, worker = self.exercise()
        self.assertEqual(['kernel', 'installation', 'worker', 'ready'], events)
        self.assertEqual('a' * 64, worker.main.call_args.kwargs['bundle_identity'])
        self.assertTrue(callable(worker.main.call_args.kwargs['ready']))

    def test_missing_kernel_authority_blocks_profile_probes_and_worker(self):
        events, installation, worker = self.exercise(rejected=True)
        self.assertEqual(['kernel'], events)
        installation.verify.assert_not_called()
        worker.main.assert_not_called()


    def test_installation_failure_prevents_owner_initialization_and_readiness(self):
        events, _installation, worker = self.exercise(installation_rejected=True)
        self.assertEqual(['kernel', 'installation'], events)
        worker.main.assert_not_called()


    def test_diagnostic_failure_prevents_readiness_signal(self):
        events, _installation, _worker = self.exercise(diagnostic_rejected=True)
        self.assertEqual(['kernel', 'installation', 'worker'], events)


class BootstrapNotificationTests(unittest.TestCase):
    def test_request_selected_or_abstract_notification_address_is_rejected(self):
        for address in ('@arbitrary', '/tmp/notify', '', '/run/systemd/notify/../notify'):
            with self.subTest(address=address), patch.dict(os.environ, {'NOTIFY_SOCKET': address}):
                with self.assertRaisesRegex(ValueError, 'notification-required'):
                    bootstrap.notification_channel()

    def test_fixed_notification_channel_is_connected_and_not_inherited(self):
        channel = Mock()
        with patch.dict(os.environ, {'NOTIFY_SOCKET': bootstrap.NOTIFY_SOCKET}), \
                patch.object(bootstrap, 'trusted'), \
                patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=0o140777, st_uid=0)), \
                patch.object(bootstrap.socket, 'socket', return_value=channel) as create:
            self.assertIs(channel, bootstrap.notification_channel())
        create.assert_called_once_with(bootstrap.socket.AF_UNIX,
            bootstrap.socket.SOCK_DGRAM | bootstrap.socket.SOCK_CLOEXEC)
        channel.connect.assert_called_once_with('/run/systemd/notify')
        channel.settimeout.assert_called_once_with(5)

    def test_nonroot_notification_socket_is_rejected(self):
        with patch.dict(os.environ, {'NOTIFY_SOCKET': bootstrap.NOTIFY_SOCKET}), \
                patch.object(bootstrap, 'trusted'), \
                patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=0o140777, st_uid=1000)):
            with self.assertRaisesRegex(ValueError, 'notification-untrusted'):
                bootstrap.notification_channel()

    def test_failed_notification_connect_closes_channel(self):
        channel = Mock()
        channel.connect.side_effect = OSError('private details')
        with patch.dict(os.environ, {'NOTIFY_SOCKET': bootstrap.NOTIFY_SOCKET}), \
                patch.object(bootstrap, 'trusted'), \
                patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=0o140777, st_uid=0)), \
                patch.object(bootstrap.socket, 'socket', return_value=channel):
            with self.assertRaises(OSError):
                bootstrap.notification_channel()
        channel.close.assert_called_once()


class BootstrapStageTests(unittest.TestCase):
    def test_attempts_remain_distinct_private_and_allowlisted(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(bootstrap, 'DIAGNOSTICS', Path(temporary) / 'bootstrap'), \
                patch.object(bootstrap, 'trusted'):
            for _ in range(2):
                stages = bootstrap.Stages()
                stages.record('kernel-verification')
                stages.record(stages.stage, 'failed')
                stages.close()
            records = sorted(bootstrap.DIAGNOSTICS.iterdir())
            self.assertEqual(2, len(records))
            for record in records:
                self.assertEqual(0o600, record.stat().st_mode & 0o777)
                rows = [json.loads(line) for line in record.read_text().splitlines()]
                self.assertEqual({'stage': 'kernel-verification', 'status': 'failed'}, rows[-1])
                self.assertLess(record.stat().st_size, 1024)

    def test_exhausted_attempt_capacity_retains_old_history_and_rejects(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(bootstrap, 'DIAGNOSTICS', Path(temporary) / 'bootstrap'), \
                patch.object(bootstrap, 'trusted'), patch.object(bootstrap, 'MAX_BOOTSTRAP_ATTEMPTS', 1):
            stages = bootstrap.Stages()
            stages.close()
            original = {p.name: p.read_bytes() for p in bootstrap.DIAGNOSTICS.iterdir()}
            with self.assertRaisesRegex(ValueError, 'attempt-capacity'):
                bootstrap.Stages()
            self.assertEqual(original, {p.name: p.read_bytes() for p in bootstrap.DIAGNOSTICS.iterdir()})


if __name__ == '__main__':
    unittest.main()
