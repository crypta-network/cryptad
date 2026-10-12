"""Offline threshold and process-selection checks for the PVE task watcher."""
import os
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pr315_pve_pressure_watch as watch


class PressureWatchTest(unittest.TestCase):
    def test_prelaunch_grace_closes_only_an_unseen_qemu(self):
        self.assertFalse(watch.prelaunch_expired(10, False, 39.999))
        self.assertTrue(watch.prelaunch_expired(10, False, 40))
        self.assertFalse(watch.prelaunch_expired(10, True, 1000))

    def test_receipt_is_complete_and_readable_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / 'suite-111.finished.json'
            value = {'kind': 'pr315-pve-watch-finished', 'suite': 'suite-111'}
            original_link = os.link

            def inspect_publication(pending, target, **options):
                self.assertFalse(receipt.exists())
                self.assertEqual(receipt, target)
                self.assertEqual(value, json.loads(pending.read_bytes()))
                self.assertEqual(0o444, pending.stat().st_mode & 0o777)
                original_link(pending, target, **options)

            with patch.object(watch.os, 'link', side_effect=inspect_publication):
                watch._write_once(receipt, value, 0o444)
            self.assertEqual(value, json.loads(receipt.read_bytes()))
            self.assertEqual(1, receipt.stat().st_nlink)
            self.assertFalse(receipt.with_name(receipt.name + '.pending').exists())

    def test_existing_receipt_cannot_be_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / 'suite-111.finished.json'
            receipt.write_bytes(b'original')
            with self.assertRaises(FileExistsError):
                watch._write_once(receipt, {'kind': 'replacement'}, 0o444)
            self.assertEqual(b'original', receipt.read_bytes())
            pending = receipt.with_name(receipt.name + '.pending')
            self.assertEqual({'kind': 'replacement'}, json.loads(pending.read_bytes()))

    def test_interrupted_write_never_publishes_partial_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / 'suite-111.finished.json'

            def interrupt(_value, stream, **_options):
                stream.write('{"incomplete":')
                raise ValueError('interrupted-publication')

            with patch.object(watch.json, 'dump', side_effect=interrupt), \
                    self.assertRaisesRegex(ValueError, 'interrupted-publication'):
                watch._write_once(receipt, {'kind': 'receipt'}, 0o444)
            self.assertFalse(receipt.exists())
            pending = receipt.with_name(receipt.name + '.pending')
            self.assertEqual(b'{"incomplete":', pending.read_bytes())
            self.assertEqual(0o600, pending.stat().st_mode & 0o777)

    def test_prelaunch_ready_wait_handles_publication_then_fails_closed(self):
        ready = {'suite': 'suite-111', 'kind': 'pr315-pve-watch-ready'}
        with patch.object(watch, 'verify_ready', side_effect=[FileNotFoundError(),
                PermissionError(), ValueError('partial'), ready]) as verify, \
                patch.object(watch.time, 'sleep'):
            self.assertEqual(ready, watch.wait_ready('suite-111', 'a' * 40))
        self.assertEqual(4, verify.call_count)
        with patch.object(watch, 'verify_ready', side_effect=ValueError('malformed')), \
                patch.object(watch.time, 'monotonic', side_effect=[0, 5]):
            with self.assertRaisesRegex(ValueError, 'ready-unavailable'):
                watch.wait_ready('suite-111', 'a' * 40)

    def test_launch_ready_requires_headroom_and_no_finished_receipt(self):
        ready = {'observedMonotonicNs': 100}
        maximum_age = (watch.PRELAUNCH_SECONDS -
                       watch.LAUNCH_HEADROOM_SECONDS) * 1_000_000_000
        with patch.object(watch, 'verify_ready', return_value=ready), \
                patch.object(watch.time, 'monotonic_ns',
                             return_value=100 + maximum_age), \
                patch.object(watch, '_ct_record',
                             side_effect=FileNotFoundError()):
            self.assertEqual(ready, watch.verify_launch_ready(
                'suite-111', 'a' * 40))
        with patch.object(watch, 'verify_ready', return_value=ready), \
                patch.object(watch.time, 'monotonic_ns',
                             return_value=101 + maximum_age), \
                self.assertRaisesRegex(ValueError, 'launch-ready-expired'):
            watch.verify_launch_ready('suite-111', 'a' * 40)
        with patch.object(watch, 'verify_ready', return_value=ready), \
                patch.object(watch.time, 'monotonic_ns', return_value=100), \
                patch.object(watch, '_ct_record', return_value={}), \
                self.assertRaisesRegex(ValueError, 'launch-already-finished'):
            watch.verify_launch_ready('suite-111', 'a' * 40)

    def test_prelaunch_stop_requires_matching_ready_and_no_qemu(self):
        source = 'a' * 40
        ready = {'schemaVersion': 1, 'kind': 'pr315-pve-watch-ready',
                 'suite': 'suite-111', 'sourceCommit': source,
                 'moduleDigest': 'b' * 64, 'observedMonotonicNs': 100}
        finished = {'schemaVersion': 1, 'kind': 'pr315-pve-watch-finished',
                    'suite': 'suite-111', 'sourceCommit': source,
                    'moduleDigest': 'b' * 64,
                    'action': 'stopped-before-launch',
                    'seenTaskQemu': False, 'finishedMonotonicNs': 101}
        def record(_path, _suite, kind):
            return ready if kind == 'pr315-pve-watch-ready' else finished

        with patch.object(watch, '_ct_record', side_effect=record):
            self.assertEqual(finished, watch.verify_stopped_before_launch(
                'suite-111', source, ready))
            with self.assertRaisesRegex(ValueError, 'ready-changed'):
                watch.verify_stopped_before_launch('suite-111', source,
                    {'observedMonotonicNs': 99})
            for changed in ({'seenTaskQemu': True},
                            {'action': 'completed'},
                            {'finishedMonotonicNs': 100}):
                with patch.object(watch, '_ct_record',
                    side_effect=lambda _path, _suite, kind: ready if kind ==
                    'pr315-pve-watch-ready' else {**finished, **changed}), \
                        self.assertRaisesRegex(ValueError,
                                               'prelaunch-stop-invalid'):
                    watch.verify_stopped_before_launch(
                        'suite-111', source, ready)

    def test_sustained_physical_and_swap_thresholds(self):
        counters = dict.fromkeys(watch.LIMITS, 0)
        observed = {'memAvailableBytes': watch.GIB - 1,
                    'swapFreeBytes': 3 * watch.GIB,
                    'memoryFullAvg10Pct': 0.0, 'ioFullAvg10Pct': 0.0}
        for _ in range(4):
            counters, reason = watch.step(counters, observed)
            self.assertIsNone(reason)
        counters, reason = watch.step(counters, observed)
        self.assertEqual('physical', reason)
        observed['memAvailableBytes'] = watch.GIB
        observed['swapFreeBytes'] = 2 * watch.GIB - 1
        counters, reason = watch.step(counters, observed)
        self.assertIsNone(reason)
        self.assertEqual(0, counters['physical'])
        _, reason = watch.step(counters, observed)
        self.assertEqual('swap', reason)

    def test_pid_match_requires_task_loader_executable_and_uid(self):
        attempt = b'/work/pr315-task/suite-71/attempt-01'
        library = attempt + b'/boot-runtime/usr/lib/x86_64-linux-gnu'
        command = [library + b'/ld-linux-x86-64.so.2', b'--inhibit-cache',
                   b'--library-path', library,
                   attempt + b'/tools/qemu-system-x86_64', b'-name',
                   b'pr312-disposable', b'-drive',
                   b'file=' + attempt + b'/guest.qcow2,if=virtio,format=qcow2']
        self.assertTrue(watch._matches_command(command, 101000, 'suite-71'))
        self.assertFalse(watch._matches_command(command, 101001, 'suite-71'))
        self.assertFalse(watch._matches_command(command, 101000, 'suite-72'))
        changed = command.copy()
        changed[4] = b'/usr/bin/qemu-system-x86_64'
        self.assertFalse(watch._matches_command(changed, 101000, 'suite-71'))
        changed = command.copy()
        changed[3] = b'/usr/lib'
        self.assertFalse(watch._matches_command(changed, 101000, 'suite-71'))
        changed = command.copy()
        changed[-1] = b'file=/other/guest.qcow2,if=virtio,format=qcow2'
        self.assertFalse(watch._matches_command(changed, 101000, 'suite-71'))

    def test_loader_inode_must_match_actual_kernel_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            loader = root / 'ld-linux-x86-64.so.2'
            other = root / 'other-loader'
            loader.write_bytes(b'loader')
            other.write_bytes(b'other')
            loader.chmod(0o500)
            link = root / 'exe'
            link.symlink_to(loader)
            self.assertTrue(watch._loader_matches_process(link, loader, os.geteuid()))
            link.unlink()
            link.symlink_to(other)
            self.assertFalse(watch._loader_matches_process(link, loader, os.geteuid()))


if __name__ == '__main__':
    unittest.main()
