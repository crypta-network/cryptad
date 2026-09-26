"""Offline threshold and process-selection checks for the PVE task watcher."""
import os
import tempfile
import unittest
from pathlib import Path

import pr315_pve_pressure_watch as watch


class PressureWatchTest(unittest.TestCase):
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
