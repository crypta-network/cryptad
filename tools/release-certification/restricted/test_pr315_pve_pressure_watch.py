"""Offline threshold and process-selection checks for the PVE task watcher."""
import unittest

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
        command = [b'/work/pr315-task/qemu-root/lib64/ld-linux-x86-64.so.2',
                   b'--library-path', b'/work/pr315-task/qemu-root/lib', b'--',
                   attempt + b'/tools/qemu-system-x86_64', b'-name',
                   b'pr312-disposable', b'-drive', attempt + b'/guest.qcow2']
        self.assertTrue(watch._matches_command(command, 101000, 'suite-71'))
        self.assertFalse(watch._matches_command(command, 101001, 'suite-71'))
        self.assertFalse(watch._matches_command(command, 101000, 'suite-72'))
        changed = command.copy()
        changed[4] = b'/usr/bin/qemu-system-x86_64'
        self.assertFalse(watch._matches_command(changed, 101000, 'suite-71'))


if __name__ == '__main__':
    unittest.main()
