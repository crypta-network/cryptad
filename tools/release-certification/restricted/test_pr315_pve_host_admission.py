"""Boundary checks for the prospective CT102 PVE TCG admission policy."""
import copy
from pathlib import Path
import tempfile
import unittest

import pr315_pve_host_admission as admission


class PveHostAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.observed = {
            'policy': admission.POLICY, 'observedMonotonicNs': 123,
            'hostAvailableBytes': 6 * admission.GIB,
            'hostSwapFreeBytes': 4 * admission.GIB,
            'memoryFullAvg10Pct': 5.0, 'ioFullAvg10Pct': 10.0,
            'ctMemoryMaxBytes': 10 * admission.GIB,
            'ctMemoryCurrentBytes': 4 * admission.GIB,
            'ctSwapMaxBytes': 12 * admission.GIB,
            'ctSwapCurrentBytes': 10 * admission.GIB,
        }

    def test_swap_covers_shortfall_after_physical_reserve_at_exact_reserves(self):
        self.assertIsNone(admission.admission_reason(self.observed))
        for key, expected in (
                ('hostSwapFreeBytes', 'pve-admission-host-swap-unavailable'),
                ('ctSwapMaxBytes', 'pve-admission-ct-swap-unavailable'),
                ('ctMemoryMaxBytes', 'pve-admission-ct-memory-unavailable')):
            changed = copy.deepcopy(self.observed)
            changed[key] -= 1
            self.assertEqual(expected, admission.admission_reason(changed))

    def test_seven_gib_available_still_requires_one_gib_swap_besides_swap_reserve(self):
        observed = dict(self.observed, hostAvailableBytes=7 * admission.GIB,
                        hostSwapFreeBytes=3 * admission.GIB,
                        ctSwapCurrentBytes=11 * admission.GIB)
        self.assertIsNone(admission.admission_reason(observed))
        self.assertEqual('pve-admission-host-swap-unavailable', admission.admission_reason(
            dict(observed, hostSwapFreeBytes=3 * admission.GIB - 1)))
        self.assertEqual('pve-admission-ct-swap-unavailable', admission.admission_reason(
            dict(observed, ctSwapCurrentBytes=11 * admission.GIB + 1)))

    def test_physical_reserve_and_pressure_cannot_be_replaced_by_swap(self):
        changed = dict(self.observed, hostAvailableBytes=admission.GIB - 1,
                       hostSwapFreeBytes=20 * admission.GIB)
        self.assertEqual('pve-admission-physical-reserve-unavailable',
                         admission.admission_reason(changed))
        for key, amount in (('memoryFullAvg10Pct', 5.01), ('ioFullAvg10Pct', 10.01)):
            changed = dict(self.observed, **{key: amount})
            self.assertEqual('pve-admission-pressure-high', admission.admission_reason(changed))
        self.assertEqual('pve-admission-observation-invalid',
                         admission.admission_reason(dict(self.observed, memoryFullAvg10Pct=float('nan'))))

    def test_snapshot_reads_host_and_real_container_limit_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cgroup = root / 'lxc/102'
            pressure = root / 'pressure'
            cgroup.mkdir(parents=True)
            pressure.mkdir()
            (root / 'meminfo').write_text('MemAvailable: 6291456 kB\nSwapFree: 4194304 kB\n')
            (pressure / 'memory').write_text('some avg10=2.00\nfull avg10=5.00 avg60=0.00\n')
            (pressure / 'io').write_text('full avg10=10.00 avg60=0.00\n')
            for name, key in (('memory.max', 'ctMemoryMaxBytes'),
                              ('memory.current', 'ctMemoryCurrentBytes'),
                              ('memory.swap.max', 'ctSwapMaxBytes'),
                              ('memory.swap.current', 'ctSwapCurrentBytes')):
                (cgroup / name).write_text(str(self.observed[key]))
            observed = admission.snapshot(root / 'meminfo', pressure, cgroup)
            self.assertEqual(self.observed['hostAvailableBytes'], observed['hostAvailableBytes'])
            self.assertIsNone(admission.admission_reason(observed))
            (cgroup / 'memory.max').write_text('max')
            with self.assertRaisesRegex(ValueError, 'counter-unavailable'):
                admission.snapshot(root / 'meminfo', pressure, cgroup)


if __name__ == '__main__':
    unittest.main()
