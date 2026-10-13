"""Prospective clocks and legacy dispatch stay distinct from installed completion."""
import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pr319_restart_runtime_runner as runner
import pr319_installed_dispatch as dispatch


class RuntimeBoundaryTests(unittest.TestCase):
    def test_invalid_diagnostic_interval_is_inside_same_selected_hour(self):
        phase = {'diagnostics': {'observedAt': '2026-10-13T19:10:00Z'}}
        row = {'caseId': 'diagnostics-unavailable', **{k: copy.deepcopy(phase)
               for k in ('before', 'during', 'after', 'recovery')}}
        value = {'restartCases': [], 'diagnosticsCases': [row]}
        authorization = {'budgetSelection': {'timePlan': {'boundaryEpochSecond': 1791921600}}}
        runner._selected_time_plan(value, authorization)
        row['during']['diagnostics']['observedAt'] = '2026-10-13T18:59:59Z'
        with self.assertRaisesRegex(ValueError, 'selected-hour-missed'):
            runner._selected_time_plan(value, authorization)

    def test_host_clock_bracket_includes_actual_invalid_sample(self):
        second = 1791918000
        def clock(offset):
            ns = (second + offset) * 10**9
            return {'hostEpochBeforeNanos': ns, 'hostEpochAfterNanos': ns + 1000000,
                'guestEpochNanos': ns, 'hostMonotonicBeforeNanos': (offset + 1) * 10**9,
                'hostMonotonicAfterNanos': (offset + 1) * 10**9 + 1000000}
        phase = {'diagnostics': {'observedAt': '2026-10-13T19:00:10Z'}}
        row = {'caseId': 'diagnostics-unavailable', **{k: copy.deepcopy(phase)
               for k in ('before', 'during', 'after', 'recovery')}}
        attachment = {'restartCases': [], 'diagnosticsCases': [row]}
        report = {'storageClock': {'before': clock(0), 'after': clock(60)}}
        runner._clock_binding(report, attachment, {})
        row['during']['diagnostics']['observedAt'] = '2026-10-13T19:02:00Z'
        with self.assertRaisesRegex(ValueError, 'observation-clock-substituted'):
            runner._clock_binding(report, attachment, {})

    def test_historical_startup_measurement_never_runs_new_lane(self):
        called = []
        driver = SimpleNamespace(controller_ready=lambda x: called.append(x),
            readiness_deadline=lambda *a: 123, STARTUP_MEASUREMENT_SECONDS=45)
        result = dispatch.observer_sequence(driver, None, None, None, 0, 0, True)
        self.assertEqual([123], called)
        self.assertFalse(result['installedPositiveExecuted'])
        self.assertEqual('startup-measurement-not-workload-acceptance', result['classification'])


if __name__ == '__main__':
    unittest.main()
