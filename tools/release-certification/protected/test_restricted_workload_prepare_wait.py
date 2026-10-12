"""Real direct-child wait regressions; no privileged or installed execution."""
import os
from pathlib import Path
import signal
import tempfile
import time
import unittest
from unittest.mock import patch

import restricted_workload as workload
import restricted_workload_prepare as preparation


class StorageChildWaitTest(unittest.TestCase):
    def child(self, *, stalled=False, status=0):
        child = os.fork()
        if child == 0:
            if stalled:
                time.sleep(30)
            os._exit(status)
        self.addCleanup(self.cleanup_child, child)
        return child

    @staticmethod
    def cleanup_child(child):
        try:
            observed, _status = os.waitpid(child, os.WNOHANG)
        except ChildProcessError:
            return
        if observed == child:
            return
        os.kill(child, signal.SIGKILL)
        end = time.monotonic() + 2
        while time.monotonic() < end:
            if os.waitpid(child, os.WNOHANG)[0] == child:
                return
            time.sleep(.01)
        raise AssertionError('Test child could not be reaped')

    def test_successful_actual_child_is_reaped(self):
        child = self.child()
        preparation._wait_storage_child(child, time.monotonic_ns() + 5_000_000_000)
        with self.assertRaises(ChildProcessError):
            os.waitpid(child, os.WNOHANG)

    def test_failed_actual_child_is_reaped_and_rejected(self):
        child = self.child(status=1)
        with self.assertRaisesRegex(workload.WorkloadError, 'initialization-failed'):
            preparation._wait_storage_child(child, time.monotonic_ns() + 5_000_000_000)
        with self.assertRaises(ChildProcessError):
            os.waitpid(child, os.WNOHANG)

    def test_stalled_actual_child_honors_campaign_deadline_and_retains_partial_state(self):
        with tempfile.TemporaryDirectory() as directory:
            retained = Path(directory) / 'partial-state'
            retained.write_text('retain on failure')
            child = self.child(stalled=True)
            started = time.monotonic()
            with self.assertRaisesRegex(workload.WorkloadError, 'initialization-timeout'):
                preparation._wait_storage_child(child, time.monotonic_ns() + 50_000_000)
            self.assertLess(time.monotonic() - started, 2.5)
            self.assertEqual('retain on failure', retained.read_text())
            with self.assertRaises(ChildProcessError):
                os.waitpid(child, os.WNOHANG)

    def test_expired_campaign_reaps_success_but_cannot_proceed(self):
        child = self.child()
        with self.assertRaisesRegex(workload.WorkloadError, 'initialization-timeout'):
            preparation._wait_storage_child(child, time.monotonic_ns() - 1)
        with self.assertRaises(ChildProcessError):
            os.waitpid(child, os.WNOHANG)

    def test_initialization_cap_does_not_follow_long_campaign_deadline(self):
        with patch.object(preparation.time, 'monotonic', side_effect=[10, 16, 16, 16]), \
                patch.object(preparation.os, 'waitpid', side_effect=[(0, 0), (42, 9)]), \
                patch.object(preparation.os, 'kill') as kill:
            with self.assertRaisesRegex(workload.WorkloadError, 'initialization-timeout'):
                preparation._wait_storage_child(42, 1_000_000_000_000)
        kill.assert_called_once_with(42, signal.SIGKILL)

    def test_uncertain_reap_stops_after_two_seconds(self):
        with patch.object(preparation.time, 'monotonic', side_effect=[10, 16, 16, 19]), \
                patch.object(preparation.os, 'waitpid', return_value=(0, 0)), \
                patch.object(preparation.os, 'kill') as kill:
            with self.assertRaisesRegex(workload.WorkloadError, 'child-reconciliation-required'):
                preparation._wait_storage_child(42, 1_000_000_000_000)
        kill.assert_called_once_with(42, signal.SIGKILL)

    def test_lost_child_ownership_never_signals_numeric_pid(self):
        with patch.object(preparation.os, 'waitpid', side_effect=ChildProcessError), \
                patch.object(preparation.os, 'kill') as kill:
            with self.assertRaisesRegex(workload.WorkloadError, 'child-reconciliation-required'):
                preparation._wait_storage_child(42, time.monotonic_ns() + 5_000_000_000)
        kill.assert_not_called()

    def test_interrupted_wait_does_not_remove_deadline(self):
        with patch.object(preparation.time, 'monotonic', side_effect=[10, 16, 16]), \
                patch.object(preparation.os, 'waitpid', side_effect=[InterruptedError(), (42, 9)]), \
                patch.object(preparation.os, 'kill') as kill:
            with self.assertRaisesRegex(workload.WorkloadError, 'initialization-timeout'):
                preparation._wait_storage_child(42, 1_000_000_000_000)
        kill.assert_called_once_with(42, signal.SIGKILL)


if __name__ == '__main__':
    unittest.main()
