"""Real direct-child wait regressions; no privileged or installed execution."""
import os
import hashlib
import json
from pathlib import Path
import signal
import tempfile
import time
import unittest
from unittest.mock import patch

import restricted_workload as workload
import restricted_workload_prepare as preparation


class ExecutionSelectionTest(unittest.TestCase):
    def test_legacy_selection_requires_absent_execution_class(self):
        plan = {'experimentId': 'pr315-installed-workload'}
        private = {'root': '/var/lib/cryptad-cross-version/experiments/pr315-installed-workload'}
        authorization = {'experimentId': plan['experimentId'], 'root': private['root']}
        self.assertTrue(preparation.valid_execution_selection(plan, private, authorization))
        self.assertFalse(preparation.valid_execution_selection(
            plan, private, {**authorization, 'executionClass': None}))
        self.assertFalse(preparation.valid_execution_selection(
            plan, private, {**authorization, 'selectionDigest': 'sha256:' + 'a' * 64}))

    def test_mail_selection_binds_class_experiment_and_root(self):
        root = '/var/lib/cryptad-cross-version/experiments/' + preparation.MAIL_EXPERIMENT
        plan = {'experimentId': preparation.MAIL_EXPERIMENT}
        private = {'root': root}
        authorization = {'executionClass': preparation.MAIL_EXECUTION_CLASS,
                         'experimentId': preparation.MAIL_EXPERIMENT, 'root': root,
                         'planDigest': 'sha256:' + 'a' * 64}
        authorization['selectionDigest'] = 'sha256:' + hashlib.sha256(json.dumps({
            'executionClass': preparation.MAIL_EXECUTION_CLASS,
            'planDigest': authorization['planDigest']}, sort_keys=True,
            separators=(',', ':'), allow_nan=False).encode()).hexdigest()
        self.assertTrue(preparation.valid_execution_selection(plan, private, authorization))
        for selected_plan, selected_private, selected_authorization in (
                ({'experimentId': 'pr315-installed-workload'}, private, authorization),
                (plan, {'root': root + '-other'}, authorization),
                (plan, private, {**authorization, 'executionClass': 'unknown'}),
                (plan, private, {**authorization, 'root': root + '-other'})):
            with self.subTest(plan=selected_plan, private=selected_private,
                              authorization=selected_authorization):
                self.assertFalse(preparation.valid_execution_selection(
                    selected_plan, selected_private, selected_authorization))


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
