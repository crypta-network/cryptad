"""Local cleanup ordering and retention tests; no installed systemd execution."""
from contextlib import contextmanager
import fcntl
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import pr314_workload_driver as driver


class CleanupTest(unittest.TestCase):
    def test_controller_stop_releases_busy_lease_before_reconciliation(self):
        events = []
        with tempfile.TemporaryDirectory() as directory:
            lease = Path(directory) / 'lease'
            with lease.open('w') as controller:
                fcntl.flock(controller, fcntl.LOCK_EX | fcntl.LOCK_NB)

                @contextmanager
                def locked():
                    with lease.open('r') as observer:
                        fcntl.flock(observer, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        yield

                # Reproduce the exact busy-lease failure of the previous first step.
                with self.assertRaises(BlockingIOError), locked():
                    pass

                def stop(command, **kwargs):
                    self.assertEqual(['/usr/bin/systemctl', 'stop',
                                      'cryptad-workload-controller.service'], command)
                    self.assertTrue(kwargs['check'])
                    self.assertEqual(110, kwargs['timeout'])
                    events.append('controller-stop')
                    fcntl.flock(controller, fcntl.LOCK_UN)

                def reconcile():
                    with locked():
                        events.append('reconcile')

                workload = SimpleNamespace(ROLES=('sender', 'recipient'), locked=locked,
                    reconcile=reconcile, quiescent=lambda role: events.append(role) or True)
                network = SimpleNamespace(teardown=lambda: events.append('teardown'))
                with patch.object(driver.subprocess, 'run', side_effect=stop), \
                        patch.dict('sys.modules', {'restricted_workload_network': network}):
                    driver.cleanup(workload)
        self.assertEqual(['controller-stop', 'reconcile', 'sender', 'recipient', 'teardown'], events)

    def test_uncertain_shutdown_retains_network_and_state(self):
        from contextlib import nullcontext
        for failure in ('stop', 'reconcile', 'quiescence'):
            workload = SimpleNamespace(ROLES=('sender',), locked=nullcontext,
                reconcile=Mock(), quiescent=Mock(return_value=failure != 'quiescence'))
            network = SimpleNamespace(teardown=Mock())
            if failure == 'reconcile':
                workload.reconcile.side_effect = BlockingIOError('lease still busy')
            with self.subTest(failure=failure), \
                    patch.object(driver.subprocess, 'run', side_effect=(
                        subprocess.TimeoutExpired('systemctl', 110) if failure == 'stop' else None)), \
                    patch.dict('sys.modules', {'restricted_workload_network': network}):
                with self.assertRaises((subprocess.TimeoutExpired, BlockingIOError, ValueError)):
                    driver.cleanup(workload)
                network.teardown.assert_not_called()
                if failure == 'stop':
                    workload.reconcile.assert_not_called()


if __name__ == '__main__':
    unittest.main()
