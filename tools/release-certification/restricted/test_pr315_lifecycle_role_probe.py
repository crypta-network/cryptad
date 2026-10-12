"""Real bounded role-side fork tests; these are not installed acceptance."""
import json
import os
from pathlib import Path
import select
import signal
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

import pr315_lifecycle_role_probe as probe


class LifecycleRoleProbeTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux pidfd and process group required')
    def test_late_child_is_created_only_after_root_trigger(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe.READY = root / 'ready.json'
            probe.TRIGGER = root / 'trigger.json'
            probe.CHILD = root / 'child.json'
            nonce = 'a' * 64
            pid = os.fork()
            if pid == 0:
                os.setsid()
                probe.sys = SimpleNamespace(argv=['probe.py', nonce, 'late-child'],
                                            flags=SimpleNamespace(isolated=1, no_site=1))
                try:
                    probe.main()
                finally:
                    os._exit(1)
            child_fd = None
            try:
                until = time.monotonic() + 3
                while not probe.READY.exists() and time.monotonic() < until:
                    time.sleep(.01)
                self.assertTrue(probe.READY.exists())
                self.assertFalse(probe.CHILD.exists())
                probe.TRIGGER.write_text(json.dumps({'schemaVersion': 1,
                    'kind': 'pr315-late-child-trigger', 'nonce': nonce}))
                probe.TRIGGER.chmod(0o600)
                while not probe.CHILD.exists() and time.monotonic() < until:
                    time.sleep(.01)
                self.assertTrue(probe.CHILD.exists())
                created = json.loads(probe.CHILD.read_text())
                self.assertEqual(pid, created['parentPid'])
                child_fd = os.pidfd_open(created['childPid'])
                self.assertFalse(select.select([child_fd], [], [], 0)[0])
            finally:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)
                if child_fd is not None:
                    self.assertTrue(select.select([child_fd], [], [], 1)[0])
                    os.close(child_fd)


if __name__ == '__main__':
    unittest.main()
