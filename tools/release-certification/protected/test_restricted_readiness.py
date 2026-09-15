"""Readiness authenticates the installed activation descriptor before request admission."""
import os
import socket
import unittest
from unittest.mock import Mock, patch

import restricted_worker as worker


class StopLoop(Exception):
    pass


class RestrictedReadinessTests(unittest.TestCase):
    def exercise(self, *, socket_type=socket.SOCK_STREAM, accepting=1, inheritable=False,
                 name='/run/cryptad-restricted/control.sock', lock_failure=False):
        events = []
        listener = Mock(family=socket.AF_UNIX)
        listener.getsockname.return_value = name
        listener.getsockopt.side_effect = lambda _level, option: (
            socket_type if option == socket.SO_TYPE else accepting)
        listener.accept.side_effect = lambda: (events.append('accept'), self.stop())
        ready = lambda: events.append('ready')
        def lock(*_args):
            events.append('lock')
            if lock_failure:
                raise BlockingIOError()
        with patch.dict(os.environ, {'LISTEN_PID': str(os.getpid()), 'LISTEN_FDS': '1'}), \
                patch.object(worker.os, 'geteuid', return_value=0), \
                patch.object(worker.os, 'umask'), patch.object(worker.os, 'chdir'), \
                patch.object(worker, 'secure'), patch.object(worker.os, 'open', return_value=10), \
                patch.object(worker.fcntl, 'flock', side_effect=lock), \
                patch.object(worker, 'Worker'), \
                patch.object(worker.socket, 'socket', return_value=listener), \
                patch.object(worker.os, 'get_inheritable', return_value=inheritable):
            try:
                worker.main(bundle_identity='a' * 64, ready=ready)
            except (StopLoop, worker.BoundaryError, BlockingIOError):
                pass
        return events

    @staticmethod
    def stop():
        raise StopLoop()

    def test_ready_occurs_after_exclusive_lock_and_before_accept(self):
        self.assertEqual(['lock', 'ready', 'accept'], self.exercise())

    def test_invalid_activation_descriptor_never_signals_ready(self):
        for change in ({'socket_type': socket.SOCK_DGRAM}, {'accepting': 0},
                       {'inheritable': True}, {'name': '/tmp/caller.sock'}):
            with self.subTest(change=change):
                self.assertEqual(['lock'], self.exercise(**change))

    def test_competing_controller_never_signals_ready(self):
        self.assertEqual(['lock'], self.exercise(lock_failure=True))


if __name__ == '__main__':
    unittest.main()
