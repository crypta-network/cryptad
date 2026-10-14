"""Offline role lifetime checks; PID1 commands are intercepted, never executed."""
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import pr320_role_lifetime as lifetime


@unittest.skipUnless(os.geteuid() == 0, 'Trusted unit-file fixtures require root ownership')
class RoleLifetimeTest(unittest.TestCase):
    def fixture(self):
        # /tmp is writable by others and is correctly rejected by the real trust checks.
        return tempfile.TemporaryDirectory(prefix='pr320-role-lifetime-test-', dir='/var/lib')

    def test_privacy_gets_two_hours_and_following_profile_restores_one_hour(self):
        with self.fixture() as temporary:
            system = Path(temporary) / 'system'
            def manager(arguments, **kwargs):
                if arguments[1] == 'daemon-reload':
                    return SimpleNamespace(stdout=b'', stderr=b'')
                unit = arguments[2]
                data = (system / (unit + '.d') / lifetime.NAME).read_bytes()
                return SimpleNamespace(stdout=b'2h\n' if data == lifetime.CONTENTS[7200] else b'1h\n',
                                       stderr=b'')
            with patch.object(lifetime, 'SYSTEM', system), \
                    patch.object(lifetime.subprocess, 'run', side_effect=manager) as commands:
                for selected, seconds in ((lifetime.PRIVACY_EXECUTION_CLASS, 7200),
                                          ('pr319-installed-restart-v1', 3600)):
                    lifetime.configure(selected)
                    for role in lifetime.ROLES:
                        path = system / ('cryptad-workload@' + role + '.service.d') / lifetime.NAME
                        self.assertEqual(lifetime.CONTENTS[seconds], path.read_bytes())
                self.assertEqual(10, commands.call_count)
                for call in commands.call_args_list:
                    self.assertEqual('/usr/bin/systemctl', call.args[0][0])
                    if call.args[0][1] == 'show':
                        self.assertIn(call.args[0][2], {
                            'cryptad-workload@' + role + '.service' for role in lifetime.ROLES})

    def test_wrong_loaded_ceiling_is_rejected(self):
        with self.fixture() as temporary, patch.object(lifetime, 'SYSTEM', Path(temporary) / 'system'), \
                patch.object(lifetime.subprocess, 'run',
                    return_value=SimpleNamespace(stdout=b'1h\n', stderr=b'')), \
                self.assertRaisesRegex(ValueError, 'role-runtime-invalid'):
            lifetime.configure(lifetime.PRIVACY_EXECUTION_CLASS)

    def test_unrelated_override_and_symlink_are_preserved_and_rejected_before_reload(self):
        for fault in ('unrelated', 'symlink'):
            with self.subTest(fault=fault), self.fixture() as temporary:
                system = Path(temporary) / 'system'
                directory = system / ('cryptad-workload@' + lifetime.ROLES[0] + '.service.d')
                directory.mkdir(parents=True)
                target = directory / lifetime.NAME
                unrelated = b'[Service]\nRuntimeMaxSec=9999\n'
                if fault == 'unrelated':
                    target.write_bytes(unrelated)
                else:
                    (directory / 'other.conf').write_bytes(unrelated)
                    target.symlink_to('other.conf')
                with patch.object(lifetime, 'SYSTEM', system), \
                        patch.object(lifetime.subprocess, 'run') as manager, \
                        self.assertRaisesRegex(ValueError, 'role-runtime-invalid'):
                    lifetime.configure(lifetime.PRIVACY_EXECUTION_CLASS)
                manager.assert_not_called()
                self.assertEqual(unrelated, target.read_bytes())


if __name__ == '__main__':
    unittest.main()
