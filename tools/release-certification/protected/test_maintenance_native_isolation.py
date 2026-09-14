"""Real namespace boundary probe for private maintenance native verification."""
from pathlib import Path
import tempfile
import sys
import unittest

import app_subject_projection as projection


@unittest.skipUnless(sys.platform == 'linux', 'maintenance native isolation requires Linux namespaces')
class NativeIsolationTest(unittest.TestCase):
    def test_native_tool_cannot_read_parent_key_or_host_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            root, tools, jdk = (parent / name for name in ('private-inputs', 'tools', 'jdk'))
            for path in (root, tools, jdk):
                path.mkdir(mode=0o700)
            secret = parent / 'recipient.key'
            secret.write_text('private-key-sentinel')
            secret.chmod(0o600)
            (root / 'bundle').write_text('signed-input-sentinel')
            registry = parent / 'public-keys'
            registry.write_text('public-registry-sentinel')
            executable = tools / 'native'
            executable.write_text('#!/bin/sh\n'
                'test ! -r ' + str(secret) + ' || exit 91\n'
                'test ! -e /etc/passwd || exit 92\n'
                'test "$(cat /work/bundle)" = signed-input-sentinel || exit 93\n'
                'test "$(cat /inputs/catalog-keys)" = public-registry-sentinel || exit 94\n'
                'printf isolated > /work/result\n')
            executable.chmod(0o700)
            projection._run_maintenance_native([str(executable), 'subject-projection', '--bundle', str(root / 'bundle'),
                '--catalog-keys', str(registry), '--output', str(root / 'result')], root, executable, tools, jdk)
            self.assertEqual('isolated', (root / 'result').read_text())
            self.assertEqual('private-key-sentinel', secret.read_text())
            self.assertEqual([], list(parent.glob('native-public-*')))

    def test_local_input_outside_invocation_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            root, tools, jdk = (parent / name for name in ('input', 'tools', 'jdk'))
            for path in (root, tools, jdk):
                path.mkdir()
            executable = tools / 'native'
            executable.write_text('#!/bin/sh\nexit 99\n')
            executable.chmod(0o700)
            with self.assertRaisesRegex(projection.ProjectionFailure, 'local-input-invalid'):
                projection._run_maintenance_native([str(executable), '--bundle', str(parent / 'key')],
                                                    root, executable, tools, jdk)


if __name__ == '__main__':
    unittest.main()
