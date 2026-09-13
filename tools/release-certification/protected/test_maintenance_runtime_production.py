"""Exercise the privileged producer boundary independently of synthetic native admission."""
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import maintenance_runtime_production as producer


class PrivateFreezeAuthorityTest(unittest.TestCase):
    def test_dispatch_uses_fixed_privilege_and_does_not_read_private_inputs_in_parent(self):
        with patch.object(producer.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'{"schemaVersion":3}', b'')) as run, \
                patch('maintenance_runtime_companion.inspect'), \
                patch('maintenance_runtime_inputs.projection_origin', side_effect=AssertionError('parent opened private inputs')):
            result = producer.seal_with_authority({'schemaVersion': 1}, Path('package'), Path('runtime'), Path('inputs'))
        self.assertEqual(3, result['schemaVersion'])
        command = run.call_args.args[0]
        self.assertEqual(['sudo', '--non-interactive', '--preserve-env=GITHUB_ACTIONS,GH_TOKEN', '/usr/bin/python3'], command[:4])
        self.assertNotIn('key', ' '.join(command))
        self.assertTrue(run.call_args.kwargs['check'])

    def test_privileged_process_owns_original_opening_and_returns_only_fixed_sealed_members(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / 'runtime'
            scratch = []
            def seal(freeze, package, root, *, projection_origin, private_root):
                self.assertEqual(0o700, private_root.stat().st_mode & 0o777)
                self.assertFalse(private_root.is_relative_to(Path(directory)))
                scratch.append(private_root)
                root.mkdir()
                for name in ('runtime-companion.json', 'runtime-companion.cms'):
                    (root / name).write_bytes(b'sealed')
                return {'schemaVersion': 3}
            stdin = type('Input', (), {'buffer': io.BytesIO(b'{"schemaVersion":1}')})()
            stdout = type('Output', (), {'buffer': io.BytesIO()})()
            with patch.object(producer.os, 'geteuid', return_value=0), \
                    patch.dict(os.environ, {'SUDO_UID': '1001', 'SUDO_GID': '1002'}), \
                    patch.object(producer.sys, 'stdin', stdin), patch.object(producer.sys, 'stdout', stdout), \
                    patch('maintenance_runtime_inputs.detect_private_inputs', return_value=True), \
                    patch('maintenance_runtime_inputs.projection_origin', return_value={'original': True}) as origin, \
                    patch.object(producer.metadata, 'seal_private_freeze', side_effect=seal), \
                    patch('maintenance_runtime_companion.inspect'), patch.object(producer.os, 'chown') as chown:
                result = producer.main(['--package', 'package', '--runtime-root', str(runtime), '--inputs', 'inputs'])
            self.assertEqual(0, result)
            origin.assert_called_once()
            self.assertEqual(3, chown.call_count)
            self.assertEqual({runtime, runtime / 'runtime-companion.json', runtime / 'runtime-companion.cms'},
                             {call.args[0] for call in chown.call_args_list})
            self.assertFalse(scratch[0].exists())
            self.assertEqual({'schemaVersion': 3}, producer.metadata.read_json(stdout.buffer.getvalue()))

    def test_unprivileged_entry_rejects_before_original_opening(self):
        with patch.object(producer.os, 'geteuid', return_value=1001), \
                patch.object(producer.sys, 'stderr', io.StringIO()), \
                patch('maintenance_runtime_inputs.projection_origin') as origin:
            self.assertEqual(2, producer.main(['--package', 'package', '--runtime-root', 'runtime', '--inputs', 'inputs']))
            origin.assert_not_called()
