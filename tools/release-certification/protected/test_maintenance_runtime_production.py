"""A writable hosted checkout must never become a privileged private resolver."""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

import maintenance_runtime_production as producer


class PrivateFreezeAuthorityTest(unittest.TestCase):
    def test_hosted_private_production_rejects_before_any_privileged_or_private_operation(self):
        with patch.object(subprocess, 'run', side_effect=AssertionError('privilege escalation')) as run, \
                patch('maintenance_runtime_inputs.projection_origin') as origin, \
                patch.object(producer.metadata, 'seal_private_freeze') as seal:
            with self.assertRaisesRegex(producer.metadata.RuntimeMetadataError, 'isolated-worker-required'):
                producer.seal_with_authority({'schemaVersion': 1}, Path('package'), Path('runtime'), Path('inputs'))
        run.assert_not_called()
        origin.assert_not_called()
        seal.assert_not_called()

    def test_hosted_validation_step_blocks_v3_without_invoking_sudo_or_python(self):
        workflow = Path(__file__).resolve().parents[3] / '.github/workflows/stable-1.0-maintenance-release.yml'
        step = workflow.read_text().split('      - name: Validate exact frozen candidate without publication\n', 1)[1]
        script = textwrap.dedent(step.split('        run: |\n', 1)[1].split('\n      - name:', 1)[0])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'build').mkdir()
            (root / 'freeze.json').write_text('{"schemaVersion":3}')
            (root / 'build/stable-1.0-maintenance.json').write_text(json.dumps({
                'inputs': {'maintenanceCandidateFreeze': 'freeze.json'}}))
            shims = root / 'bin'
            shims.mkdir()
            for name in ('sudo', 'python3'):
                command = shims / name
                command.write_text('#!/bin/sh\ntouch forbidden-execution\nexit 99\n')
                command.chmod(0o700)
            result = subprocess.run(['/bin/bash', '-c', script], cwd=root,
                env={**os.environ, 'PATH': str(shims) + ':/usr/bin:/bin'}, capture_output=True, timeout=10)
            self.assertEqual(1, result.returncode)
            self.assertIn(b'maintenance-runtime-isolated-worker-required', result.stdout)
            self.assertFalse((root / 'forbidden-execution').exists())
