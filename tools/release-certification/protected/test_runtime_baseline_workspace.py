"""Workspace reachability through both owner entrypoints; no original approval claim.

The disposable service test runs this file under the controller unit's actual sandbox. Local
nonroot tests replace only workspace ownership and upstream identity checks, and create real
temporary directories/files. The installed service test keeps actual workspace ownership checks.
"""
from contextlib import ExitStack
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runtime_baseline_approval as approval
import cross_version_supervisor_authority as supervisor


class ReachedOwnerConfiguration(Exception):
    pass


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux service workspace permissions')
class BaselineWorkspaceTests(unittest.TestCase):
    def check_workspace(self, operation):
        with ExitStack() as stack:
            actual_private_root = (hasattr(os, 'geteuid') and os.geteuid() == 0
                                   and approval.WORKSPACE.is_dir())
            if actual_private_root:
                root = approval.WORKSPACE
            else:
                root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
                stack.enter_context(patch.object(approval, 'WORKSPACE', root))
                stack.enter_context(patch.object(approval, '_private_directory', return_value=root))
                stack.enter_context(patch.object(approval.os, 'geteuid', return_value=0, create=True))
            before = set(root.iterdir())
            observed = []
            def owner_configuration(_path):
                created = set(root.iterdir()) - before
                self.assertEqual(len(created), 1)
                directory = created.pop()
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                (directory / 'synthetic-private-input').write_bytes(b'workspace-probe')
                observed.append(directory)
                raise ReachedOwnerConfiguration()
            job = 'prepare-runtime-baseline' if operation == 'prepare' else approval.JOB
            stack.enter_context(patch.object(supervisor, 'installed_identity', return_value={'sourceCommit': 'a' * 40}))
            stack.enter_context(patch.object(supervisor, 'run_identity', return_value={
                'sourceCommit': 'a' * 40, 'runId': 1, 'runAttempt': 1}))
            stack.enter_context(patch.dict(os.environ, {'GITHUB_JOB': job}))
            stack.enter_context(patch.object(approval, '_environment', return_value={}))
            stack.enter_context(patch.object(approval, '_gh', return_value=[{
                'jobs': [{'name': job, 'id': 2, 'head_sha': 'a' * 40}]}]))
            stack.enter_context(patch.object(approval, '_configuration', side_effect=owner_configuration))
            with self.assertRaises(ReachedOwnerConfiguration):
                approval.execute_owned(operation)
            self.assertEqual(len(observed), 1)
            self.assertFalse(observed[0].exists())
            self.assertEqual(set(root.iterdir()), before)

    def test_prepare_can_write_private_workspace_and_cleans_up_on_owner_failure(self):
        self.check_workspace('prepare')

    def test_approve_can_write_private_workspace_and_cleans_up_on_owner_failure(self):
        self.check_workspace('approve')


if __name__ == '__main__':
    unittest.main()
