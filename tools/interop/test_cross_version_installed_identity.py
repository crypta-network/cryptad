"""Source snapshots cannot turn a local manifest into an installed source authority."""
from pathlib import Path
import tempfile
import unittest

import cross_version_runtime as runtime


class InstalledSourceIdentityTest(unittest.TestCase):
    def test_writable_snapshot_outside_fixed_installation_is_rejected_before_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / '.restricted-manifest.json').write_text('{}')
            with self.assertRaisesRegex(runtime.RuntimeFailure, 'outside-fixed-root'):
                runtime.installed_snapshot_identity(root)

    def test_ordinary_checkout_keeps_git_identity_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.assertIsNone(runtime.installed_snapshot_identity(Path(temporary)))


if __name__ == '__main__':
    unittest.main()
