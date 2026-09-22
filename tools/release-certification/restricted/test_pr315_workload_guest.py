"""Regression for privileged imports mutating the immutable installation's byte roster."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import installation


class GuestImportTest(unittest.TestCase):
    def test_guest_disables_bytecode_before_importing_installed_owners(self):
        guest = Path(__file__).with_name('pr315_workload_guest.py')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for suppress in (False, True):
                bundle = root / str(suppress)
                bundle.mkdir(mode=0o755)
                (bundle / 'installed_owner.py').write_text('VALUE = 1\n')
                (bundle / 'installed_owner.py').chmod(0o444)
                manifest = {'schemaVersion': 1, 'kind': 'cryptad-restricted-installation',
                    'sourceCommit': 'a' * 40, 'files': installation.inventory(bundle, protected=False)}
                raw = installation.encode(manifest)
                (bundle / installation.MANIFEST).write_bytes(raw)
                script = "import importlib.util,sys\n"
                if suppress:
                    script += ("spec=importlib.util.spec_from_file_location('guest',sys.argv[2]); "
                               "module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)\n")
                script += 'sys.path.insert(0,sys.argv[1]); import installed_owner\n'
                subprocess.run([sys.executable, '-I', '-S', '-c', script, str(bundle), str(guest)],
                               check=True, timeout=10, capture_output=True)
                if suppress:
                    self.assertFalse((bundle / '__pycache__').exists())
                    installation.verify_bundle(bundle, hashlib.sha256(raw).hexdigest(), protected=False)
                else:
                    self.assertTrue((bundle / '__pycache__').exists())
                    with self.assertRaisesRegex(installation.InstallationError, 'bundle-content-mismatch'):
                        installation.verify_bundle(bundle, hashlib.sha256(raw).hexdigest(), protected=False)


if __name__ == '__main__':
    unittest.main()
