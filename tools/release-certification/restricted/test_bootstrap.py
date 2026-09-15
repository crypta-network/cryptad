"""Bootstrap ordering regressions; these do not model effective systemd execution."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import bootstrap


class BootstrapKernelAdmissionTests(unittest.TestCase):
    def exercise(self, *, rejected=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            relative = 'tools/release-certification/restricted/installation.py'
            verifier = root / relative
            verifier.parent.mkdir(parents=True)
            verifier.write_bytes(b'# exact verifier fixture\n')
            manifest = {'files': {relative: {'sha256': hashlib.sha256(verifier.read_bytes()).hexdigest()}}}
            manifest_bytes = json.dumps(manifest).encode()
            (root / '.restricted-manifest.json').write_bytes(manifest_bytes)
            approval = root / 'approval.json'
            approval.write_text(json.dumps({'bundleIdentity': hashlib.sha256(manifest_bytes).hexdigest()}))
            approval.chmod(0o600)
            events = []
            def kernel():
                events.append('kernel')
                if rejected:
                    raise ValueError('restricted-controller-kernel-state-invalid')
            installation = Mock()
            installation.verify_controller_process.side_effect = kernel
            installation.verify.side_effect = lambda: (events.append('installation') or {'bundleIdentity': 'a' * 64})
            worker = Mock()
            worker.main.side_effect = lambda **kwargs: events.append('worker')
            with patch.object(bootstrap, 'ROOT', root), patch.object(bootstrap, 'APPROVAL', approval), \
                    patch.object(bootstrap, 'trusted', side_effect=lambda path: path), \
                    patch.object(sys, 'flags', SimpleNamespace(isolated=True, no_site=True)), \
                    patch.object(sys, 'path', list(sys.path)), patch.object(sys, 'dont_write_bytecode', True), \
                    patch.object(os, 'geteuid', return_value=0), patch.object(os, 'listdir', return_value=[]), \
                    patch.object(os, 'set_inheritable'), patch.object(os, 'chdir'), \
                    patch.dict(os.environ, {'LISTEN_PID': str(os.getpid()), 'LISTEN_FDS': '1'}, clear=True), \
                    patch.dict(sys.modules, {'installation': installation, 'restricted_worker': worker}):
                if rejected:
                    with self.assertRaisesRegex(ValueError, 'kernel-state-invalid'):
                        bootstrap.main()
                else:
                    bootstrap.main()
            return events, installation, worker

    def test_kernel_authority_precedes_profile_probes_and_worker(self):
        events, _installation, worker = self.exercise()
        self.assertEqual(['kernel', 'installation', 'worker'], events)
        worker.main.assert_called_once_with(bundle_identity='a' * 64)

    def test_missing_kernel_authority_blocks_profile_probes_and_worker(self):
        events, installation, worker = self.exercise(rejected=True)
        self.assertEqual(['kernel'], events)
        installation.verify.assert_not_called()
        worker.main.assert_not_called()


if __name__ == '__main__':
    unittest.main()
