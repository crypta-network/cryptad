"""Read-only harness checks, not substitutes for its VM/service/UID execution."""
import contextlib
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import disposable_integration as harness


class DisposableHarnessTest(unittest.TestCase):
    def test_probe_always_reports_unexecuted_without_provisioning(self):
        output = io.StringIO()
        with patch('sys.argv', ['harness', '--probe']), \
                patch.object(harness, 'prerequisites', return_value=['dedicated-disposable-vm-required']), \
                patch.object(harness, 'provision') as install, contextlib.redirect_stdout(output):
            status = harness.main()
        install.assert_not_called()
        self.assertEqual(78, status)
        result = json.loads(output.getvalue())
        self.assertFalse(result['executed'])
        self.assertFalse(result['mandatoryIsolationTestSatisfied'])

    def test_explicit_vm_flag_cannot_override_missing_real_prerequisites(self):
        output = io.StringIO()
        with patch('sys.argv', ['harness', '--disposable-vm']), \
                patch.object(harness, 'prerequisites', return_value=['dedicated-disposable-vm-required']), \
                patch.object(harness, 'provision') as install, contextlib.redirect_stdout(output):
            self.assertEqual(78, harness.main())
        install.assert_not_called()
        self.assertEqual('unexecuted', json.loads(output.getvalue())['status'])

    def test_default_does_not_provision_even_with_supported_profile(self):
        with patch('sys.argv', ['harness']), patch.object(harness, 'prerequisites', return_value=[]), \
                patch.object(harness, 'provision') as install, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(78, harness.main())
        install.assert_not_called()


if __name__ == '__main__':
    unittest.main()
