"""Failure provenance and retention checks, not installed case evidence."""
import base64
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import pr315_partial_launch_diagnostics as diagnostic
import pr315_workload_fault_probes as faults


class PartialLaunchDiagnosticTest(unittest.TestCase):
    def workload(self, root):
        def write(path, value, **kwargs):
            path.write_text(json.dumps(value))
            path.chmod(0o600)
        return SimpleNamespace(ROOT=root, write=write,
                               read=lambda path: json.loads(path.read_bytes()))

    def test_first_failure_phase_survives_release_and_raw_tmpfs_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'authority').mkdir()
            tmp = root / 'state/previous/tmp'
            tmp.mkdir(parents=True)
            fault = tmp / 'pr315-partial-launch-fault.json'
            raw = b'{"private-fixture":"retained-only-before-cleanup"}'
            fault.write_bytes(raw)
            workload = self.workload(root)
            trace = diagnostic.Trace(workload, time.monotonic_ns() + 10**10)
            trace.step('fault-sampling', wait_until_ns=time.monotonic_ns() + 9*10**9)
            trace.failed()
            trace.step('release')
            def read(parent, name, **kwargs):
                return (parent / name).read_bytes()
            with patch('runtime_snapshot.read_file', side_effect=read):
                captured = trace.capture(ValueError('workload-partial-launch-fault-timeout'))
                fault.unlink()
                retained = diagnostic.retained(root, time.monotonic() + 2)
            self.assertEqual('fault-sampling', captured['phase'])
            self.assertEqual('workload-partial-launch-fault-timeout', captured['privateErrorCode'])
            self.assertEqual(raw, base64.b64decode(retained['record']['files']['fault']['privateBytesBase64']))
            self.assertEqual('unavailable-or-unsafe', retained['record']['status'])
            self.assertEqual('private-diagnostic-not-acceptance', retained['record']['classification'])
            self.assertFalse(fault.exists())

    def test_unknown_error_values_are_not_promoted_to_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'authority').mkdir()
            trace = diagnostic.Trace(self.workload(root), time.monotonic_ns()-1)
            value = trace.capture(ValueError('private-path-or-token-abcdef'))
            self.assertIsNone(value['privateErrorCode'])
            self.assertNotIn('private-path-or-token', json.dumps(value))
            self.assertTrue(all(row['status']=='original-deadline-expired' for row in value['files'].values()))
            with self.assertRaisesRegex(ValueError, 'phase-invalid'):
                trace.step('claim-passed')

    def test_diagnostic_capture_failure_cannot_replace_original_probe_error(self):
        original = ValueError('workload-partial-launch-fault-timeout')
        with patch.object(faults, '_probe_partial_launch', side_effect=original), \
                patch.object(diagnostic.Trace, 'capture', side_effect=OSError('diagnostic unavailable')):
            with self.assertRaises(ValueError) as captured:
                faults.probe_partial_launch(object(), {}, {}, 1, time.monotonic_ns()+10**9)
        self.assertIs(original, captured.exception)


if __name__=='__main__':
    unittest.main()
