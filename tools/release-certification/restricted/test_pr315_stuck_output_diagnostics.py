"""Failure provenance and retention checks, not installed case evidence."""
import base64
import json
import sys
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import pr315_stuck_output_diagnostics as diagnostic
import pr315_workload_fault_probes as faults


class StuckOutputDiagnosticTest(unittest.TestCase):
    def workload(self, root):
        def write(path, value, **kwargs):
            path.write_text(json.dumps(value))
            path.chmod(0o600)
        return SimpleNamespace(ROOT=root, write=write,
                               read=lambda path: json.loads(path.read_bytes()))

    def test_first_failure_phase_survives_later_phase_and_raw_tmpfs_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'authority').mkdir()
            tmp = root / 'state/candidate-sender/tmp'
            tmp.mkdir(parents=True)
            fault = tmp / 'pr315-stuck-output-ready.json'
            raw = b'{"private-fixture":"retained-only-before-cleanup"}'
            fault.write_bytes(raw)
            workload = self.workload(root)
            trace = diagnostic.Trace(workload, time.monotonic_ns() + 10**10)
            trace.step('collector-epoch')
            trace.failed()
            trace.step('audit-publication')
            def read(parent, name, **kwargs):
                return (parent / name).read_bytes()
            with patch('runtime_snapshot.read_file', side_effect=read):
                captured = trace.capture(ValueError('workload-stuck-collector-epoch-invalid'))
                fault.unlink()
                retained = diagnostic.retained(root, time.monotonic() + 2)
            self.assertEqual('collector-epoch', captured['phase'])
            self.assertEqual('workload-stuck-collector-epoch-invalid', captured['privateErrorCode'])
            self.assertEqual(raw, base64.b64decode(retained['record']['files']['ready']['privateBytesBase64']))
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
        original = ValueError('workload-stuck-collector-epoch-invalid')
        with patch.object(faults, '_probe_stuck_output', side_effect=original), \
                patch.object(diagnostic.Trace, 'capture', side_effect=OSError('diagnostic unavailable')):
            with self.assertRaises(ValueError) as captured:
                faults.probe_stuck_output(object(), {}, {}, 'a'*64, time.monotonic_ns()+10**9)
        self.assertIs(original, captured.exception)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux O_PATH reader required')
    def test_actual_failed_probe_retains_code_through_terminal_evidence_capture(self):
        import pr315_workload_evidence as evidence
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'authority').mkdir()
            workload = self.workload(root)
            with self.assertRaisesRegex(ValueError, 'preparation-invalid'):
                faults.probe_stuck_output(workload, {}, {}, 'a'*64,
                                         time.monotonic_ns()+10**10)
            summary = diagnostic.summary(workload)
            self.assertEqual('preconditions', summary['phase'])
            self.assertEqual('workload-stuck-output-preparation-invalid',
                             summary['privateErrorCode'])
            retained = evidence._capture(root, 'sha256:'+'a'*64, False)
            record = retained['stuckOutputDiagnostic']['record']
            self.assertEqual('private-diagnostic-not-acceptance', record['classification'])
            self.assertEqual('unavailable-or-unsafe', record['status'])
            self.assertNotIn('stuckOutputAudit', retained)


if __name__=='__main__':
    unittest.main()
