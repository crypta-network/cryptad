"""Actual fork/pipe and inode mutation checks; not installed guest acceptance."""
import os
from pathlib import Path
import sys
import tempfile
import json
from types import SimpleNamespace
from contextlib import nullcontext
import unittest
from unittest.mock import patch

import pr313_faults as faults

PROTECTED = Path(__file__).resolve().parents[1] / 'protected'
sys.path.insert(0, str(PROTECTED))
import restricted_native as native


@unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'fork'), 'Linux descriptor primitives')
class ExternalRaceTest(unittest.TestCase):
    def exercise(self, phase, kind):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / 'source'
            parent.mkdir()
            source = parent / 'projection.json'
            source.write_bytes(b'{"synthetic":"original"}\n')
            rendezvous = faults.Rendezvous(root, kind)
            rendezvous.selected = lambda: source
            try:
                with patch.object(native.os, 'read', side_effect=rendezvous.read):
                    with self.assertRaises(native.NativeBoundaryError):
                        if phase == 'input':
                            native._copy(source, root / 'copied', os.getuid(), os.getgid(), [0, 0])
                        else:
                            native._read_output(source, 32768)
            finally:
                rendezvous.close()
            self.assertTrue(rendezvous.fired)
            self.assertTrue((root / 'mutation.json').is_file())

    def test_external_input_mutations_are_rejected(self):
        for kind in faults.MUTATIONS:
            with self.subTest(kind=kind):
                self.exercise('input', kind)

    def test_external_collector_mutations_are_rejected(self):
        for kind in faults.MUTATIONS:
            with self.subTest(kind=kind):
                self.exercise('output', kind)

    def test_no_matching_acquisition_does_not_claim_witness(self):
        with tempfile.TemporaryDirectory() as temporary:
            rendezvous = faults.Rendezvous(Path(temporary), 'inode')
            rendezvous.selected = lambda: None
            rendezvous.close()
            self.assertFalse(rendezvous.fired)
            self.assertFalse((Path(temporary) / 'mutation.json').exists())


    def test_external_controller_death_retains_uncertain_state(self):
        # This verifies the test observer/controller protocol with real processes. The manager
        # below is an explicit local fake and is never counted as installed service evidence.
        for case in ('death-active', 'death-running', 'death-output'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixed = SimpleNamespace(ROOT=root, NativeBoundaryError=native.NativeBoundaryError,
                                        owning_boundary=lambda **kwargs: nullcontext())
                def write(path, value, **kwargs):
                    Path(path).write_text(json.dumps(value))
                fixed._write = write
                fixed._quiesce = lambda: None
                fixed._read_output = native._read_output
                fixed._manager = lambda action: {'InvocationID': 'a' * 32,
                                                 'SubState': 'running', 'ActiveState': 'inactive'}
                def execute(*args, **kwargs):
                    if (root / 'active.json').exists():
                        raise native.NativeBoundaryError('restricted-native-reconciliation-required')
                    stage = root / ('b' * 64)
                    stage.mkdir()
                    fixed._write(root / 'active.json', {'invocation': stage.name})
                    fixed._write(stage / 'manager.json', {'invocationId': 'a' * 32})
                    output = stage / 'output'
                    output.mkdir()
                    (output / 'stdout').write_bytes(b'pr313-output-ready\n')
                    from pr312_output_faults import CONTROL_BYTES
                    (output / 'projection.json').write_bytes(CONTROL_BYTES)
                    (output / 'complete.json').write_text(json.dumps({'invocation': stage.name, 'status': 'complete'}))
                    fixed._quiesce()
                fixed.run = execute
                observed = faults._death(case, root, fixed, [], {})
                self.assertEqual('reconciliation-required', observed['outcome'])
                self.assertEqual(observed['attackWitness']['activeRecordDigestBefore'],
                                 observed['attackWitness']['activeRecordDigestAfter'])
                self.assertTrue((root / 'active.json').exists())
                self.assertGreater(observed['attackWitness']['pidStartTime'], 0)

    def test_exceptional_quiescence_is_not_successful_output(self):
        from pr312_output_faults import CONTROL_BYTES
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary) / ('a' * 64)
            output = stage / 'output'
            output.mkdir(parents=True)
            (output / 'stdout').write_bytes(b'pr313-output-ready\n')
            (output / 'projection.json').write_bytes(CONTROL_BYTES)
            (output / 'complete.json').write_text(json.dumps({'invocation': stage.name, 'status': 'complete'}))
            faults.require_output_ready(native, stage)
            (stage / 'failure.json').write_text('{"status":"reconciliation-required"}')
            with self.assertRaisesRegex(ValueError, 'native-successful-output-not-ready'):
                faults.require_output_ready(native, stage)
            (stage / 'failure.json').unlink()
            (output / 'complete.json').write_text('{"invocation":"substituted","status":"complete"}')
            with self.assertRaisesRegex(ValueError, 'native-successful-output-not-ready'):
                faults.require_output_ready(native, stage)

    def test_candidate_execution_marker_requires_owned_uid_command_and_birth(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            group, proc = root / 'cgroup', root / 'proc'
            group.mkdir()
            child = proc / '123'
            child.mkdir(parents=True)
            (group / 'cgroup.procs').write_text('123\n')
            (child / 'stat').write_text('123 (pr313-revoke) ' + ' '.join(['S'] + ['0'] * 18 + ['987']))
            (child / 'comm').write_text('pr313-revoke\n')
            (child / 'cmdline').write_bytes(b'/usr/bin/python3\0/tools/bin/crypta-app\0subject-projection\0')
            (child / 'status').write_text('Uid:\t61002\t61002\t61002\t61002\n')
            fixed = SimpleNamespace(_native_identity=lambda: (61002, 61002))
            self.assertEqual({'pid': 123, 'startTime': 987, 'marker': 'pr313-revoke'},
                             faults.candidate_process(fixed, proc=proc, cgroup=group))
            (child / 'comm').write_text('python3\n')
            self.assertIsNone(faults.candidate_process(fixed, proc=proc, cgroup=group))
            (child / 'comm').write_text('pr313-revoke\n')
            (child / 'status').write_text('Uid:\t0\t0\t0\t0\n')
            self.assertIsNone(faults.candidate_process(fixed, proc=proc, cgroup=group))
            (child / 'status').write_text('Uid:\t61002\t61002\t61002\t61002\n')
            (child / 'cmdline').write_bytes(b'/usr/bin/python3\0/unrelated.py\0')
            self.assertIsNone(faults.candidate_process(fixed, proc=proc, cgroup=group))

    def test_case_contract_is_closed(self):
        self.assertEqual(12, len(faults.RACE_CASES))
        with self.assertRaisesRegex(ValueError, 'unknown-fixed-case'):
            faults.run('arbitrary', Path('/unused'), '0' * 64)


if __name__ == '__main__':
    unittest.main()
