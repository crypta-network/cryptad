"""Local fixed actor checks; no unit result grants installed workload acceptance."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'interop'))
import pr315_role_probe as probe
import runtime_snapshot as snapshot


class RoleProbeTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux O_PATH reader required')
    def test_fixed_output_symlink_is_real_and_descriptor_collector_rejects_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canary = root / 'canary'
            artifact = root / 'artifact'
            trigger = root / 'trigger.json'
            result = root / 'result.json'
            canary.write_bytes(b'x' * 32)
            trigger.write_text(json.dumps({'caseId': 'output-symlink', 'nonce': 'a' * 64}))
            with patch.object(probe, 'OUTPUT_CANARY', canary), \
                    patch.object(probe, 'OUTPUT_SYMLINK', artifact), \
                    patch.object(probe, 'OUTPUT_SYMLINK_TRIGGER', trigger), \
                    patch.object(probe, 'OUTPUT_SYMLINK_RESULT', result):
                probe.publish_output_symlink('a' * 64)
            self.assertTrue(artifact.is_symlink())
            self.assertEqual(str(canary), os.readlink(artifact))
            with self.assertRaisesRegex(snapshot.SnapshotError, 'file-invalid'):
                snapshot.read_file(root, artifact.name, maximum=64, timeout=2)
            self.assertEqual(b'x' * 32, snapshot.read_file(
                root, canary.name, maximum=64, timeout=2))
            self.assertEqual('output-symlink', json.loads(result.read_text())['caseId'])

    def test_sibling_probe_sends_only_fixed_recipient_syn_and_records_real_timeout(self):
        channel = MagicMock()
        channel.__enter__.return_value = channel
        channel.connect.side_effect = TimeoutError('fixed test timeout')
        with patch.object(probe.socket, 'socket', return_value=channel) as created:
            result = probe.attempt_network('sibling-fcp', 'a' * 64)
        created.assert_called_once_with(probe.socket.AF_INET, probe.socket.SOCK_STREAM)
        channel.connect.assert_called_once_with(('10.231.0.2', 19401))
        self.assertEqual({'connected': False, 'errno': 'ETIMEDOUT'}, result['outcome'])
        self.assertLess(result['startedMonotonicNs'], result['finishedMonotonicNs'])
        self.assertEqual('sibling-fcp', result['caseId'])
        with self.assertRaisesRegex(ValueError, 'network-case-invalid'):
            probe.attempt_network('sibling-app', 'a' * 64)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux proc namespaces required')
    def test_composed_role_record_fits_fixed_guest_capture_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(probe, 'TARGET', root / 'missing-observer'), \
                    patch.object(probe, 'SIBLING', root / 'missing-sibling'), \
                    patch.object(probe, 'PACKAGE', root / 'missing-package'), \
                    patch.object(probe, 'CGROUP_TARGET', root / 'missing-cgroup'), \
                    patch.object(probe, 'RESOLVER_TARGET', root / 'missing-resolver'):
                record = probe.attempt_read('a' * 64)
                record['writeAttempt'] = probe.attempt_write()
                record['identityClaim'], record['counterClaim'] = probe.fixed_false_claims()
                record['siblingRead'] = probe.attempt_fixed_access(
                    'sibling-data', probe.SIBLING)
                record['packageWrite'] = probe.attempt_fixed_access(
                    'package-expectation', probe.PACKAGE, b'pr315!')
                record['cgroupMigration'] = probe.attempt_fixed_access(
                    'cgroup-migration', probe.CGROUP_TARGET, b'2')
                record['resolverRead'] = probe.attempt_fixed_access(
                    'resolver-authority', probe.RESOLVER_TARGET)
            self.assertLessEqual(len(json.dumps(record).encode()), 4096)

    def test_fixed_role_access_rejects_arbitrary_target_and_reports_kernel_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'sibling-canary'
            target.write_bytes(b'x' * 32)
            target.chmod(0o000)
            try:
                with patch.object(probe, 'SIBLING', target):
                    denied = probe.attempt_fixed_access('sibling-data', target)
            finally:
                target.chmod(0o600)
            self.assertEqual({'opened': False, 'errno': 'EACCES'}, denied['outcome'])
            self.assertEqual(0, denied['writtenBytes'])
            self.assertEqual(b'x' * 32, target.read_bytes())
            with self.assertRaisesRegex(ValueError, 'operation-invalid'):
                probe.attempt_fixed_access('sibling-data', target.parent / 'other')

    def test_unexpected_package_write_is_bounded_and_detectable(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'cryptad.jar'
            target.write_bytes(b'x' * 32)
            with patch.object(probe, 'PACKAGE', target):
                value = probe.attempt_fixed_access('package-expectation', target, b'pr315!')
            self.assertEqual({'opened': True, 'errno': None}, value['outcome'])
            self.assertEqual(6, value['writtenBytes'])
            self.assertEqual(b'pr315!', target.read_bytes()[:6])

    def test_false_identity_and_counter_claims_are_finite(self):
        identity, counters = probe.fixed_false_claims()
        self.assertNotEqual(os.getpid(), identity['claimedHostPid'])
        self.assertEqual(0, counters['claimedMemoryCurrentBytes'])
        self.assertEqual(0, counters['claimedTasksCurrent'])
        self.assertLess(identity['startedMonotonicNs'], counters['finishedMonotonicNs'])

    def test_write_attempt_reports_real_denial_and_preserves_canary(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'observer-canary'
            raw = b'x' * 32
            target.write_bytes(raw)
            target.chmod(0o000)
            try:
                with patch.object(probe, 'TARGET', target):
                    denied = probe.attempt_write()
            finally:
                target.chmod(0o600)
            self.assertEqual({'opened': False, 'errno': 'EACCES'}, denied['outcome'])
            self.assertEqual(0, denied['writtenBytes'])
            self.assertEqual(raw, target.read_bytes())

    def test_unexpected_write_access_is_observable_with_finite_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'observer-canary'
            target.write_bytes(b'x' * 32)
            with patch.object(probe, 'TARGET', target):
                opened = probe.attempt_write()
            self.assertEqual({'opened': True, 'errno': None}, opened['outcome'])
            self.assertEqual(len(b'pr315!'), opened['writtenBytes'])
            self.assertEqual(b'pr315!', target.read_bytes()[:len(b'pr315!')])


if __name__ == '__main__':
    unittest.main()
