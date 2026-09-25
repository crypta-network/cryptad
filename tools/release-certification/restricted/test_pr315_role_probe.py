"""Local fixed actor checks; no unit result grants installed workload acceptance."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pr315_role_probe as probe


class RoleProbeTest(unittest.TestCase):
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
