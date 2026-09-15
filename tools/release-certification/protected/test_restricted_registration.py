"""Offline registration admission/quota tests, not deployed root or UID isolation evidence."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).with_name('restricted_registration.py')
SPEC = importlib.util.spec_from_file_location('registration', PATH)
registration = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(registration)


class RegistrationTests(unittest.TestCase):
    def test_reserved_then_bound_handle_consumes_one_history_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            operations, reservations = root / 'operations', root / 'reservations'
            operations.mkdir()
            reservations.mkdir()
            handle = 'a' * 64
            (reservations / (handle + '.json')).write_text('{}')
            (operations / handle).mkdir()
            with patch.object(registration, 'OPERATIONS', operations), patch.object(registration, 'RESERVATIONS', reservations):
                self.assertEqual({handle}, registration.handle_inventory())

    def test_quota_counts_all_existing_handles_including_unbound_reservations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            operations, reservations = root / 'operations', root / 'reservations'
            operations.mkdir()
            reservations.mkdir()
            for number in range(registration.MAX_HANDLES):
                (reservations / (f'{number:064x}' + '.json')).touch()
            with patch.object(registration, 'OPERATIONS', operations), patch.object(registration, 'RESERVATIONS', reservations):
                self.assertEqual(registration.MAX_HANDLES, len(registration.handle_inventory()))

    def test_checkout_cli_cannot_register_or_disclose_input_paths(self):
        result = subprocess.run([sys.executable, '-I', '-S', str(PATH), '--context', '/synthetic-private-canary',
                                 '--inputs', '/synthetic-private-canary'], capture_output=True, timeout=10)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(b'', result.stdout)
        self.assertEqual(b'restricted-registration-rejected\n', result.stderr)


if __name__ == '__main__':
    unittest.main()
