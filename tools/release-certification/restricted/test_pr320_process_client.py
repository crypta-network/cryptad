"""Real local app-process/socket checks, distinct from installed native acceptance."""
from __future__ import annotations
import array
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pr320_budget_contract import PROCESS_START_BYTES, PROCESS_CLIENT_PATH, APPROVED_PERMISSIONS
import pr318_storage_selection as fixtures
import pr320_stdio_capture as stdio


class ProcessClientTest(unittest.TestCase):
    def test_normal_start_script_uses_own_environment_token_and_transferred_fixed_peer(self):
        credential = secrets.token_urlsafe(32)
        observed = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                observed.append((self.path, body, hashlib.sha256(
                    self.headers.get('Authorization', '').encode()).digest()))
                self.send_response(204)
                self.send_header('Content-Length', '0')
                self.end_headers()
            def log_message(self, *_):
                pass
        try:
            server = http.server.HTTPServer(('127.0.0.1', 19402), Handler)
        except OSError:
            self.skipTest('Fixed synthetic peer unavailable; no alternate port or installed claim')
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                bundle = Path(temporary) / 'bundle'
                (bundle / 'bin').mkdir(parents=True)
                (bundle / 'lib').mkdir()
                run = Path(temporary) / 'run'
                run.mkdir(mode=0o700)
                (bundle / 'bin/start.sh').write_bytes(PROCESS_START_BYTES)
                (bundle / 'bin/start.sh').chmod(0o755)
                root = Path(__file__).resolve().parents[3]
                source = root / PROCESS_CLIENT_PATH
                shutil.copyfile(source, bundle / 'lib/pr320-budget-process-client.py')
                environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                    'CRYPTAD_APP_ID': 'feed-reader', 'CRYPTAD_APP_TOKEN': credential,
                    'CRYPTAD_APP_RUN_DIR': str(run)}
                process = subprocess.Popen([str(bundle / 'bin/start.sh')], cwd=bundle,
                    env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    deadline = time.monotonic() + 5
                    while not (run / 'pr320-budget-owner.sock').exists():
                        if process.poll() is not None or time.monotonic() >= deadline:
                            self.fail('Signed fixture startup did not reach its fixed local socket')
                        time.sleep(.01)
                    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
                        channel.settimeout(5)
                        channel.connect(str(run / 'pr320-budget-owner.sock'))
                        with socket.create_connection(('127.0.0.1', 19402), timeout=5) as connected:
                            task = {'schemaVersion': 1, 'uri': 'USK@synthetic/owner/0',
                                    'deadlineMonotonicNs': time.monotonic_ns() + 10_000_000_000}
                            channel.sendmsg([json.dumps(task).encode()], [(socket.SOL_SOCKET,
                                socket.SCM_RIGHTS, array.array('i', [connected.fileno()]))])
                        self.assertEqual(b'{"state":"request-written"}', channel.recv(1024))
                        self.assertEqual({'state': 'complete', 'status': 204}, json.loads(channel.recv(1024)))
                    stdout, stderr = process.communicate(timeout=5)
                    self.assertEqual(0, process.returncode)
                    # Booleans keep failed assertions from printing ephemeral credential bytes/hashes.
                    self.assertTrue(stdout == stderr == b'', 'Worker produced unexpected ordinary output')
                    self.assertEqual(1, len(observed))
                    self.assertEqual('/api/v1/trust-graph/import-uri', observed[0][0])
                    self.assertTrue(observed[0][2] == hashlib.sha256(('Bearer ' + credential).encode()).digest(),
                                    'Worker did not authenticate using its own process environment')
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate(timeout=5)
        finally:
            server.server_close()
            thread.join(timeout=2)

    def test_new_signed_process_verifier_rejects_changed_script_and_legacy_start(self):
        root = Path(__file__).resolve().parents[3]
        script = (root / PROCESS_CLIENT_PATH).read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            (bundle / 'bin').mkdir()
            (bundle / 'lib').mkdir()
            manifest = {'app.id': 'feed-reader', 'app.exec': 'bin/start.sh',
                'app.permissions': ','.join(APPROVED_PERMISSIONS['feed-reader']),
                'sandbox.mode': 'restricted-process', 'sandbox.required': 'true',
                'api.targetStability': 'experimental', 'api.experimentalCapabilitiesAccepted': 'true'}
            (bundle / 'cryptad-app.properties').write_text('\n'.join(key + '=' + value for key, value in manifest.items()))
            (bundle / 'bin/start.sh').write_bytes(PROCESS_START_BYTES)
            (bundle / 'lib/pr320-budget-process-client.py').write_bytes(script)
            fixtures._verify_app(bundle, 'feed-reader', APPROVED_PERMISSIONS, script)
            (bundle / 'lib/pr320-budget-process-client.py').write_bytes(script + b'\n')
            with self.assertRaisesRegex(ValueError, 'process-client-invalid'):
                fixtures._verify_app(bundle, 'feed-reader', APPROVED_PERMISSIONS, script)
            (bundle / 'lib/pr320-budget-process-client.py').write_bytes(script)
            (bundle / 'bin/start.sh').write_bytes(b'#!/bin/sh\nset -eu\nexec sleep 600\n')
            with self.assertRaisesRegex(ValueError, 'manifest-invalid'):
                fixtures._verify_app(bundle, 'feed-reader', APPROVED_PERMISSIONS, script)


class StdioCaptureTest(unittest.TestCase):
    def test_successive_generations_retain_distinct_pipe_bytes_and_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'logs').mkdir(mode=0o700)
            for generation in ('a' * 32, 'b' * 32):
                with self.subTest(generation=generation):
                    read_out, write_out = os.pipe()
                    read_err, write_err = os.pipe()
                    capture = stdio.Capture(root, generation=generation)
                    capture.bind(SimpleNamespace(stdout=os.fdopen(read_out, 'rb'),
                                                 stderr=os.fdopen(read_err, 'rb')))
                    os.write(write_out, generation.encode())
                    os.close(write_out)
                    os.close(write_err)
                    try:
                        capture.finish()
                        capture.receipt()
                    finally:
                        capture.close()
            for generation in ('a' * 32, 'b' * 32):
                directory = root / 'logs' / ('stdio-' + generation)
                self.assertEqual(generation.encode(), (directory / 'stdout.private.log').read_bytes())
                receipt = json.loads((directory / 'stdio.private.json').read_text())
                self.assertEqual(generation, receipt['generation'])
                self.assertEqual('complete', receipt['status'])
            with self.assertRaises(FileExistsError):
                stdio.Capture(root, generation='a' * 32)
            self.assertEqual(b'a' * 32,
                             (root / 'logs' / ('stdio-' + 'a' * 32) / 'stdout.private.log').read_bytes())

    def test_replacement_preserves_abrupt_generations_without_fabricating_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'logs').mkdir(mode=0o700)
            first = stdio.Capture(root, generation='a' * 32)
            os.write(first.files['stdout.private.log'], b'abrupt retained output')
            first.close()
            replacement = stdio.Capture(root, generation='b' * 32)
            replacement.close()
            directory = root / 'logs' / ('stdio-' + 'a' * 32)
            self.assertEqual(b'abrupt retained output', (directory / 'stdout.private.log').read_bytes())
            self.assertFalse((directory / 'stdio.private.json').exists())

    def test_real_pipe_bytes_retained_to_eof_and_budget_exhaustion_never_claims_complete(self):
        for excess in (False, True):
            with self.subTest(excess=excess), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / 'logs').mkdir(mode=0o700)
                read_out, write_out = os.pipe()
                read_err, write_err = os.pipe()
                capture = stdio.Capture(root)
                capture.bind(SimpleNamespace(stdout=os.fdopen(read_out, 'rb'), stderr=os.fdopen(read_err, 'rb')))
                os.write(write_out, b'private synthetic output')
                os.close(write_out)
                os.close(write_err)
                try:
                    with patch.object(stdio, 'MAX_STREAM_BYTES', 4 if excess else 2 * 1024 * 1024):
                        if excess:
                            with self.assertRaisesRegex(ValueError, 'output-budget-exhausted'):
                                capture.finish()
                        else:
                            capture.finish()
                        capture.receipt()
                finally:
                    capture.close()
                receipt = json.loads((root / 'logs/stdio.private.json').read_text())
                self.assertEqual('output-budget-exhausted' if excess else 'complete', receipt['status'])
                self.assertEqual(b'' if excess else b'private synthetic output',
                                 (root / 'logs/stdout.private.log').read_bytes())


if __name__ == '__main__':
    unittest.main()
