"""Real local worker restart test; this is not installed AppHost acceptance."""
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from importlib.util import module_from_spec, spec_from_file_location


class ProbeWorkerTest(unittest.TestCase):
    def test_signed_app_binds_fixed_source_port_and_emits_one_sibling_syn(self):
        script = Path(__file__).with_name('pr315-probe-app') / 'bin/probe.py'
        spec = spec_from_file_location('pr315_signed_sibling_probe_test', script)
        probe = module_from_spec(spec)
        spec.loader.exec_module(probe)
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            nonce = 'b' * 64
            trigger = data / probe.SIBLING_APP_TRIGGER
            trigger.write_text(json.dumps({'schemaVersion': 1,
                'kind': 'pr315-sibling-app-trigger', 'nonce': nonce}))
            trigger.chmod(0o600)
            calls = []

            class Channel:
                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return False

                def settimeout(self, value):
                    calls.append(('timeout', value))

                def bind(self, value):
                    calls.append(('bind', value))

                def connect(self, value):
                    calls.append(('connect', value))
                    raise TimeoutError()

            with patch.object(probe.socket, 'socket', return_value=Channel()):
                result = probe.sibling_app(data)
            self.assertEqual([('timeout', 3),
                ('bind', ('10.231.0.1', 19404)),
                ('connect', ('10.231.0.2', 19402))], calls)
            self.assertEqual({'connected': False, 'phase': 'connect',
                              'errno': 'ETIMEDOUT'}, result['outcome'])
            self.assertEqual(result, json.loads((data / probe.SIBLING_APP_RESULT).read_text()))
            self.assertFalse((data / ('.' + probe.SIBLING_APP_RESULT + '.pending')).exists())
            with self.assertRaisesRegex(ValueError, 'already-published'):
                probe.sibling_app(data)

    def test_fixed_provider_trigger_records_denial_without_reading_canary_bytes(self):
        script = Path(__file__).with_name('pr315-probe-app') / 'bin/probe.py'
        spec = spec_from_file_location('pr315_signed_probe_test', script)
        probe = module_from_spec(spec)
        spec.loader.exec_module(probe)
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            nonce = 'a' * 64
            trigger = data / probe.PROVIDER_TRIGGER
            trigger.write_text(json.dumps({'schemaVersion': 1,
                'kind': 'pr315-provider-trigger', 'nonce': nonce}))
            trigger.chmod(0o600)
            canary = data / 'root-provider-canary'
            canary.write_bytes(b'private-provider-bytes')
            real_open = probe.os.open

            def denied(path, flags, *args, **kwargs):
                if path == canary:
                    raise PermissionError(errno.EACCES, 'fixed-provider-denial')
                return real_open(path, flags, *args, **kwargs)

            with patch.object(probe, 'PROVIDER_CANARY', canary), \
                    patch.object(probe.os, 'open', side_effect=denied):
                result = probe.provider_authority(data)
            self.assertEqual({'opened': False, 'errno': 'EACCES'}, result['outcome'])
            self.assertEqual(hashlib.sha256(os.fsencode(canary)).hexdigest(),
                             result['targetPathDigest'])
            self.assertEqual(result, json.loads((data / probe.PROVIDER_RESULT).read_text()))
            self.assertFalse((data / ('.' + probe.PROVIDER_RESULT + '.pending')).exists())
            self.assertNotIn('private-provider-bytes', json.dumps(result))
            with self.assertRaisesRegex(ValueError, 'already-published'):
                probe.provider_authority(data)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux mount namespace syscall required')
    def test_second_launch_replaces_only_fixed_result_without_token_output(self):
        script = Path(__file__).with_name('pr315-probe-app') / 'bin/probe.py'
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            target = data / 'pr315-probe-result.json'
            environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                           'CRYPTAD_APP_TOKEN': 'test-token-must-not-appear',
                           'CRYPTAD_APP_DATA_DIR': str(data)}
            records = []
            for _ in range(2):
                process = subprocess.Popen([sys.executable, '-I', '-S', '-B', str(script)],
                                           stdin=subprocess.DEVNULL,
                                           stdout=subprocess.DEVNULL,
                                           stderr=subprocess.PIPE, env=environment)
                try:
                    until = time.monotonic() + 5
                    while time.monotonic() < until:
                        if target.is_file():
                            value = json.loads(target.read_text())
                            if not records or value['startedMonotonicNs'] > records[-1]['startedMonotonicNs']:
                                records.append(value)
                                break
                        if process.poll() is not None:
                            self.fail('probe worker exited before writing result')
                        time.sleep(.02)
                    else:
                        self.fail('probe worker did not replace fixed result')
                finally:
                    process.terminate()
                    process.communicate(timeout=2)
            self.assertEqual(2, len(records))
            self.assertNotEqual(records[0]['pid'], records[1]['pid'])
            self.assertEqual('unshare-mount', records[1]['mountEscape']['operation'])
            self.assertEqual(records[0], json.loads((data / 'pr315-probe-result-first.json').read_text()))
            self.assertEqual(records[1], json.loads((data / 'pr315-probe-result-second.json').read_text()))
            self.assertFalse((data / '.pr315-probe-result.new').exists())
            self.assertNotIn('test-token-must-not-appear', target.read_text())
            third = subprocess.run([sys.executable, '-I', '-S', '-B', str(script)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, env=environment, timeout=2)
            self.assertNotEqual(0, third.returncode)
            self.assertEqual(records[1], json.loads(target.read_text()))


if __name__ == '__main__':
    unittest.main()
