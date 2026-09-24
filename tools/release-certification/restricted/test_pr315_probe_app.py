"""Real local worker restart test; this is not installed AppHost acceptance."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


class ProbeWorkerTest(unittest.TestCase):
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
            self.assertFalse((data / '.pr315-probe-result.new').exists())
            self.assertNotIn('test-token-must-not-appear', target.read_text())


if __name__ == '__main__':
    unittest.main()
