"""Real fork lineage regressions; these records cannot grant installed acceptance."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest

import pr314_workload_driver as driver
import pr315_workload_fault_probes as faults


class StuckOutputActorTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux')
                         and os.environ.get('PR315_STUCK_ACTOR_DISPOSABLE') == '1',
                         'requires disposable Linux /probe.py and isolated /node/tmp')
    def test_real_fork_writer_keeps_parent_command_but_kernel_parent_selects_actor(self):
        nonce = 'c'*64
        self.assertTrue(Path('/probe.py').is_file())
        self.assertEqual(0o1777, Path('/node/tmp').stat().st_mode & 0o7777)
        parent = subprocess.Popen(['/usr/bin/setpriv', '--no-new-privs', '--',
            '/usr/bin/python3', '-I', '-S', '-B', '/probe.py', nonce, 'stuck-output'],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        writer_pid = None
        ready_path = Path('/node/tmp/pr315-stuck-output-ready.json')
        child_path = Path('/node/tmp/pr315-stuck-output-child.json')
        try:
            until = time.monotonic()+5
            while not child_path.is_file():
                if parent.poll() is not None:
                    self.fail('actual role probe exited: '+parent.stderr.read().decode())
                if time.monotonic()>=until:
                    self.fail('actual fork writer did not publish its record')
                time.sleep(.01)
            ready = json.loads(ready_path.read_bytes())
            child = json.loads(child_path.read_bytes())
            writer_pid = child['writerPid']
            self.assertEqual(parent.pid, ready['pid'])
            self.assertEqual(parent.pid, child['parentPid'])
            self.assertGreater(writer_pid, parent.pid)
            processes = []
            commands = []
            for pid in (parent.pid, writer_pid):
                proc = Path('/proc')/str(pid)
                status = dict(line.split(':',1) for line in (proc/'status').read_text().splitlines()
                              if ':' in line)
                fields = (proc/'stat').read_text().rsplit(')',1)[1].split()
                processes.append({'hostPid':pid,'hostParentPid':int(fields[1]),
                    'namespacePids':list(map(int,status['NSpid'].split())),
                    'startTicks':int(fields[19]),
                    'noNewPrivileges':status['NoNewPrivs'].strip()=='1',
                    'effectiveCapabilities':int(status['CapEff'].strip(),16)})
                commands.append((proc/'cmdline').read_bytes())
            self.assertEqual(commands[0],commands[1])
            self.assertEqual(parent.pid,processes[1]['hostParentPid'])
            observation={'processes':processes}
            with self.assertRaisesRegex(ValueError,'role-probe-actor-unavailable'):
                driver._role_probe_actor(observation,nonce,'stuck-output')
            actor,writer = faults._stuck_output_actor(observation,child,nonce)
            self.assertEqual(parent.pid,actor['hostPid'])
            self.assertEqual(writer_pid,writer['hostPid'])
            for changed in (
                    {'processes':[processes[1]]},
                    {'processes':[processes[0],dict(processes[1],hostParentPid=os.getpid())]},
                    {'processes':[dict(processes[0],effectiveCapabilities=1),processes[1]]}):
                with self.assertRaisesRegex(ValueError,'role-probe-actor-unavailable|writer-invalid'):
                    faults._stuck_output_actor(changed,child,nonce)
        finally:
            if writer_pid is not None:
                try:os.kill(writer_pid,signal.SIGTERM)
                except ProcessLookupError:pass
            if parent.poll() is None:parent.terminate()
            parent.wait(timeout=5)
            parent.stderr.close()


if __name__=='__main__':
    unittest.main()
