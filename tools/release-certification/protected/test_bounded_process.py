import os
import sys
import time
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from bounded_process import run


class BoundedProcessTest(unittest.TestCase):
    def test_stdout_limit_terminates_only_created_helper(self):
        with self.assertRaisesRegex(ValueError, "output_exceeded"):
            run([sys.executable, "-c", "import os; os.write(1, b'x' * 65536)"],
                environment={"PATH": "/usr/bin:/bin"}, output_limit=1024)

    def test_stdin_not_consumed_cannot_block_deadline(self):
        started = time.monotonic()
        with self.assertRaisesRegex(ValueError, "deadline_exceeded"):
            run([sys.executable, "-c", "import time; time.sleep(60)"],
                environment={"PATH": "/usr/bin:/bin"}, payload=b"x" * 16384, timeout=0.15)
        self.assertLess(time.monotonic() - started, 3)

    def test_exited_leader_with_descendant_pipes_still_hits_deadline(self):
        started = time.monotonic()
        with self.assertRaisesRegex(ValueError, "deadline_exceeded"):
            run([sys.executable, "-c", "import os,time; child=os.fork(); time.sleep(60) if child == 0 else os._exit(0)"],
                environment={"PATH": "/usr/bin:/bin"}, timeout=0.15)
        self.assertLess(time.monotonic() - started, 3)

    def test_environment_is_the_closed_selected_environment(self):
        output = run([sys.executable, "-c", "import os; print(sorted(os.environ))"],
                     environment={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        self.assertNotIn(b"TOKEN", output)
        self.assertNotIn(b"HOME", output)

    def test_private_diagnostic_sink_receives_both_streams_without_changing_return(self):
        observations = []
        output = run([sys.executable, "-c", "import os; os.write(1,b'out'); os.write(2,b'err')"],
                     environment={"PATH": "/usr/bin:/bin"},
                     diagnostic_sink=lambda stdout, stderr: observations.append((stdout, stderr)))
        self.assertEqual(b"out", output)
        self.assertEqual([(b"out", b"err")], observations)

    def test_failed_exec_notifies_sink_with_empty_streams(self):
        observations = []
        with self.assertRaises(FileNotFoundError):
            run(["/nonexistent-pr312-fixed-test-command"], environment={"PATH": "/usr/bin:/bin"},
                diagnostic_sink=lambda stdout, stderr: observations.append((stdout, stderr)))
        self.assertEqual([(b"", b"")], observations)

    def test_failed_exit_preserves_private_diagnostics_and_closed_error(self):
        observations = []
        with self.assertRaisesRegex(ValueError, "^bounded_process_failed$"):
            run([sys.executable, "-c", "import os; os.write(1,b'private-out'); os.write(2,b'private-err'); os._exit(2)"],
                environment={"PATH": "/usr/bin:/bin"},
                diagnostic_sink=lambda stdout, stderr: observations.append((stdout, stderr)))
        self.assertEqual([(b"private-out", b"private-err")], observations)

    def test_overflow_diagnostics_are_truncated_to_the_budget(self):
        observations = []
        with self.assertRaisesRegex(ValueError, "output_exceeded"):
            run([sys.executable, "-c", "import os; os.write(1,b'x'*65536)"],
                environment={"PATH": "/usr/bin:/bin"}, output_limit=1024,
                diagnostic_sink=lambda stdout, stderr: observations.append((stdout, stderr)))
        self.assertEqual([(b"x" * 1024, b"")], observations)

    def test_timeout_sink_runs_after_owned_process_reaped(self):
        observations = []
        def sink(stdout, stderr):
            with self.assertRaises(ProcessLookupError):
                os.kill(int(stdout), 0)
            observations.append(stderr)
        with self.assertRaisesRegex(ValueError, "deadline_exceeded"):
            run([sys.executable, "-c",
                 "import os,time; os.write(1,str(os.getpid()).encode()); os.write(2,b'private'); time.sleep(60)"],
                environment={"PATH": "/usr/bin:/bin"}, timeout=0.3, diagnostic_sink=sink)
        self.assertEqual([b"private"], observations)

    def test_sink_failure_is_closed_and_cannot_prevent_owned_process_cleanup(self):
        reaped = []
        def sink(stdout, stderr):
            with self.assertRaises(ProcessLookupError):
                os.kill(int(stdout), 0)
            reaped.append(True)
            raise OSError("private-path-and-token")
        with self.assertRaisesRegex(ValueError, "^bounded_process_diagnostics_failed$"):
            run([sys.executable, "-c",
                 "import os,time; os.write(1,str(os.getpid()).encode()); time.sleep(60)"],
                environment={"PATH": "/usr/bin:/bin"}, timeout=0.3, diagnostic_sink=sink)
        self.assertEqual([True], reaped)


if __name__ == "__main__": unittest.main()
