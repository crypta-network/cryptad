"""Closed administrator boundary tests; mocked managers do not prove installation."""
from contextlib import nullcontext
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import pr319_restart_admin as admin


def fixtures(root):
    record = {"campaign": "c" * 64, "generation": "g" * 64,
              "managerInvocation": "a" * 32, "bootId": "b", "state": "running"}
    campaign = {"executionClass": admin.EXECUTION_CLASS,
                "budgetSelectionDigest": "sha256:" + "d" * 64,
                "deadlineMonotonicNs": time.monotonic_ns() + 60_000_000_000}
    user = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
    workload = SimpleNamespace(ROOT=Path(root), locked=nullcontext,
        retained=lambda _handle: (campaign, admin.ROLE, record),
        account=lambda _role: user, admit=Mock(), exact=Mock(),
        manager=Mock(return_value={"ActiveState": "inactive"}), boot=lambda: "b",
        _stop=Mock(), stop_receipt=Mock(return_value={"membership": "only-stop-helper"}))
    return workload, campaign, record


def make_store(root):
    apps = Path(root) / "state" / admin.ROLE / "data/node/apps"
    budget = apps / "network-budget/feed-reader"
    graph = apps / "trust-graph/statements"
    # mkdir(parents=True) applies mode only to the leaf; create every private ancestor.
    for leaf in (budget, graph):
        directory = Path(root)
        for part in leaf.relative_to(root).parts:
            directory /= part
            directory.mkdir(mode=0o700, exist_ok=True)
    counter = budget / admin.COUNTER
    counter.touch(mode=0o600)
    counter.write_text("# generated\nversion=1\nappId=feed-reader\noperation=trust_graph_import\n"
        "windowStart=2026-10-13T10\\:00\\:00Z\nwindowSeconds=3600\ncount=3\n"
        "lastDecisionAt=2026-10-13T10\\:01\\:00Z\nlastDecision=allowed\n")
    document = "f" * 64
    statement = graph / (document + ".properties")
    statement.touch(mode=0o600)
    statement.write_text("version=1\ndocumentFingerprint=" + document +
        "\npayloadHash=" + "e" * 64 + "\nsignatureVerified=true\nsource=app\n"
        "importedAt=2026-10-13T10\\:00\\:00Z\nupdatedAt=2026-10-13T10\\:01\\:00Z\n"
        'documentBytes=2\ndocumentJson={"type"\\:"synthetic"}\n')
    return budget, graph


class CaptureTest(unittest.TestCase):
    def test_private_store_is_capturable_under_group_writable_umask(self):
        previous = os.umask(0o002)
        try:
            with tempfile.TemporaryDirectory() as root:
                make_store(root)
                workload, _, _ = fixtures(root)
                value = admin._store_capture(workload, os.getuid())
                self.assertEqual(3, value["durableUsage"][0]["count"])
                self.assertEqual(1, len(value["graphFacts"]))
        finally:
            os.umask(previous)

    def test_real_properties_capture_retains_windows_decisions_and_graph_metadata(self):
        with tempfile.TemporaryDirectory() as root:
            make_store(root)
            workload, _, _ = fixtures(root)
            value = admin._store_capture(workload, os.getuid())
            usage = value["durableUsage"]
            self.assertEqual(1, len(usage))
            self.assertEqual({"appId": "feed-reader", "operation": "trust_graph_import",
                "windowStart": "2026-10-13T10:00:00Z", "windowSeconds": 3600,
                "count": 3, "limit": 32, "lastDecisionAt": "2026-10-13T10:01:00Z",
                "lastDecision": "allowed", "nextAvailableAt": None}, usage[0])
            self.assertEqual("2026-10-13T10:01:00Z", value["graphFacts"][0]["updatedAt"])
            self.assertEqual({"type": "synthetic"}, value["graphFacts"][0]["document"])
            self.assertTrue(value["graphFacts"][0]["signatureVerified"])

    def test_symlink_counter_and_same_count_metadata_change_are_distinct(self):
        with tempfile.TemporaryDirectory() as root:
            budget, graph = make_store(root)
            workload, _, _ = fixtures(root)
            before = admin._store_capture(workload, os.getuid())
            statement = next(graph.iterdir())
            statement.write_text(statement.read_text().replace("10\\:01", "10\\:02"))
            after = admin._store_capture(workload, os.getuid())
            self.assertEqual(before["durableUsage"], after["durableUsage"])
            self.assertEqual(len(before["graphFacts"]), len(after["graphFacts"]))
            self.assertNotEqual(before["graphFacts"], after["graphFacts"])
            (budget / admin.COUNTER).unlink()
            (budget / admin.COUNTER).symlink_to(statement)
            with self.assertRaises(OSError):
                admin._store_capture(workload, os.getuid())

    def test_duplicate_or_identity_mismatched_counter_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            budget, _ = make_store(root)
            workload, _, _ = fixtures(root)
            counter = budget / admin.COUNTER
            original = counter.read_text()
            for changed in (original + "count=0\n", original.replace("appId=feed-reader", "appId=budget-importer")):
                counter.write_text(changed)
                with self.assertRaises(ValueError):
                    admin._store_capture(workload, os.getuid())

    def test_initial_snapshot_is_read_only_and_data_substitution_rejected(self):
        workload, _, _ = fixtures("/unused")
        faults = admin.FixedRestartFaults(workload, "selected-handle")
        capture = {"durableUsage": [], "graphFacts": []}
        with patch.object(admin.os, "geteuid", return_value=0), \
                patch.object(admin, "_data", return_value={"inode": 1}), \
                patch.object(admin, "_store_capture", return_value=capture), \
                patch.object(admin, "_daemon", side_effect=lambda *_: (
                    {"hostPid": 777}, os.open(os.devnull, os.O_RDONLY))):
            self.assertEqual([], faults.request("restart:snapshot")["durableUsage"])
            self.assertEqual([], faults.request("restart:readback")["durableUsage"])
        with patch.object(admin.os, "geteuid", return_value=0), \
                patch.object(admin, "_data", return_value={"inode": 2}), \
                self.assertRaisesRegex(ValueError, "retained-data-changed"):
            faults.request("restart:readback")


class BoundaryTest(unittest.TestCase):
    def test_fixed_private_writer_preserves_existing_bytes_and_enforces_262k_cap(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "diagnostics.private.json"
            workload = SimpleNamespace(secured=Mock())
            value = {"classification": "private-kernel-diagnostics-not-acceptance",
                     "restartFaultReceipts": [], "before": {"privateObservation": "x" * 70000}}
            with patch.object(admin.os, "geteuid", return_value=0), \
                    patch.object(admin, "Path", return_value=target):
                admin.write_restart_diagnostics(workload, value)
                saved = target.read_bytes()
                self.assertGreater(len(saved), 65536)
                self.assertEqual(0o600, target.stat().st_mode & 0o777)
                with self.assertRaises(FileExistsError):
                    admin.write_restart_diagnostics(workload, value)
                self.assertEqual(saved, target.read_bytes())
                value["before"]["privateObservation"] = "x" * 262144
                with self.assertRaisesRegex(ValueError, "private-diagnostics-limit"):
                    admin.write_restart_diagnostics(workload, value)
                self.assertEqual(saved, target.read_bytes())
            self.assertEqual([target], list(Path(root).iterdir()))

    def test_closed_commands_never_accept_pid_path_signal_or_shell(self):
        workload, _, _ = fixtures("/unused")
        faults = admin.FixedRestartFaults(workload, "selected-handle")
        for command in ("kill:123", "abrupt-settled:SIGTERM", "/tmp:restore", "sh:rm"):
            with self.subTest(command=command), self.assertRaises(ValueError):
                faults.request(command)
        workload.admit.assert_not_called()

    def test_forced_fault_pins_actual_daemon_and_preserves_intent_before_signal(self):
        workload, _, _ = fixtures("/unused")
        faults = admin.FixedRestartFaults(workload, "selected-handle")
        row = {"hostPid": 777, "startTicks": 100, "executableDigest": "jdk"}
        descriptor = os.open(os.devnull, os.O_RDONLY)
        def signal_exact(fd, sig):
            self.assertEqual(descriptor, fd)
            self.assertEqual(signal.SIGKILL, sig)
            self.assertEqual("fault-intent", faults.receipts[-1]["phase"])
        with patch.object(admin.os, "geteuid", return_value=0), \
                patch.object(admin, "_data", return_value={"inode": 1}), \
                patch.object(admin, "_daemon", return_value=(row, descriptor)), \
                patch.object(admin, "_profile", return_value={"KillMode": "control-group"}), \
                patch.object(admin.select, "select", side_effect=[([], [], []), ([descriptor], [], [])]), \
                patch.object(admin.signal, "pidfd_send_signal", signal_exact, create=True):
            value = faults.request("abrupt-settled:terminate")
        self.assertTrue(value["pidfdDeathObserved"])
        self.assertEqual(row, value["daemon"])
        workload._stop.assert_called_once()
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_failed_forced_death_keeps_original_intent_and_blocks_credit(self):
        workload, _, _ = fixtures("/unused")
        faults = admin.FixedRestartFaults(workload, "selected-handle")
        descriptor = os.open(os.devnull, os.O_RDONLY)
        with patch.object(admin.os, "geteuid", return_value=0), \
                patch.object(admin, "_data", return_value={"inode": 1}), \
                patch.object(admin, "_daemon", return_value=({"hostPid": 777}, descriptor)), \
                patch.object(admin, "_profile", return_value={}), \
                patch.object(admin.select, "select", return_value=([], [], [])), \
                patch.object(admin.signal, "pidfd_send_signal", Mock(), create=True), \
                self.assertRaisesRegex(ValueError, "forced-daemon-death-unconfirmed"):
            faults.request("abrupt-inflight:terminate")
        self.assertEqual(["fault-intent"], [row["phase"] for row in faults.receipts])
        workload._stop.assert_not_called()

    def test_permission_restoration_touches_original_inode_and_rejects_replacement(self):
        with tempfile.TemporaryDirectory() as root:
            budget, _ = make_store(root)
            workload, _, _ = fixtures(root)
            faults = admin.FixedRestartFaults(workload, "selected-handle")
            original_mode = budget.stat().st_mode & 0o777
            with patch.object(admin.os, "geteuid", return_value=0), \
                    patch.object(admin, "_data", return_value={"inode": 1}), \
                    patch.object(admin, "_probe_access"):
                faults.request("diagnostics-enumeration:restrict")
                retained = budget.with_name("retained-feed-reader")
                budget.rename(retained)
                budget.mkdir(mode=0o700)
                replacement_mode = budget.stat().st_mode & 0o777
                with self.assertRaisesRegex(ValueError, "restoration-reconciliation-required"):
                    faults.request("diagnostics-enumeration:restore")
            self.assertEqual(original_mode, retained.stat().st_mode & 0o777)
            self.assertEqual(replacement_mode, budget.stat().st_mode & 0o777)
            self.assertFalse(faults.receipts[-1]["selectedPathUnchanged"])
            self.assertFalse(faults.receipts[-1]["contentsRestored"])

    def test_successful_wrapper_cannot_turn_killed_daemon_into_graceful_exit(self):
        workload, campaign, record = fixtures("/unused")
        faults = admin.FixedRestartFaults(workload, "selected-handle")
        faults.retained_data = {"inode": 1}
        descriptor = os.open(os.devnull, os.O_RDONLY)
        trace = Mock()
        trace.observe.return_value = {"normalExit": False, "exitCode": None, "signal": 9}
        faults.pinned = (campaign, record, {"hostPid": 777}, descriptor, trace, {})
        successful_wrapper = {"Result": "success", "ExecMainCode": "1", "ExecMainStatus": "0"}
        with patch.object(admin.os, "geteuid", return_value=0), \
                patch.object(admin, "_data", return_value={"inode": 1}), \
                patch.object(admin, "_profile", return_value=successful_wrapper), \
                patch.object(admin.select, "select", return_value=([descriptor], [], [])):
            value = faults.request("graceful:terminal")
        self.assertFalse(value["gracefulExitObserved"])
        self.assertIsNone(faults.pinned)
        trace.close.assert_called_once()

    def test_healthy_daemon_exit_cannot_hide_manager_escalation(self):
        workload, campaign, record = fixtures("/unused")
        faults = admin.FixedRestartFaults(workload, "selected-handle")
        faults.retained_data = {"inode": 1}
        descriptor = os.open(os.devnull, os.O_RDONLY)
        trace = Mock()
        trace.observe.return_value = {"normalExit": True, "exitCode": 0, "signal": None}
        faults.pinned = (campaign, record, {"hostPid": 777}, descriptor, trace, {})
        escalated = {"Result": "timeout", "ExecMainCode": "2", "ExecMainStatus": "9"}
        with patch.object(admin.os, "geteuid", return_value=0), \
                patch.object(admin, "_data", return_value={"inode": 1}), \
                patch.object(admin, "_profile", return_value=escalated), \
                patch.object(admin.select, "select", return_value=([descriptor], [], [])):
            self.assertFalse(faults.request("graceful:terminal")["gracefulExitObserved"])

    def test_normal_kernel_exit_and_successful_terminal_manager_are_required_together(self):
        workload, campaign, record = fixtures("/unused")
        faults = admin.FixedRestartFaults(workload, "selected-handle")
        faults.retained_data = {"inode": 1}
        descriptor = os.open(os.devnull, os.O_RDONLY)
        trace = Mock()
        trace.observe.return_value = {"normalExit": True, "exitCode": 0, "signal": None}
        faults.pinned = (campaign, record, {"hostPid": 777}, descriptor, trace, {})
        successful_wrapper = {"Result": "success", "ExecMainCode": "1", "ExecMainStatus": "0"}
        with patch.object(admin.os, "geteuid", return_value=0), \
                patch.object(admin, "_data", return_value={"inode": 1}), \
                patch.object(admin, "_profile", return_value=successful_wrapper), \
                patch.object(admin.select, "select", return_value=([descriptor], [], [])):
            self.assertTrue(faults.request("graceful:terminal")["gracefulExitObserved"])


@unittest.skipUnless(sys.platform == "linux", "requires real Linux ptrace provider")
class KernelExitTest(unittest.TestCase):
    def test_real_normal_process_exit_is_zero(self):
        child = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.buffer.read(1)"],
                                 stdin=subprocess.PIPE)
        trace = None
        try:
            try:
                trace = admin.KernelExitWitness(child.pid)
            except OSError as error:
                self.skipTest("kernel ptrace provider unavailable: errno " + str(error.errno))
            child.stdin.write(b"x")
            child.stdin.flush()
            value = trace.observe(time.monotonic() + 5)
            self.assertTrue(value["normalExit"])
            self.assertEqual(0, value["exitCode"])
            self.assertIsNone(value["signal"])
        finally:
            if trace is not None:
                trace.close()
            child.kill() if child.poll() is None else None
            child.wait(timeout=5)
            child.stdin.close()

    def test_actual_sigkill_never_satisfies_normal_exit(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        trace = None
        try:
            try:
                trace = admin.KernelExitWitness(child.pid)
            except OSError as error:
                self.skipTest("kernel ptrace provider unavailable: errno " + str(error.errno))
            child.kill()
            value = trace.observe(time.monotonic() + 5)
            self.assertFalse(value["normalExit"])
            self.assertEqual(signal.SIGKILL, value["signal"])
            self.assertIsNone(value["exitCode"])
        finally:
            if trace is not None:
                trace.close()
            child.kill() if child.poll() is None else None
            child.wait(timeout=5)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                     "requires disposable Linux root for real role UID access probes")
class RoleAccessTest(unittest.TestCase):
    def test_enumeration_only_profile_preserves_existing_exact_key_bytes(self):
        self._real_profile(True)

    def test_read_and_search_denial_proves_required_key_is_unreadable(self):
        self._real_profile(False)

    def _real_profile(self, enumeration_only):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "scope"
            directory.mkdir(mode=0o700)
            counter = directory / admin.COUNTER
            counter.write_bytes(b"count=3\n")
            os.chown(directory, 65534, 65534)
            os.chown(counter, 65534, 65534)
            counter.chmod(0o600)
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fchmod(descriptor, 0o300 if enumeration_only else 0o200)
                admin._probe_access(descriptor, 65534, 65534, enumeration_only,
                                    time.monotonic() + 3)
                self.assertEqual(b"count=3\n", counter.read_bytes())
            finally:
                os.fchmod(descriptor, 0o700)
                os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
