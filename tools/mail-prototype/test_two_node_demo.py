"""Offline validation of the opt-in driver; fixtures never establish live delivery."""
import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import Mock, call, patch

spec = importlib.util.spec_from_file_location("mail_demo", Path(__file__).with_name("two_node_demo.py"))
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class DemoTest(unittest.TestCase):
    def test_targets_reject_remote_redirect_credentials_and_paths(self):
        for value in ("https://127.0.0.1:8888/api/v1", "http://example.com:8888/api/v1",
                      "http://127.0.0.1/api/v1", "http://u:p@127.0.0.1:8888/api/v1",
                      "http://127.0.0.1:8888/api/v1?secret=x", "http://127.0.0.1:8888/other"):
            with self.assertRaises(demo.DemoFailure):
                demo.target(value, True)
        self.assertEqual("http://127.0.0.1:8888/api/v1", demo.target("http://127.0.0.1:8888/api/v1", True))

    def test_missing_opt_in_never_constructs_http_client(self):
        args = ["--alice-api", "http://127.0.0.1:8888/api/v1", "--bob-api", "http://127.0.0.1:8889/api/v1",
                "--alice-origin", "http://127.0.0.1:9000", "--bob-origin", "http://127.0.0.1:9001"]
        with patch.object(demo, "Client") as client, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(1, demo.main(args))
            client.assert_not_called()
            self.assertNotIn("127.0.0.1", output.getvalue())

    def test_fixture_client_uses_session_origin_and_bounded_command_results(self):
        client = demo.Client("http://127.0.0.1:8888/api/v1", "http://127.0.0.1:9000", "synthetic-session")
        value = demo.base64.b64encode(b'{"status":"fixture-only"}').decode()
        with patch.object(client, "post", side_effect=[{"mail": {"requestId": "synthetic-id"}},
                                                       {"mail": {"status": "complete", "payloadBase64": value}}]) as post:
            self.assertEqual({"status": "fixture-only"}, client.command("status"))
            self.assertEqual("/mail/command", post.call_args_list[0].args[0])
            self.assertEqual("/mail/result", post.call_args_list[1].args[0])

    def test_callable_private_bodies_and_scan_hook_preserve_original_protocol_flow(self):
        alice, bob = Mock(), Mock()
        alice.command.side_effect = [
            {"status": "initialize-required"}, {"status": "ready", "recovery": "normal"},
            {"card": "alice-card"},
            {"status": "wrong-recipient"}, {"status": "accepted", "messageId": "reply-id"},
            {"status": "verified-local-copy", "body": "private-reply"}]
        bob.command.side_effect = [
            {"status": "initialize-required"}, {"status": "ready", "recovery": "normal"},
            {"card": "bob-card"},
            {"status": "accepted", "messageId": "body-id"},
            {"status": "verified-local-copy", "body": "private-body"},
            {"status": "duplicate"}, {"status": "duplicate"}]
        observed = []
        bob.restart.side_effect = lambda: observed.append("restart")
        with patch.object(demo, "pin", side_effect=["bob-pin", "alice-pin"]), patch.object(demo, "send", side_effect=["first-ref", "reply-ref"]) as send:
            result = demo.run_flow(alice, bob, 30, True, body="private-body", reply_body="private-reply",
                                   before_restart=lambda: observed.append("scan"))
        self.assertEqual(["scan", "restart"], observed)
        self.assertEqual("private-body", send.call_args_list[0].args[2])
        self.assertEqual("private-reply", send.call_args_list[1].args[2])
        self.assertEqual("observed-demo", result["overall"])
        self.assertNotIn("private-body", str(result))

    def test_existing_mailbox_aborts_before_initialization(self):
        class Fixture:
            calls = []
            def command(self, command, payload=None):
                self.calls.append(command)
                return {"status": "initialized"}
        client = Fixture()
        with self.assertRaises(demo.DemoFailure):
            demo.run_flow(client, client, 30, False)
        self.assertEqual(["status"], client.calls)

    def test_recovered_initialization_cannot_be_credited_as_fresh(self):
        alice, bob = Mock(), Mock()
        alice.command.side_effect = [
            {"status": "initialize-required"},
            {"status": "ready", "recovery": "normal", "initializationRecoveryEpoch": "1"}]
        bob.command.side_effect = [
            {"status": "initialize-required"}, {"status": "ready", "recovery": "normal"}]
        with self.assertRaises(demo.DemoFailure):
            demo.run_flow(alice, bob, 30, False)
        self.assertEqual([call("status"), call("initialize")],
                         alice.command.call_args_list)
        self.assertEqual([call("status")], bob.command.call_args_list)

    def test_recovery_marker_on_second_role_aborts_before_initialization(self):
        alice, bob = Mock(), Mock()
        alice.command.return_value = {"status": "initialize-required"}
        bob.command.return_value = {"status": "initialization-recovery-required"}
        with self.assertRaises(demo.DemoFailure):
            demo.run_flow(alice, bob, 30, False)
        alice.command.assert_called_once_with("status")
        bob.command.assert_called_once_with("status")

    def test_injected_transport_receives_fixed_mail_request(self):
        class Transport:
            requests = []

            def request(self, path, encoded, headers, deadline):
                self.requests.append((path, encoded, headers, deadline))
                if path == "/mail/command":
                    return b'{"mail":{"requestId":"fixture"}}'
                value = demo.base64.b64encode(b'{"status":"ready"}').decode("ascii")
                return ('{"mail":{"status":"complete","payloadBase64":"'
                        + value + '"}}').encode("ascii")

        transport = Transport()
        client = demo.Client("http://127.0.0.1:8888/api/v1",
                             "http://127.0.0.1:9000", "session", transport=transport)
        self.assertEqual("ready", client.command("status")["status"])
        self.assertEqual(["/mail/command", "/mail/result"],
                         [request[0] for request in transport.requests])
        self.assertTrue(all(request[2]["Origin"] == "http://127.0.0.1:9000"
                            for request in transport.requests))

    def test_dropped_mutation_result_is_uncertain_and_never_resubmitted(self):
        submitted = {"mail": {"requestId": "fixture"}}
        client = demo.Client("http://127.0.0.1:8888/api/v1",
                             "http://127.0.0.1:9000", "session")
        with patch.object(client, "post", side_effect=[submitted, demo.DemoFailure()]) as post:
            with self.assertRaises(demo.UncertainOutcome):
                client.command("confirm-send", {"approval": "one-use"})
        self.assertEqual(1, sum(call.args[0] == "/mail/command"
                                for call in post.call_args_list))

    def test_trusted_observer_gets_causal_ids_without_secret_payload_fields(self):
        observed = []
        client = demo.Client("http://127.0.0.1:8888/api/v1",
                             "http://127.0.0.1:9000", "session-canary",
                             observer=observed.append, role="candidate-sender")
        terminal = {"status": "inserted", "operation": "a" * 32,
                    "reference": "CHK@private-reference"}
        encoded = demo.base64.b64encode(
            demo.json.dumps(terminal, separators=(",", ":")).encode()).decode()
        with patch.object(client, "post", side_effect=[
                {"mail": {"requestId": "broker-private-id"}},
                {"mail": {"status": "complete", "payloadBase64": encoded}}]):
            self.assertEqual(terminal, client.command(
                "confirm-send", {"approval": "approval-canary", "body": "body-canary"}))
        self.assertEqual(1, len(observed))
        self.assertEqual({"kind", "role", "command", "requestId", "status",
                          "observedMonotonicNs", "operation", "reference"},
                         set(observed[0]))
        self.assertEqual("broker-private-id", observed[0]["requestId"])
        serialized = str(observed)
        self.assertNotIn("approval-canary", serialized)
        self.assertNotIn("body-canary", serialized)
        self.assertNotIn("session-canary", serialized)

    def test_observer_requires_a_fixed_installed_role(self):
        with self.assertRaises(demo.DemoFailure):
            demo.Client("http://127.0.0.1:8888/api/v1",
                        "http://127.0.0.1:9000", "session",
                        observer=lambda _event: None)

    def test_duplicate_json_and_noncanonical_base64_fail_closed(self):
        client = demo.Client("http://127.0.0.1:8888/api/v1",
                             "http://127.0.0.1:9000", "session")
        duplicate = demo.base64.b64encode(b'{"status":"ready","status":"ready"}').decode()
        for encoded in (duplicate, "e30"):
            with self.subTest(encoded=encoded), patch.object(
                    client, "post", side_effect=[
                        {"mail": {"requestId": "fixture"}},
                        {"mail": {"status": "complete", "payloadBase64": encoded}}]):
                with self.assertRaises(demo.DemoFailure):
                    client.command("status")

    def test_terminal_confirm_failure_is_reconciliation_required(self):
        sender = Mock()
        sender.command.side_effect = [
            {"status": "draft"},
            {"status": "approval-required", "body": "body", "approval": "one-use"},
            {"status": "network-unavailable"}]
        with self.assertRaises(demo.UncertainOutcome):
            demo.send(sender, "fingerprint", "body", 30)
        self.assertEqual(3, sender.command.call_count)

    @unittest.skipUnless(hasattr(demo.signal, "SIGALRM"), "POSIX absolute timer required")
    def test_absolute_deadline_stops_a_dribbled_operation(self):
        started = demo.time.monotonic()
        with self.assertRaises(demo.DemoFailure), demo._absolute_deadline(0.01):
            demo.time.sleep(0.1)
        self.assertLess(demo.time.monotonic() - started, 0.08)

    def test_canary_scan_decodes_form_base64_and_enclosing_json(self):
        canary = "PUBLIC SYNTHETIC CANARY"
        payload = demo.json.dumps({"body": canary, "other": "value"},
                                  separators=(",", ":")).encode()
        encoded = demo.base64.b64encode(payload).decode("ascii")
        form = demo.urllib.parse.urlencode({"command": "save-draft",
                                            "payloadBase64": encoded}).encode()
        self.assertTrue(demo.canary_exposed(form, (canary,)))
        self.assertFalse(demo.canary_exposed(form, ("different-canary",)))


if __name__ == "__main__":
    unittest.main()
