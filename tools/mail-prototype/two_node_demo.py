#!/usr/bin/env python3
"""Explicit live Mail demonstration. Never emits private response bodies or target metadata."""
import argparse
import base64
import binascii
from contextlib import contextmanager
import json
import os
import signal
import time
import urllib.parse
import urllib.request

BODY = "PUBLIC SYNTHETIC CRYPTA MAIL PROTOTYPE DEMONSTRATION"
REPLY = "PUBLIC SYNTHETIC CRYPTA MAIL PROTOTYPE REPLY"


class DemoFailure(Exception):
    """Bounded failure without private details."""


class UncertainOutcome(DemoFailure):
    """A mutating command may have completed, so callers must reconcile it."""


@contextmanager
def _absolute_deadline(seconds):
    """Bound headers and complete body consumption, including a trickled response."""
    if seconds <= 0:
        raise DemoFailure()
    if not hasattr(signal, "SIGALRM"):
        yield
        return

    def expired(_signal, _frame):
        raise DemoFailure()

    previous = signal.getsignal(signal.SIGALRM)
    old_timer = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()
    selected = min(seconds, old_timer[0]) if old_timer[0] else seconds
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, selected)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        if old_timer[0]:
            remaining = max(0.000001, old_timer[0] - (time.monotonic() - started))
            signal.setitimer(signal.ITIMER_REAL, remaining, old_timer[1])


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DemoFailure()
        result[key] = value
    return result


def canary_exposed(data, canaries):
    """Find a canary through bounded raw, URL, JSON and Base64 decoding."""
    if not isinstance(data, bytes) or len(data) > 2 * 1024 * 1024:
        raise DemoFailure()
    needles = tuple(value.encode("utf-8") for value in canaries)
    pending, seen, consumed = [(data, 0)], set(), 0
    while pending:
        value, depth = pending.pop()
        marker = (value, depth)
        if marker in seen:
            continue
        seen.add(marker)
        consumed += len(value)
        if len(seen) > 256 or consumed > 8 * 1024 * 1024:
            raise DemoFailure()
        if any(needle in value for needle in needles):
            return True
        if depth >= 4:
            continue
        try:
            text = value.decode("utf-8")
        except UnicodeError:
            text = None
        if text is not None:
            unquoted = urllib.parse.unquote_to_bytes(text.replace("+", " "))
            if unquoted != value:
                pending.append((unquoted, depth + 1))
            try:
                decoded_json = json.loads(text, object_pairs_hook=_object)
            except (ValueError, TypeError):
                decoded_json = None
            stack = [decoded_json]
            while stack:
                selected = stack.pop()
                if isinstance(selected, str):
                    pending.append((selected.encode("utf-8"), depth + 1))
                elif isinstance(selected, dict):
                    stack.extend(selected.values())
                elif isinstance(selected, list):
                    stack.extend(selected)
            for field in text.replace(";", "&").split("&"):
                if "=" in field:
                    pending.append((field.split("=", 1)[1].encode("ascii", "ignore"),
                                    depth + 1))
        compact = value.strip()
        if 4 <= len(compact) <= 2 * 1024 * 1024 and len(compact) % 4 == 0:
            try:
                decoded = base64.b64decode(compact, validate=True)
            except (binascii.Error, ValueError):
                decoded = None
            if decoded is not None and decoded != compact:
                pending.append((decoded, depth + 1))
    return False


def target(value, api=False):
    """Accept only canonical literal-loopback targets with explicit ports."""
    try:
        parsed = urllib.parse.urlsplit(value)
        if (parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "::1")
                or parsed.port is None or not 1 <= parsed.port <= 65535
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment
                or parsed.path != ("/api/v1" if api else "")):
            raise DemoFailure()
        if any(c.isspace() for c in value):
            raise DemoFailure()
        return value
    except (ValueError, TypeError):
        raise DemoFailure() from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DemoFailure()


class StandaloneHttpTransport:
    """One bounded direct-loopback request for the standalone demonstration."""

    def __init__(self, api):
        self.api = target(api, True)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, path, encoded, headers, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DemoFailure()
        request = urllib.request.Request(
            self.api + path, data=encoded, headers=headers, method="POST")
        try:
            with _absolute_deadline(remaining):
                with self.opener.open(request, timeout=min(25, remaining)) as response:
                    raw = response.read(1048577)
                    if response.status != 200 or len(raw) > 1048576:
                        raise DemoFailure()
                    return raw
        except Exception:
            raise DemoFailure() from None


class Client:
    def __init__(self, api, origin, session, password=None, *, transport=None,
                 observer=None, role=None):
        self.api = target(api, True)
        self.origin = target(origin)
        if not session or len(session) > 4096 or any(c in session for c in "\r\n"):
            raise DemoFailure()
        self.session = session
        self.password = password
        self.transport = transport or StandaloneHttpTransport(self.api)
        if observer is not None and not callable(observer):
            raise DemoFailure()
        if observer is not None and role not in {"candidate-sender", "candidate-recipient"}:
            raise DemoFailure()
        self.observer = observer
        self.role = role

    def _observe_command(self, command, request_id, result, payload):
        """Emit only the identifiers needed by the trusted installed evidence consumer."""
        if self.observer is None:
            return
        status = result.get("status")
        if not isinstance(status, str) or not 1 <= len(status) <= 64:
            raise DemoFailure()
        event = {
            "kind": "mail-command",
            "role": self.role,
            "command": command,
            "requestId": request_id,
            "status": status,
            "observedMonotonicNs": time.monotonic_ns(),
        }
        payload = payload or {}
        if command in {"confirm-send", "retry"}:
            for key in ("operation", "reference"):
                if isinstance(result.get(key), str):
                    event[key] = result[key]
        elif command == "import-reference":
            if isinstance(payload.get("reference"), str):
                event["reference"] = payload["reference"]
            if isinstance(result.get("messageId"), str):
                event["messageId"] = result["messageId"]
        elif command == "read" and isinstance(payload.get("messageId"), str):
            event["messageId"] = payload["messageId"]
        elif command == "status":
            for source, target in (("operations", "operations"),
                                   ("messageIds", "messageIds")):
                value = result.get(source)
                if isinstance(value, str):
                    event[target] = [] if not value else value.split(",")
        self.observer(event)

    def post(self, path, parameters, host=False, *, deadline=None):
        if path not in ("/mail/command", "/mail/result", "/apps/mail-prototype/stop", "/apps/mail-prototype/start"):
            raise DemoFailure()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        values = dict(parameters)
        if host:
            if not self.password:
                raise DemoFailure()
            values["formPassword"] = self.password
        else:
            headers.update({"Origin": self.origin, "X-Crypta-App-Session": self.session})
        encoded = urllib.parse.urlencode(values).encode("ascii")
        if len(encoded) > 786432:
            raise DemoFailure()
        try:
            raw = self.transport.request(
                path, encoded, headers, deadline or time.monotonic() + 25)
            result = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
            if not isinstance(result, dict):
                raise DemoFailure()
            return result
        except Exception:
            raise DemoFailure() from None

    def command(self, command, payload=None, *, deadline=None):
        deadline = min(deadline or time.monotonic() + 28, time.monotonic() + 28)
        mutating = command not in {"status", "export-contact", "read"}
        raw = json.dumps(payload or {}, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        try:
            submitted = self.post("/mail/command", {
                "command": command,
                "payloadBase64": base64.b64encode(raw).decode("ascii")}, deadline=deadline)
            if set(submitted) != {"mail"} or not isinstance(submitted["mail"], dict):
                raise DemoFailure()
            frame = submitted["mail"]
            if set(frame) != {"requestId"}:
                raise DemoFailure()
            request_id = frame["requestId"]
            if (not isinstance(request_id, str) or not request_id
                    or len(request_id) > 256 or any(c in request_id for c in "\r\n")):
                raise DemoFailure()
            while time.monotonic() < deadline:
                response = self.post(
                    "/mail/result", {"requestId": request_id}, deadline=deadline)
                if set(response) != {"mail"} or not isinstance(response["mail"], dict):
                    raise DemoFailure()
                result = response["mail"]
                if result.get("status") == "complete":
                    if set(result) != {"status", "payloadBase64"}:
                        raise DemoFailure()
                    encoded = result["payloadBase64"]
                    if not isinstance(encoded, str) or len(encoded) > 393216:
                        raise DemoFailure()
                    raw_result = base64.b64decode(encoded, validate=True)
                    if base64.b64encode(raw_result).decode("ascii") != encoded:
                        raise DemoFailure()
                    decoded = json.loads(
                        raw_result.decode("utf-8"), object_pairs_hook=_object)
                    if not isinstance(decoded, dict):
                        raise DemoFailure()
                    self._observe_command(command, request_id, decoded, payload)
                    return decoded
                if result != {"status": "pending"}:
                    raise DemoFailure()
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    time.sleep(min(0.2, remaining))
            raise DemoFailure()
        except DemoFailure as error:
            if mutating:
                raise UncertainOutcome() from error
            raise
        except (binascii.Error, KeyError, TypeError, UnicodeError, ValueError) as error:
            if mutating:
                raise UncertainOutcome() from error
            raise DemoFailure() from None

    def restart(self):
        self.post("/apps/mail-prototype/stop", {}, host=True)
        self.post("/apps/mail-prototype/start", {}, host=True)
        # Browser sessions bind the installed bundle/origin, not the terminated process token.
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            try:
                self.command("status")
                return
            except DemoFailure:
                time.sleep(0.25)
        raise DemoFailure()


def expect(result, status):
    if result.get("status") != status:
        raise DemoFailure()
    return result


def pin(receiver, card):
    inspected = expect(receiver.command("import-contact", {"card": card}), "compare-fingerprint-out-of-band")
    fingerprint = inspected["fingerprint"]
    expect(receiver.command("approve-contact", {"fingerprint": fingerprint}), "contact-approved")
    return fingerprint


def _flow_event(observer, name):
    if observer is not None:
        observer({"kind": "mail-flow", "name": name,
                  "observedMonotonicNs": time.monotonic_ns()})


def send(sender, fingerprint, body, timeout, *, observer=None, label=None):
    deadline = time.monotonic() + timeout
    expect(sender.command("save-draft", {"fingerprint": fingerprint, "subject": "Public synthetic demo", "body": body}, deadline=deadline), "draft")
    preview = expect(sender.command("preview-send", deadline=deadline), "approval-required")
    if preview.get("body") != body:
        raise DemoFailure()
    queued = sender.command(
        "confirm-send", {"approval": preview["approval"]}, deadline=deadline)
    if queued.get("status") == "inserted":
        reference = queued.get("reference", "")
        if not reference.startswith("CHK@") or len(reference) > 512:
            raise DemoFailure()
        _flow_event(observer, label + "-inserted" if label else "inserted")
        return reference
    if queued.get("status") != "queued":
        raise UncertainOutcome()
    while time.monotonic() < deadline:
        result = sender.command(
            "retry", {"operation": queued["operation"]}, deadline=deadline)
        if result.get("status") == "inserted":
            reference = result.get("reference", "")
            if not reference.startswith("CHK@") or len(reference) > 512:
                raise DemoFailure()
            _flow_event(observer, label + "-inserted" if label else "inserted")
            return reference
        expect(result, "queued")
        time.sleep(min(2, max(0, deadline - time.monotonic())))
    raise UncertainOutcome()


def run_flow(alice, bob, timeout, restart, *, body=BODY, reply_body=REPLY,
             before_restart=None, after_worker_rebind=None,
             after_worker_restart=None, observer=None):
    # Check both before either initialization: a pre-existing dataset aborts all mutation.
    expect(alice.command("status"), "initialize-required")
    expect(bob.command("status"), "initialize-required")
    for client in (alice, bob):
        result = client.command("initialize")
        expect(result, "ready")
        if (result.get("initializationRecoveryEpoch") is not None
                or result.get("recovery") != "normal"):
            raise DemoFailure()
    a_card = alice.command("export-contact")["card"]
    b_card = bob.command("export-contact")["card"]
    if a_card == b_card:
        raise DemoFailure()
    b_pin = pin(alice, b_card)
    a_pin = pin(bob, a_card)
    reference = send(alice, b_pin, body, timeout, observer=observer,
                     label="sender")
    imported = expect(bob.command("import-reference", {"reference": reference, "confirmed": "yes"}), "accepted")
    _flow_event(observer, "recipient-accepted")
    read = expect(bob.command("read", {"messageId": imported["messageId"]}), "verified-local-copy")
    if read.get("body") != body:
        raise DemoFailure()
    _flow_event(observer, "recipient-read")
    wrong = alice.command("import-reference", {"reference": reference, "confirmed": "yes"})
    expect(wrong, "wrong-recipient")
    _flow_event(observer, "wrong-recipient")
    expect(bob.command(
        "import-reference", {"reference": reference, "confirmed": "yes"}), "duplicate")
    _flow_event(observer, "duplicate-before-worker-restart")
    if restart:
        if before_restart is not None:
            before_restart()
        bob.restart()
        if after_worker_rebind is not None:
            after_worker_rebind(bob)
        _flow_event(observer, "worker-restart")
        expect(bob.command(
            "import-reference", {"reference": reference, "confirmed": "yes"}), "duplicate")
        _flow_event(observer, "duplicate-after-worker-restart")
        if after_worker_restart is not None:
            after_worker_restart(bob, reference)
    reply_ref = send(bob, a_pin, reply_body, timeout, observer=observer,
                     label="recipient")
    reply = expect(alice.command("import-reference", {"reference": reply_ref, "confirmed": "yes"}), "accepted")
    _flow_event(observer, "sender-accepted")
    reply_read = expect(
        alice.command("read", {"messageId": reply["messageId"]}),
        "verified-local-copy")
    if reply_read.get("body") != reply_body:
        raise DemoFailure()
    _flow_event(observer, "sender-read")
    if observer is not None:
        alice.command("status")
        bob.command("status")
        _flow_event(observer, "final-status")
    return {"insertFetchDecrypt": "observed", "wrongRecipient": "observed",
            "duplicateBeforeRestart": "observed",
            "duplicateAfterRestart": "observed" if restart else "skipped",
            "duplicate": "observed", "reply": "observed",
            "restart": "observed" if restart else "skipped",
            "independentStoresAndSignedInstalls": "operator-attested",
            "securityReview": "unobserved", "releaseEligible": False,
            "overall": "observed-demo" if restart else "incomplete"}


class PrivateParser(argparse.ArgumentParser):
    def error(self, message):
        raise DemoFailure()


def parser():
    result = PrivateParser(description=__doc__)
    result.add_argument("--alice-api", required=True)
    result.add_argument("--bob-api", required=True)
    result.add_argument("--alice-origin", required=True)
    result.add_argument("--bob-origin", required=True)
    result.add_argument("--execute", action="store_true")
    result.add_argument("--disposable-targets", action="store_true")
    result.add_argument("--independent-vaults-signed-installs", action="store_true")
    result.add_argument("--restart-recipient", action="store_true")
    result.add_argument("--insert-timeout-seconds", type=int, default=600)
    return result


def validate_options(args):
    if not (args.execute and args.disposable_targets and args.independent_vaults_signed_installs):
        raise DemoFailure()
    apis = [target(args.alice_api, True), target(args.bob_api, True)]
    origins = [target(args.alice_origin), target(args.bob_origin)]
    if len(set(apis + origins)) != 4 or not 30 <= args.insert_timeout_seconds <= 1800:
        raise DemoFailure()
    authorities = [urllib.parse.urlsplit(value).netloc for value in apis + origins]
    if len(set(authorities)) != 4 or len({urllib.parse.urlsplit(value).port for value in apis + origins}) != 4:
        raise DemoFailure()


def main(argv=None):
    try:
        args = parser().parse_args(argv)
        validate_options(args)
        password = os.environ.get("CRYPTAD_MAIL_DEMO_BOB_FORM_PASSWORD")
        if args.restart_recipient and not password:
            raise DemoFailure()
        alice = Client(args.alice_api, args.alice_origin, os.environ.get("CRYPTAD_MAIL_DEMO_ALICE_SESSION"))
        bob = Client(args.bob_api, args.bob_origin, os.environ.get("CRYPTAD_MAIL_DEMO_BOB_SESSION"), password)
        summary = run_flow(alice, bob, args.insert_timeout_seconds, args.restart_recipient)
        print(json.dumps(summary, sort_keys=True))
        return 0 if summary["overall"] == "observed-demo" else 2
    except Exception:
        print('{"overall":"failed","privateDetails":"withheld","releaseEligible":false}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
