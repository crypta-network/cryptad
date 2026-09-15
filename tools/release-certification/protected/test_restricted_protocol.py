"""Real bounded socket framing and closed schema tests; no isolation/deployment claim."""
import socket
import struct
import threading
import time
import unittest
from unittest.mock import Mock, patch

from restricted_protocol import BoundaryError, MAX_REQUEST, decode, encode, receive, request, send
from restricted_worker import validate_record


class RestrictedProtocolTest(unittest.TestCase):
    def test_exact_request_round_trip_over_local_socket(self):
        value = {'method': 'maintenance-validate', 'handle': 'a' * 64}
        left, right = socket.socketpair()
        with left, right:
            send(left, value, MAX_REQUEST)
            self.assertEqual(value, request(receive(right, MAX_REQUEST)))
            self.assertIsNone(right.gettimeout())

    def test_prefix_and_payload_share_one_deadline(self):
        clock = [0.0]
        left, right = socket.socketpair()
        with left, right:
            right.settimeout(17)
            left.sendall(struct.pack('!I', 2) + b'{}')
            connection = Mock(wraps=right)
            def delayed_receive(count):
                clock[0] += 3
                return right.recv(count)
            connection.recv.side_effect = delayed_receive
            with patch('restricted_protocol.time.monotonic', side_effect=lambda: clock[0]):
                with self.assertRaises(TimeoutError):
                    receive(connection, MAX_REQUEST)
            self.assertEqual([5, 2, 17],
                             [call.args[0] for call in connection.settimeout.call_args_list])
            self.assertEqual(17, right.gettimeout())

    def test_trickling_sender_cannot_extend_prefix_or_payload_deadline(self):
        for prefix_only in (True, False):
            with self.subTest(prefix_only=prefix_only):
                left, right = socket.socketpair()
                stop = threading.Event()
                def trickle():
                    frame = struct.pack('!I', 100) if prefix_only else b'x' * 100
                    try:
                        for byte in frame:
                            if stop.wait(.06 if prefix_only else .01):
                                break
                            left.sendall(bytes([byte]))
                    except OSError:
                        pass
                with left, right:
                    if not prefix_only:
                        left.sendall(struct.pack('!I', 100))
                    sender = threading.Thread(target=trickle)
                    sender.start()
                    started = time.monotonic()
                    try:
                        with self.assertRaises(TimeoutError):
                            receive(right, MAX_REQUEST, timeout=.15)
                        self.assertLess(time.monotonic() - started, .75)
                        self.assertIsNone(right.gettimeout())
                    finally:
                        stop.set()
                        sender.join(timeout=2)
                    self.assertFalse(sender.is_alive())

    def test_explicit_response_budget_can_exceed_request_budget(self):
        clock = [0.0]
        left, right = socket.socketpair()
        with left, right:
            send(left, {'status': 'unavailable'}, MAX_REQUEST)
            connection = Mock(wraps=right)
            def delayed_receive(count):
                clock[0] += 6
                return right.recv(count)
            connection.recv.side_effect = delayed_receive
            with patch('restricted_protocol.time.monotonic', side_effect=lambda: clock[0]):
                self.assertEqual({'status': 'unavailable'},
                                 decode(receive(connection, MAX_REQUEST, timeout=900), MAX_REQUEST))

    def test_arbitrary_method_paths_and_claims_rejected(self):
        for value in ({'method': 'exec', 'handle': 'a' * 64},
                      {'method': 'collect', 'handle': '../keys'},
                      {'method': 'collect', 'handle': 'a' * 64, 'runId': 123},
                      {'method': 'collect', 'handle': 'a' * 64, 'command': 'true'},
                      {'method': 'collect', 'handle': 'a' * 64, 'isolated': True}):
            with self.subTest(value=value), self.assertRaises(BoundaryError):
                request(encode(value))

    def test_duplicate_json_and_nonfinite_numbers_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises(BoundaryError):
                decode(raw, MAX_REQUEST)

    def test_oversize_header_rejected_without_reading_payload(self):
        left, right = socket.socketpair()
        with left, right:
            left.sendall(struct.pack('!I', MAX_REQUEST + 1))
            with self.assertRaises(BoundaryError):
                receive(right, MAX_REQUEST)

    def test_truncated_frame_rejected(self):
        left, right = socket.socketpair()
        with left, right:
            left.sendall(struct.pack('!I', 10) + b'abc')
            left.shutdown(socket.SHUT_WR)
            with self.assertRaises(BoundaryError):
                receive(right, MAX_REQUEST)

    def test_deep_json_fails_closed(self):
        with self.assertRaises(BoundaryError):
            decode(b'[' * 2000 + b'0' + b']' * 2000, 10000)

    def test_registration_rejects_unknown_fields_before_authority(self):
        with self.assertRaises(BoundaryError):
            validate_record({'isolationVerified': True})


if __name__ == '__main__':
    unittest.main()
