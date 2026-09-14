"""Closed local request framing; contains no private resolver imports or authority."""
from __future__ import annotations

import json
import re
import struct
import time

METHODS = frozenset({
    'maintenance-prepare', 'maintenance-validate', 'supervisor-authorize',
    'supervisor-start', 'supervisor-checkpoint', 'supervisor-finish',
    'baseline-prepare', 'baseline-approve',
})
MAX_REQUEST = 256
MAX_RESULT = 4 * 1024 * 1024
SOCKET = '/run/cryptad-restricted/control.sock'


class BoundaryError(ValueError):
    """Only fixed diagnostics cross the local client boundary."""


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def decode(raw, maximum):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise BoundaryError('restricted-invalid-json')
            value[key] = item
        return value
    try:
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= maximum:
            raise ValueError()
        result = json.loads(raw, object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        pending = [(result, 0)]
        count = 0
        while pending:
            item, depth = pending.pop()
            count += 1
            if depth > 32 or count > 32768:
                raise ValueError()
            if isinstance(item, dict):
                pending.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise BoundaryError('restricted-invalid-json') from None


def request(raw):
    value = decode(raw, MAX_REQUEST)
    if (not isinstance(value, dict) or set(value) != {'method', 'handle'}
            or value['method'] not in METHODS | {'collect'}
            or not isinstance(value['handle'], str)
            or re.fullmatch('[0-9a-f]{64}', value['handle']) is None):
        raise BoundaryError('restricted-invalid-request')
    return value


def receive(connection, maximum, *, timeout=5):
    """Bound the entire frame, including its prefix, by one monotonic deadline."""
    deadline = time.monotonic() + timeout
    previous_timeout = connection.gettimeout()
    def exact(count):
        result = bytearray()
        while len(result) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('restricted-frame-deadline')
            connection.settimeout(remaining)
            block = connection.recv(count - len(result))
            if time.monotonic() >= deadline:
                raise TimeoutError('restricted-frame-deadline')
            if not block:
                raise BoundaryError('restricted-incomplete-frame')
            result.extend(block)
        return bytes(result)
    try:
        size = struct.unpack('!I', exact(4))[0]
        if not 1 <= size <= maximum:
            raise BoundaryError('restricted-frame-limit')
        return exact(size)
    finally:
        connection.settimeout(previous_timeout)


def send(connection, value, maximum):
    raw = encode(value)
    if len(raw) > maximum:
        raise BoundaryError('restricted-frame-limit')
    connection.sendall(struct.pack('!I', len(raw)) + raw)
