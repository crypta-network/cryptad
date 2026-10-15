#!/usr/bin/python3
"""Signed synthetic app worker: one owned URI import, env credential stays in this process."""
from __future__ import annotations
import array
import http.client
import json
import os
from pathlib import Path
import socket
import time
import urllib.parse

SOCKET_NAME = 'pr320-budget-owner.sock'
PORT = 19402
MAX_BODY = 2 * 1024 * 1024


class FixedHttp(http.client.HTTPConnection):
    def connect(self):
        raise ValueError('implicit-reconnect-forbidden')


def receive(channel):
    raw, ancillary, flags, _address = channel.recvmsg(8193, socket.CMSG_SPACE(array.array('i').itemsize))
    descriptors = array.array('i')
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors.frombytes(data[:len(data) - len(data) % descriptors.itemsize])
    try:
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(raw) > 8192 or len(descriptors) != 1:
            raise ValueError('task-shape-invalid')
        value = json.loads(raw)
        if (not isinstance(value, dict) or set(value) != {'schemaVersion', 'uri', 'deadlineMonotonicNs'}
                or value['schemaVersion'] != 1 or not isinstance(value['uri'], str)
                or not 1 <= len(value['uri']) <= 4096
                or not value['uri'].startswith(('SSK@', 'USK@'))
                or any(ord(c) < 32 for c in value['uri'])
                or type(value['deadlineMonotonicNs']) is not int
                or not 0 < value['deadlineMonotonicNs'] - time.monotonic_ns() <= 45_000_000_000):
            raise ValueError('task-shape-invalid')
        connected = socket.socket(fileno=descriptors[0])
        descriptors.pop()
        if connected.getpeername() != ('127.0.0.1', PORT):
            connected.close()
            raise ValueError('task-peer-invalid')
        return value, connected
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def perform(channel, task, connected, token):
    deadline = task['deadlineMonotonicNs'] / 1e9
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        connected.close()
        raise ValueError('task-expired')
    connection = FixedHttp('127.0.0.1', PORT, timeout=remaining)
    connection.sock = connected
    try:
        body = urllib.parse.urlencode({'uri': task['uri']}).encode()
        connection.request('POST', '/api/v1/trust-graph/import-uri', body=body,
            headers={'Accept': 'application/json', 'Authorization': 'Bearer ' + token,
                     'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': str(len(body))})
        channel.sendall(b'{"state":"request-written"}')
        connected.settimeout(max(.001, deadline - time.monotonic()))
        response = connection.getresponse()
        count = 0
        while True:
            if time.monotonic() >= deadline:
                raise ValueError('task-expired')
            connected.settimeout(max(.001, deadline - time.monotonic()))
            block = response.read1(min(65536, MAX_BODY + 1 - count))
            if not block:
                break
            count += len(block)
            if count > MAX_BODY:
                raise ValueError('task-output-limit')
        try:
            channel.sendall(json.dumps({'state': 'complete', 'status': response.status}).encode())
        except OSError:
            pass
    finally:
        connection.close()


def main():
    os.umask(0o077)
    if os.environ.get('CRYPTAD_APP_ID') not in ('feed-reader', 'budget-importer'):
        return 2
    token = os.environ.get('CRYPTAD_APP_TOKEN')
    if not isinstance(token, str) or not 1 <= len(token) <= 4096 or any(ord(c) < 32 for c in token):
        return 2
    root = Path(os.environ['CRYPTAD_APP_RUN_DIR'])
    path = root / SOCKET_NAME
    # Run-dir ownership and sandbox mapping are established by normal AppHost, not task JSON.
    if not root.is_absolute() or root.is_symlink() or path.exists() or path.is_symlink():
        return 2
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server:
        server.bind(str(path))
        os.chmod(path, 0o600)
        server.listen(1)
        server.settimeout(7500)
        try:
            channel, _address = server.accept()
            with channel:
                channel.settimeout(5)
                task, connected = receive(channel)
                perform(channel, task, connected, token)
        except (OSError, ValueError, KeyError, http.client.HTTPException):
            return 2
    return 0


if __name__ == '__main__':
    # No exception/body/token/path reaches ordinary app stdout or stderr.
    try:
        code = main()
    except Exception:
        code = 2
    raise SystemExit(code)
