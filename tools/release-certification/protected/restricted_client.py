#!/usr/bin/python3
"""Submit one fixed registered operation; no sudo, credentials or path arguments."""
import argparse
from pathlib import Path
import socket
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from restricted_protocol import (BoundaryError, METHODS, MAX_REQUEST, MAX_RESULT,
                                 SOCKET, decode, encode, receive, request, send)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('method', choices=sorted(METHODS | {'collect'}))
    parser.add_argument('handle')
    args = parser.parse_args(argv)
    selected = request(encode({'method': args.method, 'handle': args.handle}))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(900)
        connection.connect(SOCKET)
        send(connection, selected, MAX_REQUEST)
        value = decode(receive(connection, MAX_RESULT, timeout=900), MAX_RESULT)
    if (not isinstance(value, dict) or set(value) != {'status', 'receipt', 'result'}
            or value['status'] != 'complete'):
        raise BoundaryError('restricted-operation-unavailable')
    # This is transport, not authority: the later owner checks its retained original result.
    sys.stdout.buffer.write(encode(value['result']) + b'\n')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, TypeError):
        print('restricted-operation-unavailable', file=sys.stderr)
        raise SystemExit(2) from None
