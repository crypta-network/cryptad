#!/usr/bin/env python3
"""Fetch and confine one exact protected third-party pilot evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from stable_lifecycle_input_producer import (  # noqa: E402
    InputError,
    _NoRedirect,
    _PinnedHandler,
    _validated_locator,
)
from cryptad_certification.engines.stable_1_0_third_party_pilot_inputs import (  # noqa: E402
    MAX_ARCHIVE_BYTES,
    assemble,
)


def _fetch_exact(
    locator: str,
    token: str,
    expected_digest: str,
    expected_size: int,
    destination: Path,
) -> None:
    canonical, _host, _port, endpoints = _validated_locator(locator)
    if len(token) > 16 * 1024 or "\n" in token or "\r" in token:
        raise InputError("third-party-pilot-input-token-invalid")
    if not 1 <= expected_size <= MAX_ARCHIVE_BYTES:
        raise InputError("third-party-pilot-input-size-invalid")
    headers = {"Accept": "application/zip"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(canonical, headers=headers)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect(), _PinnedHandler(endpoints)
    )
    digest = hashlib.sha256()
    total = 0
    try:
        with opener.open(request, timeout=30) as response, destination.open("xb") as output:
            if response.status != 200:
                raise InputError("third-party-pilot-input-fetch-failed")
            while chunk := response.read(64 * 1024):
                total += len(chunk)
                if total > expected_size:
                    raise InputError("third-party-pilot-input-size-mismatch")
                digest.update(chunk)
                output.write(chunk)
    except InputError:
        destination.unlink(missing_ok=True)
        raise
    except (OSError, urllib.error.URLError, http.client.HTTPException) as exc:
        destination.unlink(missing_ok=True)
        raise InputError("third-party-pilot-input-fetch-failed") from exc
    if total != expected_size:
        destination.unlink(missing_ok=True)
        raise InputError("third-party-pilot-input-size-mismatch")
    if f"sha256:{digest.hexdigest()}" != expected_digest:
        destination.unlink(missing_ok=True)
        raise InputError("third-party-pilot-input-digest-mismatch")


def main(argv: list[str] | None = None) -> int:
    """Fetch authenticated bytes, then apply the exact-member confinement boundary."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--expected-size", type=int, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    locator = os.environ.get("CRYPTAD_THIRD_PARTY_PILOT_EVIDENCE_URL", "")
    token = os.environ.get("CRYPTAD_THIRD_PARTY_PILOT_EVIDENCE_TOKEN", "")
    try:
        _fetch_exact(
            locator,
            token,
            arguments.expected_digest,
            arguments.expected_size,
            arguments.archive,
        )
        assemble(
            arguments.archive,
            arguments.expected_digest,
            arguments.expected_size,
            arguments.output_dir,
        )
    except (InputError, ValueError) as exc:
        print(f"third-party-pilot-evidence: {exc}")
        return 2
    finally:
        arguments.archive.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
