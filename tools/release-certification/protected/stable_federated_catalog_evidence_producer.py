#!/usr/bin/env python3
"""Fetch and confine one exact public federated-catalog evidence archive."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))

from stable_lifecycle_input_producer import (  # noqa: E402
    InputError,
    _NoRedirect,
    _PinnedHandler,
    _validated_locator,
)

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 256


def _fetch_exact(locator: str, expected_digest: str, expected_size: int, destination: Path) -> None:
    canonical, _host, _port, endpoints = _validated_locator(locator)
    if not 1 <= expected_size <= MAX_ARCHIVE_BYTES:
        raise InputError("federated-catalog-input-size-invalid")
    request = urllib.request.Request(canonical, headers={"Accept": "application/zip"})
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect(), _PinnedHandler(endpoints)
    )
    digest = hashlib.sha256()
    total = 0
    try:
        with opener.open(request, timeout=30) as response, destination.open("xb") as output:
            if response.status != 200:
                raise InputError("federated-catalog-input-fetch-failed")
            while chunk := response.read(64 * 1024):
                total += len(chunk)
                if total > expected_size:
                    raise InputError("federated-catalog-input-size-mismatch")
                digest.update(chunk)
                output.write(chunk)
    except InputError:
        destination.unlink(missing_ok=True)
        raise
    except (OSError, urllib.error.URLError, http.client.HTTPException) as exc:
        destination.unlink(missing_ok=True)
        raise InputError("federated-catalog-input-fetch-failed") from exc
    if total != expected_size:
        raise InputError("federated-catalog-input-size-mismatch")
    if f"sha256:{digest.hexdigest()}" != expected_digest:
        raise InputError("federated-catalog-input-digest-mismatch")


def _extract_confined(archive: Path, output_dir: Path) -> None:
    destination = output_dir.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        if len(members) > MAX_MEMBERS:
            raise InputError("federated-catalog-input-member-count-invalid")
        if sum(member.file_size for member in members) > MAX_ARCHIVE_BYTES:
            raise InputError("federated-catalog-input-expanded-size-invalid")
        for member in members:
            target = (destination / member.filename).resolve()
            if target != destination and destination not in target.parents:
                raise InputError("federated-catalog-input-path-invalid")
            if member.is_dir():
                continue
            mode = member.external_attr >> 16
            if mode & 0o170000 == 0o120000:
                raise InputError("federated-catalog-input-link-invalid")
        source.extractall(destination)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--expected-size", required=True, type=int)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        _fetch_exact(
            os.environ.get("CRYPTAD_FEDERATED_CATALOG_EVIDENCE_URL", ""),
            arguments.expected_digest,
            arguments.expected_size,
            arguments.archive,
        )
        _extract_confined(arguments.archive, arguments.output_dir)
    except (InputError, OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"federated-catalog-evidence: {exc}")
        return 2
    finally:
        arguments.archive.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
