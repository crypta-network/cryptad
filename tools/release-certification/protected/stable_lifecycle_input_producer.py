#!/usr/bin/env python3
"""Fetch and safely expand one exact protected Stable lifecycle input bundle."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import os
from pathlib import Path, PurePosixPath
import re
import socket
import ssl
import stat
import urllib.error
import urllib.parse
import urllib.request
import zipfile


MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_MEMBERS = 128


class InputError(RuntimeError):
    """Bounded failure at the protected lifecycle input boundary."""


def _canonical_host(value: str) -> str:
    return value.rstrip(".").encode("idna").decode("ascii").lower()


def _validated_locator(raw: str) -> tuple[str, str, int, tuple[tuple[object, ...], ...]]:
    if not raw or len(raw) > 4096:
        raise InputError("protected-lifecycle-input-locator-invalid")
    try:
        parsed = urllib.parse.urlsplit(raw)
        host = parsed.hostname
        port = parsed.port or 443
    except (UnicodeError, ValueError) as exc:
        raise InputError("protected-lifecycle-input-locator-invalid") from exc
    if (
        parsed.scheme != "https"
        or not host
        or port != 443
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(ord(character) < 33 or ord(character) == 127 for character in raw)
        or parsed.path != urllib.parse.quote(urllib.parse.unquote(parsed.path), safe="/-._~")
        or any(part in {"", ".", ".."} for part in parsed.path.split("/")[1:])
    ):
        raise InputError("protected-lifecycle-input-locator-invalid")
    try:
        canonical_host = _canonical_host(host)
    except UnicodeError as exc:
        raise InputError("protected-lifecycle-input-locator-invalid") from exc
    canonical = urllib.parse.urlunsplit(("https", canonical_host, parsed.path, "", ""))
    if canonical != raw:
        raise InputError("protected-lifecycle-input-locator-not-canonical")
    try:
        rows = socket.getaddrinfo(
            canonical_host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    except OSError as exc:
        raise InputError("protected-lifecycle-input-locator-unresolvable") from exc
    endpoints: list[tuple[object, ...]] = []
    for family, socktype, proto, _canonname, sockaddr in rows:
        try:
            address = ipaddress.ip_address(sockaddr[0])
        except ValueError as exc:
            raise InputError("protected-lifecycle-input-address-invalid") from exc
        if not address.is_global:
            raise InputError("protected-lifecycle-input-address-not-public")
        endpoint = (family, socktype, proto, sockaddr)
        if endpoint not in endpoints:
            endpoints.append(endpoint)
    if not endpoints:
        raise InputError("protected-lifecycle-input-locator-unresolvable")
    return canonical, canonical_host, port, tuple(endpoints)


def _connect(
    endpoints: tuple[tuple[object, ...], ...], timeout: float | object
) -> socket.socket:
    last_error: OSError | None = None
    for family, socktype, proto, sockaddr in endpoints:
        connection = socket.socket(family, socktype, proto)
        try:
            if isinstance(timeout, (int, float)):
                connection.settimeout(timeout)
            connection.connect(sockaddr)
            expected = ipaddress.ip_address(sockaddr[0])
            actual = ipaddress.ip_address(connection.getpeername()[0])
            if actual != expected or not actual.is_global:
                raise OSError("peer does not equal the validated global endpoint")
            return connection
        except OSError as exc:
            last_error = exc
            connection.close()
    raise InputError("protected-lifecycle-input-connect-failed") from last_error


class _PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, *, endpoints: tuple[tuple[object, ...], ...], **kwargs: object):
        super().__init__(host, **kwargs)
        self._endpoints = endpoints

    def connect(self) -> None:
        if self._tunnel_host is not None:
            raise InputError("protected-lifecycle-input-tunnel-forbidden")
        raw = _connect(self._endpoints, self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class _PinnedHandler(urllib.request.HTTPSHandler):
    def __init__(self, endpoints: tuple[tuple[object, ...], ...]) -> None:
        super().__init__(context=ssl.create_default_context())
        self._endpoints = endpoints

    def https_open(self, request: urllib.request.Request):  # type: ignore[no-untyped-def]
        return self.do_open(
            lambda host, **kwargs: _PinnedConnection(
                host, endpoints=self._endpoints, **kwargs
            ),
            request,
        )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):  # type: ignore[no-untyped-def]
        raise urllib.error.HTTPError(
            request.full_url, code, "redirect forbidden", headers, file
        )


def _fetch(url: str, token: str, expected_digest: str, destination: Path) -> None:
    canonical, _host, _port, endpoints = _validated_locator(url)
    if not token or len(token) > 16 * 1024 or "\n" in token or "\r" in token:
        raise InputError("protected-lifecycle-input-token-invalid")
    request = urllib.request.Request(
        canonical,
        headers={"Accept": "application/zip", "Authorization": f"Bearer {token}"},
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect(), _PinnedHandler(endpoints)
    )
    digest = hashlib.sha256()
    total = 0
    try:
        with opener.open(request, timeout=30) as response, destination.open("xb") as output:
            if response.status != 200:
                raise InputError("protected-lifecycle-input-fetch-failed")
            while chunk := response.read(64 * 1024):
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise InputError("protected-lifecycle-input-archive-too-large")
                digest.update(chunk)
                output.write(chunk)
    except InputError:
        destination.unlink(missing_ok=True)
        raise
    except (OSError, urllib.error.URLError, http.client.HTTPException) as exc:
        destination.unlink(missing_ok=True)
        raise InputError("protected-lifecycle-input-fetch-failed") from exc
    if f"sha256:{digest.hexdigest()}" != expected_digest:
        destination.unlink(missing_ok=True)
        raise InputError("protected-lifecycle-input-digest-mismatch")


def _safe_name(raw: str) -> PurePosixPath:
    if (
        "\\" in raw
        or re.fullmatch(r"[A-Za-z0-9._/-]+", raw) is None
        or any(ord(character) < 32 for character in raw)
    ):
        raise InputError("protected-lifecycle-input-member-name-invalid")
    name = PurePosixPath(raw)
    if name.is_absolute() or not name.parts or any(part in {"", ".", ".."} for part in name.parts):
        raise InputError("protected-lifecycle-input-member-name-invalid")
    return name


def _extract(archive: Path, destination: Path) -> None:
    try:
        with zipfile.ZipFile(archive) as bundle:
            members = bundle.infolist()
            if not members or len(members) > MAX_MEMBERS:
                raise InputError("protected-lifecycle-input-member-count-invalid")
            names: set[PurePosixPath] = set()
            portable_names: set[str] = set()
            total = 0
            for member in members:
                name = _safe_name(member.filename.rstrip("/"))
                if name in names:
                    raise InputError("protected-lifecycle-input-member-duplicate")
                names.add(name)
                portable_name = name.as_posix().casefold()
                if portable_name in portable_names:
                    raise InputError("protected-lifecycle-input-member-duplicate")
                portable_names.add(portable_name)
                mode = member.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if (
                    member.flag_bits & 1
                    or stat.S_ISLNK(mode)
                    or file_type not in {0, stat.S_IFREG, stat.S_IFDIR}
                    or (not member.is_dir() and name.suffix.lower() in {".zip", ".tar", ".gz", ".tgz"})
                ):
                    raise InputError("protected-lifecycle-input-member-unsafe")
                if member.is_dir():
                    continue
                if member.file_size <= 0 or member.file_size > MAX_MEMBER_BYTES:
                    raise InputError("protected-lifecycle-input-member-size-invalid")
                total += member.file_size
                if total > MAX_ARCHIVE_BYTES:
                    raise InputError("protected-lifecycle-input-expanded-too-large")
                target = destination.joinpath(*name.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member) as source, target.open("xb") as output:
                    written = 0
                    while chunk := source.read(64 * 1024):
                        written += len(chunk)
                        if written > member.file_size:
                            raise InputError("protected-lifecycle-input-member-size-mismatch")
                        output.write(chunk)
                    if written != member.file_size:
                        raise InputError("protected-lifecycle-input-member-size-mismatch")
    except (OSError, zipfile.BadZipFile) as exc:
        raise InputError("protected-lifecycle-input-archive-invalid") from exc


def main() -> int:
    """Fetch, digest-check, and safely extract the reviewed lifecycle ZIP."""

    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--out", required=True, type=Path)
    arguments = parser.parse_args()
    if re.fullmatch(r"sha256:[0-9a-f]{64}", arguments.expected_digest) is None:
        raise InputError("protected-lifecycle-input-digest-invalid")
    url = os.environ.pop("CRYPTAD_STABLE_LIFECYCLE_INPUT_BUNDLE_URL", "")
    token = os.environ.pop("CRYPTAD_STABLE_LIFECYCLE_INPUT_BUNDLE_BEARER_TOKEN", "")
    archive = arguments.out.parent / "stable-lifecycle-input.zip"
    arguments.out.mkdir(parents=True, exist_ok=False)
    _fetch(url, token, arguments.expected_digest, archive)
    _extract(archive, arguments.out)
    archive.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InputError as error:
        print(f"stable lifecycle input producer failed closed: {error}")
        raise SystemExit(1) from None
