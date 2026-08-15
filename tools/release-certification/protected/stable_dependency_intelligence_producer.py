#!/usr/bin/env python3
"""Retrieve one reviewed public dependency-intelligence source safely.

This producer is the network-facing half of PR-290.  It never decides whether a
Stable component is affected.  It emits bounded raw bytes, deterministic adapter
records, retrieval facts, and producer provenance for the offline certification
engine.  Tests call :func:`produce_from_bytes`; only the protected workflow calls
the live retrieval path.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime as dt
import email.utils
import gzip
import hashlib
import http.client
import io
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import sys
from typing import Any, Callable, Mapping
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptad_certification.schema_validation import validate_schema  # noqa: E402


DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
IDENTIFIER_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
RUN_RE = re.compile(r"[1-9][0-9]*\Z")
SAFE_OUTPUTS = (
    "canonical-advisory-records.json",
    "producer-manifest.json",
    "raw-response.bin",
    "stable-1.0-dependency-intelligence-provenance.json",
    "stable-1.0-dependency-intelligence-source.json",
)
ALLOWED_CONTENT_TYPES = frozenset(("application/json", "application/gzip"))
REDIRECT_STATUSES = frozenset((301, 302, 303, 307, 308))
PARSER_VERSION = "1.1"
PURL_RE = re.compile(r"pkg:[a-z0-9.+-]+/[A-Za-z0-9._~%+@/?=&-]{1,504}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}\Z")
GHSA_RE = re.compile(
    r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-"
    r"[23456789cfghjmpqrvwx]{4}\Z",
    re.IGNORECASE,
)
CVE_RE = re.compile(r"CVE-(?:19|20)[0-9]{2}-[0-9]{4,19}\Z", re.IGNORECASE)
PUBLIC_ALIAS_RE = re.compile(r"[A-Z0-9][A-Z0-9._:-]{2,127}\Z")
OSV_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,255}\Z")
MAX_TRANSCRIPT_EXCHANGE_METADATA_BYTES = 64 * 1024
OSV_QUERY_BATCH_LIMIT = 1000
POLICY_SCHEMA = "stable-1.0-dependency-vulnerability-policy-v1.schema.json"


class ProducerError(RuntimeError):
    """A fail-closed error at the protected public-source boundary."""


@dataclass(frozen=True)
class Locator:
    """One canonical policy-approved endpoint and its validated global peers."""

    url: str
    host: str
    port: int
    endpoints: tuple[tuple[object, ...], ...]


@dataclass(frozen=True)
class Response:
    """One bounded HTTP response before content decoding."""

    status: int
    headers: Mapping[str, str]
    raw: bytes


@dataclass(frozen=True)
class Retrieval:
    """One complete bounded request/response series for a reviewed source."""

    response: Response
    redirect_chain: tuple[str, ...]
    exchanges: tuple[tuple[str, str, str, Response], ...]
    source_cursor: str | None
    request_body: bytes


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _semantic_digest(value: Mapping[str, Any], field: str) -> str:
    material = dict(value)
    material.pop(field, None)
    return _digest_bytes(_canonical_json(material))


def _timestamp(value: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ProducerError("dependency-intelligence-timestamp-invalid")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ProducerError("dependency-intelligence-timestamp-invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise ProducerError("dependency-intelligence-timestamp-invalid")
    return parsed


def _format_timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def load_policy(path: Path) -> dict[str, Any]:
    """Load the closed repository policy without accepting duplicate JSON keys."""

    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise ProducerError("dependency-intelligence-policy-duplicate-key")
            result[key] = value
        return result

    try:
        raw = path.read_bytes()
        if len(raw) > 1024 * 1024:
            raise ProducerError("dependency-intelligence-policy-too-large")
        value = json.loads(raw, object_pairs_hook=pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProducerError("dependency-intelligence-policy-invalid") from exc
    if not isinstance(value, dict) or value.get("kind") != (
        "stable-1.0-dependency-vulnerability-policy"
    ):
        raise ProducerError("dependency-intelligence-policy-invalid")
    schema_errors = validate_schema(value, POLICY_SCHEMA)
    if schema_errors:
        raise ProducerError(
            "dependency-intelligence-policy-schema-invalid: " + schema_errors[0]
        )
    if (
        not DIGEST_RE.fullmatch(str(value.get("policyDigest", "")))
        or _semantic_digest(value, "policyDigest") != value.get("policyDigest")
    ):
        raise ProducerError("dependency-intelligence-policy-digest-invalid")
    return value


def _source_policy(policy: Mapping[str, Any], source_id: str) -> dict[str, Any]:
    matches = [
        row
        for row in policy.get("sources", [])
        if isinstance(row, dict) and row.get("sourceId") == source_id
    ]
    if len(matches) != 1:
        raise ProducerError("dependency-intelligence-source-not-reviewed")
    return matches[0]


def _canonical_host(host: str) -> str:
    try:
        return host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ProducerError("dependency-intelligence-endpoint-invalid") from exc


def validate_endpoint(
    policy: Mapping[str, Any],
    source_id: str,
    raw_url: str,
    resolver: Callable[..., list[tuple[object, ...]]] = socket.getaddrinfo,
) -> Locator:
    """Require an exact reviewed HTTPS URL and validate every resolved peer."""

    if not raw_url or len(raw_url) > 4096 or any(ord(char) < 33 for char in raw_url):
        raise ProducerError("dependency-intelligence-endpoint-invalid")
    try:
        parsed = urllib.parse.urlsplit(raw_url)
        host = parsed.hostname
        port = parsed.port or 443
    except ValueError as exc:
        raise ProducerError("dependency-intelligence-endpoint-invalid") from exc
    if (
        parsed.scheme != "https"
        or not host
        or port != 443
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ProducerError("dependency-intelligence-endpoint-invalid")
    canonical_host = _canonical_host(host)
    canonical = urllib.parse.urlunsplit(
        ("https", canonical_host, parsed.path or "/", parsed.query, "")
    )
    if canonical != raw_url:
        raise ProducerError("dependency-intelligence-endpoint-not-canonical")
    source = _source_policy(policy, source_id)
    origin = urllib.parse.urlsplit(str(source.get("origin", "")))
    if origin.scheme != "https" or _canonical_host(origin.hostname or "") != canonical_host:
        raise ProducerError("dependency-intelligence-origin-mismatch")
    patterns = source.get("endpointPatterns", [])
    try:
        approved = any(
            isinstance(pattern, str) and re.fullmatch(pattern, canonical)
            for pattern in patterns
        )
    except re.error as exc:
        raise ProducerError("dependency-intelligence-endpoint-pattern-invalid") from exc
    if not approved:
        raise ProducerError("dependency-intelligence-endpoint-not-allowlisted")
    try:
        resolved = resolver(
            canonical_host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    except OSError as exc:
        raise ProducerError("dependency-intelligence-endpoint-unresolvable") from exc
    endpoints: list[tuple[object, ...]] = []
    for family, socktype, proto, _canonname, sockaddr in resolved:
        try:
            address = ipaddress.ip_address(sockaddr[0])
        except ValueError as exc:
            raise ProducerError("dependency-intelligence-address-invalid") from exc
        if not address.is_global:
            raise ProducerError("dependency-intelligence-address-not-global")
        endpoint = (family, socktype, proto, sockaddr)
        if endpoint not in endpoints:
            endpoints.append(endpoint)
    if not endpoints:
        raise ProducerError("dependency-intelligence-endpoint-unresolvable")
    return Locator(canonical, canonical_host, port, tuple(endpoints))


def _connect(endpoints: tuple[tuple[object, ...], ...], timeout: float) -> socket.socket:
    last_error: OSError | None = None
    for family, socktype, proto, sockaddr in endpoints:
        connection = socket.socket(family, socktype, proto)
        try:
            connection.settimeout(timeout)
            connection.connect(sockaddr)
            expected = ipaddress.ip_address(sockaddr[0])
            actual = ipaddress.ip_address(connection.getpeername()[0])
            if actual != expected or not actual.is_global:
                raise OSError("connected peer differs from validated global endpoint")
            return connection
        except OSError as exc:
            last_error = exc
            connection.close()
    raise ProducerError("dependency-intelligence-connect-failed") from last_error


class _PinnedConnection(http.client.HTTPSConnection):
    def __init__(
        self, host: str, *, endpoints: tuple[tuple[object, ...], ...], **kwargs: object
    ) -> None:
        super().__init__(host, **kwargs)
        self._endpoints = endpoints

    def connect(self) -> None:
        if self._tunnel_host is not None:
            raise ProducerError("dependency-intelligence-proxy-tunnel-forbidden")
        raw = _connect(self._endpoints, float(self.timeout or 30))
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
        return None


def _read_response(response: Any, maximum: int) -> bytes:
    value = bytearray()
    while chunk := response.read(min(64 * 1024, maximum + 1 - len(value))):
        value.extend(chunk)
        if len(value) > maximum:
            raise ProducerError("dependency-intelligence-response-too-large")
    return bytes(value)


def _request_once(
    locator: Locator,
    bounds: Mapping[str, Any],
    method: str,
    body: bytes,
    authorization: str | None = None,
) -> Response:
    if method not in {"GET", "POST"} or (method == "GET" and body):
        raise ProducerError("dependency-intelligence-request-contract-invalid")
    headers = {
        "Accept": "application/json, application/gzip",
        "User-Agent": "cryptad-pr290/1",
    }
    if authorization is not None:
        if (
            locator.host != "api.github.com"
            or not authorization
            or len(authorization) > 4096
            or "\r" in authorization
            or "\n" in authorization
            or any(ord(char) < 33 or ord(char) > 126 for char in authorization)
        ):
            raise ProducerError("dependency-intelligence-github-credential-invalid")
        headers["Accept"] = "application/vnd.github+json"
        headers["Authorization"] = "Bearer " + authorization
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    if method == "POST":
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        locator.url,
        headers=headers,
        data=body or None,
        method=method,
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
        _PinnedHandler(locator.endpoints),
    )
    maximum = int(bounds.get("maxResponseBytes", 0))
    timeout = min(
        float(bounds.get("connectTimeoutSeconds", 10))
        + float(bounds.get("readTimeoutSeconds", 30)),
        120,
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            return Response(
                int(response.status),
                {str(key).lower(): str(value) for key, value in response.headers.items()},
                _read_response(response, maximum),
            )
    except urllib.error.HTTPError as exc:
        return Response(
            int(exc.code),
            {str(key).lower(): str(value) for key, value in exc.headers.items()},
            _read_response(exc, maximum),
        )
    except (OSError, urllib.error.URLError, http.client.HTTPException) as exc:
        raise ProducerError("dependency-intelligence-fetch-failed") from exc


def _github_next_page(raw_link: str | None, current: str) -> str | None:
    """Return the one canonical GitHub ``rel=next`` target from a Link header."""

    if raw_link is None:
        return None
    if not raw_link or len(raw_link) > 16 * 1024 or "\r" in raw_link or "\n" in raw_link:
        raise ProducerError("dependency-intelligence-pagination-link-invalid")
    next_pages: list[str] = []
    for part in raw_link.split(","):
        match = re.fullmatch(
            r'\s*<([^<>\s]+)>\s*;\s*rel="([a-z]+)"(?:\s*;[^,]*)?\s*',
            part,
        )
        if match is None:
            raise ProducerError("dependency-intelligence-pagination-link-invalid")
        target, relation = match.groups()
        if relation == "next":
            next_pages.append(urllib.parse.urljoin(current, target))
    if len(next_pages) > 1:
        raise ProducerError("dependency-intelligence-pagination-link-ambiguous")
    return next_pages[0] if next_pages else None


def _validate_github_page_url(raw_url: str, *, initial: bool) -> None:
    """Permit only the complete, unfiltered Global Advisories traversal."""

    parsed = urllib.parse.urlsplit(raw_url)
    try:
        pairs = urllib.parse.parse_qsl(
            parsed.query, keep_blank_values=True, strict_parsing=True
        )
    except ValueError as exc:
        raise ProducerError("dependency-intelligence-github-pagination-invalid") from exc
    if parsed.path != "/advisories" or parsed.fragment:
        raise ProducerError("dependency-intelligence-github-pagination-invalid")
    if initial:
        valid = pairs == [("per_page", "100")]
    else:
        values = {key: value for key, value in pairs}
        cursors = [
            value for key, value in pairs if key in {"after", "before"}
        ]
        valid = (
            len(pairs) == 2
            and len(values) == 2
            and values.get("per_page") == "100"
            and len(cursors) == 1
            and 1 <= len(cursors[0]) <= 512
        )
    if not valid:
        raise ProducerError("dependency-intelligence-github-pagination-invalid")


def _osv_record_locator(
    policy: Mapping[str, Any],
    source_id: str,
    identifier: str,
    resolver: Callable[..., list[tuple[object, ...]]],
) -> Locator:
    """Build and validate one exact reviewed OSV full-record endpoint."""

    source = _source_policy(policy, source_id)
    if (
        source.get("sourceClass") != "osv-compatible"
        or source.get("origin") != "https://api.osv.dev"
        or OSV_ID_RE.fullmatch(identifier) is None
    ):
        raise ProducerError("dependency-intelligence-osv-record-endpoint-invalid")
    encoded = urllib.parse.quote(identifier, safe="-._~")
    url = f"https://api.osv.dev/v1/vulns/{encoded}"
    if urllib.parse.unquote(encoded) != identifier:
        raise ProducerError("dependency-intelligence-osv-record-endpoint-invalid")
    try:
        resolved = resolver(
            "api.osv.dev",
            443,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except OSError as exc:
        raise ProducerError("dependency-intelligence-endpoint-unresolvable") from exc
    endpoints: list[tuple[object, ...]] = []
    for family, socktype, proto, _canonname, sockaddr in resolved:
        try:
            address = ipaddress.ip_address(sockaddr[0])
        except ValueError as exc:
            raise ProducerError("dependency-intelligence-address-invalid") from exc
        if not address.is_global:
            raise ProducerError("dependency-intelligence-address-not-global")
        endpoint = (family, socktype, proto, sockaddr)
        if endpoint not in endpoints:
            endpoints.append(endpoint)
    if not endpoints:
        raise ProducerError("dependency-intelligence-endpoint-unresolvable")
    return Locator(url, "api.osv.dev", 443, tuple(endpoints))


def _osv_index_page(
    value: Any,
    expected_results: int | None,
) -> tuple[list[tuple[str, str]], list[str | None]]:
    """Validate one querybatch index page containing only id/modified summaries."""

    if not isinstance(value, dict) or set(value) != {"results"}:
        raise ProducerError("dependency-intelligence-osv-shape-invalid")
    results = value.get("results")
    if (
        not isinstance(results, list)
        or (expected_results is not None and len(results) != expected_results)
    ):
        raise ProducerError("dependency-intelligence-osv-result-count-mismatch")
    summaries: list[tuple[str, str]] = []
    tokens: list[str | None] = []
    for result in results:
        if (
            not isinstance(result, dict)
            or not set(result) <= {"vulns", "next_page_token"}
        ):
            raise ProducerError("dependency-intelligence-osv-shape-invalid")
        vulns = result.get("vulns", [])
        if not isinstance(vulns, list):
            raise ProducerError("dependency-intelligence-osv-shape-invalid")
        for row in vulns:
            if not isinstance(row, dict) or set(row) != {"id", "modified"}:
                raise ProducerError("dependency-intelligence-osv-index-record-invalid")
            identifier = row.get("id")
            modified = row.get("modified")
            if (
                not isinstance(identifier, str)
                or OSV_ID_RE.fullmatch(identifier) is None
                or not isinstance(modified, str)
            ):
                raise ProducerError("dependency-intelligence-osv-index-record-invalid")
            _timestamp(modified)
            summaries.append((identifier, modified))
        token = result.get("next_page_token")
        if token is not None and (
            not isinstance(token, str)
            or not 1 <= len(token) <= 2048
            or any(ord(char) < 33 or ord(char) > 126 for char in token)
        ):
            raise ProducerError("dependency-intelligence-osv-page-token-invalid")
        tokens.append(token)
    return summaries, tokens


def _osv_query_batches(queries: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Partition one complete inventory query into deterministic OSV request batches."""

    return [
        queries[offset : offset + OSV_QUERY_BATCH_LIMIT]
        for offset in range(0, len(queries), OSV_QUERY_BATCH_LIMIT)
    ]


def _retrieve_osv(
    policy: Mapping[str, Any],
    source_id: str,
    endpoint: str,
    request_body: bytes,
    resolver: Callable[..., list[tuple[object, ...]]],
    requester: Callable[[Locator, Mapping[str, Any], str, bytes], Response],
) -> Retrieval:
    """Retrieve every query page and hydrate each unique OSV id deterministically."""

    bounds = policy.get("networkBounds", {})
    maximum_responses = int(bounds.get("maxResponseCount", 0))
    maximum_redirects = int(bounds.get("maxRedirects", 0))
    exchanges: list[tuple[str, str, str, Response]] = []
    redirect_chain: list[str] = []
    response_bytes = 0
    decoded_bytes = 0

    def fetch(
        url: str,
        method: str,
        body: bytes,
        identifier: str | None = None,
    ) -> Response:
        nonlocal response_bytes, decoded_bytes
        current = url
        redirects = 0
        while True:
            if len(exchanges) >= maximum_responses:
                raise ProducerError("dependency-intelligence-response-count-exceeded")
            locator = (
                _osv_record_locator(policy, source_id, identifier, resolver)
                if identifier is not None
                else validate_endpoint(policy, source_id, current, resolver)
            )
            if identifier is not None and locator.url != current:
                raise ProducerError(
                    "dependency-intelligence-osv-record-endpoint-invalid"
                )
            response = requester(locator, bounds, method, body)
            response_bytes += len(body) + len(response.raw)
            if response_bytes > int(bounds.get("maxResponseBytes", 0)):
                raise ProducerError("dependency-intelligence-response-too-large")
            exchanges.append((locator.url, method, _digest_bytes(body), response))
            if response.status in REDIRECT_STATUSES:
                location = response.headers.get("location")
                if not location or redirects >= maximum_redirects:
                    raise ProducerError("dependency-intelligence-redirect-forbidden")
                if method == "POST" and response.status not in {307, 308}:
                    raise ProducerError(
                        "dependency-intelligence-post-redirect-forbidden"
                    )
                redirected = urllib.parse.urljoin(current, location)
                if identifier is not None:
                    raise ProducerError(
                        "dependency-intelligence-osv-record-redirect-forbidden"
                    )
                validate_endpoint(policy, source_id, redirected, resolver)
                if redirected == current or redirected in redirect_chain:
                    raise ProducerError("dependency-intelligence-redirect-cycle")
                redirect_chain.append(redirected)
                redirects += 1
                current = redirected
                continue
            if response.status != 200:
                raise ProducerError("dependency-intelligence-response-status-invalid")
            decoded_bytes += len(decode_response(response, bounds))
            if decoded_bytes > int(bounds.get("maxDecompressedBytes", 0)):
                raise ProducerError("dependency-intelligence-decompressed-too-large")
            return response

    request = parse_json(request_body, bounds)
    if (
        not isinstance(request, dict)
        or set(request) != {"queries"}
        or not isinstance(request.get("queries"), list)
        or not request["queries"]
        or request_body != _canonical_json(request)
    ):
        raise ProducerError("dependency-intelligence-osv-query-contract-required")
    initial_queries = request["queries"]
    maximum_queries = min(
        int(bounds.get("maxArrayItems", 0)),
        int(bounds.get("maxRecordCount", 0)),
    )
    if any(
        not isinstance(query, dict) or "page_token" in query
        for query in initial_queries
    ) or not 1 <= len(initial_queries) <= maximum_queries:
        raise ProducerError("dependency-intelligence-osv-query-contract-required")
    pending_batches = _osv_query_batches([dict(query) for query in initial_queries])
    summaries: dict[str, str] = {}
    casefolded_ids: dict[str, str] = {}
    seen_tokens: set[tuple[str, str]] = set()
    query_pages = 0
    initial_response: Response | None = None
    while pending_batches:
        pending = pending_batches.pop(0)
        body = _canonical_json({"queries": pending})
        response = fetch(endpoint, "POST", body)
        if initial_response is None:
            initial_response = response
        query_pages += 1
        page = parse_json(decode_response(response, bounds), bounds)
        page_summaries, tokens = _osv_index_page(page, len(pending))
        for identifier, modified in page_summaries:
            folded = identifier.casefold()
            if folded in casefolded_ids and casefolded_ids[folded] != identifier:
                raise ProducerError("dependency-intelligence-osv-id-collision")
            casefolded_ids[folded] = identifier
            previous = summaries.get(identifier)
            if previous is not None and _timestamp(previous) != _timestamp(modified):
                raise ProducerError("dependency-intelligence-osv-modified-conflict")
            summaries[identifier] = modified
        next_pending: list[dict[str, Any]] = []
        for query, token in zip(pending, tokens, strict=True):
            if token is None:
                continue
            base = dict(query)
            base.pop("page_token", None)
            key = (_digest_bytes(_canonical_json(base)), token)
            if key in seen_tokens:
                raise ProducerError("dependency-intelligence-osv-pagination-cycle")
            seen_tokens.add(key)
            base["page_token"] = token
            next_pending.append(base)
        if next_pending:
            pending_batches.append(next_pending)
    for identifier in sorted(summaries):
        locator = _osv_record_locator(policy, source_id, identifier, resolver)
        response = fetch(locator.url, "GET", b"", identifier)
        record = parse_json(decode_response(response, bounds), bounds)
        if (
            not isinstance(record, dict)
            or record.get("id") != identifier
            or not isinstance(record.get("modified"), str)
            or _timestamp(record["modified"]) != _timestamp(summaries[identifier])
        ):
            raise ProducerError("dependency-intelligence-osv-hydration-mismatch")
    assert initial_response is not None
    cursor = (
        "request="
        + _digest_bytes(request_body)
        + f";query-pages={query_pages};hydrated={len(summaries)}"
    )
    return Retrieval(
        initial_response,
        tuple(redirect_chain),
        tuple(exchanges),
        cursor,
        request_body,
    )


def retrieve(
    policy: Mapping[str, Any],
    source_id: str,
    endpoint: str,
    *,
    request_body: bytes = b"",
    github_token: str | None = None,
    resolver: Callable[..., list[tuple[object, ...]]] = socket.getaddrinfo,
    requester: Callable[[Locator, Mapping[str, Any], str, bytes], Response] = _request_once,
) -> Retrieval:
    """Retrieve every bounded source page while revalidating redirects and peers."""

    bounds = policy.get("networkBounds", {})
    maximum_redirects = int(bounds.get("maxRedirects", 0))
    maximum_responses = int(bounds.get("maxResponseCount", 0))
    source = _source_policy(policy, source_id)
    source_class = source.get("sourceClass")
    if source_class == "osv-compatible":
        if github_token is not None:
            raise ProducerError("dependency-intelligence-github-credential-irrelevant")
        if urllib.parse.urlsplit(endpoint).path != "/v1/querybatch" or not request_body:
            raise ProducerError("dependency-intelligence-osv-query-contract-required")
        return _retrieve_osv(
            policy,
            source_id,
            endpoint,
            request_body,
            resolver,
            requester,
        )
    else:
        if request_body:
            raise ProducerError("dependency-intelligence-request-body-irrelevant")
        method = "GET"
    if source_class == "github-advisory-public-export":
        if requester is _request_once and not github_token:
            raise ProducerError("dependency-intelligence-github-authentication-required")
    elif github_token is not None:
        raise ProducerError("dependency-intelligence-github-credential-irrelevant")
    if source_class == "github-advisory-public-export":
        _validate_github_page_url(endpoint, initial=True)
    current = endpoint
    chain: list[str] = []
    exchanges: list[tuple[str, str, str, Response]] = []
    seen_pages: set[str] = set()
    total_raw = len(request_body)
    total_decoded = 0
    if total_raw > int(bounds.get("maxResponseBytes", 0)):
        raise ProducerError("dependency-intelligence-request-body-too-large")
    for _response_count in range(1, maximum_responses + 1):
        locator = validate_endpoint(policy, source_id, current, resolver)
        response = (
            requester(locator, bounds, method, request_body, github_token)
            if requester is _request_once
            else requester(locator, bounds, method, request_body)
        )
        if github_token is not None and (
            github_token.encode("ascii") in response.raw
            or any(
                github_token in str(key) or github_token in str(value)
                for key, value in response.headers.items()
            )
        ):
            raise ProducerError("dependency-intelligence-github-credential-reflected")
        total_raw += len(response.raw)
        if total_raw > int(bounds.get("maxResponseBytes", 0)):
            raise ProducerError("dependency-intelligence-response-too-large")
        exchanges.append(
            (locator.url, method, _digest_bytes(request_body), response)
        )
        if response.status in REDIRECT_STATUSES:
            location = response.headers.get("location")
            if not location or len(chain) >= maximum_redirects:
                raise ProducerError("dependency-intelligence-redirect-forbidden")
            if method == "POST" and response.status not in {307, 308}:
                raise ProducerError("dependency-intelligence-post-redirect-forbidden")
            redirected = urllib.parse.urljoin(current, location)
            validate_endpoint(policy, source_id, redirected, resolver)
            if redirected in chain or redirected == current:
                raise ProducerError("dependency-intelligence-redirect-cycle")
            chain.append(redirected)
            current = redirected
            continue
        if response.status != 200:
            raise ProducerError("dependency-intelligence-response-status-invalid")
        total_decoded += len(decode_response(response, bounds))
        if total_decoded > int(bounds.get("maxDecompressedBytes", 0)):
            raise ProducerError("dependency-intelligence-decompressed-too-large")
        if source_class != "github-advisory-public-export":
            return Retrieval(
                response,
                tuple(chain),
                tuple(exchanges),
                "request=" + _digest_bytes(request_body) if request_body else None,
                request_body,
            )
        if current in seen_pages:
            raise ProducerError("dependency-intelligence-pagination-cycle")
        seen_pages.add(current)
        next_page = _github_next_page(response.headers.get("link"), current)
        if next_page is None:
            return Retrieval(
                response,
                tuple(chain),
                tuple(exchanges),
                "pages=" + str(len(seen_pages)) + ";last=" + _digest_bytes(current.encode("utf-8")),
                request_body,
            )
        if next_page in seen_pages:
            raise ProducerError("dependency-intelligence-pagination-cycle")
        _validate_github_page_url(next_page, initial=False)
        validate_endpoint(policy, source_id, next_page, resolver)
        current = next_page
    raise ProducerError("dependency-intelligence-response-count-exceeded")


def _bounded_gzip(raw: bytes, maximum: int) -> bytes:
    output = bytearray()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as stream:
            while chunk := stream.read(min(64 * 1024, maximum + 1 - len(output))):
                output.extend(chunk)
                if len(output) > maximum:
                    raise ProducerError("dependency-intelligence-decompressed-too-large")
    except (OSError, EOFError) as exc:
        raise ProducerError("dependency-intelligence-compression-invalid") from exc
    return bytes(output)


def decode_response(response: Response, bounds: Mapping[str, Any]) -> bytes:
    """Validate media type and decode only bounded JSON or gzip-compressed JSON."""

    content_type = response.headers.get("content-type", "").lower().strip()
    media_type = content_type.split(";", 1)[0].strip()
    encoding = response.headers.get("content-encoding", "identity").lower().strip()
    if media_type not in ALLOWED_CONTENT_TYPES or encoding not in {"identity", "gzip"}:
        raise ProducerError("dependency-intelligence-content-type-invalid")
    if len(response.raw) > int(bounds.get("maxResponseBytes", 0)):
        raise ProducerError("dependency-intelligence-response-too-large")
    decoded = response.raw
    if media_type == "application/gzip" or encoding == "gzip":
        decoded = _bounded_gzip(decoded, int(bounds.get("maxDecompressedBytes", 0)))
    if len(decoded) > int(bounds.get("maxDecompressedBytes", 0)):
        raise ProducerError("dependency-intelligence-decompressed-too-large")
    prefix = decoded.lstrip()[:64].lower()
    if prefix.startswith((b"<html", b"<!doctype html", b"<form", b"<?xml")):
        raise ProducerError("dependency-intelligence-html-response-rejected")
    return decoded


def _check_json_bounds(value: Any, bounds: Mapping[str, Any], depth: int = 0) -> None:
    if depth > int(bounds.get("maxJsonDepth", 0)):
        raise ProducerError("dependency-intelligence-json-depth-exceeded")
    maximum_string = int(bounds.get("maxStringBytes", 0))
    maximum_array = int(bounds.get("maxArrayItems", 0))
    if isinstance(value, str):
        if len(value.encode("utf-8")) > maximum_string:
            raise ProducerError("dependency-intelligence-json-string-too-large")
    elif isinstance(value, list):
        if len(value) > maximum_array:
            raise ProducerError("dependency-intelligence-json-array-too-large")
        for row in value:
            _check_json_bounds(row, bounds, depth + 1)
    elif isinstance(value, dict):
        if len(value) > maximum_array:
            raise ProducerError("dependency-intelligence-json-object-too-large")
        for key, row in value.items():
            _check_json_bounds(key, bounds, depth + 1)
            _check_json_bounds(row, bounds, depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise ProducerError("dependency-intelligence-json-number-invalid")
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise ProducerError("dependency-intelligence-json-value-invalid")


def parse_json(decoded: bytes, bounds: Mapping[str, Any]) -> Any:
    """Parse strict UTF-8 JSON and enforce structural bounds after parsing."""

    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise ProducerError("dependency-intelligence-json-duplicate-key")
            result[key] = value
        return result

    try:
        text = decoded.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProducerError("dependency-intelligence-json-invalid") from exc
    _check_json_bounds(value, bounds)
    return value


def build_osv_query_from_inventory(
    path: Path,
    bounds: Mapping[str, Any],
) -> tuple[bytes, str]:
    """Derive the complete canonical OSV batch from one authenticated PR-289 inventory."""

    try:
        raw = path.read_bytes()
        if len(raw) > int(bounds.get("maxDecompressedBytes", 0)):
            raise ProducerError("dependency-intelligence-component-inventory-too-large")
        value = parse_json(raw, bounds)
    except OSError as exc:
        raise ProducerError("dependency-intelligence-component-inventory-invalid") from exc
    required = {
        "schemaVersion",
        "kind",
        "releaseId",
        "buildVersion",
        "sourceCommit",
        "policyDigest",
        "resolvedDependencySnapshotDigest",
        "components",
        "inventoryDigest",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ProducerError("dependency-intelligence-component-inventory-shape-invalid")
    if (
        value.get("schemaVersion") != 1
        or value.get("kind") != "stable-1.0-component-inventory"
        or COMMIT_RE.fullmatch(str(value.get("sourceCommit", ""))) is None
        or value.get("inventoryDigest") != _semantic_digest(value, "inventoryDigest")
        or not DIGEST_RE.fullmatch(str(value.get("inventoryDigest", "")))
    ):
        raise ProducerError("dependency-intelligence-component-inventory-binding-invalid")
    components = value.get("components")
    if not isinstance(components, list):
        raise ProducerError("dependency-intelligence-component-inventory-shape-invalid")
    identities: set[tuple[str, str]] = set()
    for component in components:
        if not isinstance(component, dict):
            raise ProducerError("dependency-intelligence-component-inventory-shape-invalid")
        purl = component.get("purl")
        version = component.get("version")
        if (
            not isinstance(purl, str)
            or PURL_RE.fullmatch(purl) is None
            or not isinstance(version, str)
            or VERSION_RE.fullmatch(version) is None
        ):
            raise ProducerError("dependency-intelligence-component-identity-invalid")
        identities.add((_osv_query_purl(purl, version), version))
    maximum = min(
        int(bounds.get("maxArrayItems", 0)),
        int(bounds.get("maxRecordCount", 0)),
    )
    if not 1 <= len(identities) <= maximum:
        raise ProducerError("dependency-intelligence-osv-query-count-invalid")
    body = {
        "queries": [
            {"package": {"purl": purl}, "version": version}
            for purl, version in sorted(identities)
        ]
    }
    return _canonical_json(body), str(value["inventoryDigest"])


def _transcript_bytes(retrieval: Retrieval, inventory_digest: str | None) -> bytes:
    """Frame the exact request and every raw response without lossy concatenation."""

    value = bytearray(b"CRYPTAD-PR290-RAW-TRANSCRIPT-V1\n")

    def frame(raw: bytes) -> None:
        value.extend(len(raw).to_bytes(8, "big"))
        value.extend(raw)

    frame(retrieval.request_body)
    frame((inventory_digest or "").encode("ascii"))
    for url, method, request_digest, response in retrieval.exchanges:
        headers = {}
        for name in (
            "content-type",
            "content-encoding",
            "etag",
            "last-modified",
            "link",
            "location",
        ):
            child = response.headers.get(name)
            if child is not None:
                if len(child) > 16 * 1024 or "\r" in child or "\n" in child:
                    raise ProducerError("dependency-intelligence-response-header-invalid")
                headers[name] = child
        metadata = _canonical_json(
            {
                "url": url,
                "method": method,
                "requestBodyDigest": request_digest,
                "status": response.status,
                "headers": headers,
            }
        )
        if len(metadata) > MAX_TRANSCRIPT_EXCHANGE_METADATA_BYTES:
            raise ProducerError("dependency-intelligence-transcript-metadata-too-large")
        frame(metadata)
        frame(response.raw)
    return bytes(value)


def _combined_payload(
    source: Mapping[str, Any], retrieval: Retrieval, bounds: Mapping[str, Any]
) -> tuple[Any, int, str]:
    successful_exchanges = [
        exchange for exchange in retrieval.exchanges if exchange[3].status == 200
    ]
    successful = [exchange[3] for exchange in successful_exchanges]
    decoded = [decode_response(response, bounds) for response in successful]
    if sum(len(row) for row in decoded) > int(bounds.get("maxDecompressedBytes", 0)):
        raise ProducerError("dependency-intelligence-decompressed-too-large")
    content_types = {response.headers.get("content-type", "").lower().strip() for response in successful}
    if len(content_types) != 1:
        raise ProducerError("dependency-intelligence-content-type-changed")
    parsed = [parse_json(row, bounds) for row in decoded]
    source_class = source.get("sourceClass")
    if source_class == "github-advisory-public-export":
        if any(not isinstance(page, list) for page in parsed):
            raise ProducerError("dependency-intelligence-github-shape-invalid")
        payload: Any = [record for page in parsed for record in page]
    elif source_class == "osv-compatible":
        if not parsed:
            raise ProducerError("dependency-intelligence-osv-shape-invalid")
        request = parse_json(retrieval.request_body, bounds)
        if (
            not isinstance(request, dict)
            or set(request) != {"queries"}
            or not isinstance(request.get("queries"), list)
        ):
            raise ProducerError("dependency-intelligence-osv-query-contract-required")
        summaries: dict[str, str] = {}
        hydrated: dict[str, dict[str, Any]] = {}
        casefolded_ids: dict[str, str] = {}
        pending_batches = _osv_query_batches(
            [dict(query) for query in request["queries"]]
        )
        hydration_started = False
        seen_tokens: set[tuple[str, str]] = set()
        for exchange, page in zip(successful_exchanges, parsed, strict=True):
            url, method, request_digest, _response = exchange
            if method == "POST":
                if hydration_started or not pending_batches:
                    raise ProducerError(
                        "dependency-intelligence-osv-exchange-invalid"
                    )
                pending = pending_batches.pop(0)
                expected_body = _canonical_json({"queries": pending})
                if request_digest != _digest_bytes(expected_body):
                    raise ProducerError(
                        "dependency-intelligence-osv-exchange-invalid"
                    )
                page_summaries, tokens = _osv_index_page(page, len(pending))
                for identifier, modified in page_summaries:
                    folded = identifier.casefold()
                    if (
                        folded in casefolded_ids
                        and casefolded_ids[folded] != identifier
                    ):
                        raise ProducerError(
                            "dependency-intelligence-osv-id-collision"
                        )
                    casefolded_ids[folded] = identifier
                    previous = summaries.get(identifier)
                    if (
                        previous is not None
                        and _timestamp(previous) != _timestamp(modified)
                    ):
                        raise ProducerError(
                            "dependency-intelligence-osv-modified-conflict"
                        )
                    summaries[identifier] = modified
                next_pending: list[dict[str, Any]] = []
                for query, token in zip(pending, tokens, strict=True):
                    if token is None:
                        continue
                    base = dict(query)
                    base.pop("page_token", None)
                    key = (_digest_bytes(_canonical_json(base)), token)
                    if key in seen_tokens:
                        raise ProducerError(
                            "dependency-intelligence-osv-pagination-cycle"
                        )
                    seen_tokens.add(key)
                    base["page_token"] = token
                    next_pending.append(base)
                if next_pending:
                    pending_batches.append(next_pending)
            elif method == "GET" and urllib.parse.urlsplit(url).path.startswith(
                "/v1/vulns/"
            ):
                hydration_started = True
                if not isinstance(page, dict):
                    raise ProducerError(
                        "dependency-intelligence-osv-hydration-mismatch"
                    )
                identifier = page.get("id")
                expected_url = (
                    "https://api.osv.dev/v1/vulns/"
                    + urllib.parse.quote(str(identifier), safe="-._~")
                )
                if (
                    not isinstance(identifier, str)
                    or identifier in hydrated
                    or identifier not in summaries
                    or url != expected_url
                    or not isinstance(page.get("modified"), str)
                    or _timestamp(page["modified"])
                    != _timestamp(summaries[identifier])
                ):
                    raise ProducerError(
                        "dependency-intelligence-osv-hydration-mismatch"
                    )
                hydrated[identifier] = page
            else:
                raise ProducerError("dependency-intelligence-osv-exchange-invalid")
        if (
            pending_batches
            or set(hydrated) != set(summaries)
        ):
            raise ProducerError("dependency-intelligence-osv-hydration-incomplete")
        payload = {"vulns": [hydrated[key] for key in sorted(hydrated)]}
    else:
        if len(parsed) != 1:
            raise ProducerError("dependency-intelligence-vendor-response-count-invalid")
        payload = parsed[0]
    return payload, sum(len(row) for row in decoded), next(iter(content_types))


def _source_timestamp(value: Any, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        raise ProducerError("dependency-intelligence-advisory-timestamp-invalid")
    return _format_timestamp(_timestamp(value))


def _alias(identifier: str) -> dict[str, str]:
    normalized = identifier.upper()
    if normalized.startswith("CVE-"):
        if CVE_RE.fullmatch(normalized) is None:
            raise ProducerError("dependency-intelligence-advisory-alias-invalid")
        system = "CVE"
    elif normalized.startswith("GHSA-"):
        if GHSA_RE.fullmatch(normalized) is None:
            raise ProducerError("dependency-intelligence-advisory-alias-invalid")
        system = "GHSA"
    elif PUBLIC_ALIAS_RE.fullmatch(normalized):
        system = "OSV"
    else:
        raise ProducerError("dependency-intelligence-advisory-alias-invalid")
    return {"system": system, "identifier": normalized}


def _aliases(*collections: Any) -> list[dict[str, str]]:
    values: dict[tuple[str, str], dict[str, str]] = {}
    for collection in collections:
        if collection is None:
            continue
        rows = collection if isinstance(collection, list) else [collection]
        for row in rows:
            identifier = row.get("value") if isinstance(row, dict) else row
            if identifier is None:
                continue
            if not isinstance(identifier, str):
                raise ProducerError("dependency-intelligence-advisory-alias-invalid")
            alias = _alias(identifier)
            values[(alias["system"], alias["identifier"])] = alias
    if not values:
        raise ProducerError("dependency-intelligence-advisory-alias-invalid")
    return [values[key] for key in sorted(values)]


def _selector_purl(value: Any) -> str:
    if not isinstance(value, str) or PURL_RE.fullmatch(value) is None:
        raise ProducerError("dependency-intelligence-advisory-purl-invalid")
    base, marker, suffix = value.partition("?")
    fragment = ""
    if not marker:
        base, fragment_marker, fragment_value = value.partition("#")
        fragment = fragment_marker + fragment_value if fragment_marker else ""
    else:
        suffix, fragment_marker, fragment_value = suffix.partition("#")
        fragment = fragment_marker + fragment_value if fragment_marker else ""
    path, version_marker, _version = base.rpartition("@")
    if version_marker and "/" in path:
        base = path
    qualifier = "?" + suffix if marker else ""
    selector = base + qualifier + fragment
    if PURL_RE.fullmatch(selector) is None:
        raise ProducerError("dependency-intelligence-advisory-purl-invalid")
    return selector


def _osv_query_purl(value: str, version: str) -> str:
    """Return a versionless OSV package PURL bound to the separate query version."""

    base = value.split("#", 1)[0].split("?", 1)[0]
    _package, marker, encoded_version = base.rpartition("@")
    if not marker or not encoded_version:
        raise ProducerError("dependency-intelligence-component-purl-version-missing")
    if re.search(r"%(?![0-9A-Fa-f]{2})", encoded_version):
        raise ProducerError("dependency-intelligence-component-purl-version-invalid")
    try:
        purl_version = urllib.parse.unquote(encoded_version, errors="strict")
    except UnicodeDecodeError as exc:
        raise ProducerError(
            "dependency-intelligence-component-purl-version-invalid"
        ) from exc
    if purl_version != version:
        raise ProducerError("dependency-intelligence-component-purl-version-mismatch")
    return _selector_purl(value)


def _ecosystem_semantics(ecosystem: Any, purl: str) -> tuple[str, str]:
    normalized = str(ecosystem or "").casefold()
    package_type = purl[4:].split("/", 1)[0].casefold()
    if normalized == "maven" and package_type == "maven":
        return "Maven", "maven"
    if normalized == "debian" or package_type in {"deb", "deb-generic"}:
        return "Debian", "debian"
    if normalized in {"red hat", "rocky linux", "alma linux", "rpm"} or package_type == "rpm":
        return "RPM", "rpm"
    if normalized == "jdk" and package_type == "generic":
        return "JDK", "jdk"
    if normalized == "git" and package_type == "generic":
        return "Git", "git-exact"
    return "Unknown", "unsupported"


def _range_events(raw_ranges: Any, scheme: str) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(raw_ranges, list):
        raise ProducerError("dependency-intelligence-advisory-range-invalid")
    ranges: list[dict[str, Any]] = []
    fixed: set[str] = set()
    for raw_range in raw_ranges:
        if not isinstance(raw_range, dict) or not isinstance(raw_range.get("events"), list):
            raise ProducerError("dependency-intelligence-advisory-range-invalid")
        events: list[dict[str, str]] = []
        for raw_event in raw_range["events"]:
            if not isinstance(raw_event, dict) or len(raw_event) != 1:
                raise ProducerError("dependency-intelligence-advisory-range-invalid")
            event_type, version = next(iter(raw_event.items()))
            normalized_type = {"last_affected": "last-affected"}.get(
                str(event_type), str(event_type)
            )
            if normalized_type not in {"introduced", "fixed", "last-affected", "limit"}:
                raise ProducerError("dependency-intelligence-advisory-range-invalid")
            if not isinstance(version, str) or not 1 <= len(version) <= 256:
                raise ProducerError("dependency-intelligence-advisory-range-invalid")
            events.append({"type": normalized_type, "version": version})
            if normalized_type == "fixed":
                fixed.add(version)
        supported = scheme in {"maven", "semver", "jdk"} and str(
            raw_range.get("type", "")
        ).upper() in {"ECOSYSTEM", "SEMVER"}
        ranges.append(
            {
                "rangeType": "events" if supported else "unsupported-blocking",
                "events": events,
            }
        )
    return ranges, sorted(fixed)


def _github_purl(ecosystem: Any, package_name: Any) -> str:
    if not isinstance(ecosystem, str) or not isinstance(package_name, str) or not package_name:
        raise ProducerError("dependency-intelligence-github-package-invalid")
    if ecosystem.casefold() == "maven":
        coordinates = package_name.split(":")
        if len(coordinates) != 2 or any(not row for row in coordinates):
            raise ProducerError("dependency-intelligence-github-package-invalid")
        return "pkg:maven/" + "/".join(
            urllib.parse.quote(row, safe="-._~+") for row in coordinates
        )
    safe_ecosystem = urllib.parse.quote(ecosystem.casefold(), safe="-._~+")
    segments = [row for row in package_name.split("/") if row]
    if not segments:
        raise ProducerError("dependency-intelligence-github-package-invalid")
    encoded_name = "/".join(urllib.parse.quote(row, safe="-._~+") for row in segments)
    return f"pkg:generic/{safe_ecosystem}/{encoded_name}"


def _github_ranges(
    value: Any, scheme: str
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        raise ProducerError("dependency-intelligence-advisory-range-invalid")
    if scheme not in {"maven", "semver", "jdk"} or "||" in value:
        return [{"rangeType": "unsupported-blocking", "events": []}], [], []
    comparators = [row.strip() for row in value.split(",")]
    if len(comparators) == 1:
        exact = re.fullmatch(r"(?:=\s*)?([^<>=!,\s]+)", comparators[0])
        if exact is not None:
            version = exact.group(1)
            return [], [version], []
        upper = re.fullmatch(r"(<|<=)\s*([^<>=!,\s]+)", comparators[0])
        if upper is not None:
            upper_type = "fixed" if upper.group(1) == "<" else "last-affected"
            upper_version = upper.group(2)
            return (
                [
                    {
                        "rangeType": "events",
                        "events": [
                            {"type": "introduced", "version": "0"},
                            {"type": upper_type, "version": upper_version},
                        ],
                    }
                ],
                [],
                [upper_version] if upper_type == "fixed" else [],
            )
        return [{"rangeType": "unsupported-blocking", "events": []}], [], []
    if len(comparators) != 2:
        return [{"rangeType": "unsupported-blocking", "events": []}], [], []
    lower = re.fullmatch(r">=\s*([^<>=!,\s]+)", comparators[0])
    upper = re.fullmatch(r"(<|<=)\s*([^<>=!,\s]+)", comparators[1])
    if lower is None or upper is None:
        return [{"rangeType": "unsupported-blocking", "events": []}], [], []
    upper_type = "fixed" if upper.group(1) == "<" else "last-affected"
    upper_version = upper.group(2)
    events = [
        {"type": "introduced", "version": lower.group(1)},
        {"type": upper_type, "version": upper_version},
    ]
    return (
        [{"rangeType": "events", "events": events}],
        [],
        [upper_version] if upper_type == "fixed" else [],
    )


def _merge_claims(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for claim in claims:
        key = (claim["ecosystem"], claim["purlSelector"], claim["versionScheme"])
        target = merged.setdefault(
            key,
            {
                "ecosystem": key[0],
                "purlSelector": key[1],
                "versionScheme": key[2],
                "ranges": [],
                "affectedVersions": [],
                "fixedVersions": [],
                "affectedDigests": [],
            },
        )
        for field in ("ranges", "affectedVersions", "fixedVersions", "affectedDigests"):
            target[field].extend(claim[field])
    for claim in merged.values():
        for field in ("ranges", "affectedVersions", "fixedVersions", "affectedDigests"):
            claim[field] = sorted(
                {json.dumps(row, sort_keys=True) if isinstance(row, dict) else row for row in claim[field]}
            )
            if field == "ranges":
                claim[field] = [json.loads(row) for row in claim[field]]
    return [merged[key] for key in sorted(merged)]


def _osv_advisory(source_id: str, record: dict[str, Any], native_digest: str) -> dict[str, Any]:
    identity = record.get("id")
    if not isinstance(identity, str):
        raise ProducerError("dependency-intelligence-record-identity-invalid")
    claims = []
    affected = record.get("affected")
    if not isinstance(affected, list) or not affected:
        raise ProducerError("dependency-intelligence-advisory-package-claims-missing")
    for row in affected:
        if not isinstance(row, dict) or not isinstance(row.get("package"), dict):
            raise ProducerError("dependency-intelligence-advisory-package-invalid")
        package = row["package"]
        purl = _selector_purl(package.get("purl"))
        ecosystem, scheme = _ecosystem_semantics(package.get("ecosystem"), purl)
        ranges, fixed = _range_events(row.get("ranges", []), scheme)
        versions = row.get("versions", [])
        if not isinstance(versions, list) or any(
            not isinstance(version, str) or not 1 <= len(version) <= 256
            for version in versions
        ):
            raise ProducerError("dependency-intelligence-advisory-version-invalid")
        if not ranges and not versions:
            ranges = [{"rangeType": "unsupported-blocking", "events": []}]
        claims.append(
            {
                "ecosystem": ecosystem,
                "purlSelector": purl,
                "versionScheme": scheme,
                "ranges": ranges,
                "affectedVersions": sorted(set(versions)),
                "fixedVersions": fixed,
                "affectedDigests": [],
            }
        )
    references = sorted(
        {
            row["url"]
            for row in record.get("references", [])
            if isinstance(row, dict)
            and isinstance(row.get("url"), str)
            and row["url"].startswith("https://")
            and len(row["url"]) <= 4096
        }
    )
    severity = []
    for row in record.get("severity", []):
        if not isinstance(row, dict) or not isinstance(row.get("type"), str) or not isinstance(row.get("score"), str):
            raise ProducerError("dependency-intelligence-advisory-severity-invalid")
        severity.append(
            {"system": row["type"][:64], "value": row["score"][:64], "vector": row["score"][:512]}
        )
    withdrawn = _source_timestamp(record.get("withdrawn"), nullable=True)
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-dependency-advisory-record",
        "sourceId": source_id,
        "sourceRecordId": identity,
        "sourceRecordDigest": native_digest,
        "aliases": _aliases(identity, record.get("aliases")),
        "publishedAt": _source_timestamp(record.get("published"), nullable=True),
        "modifiedAt": _source_timestamp(record.get("modified")),
        "withdrawnAt": withdrawn,
        "status": "withdrawn" if withdrawn is not None else "active",
        "packageClaims": _merge_claims(claims),
        "severityClaims": sorted(severity, key=lambda row: (row["system"], row["value"], row["vector"])),
        "references": references,
    }


def _github_advisory(source_id: str, record: dict[str, Any], native_digest: str) -> dict[str, Any]:
    identity = record.get("ghsa_id")
    if not isinstance(identity, str):
        raise ProducerError("dependency-intelligence-record-identity-invalid")
    vulnerabilities = record.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        raise ProducerError("dependency-intelligence-advisory-package-claims-missing")
    claims = []
    for row in vulnerabilities:
        if not isinstance(row, dict) or not isinstance(row.get("package"), dict):
            raise ProducerError("dependency-intelligence-advisory-package-invalid")
        package = row["package"]
        purl = _github_purl(package.get("ecosystem"), package.get("name"))
        ecosystem, scheme = _ecosystem_semantics(package.get("ecosystem"), purl)
        ranges, affected_versions, fixed_versions = _github_ranges(
            row.get("vulnerable_version_range"), scheme
        )
        fixed = row.get("first_patched_version")
        if fixed is not None:
            if not isinstance(fixed, str) or not 1 <= len(fixed) <= 256:
                raise ProducerError("dependency-intelligence-advisory-version-invalid")
            fixed_versions.append(fixed)
        claims.append(
            {
                "ecosystem": ecosystem,
                "purlSelector": purl,
                "versionScheme": scheme,
                "ranges": ranges,
                "affectedVersions": affected_versions,
                "fixedVersions": sorted(set(fixed_versions)),
                "affectedDigests": [],
            }
        )
    references = sorted(
        {
            row
            for row in record.get("references", [])
            if isinstance(row, str) and row.startswith("https://") and len(row) <= 4096
        }
    )
    severity = []
    if isinstance(record.get("severity"), str):
        severity.append({"system": "GHSA", "value": record["severity"][:64], "vector": None})
    cvss = record.get("cvss")
    if isinstance(cvss, dict) and cvss.get("score") is not None:
        vector = cvss.get("vector_string")
        severity.append(
            {
                "system": "CVSS",
                "value": str(cvss["score"])[:64],
                "vector": vector[:512] if isinstance(vector, str) and vector else None,
            }
        )
    withdrawn = _source_timestamp(record.get("withdrawn_at"), nullable=True)
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-dependency-advisory-record",
        "sourceId": source_id,
        "sourceRecordId": identity,
        "sourceRecordDigest": native_digest,
        "aliases": _aliases(identity, record.get("cve_id"), record.get("identifiers")),
        "publishedAt": _source_timestamp(record.get("published_at"), nullable=True),
        "modifiedAt": _source_timestamp(record.get("updated_at")),
        "withdrawnAt": withdrawn,
        "status": "withdrawn" if withdrawn is not None else "active",
        "packageClaims": _merge_claims(claims),
        "severityClaims": sorted(severity, key=lambda row: (row["system"], row["value"])),
        "references": references,
    }


def adapt_records(source: Mapping[str, Any], payload: Any, bounds: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Apply one closed public adapter without performing alias or affectedness decisions."""

    source_class = source.get("sourceClass")
    if source_class == "osv-compatible":
        if isinstance(payload, dict) and isinstance(payload.get("vulns"), list):
            records = payload["vulns"]
        elif isinstance(payload, dict) and isinstance(payload.get("id"), str):
            records = [payload]
        else:
            raise ProducerError("dependency-intelligence-osv-shape-invalid")
        identity_field = "id"
    elif source_class == "github-advisory-public-export":
        if not isinstance(payload, list):
            raise ProducerError("dependency-intelligence-github-shape-invalid")
        records = payload
        identity_field = "ghsa_id"
    elif source_class == "vendor-structured-or-manual":
        if not isinstance(payload, dict) or not isinstance(payload.get("advisories"), list):
            raise ProducerError("dependency-intelligence-vendor-shape-invalid")
        records = payload["advisories"]
        identity_field = "advisoryId"
    else:
        raise ProducerError("dependency-intelligence-source-class-unsupported")
    if len(records) > int(bounds.get("maxRecordCount", 0)):
        raise ProducerError("dependency-intelligence-record-count-exceeded")
    by_identity: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise ProducerError("dependency-intelligence-record-invalid")
        identity = record.get(identity_field)
        if not isinstance(identity, str) or not identity or len(identity) > 256:
            raise ProducerError("dependency-intelligence-record-identity-invalid")
        if source_class == "github-advisory-public-export" and (
            record.get("private") is True
            or record.get("visibility") not in {None, "public"}
        ):
            raise ProducerError("dependency-intelligence-private-github-record-rejected")
        canonical_record = json.loads(_canonical_json(record))
        native_digest = _digest_bytes(_canonical_json(canonical_record))
        if source_class == "osv-compatible":
            row = _osv_advisory(str(source["sourceId"]), canonical_record, native_digest)
        elif source_class == "github-advisory-public-export":
            row = _github_advisory(str(source["sourceId"]), canonical_record, native_digest)
        else:
            row = dict(canonical_record)
            row.pop("advisoryId", None)
            row["sourceId"] = source["sourceId"]
            row["sourceRecordId"] = identity
            row["sourceRecordDigest"] = native_digest
            row.pop("recordDigest", None)
        row["recordDigest"] = _semantic_digest(row, "recordDigest")
        previous = by_identity.get(identity)
        if previous is not None and previous != row:
            raise ProducerError("dependency-intelligence-record-duplicate-conflict")
        by_identity[identity] = row
    return sorted(by_identity.values(), key=lambda row: row["recordDigest"])


def _write_exclusive(path: Path, value: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(value)
    except FileExistsError as exc:
        raise ProducerError("dependency-intelligence-output-exists") from exc


def _bounded_header(value: str | None, maximum: int) -> str | None:
    if value is None:
        return None
    if not value or len(value.encode("utf-8")) > maximum or "\r" in value or "\n" in value:
        raise ProducerError("dependency-intelligence-response-header-invalid")
    return value


def _last_modified(value: str | None) -> str | None:
    bounded = _bounded_header(value, 1024)
    if bounded is None:
        return None
    try:
        parsed = email.utils.parsedate_to_datetime(bounded)
    except (TypeError, ValueError) as exc:
        raise ProducerError("dependency-intelligence-last-modified-invalid") from exc
    if parsed.tzinfo is None:
        raise ProducerError("dependency-intelligence-last-modified-invalid")
    return _format_timestamp(parsed)


def produce_from_bytes(
    *,
    policy: Mapping[str, Any],
    source_id: str,
    endpoint: str,
    response: Response,
    redirect_chain: tuple[str, ...],
    exchanges: tuple[tuple[str, str, str, Response], ...] | None = None,
    source_cursor: str | None = None,
    request_body: bytes = b"",
    inventory_digest: str | None = None,
    retrieved_at: str,
    source_edition: str,
    previous_snapshot_digest: str | None,
    previous_source_edition: str | None,
    repository: str,
    workflow_ref: str,
    source_commit: str,
    source_ref: str,
    run_id: str,
    run_attempt: str,
    artifact_name: str,
    out_root: Path,
) -> dict[str, Any]:
    """Create the allowlisted producer bundle from fixed or retrieved response bytes."""

    if repository != "crypta-network/cryptad":
        raise ProducerError("dependency-intelligence-repository-invalid")
    if not COMMIT_RE.fullmatch(source_commit) or source_ref != f"commit:{source_commit}":
        raise ProducerError("dependency-intelligence-source-identity-invalid")
    expected_workflow = (
        "crypta-network/cryptad/.github/workflows/"
        "stable-1.0-dependency-intelligence-producer.yml@refs/heads/"
    )
    if not workflow_ref.startswith(expected_workflow) or not COMMIT_RE.fullmatch(source_commit):
        raise ProducerError("dependency-intelligence-workflow-ref-invalid")
    if not RUN_RE.fullmatch(run_id) or not RUN_RE.fullmatch(run_attempt):
        raise ProducerError("dependency-intelligence-run-identity-invalid")
    if not IDENTIFIER_RE.fullmatch(artifact_name):
        raise ProducerError("dependency-intelligence-artifact-name-invalid")
    if previous_snapshot_digest is not None and not DIGEST_RE.fullmatch(previous_snapshot_digest):
        raise ProducerError("dependency-intelligence-predecessor-digest-invalid")
    retrieved = _timestamp(retrieved_at)
    source = _source_policy(policy, source_id)
    if source.get("sourceClass") == "osv-compatible":
        if not isinstance(inventory_digest, str) or DIGEST_RE.fullmatch(inventory_digest) is None:
            raise ProducerError("dependency-intelligence-component-inventory-binding-required")
    elif inventory_digest is not None:
        raise ProducerError("dependency-intelligence-component-inventory-binding-irrelevant")
    bounds = policy.get("networkBounds", {})
    method = "POST" if request_body else "GET"
    retrieval = Retrieval(
        response,
        redirect_chain,
        exchanges
        or ((endpoint, method, _digest_bytes(request_body), response),),
        source_cursor,
        request_body,
    )
    if not 1 <= len(retrieval.exchanges) <= int(
        bounds.get("maxResponseCount", 0)
    ):
        raise ProducerError("dependency-intelligence-response-count-exceeded")
    if len(request_body) + sum(len(row[3].raw) for row in retrieval.exchanges) > int(
        bounds.get("maxResponseBytes", 0)
    ):
        raise ProducerError("dependency-intelligence-response-too-large")
    transcript = _transcript_bytes(retrieval, inventory_digest)
    if len(transcript) > int(bounds.get("maxDecompressedBytes", 0)):
        raise ProducerError("dependency-intelligence-transcript-too-large")
    raw_digest = _digest_bytes(transcript)
    payload, decompressed_bytes, content_type = _combined_payload(
        source, retrieval, bounds
    )
    records = adapt_records(source, payload, policy.get("networkBounds", {}))
    record_bytes = _canonical_json(records)
    maximum_record_bytes = int(
        policy.get("documentBounds", {}).get("maxCanonicalSourceRecordBytes", 0)
    )
    if maximum_record_bytes < 1 or len(record_bytes) > maximum_record_bytes:
        raise ProducerError("dependency-intelligence-canonical-records-too-large")
    record_set_digest = _digest_bytes(
        _canonical_json([row["recordDigest"] for row in records])
    )
    parser_digest = _digest_bytes(Path(__file__).read_bytes())
    content_digest = _digest_bytes(
        _canonical_json(
            {
                "rawContentDigest": raw_digest,
                "canonicalRecordSetDigest": record_set_digest,
                "componentInventoryDigest": inventory_digest,
                "endpoint": endpoint,
                "sourceEdition": source_edition,
            }
        )
    )
    provenance = {
        "schemaVersion": 1,
        "kind": "stable-1.0-dependency-intelligence-provenance",
        "repositoryIdentity": "github.com/crypta-network/cryptad",
        "sourceId": source_id,
        "workflowRef": workflow_ref,
        "workflowSha": source_commit,
        "runId": int(run_id),
        "runAttempt": int(run_attempt),
        "jobName": "produce-intelligence",
        "artifactName": artifact_name,
        "artifactDigest": content_digest,
        "sourceCommit": source_commit,
        "sourceRef": source_ref,
        "manifestDigest": content_digest,
        "policyDigest": policy["policyDigest"],
        "componentInventoryDigest": inventory_digest,
        "producerIdentity": f"github-actions:{workflow_ref}:{run_id}:{run_attempt}",
        "attestationDigest": content_digest,
    }
    provenance["provenanceDigest"] = _semantic_digest(provenance, "provenanceDigest")
    freshness = int(source.get("freshnessSeconds", 0))
    expires = retrieved + dt.timedelta(seconds=freshness)
    source_metadata = {
        "schemaVersion": 1,
        "kind": "stable-1.0-dependency-intelligence-source",
        "sourceId": source_id,
        "sourceClass": source["sourceClass"],
        "origin": source["origin"],
        "endpoint": endpoint,
        "retrievedAt": retrieved_at,
        "generatedAt": retrieved_at,
        "expiresAt": _format_timestamp(expires),
        "sourceEdition": int(source_edition) if source_edition.isdigit() else source_edition,
        "sourceCursor": source_cursor,
        "etag": (
            _bounded_header(response.headers.get("etag"), 1024)
            if len([row for row in retrieval.exchanges if row[3].status == 200]) == 1
            else '"cryptad-pages-' + _digest_bytes(
                _canonical_json(
                    [
                        row[3].headers.get("etag")
                        for row in retrieval.exchanges
                        if row[3].status == 200
                    ]
                )
            ).removeprefix("sha256:") + '"'
        ),
        "lastModified": max(
            (
                parsed
                for parsed in (
                    _last_modified(row[3].headers.get("last-modified"))
                    for row in retrieval.exchanges
                    if row[3].status == 200
                )
                if parsed is not None
            ),
            default=None,
        ),
        "responseStatus": response.status,
        "contentType": content_type,
        "transferBytes": sum(len(row[3].raw) for row in retrieval.exchanges),
        "decompressedBytes": decompressed_bytes,
        "recordCount": len(records),
        "redirectChain": list(redirect_chain),
        "rawContentDigest": raw_digest,
        "canonicalRecordSetDigest": record_set_digest,
        "componentInventoryDigest": inventory_digest,
        "previousSourceSnapshotDigest": previous_snapshot_digest,
        "previousSourceEdition": (
            int(previous_source_edition)
            if previous_source_edition is not None and previous_source_edition.isdigit()
            else previous_source_edition
        ),
        "parserId": source["parserId"],
        "parserVersion": PARSER_VERSION,
        "parserDigest": parser_digest,
        "policyDigest": policy["policyDigest"],
        "licenseClass": source["licenseClass"],
        "publicationClass": "derived-status-only",
        "provenanceDigest": provenance["provenanceDigest"],
        "redaction": {
            "status": "pass",
            "privateCaseMaterialExcluded": True,
            "reporterIdentityExcluded": True,
            "embargoedDetailsExcluded": True,
            "credentialsExcluded": True,
            "privateUrisExcluded": True,
            "absolutePathsExcluded": True,
            "rawFeedsExcluded": True,
            "sideEffectsPerformed": False,
        },
    }
    source_metadata["sourceSnapshotDigest"] = _semantic_digest(
        source_metadata, "sourceSnapshotDigest"
    )
    out_root.mkdir(parents=True, exist_ok=False)
    _write_exclusive(out_root / "raw-response.bin", transcript)
    _write_exclusive(out_root / "canonical-advisory-records.json", record_bytes + b"\n")
    _write_exclusive(
        out_root / "stable-1.0-dependency-intelligence-provenance.json",
        _canonical_json(provenance) + b"\n",
    )
    _write_exclusive(
        out_root / "stable-1.0-dependency-intelligence-source.json",
        _canonical_json(source_metadata) + b"\n",
    )
    roles = []
    for name in SAFE_OUTPUTS:
        if name == "producer-manifest.json":
            continue
        path = out_root / name
        roles.append(
            {"file": name, "sha256": _digest_bytes(path.read_bytes()), "size": path.stat().st_size}
        )
    manifest = {
        "schemaVersion": 1,
        "kind": "stable-1.0-dependency-intelligence-producer-manifest",
        "sourceId": source_id,
        "sourceCommit": source_commit,
        "runId": int(run_id),
        "runAttempt": int(run_attempt),
        "artifactName": artifact_name,
        "files": sorted(roles, key=lambda row: row["file"]),
    }
    manifest["manifestDigest"] = _semantic_digest(manifest, "manifestDigest")
    _write_exclusive(out_root / "producer-manifest.json", _canonical_json(manifest) + b"\n")
    actual = tuple(sorted(path.name for path in out_root.iterdir()))
    if actual != tuple(sorted(SAFE_OUTPUTS)):
        raise ProducerError("dependency-intelligence-output-allowlist-failed")
    return manifest


def _optional(value: str) -> str | None:
    return value or None


def main(argv: list[str] | None = None) -> int:
    """Run one protected retrieval and produce its closed artifact bundle."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--retrieved-at", required=True)
    parser.add_argument("--source-edition", required=True)
    parser.add_argument("--previous-snapshot-digest", default="")
    parser.add_argument("--previous-source-edition", default="")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--osv-component-inventory", type=Path)
    parser.add_argument("--out-root", type=Path, required=True)
    args = parser.parse_args(argv)
    policy = load_policy(args.policy)
    request_body = b""
    inventory_digest = None
    github_token = os.environ.pop(
        "CRYPTAD_DEPENDENCY_INTELLIGENCE_GITHUB_TOKEN", ""
    ) or None
    if args.source_id == "osv-public":
        if args.osv_component_inventory is None:
            raise ProducerError("dependency-intelligence-osv-query-contract-required")
        request_body, inventory_digest = build_osv_query_from_inventory(
            args.osv_component_inventory,
            policy.get("networkBounds", {}),
        )
    elif args.osv_component_inventory is not None:
        raise ProducerError("dependency-intelligence-osv-query-irrelevant")
    if args.source_id == "github-public-advisories" and github_token is None:
        raise ProducerError("dependency-intelligence-github-authentication-required")
    if args.source_id != "github-public-advisories" and github_token is not None:
        raise ProducerError("dependency-intelligence-github-credential-irrelevant")
    retrieval = retrieve(
        policy,
        args.source_id,
        args.endpoint,
        request_body=request_body,
        github_token=github_token,
    )
    produce_from_bytes(
        policy=policy,
        source_id=args.source_id,
        endpoint=args.endpoint,
        response=retrieval.response,
        redirect_chain=retrieval.redirect_chain,
        exchanges=retrieval.exchanges,
        source_cursor=retrieval.source_cursor,
        request_body=retrieval.request_body,
        inventory_digest=inventory_digest,
        retrieved_at=args.retrieved_at,
        source_edition=args.source_edition,
        previous_snapshot_digest=_optional(args.previous_snapshot_digest),
        previous_source_edition=_optional(args.previous_source_edition),
        repository=args.repository,
        workflow_ref=args.workflow_ref,
        source_commit=args.source_commit,
        source_ref=args.source_ref,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
        artifact_name=args.artifact_name,
        out_root=args.out_root,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
