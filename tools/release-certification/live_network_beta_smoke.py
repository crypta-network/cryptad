#!/usr/bin/env python3
"""Run explicit live-network beta certification evidence collection.

This script is intentionally Python-only and keeps raw live-node inputs out of
artifacts. It accepts only localhost node URLs, reads the operator form password
from the environment, and writes sanitized evidence for the release
certification aggregator.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime as dt
import hashlib
import http.server
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable


SCHEMA_VERSION = 1
SUMMARY_FILE_NAME = "summary.json"
REPORT_FILE_NAME = "live-network-beta-smoke-report.md"
MODES = ("pr", "nightly", "release-candidate")
EVIDENCE_IDS = (
    "live-network-beta.preflight",
    "live-network-beta.catalog-usk-fetch",
    "live-network-beta.app-install-update-rollback",
    "live-network-beta.content-fetch",
    "live-network-beta.feed-subscription",
    "live-network-beta.profile-publish",
    "live-network-beta.trust-statement-publish-import",
    "live-network-beta.app-service-score",
    "live-network-beta.interop-perf-budget",
    "live-network-beta.redaction",
)
REQUIRED_EVIDENCE_IDS = tuple(
    evidence_id
    for evidence_id in EVIDENCE_IDS
    if evidence_id != "live-network-beta.app-service-score"
)
CATALOG_GATED_MUTATING_EVIDENCE_IDS = (
    "live-network-beta.app-install-update-rollback",
    "live-network-beta.feed-subscription",
    "live-network-beta.profile-publish",
    "live-network-beta.trust-statement-publish-import",
    "live-network-beta.app-service-score",
)
APP_PRINCIPAL_GATED_EVIDENCE_IDS = (
    "live-network-beta.content-fetch",
    "live-network-beta.feed-subscription",
    "live-network-beta.profile-publish",
    "live-network-beta.trust-statement-publish-import",
    "live-network-beta.app-service-score",
)
LOCALHOSTS = {"127.0.0.1", "localhost", "::1", "0:0:0:0:0:0:0:1"}
URI_RE = re.compile(r"^(?:(?P<scheme>crypta):)?(?P<family>CHK|SSK|USK|KSK)@", re.IGNORECASE)
PRIVATE_URI_RE = re.compile(r"\b(?:crypta:)?(?:SSK|USK)@[^,\s\"']*(?:PRIVATE|INSERT)[^,\s\"']*", re.IGNORECASE)
TOKEN_RE = re.compile(
    r"(?i)\b(?:authorization|cookie|set-cookie|x-crypta-app-session|cryptad_app_token|"
    r"browser[-_ ]?session[-_ ]?token|app[-_ ]?process[-_ ]?token|token)\b\s*[:=]\s*[^,\s}\]]+"
)
RAW_BODY_RE = re.compile(
    r"(?i)\b(?:raw[-_ ]?)?(?:request|response|feed|fetched|social|message|profile|trust)"
    r"[-_ ]?(?:body|document|payload|content)\b\s*[:=]"
)
RAW_SIGNATURE_RE = re.compile(r"(?i)\b(?:raw[-_ ]?)?signature(?:[-_ ]?(?:value|base64|payload))?\b\s*[:=]")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE)
ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9_:/.\->])/(?:[A-Za-z0-9._ -]+/)+[A-Za-z0-9._ -]+")
WINDOWS_PATH_RE = re.compile(r"(?<![A-Za-z0-9_:/.\->])[A-Za-z]:[\\/][^:*?\"<>|\r\n]+")
QUERY_SECRET_RE = re.compile(r"\?[A-Za-z0-9_.~=&%-]*(?:token|password|secret|key)=", re.IGNORECASE)
APP_SESSION_HEADER = "X-Crypta-App-Session"
FORM_PASSWORD_PARAMETER = "formPassword"


@dataclasses.dataclass(frozen=True)
class Settings:
    workspace_root: Path
    out_dir: Path
    mode: str
    node_base_url: str
    required: bool
    form_password: str
    timeout_seconds: int
    poll_interval_seconds: int
    max_poll_attempts: int
    max_duration_seconds: int
    max_step_duration_seconds: int
    env: dict[str, str]


@dataclasses.dataclass(frozen=True)
class UrlValidation:
    ok: bool
    normalized: str
    shape: str
    reason: str = ""


@dataclasses.dataclass(frozen=True)
class HttpResult:
    status: int
    duration_ms: int
    details: dict[str, Any]
    body: Any = None


Transport = Callable[[str, str, dict[str, str], bytes | None, int], tuple[int, dict[str, str], bytes]]


class MissingAppPrincipal(RuntimeError):
    """Raised when an app-only route cannot be called with an app browser session."""

    def __init__(self, app_id: str, details: dict[str, Any]) -> None:
        super().__init__(f"App browser session unavailable for {app_id}.")
        self.app_id = app_id
        self.details = details


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep certification requests on the validated localhost origin only."""

    def redirect_request(
        self,
        _req: urllib.request.Request,
        _fp: Any,
        _code: int,
        _msg: str,
        _headers: Any,
        _newurl: str,
    ) -> None:
        return None


def build_cert_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirectHandler)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def monotonic_ms() -> int:
    return int(time.monotonic() * 1000)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def env_flag(env: dict[str, str], name: str) -> bool:
    return env.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def int_env(env: dict[str, str], name: str, default: int) -> int:
    try:
        value = int(env.get(name, "").strip())
    except ValueError:
        return default
    return value if value > 0 else default


def validate_local_node_url(raw_url: str) -> UrlValidation:
    raw = raw_url.strip()
    if not raw:
        return UrlValidation(False, "", "missing", "node base URL is missing")
    if raw.startswith("//"):
        return UrlValidation(False, "", "<rejected-url>", "protocol-relative URLs are not allowed")
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme != "http":
        return UrlValidation(False, "", "<rejected-url>", "node base URL must use http")
    if parsed.username or parsed.password:
        return UrlValidation(False, "", "<rejected-url>", "node base URL must not contain credentials")
    if parsed.query:
        return UrlValidation(False, "", "<rejected-url>", "node base URL must not contain a query string")
    if parsed.fragment:
        return UrlValidation(False, "", "<rejected-url>", "node base URL must not contain a fragment")
    try:
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return UrlValidation(False, "", "<rejected-url>", "node base URL host or port is invalid")
    if host not in LOCALHOSTS:
        return UrlValidation(False, "", "<rejected-remote-url>", "node base URL must target localhost")
    if parsed.path not in ("", "/"):
        return UrlValidation(False, "", "<rejected-url>", "node base URL must not contain a path")
    if port is not None and not (1 <= port <= 65535):
        return UrlValidation(False, "", "<rejected-url>", "node base URL port is invalid")
    display_host = "::1" if host == "0:0:0:0:0:0:0:1" else host
    if ":" in display_host and display_host != "localhost":
        netloc = f"[{display_host}]"
    else:
        netloc = display_host
    if port is not None:
        netloc = f"{netloc}:{port}"
        shape = f"http://{display_host if display_host != '::1' else '[::1]'}:<port>"
    else:
        shape = f"http://{display_host if display_host != '::1' else '[::1]'}"
    return UrlValidation(True, f"http://{netloc}", shape, "")


def sha256_short(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def safe_uri_shape(uri: str) -> dict[str, Any]:
    value = uri.strip()
    match = URI_RE.match(value)
    if not match:
        return {"valid": False, "family": "unknown", "shape": "<redacted-uri>"}
    family = match.group("family").upper()
    scheme = "crypta:" if match.group("scheme") else ""
    suffix = ""
    without_query = value.split("?", 1)[0].split("#", 1)[0]
    if "/" in without_query:
        suffix = without_query.rsplit("/", 1)[-1][:80]
    shape = f"{scheme}{family}@..."
    if suffix:
        shape = f"{shape}/{suffix}"
    return {
        "valid": True,
        "family": family,
        "shape": shape,
        "digest": sha256_short(value),
    }


def safe_catalog_source(source: str) -> dict[str, Any]:
    shape = safe_uri_shape(source)
    return {
        **shape,
        "catalogPropertiesSuffix": source.strip().endswith("/cryptad-app-catalog.properties"),
        "signatureSidecar": "cryptad-app-catalog.signature",
    }


def load_private_insert_fixture(env: dict[str, str]) -> tuple[bool, str, str]:
    env_name = env.get("CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV", "").strip()
    file_name = env.get("CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE", "").strip()
    if env_name:
        value = env.get(env_name, "").strip()
        if value:
            return True, "environment-indirection", value
        return False, "environment-indirection", ""
    if file_name:
        try:
            value = Path(file_name).read_text(encoding="utf-8").strip()
        except OSError:
            return False, "file-indirection", ""
        return bool(value), "file-indirection", value
    return False, "missing", ""


def evidence(
    evidence_id: str,
    status: str,
    required: bool,
    summary: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": evidence_id,
        "status": status,
        "requiredForReleaseCandidate": required,
        "summary": summary,
        "source": "live-network-beta-smoke",
        "details": details or {},
    }


class CertHttpClient:
    def __init__(
        self,
        base_url: str,
        form_password: str,
        timeout_seconds: int,
        transport: Transport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.form_password = form_password
        self.timeout_seconds = timeout_seconds
        self.transport = transport
        self._app_sessions: dict[str, str] = {}
        self._app_origins: dict[str, str] = {}
        self._app_session_details: dict[str, dict[str, Any]] = {}

    def request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
        *,
        principal: str = "host",
        app_id: str = "",
    ) -> HttpResult:
        if not path.startswith("/"):
            raise ValueError("request path must be absolute")
        normalized_principal = principal.strip().lower()
        body: bytes | None = None
        headers = {"Accept": "application/json"}
        params = dict(data or {})
        if normalized_principal == "app":
            if not app_id:
                raise MissingAppPrincipal("<missing-app-id>", {"reason": "app id was not supplied"})
            headers[APP_SESSION_HEADER] = self.app_session(app_id)
            origin = self.app_session_origin(app_id)
            if origin:
                headers["Origin"] = origin
        elif normalized_principal == "host":
            if method.upper() in {"POST", "DELETE", "PATCH", "PUT"} and self.form_password:
                params[FORM_PASSWORD_PARAMETER] = self.form_password
        else:
            raise ValueError("principal must be 'host' or 'app'")
        if params:
            body = urllib.parse.urlencode(
                {key: str(value) for key, value in params.items()}
            ).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        return self._request_with_headers(method, path, headers, body, normalized_principal)

    def app_session(self, app_id: str) -> str:
        normalized_app_id = app_id.strip()
        if not normalized_app_id:
            raise MissingAppPrincipal("<missing-app-id>", {"reason": "app id was blank"})
        if normalized_app_id not in self._app_sessions:
            self._fetch_app_session(normalized_app_id)
        return self._app_sessions[normalized_app_id]

    def app_session_details(self, app_id: str) -> dict[str, Any]:
        return dict(self._app_session_details.get(app_id, {}))

    def app_session_origin(self, app_id: str) -> str:
        normalized_app_id = app_id.strip()
        self.app_session(normalized_app_id)
        return self._app_origins.get(normalized_app_id, "")

    def app_session_values(self) -> list[str]:
        return list(self._app_sessions.values())

    def _fetch_app_session(self, app_id: str) -> None:
        encoded_app_id = urllib.parse.quote(app_id, safe="")
        path = f"/apps/{encoded_app_id}/.well-known/cryptad-bootstrap.json"
        start = monotonic_ms()
        headers = {"Accept": "application/json"}
        if self.transport is None:
            status, response_headers, response_body = self._urllib_request("GET", path, headers, None)
        else:
            status, response_headers, response_body = self.transport(
                "GET", path, headers, None, self.timeout_seconds
            )
        duration = max(0, monotonic_ms() - start)
        parsed_body = parse_json_body(response_body)
        details = {
            "method": "GET",
            "path": path,
            "status": status,
            "durationMs": duration,
            "response": response_summary(response_headers, parsed_body, response_body),
            "browserSessionTokenStored": False,
            "uiOriginStored": False,
        }
        details["response"]["byteCount"] = 0
        self._app_session_details[app_id] = details
        token = ""
        ui_origin = ""
        ui_origin_valid = True
        if isinstance(parsed_body, dict):
            token = str(parsed_body.get("browserSessionToken") or "").strip()
            raw_origin = str(parsed_body.get("uiOrigin") or "").strip()
            details["uiOriginProvided"] = bool(raw_origin)
            if raw_origin:
                origin_validation = validate_local_node_url(raw_origin)
                details["uiOriginAccepted"] = origin_validation.ok
                details["uiOriginShape"] = origin_validation.shape
                ui_origin_valid = origin_validation.ok
                ui_origin = origin_validation.normalized if origin_validation.ok else ""
        if (
            not step_ok(HttpResult(status=status, duration_ms=duration, details=details, body=parsed_body))
            or not token
            or not ui_origin_valid
        ):
            raise MissingAppPrincipal(app_id, details)
        self._app_sessions[app_id] = token
        if ui_origin:
            self._app_origins[app_id] = ui_origin

    def _request_with_headers(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
        principal: str,
    ) -> HttpResult:
        start = monotonic_ms()
        if self.transport is None:
            status, response_headers, response_body = self._urllib_request(method, path, headers, body)
        else:
            status, response_headers, response_body = self.transport(
                method, path, headers, body, self.timeout_seconds
            )
        duration = max(0, monotonic_ms() - start)
        parsed_body = parse_json_body(response_body)
        details = {
            "method": method,
            "path": path,
            "principal": principal,
            "status": status,
            "durationMs": duration,
            "response": response_summary(response_headers, parsed_body, response_body),
        }
        return HttpResult(status=status, duration_ms=duration, details=details, body=parsed_body)

    def _urllib_request(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
    ) -> tuple[int, dict[str, str], bytes]:
        request = urllib.request.Request(
            self.base_url + path,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            opener = build_cert_opener()
            with opener.open(request, timeout=self.timeout_seconds) as response:
                return response.status, dict(response.headers.items()), response.read(1024 * 1024)
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers.items()), exc.read(4096)


def parse_json_body(body: bytes) -> Any:
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def response_summary(headers: dict[str, str], parsed_body: Any, body: bytes) -> dict[str, Any]:
    content_type = headers.get("content-type") or headers.get("Content-Type") or ""
    summary: dict[str, Any] = {
        "contentType": content_type.split(";", 1)[0][:80],
        "byteCount": len(body),
        "bodyStored": False,
    }
    if isinstance(parsed_body, dict):
        summary["jsonObject"] = True
        summary["jsonKeys"] = sorted(str(key)[:80] for key in parsed_body.keys())[:20]
    elif isinstance(parsed_body, list):
        summary["jsonArrayLength"] = len(parsed_body)
    else:
        summary["jsonObject"] = False
    return summary


def step_ok(result: HttpResult, allow_not_found: bool = False) -> bool:
    if 200 <= result.status < 300:
        return True
    return allow_not_found and result.status == 404


def quote_segment(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def nested_value(body: Any, *path: str) -> Any:
    value = body
    for segment in path:
        if not isinstance(value, dict):
            return None
        value = value.get(segment)
    return value


def extract_catalog_summary(body: Any) -> dict[str, Any]:
    if isinstance(body, dict) and isinstance(body.get("catalog"), dict):
        return body["catalog"]
    if isinstance(body, dict):
        return body
    return {}


def extract_catalog_id(body: Any) -> str:
    candidates = (
        nested_value(body, "catalog", "catalogId"),
        nested_value(body, "catalog", "id"),
        nested_value(body, "catalogId"),
        nested_value(body, "id"),
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return ""


def extract_catalog_signature_key_id(body: Any) -> str:
    summary = extract_catalog_summary(body)
    candidates = (
        nested_value(summary, "signature", "keyId"),
        nested_value(summary, "catalogSignature", "keyId"),
        summary.get("signatureKeyId") if isinstance(summary, dict) else None,
        summary.get("catalogSignatureKeyId") if isinstance(summary, dict) else None,
        summary.get("trustedCatalogKeyId") if isinstance(summary, dict) else None,
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return ""


def catalog_entries(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, dict) and isinstance(body.get("catalogs"), list):
        return [entry for entry in body["catalogs"] if isinstance(entry, dict)]
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    return []


def catalog_entry_for_source(body: Any, source: str) -> dict[str, Any]:
    source_text = source.strip()
    for entry in catalog_entries(body):
        if str(entry.get("source") or "").strip() == source_text:
            return entry
    return {}


def catalog_entry_for_id(body: Any, catalog_id: str) -> dict[str, Any]:
    catalog_id_text = catalog_id.strip()
    for entry in catalog_entries(body):
        if str(entry.get("catalogId") or entry.get("id") or "").strip() == catalog_id_text:
            return entry
    return {}


def extract_app_count(body: Any) -> int | None:
    if isinstance(body, dict) and isinstance(body.get("apps"), list):
        return len(body["apps"])
    if isinstance(body, list):
        return len(body)
    return None


def runtime_is_running(body: Any) -> bool:
    bodies = []
    runtime = nested_value(body, "runtime")
    if isinstance(runtime, dict):
        bodies.append(runtime)
    bodies.append(body)
    for candidate in bodies:
        running = nested_value(candidate, "running")
        if isinstance(running, bool):
            return running
        state = nested_value(candidate, "state")
        if isinstance(state, str) and state.strip().upper() in {"RUNNING", "STARTED"}:
            return True
        status = nested_value(candidate, "status")
        if isinstance(status, str) and status.strip().lower() in {"running", "started"}:
            return True
    return False


def extract_subscription_id(body: Any) -> str:
    candidates = (
        nested_value(body, "subscription", "subscriptionId"),
        nested_value(body, "subscription", "id"),
        nested_value(body, "subscriptionId"),
        nested_value(body, "id"),
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return ""


def extract_identity_id(body: Any) -> str:
    candidates = (
        nested_value(body, "identity", "identityId"),
        nested_value(body, "identity", "id"),
        nested_value(body, "identityId"),
        nested_value(body, "id"),
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return ""


def extract_grant_id(body: Any) -> str:
    candidates = (
        nested_value(body, "grant", "grantId"),
        nested_value(body, "grant", "id"),
        nested_value(body, "grantId"),
        nested_value(body, "id"),
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return ""


def extract_grant_ids(body: Any) -> set[str]:
    grants = nested_value(body, "grants")
    if not isinstance(grants, list):
        grants = body if isinstance(body, list) else []
    ids: set[str] = set()
    for grant in grants:
        grant_id = extract_grant_id(grant)
        if grant_id:
            ids.add(grant_id)
    return ids


def extract_grant_status(body: Any) -> str:
    candidates = (
        nested_value(body, "grant", "status"),
        nested_value(body, "grant", "state"),
        nested_value(body, "status"),
        nested_value(body, "state"),
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip().lower()
    return ""


def grant_created_by_request(body: Any) -> bool:
    containers: list[Any] = []
    grant = nested_value(body, "grant")
    if isinstance(grant, dict):
        containers.append(grant)
    containers.append(body)
    for container in containers:
        if not isinstance(container, dict):
            continue
        for key in ("created", "createdByRequest", "createdByThisRequest", "newGrant", "new"):
            if container.get(key) is True:
                return True
        for key in ("reused", "existing", "reusedExistingGrant"):
            if container.get(key) is True:
                return False
    return False


def document_base64_from_body(body: Any, *document_path: str) -> str:
    document = nested_value(body, *document_path) if document_path else body
    if document is None:
        return ""
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(encoded).decode("ascii")


def failing_exception_evidence(
    evidence_id: str,
    settings: Settings,
    summary: str,
    exc: BaseException,
    details: dict[str, Any],
) -> dict[str, Any]:
    safe_details = {**details, "error": type(exc).__name__}
    if isinstance(exc, MissingAppPrincipal):
        safe_details["appPrincipal"] = {"appId": exc.app_id, "session": exc.details}
    is_required = settings.required and evidence_id in REQUIRED_EVIDENCE_IDS
    return evidence(
        evidence_id,
        "fail" if is_required else "warn",
        is_required,
        summary,
        safe_details,
    )


def missing_fixture_evidence(
    evidence_id: str,
    required_mode: bool,
    fixture_names: list[str],
    details: dict[str, Any],
) -> dict[str, Any]:
    status = "fail" if required_mode else "warn"
    return evidence(
        evidence_id,
        status,
        required_mode and evidence_id in REQUIRED_EVIDENCE_IDS,
        f"Live-network fixture is missing: {', '.join(fixture_names)}.",
        {**details, "missingFixtures": fixture_names},
    )


def run_request_sequence(
    client: CertHttpClient,
    steps: list[tuple[str, str, dict[str, Any] | None, bool]],
) -> tuple[bool, list[dict[str, Any]], int]:
    summaries: list[dict[str, Any]] = []
    total_duration = 0
    ok = True
    for method, path, data, allow_not_found in steps:
        result = client.request(method, path, data)
        summaries.append(result.details)
        total_duration += result.duration_ms
        if not step_ok(result, allow_not_found):
            ok = False
            break
    return ok, summaries, total_duration


def poll_request_until_ok(
    settings: Settings,
    client: CertHttpClient,
    steps: list[dict[str, Any]],
    method: str,
    path: str,
    data: dict[str, Any],
    *,
    principal: str,
    app_id: str,
) -> tuple[bool, int]:
    max_attempts = max(1, settings.max_poll_attempts)
    for attempt in range(1, max_attempts + 1):
        result = client.request(method, path, data, principal=principal, app_id=app_id)
        result.details["pollAttempt"] = attempt
        steps.append(result.details)
        if step_ok(result):
            return True, attempt
        if attempt < max_attempts and settings.poll_interval_seconds > 0:
            time.sleep(settings.poll_interval_seconds)
    return False, max_attempts


def collect_preflight(settings: Settings, validation: UrlValidation, client: CertHttpClient | None) -> dict[str, Any]:
    details = {
        "enabled": True,
        "required": settings.required,
        "node": {
            "baseUrlShape": validation.shape,
            "localhostOnly": validation.ok,
        },
        "formPasswordProvidedFromEnvironment": bool(settings.form_password),
        "rawBodiesStored": False,
    }
    if not validation.ok:
        return evidence(
            "live-network-beta.preflight",
            "fail" if settings.required else "warn",
            settings.required,
            f"Live node preflight rejected the node URL: {validation.reason}.",
            details,
        )
    if not settings.form_password:
        return evidence(
            "live-network-beta.preflight",
            "fail" if settings.required else "warn",
            settings.required,
            "Live node preflight requires CRYPTAD_CERT_FORM_PASSWORD from the environment.",
            details,
        )
    assert client is not None
    try:
        result = client.request("GET", "/api/v1/diagnostics")
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        details["error"] = type(exc).__name__
        return evidence(
            "live-network-beta.preflight",
            "fail" if settings.required else "warn",
            settings.required,
            "Local node diagnostics route was not reachable.",
            details,
        )
    details["diagnostics"] = result.details
    if not step_ok(result):
        return evidence(
            "live-network-beta.preflight",
            "fail" if settings.required else "warn",
            settings.required,
            "Local node diagnostics route returned a non-success status.",
            details,
        )
    return evidence(
        "live-network-beta.preflight",
        "pass",
        settings.required,
        "Local node preflight passed.",
        details,
    )


def cleanup_added_catalog(client: CertHttpClient, catalog_id: str, details: dict[str, Any]) -> None:
    catalog_path = quote_segment(catalog_id)
    cleanup_path = f"/api/v1/app-catalogs/{catalog_path}"
    cleanup_steps = details.setdefault("catalogCleanupSteps", [])
    details["catalogCleanupAttempted"] = True
    try:
        cleanup = client.request("DELETE", cleanup_path, None)
        cleanup_steps.append(cleanup.details)
        details["catalogCleanupSucceeded"] = step_ok(cleanup, allow_not_found=True)
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        cleanup_steps.append(
            {
                "method": "DELETE",
                "path": cleanup_path,
                "principal": "host",
                "status": "cleanup-exception",
                "error": type(exc).__name__,
                "durationMs": 0,
            }
        )
        details["catalogCleanupSucceeded"] = False


def collect_catalog(settings: Settings, client: CertHttpClient | None) -> dict[str, Any]:
    source = settings.env.get("CRYPTAD_CERT_LIVE_CATALOG_SOURCE", "").strip()
    expected_key_id = settings.env.get("CRYPTAD_CERT_LIVE_CATALOG_EXPECTED_KEY_ID", "").strip()
    configured_catalog_id = settings.env.get("CRYPTAD_CERT_LIVE_CATALOG_ID", "crypta-first-party-beta").strip() or "crypta-first-party-beta"
    details = {
        "catalogSource": safe_catalog_source(source) if source else {},
        "configuredCatalogId": configured_catalog_id,
        "expectedKeyIdConfigured": bool(expected_key_id),
        "rawCatalogStored": False,
        "rawSignatureStored": False,
    }
    if not source:
        return missing_fixture_evidence(
            "live-network-beta.catalog-usk-fetch",
            settings.required,
            ["CRYPTAD_CERT_LIVE_CATALOG_SOURCE"],
            details,
        )
    source_shape = safe_catalog_source(source)
    if not source_shape["valid"] or source_shape["family"] != "USK" or not source_shape["catalogPropertiesSuffix"]:
        return evidence(
            "live-network-beta.catalog-usk-fetch",
            "fail" if settings.required else "warn",
            settings.required,
            "Live catalog source must be a crypta:USK catalog properties source.",
            details,
        )
    if settings.required and not expected_key_id:
        return evidence(
            "live-network-beta.catalog-usk-fetch",
            "fail",
            True,
            "Live catalog expected signing key id is required before catalog source mutation.",
            {**details, "catalogMutationSkipped": True},
        )
    if client is None:
        return evidence("live-network-beta.catalog-usk-fetch", "fail", settings.required, "HTTP client unavailable.", details)
    steps: list[dict[str, Any]] = []
    observed_key_id = ""
    observed_catalog_id = configured_catalog_id
    added_by_this_run = False
    ok = True
    try:
        add = client.request("POST", "/api/v1/app-catalogs/add", {"source": source})
        steps.append(add.details)
        if step_ok(add):
            added_by_this_run = True
            observed_catalog_id = extract_catalog_id(add.body) or configured_catalog_id
            observed_key_id = extract_catalog_signature_key_id(add.body)
        elif add.status == 409:
            list_catalogs = client.request("GET", "/api/v1/app-catalogs")
            steps.append(list_catalogs.details)
            matched = catalog_entry_for_source(list_catalogs.body, source)
            id_matched = catalog_entry_for_id(list_catalogs.body, configured_catalog_id)
            details["catalogConflictSourceMatched"] = bool(matched)
            details["catalogConflictCatalogIdMatched"] = bool(id_matched)
            ok = step_ok(list_catalogs) and bool(matched)
            details["reusedConfiguredCatalog"] = bool(matched)
            if matched:
                observed_catalog_id = extract_catalog_id(matched) or configured_catalog_id
                observed_key_id = extract_catalog_signature_key_id(matched)
            else:
                details["catalogConflictReason"] = "configured catalog id exists with a different or unavailable source"
        else:
            ok = False
        if ok:
            catalog_path = quote_segment(observed_catalog_id)
            refresh = client.request("POST", f"/api/v1/app-catalogs/{catalog_path}/refresh", {})
            steps.append(refresh.details)
            if step_ok(refresh):
                observed_key_id = extract_catalog_signature_key_id(refresh.body) or observed_key_id
                observed_catalog_id = extract_catalog_id(refresh.body) or observed_catalog_id
            else:
                ok = False
        if ok:
            catalog_path = quote_segment(observed_catalog_id)
            apps = client.request("GET", f"/api/v1/app-catalogs/{catalog_path}/apps")
            steps.append(apps.details)
            details["appCount"] = extract_app_count(apps.body)
            ok = step_ok(apps)
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        details["steps"] = steps
        details["catalogAddedByThisRun"] = added_by_this_run
        if added_by_this_run:
            cleanup_added_catalog(client, observed_catalog_id, details)
        return failing_exception_evidence(
            "live-network-beta.catalog-usk-fetch",
            settings,
            "Live catalog fetch or verification did not complete.",
            exc,
            details,
        )
    details["steps"] = steps
    details["catalogAddedByThisRun"] = added_by_this_run
    details.setdefault("appCount", None)
    details["signatureSidecar"] = "cryptad-app-catalog.signature"
    details["observedCatalogId"] = observed_catalog_id
    details["keyId"] = observed_key_id if observed_key_id else "<not-observed>"
    details["keyIdMatchesExpected"] = bool(expected_key_id and observed_key_id == expected_key_id)
    if not ok:
        if added_by_this_run:
            cleanup_added_catalog(client, observed_catalog_id, details)
        return evidence(
            "live-network-beta.catalog-usk-fetch",
            "fail" if settings.required else "warn",
            settings.required,
            "Live catalog fetch or verification did not complete.",
            details,
        )
    if not expected_key_id:
        if added_by_this_run:
            cleanup_added_catalog(client, observed_catalog_id, details)
        return evidence(
            "live-network-beta.catalog-usk-fetch",
            "fail" if settings.required else "warn",
            settings.required,
            "Live catalog expected signing key id was not configured.",
            details,
        )
    if not observed_key_id:
        if added_by_this_run:
            cleanup_added_catalog(client, observed_catalog_id, details)
        return evidence(
            "live-network-beta.catalog-usk-fetch",
            "fail" if settings.required else "warn",
            settings.required,
            "Live catalog fetch succeeded, but the verified signing key id was not observable.",
            details,
        )
    if observed_key_id != expected_key_id:
        if added_by_this_run:
            cleanup_added_catalog(client, observed_catalog_id, details)
        return evidence(
            "live-network-beta.catalog-usk-fetch",
            "fail" if settings.required else "warn",
            settings.required,
            "Live catalog signing key id did not match the configured expected key id.",
            details,
        )
    return evidence(
        "live-network-beta.catalog-usk-fetch",
        "pass",
        settings.required,
        "Live first-party USK catalog fetch and verification passed.",
        details,
    )


def collect_app_lifecycle(settings: Settings, client: CertHttpClient | None) -> dict[str, Any]:
    if client is None:
        return evidence("live-network-beta.app-install-update-rollback", "fail", settings.required, "HTTP client unavailable.")
    app_id = settings.env.get("CRYPTAD_CERT_LIVE_APP_ID", "site-publisher").strip() or "site-publisher"
    catalog_id = settings.env.get("CRYPTAD_CERT_LIVE_CATALOG_ID", "crypta-first-party-beta").strip() or "crypta-first-party-beta"
    details = {
        "appId": app_id,
        "catalogId": catalog_id,
        "rawUpdateOutputStored": False,
        "tokensStored": False,
    }
    steps: list[dict[str, Any]] = []
    cleanup_steps: list[dict[str, Any]] = []
    restore_steps: list[dict[str, Any]] = []
    ok = False
    installed_by_this_run = False
    pre_existing = False
    pre_existing_running = False
    pre_existing_stopped_started_by_this_run = False
    caught_exception: BaseException | None = None
    try:
        existing = client.request("GET", f"/api/v1/apps/{app_id}/runtime")
        steps.append(existing.details)
        if existing.status != 404 and not step_ok(existing):
            raise RuntimeError("initial runtime status failed")
        pre_existing = step_ok(existing)
        pre_existing_running = pre_existing and runtime_is_running(existing.body)
        if pre_existing:
            ok = True
            details["installSkipped"] = "target app was pre-existing"
        else:
            install = client.request("POST", f"/api/v1/app-catalogs/{catalog_id}/apps/{app_id}/install", {})
            steps.append(install.details)
            installed_by_this_run = step_ok(install)
            ok = installed_by_this_run
        if ok and pre_existing_running:
            pre_stop = client.request("POST", f"/api/v1/apps/{app_id}/stop", {})
            steps.append(pre_stop.details)
            ok = step_ok(pre_stop)
            details["preExistingRunningStoppedForSmoke"] = ok
        lifecycle_steps: tuple[tuple[str, str, dict[str, Any] | None, bool], ...] = (
            ("GET", f"/api/v1/apps/{app_id}/runtime", None, False),
            ("POST", f"/api/v1/apps/{app_id}/start", {}, False),
            ("POST", f"/api/v1/apps/{app_id}/stop", {}, False),
            ("POST", f"/api/v1/apps/{app_id}/updates/check", {}, False),
            ("POST", f"/api/v1/app-catalogs/{catalog_id}/apps/{app_id}/update", {}, False),
            ("POST", f"/api/v1/apps/{app_id}/updates/rollback", {}, False),
        )
        for method, path, data, allow_not_found in lifecycle_steps:
            if not ok:
                break
            result = client.request(method, path, data)
            steps.append(result.details)
            result_ok = step_ok(result, allow_not_found)
            if pre_existing and not pre_existing_running and method == "POST" and path.endswith("/start") and result_ok:
                pre_existing_stopped_started_by_this_run = True
                details["preExistingStoppedStartedBySmoke"] = True
            elif (
                pre_existing
                and not pre_existing_running
                and method == "POST"
                and path.endswith("/stop")
                and result_ok
            ):
                pre_existing_stopped_started_by_this_run = False
                details["preExistingStoppedRestoredByLifecycle"] = True
            if not result_ok:
                ok = False
    except (OSError, urllib.error.URLError, TimeoutError, MissingAppPrincipal, RuntimeError) as exc:
        caught_exception = exc
        ok = False
    finally:
        if installed_by_this_run:
            cleanup_ok = True
            for method, path, data, allow_not_found in (
                ("POST", f"/api/v1/apps/{app_id}/stop", {}, True),
                ("DELETE", f"/api/v1/apps/{app_id}", None, True),
            ):
                try:
                    cleanup = client.request(method, path, data)
                    cleanup_steps.append(cleanup.details)
                    if not step_ok(cleanup, allow_not_found):
                        cleanup_ok = False
                except (OSError, urllib.error.URLError, TimeoutError) as exc:
                    cleanup_ok = False
                    cleanup_steps.append(
                        {
                            "method": method,
                            "path": path,
                            "principal": "host",
                            "status": "cleanup-exception",
                            "error": type(exc).__name__,
                            "durationMs": 0,
                        }
                    )
                    continue
                except MissingAppPrincipal as exc:
                    cleanup_ok = False
                    cleanup_steps.append(
                        {
                            "method": method,
                            "path": path,
                            "principal": "host",
                            "status": "cleanup-exception",
                            "error": type(exc).__name__,
                            "durationMs": 0,
                        }
                    )
                    continue
            details["cleanupSucceeded"] = cleanup_ok
        elif pre_existing_running:
            restore_ok = True
            try:
                restore = client.request("POST", f"/api/v1/apps/{app_id}/start", {})
                restore_steps.append(restore.details)
                restore_ok = step_ok(restore)
            except (OSError, urllib.error.URLError, TimeoutError, MissingAppPrincipal) as exc:
                restore_ok = False
                restore_steps.append(
                    {
                        "method": "POST",
                        "path": f"/api/v1/apps/{app_id}/start",
                        "principal": "host",
                        "status": "restore-exception",
                        "error": type(exc).__name__,
                        "durationMs": 0,
                    }
                )
            details["cleanupSucceeded"] = True
            details["restoreSucceeded"] = restore_ok
        elif pre_existing_stopped_started_by_this_run:
            restore_ok = True
            try:
                restore = client.request("POST", f"/api/v1/apps/{app_id}/stop", {})
                restore_steps.append(restore.details)
                restore_ok = step_ok(restore)
            except (OSError, urllib.error.URLError, TimeoutError, MissingAppPrincipal) as exc:
                restore_ok = False
                restore_steps.append(
                    {
                        "method": "POST",
                        "path": f"/api/v1/apps/{app_id}/stop",
                        "principal": "host",
                        "status": "restore-exception",
                        "error": type(exc).__name__,
                        "durationMs": 0,
                    }
                )
            details["cleanupSucceeded"] = True
            details["preExistingStoppedRestoreSucceeded"] = restore_ok
        else:
            details["cleanupSucceeded"] = True
            details["cleanupSkipped"] = "target app was pre-existing or install did not complete"
    details["preExistingInstall"] = pre_existing
    details["preExistingRunning"] = pre_existing_running
    details["preExistingStoppedStartedBySmoke"] = bool(details.get("preExistingStoppedStartedBySmoke"))
    details["installedByThisRun"] = installed_by_this_run
    details["steps"] = steps
    details["cleanupSteps"] = cleanup_steps
    details["restoreSteps"] = restore_steps
    if caught_exception is not None:
        return failing_exception_evidence(
            "live-network-beta.app-install-update-rollback",
            settings,
            "Live app install/update/rollback smoke failed before completion.",
            caught_exception,
            details,
        )
    if not ok:
        return evidence(
            "live-network-beta.app-install-update-rollback",
            "fail" if settings.required else "warn",
            settings.required,
            "Live app install/update/rollback smoke failed; cleanup was attempted only for app installs created by this run.",
            details,
        )
    if not details.get("cleanupSucceeded", False):
        return evidence(
            "live-network-beta.app-install-update-rollback",
            "fail" if settings.required else "warn",
            settings.required,
            "Live app lifecycle smoke completed, but cleanup failed for the app installed by this run.",
            details,
        )
    if not details.get("restoreSucceeded", True):
        return evidence(
            "live-network-beta.app-install-update-rollback",
            "fail" if settings.required else "warn",
            settings.required,
            "Live app lifecycle smoke completed, but restoring the pre-existing running app failed.",
            details,
        )
    if not details.get("preExistingStoppedRestoreSucceeded", True):
        return evidence(
            "live-network-beta.app-install-update-rollback",
            "fail" if settings.required else "warn",
            settings.required,
            "Live app lifecycle smoke completed, but restoring the pre-existing stopped app failed.",
            details,
        )
    return evidence(
        "live-network-beta.app-install-update-rollback",
        "pass",
        settings.required,
        "Live app install/update/rollback smoke passed.",
        details,
    )


def configured_app_id(settings: Settings, env_name: str, default: str) -> str:
    return settings.env.get(env_name, default).strip() or default


def add_app_requirement(requirements: dict[str, list[str]], app_id: str, reason: str) -> None:
    reasons = requirements.setdefault(app_id, [])
    if reason not in reasons:
        reasons.append(reason)


def app_principal_requirements(settings: Settings, private_insert_present: bool) -> dict[str, list[str]]:
    requirements: dict[str, list[str]] = {}
    content_app_id = configured_app_id(settings, "CRYPTAD_CERT_LIVE_CONTENT_APP_ID", "feed-reader")
    feed_app_id = configured_app_id(settings, "CRYPTAD_CERT_LIVE_FEED_APP_ID", "feed-reader")
    profile_app_id = configured_app_id(settings, "CRYPTAD_CERT_LIVE_PROFILE_APP_ID", "profile-publisher")
    trust_app_id = configured_app_id(settings, "CRYPTAD_CERT_LIVE_TRUST_APP_ID", "trust-graph")
    score_caller_app_id = configured_app_id(
        settings,
        "CRYPTAD_CERT_LIVE_APP_SERVICE_CALLER_APP_ID",
        "social-inbox",
    )
    if settings.env.get("CRYPTAD_CERT_LIVE_CONTENT_FETCH_URI", "").strip():
        add_app_requirement(requirements, content_app_id, "content-fetch")
    if settings.env.get("CRYPTAD_CERT_LIVE_FEED_USK_URI", "").strip():
        add_app_requirement(requirements, feed_app_id, "feed-subscription")
    if private_insert_present:
        add_app_requirement(requirements, profile_app_id, "profile-publish")
        add_app_requirement(requirements, trust_app_id, "trust-statement-publish-import")
        if settings.env.get("CRYPTAD_CERT_LIVE_PROFILE_PUBLIC_URI", "").strip():
            add_app_requirement(requirements, content_app_id, "profile-publish-fetchback")
    if env_flag(settings.env, "CRYPTAD_CERT_LIVE_APP_SERVICE_SCORE"):
        add_app_requirement(requirements, score_caller_app_id, "app-service-score-caller")
        add_app_requirement(requirements, "trust-graph", "app-service-score-provider")
    return requirements


def prepare_app_principals(settings: Settings, client: CertHttpClient, private_insert_present: bool) -> dict[str, Any]:
    catalog_id = settings.env.get("CRYPTAD_CERT_LIVE_CATALOG_ID", "crypta-first-party-beta").strip() or "crypta-first-party-beta"
    requirements = app_principal_requirements(settings, private_insert_present)
    details: dict[str, Any] = {
        "catalogId": catalog_id,
        "appIds": list(requirements),
        "requirements": requirements,
        "steps": [],
        "installedByThisRun": [],
        "preExistingApps": [],
        "cleanupSteps": [],
        "cleanupSucceeded": True,
        "ok": True,
    }
    for app_id in requirements:
        app_path = quote_segment(app_id)
        try:
            runtime = client.request("GET", f"/api/v1/apps/{app_path}/runtime")
            details["steps"].append(runtime.details)
            if step_ok(runtime):
                details["preExistingApps"].append(app_id)
                continue
            if runtime.status != 404:
                details["ok"] = False
                details["failureAppId"] = app_id
                details["failureReason"] = "runtime status failed before install"
                break
            install = client.request("POST", f"/api/v1/app-catalogs/{catalog_id}/apps/{app_path}/install", {})
            details["steps"].append(install.details)
            if step_ok(install):
                details["installedByThisRun"].append(app_id)
                continue
            if install.status == 409:
                recheck = client.request("GET", f"/api/v1/apps/{app_path}/runtime")
                details["steps"].append(recheck.details)
                if step_ok(recheck):
                    details["preExistingApps"].append(app_id)
                    continue
            details["ok"] = False
            details["failureAppId"] = app_id
            details["failureReason"] = "catalog install failed"
            break
        except (OSError, urllib.error.URLError, TimeoutError, MissingAppPrincipal) as exc:
            details["ok"] = False
            details["failureAppId"] = app_id
            details["failureReason"] = type(exc).__name__
            break
    return details


def cleanup_prepared_app_principals(client: CertHttpClient, preparation: dict[str, Any]) -> None:
    installed_by_this_run = preparation.get("installedByThisRun", [])
    if not isinstance(installed_by_this_run, list):
        return
    cleanup_steps = preparation.setdefault("cleanupSteps", [])
    cleanup_succeeded = True
    for app_id in reversed(installed_by_this_run):
        app_path = quote_segment(str(app_id))
        for method, path, data, allow_not_found in (
            ("POST", f"/api/v1/apps/{app_path}/stop", {}, True),
            ("DELETE", f"/api/v1/apps/{app_path}", None, True),
        ):
            try:
                cleanup = client.request(method, path, data)
                cleanup_steps.append(cleanup.details)
                if not step_ok(cleanup, allow_not_found):
                    cleanup_succeeded = False
            except (OSError, urllib.error.URLError, TimeoutError, MissingAppPrincipal) as exc:
                cleanup_succeeded = False
                cleanup_steps.append(
                    {
                        "method": method,
                        "path": path,
                        "principal": "host",
                        "status": "cleanup-exception",
                        "error": type(exc).__name__,
                        "durationMs": 0,
                    }
                )
    preparation["cleanupSucceeded"] = cleanup_succeeded


def attach_app_principal_preparation(
    items: list[dict[str, Any]],
    preparation: dict[str, Any],
    settings: Settings,
) -> None:
    cleanup_succeeded = bool(preparation.get("cleanupSucceeded", True))
    for item in items:
        details = item.setdefault("details", {})
        if isinstance(details, dict):
            details["appPrincipalPreparation"] = preparation
        if cleanup_succeeded or item.get("status") == "skip":
            continue
        item["status"] = "fail" if item.get("requiredForReleaseCandidate") else "warn"
        item["summary"] = f"{item.get('summary', 'Live app-principal workflow completed.')} App cleanup failed."
        if settings.required and item.get("id") in REQUIRED_EVIDENCE_IDS:
            item["requiredForReleaseCandidate"] = True


def app_principal_blocked_evidence(
    evidence_id: str,
    settings: Settings,
    preparation: dict[str, Any],
) -> dict[str, Any]:
    if evidence_id == "live-network-beta.app-service-score" and not env_flag(
        settings.env,
        "CRYPTAD_CERT_LIVE_APP_SERVICE_SCORE",
    ):
        return evidence(
            evidence_id,
            "skip",
            False,
            "Live app-service score invocation was not requested.",
            {"enabled": False, "appPrincipalPreparation": preparation},
        )
    required = settings.required and evidence_id in REQUIRED_EVIDENCE_IDS
    return evidence(
        evidence_id,
        "fail" if required else "warn",
        required,
        "Live app-principal workflow did not run because required static apps could not be prepared.",
        {
            "enabled": True,
            "required": settings.required,
            "appPrincipalPreparation": preparation,
        },
    )


def collect_content_fetch(settings: Settings, client: CertHttpClient | None) -> dict[str, Any]:
    uri = settings.env.get("CRYPTAD_CERT_LIVE_CONTENT_FETCH_URI", "").strip()
    app_id = settings.env.get("CRYPTAD_CERT_LIVE_CONTENT_APP_ID", "feed-reader").strip() or "feed-reader"
    details = {
        "uri": safe_uri_shape(uri) if uri else {},
        "bodyStored": False,
        "appId": app_id,
    }
    if not uri:
        return missing_fixture_evidence(
            "live-network-beta.content-fetch",
            settings.required,
            ["CRYPTAD_CERT_LIVE_CONTENT_FETCH_URI"],
            details,
        )
    uri_shape = safe_uri_shape(uri)
    if not uri_shape["valid"] or uri_shape["family"] not in {"CHK", "SSK", "USK", "KSK"}:
        return evidence(
            "live-network-beta.content-fetch",
            "fail" if settings.required else "warn",
            settings.required,
            "Live content fetch URI is not a supported content-key family.",
            details,
        )
    assert client is not None
    try:
        result = client.request(
            "POST",
            "/api/v1/content/fetch",
            {"uri": uri, "format": "base64", "maxBytes": 262144},
            principal="app",
            app_id=app_id,
        )
    except (OSError, urllib.error.URLError, TimeoutError, MissingAppPrincipal) as exc:
        return failing_exception_evidence(
            "live-network-beta.content-fetch",
            settings,
            "Live content fetch could not be called with an app principal.",
            exc,
            details,
        )
    details["step"] = result.details
    details["appSession"] = client.app_session_details(app_id)
    details["byteCount"] = result.details["response"]["byteCount"]
    details["digest"] = "metadata-only"
    if not step_ok(result):
        return evidence(
            "live-network-beta.content-fetch",
            "fail" if settings.required else "warn",
            settings.required,
            "Live content fetch failed.",
            details,
        )
    return evidence("live-network-beta.content-fetch", "pass", settings.required, "Live content fetch passed.", details)


def collect_feed_subscription(settings: Settings, client: CertHttpClient | None) -> dict[str, Any]:
    uri = settings.env.get("CRYPTAD_CERT_LIVE_FEED_USK_URI", "").strip()
    app_id = settings.env.get("CRYPTAD_CERT_LIVE_FEED_APP_ID", "feed-reader").strip() or "feed-reader"
    details = {
        "feedSource": safe_uri_shape(uri) if uri else {},
        "appId": app_id,
        "rawFeedBodyStored": False,
        "pollIntervalSeconds": settings.poll_interval_seconds,
        "maxPollAttempts": settings.max_poll_attempts,
    }
    if not uri:
        return missing_fixture_evidence(
            "live-network-beta.feed-subscription",
            settings.required,
            ["CRYPTAD_CERT_LIVE_FEED_USK_URI"],
            details,
        )
    uri_shape = safe_uri_shape(uri)
    if not uri_shape["valid"] or uri_shape["family"] != "USK":
        return evidence(
            "live-network-beta.feed-subscription",
            "fail" if settings.required else "warn",
            settings.required,
            "Live feed subscription fixture must be a USK source.",
            details,
        )
    assert client is not None
    steps: list[dict[str, Any]] = []
    cleanup_steps: list[dict[str, Any]] = []
    subscription_id = ""
    subscription_deleted = False
    cleanup_ok = True
    ok = False
    workflow_exception: BaseException | None = None
    try:
        create = client.request(
            "POST",
            "/api/v1/content/subscriptions",
            {"uri": uri, "label": "cert-live-feed"},
            principal="app",
            app_id=app_id,
        )
        steps.append(create.details)
        subscription_id = extract_subscription_id(create.body)
        details["subscriptionIdObserved"] = bool(subscription_id)
        if subscription_id:
            details["subscriptionIdShape"] = f"{subscription_id[:8]}..." if len(subscription_id) > 8 else subscription_id
        if not step_ok(create) or not subscription_id:
            ok = False
        else:
            ok = True
            subscription_path = quote_segment(subscription_id)
            for method, path, data in (
                ("POST", f"/api/v1/content/subscriptions/{subscription_path}/refresh", {}),
                ("POST", f"/api/v1/content/subscriptions/{subscription_path}/pause", {}),
                ("POST", f"/api/v1/content/subscriptions/{subscription_path}/resume", {}),
            ):
                result = client.request(method, path, data, principal="app", app_id=app_id)
                steps.append(result.details)
                if not step_ok(result):
                    ok = False
                    break
    except (OSError, urllib.error.URLError, TimeoutError, MissingAppPrincipal) as exc:
        workflow_exception = exc
    finally:
        if subscription_id and not subscription_deleted:
            try:
                delete = client.request(
                    "DELETE",
                    f"/api/v1/content/subscriptions/{quote_segment(subscription_id)}",
                    None,
                    principal="app",
                    app_id=app_id,
                )
                cleanup_steps.append(delete.details)
                subscription_deleted = step_ok(delete)
                cleanup_ok = subscription_deleted
            except (OSError, urllib.error.URLError, TimeoutError, MissingAppPrincipal) as exc:
                cleanup_ok = False
                cleanup_steps.append(
                    {
                        "method": "DELETE",
                        "path": f"/api/v1/content/subscriptions/{quote_segment(subscription_id)}",
                        "principal": "app",
                        "status": "cleanup-exception",
                        "error": type(exc).__name__,
                        "durationMs": 0,
                    }
                )
    details["steps"] = steps
    details["cleanupSteps"] = cleanup_steps
    details["cleanupSucceeded"] = cleanup_ok
    details["appSession"] = client.app_session_details(app_id)
    if workflow_exception is not None:
        return failing_exception_evidence(
            "live-network-beta.feed-subscription",
            settings,
            "Live feed subscription workflow could not be called with an app principal.",
            workflow_exception,
            details,
        )
    details["lastKnownEditionObserved"] = ok
    details["queuePressureStoredAsMetadataOnly"] = True
    if not ok:
        return evidence(
            "live-network-beta.feed-subscription",
            "fail" if settings.required else "warn",
            settings.required,
            "Live feed subscription workflow failed.",
            details,
        )
    if not cleanup_ok:
        return evidence(
            "live-network-beta.feed-subscription",
            "fail" if settings.required else "warn",
            settings.required,
            "Live feed subscription workflow passed, but subscription cleanup failed.",
            details,
        )
    return evidence(
        "live-network-beta.feed-subscription",
        "pass",
        settings.required,
        "Live feed subscription and edition tracking passed.",
        details,
    )


def collect_profile_publish(
    settings: Settings,
    client: CertHttpClient | None,
    private_insert_present: bool,
    private_insert_value: str,
) -> dict[str, Any]:
    public_uri = settings.env.get("CRYPTAD_CERT_LIVE_PROFILE_PUBLIC_URI", "").strip()
    app_id = settings.env.get("CRYPTAD_CERT_LIVE_PROFILE_APP_ID", "profile-publisher").strip() or "profile-publisher"
    fetch_app_id = settings.env.get("CRYPTAD_CERT_LIVE_CONTENT_APP_ID", "feed-reader").strip() or "feed-reader"
    details = {
        "privateInsertFixturePresent": private_insert_present,
        "appId": app_id,
        "fetchAppId": fetch_app_id if public_uri else "",
        "publicUri": safe_uri_shape(public_uri) if public_uri else {},
        "rawProfileDocumentStored": False,
        "rawSignatureStored": False,
        "documentBase64Stored": False,
        "privateInsertUriStored": False,
        "fetchbackPollIntervalSeconds": settings.poll_interval_seconds,
        "fetchbackMaxPollAttempts": settings.max_poll_attempts,
    }
    if not private_insert_present:
        return missing_fixture_evidence(
            "live-network-beta.profile-publish",
            settings.required,
            ["CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV or CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE"],
            details,
        )
    assert client is not None
    steps: list[dict[str, Any]] = []
    try:
        identity = client.request(
            "POST",
            "/api/v1/app-vault/identities",
            {"label": "cert-live-profile", "scopes": "metadata.read,sign.domain-separated"},
            principal="app",
            app_id=app_id,
        )
        steps.append(identity.details)
        identity_id = extract_identity_id(identity.body)
        details["identityIdObserved"] = bool(identity_id)
        if not step_ok(identity) or not identity_id:
            ok = False
        else:
            profile_document = client.request(
                "POST",
                f"/api/v1/app-vault/identities/{quote_segment(identity_id)}/profile-document",
                {"displayName": "Crypta live beta certification", "bio": "synthetic certification profile"},
                principal="app",
                app_id=app_id,
            )
            steps.append(profile_document.details)
            document_base64 = document_base64_from_body(
                profile_document.body, "profileDocument"
            ) or document_base64_from_body(profile_document.body)
            details["signedDocumentObserved"] = bool(document_base64)
            ok = step_ok(profile_document) and bool(document_base64)
        if ok:
            insert = client.request(
                "POST",
                "/api/v1/queue/inserts/app-document",
                {
                    "insertUri": private_insert_value,
                    "identifier": "cert-live-profile",
                    "documentBase64": document_base64,
                    "contentType": "application/json",
                    "targetFilename": "profile.json",
                },
                principal="app",
                app_id=app_id,
            )
            steps.append(insert.details)
            ok = step_ok(insert)
        if ok and public_uri:
            ok, fetchback_attempts = poll_request_until_ok(
                settings,
                client,
                steps,
                "POST",
                "/api/v1/content/fetch",
                {"uri": public_uri, "format": "base64", "purpose": "profile-publish-fetchback"},
                principal="app",
                app_id=fetch_app_id,
            )
            details["fetchbackPollAttempts"] = fetchback_attempts
    except (OSError, urllib.error.URLError, TimeoutError, MissingAppPrincipal) as exc:
        details["steps"] = steps
        details["appSession"] = client.app_session_details(app_id)
        if public_uri:
            details["fetchAppSession"] = client.app_session_details(fetch_app_id)
        return failing_exception_evidence(
            "live-network-beta.profile-publish",
            settings,
            "Live synthetic profile publish could not be called with an app principal.",
            exc,
            details,
        )
    details["steps"] = steps
    details["appSession"] = client.app_session_details(app_id)
    if public_uri:
        details["fetchAppSession"] = client.app_session_details(fetch_app_id)
    details["publishedObjectObserved"] = ok and bool(public_uri)
    if not ok:
        return evidence(
            "live-network-beta.profile-publish",
            "fail" if settings.required else "warn",
            settings.required,
            "Live synthetic profile publish failed.",
            details,
        )
    return evidence(
        "live-network-beta.profile-publish",
        "pass",
        settings.required,
        "Live synthetic profile publish passed.",
        details,
    )


def collect_trust_publish(
    settings: Settings,
    client: CertHttpClient | None,
    private_insert_present: bool,
    private_insert_value: str,
) -> dict[str, Any]:
    public_uri = settings.env.get("CRYPTAD_CERT_LIVE_TRUST_PUBLIC_URI", "").strip()
    app_id = settings.env.get("CRYPTAD_CERT_LIVE_TRUST_APP_ID", "trust-graph").strip() or "trust-graph"
    details = {
        "privateInsertFixturePresent": private_insert_present,
        "appId": app_id,
        "publicUri": safe_uri_shape(public_uri) if public_uri else {},
        "rawTrustDocumentStored": False,
        "rawSignatureStored": False,
        "documentBase64Stored": False,
        "privateInsertUriStored": False,
        "importPollIntervalSeconds": settings.poll_interval_seconds,
        "importMaxPollAttempts": settings.max_poll_attempts,
    }
    if not private_insert_present:
        return missing_fixture_evidence(
            "live-network-beta.trust-statement-publish-import",
            settings.required,
            ["CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV or CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE"],
            details,
        )
    assert client is not None
    steps: list[dict[str, Any]] = []
    try:
        identity = client.request(
            "POST",
            "/api/v1/app-vault/identities",
            {"label": "cert-live-trust", "scopes": "metadata.read,sign.domain-separated"},
            principal="app",
            app_id=app_id,
        )
        steps.append(identity.details)
        identity_id = extract_identity_id(identity.body)
        details["identityIdObserved"] = bool(identity_id)
        if not step_ok(identity) or not identity_id:
            ok = False
        else:
            trust_document = client.request(
                "POST",
                f"/api/v1/app-vault/identities/{quote_segment(identity_id)}/trust-statement",
                {
                    "subjectKind": "profile",
                    "subjectUri": "USK@cert-live-profile/profile.json",
                    "context": "certification",
                    "score": 50,
                    "confidence": 80,
                    "reason": "synthetic certification trust statement",
                    "tags": "certification,live-beta",
                },
                principal="app",
                app_id=app_id,
            )
            steps.append(trust_document.details)
            document_base64 = document_base64_from_body(
                trust_document.body, "trustStatement", "trustStatement"
            ) or document_base64_from_body(trust_document.body, "trustStatement")
            details["signedDocumentObserved"] = bool(document_base64)
            ok = step_ok(trust_document) and bool(document_base64)
        if ok:
            insert = client.request(
                "POST",
                "/api/v1/queue/inserts/app-document",
                {
                    "insertUri": private_insert_value,
                    "identifier": "cert-live-trust-statement",
                    "documentBase64": document_base64,
                    "contentType": "application/json",
                    "targetFilename": "trust.json",
                },
                principal="app",
                app_id=app_id,
            )
            steps.append(insert.details)
            ok = step_ok(insert)
        if ok and public_uri:
            ok, import_attempts = poll_request_until_ok(
                settings,
                client,
                steps,
                "POST",
                "/api/v1/trust-graph/import-uri",
                {"uri": public_uri},
                principal="app",
                app_id=app_id,
            )
            details["importPollAttempts"] = import_attempts
    except (OSError, urllib.error.URLError, TimeoutError, MissingAppPrincipal) as exc:
        details["steps"] = steps
        details["appSession"] = client.app_session_details(app_id)
        return failing_exception_evidence(
            "live-network-beta.trust-statement-publish-import",
            settings,
            "Live synthetic trust statement publish/import could not be called with an app principal.",
            exc,
            details,
        )
    details["steps"] = steps
    details["appSession"] = client.app_session_details(app_id)
    details["importObserved"] = ok and bool(public_uri)
    if not ok:
        return evidence(
            "live-network-beta.trust-statement-publish-import",
            "fail" if settings.required else "warn",
            settings.required,
            "Live synthetic trust statement publish/import failed.",
            details,
        )
    return evidence(
        "live-network-beta.trust-statement-publish-import",
        "pass",
        settings.required,
        "Live synthetic trust statement publish/import passed.",
        details,
    )


def collect_app_service_score(settings: Settings, client: CertHttpClient | None) -> dict[str, Any]:
    enabled = env_flag(settings.env, "CRYPTAD_CERT_LIVE_APP_SERVICE_SCORE")
    caller_app_id = settings.env.get("CRYPTAD_CERT_LIVE_APP_SERVICE_CALLER_APP_ID", "social-inbox").strip() or "social-inbox"
    details = {
        "enabled": enabled,
        "callerAppId": caller_app_id,
        "providerAppId": "trust-graph",
        "serviceId": "trust.score",
        "rawSubjectStored": False,
        "providerAppDataStored": False,
    }
    if not enabled:
        return evidence(
            "live-network-beta.app-service-score",
            "skip",
            False,
            "Live app-service score invocation was not requested.",
            details,
        )
    assert client is not None
    steps: list[dict[str, Any]] = []
    grant_id = ""
    grant_created = False
    ok = False
    workflow_exception: BaseException | None = None
    try:
        existing_grant_ids: set[str] | None = None
        list_grants = client.request(
            "GET",
            "/api/v1/app-services/grants",
            principal="app",
            app_id=caller_app_id,
        )
        steps.append(list_grants.details)
        if 200 <= list_grants.status < 300:
            existing_grant_ids = extract_grant_ids(list_grants.body)
            details["grantListBeforeObserved"] = True
            details["grantListBeforeCount"] = len(existing_grant_ids)
        else:
            details["grantListBeforeObserved"] = False
            details["grantListBeforeStatus"] = list_grants.status
            ok = False
            details["grantRequestSkipped"] = "existing grants could not be listed safely"
        if existing_grant_ids is not None:
            request_grant = client.request(
                "POST",
                "/api/v1/app-services/grants",
                {
                    "providerAppId": "trust-graph",
                    "serviceId": "trust.score",
                    "scopes": "score.read",
                    "contexts": "message-author",
                    "purpose": "Live-network beta certification score smoke.",
                },
                principal="app",
                app_id=caller_app_id,
            )
            steps.append(request_grant.details)
            grant_id = extract_grant_id(request_grant.body)
            grant_status = extract_grant_status(request_grant.body)
            grant_created_from_body = grant_created_by_request(request_grant.body)
            grant_created_from_list = bool(
                grant_id and existing_grant_ids is not None and grant_id not in existing_grant_ids
            )
            grant_created = grant_created_from_body or grant_created_from_list
            details["grantIdObserved"] = bool(grant_id)
            details["grantStatus"] = grant_status or "unknown"
            details["grantCreatedByThisRun"] = grant_created
            details["grantCreatedInferredFromList"] = grant_created_from_list
            details["grantReused"] = bool(grant_id and not grant_created)
            if not step_ok(request_grant) or not grant_id:
                ok = False
            elif grant_created:
                grant_path = quote_segment(grant_id)
                approve = client.request("POST", f"/api/v1/app-services/grants/{grant_path}/approve", {})
                steps.append(approve.details)
                ok = step_ok(approve)
            elif grant_status == "active":
                details["grantApprovalSkipped"] = "returned grant was already active and was not created by this run"
                ok = True
            else:
                details["grantApprovalSkipped"] = "returned grant ownership was not observable"
                ok = False
            if ok:
                invoke = client.request(
                    "POST",
                    "/api/v1/app-services/trust-graph/services/trust.score/invoke",
                    {
                        "subjectKind": "identity",
                        "subjectUri": "crypta:identity:cert-live-subject",
                        "context": "message-author",
                    },
                    principal="app",
                    app_id=caller_app_id,
                )
                steps.append(invoke.details)
                ok = step_ok(invoke)
            elif grant_id and not grant_created:
                details["grantRevokeSkipped"] = "returned grant was not created by this run"
            audit = client.request("GET", "/api/v1/app-services/audit")
            steps.append(audit.details)
            ok = ok and step_ok(audit, True)
    except (OSError, urllib.error.URLError, TimeoutError, MissingAppPrincipal) as exc:
        workflow_exception = exc
    finally:
        if grant_id and grant_created:
            details["grantRevokeAttempted"] = True
            revoke_path = f"/api/v1/app-services/grants/{quote_segment(grant_id)}/revoke"
            try:
                revoke = client.request(
                    "POST",
                    revoke_path,
                    {},
                    principal="app",
                    app_id=caller_app_id,
                )
                steps.append(revoke.details)
                details["grantRevokeSucceeded"] = step_ok(revoke)
                ok = ok and details["grantRevokeSucceeded"]
            except (OSError, urllib.error.URLError, TimeoutError, MissingAppPrincipal) as exc:
                steps.append(
                    {
                        "method": "POST",
                        "path": revoke_path,
                        "principal": "app",
                        "status": "cleanup-exception",
                        "error": type(exc).__name__,
                        "durationMs": 0,
                    }
                )
                details["grantRevokeSucceeded"] = False
                ok = False
        elif grant_id and not grant_created:
            details["grantRevokeAttempted"] = False
            details["grantRevokeSkipped"] = "returned grant was not created by this run"
    details["steps"] = steps
    details["appSession"] = client.app_session_details(caller_app_id)
    if workflow_exception is not None:
        return failing_exception_evidence(
            "live-network-beta.app-service-score",
            settings,
            "Live app-service score invocation could not be called with an app principal.",
            workflow_exception,
            details,
        )
    if not ok:
        return evidence(
            "live-network-beta.app-service-score",
            "warn",
            False,
            "Live app-service score invocation did not complete.",
            details,
        )
    return evidence(
        "live-network-beta.app-service-score",
        "pass",
        False,
        "Live app-service score invocation passed.",
        details,
    )


def collect_perf_budget(settings: Settings, evidence_items: list[dict[str, Any]], total_duration_ms: int) -> dict[str, Any]:
    step_durations: dict[str, int] = {}
    retry_count = 0
    for item in evidence_items:
        duration = 0
        details = item.get("details", {})
        if not isinstance(details, dict):
            continue
        for key in ("step", "diagnostics"):
            value = details.get(key)
            if isinstance(value, dict):
                duration += int(value.get("durationMs", 0))
        for step in details.get("steps", []):
            if isinstance(step, dict):
                duration += int(step.get("durationMs", 0))
                poll_attempt = step.get("pollAttempt")
                if isinstance(poll_attempt, int) and poll_attempt > 1:
                    retry_count += 1
        if duration:
            step_durations[str(item.get("id"))] = duration
    failures: list[str] = []
    if settings.max_duration_seconds and total_duration_ms > settings.max_duration_seconds * 1000:
        failures.append("total duration exceeded configured budget")
    if settings.max_step_duration_seconds:
        slow_steps = [
            evidence_id
            for evidence_id, duration in step_durations.items()
            if duration > settings.max_step_duration_seconds * 1000
        ]
        if slow_steps:
            failures.append("one or more step durations exceeded configured budget")
    details = {
        "totalDurationMs": total_duration_ms,
        "stepDurationsMs": step_durations,
        "retryCount": retry_count,
        "pollIntervalSeconds": settings.poll_interval_seconds,
        "maxPollAttempts": settings.max_poll_attempts,
        "timeoutSeconds": settings.timeout_seconds,
        "contentByteCap": 262144,
    }
    if failures:
        return evidence(
            "live-network-beta.interop-perf-budget",
            "fail" if settings.required else "warn",
            settings.required,
            "Live-network beta interop/performance budget found issues.",
            {**details, "failures": failures},
        )
    return evidence(
        "live-network-beta.interop-perf-budget",
        "pass",
        settings.required,
        "Live-network beta interop/performance budget metadata was recorded.",
        details,
    )


def scan_forbidden_text(text: str, secrets: list[str], workspace_root: Path) -> list[str]:
    findings: list[str] = []
    for index, secret in enumerate(secrets):
        if secret and secret in text:
            findings.append(f"secret-{index}")
    pattern_checks = (
        ("private-insert-uri", PRIVATE_URI_RE),
        ("token", TOKEN_RE),
        ("raw-body", RAW_BODY_RE),
        ("raw-signature", RAW_SIGNATURE_RE),
        ("private-key", PRIVATE_KEY_RE),
        ("query-secret", QUERY_SECRET_RE),
        ("windows-path", WINDOWS_PATH_RE),
    )
    for name, pattern in pattern_checks:
        if pattern.search(text):
            findings.append(name)
    for match in ABSOLUTE_PATH_RE.finditer(text):
        value = match.group(0)
        if value.startswith(("/api/v1/", "/apps/", "/app/node/")):
            continue
        if str(workspace_root) and value.startswith(str(workspace_root)):
            findings.append("local-absolute-path")
            continue
        if value.startswith(("/home/", "/Users/", "/work/", "/tmp/")):
            findings.append("local-absolute-path")
    return sorted(dict.fromkeys(findings))


def collect_redaction(
    settings: Settings,
    summary_without_redaction: dict[str, Any],
    report_without_redaction: str,
    private_insert_value: str,
    app_session_values: list[str],
) -> dict[str, Any]:
    text = json.dumps(summary_without_redaction, sort_keys=True) + "\n" + report_without_redaction
    findings = scan_forbidden_text(
        text,
        [settings.form_password, private_insert_value, *app_session_values],
        settings.workspace_root,
    )
    details = {
        "forbiddenPatternsChecked": True,
        "rawBodiesStored": False,
        "privateInsertUrisStored": False,
        "localPathsStored": False,
        "formPasswordStored": False,
        "tokenValuesStored": False,
        "rawSignaturesStored": False,
        "findings": findings,
        "redactionFindings": findings,
    }
    if findings:
        return evidence(
            "live-network-beta.redaction",
            "fail",
            True,
            "Live-network beta redaction scan found forbidden output.",
            details,
        )
    return evidence(
        "live-network-beta.redaction",
        "pass",
        True,
        "Live-network beta artifact redaction and privacy guard passed.",
        details,
    )


def overall_status(required: bool, evidence_items: list[dict[str, Any]]) -> str:
    if any(item["requiredForReleaseCandidate"] and item["status"] in {"fail", "missing", "skip"} for item in evidence_items):
        return "fail"
    if any(item["requiredForReleaseCandidate"] and item["status"] == "warn" for item in evidence_items):
        return "warn"
    if any(item["status"] in {"fail", "missing", "warn"} for item in evidence_items):
        return "warn"
    return "pass"


def smoke_exit_code(settings: Settings, summary: dict[str, Any]) -> int:
    if summary.get("status") != "fail":
        return 0
    if settings.required:
        return 1
    for item in summary.get("evidence", []):
        if item.get("id") == "live-network-beta.redaction" and item.get("status") == "fail":
            return 1
    return 0


def catalog_blocked_mutation_evidence(evidence_id: str, settings: Settings, catalog_status: str) -> dict[str, Any]:
    required = settings.required and evidence_id in REQUIRED_EVIDENCE_IDS
    return evidence(
        evidence_id,
        "fail" if required else "skip",
        required,
        "Live workflow mutation did not run because catalog verification did not pass.",
        {
            "enabled": True,
            "required": settings.required,
            "catalogEvidenceId": "live-network-beta.catalog-usk-fetch",
            "catalogStatus": catalog_status,
            "mutationSkipped": True,
        },
    )


def run_smoke(settings: Settings, transport: Transport | None = None) -> tuple[dict[str, Any], str, int]:
    started = utc_now()
    start_ms = monotonic_ms()
    validation = validate_local_node_url(settings.node_base_url)
    client = (
        CertHttpClient(validation.normalized, settings.form_password, settings.timeout_seconds, transport)
        if validation.ok and settings.form_password
        else None
    )
    private_insert_present, private_insert_source, private_insert_value = load_private_insert_fixture(settings.env)
    evidence_items: list[dict[str, Any]] = []
    preflight = collect_preflight(settings, validation, client)
    evidence_items.append(preflight)
    if client is None or preflight["status"] != "pass":
        for evidence_id in EVIDENCE_IDS[1:-2]:
            evidence_items.append(
                evidence(
                    evidence_id,
                    "fail" if settings.required and evidence_id in REQUIRED_EVIDENCE_IDS else "skip",
                    settings.required and evidence_id in REQUIRED_EVIDENCE_IDS,
                    "Live workflow did not run because preflight did not pass.",
                    {"enabled": True, "required": settings.required, "preflightStatus": preflight["status"]},
                )
            )
    else:
        catalog = collect_catalog(settings, client)
        evidence_items.append(catalog)
        if catalog["status"] == "pass":
            evidence_items.append(collect_app_lifecycle(settings, client))
            app_principal_preparation = prepare_app_principals(settings, client, private_insert_present)
            app_principal_evidence: list[dict[str, Any]] = []
            try:
                if app_principal_preparation["ok"]:
                    app_principal_evidence.append(collect_content_fetch(settings, client))
                    app_principal_evidence.append(collect_feed_subscription(settings, client))
                    app_principal_evidence.append(
                        collect_profile_publish(settings, client, private_insert_present, private_insert_value)
                    )
                    app_principal_evidence.append(
                        collect_trust_publish(settings, client, private_insert_present, private_insert_value)
                    )
                    app_principal_evidence.append(collect_app_service_score(settings, client))
                else:
                    for evidence_id in APP_PRINCIPAL_GATED_EVIDENCE_IDS:
                        app_principal_evidence.append(
                            app_principal_blocked_evidence(evidence_id, settings, app_principal_preparation)
                        )
            finally:
                cleanup_prepared_app_principals(client, app_principal_preparation)
            attach_app_principal_preparation(app_principal_evidence, app_principal_preparation, settings)
            evidence_items.extend(app_principal_evidence)
        else:
            evidence_items.append(
                catalog_blocked_mutation_evidence(
                    "live-network-beta.app-install-update-rollback",
                    settings,
                    catalog["status"],
                )
            )
            evidence_items.append(collect_content_fetch(settings, client))
            for evidence_id in CATALOG_GATED_MUTATING_EVIDENCE_IDS[1:]:
                evidence_items.append(catalog_blocked_mutation_evidence(evidence_id, settings, catalog["status"]))
    total_duration_ms = max(0, monotonic_ms() - start_ms)
    evidence_items.append(collect_perf_budget(settings, evidence_items, total_duration_ms))
    summary = build_summary(settings, started, total_duration_ms, validation, evidence_items, private_insert_source)
    report = render_report(summary)
    app_session_values = client.app_session_values() if client is not None else []
    redaction_evidence = collect_redaction(settings, summary, report, private_insert_value, app_session_values)
    evidence_items.append(redaction_evidence)
    total_duration_ms = max(0, monotonic_ms() - start_ms)
    summary = build_summary(settings, started, total_duration_ms, validation, evidence_items, private_insert_source)
    report = render_report(summary)
    exit_code = smoke_exit_code(settings, summary)
    return summary, report, exit_code


def build_summary(
    settings: Settings,
    started: str,
    duration_ms: int,
    validation: UrlValidation,
    evidence_items: list[dict[str, Any]],
    private_insert_source: str,
) -> dict[str, Any]:
    finished = utc_now()
    redaction_status = "missing"
    for item in evidence_items:
        if item.get("id") == "live-network-beta.redaction":
            redaction_status = str(item.get("status", "missing"))
    passed = sum(1 for item in evidence_items if item.get("status") == "pass")
    failed = sum(1 for item in evidence_items if item.get("status") == "fail")
    skipped = sum(1 for item in evidence_items if item.get("status") == "skip")
    warnings = sum(1 for item in evidence_items if item.get("status") == "warn")
    return {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "live-network-beta-smoke",
        "mode": settings.mode,
        "enabled": True,
        "required": settings.required,
        "status": overall_status(settings.required, evidence_items),
        "startedAt": started,
        "finishedAt": finished,
        "durationMs": duration_ms,
        "node": {
            "baseUrlShape": validation.shape,
            "localhostOnly": validation.ok,
            "version": "redacted-or-safe",
            "build": "redacted-or-safe",
        },
        "fixturePresence": {
            "catalogSource": bool(settings.env.get("CRYPTAD_CERT_LIVE_CATALOG_SOURCE", "").strip()),
            "contentFetchUri": bool(settings.env.get("CRYPTAD_CERT_LIVE_CONTENT_FETCH_URI", "").strip()),
            "feedUskUri": bool(settings.env.get("CRYPTAD_CERT_LIVE_FEED_USK_URI", "").strip()),
            "privateInsertFixture": private_insert_source != "missing",
            "privateInsertFixtureSource": private_insert_source,
            "profilePublicUri": bool(settings.env.get("CRYPTAD_CERT_LIVE_PROFILE_PUBLIC_URI", "").strip()),
            "trustPublicUri": bool(settings.env.get("CRYPTAD_CERT_LIVE_TRUST_PUBLIC_URI", "").strip()),
        },
        "stepCounts": {
            "total": len(evidence_items),
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "skipped": skipped,
        },
        "artifactPaths": [SUMMARY_FILE_NAME, REPORT_FILE_NAME],
        "evidence": evidence_items,
        "redaction": {
            "status": redaction_status,
            "forbiddenPatternsChecked": redaction_status != "missing",
            "rawBodiesStored": False,
            "privateInsertUrisStored": False,
            "localPathsStored": False,
        },
    }


def render_report(summary: dict[str, Any]) -> str:
    lines = [
        "# Live Network Beta Smoke",
        "",
        f"- Mode: `{summary['mode']}`",
        f"- Status: `{summary['status']}`",
        f"- Required: `{'yes' if summary['required'] else 'no'}`",
        f"- Node: `{summary['node']['baseUrlShape']}`",
        f"- Duration: `{summary['durationMs']} ms`",
        "",
        "## Evidence",
        "",
        "| Evidence | Status | Required | Summary |",
        "| --- | --- | --- | --- |",
    ]
    for item in summary["evidence"]:
        lines.append(
            "| `{id}` | `{status}` | {required} | {summary_text} |".format(
                id=item["id"],
                status=item["status"],
                required="yes" if item["requiredForReleaseCandidate"] else "no",
                summary_text=str(item["summary"]).replace("|", "\\|"),
            )
        )
    lines.extend(
        [
            "",
            "## Privacy",
            "",
            "Artifacts contain status, timing, counts, safe URI shapes, and redaction booleans only. Raw bodies, signatures, tokens, form passwords, private insert URIs, private keys, and local absolute paths are not written.",
            "",
        ]
    )
    return "\n".join(lines)


def settings_from_args(args: argparse.Namespace, env: dict[str, str] | None = None) -> Settings:
    env_map = dict(os.environ if env is None else env)
    workspace_root = args.workspace_root.resolve()
    out_dir = (workspace_root / args.out_dir).resolve() if not args.out_dir.is_absolute() else args.out_dir.resolve()
    mode = args.mode or env_map.get("CRYPTAD_CERT_MODE", "pr")
    if mode not in MODES:
        raise SystemExit(f"--mode must be one of {', '.join(MODES)}")
    required = bool(args.require or env_flag(env_map, "CRYPTAD_CERT_REQUIRE_LIVE_NETWORK_BETA"))
    node_base_url = args.node_base_url or env_map.get("CRYPTAD_CERT_NODE_BASE_URL", "")
    return Settings(
        workspace_root=workspace_root,
        out_dir=out_dir,
        mode=mode,
        node_base_url=node_base_url,
        required=required,
        form_password=env_map.get("CRYPTAD_CERT_FORM_PASSWORD", ""),
        timeout_seconds=int_env(env_map, "CRYPTAD_CERT_LIVE_TIMEOUT_SECONDS", 900),
        poll_interval_seconds=int_env(env_map, "CRYPTAD_CERT_LIVE_POLL_INTERVAL_SECONDS", 5),
        max_poll_attempts=int_env(env_map, "CRYPTAD_CERT_LIVE_MAX_POLL_ATTEMPTS", 24),
        max_duration_seconds=int_env(env_map, "CRYPTAD_CERT_LIVE_MAX_DURATION_SECONDS", 0),
        max_step_duration_seconds=int_env(env_map, "CRYPTAD_CERT_LIVE_MAX_STEP_DURATION_SECONDS", 0),
        env=env_map,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run Python-only self-tests.")
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    parser.add_argument("--out-dir", type=Path, default=Path("build/release-certification/live-network-beta-smoke"))
    parser.add_argument("--mode", choices=MODES, default=None)
    parser.add_argument("--node-base-url", default="", help="Local Crypta node base URL.")
    parser.add_argument("--require", action="store_true", help="Fail when live-network beta evidence is missing or failing.")
    return parser


class FakeTransport:
    def __init__(
        self,
        failures: set[str] | None = None,
        *,
        exceptions: set[str] | None = None,
        path_statuses: dict[str, int] | None = None,
        body_status_sequences: dict[tuple[str, str, str], list[int]] | None = None,
        catalog_source: str = "crypta:USK@PUBLIC/cryptad-app-catalog.properties",
        conflict_on_catalog_add: bool = False,
        runtime_envelope: bool = False,
        require_app_origin: bool = True,
        bootstrap_requires_install: bool = True,
        app_service_grant_created: bool = True,
        app_service_grant_status: str = "pending",
    ) -> None:
        self.failures = failures or set()
        self.exceptions = exceptions or set()
        self.path_statuses = dict(path_statuses or {})
        self.body_status_sequences = {
            key: list(value)
            for key, value in (body_status_sequences or {}).items()
        }
        self.catalog_source = catalog_source
        self.conflict_on_catalog_add = conflict_on_catalog_add
        self.runtime_envelope = runtime_envelope
        self.require_app_origin = require_app_origin
        self.bootstrap_requires_install = bootstrap_requires_install
        self.app_service_grant_created = app_service_grant_created
        self.app_service_grant_status = app_service_grant_status
        self.calls: list[tuple[str, str]] = []
        self.headers_by_call: list[dict[str, str]] = []
        self.deleted_catalogs: set[str] = set()
        self.installed_apps: set[str] = set()
        self.running_apps: set[str] = set()
        self.subscription_create_saw_uri = False
        self.approved_grants: set[str] = set()
        self.revoked_grants: set[str] = set()

    def __call__(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
        _timeout_seconds: int,
    ) -> tuple[int, dict[str, str], bytes]:
        self.calls.append((method, path))
        self.headers_by_call.append(dict(headers))
        if path in self.exceptions:
            raise TimeoutError(f"forced timeout for {path}")
        body_status = self._body_status(path, body)
        if body_status is not None:
            payload = {"error": "forced_status", "status": body_status}
            return body_status, {"Content-Type": "application/json"}, json.dumps(payload).encode("utf-8")
        if path in self.path_statuses:
            status = self.path_statuses[path]
            payload = {"error": "forced_status", "status": status}
            return status, {"Content-Type": "application/json"}, json.dumps(payload).encode("utf-8")
        if path in self.failures:
            return 500, {"Content-Type": "application/json"}, b'{"status":"failed","rawBody":"not returned"}'
        if self._app_route_requires_session(method, path):
            if not headers.get(APP_SESSION_HEADER):
                return 403, {"Content-Type": "application/json"}, b'{"error":"missing_app_session"}'
            if self.require_app_origin and headers.get("Origin") != self._expected_origin_for_headers(headers):
                return 403, {"Content-Type": "application/json"}, b'{"error":"origin_mismatch"}'
        if self._host_mutation_requires_password(method, path) and not headers.get(APP_SESSION_HEADER) and (
            body is None or f"{FORM_PASSWORD_PARAMETER}=".encode("ascii") not in body
        ):
            return 403, {"Content-Type": "application/json"}, b'{"error":"missing_form_password"}'
        if path == "/api/v1/app-catalogs/add" and self.conflict_on_catalog_add:
            return 409, {"Content-Type": "application/json"}, b'{"error":"catalog_already_exists"}'
        payload: Any
        if path.startswith("/apps/") and path.endswith("/.well-known/cryptad-bootstrap.json"):
            app_id = urllib.parse.unquote(path.split("/")[2])
            if self.bootstrap_requires_install and app_id not in self.installed_apps:
                return 404, {"Content-Type": "application/json"}, b'{"error":"app_not_installed"}'
            payload = {
                "appId": app_id,
                "uiOrigin": self._ui_origin_for_app(app_id),
                "uiOriginMode": "isolated-loopback",
                "uiOriginStatus": "active",
                "browserSessionToken": f"browser-session-{app_id}",
                "browserSessionExpiresAt": "2026-01-01T00:00:00Z",
            }
        elif path == "/api/v1/app-catalogs/add" or (
            path.startswith("/api/v1/app-catalogs/") and path.endswith("/refresh")
        ):
            payload = {
                "catalog": {
                    "catalogId": "crypta-first-party-beta",
                    "name": "Crypta First-Party Beta Catalog",
                    "appCount": 1,
                    "signatureKeyId": "crypta-first-party-beta",
                }
            }
        elif path == "/api/v1/app-catalogs":
            payload = {
                "catalogs": [
                    {
                        "catalogId": "crypta-first-party-beta",
                        "source": self.catalog_source,
                        "appCount": 1,
                        "signatureKeyId": "crypta-first-party-beta",
                    }
                ]
            }
        elif method == "DELETE" and path.startswith("/api/v1/app-catalogs/"):
            catalog_id = urllib.parse.unquote(path.rsplit("/", 1)[-1])
            self.deleted_catalogs.add(catalog_id)
            payload = {"catalog": {"catalogId": catalog_id, "removed": True}}
        elif path.endswith("/apps"):
            payload = {"apps": [{"appId": "site-publisher"}]}
        elif path.endswith("/diagnostics"):
            payload = {"status": "ok", "node": "redacted"}
        elif path.endswith("/runtime"):
            app_id = path.split("/")[4]
            if app_id not in self.installed_apps:
                return 404, {"Content-Type": "application/json"}, b'{"error":"not_found"}'
            running = app_id in self.running_apps
            payload = {
                "appId": app_id,
                "state": "RUNNING" if running else "STOPPED",
                "running": running,
                "status": "running" if running else "stopped",
            }
            if self.runtime_envelope:
                payload = {"runtime": payload}
        elif "/app-catalogs/" in path and path.endswith("/install"):
            app_id = path.split("/")[-2]
            if app_id in self.installed_apps:
                return 409, {"Content-Type": "application/json"}, b'{"error":"app_already_installed"}'
            self.installed_apps.add(app_id)
            payload = {"status": "installed", "appId": app_id}
        elif method == "POST" and path.startswith("/api/v1/apps/") and path.endswith("/start"):
            app_id = path.split("/")[-2]
            if app_id in self.running_apps:
                return 409, {"Content-Type": "application/json"}, b'{"error":"app_already_running"}'
            self.installed_apps.add(app_id)
            self.running_apps.add(app_id)
            payload = {"status": "running", "appId": app_id}
        elif method == "POST" and path.startswith("/api/v1/apps/") and path.endswith("/stop"):
            app_id = path.split("/")[-2]
            self.running_apps.discard(app_id)
            payload = {"status": "stopped", "appId": app_id}
        elif method == "DELETE" and path.startswith("/api/v1/apps/"):
            app_id = path.split("/")[-1]
            self.installed_apps.discard(app_id)
            self.running_apps.discard(app_id)
            payload = {"status": "deleted", "appId": app_id}
        elif path.endswith("/profile-document"):
            payload = {
                "schema": "crypta.profile.v1",
                "profile": {"displayName": "Crypta live beta certification"},
                "identity": {"identityId": "identity-profile-cert"},
                "signature": {"signatureBase64": "signature-redacted"},
            }
        elif path.endswith("/trust-statement"):
            payload = {
                "trustStatement": {
                    "type": "crypta.trust.statement.v1",
                    "payload": {"subject": "cert-live-subject"},
                    "signature": {"signatureBase64": "signature-redacted"},
                }
            }
        elif path == "/api/v1/app-vault/identities":
            payload = {"identityId": "identity-cert-live"}
        elif path == "/api/v1/queue/inserts/app-document":
            payload = {"status": "queued", "insertUri": "<redacted>", "identifier": "cert-live"}
        elif path == "/api/v1/content/subscriptions":
            if method == "POST" and not self._body_has_parameter(body, "uri"):
                return 400, {"Content-Type": "application/json"}, b'{"error":"missing_uri"}'
            self.subscription_create_saw_uri = True
            payload = {"subscription": {"subscriptionId": "sub-self-test", "edition": 7}}
        elif "/content/subscriptions/sub-self-test" in path:
            payload = {"subscription": {"subscriptionId": "sub-self-test", "edition": 7}}
        elif path == "/api/v1/app-services/grants" and method == "GET":
            grants = []
            if not self.app_service_grant_created:
                grants.append(
                    {
                        "grantId": "grant-self-test",
                        "status": self.app_service_grant_status,
                        "consumerAppId": "social-inbox",
                        "providerAppId": "trust-graph",
                        "serviceId": "trust.score",
                    }
                )
            payload = {"grants": grants}
        elif path == "/api/v1/app-services/grants" and method == "POST":
            payload = {
                "grant": {
                    "grantId": "grant-self-test",
                    "status": self.app_service_grant_status,
                    "created": self.app_service_grant_created,
                    "reused": not self.app_service_grant_created,
                }
            }
        elif path == "/api/v1/app-services/grants/grant-self-test/approve":
            if self.app_service_grant_status == "active" and not self.app_service_grant_created:
                return 409, {"Content-Type": "application/json"}, b'{"error":"grant_already_active"}'
            self.approved_grants.add("grant-self-test")
            payload = {"grant": {"grantId": "grant-self-test", "status": "active"}}
        elif path == "/api/v1/app-services/grants/grant-self-test/revoke":
            self.revoked_grants.add("grant-self-test")
            payload = {"grant": {"grantId": "grant-self-test", "status": "revoked"}}
        elif "/api/v1/app-services/grants/grant-self-test" in path:
            payload = {"grant": {"grantId": "grant-self-test", "status": "active"}}
        elif path.endswith("/invoke"):
            payload = {"serviceCall": {"status": "ok", "result": {"score": 50}}}
        else:
            payload = {"status": "ok", "id": "cert-live-feed", "edition": 7, "byteCount": 42}
        return 200, {"Content-Type": "application/json"}, json.dumps(payload).encode("utf-8")

    @staticmethod
    def _app_route_requires_session(method: str, path: str) -> bool:
        return (
            path.startswith("/api/v1/content/fetch")
            or path.startswith("/api/v1/content/subscriptions")
            or path.startswith("/api/v1/app-vault/")
            or path.startswith("/api/v1/queue/inserts/app-document")
            or path.startswith("/api/v1/trust-graph/import-uri")
            or (path == "/api/v1/app-services/grants" and method in {"GET", "POST"})
            or (path.startswith("/api/v1/app-services/trust-graph/services/") and path.endswith("/invoke"))
            or (path.startswith("/api/v1/app-services/grants/") and path.endswith("/revoke"))
        )

    @staticmethod
    def _host_mutation_requires_password(method: str, path: str) -> bool:
        if method not in {"POST", "DELETE", "PATCH", "PUT"}:
            return False
        if path.startswith("/api/v1/content/"):
            return False
        if path.startswith("/api/v1/app-vault/"):
            return False
        if path.startswith("/api/v1/queue/inserts/app-document"):
            return False
        if path == "/api/v1/app-services/grants" or path.endswith("/invoke") or path.endswith("/revoke"):
            return False
        return path.startswith("/api/v1/")

    @staticmethod
    def _body_has_parameter(body: bytes | None, name: str) -> bool:
        return bool(FakeTransport._body_parameter(body, name))

    @staticmethod
    def _body_parameter(body: bytes | None, name: str) -> str:
        if body is None:
            return ""
        try:
            params = urllib.parse.parse_qs(body.decode("utf-8"), keep_blank_values=True)
        except UnicodeDecodeError:
            return ""
        for value in params.get(name, []):
            if value.strip():
                return value.strip()
        return ""

    def _body_status(self, path: str, body: bytes | None) -> int | None:
        for key in list(self.body_status_sequences):
            match_path, name, value = key
            if path != match_path or self._body_parameter(body, name) != value:
                continue
            statuses = self.body_status_sequences[key]
            if not statuses:
                del self.body_status_sequences[key]
                return None
            status = statuses.pop(0)
            if not statuses:
                del self.body_status_sequences[key]
            return status
        return None

    @staticmethod
    def _ui_origin_for_app(app_id: str) -> str:
        port = 30000 + (sum(ord(character) for character in app_id) % 10000)
        return f"http://127.0.0.1:{port}"

    def _expected_origin_for_headers(self, headers: dict[str, str]) -> str:
        session = headers.get(APP_SESSION_HEADER, "")
        if not session.startswith("browser-session-"):
            return ""
        return self._ui_origin_for_app(session.removeprefix("browser-session-"))


def run_no_redirect_self_test() -> None:
    captured_posts: list[dict[str, str]] = []
    captured_leaks: list[dict[str, str]] = []

    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        redirect_target = ""

        def do_GET(self) -> None:
            if self.path == "/apps/redirect-app/.well-known/cryptad-bootstrap.json":
                payload = {
                    "appId": "redirect-app",
                    "uiOrigin": f"http://127.0.0.1:{self.server.server_port}",
                    "browserSessionToken": "redirect-session-token",
                }
                encoded = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
                return
            if self.path == "/leak":
                captured_leaks.append({"path": self.path, "session": self.headers.get(APP_SESSION_HEADER, "")})
            self.send_response(500)
            self.end_headers()

        def do_POST(self) -> None:
            body_length = int(self.headers.get("Content-Length", "0") or "0")
            if body_length:
                self.rfile.read(body_length)
            if self.path == "/redirect":
                captured_posts.append(
                    {
                        "path": self.path,
                        "session": self.headers.get(APP_SESSION_HEADER, ""),
                        "origin": self.headers.get("Origin", ""),
                    }
                )
                self.send_response(302)
                self.send_header("Location", self.redirect_target)
                self.end_headers()
                return
            if self.path == "/leak":
                captured_leaks.append({"path": self.path, "session": self.headers.get(APP_SESSION_HEADER, "")})
            self.send_response(500)
            self.end_headers()

        def log_message(self, _format: str, *_args: Any) -> None:
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    RedirectHandler.redirect_target = f"http://127.0.0.1:{server.server_port}/leak"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = CertHttpClient(f"http://127.0.0.1:{server.server_port}", "self-test-form-password", 2)
        result = client.request("POST", "/redirect", {}, principal="app", app_id="redirect-app")
        assert result.status == 302, result.details
        assert captured_posts == [
            {
                "path": "/redirect",
                "session": "redirect-session-token",
                "origin": f"http://127.0.0.1:{server.server_port}",
            }
        ], captured_posts
        assert captured_leaks == [], captured_leaks
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def run_no_proxy_self_test() -> None:
    original_proxy_env = {
        name: os.environ.get(name)
        for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy")
    }
    try:
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:9"
        os.environ["ALL_PROXY"] = "http://127.0.0.1:9"
        os.environ.pop("NO_PROXY", None)
        os.environ.pop("no_proxy", None)
        opener = build_cert_opener()
        assert not any(isinstance(handler, urllib.request.ProxyHandler) for handler in opener.handlers), [
            type(handler).__name__ for handler in opener.handlers
        ]
    finally:
        for name, value in original_proxy_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def self_test_settings(env: dict[str, str] | None = None) -> argparse.Namespace:
    return argparse.Namespace(
        workspace_root=Path.cwd(),
        out_dir=Path("build/live-network-self-test"),
        mode="release-candidate",
        node_base_url="http://127.0.0.1:8888",
        require=True,
    )


def run_self_test() -> None:
    accepted = (
        "http://127.0.0.1:8888",
        "http://localhost:8888",
        "http://[::1]:8888",
        "http://[0:0:0:0:0:0:0:1]:8888",
    )
    for value in accepted:
        assert validate_local_node_url(value).ok, value
    rejected = (
        "",
        "//127.0.0.1:8888",
        "https://127.0.0.1:8888",
        "http://user:pass@127.0.0.1:8888",
        "http://127.0.0.1:8888/?token=secret",
        "http://127.0.0.1:8888/#frag",
        "http://0.0.0.0:8888",
        "http://192.168.1.10:8888",
        "http://node.example.invalid:8888",
        "http://127.0.0.1:8888/api",
        "http://127.0.0.1:99999",
    )
    for value in rejected:
        assert not validate_local_node_url(value).ok, value

    run_no_redirect_self_test()
    run_no_proxy_self_test()
    assert runtime_is_running({"runtime": {"running": True}}) is True
    assert runtime_is_running({"runtime": {"state": "RUNNING"}}) is True
    assert runtime_is_running({"runtime": {"running": False, "state": "STOPPED"}}) is False

    base_env = {
        "CRYPTAD_CERT_FORM_PASSWORD": "self-test-form-password",
        "CRYPTAD_CERT_LIVE_CATALOG_SOURCE": "crypta:USK@PUBLIC/cryptad-app-catalog.properties",
        "CRYPTAD_CERT_LIVE_CATALOG_EXPECTED_KEY_ID": "crypta-first-party-beta",
        "CRYPTAD_CERT_LIVE_CONTENT_FETCH_URI": "crypta:CHK@PUBLIC-CONTENT",
        "CRYPTAD_CERT_LIVE_FEED_USK_URI": "crypta:USK@PUBLIC/feed.json",
        "CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV": "SELF_TEST_PRIVATE_INSERT",
        "SELF_TEST_PRIVATE_INSERT": "SSK@PRIVATE-INSERT-URI",
        "CRYPTAD_CERT_LIVE_PROFILE_PUBLIC_URI": "crypta:USK@PUBLIC/profile.json",
        "CRYPTAD_CERT_LIVE_TRUST_PUBLIC_URI": "crypta:USK@PUBLIC/trust.json",
        "CRYPTAD_CERT_LIVE_APP_SERVICE_SCORE": "1",
    }
    invalid_port_args = self_test_settings()
    invalid_port_args.node_base_url = "http://127.0.0.1:99999"
    invalid_port_summary, _invalid_port_report, invalid_port_exit = run_smoke(
        settings_from_args(invalid_port_args, base_env),
        FakeTransport(),
    )
    assert invalid_port_exit == 1, invalid_port_summary
    invalid_port_preflight = next(
        item for item in invalid_port_summary["evidence"] if item["id"] == "live-network-beta.preflight"
    )
    assert invalid_port_preflight["status"] == "fail", invalid_port_preflight

    optional_redaction_args = self_test_settings()
    optional_redaction_args.require = False
    optional_redaction_settings = settings_from_args(
        optional_redaction_args,
        {"CRYPTAD_CERT_FORM_PASSWORD": "optional-redaction-password"},
    )
    optional_redaction = collect_redaction(
        optional_redaction_settings,
        {"leaked": "optional-redaction-password"},
        "",
        "",
        [],
    )
    optional_redaction_summary = {
        "status": overall_status(False, [optional_redaction]),
        "evidence": [optional_redaction],
    }
    assert optional_redaction["status"] == "fail", optional_redaction
    assert optional_redaction["requiredForReleaseCandidate"] is True, optional_redaction
    assert optional_redaction_summary["status"] == "fail", optional_redaction_summary
    assert smoke_exit_code(optional_redaction_settings, optional_redaction_summary) == 1

    settings = settings_from_args(self_test_settings(), base_env)

    def assert_catalog_blocked_mutations_skipped(summary_value: dict[str, Any], transport: FakeTransport) -> None:
        evidence_by_id = {item["id"]: item for item in summary_value["evidence"]}
        for evidence_id in CATALOG_GATED_MUTATING_EVIDENCE_IDS:
            item = evidence_by_id[evidence_id]
            expected_status = "fail" if evidence_id in REQUIRED_EVIDENCE_IDS else "skip"
            assert item["status"] == expected_status, item
            assert item["details"]["mutationSkipped"] is True, item
            assert item["details"]["catalogStatus"] == "fail", item
        blocked_calls = [
            call
            for call in transport.calls
            if call[1].endswith("/install")
            or call[1].startswith("/api/v1/apps/site-publisher")
            or call[1].startswith("/api/v1/content/subscriptions")
            or call[1].startswith("/api/v1/app-vault/")
            or call[1].startswith("/api/v1/queue/inserts/app-document")
            or call[1].startswith("/api/v1/trust-graph/import-uri")
            or call[1].startswith("/api/v1/app-services/")
        ]
        assert blocked_calls == [], blocked_calls

    optional_fixture_args = self_test_settings()
    optional_fixture_args.require = False
    optional_fixture_settings = settings_from_args(
        optional_fixture_args,
        {
            "CRYPTAD_CERT_FORM_PASSWORD": "self-test-form-password",
            "CRYPTAD_CERT_LIVE_CATALOG_SOURCE": "crypta:USK@PUBLIC/cryptad-app-catalog.properties",
            "CRYPTAD_CERT_LIVE_CATALOG_EXPECTED_KEY_ID": "crypta-first-party-beta",
        },
    )
    optional_fixture_summary, _optional_fixture_report, optional_fixture_exit = run_smoke(
        optional_fixture_settings,
        FakeTransport(),
    )
    assert optional_fixture_exit == 0, optional_fixture_summary
    assert optional_fixture_summary["status"] == "warn", optional_fixture_summary
    optional_fixture_evidence = {item["id"]: item for item in optional_fixture_summary["evidence"]}
    for evidence_id in (
        "live-network-beta.content-fetch",
        "live-network-beta.feed-subscription",
        "live-network-beta.profile-publish",
        "live-network-beta.trust-statement-publish-import",
    ):
        item = optional_fixture_evidence[evidence_id]
        assert item["status"] == "warn", item
        assert item["requiredForReleaseCandidate"] is False, item
    assert optional_fixture_evidence["live-network-beta.app-service-score"]["status"] == "skip", (
        optional_fixture_evidence["live-network-beta.app-service-score"]
    )

    passing_transport = FakeTransport()
    summary, report, exit_code = run_smoke(settings, passing_transport)
    assert exit_code == 0, summary
    assert summary["status"] == "pass", summary
    assert all(item["status"] == "pass" for item in summary["evidence"]), summary
    assert passing_transport.subscription_create_saw_uri, passing_transport.calls
    app_origins = [
        headers.get("Origin")
        for (method, path), headers in zip(passing_transport.calls, passing_transport.headers_by_call)
        if passing_transport._app_route_requires_session(method, path)
    ]
    assert app_origins, passing_transport.calls
    assert all(origin and origin.startswith("http://127.0.0.1:") for origin in app_origins), app_origins
    assert passing_transport.approved_grants == {"grant-self-test"}, passing_transport.calls
    assert passing_transport.revoked_grants == {"grant-self-test"}, passing_transport.calls
    content_fetch = next(item for item in summary["evidence"] if item["id"] == "live-network-beta.content-fetch")
    app_prep = content_fetch["details"]["appPrincipalPreparation"]
    assert set(app_prep["installedByThisRun"]) == {
        "feed-reader",
        "profile-publisher",
        "trust-graph",
        "social-inbox",
    }, app_prep
    assert app_prep["cleanupSucceeded"] is True, app_prep
    assert passing_transport.installed_apps == set(), passing_transport.installed_apps
    encoded = json.dumps(summary, sort_keys=True) + report
    for forbidden in (
        "self-test-form-password",
        "SSK@PRIVATE-INSERT-URI",
        "browser-session-feed-reader",
        "browser-session-profile-publisher",
        "browser-session-trust-graph",
        "browser-session-social-inbox",
        str(Path.cwd()),
    ):
        assert forbidden not in encoded, forbidden
    feed_subscription = next(item for item in summary["evidence"] if item["id"] == "live-network-beta.feed-subscription")
    feed_paths = [step["path"] for step in feed_subscription["details"]["steps"]]
    assert any("/sub-self-test/" in path for path in feed_paths), feed_paths
    assert all("cert-live-feed" not in path for path in feed_paths), feed_paths

    reused_grant_transport = FakeTransport(app_service_grant_created=False, app_service_grant_status="active")
    reused_grant_summary, _reused_grant_report, reused_grant_exit = run_smoke(settings, reused_grant_transport)
    assert reused_grant_exit == 0, reused_grant_summary
    assert reused_grant_summary["status"] == "pass", reused_grant_summary
    reused_score = next(
        item
        for item in reused_grant_summary["evidence"]
        if item["id"] == "live-network-beta.app-service-score"
    )
    assert reused_score["status"] == "pass", reused_score
    assert reused_score["details"]["grantReused"] is True, reused_score
    assert reused_score["details"]["grantCreatedByThisRun"] is False, reused_score
    assert reused_score["details"]["grantApprovalSkipped"], reused_score
    assert reused_score["details"]["grantRevokeSkipped"], reused_score
    assert reused_grant_transport.approved_grants == set(), reused_grant_transport.calls
    assert reused_grant_transport.revoked_grants == set(), reused_grant_transport.calls
    assert ("POST", "/api/v1/app-services/grants/grant-self-test/approve") not in reused_grant_transport.calls
    assert ("POST", "/api/v1/app-services/grants/grant-self-test/revoke") not in reused_grant_transport.calls

    reused_pending_grant_transport = FakeTransport(app_service_grant_created=False, app_service_grant_status="pending")
    (
        reused_pending_grant_summary,
        _reused_pending_grant_report,
        reused_pending_grant_exit,
    ) = run_smoke(settings, reused_pending_grant_transport)
    assert reused_pending_grant_exit == 0, reused_pending_grant_summary
    assert reused_pending_grant_summary["status"] == "warn", reused_pending_grant_summary
    reused_pending_score = next(
        item
        for item in reused_pending_grant_summary["evidence"]
        if item["id"] == "live-network-beta.app-service-score"
    )
    assert reused_pending_score["status"] == "warn", reused_pending_score
    assert reused_pending_score["details"]["grantReused"] is True, reused_pending_score
    assert reused_pending_score["details"]["grantApprovalSkipped"], reused_pending_score
    reused_pending_calls = reused_pending_grant_transport.calls
    assert reused_pending_grant_transport.approved_grants == set(), reused_pending_calls
    assert reused_pending_grant_transport.revoked_grants == set(), reused_pending_calls
    assert ("POST", "/api/v1/app-services/grants/grant-self-test/approve") not in reused_pending_calls
    assert ("POST", "/api/v1/app-services/grants/grant-self-test/revoke") not in reused_pending_calls

    grant_list_failure_transport = FakeTransport(path_statuses={"/api/v1/app-services/grants": 403})
    grant_list_failure_summary, _grant_list_failure_report, grant_list_failure_exit = run_smoke(
        settings,
        grant_list_failure_transport,
    )
    assert grant_list_failure_exit == 0, grant_list_failure_summary
    assert grant_list_failure_summary["status"] == "warn", grant_list_failure_summary
    grant_list_failure_score = next(
        item
        for item in grant_list_failure_summary["evidence"]
        if item["id"] == "live-network-beta.app-service-score"
    )
    assert grant_list_failure_score["status"] == "warn", grant_list_failure_score
    assert grant_list_failure_score["details"]["grantListBeforeObserved"] is False, grant_list_failure_score
    assert ("POST", "/api/v1/app-services/grants") not in grant_list_failure_transport.calls
    assert grant_list_failure_transport.approved_grants == set(), grant_list_failure_transport.calls
    assert grant_list_failure_transport.revoked_grants == set(), grant_list_failure_transport.calls

    optional_score_failure_summary, _optional_score_failure_report, optional_score_failure_exit = run_smoke(
        settings,
        FakeTransport({"/api/v1/app-services/trust-graph/services/trust.score/invoke"}),
    )
    assert optional_score_failure_exit == 0, optional_score_failure_summary
    assert optional_score_failure_summary["status"] == "warn", optional_score_failure_summary
    optional_score_failure = next(
        item
        for item in optional_score_failure_summary["evidence"]
        if item["id"] == "live-network-beta.app-service-score"
    )
    assert optional_score_failure["status"] == "warn", optional_score_failure
    assert optional_score_failure["requiredForReleaseCandidate"] is False, optional_score_failure

    score_exception_transport = FakeTransport(
        exceptions={"/api/v1/app-services/trust-graph/services/trust.score/invoke"}
    )
    score_exception_summary, _score_exception_report, score_exception_exit = run_smoke(
        settings,
        score_exception_transport,
    )
    assert score_exception_exit == 0, score_exception_summary
    assert score_exception_summary["status"] == "warn", score_exception_summary
    score_exception = next(
        item
        for item in score_exception_summary["evidence"]
        if item["id"] == "live-network-beta.app-service-score"
    )
    assert score_exception["status"] == "warn", score_exception
    assert score_exception["details"]["grantRevokeAttempted"] is True, score_exception
    assert score_exception["details"]["grantRevokeSucceeded"] is True, score_exception
    assert score_exception_transport.approved_grants == {"grant-self-test"}, score_exception_transport.calls
    assert score_exception_transport.revoked_grants == {"grant-self-test"}, score_exception_transport.calls
    assert ("POST", "/api/v1/app-services/grants/grant-self-test/revoke") in score_exception_transport.calls

    polling_settings = dataclasses.replace(settings, poll_interval_seconds=0, max_poll_attempts=3)
    profile_poll_transport = FakeTransport(
        body_status_sequences={
            ("/api/v1/content/fetch", "purpose", "profile-publish-fetchback"): [404],
        }
    )
    profile_poll_summary, _profile_poll_report, profile_poll_exit = run_smoke(
        polling_settings,
        profile_poll_transport,
    )
    assert profile_poll_exit == 0, profile_poll_summary
    profile_poll = next(
        item for item in profile_poll_summary["evidence"] if item["id"] == "live-network-beta.profile-publish"
    )
    assert profile_poll["status"] == "pass", profile_poll
    assert profile_poll["details"]["fetchbackPollAttempts"] == 2, profile_poll
    profile_poll_steps = [
        step
        for step in profile_poll["details"]["steps"]
        if step["path"] == "/api/v1/content/fetch" and "pollAttempt" in step
    ]
    assert [step["status"] for step in profile_poll_steps] == [404, 200], profile_poll_steps

    trust_poll_transport = FakeTransport(
        body_status_sequences={
            ("/api/v1/trust-graph/import-uri", "uri", "crypta:USK@PUBLIC/trust.json"): [404],
        }
    )
    trust_poll_summary, _trust_poll_report, trust_poll_exit = run_smoke(
        polling_settings,
        trust_poll_transport,
    )
    assert trust_poll_exit == 0, trust_poll_summary
    trust_poll = next(
        item
        for item in trust_poll_summary["evidence"]
        if item["id"] == "live-network-beta.trust-statement-publish-import"
    )
    assert trust_poll["status"] == "pass", trust_poll
    assert trust_poll["details"]["importPollAttempts"] == 2, trust_poll
    trust_poll_steps = [
        step
        for step in trust_poll["details"]["steps"]
        if step["path"] == "/api/v1/trust-graph/import-uri" and "pollAttempt" in step
    ]
    assert [step["status"] for step in trust_poll_steps] == [404, 200], trust_poll_steps

    diagnostics_failure_transport = FakeTransport(path_statuses={"/api/v1/diagnostics": 500})
    diagnostics_failure_summary, _diagnostics_failure_report, diagnostics_failure_exit = run_smoke(
        settings,
        diagnostics_failure_transport,
    )
    assert diagnostics_failure_exit == 1, diagnostics_failure_summary
    diagnostics_preflight = next(
        item for item in diagnostics_failure_summary["evidence"] if item["id"] == "live-network-beta.preflight"
    )
    assert diagnostics_preflight["status"] == "fail", diagnostics_preflight
    diagnostics_catalog = next(
        item
        for item in diagnostics_failure_summary["evidence"]
        if item["id"] == "live-network-beta.catalog-usk-fetch"
    )
    assert diagnostics_catalog["status"] == "fail", diagnostics_catalog
    assert diagnostics_catalog["details"]["preflightStatus"] == "fail", diagnostics_catalog
    assert ("POST", "/api/v1/app-catalogs/add") not in diagnostics_failure_transport.calls
    assert (
        "POST",
        "/api/v1/app-catalogs/crypta-first-party-beta/apps/site-publisher/install",
    ) not in diagnostics_failure_transport.calls

    matching_catalog_conflict_transport = FakeTransport(conflict_on_catalog_add=True)
    matching_catalog_conflict_summary, _matching_catalog_report, matching_catalog_conflict_exit = run_smoke(
        settings,
        matching_catalog_conflict_transport,
    )
    assert matching_catalog_conflict_exit == 0, matching_catalog_conflict_summary
    matching_catalog_conflict = next(
        item
        for item in matching_catalog_conflict_summary["evidence"]
        if item["id"] == "live-network-beta.catalog-usk-fetch"
    )
    assert matching_catalog_conflict["status"] == "pass", matching_catalog_conflict
    assert matching_catalog_conflict["details"]["reusedConfiguredCatalog"] is True, matching_catalog_conflict
    assert matching_catalog_conflict["details"]["catalogConflictSourceMatched"] is True, matching_catalog_conflict
    assert matching_catalog_conflict["details"]["catalogConflictCatalogIdMatched"] is True, matching_catalog_conflict

    different_catalog_conflict_transport = FakeTransport(
        catalog_source="crypta:USK@DIFFERENT/cryptad-app-catalog.properties",
        conflict_on_catalog_add=True,
    )
    different_catalog_conflict_summary, _different_catalog_report, different_catalog_conflict_exit = run_smoke(
        settings,
        different_catalog_conflict_transport,
    )
    assert different_catalog_conflict_exit == 1, different_catalog_conflict_summary
    different_catalog_conflict = next(
        item
        for item in different_catalog_conflict_summary["evidence"]
        if item["id"] == "live-network-beta.catalog-usk-fetch"
    )
    assert different_catalog_conflict["status"] == "fail", different_catalog_conflict
    assert different_catalog_conflict["details"]["reusedConfiguredCatalog"] is False, different_catalog_conflict
    assert different_catalog_conflict["details"]["catalogConflictSourceMatched"] is False, different_catalog_conflict
    assert different_catalog_conflict["details"]["catalogConflictCatalogIdMatched"] is True, different_catalog_conflict
    assert (
        "POST",
        "/api/v1/app-catalogs/crypta-first-party-beta/refresh",
    ) not in different_catalog_conflict_transport.calls
    assert ("DELETE", "/api/v1/app-catalogs/crypta-first-party-beta") not in different_catalog_conflict_transport.calls
    assert different_catalog_conflict_transport.deleted_catalogs == set(), different_catalog_conflict_transport.calls
    assert_catalog_blocked_mutations_skipped(different_catalog_conflict_summary, different_catalog_conflict_transport)

    missing_key_env = dict(base_env)
    missing_key_env.pop("CRYPTAD_CERT_LIVE_CATALOG_EXPECTED_KEY_ID")
    missing_key_transport = FakeTransport()
    missing_key_summary, _missing_key_report, missing_key_exit = run_smoke(
        settings_from_args(self_test_settings(), missing_key_env),
        missing_key_transport,
    )
    assert missing_key_exit == 1, missing_key_summary
    missing_key_catalog = next(
        item for item in missing_key_summary["evidence"] if item["id"] == "live-network-beta.catalog-usk-fetch"
    )
    assert missing_key_catalog["status"] == "fail", missing_key_catalog
    assert missing_key_catalog["details"]["catalogMutationSkipped"] is True, missing_key_catalog
    assert ("POST", "/api/v1/app-catalogs/add") not in missing_key_transport.calls
    assert ("POST", "/api/v1/app-catalogs/crypta-first-party-beta/refresh") not in missing_key_transport.calls
    assert ("DELETE", "/api/v1/app-catalogs/crypta-first-party-beta") not in missing_key_transport.calls
    assert_catalog_blocked_mutations_skipped(missing_key_summary, missing_key_transport)

    wrong_key_env = dict(base_env)
    wrong_key_env["CRYPTAD_CERT_LIVE_CATALOG_EXPECTED_KEY_ID"] = "unexpected-catalog-key"
    wrong_key_transport = FakeTransport()
    wrong_key_summary, _wrong_key_report, wrong_key_exit = run_smoke(
        settings_from_args(self_test_settings(), wrong_key_env),
        wrong_key_transport,
    )
    assert wrong_key_exit == 1, wrong_key_summary
    wrong_key_catalog = next(
        item for item in wrong_key_summary["evidence"] if item["id"] == "live-network-beta.catalog-usk-fetch"
    )
    assert wrong_key_catalog["status"] == "fail", wrong_key_catalog
    assert wrong_key_catalog["details"]["catalogAddedByThisRun"] is True, wrong_key_catalog
    assert wrong_key_catalog["details"]["catalogCleanupAttempted"] is True, wrong_key_catalog
    assert wrong_key_catalog["details"]["catalogCleanupSucceeded"] is True, wrong_key_catalog
    assert ("DELETE", "/api/v1/app-catalogs/crypta-first-party-beta") in wrong_key_transport.calls
    assert wrong_key_transport.deleted_catalogs == {"crypta-first-party-beta"}, wrong_key_transport.calls
    assert_catalog_blocked_mutations_skipped(wrong_key_summary, wrong_key_transport)

    missing_settings = settings_from_args(
        argparse.Namespace(
            workspace_root=Path.cwd(),
            out_dir=Path("build/live-network-self-test"),
            mode="release-candidate",
            node_base_url="",
            require=True,
        ),
        {},
    )
    missing_summary, _missing_report, missing_exit = run_smoke(missing_settings, FakeTransport())
    assert missing_exit == 1, missing_summary
    assert missing_summary["status"] == "fail", missing_summary

    fast_failure_settings = dataclasses.replace(settings, poll_interval_seconds=0, max_poll_attempts=1)
    failing_summary, _failing_report, failing_exit = run_smoke(
        fast_failure_settings,
        FakeTransport({"/api/v1/content/fetch"}),
    )
    assert failing_exit == 1, failing_summary
    content_fetch = next(item for item in failing_summary["evidence"] if item["id"] == "live-network-beta.content-fetch")
    assert content_fetch["status"] == "fail", content_fetch
    lifecycle = next(
        item for item in failing_summary["evidence"] if item["id"] == "live-network-beta.app-install-update-rollback"
    )
    assert lifecycle["details"]["cleanupSteps"], lifecycle

    preexisting_transport = FakeTransport()
    preexisting_transport.installed_apps.add("site-publisher")
    preexisting_summary, _preexisting_report, preexisting_exit = run_smoke(settings, preexisting_transport)
    assert preexisting_exit == 0, preexisting_summary
    preexisting_lifecycle = next(
        item
        for item in preexisting_summary["evidence"]
        if item["id"] == "live-network-beta.app-install-update-rollback"
    )
    assert preexisting_lifecycle["details"]["preExistingInstall"] is True, preexisting_lifecycle
    assert preexisting_lifecycle["details"]["installSkipped"] == "target app was pre-existing", preexisting_lifecycle
    assert preexisting_lifecycle["details"]["cleanupSteps"] == [], preexisting_lifecycle
    assert (
        "POST",
        "/api/v1/app-catalogs/crypta-first-party-beta/apps/site-publisher/install",
    ) not in preexisting_transport.calls
    assert ("DELETE", "/api/v1/apps/site-publisher") not in preexisting_transport.calls

    preexisting_running_transport = FakeTransport()
    preexisting_running_transport.installed_apps.add("site-publisher")
    preexisting_running_transport.running_apps.add("site-publisher")
    preexisting_running_summary, _preexisting_running_report, preexisting_running_exit = run_smoke(
        settings,
        preexisting_running_transport,
    )
    assert preexisting_running_exit == 0, preexisting_running_summary
    preexisting_running_lifecycle = next(
        item
        for item in preexisting_running_summary["evidence"]
        if item["id"] == "live-network-beta.app-install-update-rollback"
    )
    assert preexisting_running_lifecycle["status"] == "pass", preexisting_running_lifecycle
    assert preexisting_running_lifecycle["details"]["preExistingInstall"] is True, preexisting_running_lifecycle
    assert preexisting_running_lifecycle["details"]["preExistingRunning"] is True, preexisting_running_lifecycle
    assert preexisting_running_lifecycle["details"]["preExistingRunningStoppedForSmoke"] is True, (
        preexisting_running_lifecycle
    )
    assert preexisting_running_lifecycle["details"]["restoreSucceeded"] is True, preexisting_running_lifecycle
    assert (
        "POST",
        "/api/v1/app-catalogs/crypta-first-party-beta/apps/site-publisher/install",
    ) not in preexisting_running_transport.calls
    assert ("DELETE", "/api/v1/apps/site-publisher") not in preexisting_running_transport.calls
    assert "site-publisher" in preexisting_running_transport.running_apps

    preexisting_enveloped_running_transport = FakeTransport(runtime_envelope=True)
    preexisting_enveloped_running_transport.installed_apps.add("site-publisher")
    preexisting_enveloped_running_transport.running_apps.add("site-publisher")
    preexisting_enveloped_summary, _preexisting_enveloped_report, preexisting_enveloped_exit = run_smoke(
        settings,
        preexisting_enveloped_running_transport,
    )
    assert preexisting_enveloped_exit == 0, preexisting_enveloped_summary
    preexisting_enveloped_lifecycle = next(
        item
        for item in preexisting_enveloped_summary["evidence"]
        if item["id"] == "live-network-beta.app-install-update-rollback"
    )
    assert preexisting_enveloped_lifecycle["status"] == "pass", preexisting_enveloped_lifecycle
    assert preexisting_enveloped_lifecycle["details"]["preExistingRunning"] is True, (
        preexisting_enveloped_lifecycle
    )
    assert "site-publisher" in preexisting_enveloped_running_transport.running_apps

    preexisting_stopped_stop_failure_transport = FakeTransport(
        body_status_sequences={
            ("/api/v1/apps/site-publisher/stop", FORM_PASSWORD_PARAMETER, "self-test-form-password"): [500],
        }
    )
    preexisting_stopped_stop_failure_transport.installed_apps.add("site-publisher")
    (
        preexisting_stopped_stop_failure_summary,
        _preexisting_stopped_stop_failure_report,
        preexisting_stopped_stop_failure_exit,
    ) = run_smoke(
        settings,
        preexisting_stopped_stop_failure_transport,
    )
    assert preexisting_stopped_stop_failure_exit == 1, preexisting_stopped_stop_failure_summary
    preexisting_stopped_stop_failure = next(
        item
        for item in preexisting_stopped_stop_failure_summary["evidence"]
        if item["id"] == "live-network-beta.app-install-update-rollback"
    )
    assert preexisting_stopped_stop_failure["status"] == "fail", preexisting_stopped_stop_failure
    assert preexisting_stopped_stop_failure["details"]["preExistingInstall"] is True, (
        preexisting_stopped_stop_failure
    )
    assert preexisting_stopped_stop_failure["details"]["preExistingRunning"] is False, (
        preexisting_stopped_stop_failure
    )
    assert preexisting_stopped_stop_failure["details"]["preExistingStoppedStartedBySmoke"] is True, (
        preexisting_stopped_stop_failure
    )
    assert preexisting_stopped_stop_failure["details"]["preExistingStoppedRestoreSucceeded"] is True, (
        preexisting_stopped_stop_failure
    )
    assert preexisting_stopped_stop_failure_transport.calls.count(
        ("POST", "/api/v1/apps/site-publisher/stop")
    ) == 2, preexisting_stopped_stop_failure_transport.calls
    assert "site-publisher" not in preexisting_stopped_stop_failure_transport.running_apps

    missing_start_transport = FakeTransport(path_statuses={"/api/v1/apps/site-publisher/start": 404})
    missing_start_summary, _missing_start_report, missing_start_exit = run_smoke(
        settings,
        missing_start_transport,
    )
    assert missing_start_exit == 1, missing_start_summary
    missing_start_lifecycle = next(
        item
        for item in missing_start_summary["evidence"]
        if item["id"] == "live-network-beta.app-install-update-rollback"
    )
    assert missing_start_lifecycle["status"] == "fail", missing_start_lifecycle
    assert ("DELETE", "/api/v1/apps/site-publisher") in missing_start_transport.calls

    missing_stop_transport = FakeTransport(path_statuses={"/api/v1/apps/site-publisher/stop": 404})
    missing_stop_summary, _missing_stop_report, missing_stop_exit = run_smoke(
        settings,
        missing_stop_transport,
    )
    assert missing_stop_exit == 1, missing_stop_summary
    missing_stop_lifecycle = next(
        item
        for item in missing_stop_summary["evidence"]
        if item["id"] == "live-network-beta.app-install-update-rollback"
    )
    assert missing_stop_lifecycle["status"] == "fail", missing_stop_lifecycle
    assert ("DELETE", "/api/v1/apps/site-publisher") in missing_stop_transport.calls

    missing_update_check_transport = FakeTransport(path_statuses={"/api/v1/apps/site-publisher/updates/check": 404})
    missing_update_check_summary, _missing_update_check_report, missing_update_check_exit = run_smoke(
        settings,
        missing_update_check_transport,
    )
    assert missing_update_check_exit == 1, missing_update_check_summary
    missing_update_check_lifecycle = next(
        item
        for item in missing_update_check_summary["evidence"]
        if item["id"] == "live-network-beta.app-install-update-rollback"
    )
    assert missing_update_check_lifecycle["status"] == "fail", missing_update_check_lifecycle
    assert ("DELETE", "/api/v1/apps/site-publisher") in missing_update_check_transport.calls

    missing_catalog_update_transport = FakeTransport(
        path_statuses={"/api/v1/app-catalogs/crypta-first-party-beta/apps/site-publisher/update": 404}
    )
    missing_catalog_update_summary, _missing_catalog_update_report, missing_catalog_update_exit = run_smoke(
        settings,
        missing_catalog_update_transport,
    )
    assert missing_catalog_update_exit == 1, missing_catalog_update_summary
    missing_catalog_update_lifecycle = next(
        item
        for item in missing_catalog_update_summary["evidence"]
        if item["id"] == "live-network-beta.app-install-update-rollback"
    )
    assert missing_catalog_update_lifecycle["status"] == "fail", missing_catalog_update_lifecycle
    assert ("DELETE", "/api/v1/apps/site-publisher") in missing_catalog_update_transport.calls

    cleanup_stop_failure_transport = FakeTransport(path_statuses={"/api/v1/apps/site-publisher/stop": 500})
    cleanup_stop_failure_summary, _cleanup_stop_report, cleanup_stop_failure_exit = run_smoke(
        settings,
        cleanup_stop_failure_transport,
    )
    assert cleanup_stop_failure_exit == 1, cleanup_stop_failure_summary
    cleanup_stop_lifecycle = next(
        item
        for item in cleanup_stop_failure_summary["evidence"]
        if item["id"] == "live-network-beta.app-install-update-rollback"
    )
    cleanup_paths = [step["path"] for step in cleanup_stop_lifecycle["details"]["cleanupSteps"]]
    assert cleanup_stop_lifecycle["status"] == "fail", cleanup_stop_lifecycle
    assert "/api/v1/apps/site-publisher/stop" in cleanup_paths, cleanup_paths
    assert "/api/v1/apps/site-publisher" in cleanup_paths, cleanup_paths
    assert ("DELETE", "/api/v1/apps/site-publisher") in cleanup_stop_failure_transport.calls
    assert "site-publisher" not in cleanup_stop_failure_transport.installed_apps

    rollback_failure_summary, _rollback_report, rollback_exit = run_smoke(
        settings,
        FakeTransport({"/api/v1/apps/site-publisher/updates/rollback"}),
    )
    assert rollback_exit == 1, rollback_failure_summary
    rollback_lifecycle = next(
        item
        for item in rollback_failure_summary["evidence"]
        if item["id"] == "live-network-beta.app-install-update-rollback"
    )
    assert rollback_lifecycle["status"] == "fail", rollback_lifecycle

    lifecycle_cleanup_summary, _lifecycle_cleanup_report, lifecycle_cleanup_exit = run_smoke(
        settings,
        FakeTransport({"/api/v1/apps/site-publisher"}),
    )
    assert lifecycle_cleanup_exit == 1, lifecycle_cleanup_summary
    lifecycle_cleanup = next(
        item
        for item in lifecycle_cleanup_summary["evidence"]
        if item["id"] == "live-network-beta.app-install-update-rollback"
    )
    assert lifecycle_cleanup["status"] == "fail", lifecycle_cleanup
    assert lifecycle_cleanup["details"]["cleanupSucceeded"] is False, lifecycle_cleanup

    feed_cleanup_transport = FakeTransport({"/api/v1/content/subscriptions/sub-self-test/refresh"})
    feed_cleanup_summary, _feed_cleanup_report, feed_cleanup_exit = run_smoke(
        settings,
        feed_cleanup_transport,
    )
    assert feed_cleanup_exit == 1, feed_cleanup_summary
    feed_cleanup = next(
        item for item in feed_cleanup_summary["evidence"] if item["id"] == "live-network-beta.feed-subscription"
    )
    assert feed_cleanup["status"] == "fail", feed_cleanup
    assert ("DELETE", "/api/v1/content/subscriptions/sub-self-test") in feed_cleanup_transport.calls

    leaks = "\n".join(
        [
            "form self-test-form-password",
            "private SSK@PRIVATE-INSERT-URI",
            "rawRequestBody: secret",
            "rawSignature: abc",
            "Authorization: Bearer token-value",
            "X-Crypta-App-Session: browser-session-secret",
            "/home/alice/cryptad/private.txt",
        ]
    )
    findings = scan_forbidden_text(leaks, ["self-test-form-password", "SSK@PRIVATE-INSERT-URI"], Path.cwd())
    for expected in ("secret-0", "secret-1", "raw-body", "raw-signature", "token", "local-absolute-path"):
        assert expected in findings, findings


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        run_self_test()
        print("live-network-beta-smoke self-test passed")
        return 0
    settings = settings_from_args(args)
    summary, report, exit_code = run_smoke(settings)
    write_json(settings.out_dir / SUMMARY_FILE_NAME, summary)
    write_text(settings.out_dir / REPORT_FILE_NAME, report)
    print(f"Live-network beta smoke {summary['status']}: {REPORT_FILE_NAME}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
