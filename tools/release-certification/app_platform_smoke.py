#!/usr/bin/env python3
"""Collect app-platform release-certification smoke evidence.

The smoke runner keeps its self-test Python-only and offline.  Normal runs can
optionally invoke Gradle and the installed ``crypta-app`` launcher to validate
first-party staged apps, sample app packaging, signed bundles, signed catalogs,
app-owned static UI, content fetch, content subscriptions and feed-reader routes,
profile publishing routes, generated document inserts, and legacy-admin retirement state.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import dataclasses
import hashlib
import html.parser
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


TOOL_NAME = "app-platform-smoke"
SCHEMA_VERSION = 1
MODES = ("pr", "nightly", "release-candidate")
DEFAULT_OUT_DIR = Path("build/release-certification/app-platform-smoke")
SUMMARY_FILE_NAME = "summary.json"
REPORT_FILE_NAME = "app-platform-smoke-report.md"
APP_IDS = (
    "queue-manager",
    "publisher",
    "site-publisher",
    "profile-publisher",
    "social-inbox",
    "feed-reader",
    "trust-graph",
)
CURRENT_PLATFORM_API_CONTRACT_VERSION = 16
LEGACY_REMOVAL_WAVE_ONE_IDS = (
    "queue-downloads",
    "queue-uploads",
    "file-insert",
    "local-file-insert",
    "friends",
    "add-friend",
    "strangers",
    "connectivity",
)
LEGACY_REMOVAL_WAVE_TWO_IDS = (
    "alerts",
    "config",
    "core-update",
    "statistics",
)
LEGACY_REMOVAL_WAVE_THREE_IDS = (
    "security-levels",
)
LEGACY_REMOVAL_WAVE_TWO_SCOPE_EXPANSION_IDS = (
    "queue-downloads",
    "queue-uploads",
    "config",
    "statistics",
)
APP_UI_DESIGN_SYSTEM_DOC = Path("docs/app-ui-design-system.md")
APP_VAULT_DOC = Path("docs/app-secret-and-identity-vault.md")
DEVELOPER_BETA_TOOLKIT_DOC = Path("docs/developer-beta-toolkit.md")
APP_VAULT_CAPABILITIES = (
    "vault.secrets.read",
    "vault.secrets.write",
    "vault.identities.read",
    "vault.identities.create",
    "vault.identities.use",
    "vault.identities.manage",
)
PROFILE_PUBLISHER_PERMISSIONS = {
    "queue.read",
    "queue.write",
    "content.insert.app-document",
    "vault.identities.read",
    "vault.identities.create",
    "vault.identities.use",
    "app.data.read",
    "app.data.write",
}
FEED_READER_PERMISSIONS = {
    "content.fetch",
    "content.subscribe",
    "content.insert.app-document",
    "queue.read",
    "queue.write",
    "app.data.read",
    "app.data.write",
}
TRUST_GRAPH_PERMISSIONS = {
    "trust.read",
    "trust.write",
    "content.fetch",
    "content.subscribe",
    "content.insert.app-document",
    "queue.read",
    "queue.write",
    "vault.identities.read",
    "vault.identities.create",
    "vault.identities.use",
    "app.data.read",
    "app.data.write",
}
SOCIAL_INBOX_PERMISSIONS = {
    "vault.identities.read",
    "vault.identities.create",
    "vault.identities.use",
    "content.fetch",
    "content.subscribe",
    "content.insert.app-document",
    "queue.read",
    "queue.write",
    "app.data.read",
    "app.data.write",
    "app.services.read",
    "app.services.call",
}
SOCIAL_INBOX_DISPLAY_NAMES = {
    "Social Inbox Preview",
    "Social Inbox RC",
    "Social Inbox Reference",
}
SECRET_COMMAND_VALUE_OPTIONS = {
    "--private-key-base64",
    "--private-key-file",
    "--reviewer-private-key-base64",
    "--reviewer-private-key-file",
    "--trusted-public-key-base64",
}
SENSITIVE_KEY_PATTERN = (
    r"CRYPTAD_APP_TOKEN|formPassword|browserSessionToken|X-Crypta-App-Session|"
    r"authorization|cookie|set-cookie|private[-_ ]?key|token|password|passwd|secret|credential|"
    r"identity[-_ ]?seed|recovery[-_ ]?phrase|mnemonic|"
    r"raw[-_ ]?request[-_ ]?bod(?:y|ies)|request[-_ ]?bod(?:y|ies)|"
    r"raw[-_ ]?feed[-_ ]?bod(?:y|ies)|feed[-_ ]?bod(?:y|ies)|"
    r"raw[-_ ]?trust[-_ ]?statement[-_ ]?bod(?:y|ies)|trust[-_ ]?statement[-_ ]?bod(?:y|ies)"
    r"|raw[-_ ]?message[-_ ]?bod(?:y|ies)|message[-_ ]?bod(?:y|ies)"
    r"|raw[-_ ]?fetched[-_ ]?bod(?:y|ies)|fetched[-_ ]?bod(?:y|ies)"
    r"|raw[-_ ]?signature[-_ ]?valu(?:e|es)|signature[-_ ]?valu(?:e|es)"
    r"|app[-_ ]?data[-_ ]?backup|backup[-_ ]?payload|payloadBase64|"
    r"raw[-_ ]?app[-_ ]?data[-_ ]?valu(?:e|es)|record[-_ ]?valu(?:e|es)"
)
SENSITIVE_RE = re.compile(
    rf"({SENSITIVE_KEY_PATTERN})",
    re.IGNORECASE,
)
SENSITIVE_HEADER_RE = re.compile(
    r"(?P<prefix>\b(?:Authorization|Cookie|Set-Cookie|X-Crypta-App-Session|X-Crypta-Form-Password)\s*:\s*)"
    r"(?P<value>[^\r\n]*)",
    re.IGNORECASE,
)
SENSITIVE_TEXT_LABEL_RE = re.compile(
    r"(?P<prefix>\b(?:"
    r"raw[-_ ]+request[-_ ]+bod(?:y|ies)|request[-_ ]+bod(?:y|ies)|"
    r"raw[-_ ]+feed[-_ ]+bod(?:y|ies)|feed[-_ ]+bod(?:y|ies)|"
    r"raw[-_ ]+trust[-_ ]+statement[-_ ]+bod(?:y|ies)|"
    r"trust[-_ ]+statement[-_ ]+bod(?:y|ies)|"
    r"raw[-_ ]+message[-_ ]+bod(?:y|ies)|message[-_ ]+bod(?:y|ies)|"
    r"raw[-_ ]+fetched[-_ ]+bod(?:y|ies)|fetched[-_ ]+bod(?:y|ies)|"
    r"raw[-_ ]+trust[-_ ]+signature|trust[-_ ]+signature|"
    r"raw[-_ ]+signature[-_ ]+valu(?:e|es)|signature[-_ ]+valu(?:e|es)"
    r")\s*:\s*)"
    r"(?P<value>[^\r\n]*)",
    re.IGNORECASE,
)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?P<prefix>(?<![A-Za-z0-9_])(?P<key_quote>[\"']?)"
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?P=key_quote)\s*[:=]\s*)"
    r"(?:(?P<value_quote>[\"'])(?P<quoted_value>[^\"'\r\n]*)(?P=value_quote)|"
    r"(?P<value>(?:(?:Bearer|Basic|Digest)\s+)?[^\s,;&}\]]+))",
    re.IGNORECASE,
)
PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN (?P<key_type>[A-Z0-9 ]*PRIVATE KEY)-----[\s\S]*?-----END (?P=key_type)-----"
    r"|-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY)-----[\s\S]*?(?=\r?\n-----BEGIN [A-Z0-9 ]+-----|\Z)",
    re.IGNORECASE,
)
PUBLIC_BETA_SECURITY_EVIDENCE_IDS = (
    "public-beta-security.app-ui-csp",
    "public-beta-security.app-origin-policy",
    "public-beta-security.content-fetch-bounds",
    "public-beta-security.feed-sanitization",
    "public-beta-security.social-inbox-sanitization",
    "public-beta-security.profile-sanitization",
    "public-beta-security.trust-statement-hardening",
    "public-beta-security.apphost-env-minimization",
    "public-beta-security.sandbox-host-checks",
    "public-beta-security.audit-redaction-fuzz",
    "public-beta-security.transparency-log-privacy",
)
PUBLIC_BETA_SECURITY_SENSITIVE_FIXTURES = (
    "CRYPTAD_APP_TOKEN=0123456789abcdef0123456789abcdef",
    "X-Crypta-App-Session: browser-session-secret",
    "X-Crypta-Form-Password=form-secret",
    "Authorization: Bearer host-or-app-secret",
    "SSK@PRIVATE-INSERT-URI",
    "USK@PRIVATE-INSERT-URI",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----\npem-private-key-body\n-----END PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----\ntruncated-pem-private-key-body",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "/home/alice/.crypta/apps/social-inbox/data",
    r"C:\Users\Alice\Crypta\apps\social-inbox\data",
    "raw fetched body: <script>alert(1)</script>",
    "raw trust statement body: {\"subject\":\"private-document\"}",
    "raw message body: private-social-body",
    "raw trust signature: MEUCIQD...",
)
PUBLIC_BETA_SECURITY_MARKUP_FIXTURES = (
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '<a href="javascript:alert(1)">click</a>',
    '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
)
URI_KEY_RE = re.compile(r"\b(?:CHK|SSK|USK)@[^\s\])},;\"']+")
ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9_:/.\->])/(?:[A-Za-z0-9._ -]+/)+[A-Za-z0-9._ -]+")
WINDOWS_DRIVE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->])(?:[A-Za-z]:[\\/](?:[^\\/:*?\"<>|\r\n]+[\\/])*[^\\/:*?\"<>|\r\n]+[\\/]?)"
)
WINDOWS_UNC_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->])(?:\\\\[^\\/:*?\"<>|\r\n]+\\[^\\/:*?\"<>|\r\n]+(?:\\[^\\/:*?\"<>|\r\n]+)*\\?)"
)
FILE_URI_PATH_RE = re.compile(r"\bfile://(?P<path>[^\s\])},;\"']+)")
ROUTE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->])/"
    r"(?:api/v1|apps|app/node|app-data|app-vault|content|identity-vault|operator|platform|queue|"
    r"trust-graph|\.well-known)(?:/[^\s\]),;\"'?]*)?"
)
ROUTE_IDENTIFIER_RE = re.compile(r"(?:\{[A-Za-z][A-Za-z0-9]*\}|[A-Za-z0-9][A-Za-z0-9._~-]*)")
NON_SECRET_METADATA_SUFFIXES = (
    "available",
    "configured",
    "enabled",
    "excluded",
    "excludedfromevidence",
    "present",
    "redacted",
    "required",
    "source",
)
BODY_KEY_FRAGMENTS = (
    "requestbody",
    "rawrequestbody",
    "requestbodies",
    "rawrequestbodies",
    "feedbody",
    "rawfeedbody",
    "feedbodies",
    "rawfeedbodies",
    "feedpayload",
    "rawfeedpayload",
    "feedcontent",
    "rawfeedcontent",
    "truststatementbody",
    "rawtruststatementbody",
    "truststatementbodies",
    "rawtruststatementbodies",
    "truststatementpayload",
    "rawtruststatementpayload",
    "truststatementcontent",
    "rawtruststatementcontent",
    "messagebody",
    "rawmessagebody",
    "messagebodies",
    "rawmessagebodies",
    "fetchedbody",
    "rawfetchedbody",
    "fetchedbodies",
    "rawfetchedbodies",
)


@dataclasses.dataclass(frozen=True)
class Settings:
    workspace_root: Path
    out_dir: Path
    mode: str
    skip_gradle: bool
    cli_path: Path | None
    live: bool
    live_base_url: str
    live_form_password: str
    timeout_seconds: int


@dataclasses.dataclass(frozen=True)
class CommandResult:
    args: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int


@dataclasses.dataclass(frozen=True)
class EvidenceItem:
    id: str
    status: str
    required_for_release_candidate: bool
    summary: str
    source: str
    details: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "requiredForReleaseCandidate": self.required_for_release_candidate,
            "summary": self.summary,
            "source": self.source,
            "details": self.details,
        }


class ScriptExtractor(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        values = dict(attrs)
        src = values.get("src")
        if src:
            self.scripts.append(src)


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def path_prefix_variants(path: Path | str) -> list[str]:
    variants: list[str] = []
    for candidate in (Path(path), Path(path).resolve()):
        candidate_text = str(candidate)
        for value in (candidate_text, candidate_text.replace("\\", "/")):
            normalized = value.rstrip("/\\")
            if normalized and normalized not in variants:
                variants.append(normalized)
    return variants


def display_path(path: Path | str, workspace_root: Path, out_dir: Path | None = None) -> str:
    raw = str(path)
    if not raw:
        return ""
    candidate = Path(raw)
    if not candidate.is_absolute():
        return raw.replace("\\", "/")
    try:
        return "<repo>/" + candidate.resolve().relative_to(workspace_root.resolve()).as_posix()
    except ValueError:
        pass
    if out_dir is not None:
        try:
            relative = candidate.resolve().relative_to(out_dir.resolve())
            out_dir_display = display_path(out_dir, workspace_root)
            if not relative.parts:
                return out_dir_display
            return f"{out_dir_display}/{relative.as_posix()}"
        except ValueError:
            pass
    try:
        return "<workdir>/" + candidate.resolve().relative_to(Path(tempfile.gettempdir()).resolve()).as_posix()
    except ValueError:
        return "<path>/" + candidate.name


def summary_source(settings: Settings) -> str:
    return display_path(settings.out_dir / SUMMARY_FILE_NAME, settings.workspace_root, settings.out_dir)


def replace_absolute_path_prefix(text: str, prefix: str, replacement: str) -> str:
    if not prefix or prefix in {"/", "\\"}:
        return text
    normalized = prefix.rstrip("/\\")
    if not normalized:
        return text
    pattern = re.compile(rf"(?<![A-Za-z0-9_:/.\->]){re.escape(normalized)}(?=$|[/\\])")
    return pattern.sub(replacement, text)


def path_leaf(path_text: str) -> str:
    stripped = path_text.rstrip("\\/")
    leaf = re.split(r"[\\/]+", stripped)[-1]
    return leaf or "path"


def scrub_absolute_path_match(match: re.Match[str]) -> str:
    return "<path>/" + path_leaf(match.group(0))


def scrub_file_uri_match(match: re.Match[str]) -> str:
    return "file://<path>/" + path_leaf(match.group("path"))


def scrub_sensitive_assignment_match(match: re.Match[str]) -> str:
    if not should_redact_key_name(match.group("key")):
        return match.group(0)
    value_quote = match.group("value_quote") or ""
    return match.group("prefix") + value_quote + "<redacted>" + value_quote


def route_segments(route_path: str) -> list[str]:
    return [segment for segment in route_path.strip("/").split("/") if segment]


def is_route_identifier(segment: str) -> bool:
    return bool(ROUTE_IDENTIFIER_RE.fullmatch(segment))


def is_protected_apps_route(segments: list[str]) -> bool:
    if segments == ["apps"] or segments == ["apps", "install"]:
        return True
    if len(segments) < 2 or segments[0] != "apps" or not is_route_identifier(segments[1]):
        return False
    if len(segments) == 2:
        return True
    if len(segments) == 3:
        return segments[2] in {
            "runtime",
            "logs",
            "permissions",
            "audit",
            "start",
            "stop",
            "update",
            "updates",
        }
    return len(segments) == 4 and segments[2] == "updates" and segments[3] in {
        "check",
        "stage",
        "apply",
        "rollback",
        "policy",
    }


def is_protected_queue_route(segments: list[str]) -> bool:
    if segments == ["queue"]:
        return True
    if len(segments) == 2:
        return segments[1] in {"count", "keys", "downloads"}
    if len(segments) == 3 and segments[1] == "inserts":
        return segments[2] in {"file", "directory", "app-document"}
    if len(segments) == 3 and segments[1] == "requests":
        return segments[2] in {"remove", "restart", "priority"}
    return len(segments) == 3 and segments[1] == "cleanup" and segments[2] in {
        "uploads",
        "downloads",
    }


def is_protected_content_route(segments: list[str]) -> bool:
    if segments == ["content", "fetch"] or segments == ["content", "subscriptions"]:
        return True
    if len(segments) == 3 and segments[:2] == ["content", "subscriptions"]:
        return is_route_identifier(segments[2])
    return (
        len(segments) == 4
        and segments[:2] == ["content", "subscriptions"]
        and is_route_identifier(segments[2])
        and segments[3] in {"refresh", "pause", "resume"}
    )


def is_protected_app_data_route(segments: list[str]) -> bool:
    if len(segments) == 2 and segments[0] == "app-data":
        return segments[1] in {"status", "namespaces", "records", "export", "import"}
    if len(segments) == 3 and segments[:2] == ["app-data", "namespaces"]:
        return is_route_identifier(segments[2])
    if len(segments) == 4 and segments[:2] == ["app-data", "namespaces"]:
        return is_route_identifier(segments[2]) and segments[3] == "schema"
    return (
        len(segments) == 4
        and segments[:2] == ["app-data", "records"]
        and is_route_identifier(segments[2])
        and is_route_identifier(segments[3])
    )


def is_protected_app_vault_route(segments: list[str]) -> bool:
    if len(segments) == 2 and segments[0] == "app-vault":
        return segments[1] in {"secrets", "identities", "grants"}
    if len(segments) == 3 and segments[:2] == ["app-vault", "secrets"]:
        return is_route_identifier(segments[2])
    if len(segments) == 3 and segments[:2] == ["app-vault", "identities"]:
        return is_route_identifier(segments[2])
    if len(segments) == 4 and segments[:2] == ["app-vault", "identities"]:
        return is_route_identifier(segments[2]) and segments[3] in {
            "use",
            "profile-document",
            "trust-statement",
        }
    return len(segments) == 3 and segments[:2] == ["app-vault", "grants"] and segments[2] == "request"


def is_protected_identity_vault_route(segments: list[str]) -> bool:
    if len(segments) == 2 and segments[0] == "identity-vault":
        return segments[1] in {"identities", "grants"}
    return (
        len(segments) == 3
        and segments[0] == "identity-vault"
        and segments[1] in {"identities", "grants"}
        and is_route_identifier(segments[2])
    )


def is_protected_trust_graph_route(segments: list[str]) -> bool:
    if len(segments) == 2 and segments[0] == "trust-graph":
        return segments[1] in {
            "status",
            "anchors",
            "import",
            "import-uri",
            "audit",
            "subjects",
            "statements",
            "score",
        }
    return (
        len(segments) == 3
        and segments[:2] == ["trust-graph", "anchors"]
        and is_route_identifier(segments[2])
    )


def is_protected_route_path(route_path: str) -> bool:
    segments = route_segments(route_path)
    if len(segments) >= 2 and segments[:2] == ["api", "v1"]:
        return True
    if len(segments) >= 2 and segments[:2] == ["app", "node"]:
        return True
    if segments and segments[0] == ".well-known":
        return True
    if segments == ["platform", "contract"]:
        return True
    if not segments:
        return False
    return (
        is_protected_apps_route(segments)
        or is_protected_queue_route(segments)
        or is_protected_content_route(segments)
        or is_protected_app_data_route(segments)
        or is_protected_app_vault_route(segments)
        or is_protected_identity_vault_route(segments)
        or is_protected_trust_graph_route(segments)
    )


def protect_route_paths(text: str) -> tuple[str, list[tuple[str, str]]]:
    routes: list[tuple[str, str]] = []

    def replace_route(match: re.Match[str]) -> str:
        if not is_protected_route_path(match.group(0)):
            return match.group(0)
        token = f"__CRYPTAD_ROUTE_{len(routes)}__"
        routes.append((token, match.group(0)))
        return token

    return ROUTE_PATH_RE.sub(replace_route, text), routes


def restore_route_paths(text: str, routes: list[tuple[str, str]]) -> str:
    restored = text
    for token, route in routes:
        restored = restored.replace(token, route)
    return restored


def normalize_redacted_separators(text: str) -> str:
    def normalize_match(match: re.Match[str]) -> str:
        return match.group("prefix") + match.group("tail").replace("\\", "/")

    return re.sub(
        r"(?P<prefix><(?:repo|home|workdir|path)>)(?P<tail>(?:[\\/][^\s\])},;\"']*)?)",
        normalize_match,
        text,
    )


def scrub_text(text: str, workspace_root: Path) -> str:
    redacted = SENSITIVE_HEADER_RE.sub(lambda match: match.group("prefix") + "<redacted>", text)
    redacted = SENSITIVE_TEXT_LABEL_RE.sub(lambda match: match.group("prefix") + "<redacted>", redacted)
    redacted = PRIVATE_KEY_BLOCK_RE.sub("<redacted-private-key>", redacted)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(scrub_sensitive_assignment_match, redacted)
    redacted = URI_KEY_RE.sub("<redacted-uri>", redacted)
    redacted = FILE_URI_PATH_RE.sub(scrub_file_uri_match, redacted)
    redacted, protected_routes = protect_route_paths(redacted)
    for root_text in path_prefix_variants(workspace_root):
        redacted = replace_absolute_path_prefix(redacted, root_text, "<repo>")
    home = str(Path.home())
    if home and home != "/":
        redacted = replace_absolute_path_prefix(redacted, home, "<home>")
    redacted = replace_absolute_path_prefix(redacted, tempfile.gettempdir(), "<workdir>")
    redacted = WINDOWS_UNC_PATH_RE.sub(scrub_absolute_path_match, redacted)
    redacted = WINDOWS_DRIVE_PATH_RE.sub(scrub_absolute_path_match, redacted)
    redacted = ABSOLUTE_PATH_RE.sub(scrub_absolute_path_match, redacted)
    redacted = normalize_redacted_separators(redacted)
    return restore_route_paths(redacted, protected_routes)


def normalize_key_name(key_hint: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key_hint.lower())


def should_redact_key_name(key_hint: str, value: Any | None = None) -> bool:
    normalized = normalize_key_name(key_hint)
    if not normalized:
        return False
    if any(fragment in normalized for fragment in BODY_KEY_FRAGMENTS):
        return not (isinstance(value, bool) and normalized.endswith(NON_SECRET_METADATA_SUFFIXES))
    if normalized.endswith(NON_SECRET_METADATA_SUFFIXES):
        return False
    if normalized in {
        "authorization",
        "cookie",
        "setcookie",
        "credential",
        "cryptadapptoken",
        "formpassword",
        "privatekey",
        "secret",
        "token",
        "password",
        "passwd",
        "identityseed",
        "recoveryphrase",
        "mnemonic",
        "seed",
        "browsersessiontoken",
        "xcryptaappsession",
    }:
        return True
    if "signature" in normalized and any(
        fragment in normalized for fragment in ("value", "base64", "payload", "document")
    ):
        return True
    return any(
        fragment in normalized
        for fragment in (
            "privatekey",
            "token",
            "password",
            "passwd",
            "secret",
            "credential",
            "seedphrase",
            "recoveryphrase",
            "mnemonic",
        )
    )


def sanitize_value(value: Any, workspace_root: Path, key_hint: str = "") -> Any:
    if should_redact_key_name(key_hint, value):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(key): sanitize_value(child, workspace_root, str(key)) for key, child in value.items()}
    if isinstance(value, list):
        return [sanitize_value(child, workspace_root, key_hint) for child in value]
    if isinstance(value, tuple):
        return tuple(sanitize_value(child, workspace_root, key_hint) for child in value)
    if isinstance(value, str):
        return scrub_text(value, workspace_root)
    return value


def is_local_live_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1", "0:0:0:0:0:0:0:1"}


DIRECT_LOCAL_ENDPOINT_RE = re.compile(
    r"(?i)(?:"
    r"\blocalhost\b|"
    r"\b127(?:\.\d{1,3}){3}\b|"
    r"\b0\.0\.0\.0\b|"
    r"\[::1\]|"
    r"(?<![0-9a-f:])::1(?![0-9a-f:])|"
    r"\b0:0:0:0:0:0:0:1\b"
    r")"
)


def has_direct_local_endpoint_reference(text: str) -> bool:
    return DIRECT_LOCAL_ENDPOINT_RE.search(text) is not None


def normalized_source_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower())


def social_inbox_docs_frame_spike_non_goals(docs_text: str) -> bool:
    normalized = normalized_source_text(docs_text)
    wot_non_goal = bool(
        re.search(
            r"\bnot\s+(?:a\s+)?(?:[^.]{0,160}\b)?full\s+(?:wot|web of trust)\b",
            normalized,
        )
    )
    daemon_store_non_goal = (
        "daemon-core message store" in normalized or "daemon message store" in normalized
    )
    return (
        wot_non_goal
        and "freetalk" in normalized
        and "sone" in normalized
        and "freemail" in normalized
        and "encrypted mail" in normalized
        and daemon_store_non_goal
    )


def live_base_url_details(base_url: str) -> dict[str, Any]:
    if not base_url:
        return {"baseUrl": "missing", "localhostOnly": False}
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname or ""
    if not is_local_live_host(host):
        return {"baseUrl": "<redacted-remote-url>", "localhostOnly": False}
    netloc = host
    if parsed.port is not None:
        netloc = f"{host}:{parsed.port}"
    scheme = parsed.scheme or "http"
    return {"baseUrl": f"{scheme}://{netloc}", "localhostOnly": True}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def parse_properties(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"{path}:{line_number}: expected key=value")
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"{path}:{line_number}: blank property key")
        if key in result:
            raise ValueError(f"{path}:{line_number}: duplicate property key: {key}")
        result[key] = value.strip()
    return result


def parse_permission_set(raw_permissions: str) -> set[str]:
    return {
        permission.strip()
        for permission in raw_permissions.split(",")
        if permission.strip()
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_command(
    args: list[str],
    settings: Settings,
    log_name: str,
    timeout_seconds: int | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    logs_dir = settings.out_dir / "artifacts" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    try:
        completed = subprocess.run(
            args,
            cwd=str(settings.workspace_root),
            env=merged_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds or settings.timeout_seconds,
            check=False,
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr if isinstance(exc.stderr, str) else "") + "\nCommand timed out."
    except OSError as exc:
        exit_code = 127
        stdout = ""
        stderr = str(exc)
    duration_ms = int((time.monotonic() - started) * 1000)
    result = CommandResult(args=args, exit_code=exit_code, stdout=stdout, stderr=stderr, duration_ms=duration_ms)
    write_text(logs_dir / f"{log_name}.stdout.log", scrub_text(stdout, settings.workspace_root))
    write_text(logs_dir / f"{log_name}.stderr.log", scrub_text(stderr, settings.workspace_root))
    return result


def gradle_command(settings: Settings, tasks: list[str], log_name: str) -> CommandResult | None:
    if settings.skip_gradle:
        return None
    wrapper = settings.workspace_root / ("gradlew.bat" if platform.system() == "Windows" else "gradlew")
    return run_command([str(wrapper), *tasks], settings, log_name, timeout_seconds=1200)


def command_ok(result: CommandResult | None) -> bool:
    return result is None or result.exit_code == 0


def command_details(result: CommandResult | None, settings: Settings) -> dict[str, Any]:
    if result is None:
        return {"skipped": True, "reason": "Gradle execution was skipped by configuration."}
    return {
        "exitCode": result.exit_code,
        "durationMs": result.duration_ms,
        "command": redact_command(result.args, settings),
    }


def redact_command(args: list[str], settings: Settings) -> list[str]:
    redacted: list[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            redacted.append("<redacted>")
            skip_next = False
            continue
        if arg in SECRET_COMMAND_VALUE_OPTIONS:
            redacted.append(arg)
            skip_next = True
        elif "private" in arg.lower() and "key" in arg.lower() and "=" in arg:
            key, _ = arg.split("=", 1)
            redacted.append(key + "=<redacted>")
        else:
            redacted.append(scrub_text(arg, settings.workspace_root))
    return redacted


def root_consequence(settings: Settings, release_candidate_status: str, non_rc_status: str = "warn") -> str:
    return release_candidate_status if settings.mode == "release-candidate" else non_rc_status


def first_party_app_specs(settings: Settings) -> list[dict[str, Any]]:
    return [
        {
            "appId": "queue-manager",
            "name": "Queue Manager",
            "stagedDir": settings.workspace_root / "apps/queue-manager/build/cryptad-app/queue-manager",
            "sourceDir": settings.workspace_root / "apps/queue-manager/src/staged",
            "launcher": "bin/queue-manager.sh",
            "permissions": {"queue.read", "queue.write"},
        },
        {
            "appId": "publisher",
            "name": "Publisher",
            "stagedDir": settings.workspace_root / "apps/publisher/build/cryptad-app/publisher",
            "sourceDir": settings.workspace_root / "apps/publisher/src/staged",
            "launcher": "bin/publisher.sh",
            "permissions": {"queue.read", "queue.write", "content.insert"},
        },
        {
            "appId": "site-publisher",
            "name": "Site Publisher",
            "stagedDir": (
                settings.workspace_root
                / "apps/site-publisher/build/cryptad-app/site-publisher"
            ),
            "sourceDir": settings.workspace_root / "apps/site-publisher/src/staged",
            "launcher": "bin/site-publisher.sh",
            "permissions": {"queue.read", "queue.write", "content.insert"},
            "apiMinimumVersion": 3,
            "apiMaximumTestedVersion": CURRENT_PLATFORM_API_CONTRACT_VERSION,
        },
        {
            "appId": "profile-publisher",
            "name": "Profile Publisher",
            "stagedDir": (
                settings.workspace_root
                / "apps/profile-publisher/build/cryptad-app/profile-publisher"
            ),
            "sourceDir": settings.workspace_root / "apps/profile-publisher/src/staged",
            "launcher": "bin/profile-publisher.sh",
            "permissions": PROFILE_PUBLISHER_PERMISSIONS,
            "apiMinimumVersion": 9,
            "apiMaximumTestedVersion": CURRENT_PLATFORM_API_CONTRACT_VERSION,
        },
        {
            "appId": "social-inbox",
            "name": "Social Inbox RC",
            "allowedNames": SOCIAL_INBOX_DISPLAY_NAMES,
            "stagedDir": (
                settings.workspace_root / "apps/social-inbox/build/cryptad-app/social-inbox"
            ),
            "sourceDir": settings.workspace_root / "apps/social-inbox/src/staged",
            "launcher": "bin/social-inbox.sh",
            "permissions": SOCIAL_INBOX_PERMISSIONS,
            "apiMinimumVersion": 16,
            "apiMaximumTestedVersion": CURRENT_PLATFORM_API_CONTRACT_VERSION,
            "experimentalCapabilitiesAccepted": True,
        },
        {
            "appId": "feed-reader",
            "name": "Feed Reader & Publisher",
            "stagedDir": (
                settings.workspace_root / "apps/feed-reader/build/cryptad-app/feed-reader"
            ),
            "sourceDir": settings.workspace_root / "apps/feed-reader/src/staged",
            "launcher": "bin/feed-reader.sh",
            "permissions": FEED_READER_PERMISSIONS,
            "apiMinimumVersion": 9,
            "apiMaximumTestedVersion": CURRENT_PLATFORM_API_CONTRACT_VERSION,
        },
        {
            "appId": "trust-graph",
            "name": "Trust Graph Local RC",
            "stagedDir": (
                settings.workspace_root / "apps/trust-graph/build/cryptad-app/trust-graph"
            ),
            "sourceDir": settings.workspace_root / "apps/trust-graph/src/staged",
            "launcher": "bin/trust-graph.sh",
            "permissions": TRUST_GRAPH_PERMISSIONS,
            "apiMinimumVersion": 10,
            "apiMaximumTestedVersion": CURRENT_PLATFORM_API_CONTRACT_VERSION,
            "experimentalCapabilitiesAccepted": True,
        },
    ]


def validate_app_bundle(bundle_dir: Path, spec: dict[str, Any], settings: Settings) -> tuple[bool, list[str], dict[str, Any]]:
    errors: list[str] = []
    details: dict[str, Any] = {"bundleDir": display_path(bundle_dir, settings.workspace_root)}
    manifest_path = bundle_dir / "cryptad-app.properties"
    if not manifest_path.is_file():
        errors.append("cryptad-app.properties is missing")
        return False, errors, details
    try:
        manifest = parse_properties(manifest_path)
    except ValueError as exc:
        errors.append(str(exc))
        return False, errors, details
    details["manifest"] = {
        "appId": manifest.get("app.id"),
        "name": manifest.get("app.name"),
        "version": manifest.get("app.version"),
        "uiMode": manifest.get("app.ui.mode"),
        "uiEntry": manifest.get("app.ui.entry"),
        "permissions": sorted(parse_permission_set(manifest.get("app.permissions", ""))),
        "apiMinimumVersion": manifest.get("api.minimumVersion"),
        "apiMaximumTestedVersion": manifest.get("api.maximumTestedVersion"),
    }
    for key in ("app.id", "app.name", "app.version"):
        if not manifest.get(key):
            errors.append(f"{key} is missing")
    if manifest.get("app.id") != spec["appId"]:
        errors.append(f"app.id expected {spec['appId']}, got {manifest.get('app.id')}")
    allowed_names = set(spec.get("allowedNames", {spec["name"]}))
    if manifest.get("app.name") not in allowed_names:
        errors.append(
            f"app.name expected one of {sorted(allowed_names)}, got {manifest.get('app.name')}"
        )
    if manifest.get("app.ui.mode") != "static":
        errors.append("app.ui.mode must be static")
    if manifest.get("app.ui.entry") != "static/index.html":
        errors.append("app.ui.entry must be static/index.html")
    declared_permissions = parse_permission_set(manifest.get("app.permissions", ""))
    if not spec["permissions"].issubset(declared_permissions):
        errors.append("manifest permissions are incomplete")
    if "apiMinimumVersion" in spec and manifest.get("api.minimumVersion") != str(
        spec["apiMinimumVersion"]
    ):
        errors.append("api.minimumVersion does not match expected first-party metadata")
    if "apiMaximumTestedVersion" in spec and manifest.get("api.maximumTestedVersion") != str(
        spec["apiMaximumTestedVersion"]
    ):
        errors.append("api.maximumTestedVersion does not match expected first-party metadata")
    for relative in (spec["launcher"], "static/index.html", "static/app.js", "static/app.css", "static/crypta-platform.js"):
        if not (bundle_dir / relative).is_file():
            errors.append(f"{relative} is missing")
    static_errors, static_details = validate_static_ui_files(bundle_dir / "static", settings)
    errors.extend(static_errors)
    details.update(static_details)
    return not errors, errors, details


def validate_static_ui_files(static_dir: Path, settings: Settings) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    details: dict[str, Any] = {}
    index = static_dir / "index.html"
    app_js = static_dir / "app.js"
    sdk = static_dir / "crypta-platform.js"
    if index.is_file():
        scripts = extract_scripts(index)
        normalized_scripts = [normalize_static_script_ref(script) for script in scripts]
        details["scripts"] = scripts
        if "crypta-platform.js" not in normalized_scripts:
            errors.append("index.html does not load crypta-platform.js")
        if "app.js" in normalized_scripts and "crypta-platform.js" in normalized_scripts:
            if normalized_scripts.index("crypta-platform.js") > normalized_scripts.index("app.js"):
                errors.append("index.html must load crypta-platform.js before app.js")
    if app_js.is_file():
        app_text = app_js.read_text(encoding="utf-8")
        if ".bootstrap.load" not in app_text:
            errors.append("app.js does not call CryptaPlatform.bootstrap.load")
    if sdk.is_file():
        sdk_text = sdk.read_text(encoding="utf-8")
        if "window.CryptaPlatform" not in sdk_text:
            errors.append("crypta-platform.js does not expose window.CryptaPlatform")
        if "X-Crypta-App-Session" not in sdk_text:
            errors.append("crypta-platform.js does not use X-Crypta-App-Session")
    for file_path in static_dir.glob("**/*"):
        if not file_path.is_file():
            continue
        text = file_path.read_text(encoding="utf-8", errors="replace")
        for forbidden in ("CRYPTAD_APP_TOKEN", "formPassword", "localStorage.setItem", "sessionStorage.setItem"):
            if forbidden in text:
                errors.append(f"{display_path(file_path, settings.workspace_root)} contains forbidden text {forbidden}")
    canonical_sdk = settings.workspace_root / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    if sdk.is_file() and canonical_sdk.is_file():
        details["sdkMatchesCanonical"] = sha256_file(sdk) == sha256_file(canonical_sdk)
        if not details["sdkMatchesCanonical"]:
            errors.append("staged SDK does not match canonical SDK resource")
    return errors, details


def normalize_static_script_ref(script: str) -> str:
    value = script.split("?", 1)[0].split("#", 1)[0]
    while value.startswith("./"):
        value = value[2:]
    return value


def extract_scripts(path: Path) -> list[str]:
    parser = ScriptExtractor()
    parser.feed(path.read_text(encoding="utf-8"))
    return parser.scripts


def check_source_static_ui(settings: Settings) -> tuple[bool, list[str], dict[str, Any]]:
    errors: list[str] = []
    details: dict[str, Any] = {}
    for spec in first_party_app_specs(settings):
        static_dir = spec["sourceDir"] / "static"
        app_errors, app_details = validate_static_ui_files(static_dir, settings)
        errors.extend(f"{spec['appId']}: {error}" for error in app_errors)
        details[spec["appId"]] = app_details
    sdk_path = settings.workspace_root / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    if not sdk_path.is_file():
        errors.append("canonical SDK resource is missing")
    else:
        details["sdkResource"] = display_path(sdk_path, settings.workspace_root)
    return not errors, errors, details


def find_cli(settings: Settings) -> Path | None:
    if settings.cli_path is not None:
        return settings.cli_path
    script = "crypta-app.bat" if platform.system() == "Windows" else "crypta-app"
    candidate = settings.workspace_root / "platform-devtools/build/install/crypta-app/bin" / script
    if candidate.is_file():
        return candidate
    return None


def run_cli(cli: Path, args: list[str], settings: Settings, log_name: str) -> CommandResult:
    return run_command([str(cli), *args], settings, log_name, timeout_seconds=180)


def remove_existing_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def write_live_smoke_launcher(sample_dir: Path) -> None:
    launcher = sample_dir / "bin/start.sh"
    launcher.parent.mkdir(parents=True, exist_ok=True)
    launcher.write_text(
        """#!/usr/bin/env sh
set -eu

child=""
cleanup() {
  if [ -n "$child" ]; then
    kill "$child" 2>/dev/null || true
  fi
  exit 0
}

trap cleanup INT TERM

while :; do
  sleep 60 &
  child="$!"
  wait "$child" 2>/dev/null || true
  child=""
done
""",
        encoding="utf-8",
    )
    launcher.chmod(0o755)


def signing_inputs(env: dict[str, str]) -> dict[str, Any]:
    key_id = env.get("CRYPTAD_APP_SIGNING_KEY_ID", "").strip()
    private_file = env.get("CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE", "").strip()
    private_base64 = env.get("CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64", "").strip()
    public_file = env.get("CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE", "").strip()
    public_base64 = env.get("CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64", "").strip()
    return {
        "keyId": key_id,
        "privateFile": private_file,
        "privateBase64": bool(private_base64),
        "publicFile": public_file,
        "publicBase64": bool(public_base64),
        "hasPrivate": bool(private_file or private_base64),
        "hasPublic": bool(public_file or public_base64),
        "complete": bool(key_id and (private_file or private_base64) and (public_file or public_base64)),
    }


def reviewer_inputs(env: dict[str, str]) -> dict[str, Any]:
    key_id = env.get("CRYPTAD_APP_REVIEWER_KEY_ID", "").strip()
    private_file = env.get("CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE", "").strip()
    private_base64 = env.get("CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64", "").strip()
    public_file = env.get("CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE", "").strip()
    public_base64 = env.get("CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64", "").strip()
    policy_id = env.get("CRYPTAD_APP_REVIEW_POLICY_ID", "crypta-app-review-v1").strip()
    policy_version = env.get("CRYPTAD_APP_REVIEW_POLICY_VERSION", "1").strip()
    return {
        "keyId": key_id,
        "privateFile": private_file,
        "privateBase64": bool(private_base64),
        "publicFile": public_file,
        "publicBase64": bool(public_base64),
        "policyId": policy_id,
        "policyVersion": policy_version,
        "hasPrivate": bool(private_file or private_base64),
        "hasPublic": bool(public_file or public_base64),
        "complete": bool(key_id and policy_id and policy_version and (private_file or private_base64) and (public_file or public_base64)),
    }


def sign_args(bundle_dir: Path, inputs: dict[str, Any]) -> list[str]:
    args = ["sign", "--bundle-dir", str(bundle_dir), "--key-id", inputs["keyId"]]
    if inputs["privateFile"]:
        args.extend(["--private-key-file", inputs["privateFile"]])
    else:
        args.extend(["--private-key-env", "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64"])
    return args


def verify_args(bundle_dir: Path, inputs: dict[str, Any]) -> list[str]:
    args = ["verify", "--bundle-dir", str(bundle_dir), "--trusted-key-id", inputs["keyId"]]
    if inputs["publicFile"]:
        args.extend(["--trusted-public-key-file", inputs["publicFile"]])
    else:
        args.extend(["--trusted-public-key-base64", os.environ.get("CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64", "")])
    return args


def catalog_sign_args(catalog_file: Path, inputs: dict[str, Any]) -> list[str]:
    args = ["catalog", "sign", "--catalog-file", str(catalog_file), "--key-id", inputs["keyId"]]
    if inputs["privateFile"]:
        args.extend(["--private-key-file", inputs["privateFile"]])
    else:
        args.extend(["--private-key-env", "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64"])
    return args


def catalog_verify_args(catalog_file: Path, inputs: dict[str, Any]) -> list[str]:
    args = ["catalog", "verify", "--catalog-file", str(catalog_file), "--trusted-key-id", inputs["keyId"]]
    if inputs["publicFile"]:
        args.extend(["--trusted-public-key-file", inputs["publicFile"]])
    else:
        args.extend(["--trusted-public-key-base64", os.environ.get("CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64", "")])
    return args


def review_sign_args(descriptor: Path, receipt_file: Path, inputs: dict[str, Any]) -> list[str]:
    args = [
        "review",
        "sign",
        "--catalog-entry",
        str(descriptor),
        "--receipt-file",
        str(receipt_file),
        "--reviewer-key-id",
        inputs["keyId"],
        "--policy-id",
        inputs["policyId"],
        "--policy-version",
        inputs["policyVersion"],
        "--status",
        "reviewed",
        "--reviewed-at",
        "2026-05-01T00:00:00Z",
        "--overwrite",
    ]
    if inputs["privateFile"]:
        args.extend(["--reviewer-private-key-file", inputs["privateFile"]])
    else:
        args.extend(["--reviewer-private-key-env", "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64"])
    return args


def review_verify_args(descriptor: Path, receipt_file: Path, trusted_keys_file: Path) -> list[str]:
    return [
        "review",
        "verify",
        "--catalog-entry",
        str(descriptor),
        "--receipt-file",
        str(receipt_file),
        "--trusted-reviewer-keys-file",
        str(trusted_keys_file),
    ]


def reviewer_public_key_base64(inputs: dict[str, Any]) -> str:
    if inputs["publicBase64"]:
        return "".join(os.environ.get("CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64", "").split())
    public_file = inputs["publicFile"]
    if not public_file:
        return ""
    raw = Path(public_file).read_bytes()
    text = raw.decode("utf-8", errors="ignore")
    if "BEGIN PUBLIC KEY" in text:
        return "".join(
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.startswith("-----")
        )
    compact_text = compact_base64_key_text(raw)
    if compact_text:
        return compact_text
    return base64.b64encode(raw).decode("ascii")


def compact_base64_key_text(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    compact = "".join(text.split())
    if not compact:
        return None
    try:
        base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    return compact


def write_trusted_reviewer_keys(path: Path, inputs: dict[str, Any]) -> None:
    public_key = reviewer_public_key_base64(inputs)
    path.write_text(
        "\n".join(
            [
                "trusted.reviewers.version=1",
                f"reviewer.1.id={inputs['keyId']}",
                "reviewer.1.algorithm=Ed25519",
                f"reviewer.1.public.key.base64={public_key}",
                "reviewer.1.display.name=Certification Reviewer",
                f"reviewer.1.policy.id={inputs['policyId']}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def collect_first_party_evidence(settings: Settings, cli: Path | None) -> EvidenceItem:
    gradle_result = gradle_command(settings, ["stageFirstPartyApps"], "gradle-stage-first-party-apps")
    errors: list[str] = []
    details: dict[str, Any] = {"stageCommand": command_details(gradle_result, settings), "apps": {}}
    if gradle_result is not None and gradle_result.exit_code != 0:
        errors.append("stageFirstPartyApps failed")
    for spec in first_party_app_specs(settings):
        ok, app_errors, app_details = validate_app_bundle(spec["stagedDir"], spec, settings)
        details["apps"][spec["appId"]] = app_details
        if not ok:
            errors.extend(f"{spec['appId']}: {error}" for error in app_errors)
        if cli is not None and spec["stagedDir"].is_dir():
            result = run_cli(cli, ["validate", "--bundle-dir", str(spec["stagedDir"])], settings, f"crypta-app-validate-{spec['appId']}")
            details["apps"][spec["appId"]]["cliValidate"] = command_details(result, settings)
            if result.exit_code != 0:
                errors.append(f"crypta-app validate failed for {spec['appId']}")
    if errors:
        return EvidenceItem(
            "app-platform.first-party",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "First-party staged app validation found problems.",
            summary_source(settings),
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.first-party",
        "pass",
        True,
        "First-party staged app manifests and static assets passed.",
        summary_source(settings),
        details,
    )


def sample_workspace(settings: Settings) -> Path:
    work_dir = settings.out_dir / "work"
    work_dir.mkdir(parents=True, exist_ok=True)
    return work_dir


def collect_cli_evidence(settings: Settings, cli: Path | None) -> tuple[EvidenceItem, dict[str, Path]]:
    details: dict[str, Any] = {}
    sample_paths: dict[str, Path] = {}
    install_result = gradle_command(settings, [":platform-devtools:installDist"], "gradle-platform-devtools-installDist")
    details["installDistCommand"] = command_details(install_result, settings)
    cli = find_cli(settings)
    if install_result is not None and install_result.exit_code != 0:
        return (
            EvidenceItem(
                "app-platform.devtools-cli",
                root_consequence(settings, "fail"),
                True,
                "platform-devtools installDist failed.",
                summary_source(settings),
                details,
            ),
            sample_paths,
        )
    if cli is None or not cli.is_file():
        return (
            EvidenceItem(
                "app-platform.devtools-cli",
                root_consequence(settings, "missing"),
                True,
                "crypta-app launcher is missing.",
                summary_source(settings),
                details,
            ),
            sample_paths,
        )
    details["cliPath"] = display_path(cli, settings.workspace_root)
    sample_dir = sample_workspace(settings) / "cert-smoke-app"
    sample_zip = sample_workspace(settings) / "cert-smoke-app-0.1.0.zip"
    remove_existing_path(sample_dir)
    init_result = run_cli(
        cli,
        [
            "init",
            "--dir",
            str(sample_dir),
            "--app-id",
            "cert-smoke",
            "--name",
            "Certification Smoke",
            "--version",
            "0.1.0",
            "--ui-mode",
            "static",
            "--permission",
            "queue.read",
            "--overwrite",
        ],
        settings,
        "crypta-app-init-sample",
    )
    launcher_error = ""
    if init_result.exit_code == 0:
        try:
            write_live_smoke_launcher(sample_dir)
        except OSError as exc:
            launcher_error = scrub_text(str(exc), settings.workspace_root)
    validate_result = run_cli(cli, ["validate", "--bundle-dir", str(sample_dir)], settings, "crypta-app-validate-sample")
    remove_existing_path(sample_zip)
    pack_result = run_cli(
        cli,
        ["pack", "--bundle-dir", str(sample_dir), "--output", str(sample_zip), "--overwrite"],
        settings,
        "crypta-app-pack-sample",
    )
    details["sample"] = {
        "appId": "cert-smoke",
        "bundleDir": display_path(sample_dir, settings.workspace_root),
        "zip": display_path(sample_zip, settings.workspace_root),
        "init": command_details(init_result, settings),
        "launcherRewritten": not launcher_error and init_result.exit_code == 0,
        "validate": command_details(validate_result, settings),
        "pack": command_details(pack_result, settings),
    }
    if launcher_error:
        details["sample"]["launcherError"] = launcher_error
    sample_paths.update({"bundleDir": sample_dir, "zip": sample_zip, "cli": cli})
    pack_output_exists = sample_zip.is_file()
    details["sample"]["zipExists"] = pack_output_exists
    if pack_output_exists:
        details["sample"]["zipSha256"] = sha256_file(sample_zip)
        details["sample"]["zipSizeBytes"] = sample_zip.stat().st_size
    failed = [name for name, result in (("init", init_result), ("validate", validate_result), ("pack", pack_result)) if result.exit_code != 0]
    if launcher_error:
        failed.append("launcher")
    if pack_result.exit_code == 0 and not pack_output_exists:
        failed.append("pack-output")
    if failed:
        return (
            EvidenceItem(
                "app-platform.devtools-cli",
                root_consequence(settings, "fail"),
                True,
                "crypta-app sample init, validate, or pack failed.",
                summary_source(settings),
                {"failedSteps": failed, **details},
            ),
            sample_paths,
        )
    return (
        EvidenceItem(
            "app-platform.devtools-cli",
            "pass",
            True,
            "crypta-app init, validate, and pack passed.",
            summary_source(settings),
            details,
        ),
        sample_paths,
    )


def collect_developer_beta_toolkit_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    devtools_dir = workspace / "platform-devtools/src/main/java/network/crypta/platform/devtools"
    devserver_dir = devtools_dir / "devserver"
    test_dir = workspace / "platform-devtools/src/test/java/network/crypta/platform/devtools"
    docs_path = workspace / DEVELOPER_BETA_TOOLKIT_DOC
    sources = {
        "cli": devtools_dir / "CryptaAppCli.java",
        "templateKind": devtools_dir / "AppTemplateKind.java",
        "scaffolder": devtools_dir / "AppTemplateScaffolder.java",
        "testSuite": devtools_dir / "AppTestSuite.java",
        "devServer": devserver_dir / "CryptaAppDevServer.java",
        "devServerConfig": devserver_dir / "DevServerConfig.java",
        "mockApi": devserver_dir / "MockPlatformApi.java",
        "catalogEntry": devtools_dir / "CatalogEntryDescriptorGenerator.java",
        "publishPlan": devtools_dir / "PublicationPlanWriter.java",
        "keyGenerator": devtools_dir / "DeveloperKeyGenerator.java",
        "toolkitTests": test_dir / "DeveloperBetaToolkitCliTest.java",
        "docs": docs_path,
    }
    text = {name: read_source(path) for name, path in sources.items()}
    required_templates = {
        "static-basic": "STATIC_BASIC",
        "queue-dashboard": "QUEUE_DASHBOARD",
        "publisher": "PUBLISHER",
        "vault-profile": "VAULT_PROFILE",
    }
    command_checks = {
        "devCommand": '@Command(name = "dev"' in text["cli"],
        "testCommand": '@Command(name = "test"' in text["cli"],
        "keysGenerateCommand": '@Command(name = "generate"' in text["cli"] and "KeysGenerateCommand" in text["cli"],
        "catalogEntryCommand": '@Command(name = "entry"' in text["cli"] and "CatalogEntryCommand" in text["cli"],
        "publishUskCommand": '@Command(name = "publish-usk"' in text["cli"],
    }
    template_checks = {
        template: template in text["templateKind"] and enum_name in text["scaffolder"]
        for template, enum_name in required_templates.items()
    }
    flow_checks = {
        "devServerLoopbackDefault": "127.0.0.1" in text["devServerConfig"] and "allowNonLoopback" in text["devServer"],
        "mockSessionRequired": "invalid_app_browser_session" in text["mockApi"] and "X-Crypta-App-Session" in text["mockApi"],
        "offlineTestSmoke": "dev.bootstrap-smoke" in text["testSuite"] and "AppTestReport" in text["testSuite"],
        "catalogDescriptorGenerator": "artifact.path" in text["catalogEntry"] and "permissions.rationale." in text["catalogEntry"],
        "publishUskDryRunAndLive": (
            "--dry-run" in text["cli"]
            and "--live" in text["cli"]
            and "PublicationPlanWriter" in text["cli"]
            and "LiveUskPublicationService" in text["cli"]
            and "Crypta Catalog USK Publication Plan" in text["publishPlan"]
        ),
        "keyGeneration": "Ed25519" in text["keyGenerator"] and "trusted.keys.version=1" in text["keyGenerator"],
        "selfTestsCoverFlow": (
            "test_whenFreshStaticTemplateCheckedStrict_expectPassingHumanAndJsonReport" in text["toolkitTests"]
            and "catalogEntryAndPublishUsk_whenSignedArtifactsPrepared_expectOfflinePlan" in text["toolkitTests"]
            and "devServer_whenStaticAppServed_expectBootstrapStaticAndSessionProtectedApi" in text["toolkitTests"]
        ),
        "guideExists": docs_path.is_file(),
        "guideCoversFlow": (
            "crypta-app init" in text["docs"]
            and "--template queue-dashboard" in text["docs"]
            and "crypta-app dev --bundle-dir" in text["docs"]
            and "crypta-app test --bundle-dir" in text["docs"]
            and "crypta-app keys generate" in text["docs"]
            and "crypta-app catalog entry" in text["docs"]
            and "crypta-app publish-usk" in text["docs"]
        ),
    }
    checks = {**command_checks, "templates": template_checks, **flow_checks}
    missing_files = [
        name
        for name, path in sources.items()
        if not path.is_file()
    ]
    failed_checks = [
        name
        for name, value in checks.items()
        if value is False or (isinstance(value, dict) and not all(value.values()))
    ]
    details = {
        "sources": {name: display_path(path, workspace) for name, path in sources.items()},
        "checks": checks,
    }
    if missing_files or failed_checks:
        return EvidenceItem(
            "app-platform.developer-beta-toolkit",
            root_consequence(settings, "fail"),
            True,
            "Developer beta toolkit evidence found missing commands, docs, or self-test coverage.",
            source,
            {"missingFiles": missing_files, "failedChecks": failed_checks, **details},
        )
    return EvidenceItem(
        "app-platform.developer-beta-toolkit",
        "pass",
        True,
        "Developer beta toolkit command, mock-dev, test, catalog, and publication-plan evidence passed.",
        source,
        details,
    )


def stable_capability_names(capabilities: list[Any]) -> list[str]:
    names: list[str] = []
    for entry in capabilities:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("stability", "unknown")).lower() != "stable":
            continue
        name = str(entry.get("name") or entry.get("id") or "").strip()
        if name and name not in names:
            names.append(name)
    return sorted(names)


def stable_endpoint_identities(endpoints: list[Any]) -> list[str]:
    identities: list[str] = []
    for entry in endpoints:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("stability", "unknown")).lower() != "stable":
            continue
        route = str(entry.get("routeTemplate") or entry.get("path") or entry.get("route") or "").strip()
        if not route:
            continue
        method = str(entry.get("method", "")).strip().upper()
        identity = f"{method} {route}" if method else route
        if identity not in identities:
            identities.append(identity)
    return sorted(identities)


def capability_names(capabilities: list[Any]) -> list[str]:
    names: list[str] = []
    for entry in capabilities:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or entry.get("id") or "").strip()
        if name and name not in names:
            names.append(name)
    return sorted(names)


def endpoint_identities(endpoints: list[Any]) -> list[str]:
    identities: list[str] = []
    for entry in endpoints:
        if not isinstance(entry, dict):
            continue
        route = str(entry.get("routeTemplate") or entry.get("path") or entry.get("route") or "").strip()
        if not route:
            continue
        method = str(entry.get("method", "")).strip().upper()
        identity = f"{method} {route}" if method else route
        if identity not in identities:
            identities.append(identity)
    return sorted(identities)


def collect_platform_api_contract_evidence(
    settings: Settings, cli: Path | None, sample_paths: dict[str, Path]
) -> EvidenceItem:
    source = summary_source(settings)
    artifact = settings.out_dir / "artifacts" / "platform-api-contract.json"
    details: dict[str, Any] = {"artifactPath": display_path(artifact, settings.workspace_root, settings.out_dir)}
    if cli is None or not cli.is_file():
        return EvidenceItem(
            "platform-api.contract",
            root_consequence(settings, "missing"),
            True,
            "crypta-app CLI is unavailable for Platform API contract evidence.",
            source,
            details,
        )

    snapshot_result = run_cli(
        cli,
        ["api", "snapshot", "--output", str(artifact)],
        settings,
        "crypta-app-api-snapshot",
    )
    details["snapshotCommand"] = command_details(snapshot_result, settings)
    errors: list[str] = []
    if snapshot_result.exit_code != 0:
        errors.append("contract snapshot generation failed")
    if not artifact.is_file():
        errors.append("contract snapshot file was not written")

    contract: dict[str, Any] = {}
    if artifact.is_file():
        try:
            payload = json.loads(artifact.read_text(encoding="utf-8"))
            contract = payload.get("contract", payload) if isinstance(payload, dict) else {}
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"contract snapshot is not valid JSON: {exc}")

    capabilities = contract.get("capabilities", []) if isinstance(contract, dict) else []
    endpoints = contract.get("endpoints", []) if isinstance(contract, dict) else []
    if not isinstance(capabilities, list):
        errors.append("contract capabilities must be a list")
        capabilities = []
    if not isinstance(endpoints, list):
        errors.append("contract endpoints must be a list")
        endpoints = []
    stability_counts: dict[str, int] = {}
    flagged: list[str] = []
    for collection_name, entries in (("capability", capabilities), ("endpoint", endpoints)):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            stability = str(entry.get("stability", "unknown"))
            stability_counts[stability] = stability_counts.get(stability, 0) + 1
            if stability != "stable":
                flagged.append(f"{collection_name}:{entry.get('name') or entry.get('routeTemplate')}:{stability}")
    contract_version = contract.get("contractVersion") if isinstance(contract, dict) else None
    api_version = contract.get("apiVersion") if isinstance(contract, dict) else None
    details["contractVersion"] = contract_version
    details["apiVersion"] = api_version
    details["capabilityCount"] = len(capabilities)
    details["endpointCount"] = len(endpoints)
    details["stableCapabilities"] = stable_capability_names(capabilities)
    details["stableEndpoints"] = stable_endpoint_identities(endpoints)
    details["stabilityCounts"] = stability_counts
    details["flaggedStability"] = flagged
    required_app_data_capabilities = {"app.data.read", "app.data.write"}
    required_app_data_endpoints = {
        "GET /app-data/status",
        "GET /app-data/namespaces",
        "GET /app-data/namespaces/{namespace}",
        "POST /app-data/namespaces/{namespace}/schema",
        "DELETE /app-data/namespaces/{namespace}",
        "GET /app-data/records",
        "GET /app-data/records/{namespace}/{key}",
        "POST /app-data/records",
        "DELETE /app-data/records/{namespace}/{key}",
        "GET /app-data/export",
        "POST /app-data/import",
    }
    required_trust_exchange_capabilities = {"content.fetch", "trust.read", "trust.write"}
    required_trust_exchange_endpoints = {
        "GET /trust-graph/audit",
        "POST /trust-graph/import-uri",
    }
    required_social_message_capabilities = {
        "vault.identities.read",
        "vault.identities.use",
    }
    required_social_message_endpoints = {
        "POST /app-vault/identities/{identityId}/social-message",
    }
    required_app_service_capabilities = {
        "app.services.read",
        "app.services.call",
    }
    required_app_service_endpoints = {
        "GET /app-services",
        "GET /app-services/audit",
        "GET /app-services/dependencies",
        "GET /app-services/dependencies/consumers/{consumerAppId}",
        "GET /app-services/grant-bundles",
        "GET /app-services/grants",
        "POST /app-services/grant-bundles",
        "POST /app-services/grant-bundles/{bundleId}/approve",
        "POST /app-services/grant-bundles/{bundleId}/reject",
        "POST /app-services/grant-bundles/{bundleId}/renew",
        "POST /app-services/grants",
        "POST /app-services/grants/{grantId}/approve",
        "POST /app-services/grants/{grantId}/revoke",
        "GET /app-services/{providerAppId}/services",
        "GET /app-services/{providerAppId}/services/{serviceId}",
        "POST /app-services/{providerAppId}/services/{serviceId}/invoke",
    }
    stable_capabilities = set(details["stableCapabilities"])
    stable_endpoints = set(details["stableEndpoints"])
    contract_capabilities = set(capability_names(capabilities))
    contract_endpoints = set(endpoint_identities(endpoints))
    missing_app_data_capabilities = sorted(required_app_data_capabilities - stable_capabilities)
    missing_app_data_endpoints = sorted(required_app_data_endpoints - stable_endpoints)
    missing_trust_exchange_capabilities = sorted(
        required_trust_exchange_capabilities - contract_capabilities
    )
    missing_trust_exchange_endpoints = sorted(
        required_trust_exchange_endpoints - contract_endpoints
    )
    missing_social_message_capabilities = sorted(
        required_social_message_capabilities - contract_capabilities
    )
    missing_social_message_endpoints = sorted(
        required_social_message_endpoints - contract_endpoints
    )
    missing_app_service_capabilities = sorted(
        required_app_service_capabilities - contract_capabilities
    )
    missing_app_service_endpoints = sorted(required_app_service_endpoints - contract_endpoints)
    details["appDataContract"] = {
        "capabilities": sorted(required_app_data_capabilities),
        "endpoints": sorted(required_app_data_endpoints),
        "missingCapabilities": missing_app_data_capabilities,
        "missingEndpoints": missing_app_data_endpoints,
    }
    details["trustGraphExchangeContract"] = {
        "capabilities": sorted(required_trust_exchange_capabilities),
        "endpoints": sorted(required_trust_exchange_endpoints),
        "missingCapabilities": missing_trust_exchange_capabilities,
        "missingEndpoints": missing_trust_exchange_endpoints,
    }
    details["socialMessageContract"] = {
        "capabilities": sorted(required_social_message_capabilities),
        "endpoints": sorted(required_social_message_endpoints),
        "missingCapabilities": missing_social_message_capabilities,
        "missingEndpoints": missing_social_message_endpoints,
    }
    details["appServicesContract"] = {
        "capabilities": sorted(required_app_service_capabilities),
        "endpoints": sorted(required_app_service_endpoints),
        "missingCapabilities": missing_app_service_capabilities,
        "missingEndpoints": missing_app_service_endpoints,
    }
    if contract:
        if not isinstance(contract_version, int) or isinstance(contract_version, bool) or contract_version <= 0:
            errors.append("contractVersion must be a positive integer")
        if not isinstance(api_version, str) or not api_version.strip():
            errors.append("apiVersion must be a non-empty string")
        if contract_version != CURRENT_PLATFORM_API_CONTRACT_VERSION:
            errors.append(
                "contractVersion must be "
                f"{CURRENT_PLATFORM_API_CONTRACT_VERSION} for app-service dependency bundle support"
            )
    if not capabilities:
        errors.append("contract has no capability descriptors")
    if not endpoints:
        errors.append("contract has no endpoint descriptors")
    if missing_app_data_capabilities:
        errors.append("contract is missing app-data capability descriptors")
    if missing_app_data_endpoints:
        errors.append("contract is missing app-data endpoint descriptors")
    if missing_trust_exchange_capabilities:
        errors.append("contract is missing trust graph exchange capability descriptors")
    if missing_trust_exchange_endpoints:
        errors.append("contract is missing trust graph exchange endpoint descriptors")
    if missing_social_message_capabilities:
        errors.append("contract is missing social message capability descriptors")
    if missing_social_message_endpoints:
        errors.append("contract is missing social message endpoint descriptors")
    if missing_app_service_capabilities:
        errors.append("contract is missing app-service capability descriptors")
    if missing_app_service_endpoints:
        errors.append("contract is missing app-service endpoint descriptors")

    verifier_args = ["compat", "verify"]
    if settings.mode == "release-candidate":
        verifier_args.append("--strict")
    verifier_args.extend(["--contract", str(artifact)])
    verification: dict[str, Any] = {}
    for spec in first_party_app_specs(settings):
        staged_dir = spec["stagedDir"]
        if staged_dir.is_dir():
            result = run_cli(
                cli,
                [*verifier_args, "--bundle-dir", str(staged_dir)],
                settings,
                f"crypta-app-compat-{spec['appId']}",
            )
            verification[spec["appId"]] = command_details(result, settings)
            if result.exit_code != 0:
                errors.append(f"compat verify failed for {spec['appId']}")
        else:
            verification[spec["appId"]] = {"skipped": True, "reason": "staged app directory missing"}
    sample_dir = sample_paths.get("bundleDir")
    if sample_dir is not None and sample_dir.is_dir():
        result = run_cli(
            cli,
            [*verifier_args, "--bundle-dir", str(sample_dir)],
            settings,
            "crypta-app-compat-sample",
        )
        verification["cert-smoke"] = command_details(result, settings)
        if result.exit_code != 0:
            errors.append("compat verify failed for cert-smoke")
    details["verifier"] = verification

    if errors:
        return EvidenceItem(
            "platform-api.contract",
            root_consequence(settings, "fail"),
            True,
            "Platform API contract evidence found compatibility risks.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "platform-api.contract",
        "pass",
        True,
        "Platform API contract snapshot and offline compatibility checks passed.",
        source,
        details,
    )


def collect_app_services_evidence(settings: Settings) -> list[EvidenceItem]:
    source = summary_source(settings)
    workspace = settings.workspace_root
    api_dir = workspace / "platform-api/src/main/java/network/crypta/platform/api"
    appservices_dir = api_dir / "appservices"
    api_tests_dir = workspace / "platform-api/src/test/java/network/crypta/platform/api"
    appservices_tests_dir = api_tests_dir / "appservices"
    trust_manifest_path = workspace / "apps/trust-graph/src/staged/cryptad-app.properties.template"
    social_manifest_path = workspace / "apps/social-inbox/src/staged/cryptad-app.properties.template"
    if not trust_manifest_path.is_file():
        trust_manifest_path = (
            workspace / "apps/trust-graph/build/cryptad-app/trust-graph/cryptad-app.properties"
        )
    if not social_manifest_path.is_file():
        social_manifest_path = (
            workspace / "apps/social-inbox/build/cryptad-app/social-inbox/cryptad-app.properties"
        )
    try:
        trust_manifest = parse_properties(trust_manifest_path) if trust_manifest_path.is_file() else {}
    except ValueError:
        trust_manifest = {}
    try:
        social_manifest = parse_properties(social_manifest_path) if social_manifest_path.is_file() else {}
    except ValueError:
        social_manifest = {}
    social_permissions = parse_permission_set(social_manifest.get("app.permissions", ""))
    contract_text = read_source(api_dir / "PlatformApiContract.java")
    capabilities_text = read_source(api_dir / "PlatformApiCapabilities.java")
    router_text = read_source(api_dir / "PlatformApiRouter.java")
    route_text = read_source(api_dir / "PlatformApiAppServiceRoutes.java")
    shared_services_text = read_source(api_dir / "PlatformApiSharedAppServices.java")
    runtime_text = read_source(
        workspace
        / "bridge-http-runtime/src/main/java/network/crypta/clients/http/bridge/CoreHttpShellRuntimeSupport.java"
    )
    coordinator_text = read_source(appservices_dir / "AppServiceCoordinator.java")
    parser_text = read_source(appservices_dir / "AppServiceManifestParser.java")
    descriptor_text = read_source(appservices_dir / "AppServiceDescriptor.java")
    request_descriptor_text = read_source(appservices_dir / "AppServiceRequestDescriptor.java")
    grant_text = read_source(appservices_dir / "AppServiceGrant.java")
    status_text = read_source(appservices_dir / "AppServiceGrantStatus.java")
    audit_text = read_source(appservices_dir / "AppServiceAuditEvent.java")
    audit_text_normalized = re.sub(r"\s+", " ", re.sub(r"(?m)^\s*\*\s?", " ", audit_text))
    store_text = "\n".join(
        read_source(appservices_dir / name)
        for name in (
            "AppServiceGrantStore.java",
            "FileAppServiceGrantStore.java",
            "InMemoryAppServiceGrantStore.java",
        )
    )
    appservices_model_text = "\n".join(
        read_source(path) for path in sorted(appservices_dir.glob("*.java"))
    )
    adapter_text = read_source(appservices_dir / "TrustGraphScoreAppServiceAdapter.java")
    tests_text = "\n".join(
        read_source(path)
        for path in (
            appservices_tests_dir / "AppServiceManifestParserTest.java",
            appservices_tests_dir / "AppServiceGrantStoreTest.java",
            appservices_tests_dir / "AppServiceCoordinatorTest.java",
            appservices_tests_dir / "TrustGraphScoreAppServiceAdapterTest.java",
            api_tests_dir / "PlatformApiAppServicesRouterTest.java",
        )
    )
    sdk_text = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    shell_text = read_source(
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    social_app_js = read_source(workspace / "apps/social-inbox/src/staged/static/app.js")
    social_index = read_source(workspace / "apps/social-inbox/src/staged/static/index.html")
    trust_index = read_source(workspace / "apps/trust-graph/src/staged/static/index.html")
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/app-service-discovery-and-grants.md",
            "docs/platform-api-contract.md",
            "docs/platform-sdk-js.md",
            "docs/social-inbox-reference-app.md",
            "docs/trust-graph-preview.md",
            "docs/release-certification.md",
            "tools/release-certification/README.md",
        )
    )

    def item(
        evidence_id: str,
        pass_summary: str,
        fail_summary: str,
        checks: dict[str, bool],
        details: dict[str, Any] | None = None,
    ) -> EvidenceItem:
        errors = [name for name, passed in checks.items() if passed is not True]
        payload: dict[str, Any] = {
            "checks": checks,
            "sources": {
                "contract": display_path(api_dir / "PlatformApiContract.java", workspace),
                "routes": display_path(api_dir / "PlatformApiAppServiceRoutes.java", workspace),
                "coordinator": display_path(appservices_dir / "AppServiceCoordinator.java", workspace),
                "socialManifest": display_path(social_manifest_path, workspace),
                "trustManifest": display_path(trust_manifest_path, workspace),
            },
        }
        if details:
            payload.update(details)
        if errors:
            return EvidenceItem(
                evidence_id,
                root_consequence(settings, "fail"),
                True,
                fail_summary,
                source,
                {"errors": errors, **payload},
            )
        return EvidenceItem(evidence_id, "pass", True, pass_summary, source, payload)

    registry_checks = {
        "contractV12AndCapabilitiesPresent": (
            "CURRENT_CONTRACT_VERSION = 16" in contract_text
            and "APP_SERVICES_CONTRACT_VERSION = 12" in contract_text
            and "APP_SERVICE_DEPENDENCY_BUNDLES_CONTRACT_VERSION = 16" in contract_text
            and "APP_SERVICES_READ" in capabilities_text
            and "APP_SERVICES_CALL" in capabilities_text
            and "app.services.read" in capabilities_text
            and "app.services.call" in capabilities_text
        ),
        "routeFamilyPresent": (
            "PlatformApiAppServiceRoutes" in router_text
            and 'case "app-services"' in router_text
            and "Routes local app-service discovery" in route_text
            and "service.listServices()" in route_text
        ),
        "descriptorParserPresent": (
            "record AppServiceDescriptor" in descriptor_text
            and "record AppServiceRequestDescriptor" in request_descriptor_text
            and "app.services.provides" in parser_text
            and "app.service-request." in parser_text
        ),
        "runtimeWiresSharedCoordinator": (
            "AppServiceCoordinator appServiceCoordinator" in shared_services_text
            and "new AppServiceCoordinator" in runtime_text
            and 'resolve("app-services")' in runtime_text
            and "TrustGraphScoreAppServiceAdapter" in runtime_text
        ),
        "sdkHelpersPresent": (
            "services: Object.freeze" in sdk_text
            and "listAppServices" in sdk_text
            and "requestAppServiceGrant" in sdk_text
            and "requestAppServiceBundle" in sdk_text
            and "listAppServiceDependencies" in sdk_text
            and "invokeAppService" in sdk_text
        ),
        "testsCoverManifestAndRouter": (
            "AppServiceManifestParserTest" in tests_text
            and "PlatformApiAppServicesRouterTest" in tests_text
        ),
    }
    grants_checks = {
        "grantModelHasRequiredFields": all(
            fragment in grant_text
            for fragment in (
                "grantId",
                "consumerAppId",
                "providerAppId",
                "serviceId",
                "scopes",
                "contexts",
                "purpose",
                "approvedAt",
                "revokedAt",
                "lastUsedAt",
                "useCount",
                "tokenFingerprint",
                "bundleId",
                "expiresAt",
                "compatibilityFingerprint",
                "providerServiceVersionAtApproval",
            )
        ),
        "grantStatusesPresent": all(
            status in status_text
            for status in (
                "PENDING",
                "ACTIVE",
                "REVOKED",
                "INACTIVE",
                "EXPIRED",
                "REVALIDATION_REQUIRED",
            )
        ),
        "storesAreFileBackedAndInMemory": (
            "class FileAppServiceGrantStore" in store_text
            and "class InMemoryAppServiceGrantStore" in store_text
            and "ATOMIC_MOVE" in store_text
            and '"grants"' in store_text
            and '"bundles"' in store_text
            and '"audit"' in store_text
        ),
        "coordinatorEnforcesApprovalRevocation": (
            "requestGrant" in coordinator_text
            and "approveGrant" in coordinator_text
            and "revokeGrant" in coordinator_text
            and "App principals cannot approve app-service grants." in coordinator_text
            and "active app-service grant" in coordinator_text
        ),
        "testsCoverGrantLifecycle": all(
            fragment in tests_text
            for fragment in (
                "grantLifecycle_whenApprovedThenRevoked_expectInvocationBoundary",
                "invoke_whenConsumerManifestDropsCallPermission_expectDenied",
                "requestGrant_whenProviderNotInstalled_expectProviderMissing",
                "fileStore_whenGrantsReload_expectDeterministicOrderingAndRedactedJson",
                "fileStore_whenBundleAndGrantLifecycleFieldsReload_expectDeterministicRecords",
                "fileStore_whenAuditEventsReload_expectNewestFirstAndRedactedSubjectHash",
            )
        ),
    }
    dependency_checks = {
        "dependencyModelsPresent": all(
            fragment in appservices_model_text
            for fragment in (
                "record AppServiceDependencyDescriptor",
                "enum AppServiceDependencyKind",
                "enum AppServiceDegradeBehavior",
                "record AppServiceVersionRange",
            )
        ),
        "dependencyParserStrictFieldsPresent": (
            'dependencyPrefix + "minServiceVersion"' in parser_text
            and 'dependencyPrefix + "maxServiceVersion"' in parser_text
            and 'dependencyPrefix + "grantExpiresAfter"' in parser_text
            and "duplicate alias" in parser_text
            and "Field value must not contain local filesystem paths" in parser_text
        ),
        "dependencyRoutesPresent": (
            '"/app-services/dependencies"' in contract_text
            and "service.dependencyGraph" in route_text
            and "dependencyGraph(" in coordinator_text
        ),
        "dependencyTestsPresent": all(
            fragment in tests_text
            for fragment in (
                "parseServiceRequests_whenOptionalDependencyFieldsPresent_expectDependencyDescriptor",
                "parseServiceRequests_whenRequiredDependencyFieldsPresent_expectRequiredDescriptor",
                "dependencyGraph_whenProviderAvailable_expectSocialInboxTrustGraphEdge",
                "dependencyGraph_whenAppReadsOtherConsumer_expectForbidden",
            )
        ),
    }
    bundle_checks = {
        "bundleModelsAndStorePresent": all(
            fragment in appservices_model_text
            for fragment in (
                "record AppServiceGrantBundle",
                "enum AppServiceGrantBundleStatus",
                "listBundles",
                "writeBundle",
            )
        ),
        "bundleRoutesPresent": (
            '"/app-services/grant-bundles"' in contract_text
            and "approveBundle" in route_text
            and "rejectBundle" in route_text
            and "renewBundle" in route_text
        ),
        "bundleCoordinatorHostOnly": (
            "App principals cannot approve app-service grant bundles." in coordinator_text
            and "App principals cannot reject app-service grant bundles." in coordinator_text
            and "App principals cannot renew app-service grant bundles." in coordinator_text
        ),
        "bundleTestsPresent": all(
            fragment in tests_text
            for fragment in (
                "grantBundleLifecycle_whenApprovedExpiredAndRenewed_expectInvocationBoundary",
                "approveBundle_whenRejected_expectNoActiveGrantCreated",
                "route_whenAppUsesDependencyAndBundleRoutes_expectScopedReviewFlow",
            )
        ),
    }
    expiry_checks = {
        "grantExpiryFieldsPresent": (
            "expiresAt" in grant_text
            and "renewedAt" in grant_text
            and "isExpired" in coordinator_text
            and "MAX_BUNDLE_GRANT_DURATION" in coordinator_text
        ),
        "expiredGrantsFailClosed": (
            "effectiveStatus(grant) == AppServiceGrantStatus.ACTIVE" in coordinator_text
            and "AppServiceGrantStatus.EXPIRED" in coordinator_text
            and "grantBundleLifecycle_whenApprovedExpiredAndRenewed_expectInvocationBoundary"
            in tests_text
        ),
        "renewalRevalidates": (
            "renewBundle" in coordinator_text
            and "approveOrRenewBundle" in coordinator_text
            and "ensureDescriptorSupported" in coordinator_text
            and "descriptor.compatibilityFingerprint()" in coordinator_text
        ),
    }
    revalidation_checks = {
        "compatibilityFingerprintPresent": (
            "compatibilityFingerprint" in descriptor_text
            and "providerServiceVersionAtApproval" in grant_text
            and "approvalMetadataStillMatches" in coordinator_text
        ),
        "descriptorDriftNonAuthorizing": (
            "REVALIDATION_REQUIRED" in status_text
            and "revalidation-required" in status_text
            and "invoke_whenProviderDescriptorDriftsAfterBundleApproval_expectRevalidationRequired"
            in tests_text
        ),
        "descriptorMatchingChecksVersionScopeContextKindAdapter": (
            "satisfiesVersionRange" in descriptor_text
            and "hasUnsupportedScopes" in descriptor_text
            and "supportsContext" in descriptor_text
            and "SUPPORTED_SERVICE_KIND" in coordinator_text
            and "adapters.containsKey" in coordinator_text
        ),
    }
    provider_checks = {
        "trustGraphManifestAdvertisesService": (
            trust_manifest.get("app.services.provides") == "trust-score"
            and trust_manifest.get("app.service.trust-score.id") == "trust.score"
            and trust_manifest.get("app.service.trust-score.kind") == "platform-adapter"
            and trust_manifest.get("app.service.trust-score.adapter") == "trust-graph.score"
            and "score.read" in parse_permission_set(
                trust_manifest.get("app.service.trust-score.scopes", "")
            )
        ),
        "adapterIsBoundedNotProxy": (
            'ADAPTER_ID = "trust-graph.score"' in adapter_text
            and "trustGraphApiHandler.score" in adapter_text
            and "not a proxy" in adapter_text
            and "subjectUriHash" in adapter_text
            and 'json.put("subjectUri",' not in adapter_text
        ),
        "providerDocsAndUiDescribePreviewGrantBoundary": (
            "Trust Score Service" in trust_index
            and "operator-approved app-service grants" in trust_index
            and "trust.score" in docs_text
            and "not complete WoT" in docs_text
        ),
        "adapterTestsCoverRedaction": (
            "TrustGraphScoreAppServiceAdapterTest" in tests_text
            and "invoke_whenScoreRequested_expectRedactedScoreSummary" in tests_text
            and "subjectUriHash" in tests_text
        ),
    }
    social_checks = {
        "socialManifestRequestsServiceGrant": (
            social_manifest.get("app.services.requests") == "trust-score"
            and social_manifest.get("app.service-request.trust-score.provider") == "trust-graph"
            and social_manifest.get("app.service-request.trust-score.service") == "trust.score"
            and social_manifest.get("app.service-request.trust-score.scopes") == "score.read"
            and social_manifest.get("app.service-request.trust-score.contexts") == "message-author"
        ),
        "socialManifestUsesAppServiceCapabilities": (
            {"app.services.read", "app.services.call"}.issubset(social_permissions)
            and "trust.read" not in social_permissions
            and social_manifest.get("api.minimumVersion") == "16"
            and social_manifest.get("api.maximumTestedVersion")
            == str(CURRENT_PLATFORM_API_CONTRACT_VERSION)
        ),
        "socialUsesSdkServicesNamespace": (
            "CryptaPlatform.services.get" in social_app_js
            and "CryptaPlatform.services.grants.list" in social_app_js
            and "CryptaPlatform.services.bundles.request" in social_app_js
            and "CryptaPlatform.services.invoke" in social_app_js
            and "CryptaPlatform.trust.score" not in social_app_js
        ),
        "socialUiShowsGrantStates": (
            "Request trust grant" in social_index
            and "trust-service-status" in social_index
            and "Trust score unavailable / grant required" in social_app_js
            and "Trust score unavailable / grant expired." in social_app_js
            and "Trust score unavailable / grant requires operator revalidation." in social_app_js
        ),
        "socialDocsDescribeRevocation": (
            "Trust Score Service grant" in docs_text
            and "revoked" in docs_text
            and "must not fall back to\n`CryptaPlatform.trust.score`" in docs_text
        ),
    }
    web_shell_checks = {
        "webShellLoadsAppServiceData": (
            'apiUrl("app-services")' in shell_text
            and 'apiUrl("app-services/grants")' in shell_text
            and 'apiUrl("app-services/dependencies")' in shell_text
            and 'apiUrl("app-services/grant-bundles")' in shell_text
            and 'apiUrl("app-services/audit?limit=12")' in shell_text
        ),
        "webShellRendersGrantActions": (
            "App-service grants" in shell_text
            and "Approve" in shell_text
            and "Revoke" in shell_text
            and "Renew bundle" in shell_text
            and "renderAppServiceDependencyGraph" in shell_text
            and "renderAppServiceBundleCard" in shell_text
            and "appServiceGrantPath" in shell_text
        ),
        "webShellOmitsPrivateMaterial": (
            "tokenFingerprint" not in shell_text
            and "CRYPTAD_APP_TOKEN" not in shell_text
            and "privateInsertUri" not in shell_text
        ),
        "webShellTestsPresent": "App-service grants" in read_source(
            workspace
            / "platform-web-shell/src/test/java/network/crypta/platform/webshell/WebShellResourcesTest.java"
        ),
    }
    redaction_checks = {
        "auditModelIsRedacted": (
            "subjectUriHash" in audit_text
            and "raw subject URIs" in audit_text_normalized
            and "raw tokens" in audit_text_normalized
            and "local paths" in audit_text_normalized
        ),
        "invocationReturnsHashNotRawSubject": (
            "subjectUriHash" in adapter_text
            and 'json.put("subjectUri",' not in adapter_text
            and "completeWot" in adapter_text
        ),
        "grantJsonContainsOnlyFingerprint": (
            "tokenFingerprint" in grant_text
            and "PR-243 does not issue raw service tokens" in grant_text
            and "rawToken" not in grant_text
        ),
        "docsStateNoGenericProxyOrLocalhostTrust": (
            "not a localhost proxy" in docs_text
            and "not generic RPC" in docs_text
            and "raw service tokens" in docs_text
            and "ambient access" in docs_text
            and "raw request bodies" in docs_text
        ),
        "evidenceIdsDocumented": all(
            evidence_id in docs_text
            for evidence_id in (
                "app-services.registry",
                "app-services.grants",
                "app-services.trust-score-provider",
                "reference-app.social-inbox-service-grant",
                "app-services.web-shell",
                "app-services.redaction",
                "app-services.dependency-graph",
                "app-services.grant-bundles",
                "app-services.grant-expiry-renewal",
                "app-services.provider-revalidation",
                "reference-app.social-inbox-service-dependency",
                "app-services.dependency-redaction",
            )
        ),
    }
    social_dependency_checks = {
        "socialManifestDeclaresOptionalDependency": (
            social_manifest.get("app.service-request.trust-score.dependency.kind") == "optional"
            and social_manifest.get("app.service-request.trust-score.dependency.required") == "false"
            and social_manifest.get("app.service-request.trust-score.dependency.featureId")
            == "trust-score-annotations"
            and social_manifest.get("app.service-request.trust-score.dependency.grantBundle")
            == "trust-annotations"
        ),
        "socialDegradesSafely": (
            "markTrustScoresUnavailable" in social_app_js
            and "Trust score unavailable / grant expired." in social_app_js
            and "Trust score unavailable / grant requires operator revalidation." in social_app_js
            and "CryptaPlatform.trust.score" not in social_app_js
        ),
        "socialDependencyDocsPresent": (
            "Trust score annotations" in docs_text
            and "trust-annotations" in docs_text
            and "optional" in docs_text
        ),
    }
    bundle_source = read_source(appservices_dir / "AppServiceGrantBundle.java")
    dependency_redaction_checks = {
        "dependencyJsonPathFreeByConstruction": (
            "dependencyJson" in coordinator_text
            and "providerServiceVersion" in coordinator_text
            and "subjectUri" not in request_descriptor_text
            and "request bodies" in appservices_model_text
        ),
        "bundlePublicJsonFieldsSafe": (
            "AppServiceGrantBundle" in appservices_model_text
            and app_service_bundle_public_fields_are_safe(bundle_source)
        ),
        "uiAndEvidenceAvoidRawSensitiveValues": (
            "subjectUriHash" in shell_text
            and '"subjectUri"' not in shell_text
            and "subjectUri:" not in shell_text
            and "privateInsertUri" not in shell_text
            and "CRYPTAD_APP_TOKEN" not in shell_text
        ),
    }
    return [
        item(
            "app-services.registry",
            "App-service registry and descriptor evidence passed deterministic checks.",
            "App-service registry evidence is incomplete.",
            registry_checks,
        ),
        item(
            "app-services.grants",
            "App-service grant lifecycle evidence passed deterministic checks.",
            "App-service grant lifecycle evidence is incomplete.",
            grants_checks,
        ),
        item(
            "app-services.dependency-graph",
            "App-service dependency graph evidence passed deterministic checks.",
            "App-service dependency graph evidence is incomplete.",
            dependency_checks,
        ),
        item(
            "app-services.grant-bundles",
            "App-service grant-bundle evidence passed deterministic checks.",
            "App-service grant-bundle evidence is incomplete.",
            bundle_checks,
        ),
        item(
            "app-services.grant-expiry-renewal",
            "App-service grant expiry and renewal evidence passed deterministic checks.",
            "App-service grant expiry and renewal evidence is incomplete.",
            expiry_checks,
        ),
        item(
            "app-services.provider-revalidation",
            "App-service provider descriptor revalidation evidence passed deterministic checks.",
            "App-service provider descriptor revalidation evidence is incomplete.",
            revalidation_checks,
        ),
        item(
            "app-services.trust-score-provider",
            "Trust Graph trust.score provider evidence passed deterministic checks.",
            "Trust Graph trust.score provider evidence is incomplete.",
            provider_checks,
        ),
        item(
            "reference-app.social-inbox-service-grant",
            "Social Inbox app-service grant evidence passed deterministic checks.",
            "Social Inbox app-service grant evidence is incomplete.",
            social_checks,
        ),
        item(
            "reference-app.social-inbox-service-dependency",
            "Social Inbox service dependency evidence passed deterministic checks.",
            "Social Inbox service dependency evidence is incomplete.",
            social_dependency_checks,
        ),
        item(
            "app-services.web-shell",
            "Web Shell app-service grant UI evidence passed deterministic checks.",
            "Web Shell app-service grant UI evidence is incomplete.",
            web_shell_checks,
        ),
        item(
            "app-services.redaction",
            "App-service redaction and boundary evidence passed deterministic checks.",
            "App-service redaction and boundary evidence is incomplete.",
            redaction_checks,
            {
                "redaction": {
                    "rawTokensExcluded": True,
                    "rawSubjectUrisExcluded": True,
                    "privateInsertUrisExcluded": True,
                    "absolutePathsExcluded": True,
                    "genericProxyExcluded": True,
                }
            },
        ),
        item(
            "app-services.dependency-redaction",
            "App-service dependency and bundle redaction evidence passed deterministic checks.",
            "App-service dependency and bundle redaction evidence is incomplete.",
            dependency_redaction_checks,
        ),
    ]


def collect_signed_bundle_evidence(settings: Settings, sample_paths: dict[str, Path]) -> EvidenceItem:
    inputs = signing_inputs(os.environ)
    details: dict[str, Any] = {
        "keyIdPresent": bool(inputs["keyId"]),
        "privateKeyPresent": inputs["hasPrivate"],
        "publicKeyPresent": inputs["hasPublic"],
        "privateKeySource": "file" if inputs["privateFile"] else ("environment" if inputs["privateBase64"] else "missing"),
        "publicKeySource": "file" if inputs["publicFile"] else ("environment" if inputs["publicBase64"] else "missing"),
    }
    source = summary_source(settings)
    if not inputs["complete"]:
        status = "fail" if settings.mode == "release-candidate" else "skip"
        return EvidenceItem(
            "app-platform.signed-bundles",
            status,
            True,
            "Signing key inputs are not complete; signed bundle verification was not run.",
            source,
            details,
        )
    gradle_result = gradle_command(settings, ["signFirstPartyApps", "verifyFirstPartyApps"], "gradle-sign-verify-first-party-apps")
    details["firstPartySignVerifyCommand"] = command_details(gradle_result, settings)
    failures: list[str] = []
    if gradle_result is None:
        details["firstPartySignVerifyRan"] = False
        if settings.mode == "release-candidate":
            failures.append("first-party sign/verify Gradle task was skipped")
    elif gradle_result.exit_code != 0:
        details["firstPartySignVerifyRan"] = True
        failures.append("first-party sign/verify Gradle task failed")
    else:
        details["firstPartySignVerifyRan"] = True
    cli = sample_paths.get("cli")
    sample_dir = sample_paths.get("bundleDir")
    if cli and sample_dir and sample_dir.is_dir():
        sign_result = run_cli(cli, sign_args(sample_dir, inputs), settings, "crypta-app-sign-sample")
        verify_result = run_cli(cli, verify_args(sample_dir, inputs), settings, "crypta-app-verify-sample")
        details["sampleSign"] = command_details(sign_result, settings)
        details["sampleVerify"] = command_details(verify_result, settings)
        if sign_result.exit_code != 0:
            failures.append("sample bundle sign failed")
        if verify_result.exit_code != 0:
            failures.append("sample bundle verify failed")
        sample_zip = sample_paths.get("zip")
        if sample_zip and sign_result.exit_code == 0 and verify_result.exit_code == 0:
            repack_result = run_cli(
                cli,
                ["pack", "--bundle-dir", str(sample_dir), "--output", str(sample_zip), "--overwrite"],
                settings,
                "crypta-app-pack-signed-sample",
            )
            details["sampleRepackAfterSigning"] = command_details(repack_result, settings)
            if repack_result.exit_code != 0:
                failures.append("signed sample bundle repack failed")
            elif sample_zip.is_file():
                details["signedSampleZipSha256"] = sha256_file(sample_zip)
                details["signedSampleZipSizeBytes"] = sample_zip.stat().st_size
    else:
        failures.append("sample bundle was unavailable for signing")
    if failures:
        return EvidenceItem(
            "app-platform.signed-bundles",
            "fail",
            True,
            "Signed bundle smoke failed.",
            source,
            {"failures": failures, **details},
        )
    return EvidenceItem(
        "app-platform.signed-bundles",
        "pass",
        True,
        "First-party and sample bundle signing evidence passed.",
        source,
        details,
    )


def collect_catalog_evidence(settings: Settings, sample_paths: dict[str, Path]) -> EvidenceItem:
    source = summary_source(settings)
    cli = sample_paths.get("cli")
    sample_zip = sample_paths.get("zip")
    details: dict[str, Any] = {}
    if not cli or not sample_zip or not sample_zip.is_file():
        return EvidenceItem("catalog.smoke", root_consequence(settings, "missing"), True, "Sample ZIP or crypta-app CLI is unavailable for catalog smoke.", source, details)
    catalog_dir = sample_workspace(settings) / "catalog"
    catalog_dir.mkdir(parents=True, exist_ok=True)
    descriptor = catalog_dir / "entry.properties"
    catalog_file = catalog_dir / "cryptad-app-catalog.properties"
    signature_file = catalog_dir / "cryptad-app-catalog.signature"
    descriptor.write_text(
        "\n".join(
            [
                f"artifact.path={sample_zip.resolve()}",
                f"bundle.uri={sample_zip.resolve().as_uri()}",
                "summary=Certification smoke app.",
                "name=Certification Smoke",
                "permissions=queue.read",
                "app.id=cert-smoke",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    remove_existing_path(catalog_file)
    remove_existing_path(signature_file)
    create_result = run_cli(
        cli,
        [
            "catalog",
            "create",
            "--catalog-file",
            str(catalog_file),
            "--catalog-id",
            "cert-smoke",
            "--name",
            "Certification Smoke Apps",
            "--generated-at",
            "2026-05-01T00:00:00Z",
            "--entry",
            str(descriptor),
            "--overwrite",
        ],
        settings,
        "crypta-app-catalog-create",
    )
    details["create"] = command_details(create_result, settings)
    if create_result.exit_code != 0:
        return EvidenceItem("catalog.smoke", root_consequence(settings, "fail"), True, "Catalog creation failed.", source, details)
    catalog_exists = catalog_file.is_file()
    details["catalogExists"] = catalog_exists
    if not catalog_exists:
        return EvidenceItem(
            "catalog.smoke",
            root_consequence(settings, "fail"),
            True,
            "Catalog creation did not produce catalog output.",
            source,
            details,
        )
    catalog = parse_properties(catalog_file)
    details["catalog"] = {
        "catalogId": catalog.get("catalog.id"),
        "catalogVersion": catalog.get("catalog.version"),
        "entries": catalog.get("catalog.entries"),
        "appId": catalog.get("app.cert-smoke.id"),
        "bundleSha256": catalog.get("app.cert-smoke.bundle.sha256"),
        "bundleSizeBytes": catalog.get("app.cert-smoke.bundle.size.bytes"),
        "catalogSha256": sha256_file(catalog_file),
    }
    inputs = signing_inputs(os.environ)
    details["signingInputs"] = {
        "keyIdPresent": bool(inputs["keyId"]),
        "privateKeyPresent": inputs["hasPrivate"],
        "publicKeyPresent": inputs["hasPublic"],
    }
    if not inputs["complete"]:
        status = "fail" if settings.mode == "release-candidate" else "warn"
        return EvidenceItem(
            "catalog.smoke",
            status,
            True,
            "Catalog creation passed, but signing key inputs are incomplete.",
            source,
            details,
        )
    sign_result = run_cli(cli, catalog_sign_args(catalog_file, inputs), settings, "crypta-app-catalog-sign")
    verify_result = run_cli(cli, catalog_verify_args(catalog_file, inputs), settings, "crypta-app-catalog-verify")
    details["sign"] = command_details(sign_result, settings)
    details["verify"] = command_details(verify_result, settings)
    if sign_result.exit_code != 0 or verify_result.exit_code != 0:
        return EvidenceItem("catalog.smoke", "fail", True, "Signed catalog smoke failed.", source, details)
    return EvidenceItem("catalog.smoke", "pass", True, "Catalog create, sign, and verify smoke passed.", source, details)


def collect_live_usk_catalog_publication_evidence(
    settings: Settings, sample_paths: dict[str, Path]
) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    devtools_dir = workspace / "platform-devtools/src/main/java/network/crypta/platform/devtools"
    test_dir = workspace / "platform-devtools/src/test/java/network/crypta/platform/devtools"
    cli_text = read_source(devtools_dir / "CryptaAppCli.java")
    service_text = read_source(devtools_dir / "LiveUskPublicationService.java")
    publisher_text = read_source(devtools_dir / "PlatformApiLiveUskPublisher.java")
    result_text = read_source(devtools_dir / "LiveUskPublicationResult.java")
    writer_text = read_source(devtools_dir / "LiveUskPublicationResultWriter.java")
    validator_text = read_source(devtools_dir / "PublicationInputValidator.java")
    tests_text = "\n".join(
        read_source(path)
        for path in (
            test_dir / "DeveloperBetaToolkitCliTest.java",
            test_dir / "LiveUskPublicationServiceTest.java",
            test_dir / "PublicationPlanWriterTest.java",
        )
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/developer-beta-toolkit.md",
            "docs/app-platform-beta-tutorials.md",
            "docs/first-party-beta-catalog.md",
            "docs/app-catalogs.md",
            "docs/release-certification.md",
            "docs/cryptad-release-workflow-and-runbook.md",
        )
    )
    checks = {
        "explicitLiveMode": (
            '"--live"' in cli_text
            and '"--dry-run"' in cli_text
            and "requires exactly one of --dry-run or --live" in cli_text
        ),
        "secureLiveInputs": (
            "--private-insert-uri-env" in cli_text
            and "--private-insert-uri-file" in cli_text
            and "--form-password-env" in cli_text
            and "--form-password-file" in cli_text
            and "loadSecureText" in cli_text
        ),
        "localVerificationBeforeInsert": (
            "PublicationInputValidator.validate" in service_text
            and "AppCatalogVerifier.verify" in service_text
            and "requirePrivateInsertUri" in service_text
        ),
        "realQueueInsertionPath": (
            "queue/inserts/directory" in publisher_text
            and "sourcePath" in publisher_text
            and "insertUri" in publisher_text
            and "COMPAT_CURRENT" in publisher_text
            and "followRedirects(HttpClient.Redirect.NEVER)" in publisher_text
        ),
        "optionalLiveFetchVerification": (
            "content/fetch" in publisher_text
            and "contentBase64" in publisher_text
            and "live_publish_verification_failed" in publisher_text
        ),
        "sanitizedResultModel": (
            "catalogSha256" in result_text
            and "signatureSha256" in result_text
            and "catalogSigningKeyId" in result_text
            and "catalogInsertStatus" in result_text
            and "schedulerRefreshVerificationStatus" in result_text
            and "privateInsertUri" not in writer_text
            and "formPassword" not in writer_text
            and "stagingDirectory" not in writer_text
        ),
        "sharedInputValidation": (
            "crypta:USK@.../" in validator_text
            and "cryptad-app-catalog.properties" in validator_text
            and "cryptad-app-catalog.signature" in validator_text
        ),
        "testsCoverLiveAndRedaction": (
            "publish_whenFakePublisherSucceeds_expectSanitizedSummaryAndRetainedStaging"
            in tests_text
            and "publish_whenInsertIsOnlyQueued_expectStagingRetainedWithoutPathInSummary"
            in tests_text
            and "publish_whenPrivateInsertUriDoesNotMatchPublicSource_expectFailureWithoutPublisherOrSummary"
            in tests_text
            and "private insert URI must be configured by exactly one env or file source"
            in tests_text
            and "staging_sidecars_retained_until_live_insert_completion" in tests_text
            and "assertFalse(liveSummaryText.contains(LIVE_PRIVATE_INSERT_URI))" in tests_text
        ),
        "docsCoverLivePublication": (
            "crypta-app publish-usk --live" in docs_text
            and "private insert URI" in docs_text
            and "cryptad-app-catalog.signature" in docs_text
            and "same USK" in docs_text
            and "dry-run" in docs_text.lower()
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "liveNodeRequired": False,
        "actualLiveInsertionOptional": True,
        "publicSourceShape": "crypta:USK@.../cryptad-app-catalog.properties",
        "signatureSidecar": "cryptad-app-catalog.signature",
        "checks": checks,
        "sources": {
            "cli": display_path(devtools_dir / "CryptaAppCli.java", workspace),
            "service": display_path(devtools_dir / "LiveUskPublicationService.java", workspace),
            "publisher": display_path(devtools_dir / "PlatformApiLiveUskPublisher.java", workspace),
            "result": display_path(devtools_dir / "LiveUskPublicationResult.java", workspace),
            "writer": display_path(devtools_dir / "LiveUskPublicationResultWriter.java", workspace),
            "validator": display_path(devtools_dir / "PublicationInputValidator.java", workspace),
            "tests": display_path(test_dir / "LiveUskPublicationServiceTest.java", workspace),
        },
    }
    if errors:
        return EvidenceItem(
            "catalog.live-usk-publication",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Live USK catalog publication evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "catalog.live-usk-publication",
        "pass",
        True,
        "Live USK catalog publication source and redaction evidence passed.",
        source,
        details,
    )


def collect_live_usk_source_verification_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    appcatalog_dir = workspace / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    appcatalog_tests = workspace / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog"
    api_tests = workspace / "platform-api/src/test/java/network/crypta/platform/api/appcatalogs"
    source_text = read_source(appcatalog_dir / "AppCatalogSource.java")
    uri_text = read_source(appcatalog_dir / "CryptaCatalogUri.java")
    fetcher_text = read_source(appcatalog_dir / "AppCatalogFetcher.java")
    manager_text = read_source(appcatalog_dir / "AppCatalogManager.java")
    recommended_text = read_source(appcatalog_dir / "RecommendedAppCatalogs.java")
    appcatalog_test_text = read_source(appcatalog_tests / "AppCatalogManagerTest.java")
    api_test_text = read_source(api_tests / "AppCatalogsApiHandlerTest.java")
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/app-catalogs.md",
            "docs/first-party-beta-catalog.md",
            "docs/app-update-lifecycle.md",
        )
    )
    checks = {
        "cryptaUskSourceAccepted": (
            "CryptaCatalogUri.parse" in source_text
            and "crypta:USK@" in uri_text
            and "SIGNATURE_QUERY_PREFIX" in uri_text
        ),
        "resolvedEditionSignatureSidecar": (
            "signatureFetchKeyForResolvedCatalog" in uri_text
            and "normalizeResolvedCatalogFetchKey" in uri_text
            and "requireCompatibleResolvedKeyKind" in uri_text
            and "siblingSignatureKey(resolvedKey)" in uri_text
        ),
        "boundedContentFetch": (
            "ContentFetchPort" in fetcher_text
            and "signatureFetchKeyForResolvedCatalog(catalogBytes.resolvedUri())" in fetcher_text
            and "MAX_CATALOG_BYTES" in fetcher_text
            and "MAX_SIGNATURE_BYTES" in fetcher_text
        ),
        "verifyBeforeStorage": (
            "AppCatalogVerifier.verify" in manager_text
            and "sourceStore.write(catalog, source, fetched" in manager_text
            and "CATALOG_ID_MISMATCH" in manager_text
        ),
        "refreshPreservesPreviousOnFailure": (
            "recordRefreshFailure" in manager_text
            and "previous stored sidecars remain in place" in manager_text
        ),
        "firstPartySourceConfigDriven": (
            "CRYPTAD_FIRST_PARTY_CATALOG_SOURCE" in recommended_text
            and "CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_CATALOG_KEY_ID" in recommended_text
        ),
        "testsCoverResolvedEdition": (
            "fetch_whenCryptaCatalogResolvesToUskEdition_expectSignatureFetchedFromResolvedEdition"
            in appcatalog_test_text
            and "fetch_whenCryptaResolvedCatalogHasSchemePrefix_expectSignatureFetchedFromResolvedEdition"
            in appcatalog_test_text
            and "fetch_whenCryptaResolvedCatalogChangesKeyKind_expectInvalidCatalogSource"
            in appcatalog_test_text
            and "fetch_whenCryptaSourceUsesContentFetchPort_expectBoundedRequests"
            in appcatalog_test_text
        ),
        "testsCoverRefreshPreservation": (
            "refresh_whenCryptaFetchFails_expectPreviousVerifiedCatalogPreservedAndMetadataUpdated"
            in appcatalog_test_text
            and "refresh_whenCryptaVerificationFailsAfterResolvedFetch_expectMetadataUsesResolvedUri"
            in appcatalog_test_text
        ),
        "recommendedSummariesRedactSources": (
            "listRecommendedCatalogs_whenConfiguredAndTrusted_expectCanAddAndRedactedSource"
            in api_test_text
            and "listRecommendedCatalogs_whenHttpsSourceHasQuery_expectQueryRedacted"
            in api_test_text
            and "listRecommendedCatalogs_whenFileSourceConfigured_expectPathRedacted"
            in api_test_text
        ),
        "docsCoverUskVerification": (
            "crypta:USK@" in docs_text
            and "same USK" in docs_text
            and "signed catalog verification" in docs_text.lower()
            and "cryptad-app-catalog.signature" in docs_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "liveNodeRequired": False,
        "checks": checks,
        "sources": {
            "sourceModel": display_path(appcatalog_dir / "AppCatalogSource.java", workspace),
            "cryptaUri": display_path(appcatalog_dir / "CryptaCatalogUri.java", workspace),
            "fetcher": display_path(appcatalog_dir / "AppCatalogFetcher.java", workspace),
            "manager": display_path(appcatalog_dir / "AppCatalogManager.java", workspace),
            "tests": display_path(appcatalog_tests / "AppCatalogManagerTest.java", workspace),
        },
    }
    if errors:
        return EvidenceItem(
            "catalog.live-usk-source-verification",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Live USK source verification evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "catalog.live-usk-source-verification",
        "pass",
        True,
        "Live USK source verification evidence passed deterministic checks.",
        source,
        details,
    )


def collect_first_party_beta_catalog_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    appcatalog_dir = workspace / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    appcatalog_tests = workspace / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog"
    model_text = read_source(appcatalog_dir / "RecommendedAppCatalog.java")
    provider_text = read_source(appcatalog_dir / "RecommendedAppCatalogs.java")
    downloader_text = read_source(appcatalog_dir / "AppCatalogArtifactDownloader.java")
    manager_text = read_source(appcatalog_dir / "AppCatalogManager.java")
    appcatalog_test_text = "\n".join(
        read_source(path)
        for path in (
            appcatalog_tests / "AppCatalogManagerTest.java",
            appcatalog_tests / "AppCatalogParserTest.java",
            appcatalog_tests / "AppCatalogEntryDescriptorTest.java",
            appcatalog_tests / "RecommendedAppCatalogsTest.java",
        )
    )
    api_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    )
    api_routes_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiAppRoutes.java"
    )
    api_contract_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    shell_text = read_source(
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/app-catalogs.md",
            "docs/app-dev-cli.md",
            "docs/first-party-beta-catalog.md",
            "docs/release-certification.md",
        )
    )
    app_ids = list(APP_IDS)
    checks = {
        "recommendedDescriptorPresent": (
            "public record RecommendedAppCatalog" in model_text
            and "trustedCatalogKeyId" in model_text
            and "AppCatalogSource.parse" in model_text
        ),
        "firstPartyProviderPresent": (
            "FIRST_PARTY_BETA_CATALOG_ID" in provider_text
            and "crypta-first-party-beta" in provider_text
            and "CRYPTAD_FIRST_PARTY_CATALOG_SOURCE" in provider_text
        ),
        "apiRecommendedEndpointsPresent": (
            "listRecommendedCatalogs" in api_text
            and "addRecommended" in api_text
            and "routeRecommendedAppCatalogs" in api_routes_text
            and "routeRecommendedAppCatalogAddOrApp" in api_routes_text
            and '"/app-catalogs/recommended"' in api_contract_text
            and '"/app-catalogs/recommended/{catalogId}/add"' in api_contract_text
            and "catalogs.recommended.list" in api_contract_text
            and "catalogs.recommended.add" in api_contract_text
            and "recommended_catalog_trusted_key_missing" in api_text
        ),
        "webShellOnboardingPresent": (
            "renderRecommendedCatalogs" in shell_text
            and "renderRecommendedCatalogCard" in shell_text
            and "app-catalogs/recommended" in shell_text
            and "addRecommended" in shell_text
        ),
        "cryptaArtifactTransportPresent": (
            "copyCryptaArtifact" in downloader_text
            and "ContentFetchPort" in downloader_text
            and "cryptaArtifactFetchKey" in downloader_text
            and "new AppCatalogArtifactDownloader(contentFetchPort)" in manager_text
        ),
        "cryptaArtifactUriTestsPresent": (
            "entry_whenArtifactUriIsCryptaChk_expectAccepted" in appcatalog_test_text
            and "prepareInstallPlan_whenCryptaArtifactUsesContentFetchPort_expectVerifiedPlan"
            in appcatalog_test_text
            and "download_whenCryptaRuntimeIsUnavailable_expectArtifactFetchUnavailable"
            in appcatalog_test_text
        ),
        "firstPartyAppMetadataDocumented": all(app_id in docs_text for app_id in app_ids)
        and "permissions.rationale" in docs_text
        and "api.minimumVersion" in docs_text
        and "changelog.summary" in docs_text
        and "review receipts" in docs_text.lower(),
        "cryptaArtifactPublicationDocumented": (
            "crypta:CHK@" in docs_text
            and "CRYPTAD_FIRST_PARTY_CATALOG_SOURCE" in docs_text
            and "CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED" in docs_text
        ),
        "privateKeysExcludedByDocs": (
            "No private keys" in docs_text or "no private keys" in docs_text.lower()
        ),
    }
    configuration = {
        "sourceConfigured": bool(os.environ.get("CRYPTAD_FIRST_PARTY_CATALOG_SOURCE", "").strip()),
        "trustedCatalogKeyHintConfigured": bool(
            os.environ.get("CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_KEY_ID", "").strip()
            or os.environ.get("CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_CATALOG_KEY_ID", "").strip()
        ),
        "apphostTrustedKeyConfigured": bool(
            os.environ.get("CRYPTAD_APPHOST_TRUSTED_KEY_ID", "").strip()
            or os.environ.get("CRYPTAD_APPHOST_TRUSTED_KEYS_FILE", "").strip()
            or os.environ.get("CRYPTAD_APPHOST_TRUSTED_PUBLIC_KEY_FILE", "").strip()
            or os.environ.get("CRYPTAD_APPHOST_TRUSTED_PUBLIC_KEY_BASE64", "").strip()
        ),
    }
    details = {
        "catalogId": "crypta-first-party-beta",
        "requiredFirstPartyApps": app_ids,
        "configuration": configuration,
        "checks": checks,
        "sources": {
            "recommendedModel": display_path(appcatalog_dir / "RecommendedAppCatalog.java", workspace),
            "recommendedProvider": display_path(appcatalog_dir / "RecommendedAppCatalogs.java", workspace),
            "artifactDownloader": display_path(appcatalog_dir / "AppCatalogArtifactDownloader.java", workspace),
            "apiHandler": display_path(
                workspace
                / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java",
                workspace,
            ),
            "webShell": display_path(
                workspace
                / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js",
                workspace,
            ),
            "docs": [
                display_path(workspace / "docs/app-catalogs.md", workspace),
                display_path(workspace / "docs/first-party-beta-catalog.md", workspace),
            ],
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-catalog.first-party-beta",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "First-party beta catalog onboarding evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-catalog.first-party-beta",
        "pass",
        True,
        "First-party beta catalog onboarding evidence passed deterministic checks.",
        source,
        details,
    )


def collect_production_catalog_channels_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    appcatalog_dir = workspace / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    appcatalog_tests = workspace / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog"
    api_dir = workspace / "platform-api/src/main/java/network/crypta/platform/api"
    api_updates_dir = api_dir / "appupdates"
    devtools_dir = workspace / "platform-devtools/src/main/java/network/crypta/platform/devtools"
    shell_dir = workspace / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static"
    channel_text = read_source(appcatalog_dir / "AppCatalogChannel.java")
    production_metadata_text = read_source(appcatalog_dir / "AppCatalogProductionMetadata.java")
    parser_writer_text = "\n".join(
        read_source(path)
        for path in (
            appcatalog_dir / "AppCatalog.java",
            appcatalog_dir / "AppCatalogParser.java",
            appcatalog_dir / "AppCatalogWriter.java",
            appcatalog_dir / "AppCatalogEntryDescriptor.java",
            appcatalog_dir / "AppCatalogSecurityAdvisory.java",
        )
    )
    appcatalog_test_text = "\n".join(
        read_source(path)
        for path in (
            appcatalog_tests / "AppCatalogParserTest.java",
            appcatalog_tests / "AppCatalogWriterTest.java",
            appcatalog_tests / "AppCatalogEntryDescriptorTest.java",
            appcatalog_tests / "AppCatalogMetadataTest.java",
        )
    )
    api_text = "\n".join(
        read_source(path)
        for path in (
            api_dir / "appcatalogs/AppCatalogsApiHandler.java",
            api_updates_dir / "AppUpdatePolicy.java",
            api_updates_dir / "AppUpdateService.java",
            api_updates_dir / "AppUpdateCandidate.java",
            api_updates_dir / "AppUpdatesApiHandler.java",
            api_dir / "PlatformApiContract.java",
        )
    )
    devtools_text = "\n".join(
        read_source(path)
        for path in (
            devtools_dir / "CatalogEntryDescriptorGenerator.java",
            devtools_dir / "CryptaAppCli.java",
        )
    )
    shell_text = "\n".join(
        read_source(path) for path in (shell_dir / "web-shell.js", shell_dir / "index.html")
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/app-catalogs.md",
            "docs/app-update-lifecycle.md",
            "docs/platform-api-surface.md",
            "docs/production-first-party-catalog-channels.md",
            "docs/first-party-beta-catalog.md",
        )
    )
    checks = {
        "channelEnumPresent": all(
            token in channel_text for token in ("stable", "beta", "nightly", "deprecated")
        ),
        "schemaV3ParserWriterPresent": (
            "VERSION_PRODUCTION_CHANNELS = 3" in parser_writer_text
            and "maximumCryptaVersion" in parser_writer_text
            and "securityAdvisory" in parser_writer_text
            and "replacementAppId" in parser_writer_text
        ),
        "productionMetadataDefaultsSafe": (
            "AppCatalogChannel.STABLE" in production_metadata_text
            and "AppCatalogSupportStatus.SUPPORTED" in production_metadata_text
            and "deprecatedForAutomaticUpdates" in production_metadata_text
        ),
        "parserWriterTestsPresent": (
            "parse_whenCatalogHasProductionChannelMetadata_expectMetadataNormalized"
            in appcatalog_test_text
            and "serialize_whenVersionTwoCatalogHasProductionMetadata_expectInvalidCatalogEntry"
            in appcatalog_test_text
            and "parse_whenVersionTwoCatalogOmitsProductionMetadata_expectStableDefaults"
            in appcatalog_test_text
        ),
        "apiExposurePresent": (
            '"channel"' in api_text
            and '"supportStatus"' in api_text
            and '"securityAdvisories"' in api_text
            and '"defaultEntryChannel"' in api_text
            and '"allowedChannels"' in api_text
        ),
        "updatePolicyBlocksNonStableAutomation": (
            "DEFAULT_ALLOWED_CHANNELS" in api_text
            and "channel_policy_blocked" in api_text
            and "allowsAutomaticChannel" in api_text
            and "deprecatedForAutomaticUpdates" in api_text
        ),
        "devtoolsDescriptorSupportPresent": (
            "--channel" in devtools_text
            and "--support-status" in devtools_text
            and "--security-advisory" in devtools_text
            and "maximumCryptaVersion" in devtools_text
        ),
        "webShellChannelControlsPresent": (
            "catalog-channel-select" in shell_text
            and "catalogAppChannel" in shell_text
            and "securityAdvisoryListNode" in shell_text
            and "is-deprecated-channel" in shell_text
        ),
        "signatureAndReviewSemanticsRetained": (
            "AppCatalogVerifier.verify" in read_source(appcatalog_dir / "AppCatalogManager.java")
            and "AppReviewReceiptVerifier.evaluate" in api_text
        ),
        "documentationPresent": (
            "catalog.version=3" in docs_text
            and "stable" in docs_text
            and "nightly" in docs_text
            and "channel_policy_blocked" in docs_text
            and "deprecated entries" in docs_text.lower()
        ),
    }
    details = {
        "channels": ["stable", "beta", "nightly", "deprecated"],
        "defaultAutomaticChannels": ["stable"],
        "deprecatedAutomaticUpdatesBlocked": True,
        "checks": checks,
        "redactionGuarantees": [
            "private insert URIs excluded",
            "tokens redacted",
            "private keys redacted",
            "raw fetched content excluded",
            "raw app data excluded",
            "absolute staging paths sanitized",
        ],
        "sources": {
            "catalogChannel": display_path(appcatalog_dir / "AppCatalogChannel.java", workspace),
            "catalogParser": display_path(appcatalog_dir / "AppCatalogParser.java", workspace),
            "catalogWriter": display_path(appcatalog_dir / "AppCatalogWriter.java", workspace),
            "apiHandler": display_path(api_dir / "appcatalogs/AppCatalogsApiHandler.java", workspace),
            "updatePolicy": display_path(api_updates_dir / "AppUpdatePolicy.java", workspace),
            "webShell": display_path(shell_dir / "web-shell.js", workspace),
            "docs": display_path(
                workspace / "docs/production-first-party-catalog-channels.md", workspace
            ),
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "catalog.production-channels",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Production catalog channel evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "catalog.production-channels",
        "pass",
        True,
        "Production catalog channel evidence passed deterministic checks.",
        source,
        details,
    )


def collect_app_review_receipt_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    appcatalog_dir = settings.workspace_root / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    verifier_text = read_source(appcatalog_dir / "AppReviewReceiptVerifier.java")
    receipt_text = read_source(appcatalog_dir / "AppReviewReceipt.java")
    payload_text = read_source(appcatalog_dir / "AppReviewReceiptPayload.java")
    io_text = read_source(appcatalog_dir / "AppReviewReceiptIO.java")
    keys_text = read_source(appcatalog_dir / "TrustedReviewerKeys.java")
    cli_text = read_source(settings.workspace_root / "platform-devtools/src/main/java/network/crypta/platform/devtools/CryptaAppCli.java")
    checks = {
        "canonicalPayloadExcludesSignature": (
            "canonicalPayloadBytes" in payload_text
            and "review.receipt.signature.value.base64" not in payload_text
        ),
        "receiptSignatureIndependent": (
            "Signature.getInstance(receipt.signature().algorithm())" in verifier_text
            and "receipt.payload().canonicalPayloadBytes()" in verifier_text
        ),
        "bindingChecks": (
            "receipt.mismatchStatus(" in verifier_text
            and "binding.appId()" in verifier_text
            and "binding.version()" in verifier_text
            and "binding.artifactSha256()" in verifier_text
            and "binding.artifactSizeBytes()" in verifier_text
            and "AppReviewTrustStatus.ARTIFACT_MISMATCH" in receipt_text
            and "AppReviewTrustStatus.APP_MISMATCH" in receipt_text
        ),
        "expiryAndUnknownReviewerFailClosed": (
            "AppReviewTrustStatus.EXPIRED" in verifier_text
            and "AppReviewTrustStatus.UNKNOWN_REVIEWER" in verifier_text
        ),
        "trustedReviewerRegistrySeparate": (
            "trusted.reviewers.version" in keys_text
            and "public.key.base64" in keys_text
        ),
        "parserWriterEmbedsReceipt": (
            "parseProperties" in io_text
            and "appendReceiptProperties" in io_text
            and "review.receipt.signature.value.base64" in io_text
        ),
        "devtoolsSignVerify": (
            'name = "review"' in cli_text
            and "ReviewSignCommand" in cli_text
            and "ReviewVerifyCommand" in cli_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "receiptSchemaVersion": 1,
        "signatureAlgorithm": "Ed25519",
        "checks": checks,
        "sources": {
            "verifier": display_path(appcatalog_dir / "AppReviewReceiptVerifier.java", settings.workspace_root),
            "receipt": display_path(appcatalog_dir / "AppReviewReceipt.java", settings.workspace_root),
            "payload": display_path(appcatalog_dir / "AppReviewReceiptPayload.java", settings.workspace_root),
            "receiptIo": display_path(appcatalog_dir / "AppReviewReceiptIO.java", settings.workspace_root),
            "trustedReviewerKeys": display_path(appcatalog_dir / "TrustedReviewerKeys.java", settings.workspace_root),
            "devtools": display_path(settings.workspace_root / "platform-devtools/src/main/java/network/crypta/platform/devtools/CryptaAppCli.java", settings.workspace_root),
        },
    }
    if errors:
        return EvidenceItem(
            "app-review.trusted-receipts",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "App-review receipt evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-review.trusted-receipts",
        "pass",
        True,
        "Trusted review receipt model and offline tooling evidence passed.",
        source,
        details,
    )


def collect_app_review_policy_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    appcatalog_dir = settings.workspace_root / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    api_catalogs = settings.workspace_root / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    api_updates = settings.workspace_root / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateService.java"
    policy_text = read_source(appcatalog_dir / "AppReviewPolicy.java")
    mode_text = read_source(appcatalog_dir / "AppReviewPolicyMode.java")
    decision_text = read_source(appcatalog_dir / "AppReviewTrustDecision.java")
    catalogs_text = read_source(api_catalogs)
    updates_text = read_source(api_updates)
    checks = {
        "policyModes": (
            "ADVISORY" in mode_text
            and "WARN_UNTRUSTED" in mode_text
            and "REQUIRE_TRUSTED_REVIEW" in mode_text
            and "REQUIRE_TRUSTED_REVIEW_FOR_APPLY_WHEN_STOPPED" in mode_text
        ),
        "defaultAdvisory": "AppReviewPolicyMode.ADVISORY" in policy_text,
        "decisionFlags": (
            "requiresAcknowledgement" in decision_text
            and "blocksInstall" in decision_text
            and "blocksUpdate" in decision_text
            and "blocksPolicyApply" in decision_text
        ),
        "catalogInstallUpdateGate": (
            "requireReviewGate(" in catalogs_text
            and "reviewAcknowledged" in catalogs_text
            and "app_review_missing" in catalogs_text
        ),
        "updateLifecycleGate": (
            "requireReviewGate(candidate.reviewTrust()" in updates_text
            and "eligibleForAutomaticApply()" in read_source(settings.workspace_root / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateCandidate.java")
            and "app_review_rejected" in updates_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "mode": "advisory default; warn/block modes operator-configured",
        "checks": checks,
        "sources": {
            "policy": display_path(appcatalog_dir / "AppReviewPolicy.java", settings.workspace_root),
            "policyMode": display_path(appcatalog_dir / "AppReviewPolicyMode.java", settings.workspace_root),
            "decision": display_path(appcatalog_dir / "AppReviewTrustDecision.java", settings.workspace_root),
            "catalogsApi": display_path(api_catalogs, settings.workspace_root),
            "updatesApi": display_path(api_updates, settings.workspace_root),
        },
    }
    if errors:
        return EvidenceItem("app-review.policy", "fail" if settings.mode == "release-candidate" else "warn", True, "App-review policy evidence is incomplete.", source, {"errors": errors, **details})
    return EvidenceItem("app-review.policy", "pass", True, "App-review policy gates passed deterministic evidence checks.", source, details)


def collect_app_review_governance_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    appcatalog_dir = workspace / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    api_routes = workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiAppRoutes.java"
    api_handler = workspace / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    shell = workspace / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    status_text = read_source(appcatalog_dir / "TrustedReviewerKeyStatus.java")
    lifecycle_text = read_source(appcatalog_dir / "TrustedReviewerKeyLifecycle.java")
    verifier_text = read_source(appcatalog_dir / "AppReviewReceiptVerifier.java")
    routes_text = read_source(api_routes)
    handler_text = read_source(api_handler)
    shell_text = read_source(shell)
    checks = {
        "reviewerLifecycleStatuses": all(value in status_text for value in ("ACTIVE", "RETIRED", "REVOKED")),
        "policyVersionConstraint": "TrustedReviewerPolicyConstraint" in read_source(appcatalog_dir / "TrustedReviewerPolicyConstraint.java"),
        "lifecycleTrustStatuses": all(
            value in verifier_text
            for value in (
                "REVOKED_REVIEWER",
                "RETIRED_REVIEWER",
                "REVIEWER_NOT_YET_VALID",
                "REVIEWER_EXPIRED",
                "REVIEW_POLICY_MISMATCH",
            )
        ),
        "governanceRoutes": (
            "routeAppReviewRequest" in routes_text
            and "app-review" in routes_text
            and "reviewer-keys" in routes_text
            and "transparency-log" in routes_text
        ),
        "redactedReviewerSummaries": (
            "TrustedReviewerKeySummary" in handler_text
            and "publicKey" not in read_source(appcatalog_dir / "TrustedReviewerKeySummary.java")
        ),
        "webShellGovernance": (
            "Review governance" in shell_text
            and "reviewerKeyStatus" in shell_text
            and "policyVersionStatus" in shell_text
        ),
        "lifecycleValidation": (
            "revocation metadata requires status=revoked" in lifecycle_text
            and "reviewer valid.until must be after valid.from" in lifecycle_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "checks": checks,
        "sources": {
            "status": display_path(appcatalog_dir / "TrustedReviewerKeyStatus.java", workspace),
            "lifecycle": display_path(appcatalog_dir / "TrustedReviewerKeyLifecycle.java", workspace),
            "verifier": display_path(appcatalog_dir / "AppReviewReceiptVerifier.java", workspace),
            "apiRoutes": display_path(api_routes, workspace),
            "apiHandler": display_path(api_handler, workspace),
            "webShell": display_path(shell, workspace),
        },
    }
    if errors:
        return EvidenceItem(
            "app-review.governance",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "App-review governance evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-review.governance",
        "pass",
        True,
        "App-review governance evidence passed deterministic source checks.",
        source,
        details,
    )


def collect_app_review_reviewer_key_lifecycle_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    appcatalog_dir = workspace / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    tests = workspace / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog/AppReviewReceiptTest.java"
    keys_text = read_source(appcatalog_dir / "TrustedReviewerKeys.java")
    tests_text = read_source(tests)
    checks = {
        "v2Parser": (
            "trusted.reviewers.version" in keys_text
            and "policy.version" in keys_text
            and "valid.from" in keys_text
            and "revoked.at" in keys_text
        ),
        "duplicateIdsFailClosed": "duplicate trusted reviewer key id" in keys_text,
        "strictInstants": "Instant.parse(value)" in keys_text,
        "revokedReviewerTest": "evaluate_whenReviewerKeyIsRevoked_expectRevokedReviewer" in tests_text,
        "retiredReviewerTest": "evaluate_whenRetiredReviewerCoversReviewedAt_expectTrustedHistoricalReview" in tests_text,
        "retiredReviewerRequiresWindowTest": "evaluate_whenRetiredReviewerHasNoValidityEnd_expectRetiredReviewer" in tests_text,
        "policyMismatchTest": "evaluate_whenPolicyVersionDoesNotMatchReviewerConstraint_expectPolicyMismatch" in tests_text,
        "policyVersionRequiresPolicyIdTest": "trustedReviewerKeysLoad_whenPolicyVersionOmitsPolicyId_expectInvalidCatalogEntry" in tests_text,
        "redactedSummaryTest": "publicKey" in tests_text and "containsKey" in tests_text,
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "checks": checks,
        "sources": {
            "trustedReviewerKeys": display_path(appcatalog_dir / "TrustedReviewerKeys.java", workspace),
            "tests": display_path(tests, workspace),
        },
    }
    if errors:
        return EvidenceItem(
            "app-review.reviewer-key-lifecycle",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Reviewer-key lifecycle evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-review.reviewer-key-lifecycle",
        "pass",
        True,
        "Reviewer-key lifecycle parser and verifier evidence passed.",
        source,
        details,
    )


def collect_app_review_transparency_log_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    appcatalog_dir = workspace / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    record_text = read_source(appcatalog_dir / "AppReviewTransparencyRecord.java")
    store_text = read_source(appcatalog_dir / "FileAppReviewTransparencyStore.java")
    log_text = read_source(appcatalog_dir / "AppReviewTransparencyLog.java")
    manager_text = read_source(appcatalog_dir / "AppCatalogManager.java")
    tests_text = read_source(workspace / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog/AppReviewReceiptTest.java")
    checks = {
        "hashChain": (
            "previousRecordHash" in record_text
            and "recordHash" in record_text
            and "computeRecordHash" in record_text
            and "verifyRecords" in store_text
        ),
        "redactedFields": (
            "privateKey" not in record_text
            and "processToken" not in record_text
            and "browserSession" not in record_text
            and "signature.value" not in record_text
        ),
        "receiptObservationDedup": "REVIEW_RECEIPT_OBSERVED" in log_text and "receiptFingerprint" in log_text,
        "receiptObservationPayloadBindingTest": "transparencyLog_whenMismatchedReceiptObserved_expectReceiptPayloadBinding" in tests_text,
        "gateReceiptStatusTest": "transparencyRecordFromCatalogDecision_whenReceiptAndPublisherStatusesDiffer_expectReceiptStatus" in tests_text,
        "publisherOnlyNoReceiptStatusTest": "transparencyRecordFromCatalogDecision_whenOnlyPublisherReviewExists_expectNoReceiptStatus" in tests_text,
        "managerOwnedStore": "reviewTransparencyLog" in manager_text,
        "rejectUnknownFields": "rejectUnknownJsonFields" in record_text,
        "rejectTrailingData": "expectEnd()" in record_text,
        "tamperTest": "transparencyStoreVerify_whenRecordIsTampered_expectVerificationFailure" in tests_text,
        "unknownFieldTest": "transparencyStoreVerify_whenRecordHasUnknownField_expectVerificationFailure" in tests_text,
        "trailingDataTest": "transparencyStoreVerify_whenRecordHasTrailingData_expectVerificationFailure" in tests_text,
        "warningListTamperTest": "transparencyStoreVerify_whenWarningListShapeIsTampered_expectVerificationFailure" in tests_text,
        "booleanTypeTamperTest": "transparencyStoreVerify_whenBooleanFieldHasStringValue_expectVerificationFailure" in tests_text,
        "schemaVersionRangeTest": "transparencyStoreVerify_whenSchemaVersionIsOutOfRange_expectVerificationFailure" in tests_text,
        "bestEffortMalformedLogTest": "transparencyLogRecordCatalogDecision_whenExistingLogIsMalformed_expectBestEffort" in tests_text,
        "bestEffortNullRecordIdTest": "transparencyLogRecordCatalogDecision_whenExistingReceiptRecordHasNullId_expectBestEffort" in tests_text,
        "dedupTest": "transparencyLog_whenReceiptObservedTwice_expectReceiptObservationDeduplicated" in tests_text,
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "checks": checks,
        "sources": {
            "record": display_path(appcatalog_dir / "AppReviewTransparencyRecord.java", workspace),
            "store": display_path(appcatalog_dir / "FileAppReviewTransparencyStore.java", workspace),
            "log": display_path(appcatalog_dir / "AppReviewTransparencyLog.java", workspace),
            "manager": display_path(appcatalog_dir / "AppCatalogManager.java", workspace),
        },
    }
    if errors:
        return EvidenceItem(
            "app-review.transparency-log",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Review transparency-log evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-review.transparency-log",
        "pass",
        True,
        "Review transparency-log hash-chain and redaction evidence passed.",
        source,
        details,
    )


def collect_app_review_history_api_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    routes = workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiAppRoutes.java"
    handler = workspace / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    shell = workspace / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    routes_text = read_source(routes)
    handler_text = read_source(handler)
    shell_text = read_source(shell)
    checks = {
        "reviewHistoryRoute": "review-history" in routes_text and "reviewHistory(" in handler_text,
        "governanceEndpoint": "governance()" in handler_text,
        "reviewerKeysEndpoint": "reviewerKeys()" in handler_text,
        "transparencyEndpoint": "transparencyLog(" in handler_text and "verifyTransparencyLog" in handler_text,
        "shellHistoryFetch": "loadCatalogAppReviewHistory" in shell_text,
        "shellTrustDelta": "trustDelta" in handler_text and "Installed version" in shell_text,
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "checks": checks,
        "sources": {
            "routes": display_path(routes, workspace),
            "handler": display_path(handler, workspace),
            "webShell": display_path(shell, workspace),
        },
    }
    if errors:
        return EvidenceItem(
            "app-review.review-history-api",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Review-history API evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-review.review-history-api",
        "pass",
        True,
        "Review-history and governance API evidence passed.",
        source,
        details,
    )


def collect_app_review_first_party_chain_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    smoke_text = read_source(workspace / "tools/release-certification/app_platform_smoke.py")
    docs_text = read_source(workspace / "docs/app-review-governance.md")
    checks = {
        "firstPartyCatalogEvidence": "collect_app_review_first_party_catalog_evidence" in smoke_text,
        "reviewReceiptVerify": "review_verify_args" in smoke_text and "trustedPositiveReceipts" in smoke_text,
        "governanceEvidenceRequired": "app-review.governance" in smoke_text,
        "transparencyEvidenceRequired": "app-review.transparency-log" in smoke_text,
        "docsExplainLocalLog": (
            "tamper-evident" in docs_text.lower()
            and "not a global public" in docs_text.lower()
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {"checks": checks}
    if errors:
        return EvidenceItem(
            "app-review.first-party-review-chain",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "First-party app-review chain evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-review.first-party-review-chain",
        "pass",
        True,
        "First-party app-review chain evidence passed deterministic checks.",
        source,
        details,
    )


def write_first_party_review_descriptor(
    descriptor: Path,
    spec: dict[str, Any],
    manifest: dict[str, str],
    artifact_zip: Path,
) -> None:
    app_id = manifest.get("app.id", spec["appId"])
    app_name = manifest.get("app.name", spec["name"])
    permissions = ",".join(sorted(parse_permission_set(manifest.get("app.permissions", ""))))
    lines = [
        f"artifact.path={artifact_zip.resolve()}",
        f"bundle.uri={artifact_zip.resolve().as_uri()}",
        f"summary=First-party release-candidate review target for {app_name}.",
        f"name={app_name}",
        f"permissions={permissions}",
        f"app.id={app_id}",
        f"version={manifest.get('app.version', '')}",
        "review.status=reviewed",
        "review.note=First-party app review receipt required for release promotion.",
        "changelog.summary=Release certification first-party catalog evidence.",
    ]
    if manifest.get("api.minimumVersion"):
        lines.append(f"api.minimumVersion={manifest['api.minimumVersion']}")
    if manifest.get("api.maximumTestedVersion"):
        lines.append(f"api.maximumTestedVersion={manifest['api.maximumTestedVersion']}")
    if manifest.get("api.experimentalCapabilitiesAccepted"):
        lines.append(
            "api.experimentalCapabilitiesAccepted="
            + manifest["api.experimentalCapabilitiesAccepted"]
        )
    descriptor.write_text("\n".join(lines) + "\n", encoding="utf-8")


def collect_app_review_first_party_catalog_evidence(settings: Settings, sample_paths: dict[str, Path]) -> EvidenceItem:
    source = summary_source(settings)
    cli = sample_paths.get("cli")
    specs = first_party_app_specs(settings)
    details: dict[str, Any] = {
        "policyMode": "release-candidate requires trusted positive receipts",
        "firstPartyApps": [spec["appId"] for spec in specs],
        "referenceContentApp": "site-publisher",
        "coverage": {
            "catalogAppsInspected": 0,
            "trustedPositiveReceipts": 0,
            "missingReceipts": len(specs),
            "expiredOrMismatchedOrUnknownReviewer": 0,
            "trustedRejectedReceipts": 0,
            "promotionBlocked": True,
        },
    }
    if not cli:
        return EvidenceItem("app-review.first-party-catalog", root_consequence(settings, "missing"), True, "crypta-app CLI is unavailable for first-party review catalog evidence.", source, details)
    inputs = reviewer_inputs(os.environ)
    details["reviewerInputs"] = {
        "keyIdPresent": bool(inputs["keyId"]),
        "privateKeyPresent": inputs["hasPrivate"],
        "publicKeyPresent": inputs["hasPublic"],
        "policyId": inputs["policyId"],
        "policyVersion": inputs["policyVersion"],
    }
    if not inputs["complete"]:
        return EvidenceItem(
            "app-review.first-party-catalog",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Reviewer key inputs are incomplete; trusted first-party review receipts were not verified.",
            source,
            details,
        )
    review_dir = sample_workspace(settings) / "app-review"
    review_dir.mkdir(parents=True, exist_ok=True)
    trusted_keys_file = review_dir / "trusted-reviewers.properties"
    catalog_file = review_dir / "cryptad-app-catalog.properties"
    remove_existing_path(catalog_file)
    try:
        write_trusted_reviewer_keys(trusted_keys_file, inputs)
    except OSError as exc:
        details["trustedReviewerKeys"] = {
            "error": scrub_text(str(exc), settings.workspace_root)
        }
        return EvidenceItem(
            "app-review.first-party-catalog",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Reviewer public key material could not be read for app-review catalog evidence.",
            source,
            details,
        )

    failures: list[str] = []
    entry_files: list[Path] = []
    receipt_files: list[Path] = []
    details["apps"] = {}
    for spec in specs:
        app_id = spec["appId"]
        app_details: dict[str, Any] = {
            "stagedDir": display_path(spec["stagedDir"], settings.workspace_root),
        }
        details["apps"][app_id] = app_details
        manifest_path = spec["stagedDir"] / "cryptad-app.properties"
        if not manifest_path.is_file():
            failures.append(f"{app_id}: staged manifest is missing")
            continue
        try:
            manifest = parse_properties(manifest_path)
        except ValueError as exc:
            failures.append(f"{app_id}: {exc}")
            continue
        version = manifest.get("app.version", "unknown")
        artifact_zip = review_dir / f"{app_id}-{version}.zip"
        descriptor = review_dir / f"{app_id}.properties"
        receipt_file = review_dir / f"{app_id}-review-receipt.properties"
        remove_existing_path(artifact_zip)
        remove_existing_path(descriptor)
        remove_existing_path(receipt_file)
        pack_result = run_cli(
            cli,
            [
                "pack",
                "--bundle-dir",
                str(spec["stagedDir"]),
                "--output",
                str(artifact_zip),
                "--overwrite",
            ],
            settings,
            f"crypta-app-review-pack-{app_id}",
        )
        app_details["pack"] = command_details(pack_result, settings)
        app_details["artifact"] = display_path(artifact_zip, settings.workspace_root, settings.out_dir)
        if pack_result.exit_code != 0 or not artifact_zip.is_file():
            failures.append(f"{app_id}: first-party bundle pack failed")
            continue
        write_first_party_review_descriptor(descriptor, spec, manifest, artifact_zip)
        sign_result = run_cli(
            cli,
            review_sign_args(descriptor, receipt_file, inputs),
            settings,
            f"crypta-app-review-sign-{app_id}",
        )
        verify_result = run_cli(
            cli,
            review_verify_args(descriptor, receipt_file, trusted_keys_file),
            settings,
            f"crypta-app-review-verify-{app_id}",
        )
        app_details["descriptor"] = display_path(descriptor, settings.workspace_root, settings.out_dir)
        app_details["receipt"] = display_path(receipt_file, settings.workspace_root, settings.out_dir)
        app_details["sign"] = command_details(sign_result, settings)
        app_details["verify"] = command_details(verify_result, settings)
        if sign_result.exit_code != 0:
            failures.append(f"{app_id}: review receipt signing failed")
        if verify_result.exit_code != 0:
            failures.append(f"{app_id}: review receipt verification failed")
        if sign_result.exit_code == 0 and verify_result.exit_code == 0:
            entry_files.append(descriptor)
            receipt_files.append(receipt_file)
    if failures:
        return EvidenceItem(
            "app-review.first-party-catalog",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "First-party review catalog preparation failed.",
            source,
            {"failures": failures, **details},
        )

    create_args = [
        "catalog",
        "create",
        "--catalog-file",
        str(catalog_file),
        "--catalog-id",
        "cert-first-party-review",
        "--name",
        "Certification First-Party Apps",
        "--generated-at",
        "2026-05-01T00:00:00Z",
    ]
    for entry_file in entry_files:
        create_args.extend(["--entry", str(entry_file)])
    for receipt_file in receipt_files:
        create_args.extend(["--review-receipt", str(receipt_file)])
    create_args.append("--overwrite")
    create_result = run_cli(cli, create_args, settings, "crypta-app-review-catalog-create")
    details["catalogCreate"] = command_details(create_result, settings)
    catalog = parse_properties(catalog_file) if catalog_file.is_file() else {}
    catalog_entries = parse_permission_set(catalog.get("catalog.entries", ""))
    expected_app_ids = {spec["appId"] for spec in specs}
    inspected_app_ids = {
        app_id
        for app_id in expected_app_ids
        if catalog.get(f"app.{app_id}.id") == app_id or app_id in catalog_entries
    }
    receipt_statuses = {
        app_id: catalog.get(f"app.{app_id}.review.receipt.status")
        for app_id in expected_app_ids
    }
    trusted_positive_receipts = sum(
        1 for status in receipt_statuses.values() if status == "reviewed"
    )
    trusted_rejected_receipts = sum(
        1 for status in receipt_statuses.values() if status == "rejected"
    )
    missing_receipts = sum(1 for status in receipt_statuses.values() if not status)
    verify_failures = sum(
        1
        for app_details in details["apps"].values()
        if app_details.get("verify", {}).get("exitCode") != 0
    )
    details["coverage"] = {
        "catalogAppsInspected": len(inspected_app_ids),
        "trustedPositiveReceipts": trusted_positive_receipts,
        "missingReceipts": missing_receipts,
        "expiredOrMismatchedOrUnknownReviewer": verify_failures,
        "trustedRejectedReceipts": trusted_rejected_receipts,
        "promotionBlocked": (
            create_result.exit_code != 0
            or inspected_app_ids != expected_app_ids
            or trusted_positive_receipts != len(expected_app_ids)
        ),
    }
    details["catalog"] = {
        "catalogId": catalog.get("catalog.id"),
        "entries": sorted(catalog_entries),
        "inspectedAppIds": sorted(inspected_app_ids),
        "receiptStatuses": receipt_statuses,
    }
    if details["coverage"]["promotionBlocked"]:
        return EvidenceItem("app-review.first-party-catalog", "fail" if settings.mode == "release-candidate" else "warn", True, "Trusted first-party review receipt catalog evidence failed.", source, details)
    return EvidenceItem("app-review.first-party-catalog", "pass", True, "First-party catalog review receipt evidence covered all first-party apps.", source, details)


def design_system_source_dir(settings: Settings) -> Path:
    return (
        settings.workspace_root
        / "platform-design-system/src/main/resources/network/crypta/platform/designsystem/static"
    )


def design_system_asset_names() -> tuple[str, ...]:
    return ("crypta-ui-tokens.css", "crypta-ui.css", "crypta-ui-components.js")


def collect_app_ui_design_system_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    canonical_dir = design_system_source_dir(settings)
    details: dict[str, Any] = {
        "canonicalResourceDir": display_path(canonical_dir, settings.workspace_root),
        "assets": [],
        "apps": {},
    }
    errors: list[str] = []
    for asset_name in design_system_asset_names():
        asset_path = canonical_dir / asset_name
        if not asset_path.is_file():
            errors.append(f"canonical design-system asset missing: {asset_name}")
            details["assets"].append({"name": asset_name, "present": False})
            continue
        details["assets"].append(
            {
                "name": asset_name,
                "present": True,
                "sha256": sha256_file(asset_path),
                "sizeBytes": asset_path.stat().st_size,
            }
        )
    for spec in first_party_app_specs(settings):
        app_details: dict[str, Any] = {"assets": []}
        staged_static_dir = spec["stagedDir"] / "static/crypta-ui"
        for asset_name in design_system_asset_names():
            staged_asset = staged_static_dir / asset_name
            canonical_asset = canonical_dir / asset_name
            present = staged_asset.is_file()
            matches = (
                present
                and canonical_asset.is_file()
                and sha256_file(staged_asset) == sha256_file(canonical_asset)
            )
            app_details["assets"].append(
                {
                    "name": asset_name,
                    "present": present,
                    "matchesCanonical": matches,
                    "path": display_path(staged_asset, settings.workspace_root),
                }
            )
            if not present:
                errors.append(f"{spec['appId']}: staged design-system asset missing: {asset_name}")
            elif not matches:
                errors.append(f"{spec['appId']}: staged design-system asset differs: {asset_name}")
        details["apps"][spec["appId"]] = app_details
    if errors:
        return EvidenceItem(
            "app-ui.design-system",
            root_consequence(settings, "fail"),
            True,
            "App UI design-system asset evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-ui.design-system",
        "pass",
        True,
        "Canonical app UI design-system assets are present and staged into first-party apps.",
        source,
        details,
    )


def stylesheet_order_ok(index_html: str) -> bool:
    tokens = index_html.find("crypta-ui-tokens.css")
    ui_css = index_html.find("crypta-ui.css")
    app_css = index_html.find("app.css")
    return tokens >= 0 and ui_css > tokens and app_css > ui_css


def permission_disclosure_block(index_html: str) -> str:
    lower = index_html.lower()
    candidates = [
        lower.find("cr-permission-summary"),
        lower.find("data-crypta-permission-summary"),
        lower.find("<crypta-permission-summary"),
    ]
    starts = [candidate for candidate in candidates if candidate >= 0]
    if not starts:
        return ""
    start = min(starts)
    end_candidates = [
        lower.find("</section>", start),
        lower.find("</crypta-permission-summary>", start),
    ]
    ends = [candidate for candidate in end_candidates if candidate >= 0]
    end = min(ends) if ends else len(index_html)
    return index_html[start:end]


def source_ui_adoption_details(
    static_dir: Path, permissions: set[str], settings: Settings
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    index = static_dir / "index.html"
    details: dict[str, Any] = {
        "index": display_path(index, settings.workspace_root),
        "designSystemStylesheetOrder": False,
        "usesDesignSystemClasses": False,
        "hasPermissionDisclosure": False,
    }
    if not index.is_file():
        return ["static/index.html is missing"], details
    index_html = index.read_text(encoding="utf-8")
    details["designSystemStylesheetOrder"] = stylesheet_order_ok(index_html)
    details["usesDesignSystemClasses"] = "cr-" in index_html
    details["hasPermissionDisclosure"] = (
        "cr-permission-summary" in index_html
        or "data-crypta-permission-summary" in index_html
        or "<crypta-permission-summary" in index_html
    )
    if not details["designSystemStylesheetOrder"]:
        errors.append("index.html does not load design-system CSS before app CSS")
    if not details["usesDesignSystemClasses"]:
        errors.append("index.html does not use cr-* design-system classes")
    if permissions and not details["hasPermissionDisclosure"]:
        errors.append("manifest permissions have no visible permission disclosure")
    disclosure = permission_disclosure_block(index_html)
    mentioned_permissions = set(
        re.findall(r"\b[a-z][a-z0-9._-]*\.[a-z][a-z0-9._-]*\b", disclosure)
    )
    omitted = sorted(permissions - mentioned_permissions)
    undeclared = sorted(mentioned_permissions - permissions)
    details["mentionedPermissions"] = sorted(mentioned_permissions)
    details["omittedPermissions"] = omitted
    if details["hasPermissionDisclosure"] and omitted:
        errors.append("permission disclosure omits declared permissions: " + ",".join(omitted))
    if undeclared:
        errors.append(
            "permission disclosure mentions undeclared permissions: " + ",".join(undeclared)
        )
    return errors, details


def collect_app_ui_first_party_adoption_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    details: dict[str, Any] = {"sourceStaticUi": {}, "stagedStaticUi": {}}
    errors: list[str] = []
    for spec in first_party_app_specs(settings):
        source_errors, source_details = source_ui_adoption_details(
            spec["sourceDir"] / "static", spec["permissions"], settings
        )
        staged_errors, staged_details = source_ui_adoption_details(
            spec["stagedDir"] / "static", spec["permissions"], settings
        )
        details["sourceStaticUi"][spec["appId"]] = source_details
        details["stagedStaticUi"][spec["appId"]] = staged_details
        errors.extend(f"{spec['appId']} source: {error}" for error in source_errors)
        errors.extend(f"{spec['appId']} staged: {error}" for error in staged_errors)
    if errors:
        return EvidenceItem(
            "app-ui.first-party-adoption",
            root_consequence(settings, "fail"),
            True,
            "First-party app UI design-system adoption checks found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-ui.first-party-adoption",
        "pass",
        True,
        "First-party static apps use design-system loading order, classes, and permission disclosure.",
        source,
        details,
    )


def collect_app_ui_lint_evidence(settings: Settings, cli: Path | None) -> EvidenceItem:
    source = summary_source(settings)
    details: dict[str, Any] = {"apps": {}}
    if cli is None or not cli.is_file():
        return EvidenceItem(
            "app-ui.lint",
            root_consequence(settings, "missing"),
            True,
            "crypta-app CLI is unavailable for app UI lint evidence.",
            source,
            details,
        )
    errors: list[str] = []
    lint_dir = settings.out_dir / "artifacts" / "app-ui-lint"
    lint_dir.mkdir(parents=True, exist_ok=True)
    for spec in first_party_app_specs(settings):
        json_path = lint_dir / f"{spec['appId']}.json"
        remove_existing_path(json_path)
        result = run_cli(
            cli,
            [
                "ui",
                "lint",
                "--bundle-dir",
                str(spec["stagedDir"]),
                "--strict",
                "--json",
                str(json_path),
            ],
            settings,
            f"crypta-app-ui-lint-{spec['appId']}",
        )
        app_details = {
            "command": command_details(result, settings),
            "json": display_path(json_path, settings.workspace_root, settings.out_dir),
        }
        lint_json = read_json_file(json_path)
        if lint_json:
            app_details["report"] = {
                "appId": str(lint_json.get("appId", "")),
                "uiMode": str(lint_json.get("uiMode", "")),
                "applicable": lint_json.get("applicable"),
            }
            summary = lint_json.get("summary", {})
            app_details["summary"] = summary
            findings = lint_json.get("findings", [])
            if isinstance(findings, list):
                app_details["findingIds"] = [
                    str(finding.get("id", "unknown"))
                    for finding in findings
                    if isinstance(finding, dict)
                ]
        details["apps"][spec["appId"]] = app_details
        if result.exit_code != 0:
            errors.append(f"crypta-app ui lint failed for {spec['appId']}")
        errors.extend(ui_lint_report_errors(lint_json, str(spec["appId"])))
    if errors:
        return EvidenceItem(
            "app-ui.lint",
            root_consequence(settings, "fail"),
            True,
            "First-party app UI lint found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-ui.lint",
        "pass",
        True,
        "crypta-app ui lint passed for first-party static apps.",
        source,
        details,
    )


def collect_app_vault_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    doc_path = settings.workspace_root / APP_VAULT_DOC
    vocabulary_path = (
        settings.workspace_root
        / "platform-devtools/src/main/java/network/crypta/platform/devtools/DevtoolsCapabilityVocabulary.java"
    )
    details: dict[str, Any] = {
        "doc": display_path(doc_path, settings.workspace_root),
        "devtoolsVocabulary": display_path(vocabulary_path, settings.workspace_root),
        "capabilities": list(APP_VAULT_CAPABILITIES),
        "checks": {},
        "redaction": {
            "capabilityNamesRetained": True,
            "secretValuesRedacted": True,
            "identityPrivateMaterialRedacted": True,
            "signatureValuesRedacted": True,
        },
    }
    errors: list[str] = []
    doc_text = ""
    if doc_path.is_file():
        doc_text = doc_path.read_text(encoding="utf-8")
    else:
        errors.append(f"{APP_VAULT_DOC} is missing")
    vocabulary_text = vocabulary_path.read_text(encoding="utf-8") if vocabulary_path.is_file() else ""
    if not vocabulary_text:
        errors.append("devtools app-vault capability vocabulary is missing")

    lower_doc = doc_text.lower()
    lower_vocab = vocabulary_text.lower()
    missing_doc_capabilities = [
        capability for capability in APP_VAULT_CAPABILITIES if capability not in doc_text
    ]
    missing_vocab_capabilities = [
        capability for capability in APP_VAULT_CAPABILITIES if capability not in lower_vocab
    ]
    if missing_doc_capabilities:
        errors.append("vault doc omits capabilities: " + ",".join(missing_doc_capabilities))
    if missing_vocab_capabilities:
        errors.append(
            "devtools vocabulary omits capabilities: " + ",".join(missing_vocab_capabilities)
        )
    checks = details["checks"]
    checks["capabilitiesDocumented"] = not missing_doc_capabilities
    checks["devtoolsVocabularyPresent"] = not missing_vocab_capabilities
    checks["appOwnedAndSharedIdentities"] = "app-owned" in lower_doc and "shared identit" in lower_doc
    checks["processBrowserRestrictions"] = (
        "process" in lower_doc and "browser" in lower_doc and "cryptad_app_token" in lower_doc
    )
    checks["atRestLimitations"] = (
        ("at-rest" in lower_doc or "at rest" in lower_doc)
        and "local" in lower_doc
        and "limit" in lower_doc
    )
    checks["grantLifecycle"] = all(
        word in lower_doc for word in ("update", "rollback", "uninstall", "reinstall")
    )
    checks["auditAndRedaction"] = "audit" in lower_doc and "redact" in lower_doc
    checks["futureExtensionPoint"] = all(word in lower_doc for word in ("content", "social", "mail"))
    checks["browserSafeIdentityCreationRoute"] = (
        "post /api/v1/app-vault/identities" in lower_doc
        and "browser" in lower_doc
        and "vault.identities.create" in doc_text
    )
    checks["profileDocumentRoute"] = (
        "post /api/v1/app-vault/identities/{identityid}/profile-document" in lower_doc
        and "vault.identities.read" in doc_text
        and "vault.identities.use" in doc_text
        and "profile document" in lower_doc
    )
    for name, passed in checks.items():
        if not passed:
            errors.append(f"vault documentation check failed: {name}")
    if errors:
        return EvidenceItem(
            "app-vault.capabilities",
            root_consequence(settings, "fail"),
            True,
            "App secret and identity vault evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-vault.capabilities",
        "pass",
        True,
        "App secret and identity vault capability docs and redaction checks passed.",
        source,
        details,
    )


def collect_identity_profile_publish_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    route = "/app-vault/identities/{identityId}/profile-document"
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/app-secret-and-identity-vault.md",
            "docs/platform-api-contract.md",
            "docs/platform-api-surface.md",
            "docs/release-certification.md",
        )
    )
    contract_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    router_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java"
    )
    handler_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appvault/AppVaultApiHandler.java"
    )
    tests_text = "\n".join(
        read_source(path)
        for path in sorted((workspace / "platform-api/src/test/java").rglob("*.java"))
        if "AppVault" in path.name or "Capabilities" in path.name or "Contract" in path.name
    )
    lower_docs = docs_text.lower()
    source_text = "\n".join((contract_text, router_text, handler_text, tests_text))
    checks = {
        "routeDocumented": "post /api/v1/app-vault/identities/{identityid}/profile-document"
        in lower_docs,
        "requiredCapabilitiesDocumented": (
            "vault.identities.read" in docs_text and "vault.identities.use" in docs_text
        ),
        "profilePublisherDocumented": (
            "profile-publisher" in lower_docs and "Profile Publisher" in docs_text
        ),
        "routeInContractOrRouter": route in source_text,
        "routeUsesVaultIdentityReadAndUseCapabilities": (
            route in contract_text
            and "VAULT_IDENTITIES_READ" in contract_text
            and "VAULT_IDENTITIES_USE" in contract_text
        ),
        "handlerOrTestEvidencePresent": "profile-document" in handler_text
        or "profile-document" in tests_text,
        "redactionDocumented": all(
            phrase in lower_docs
            for phrase in (
                "raw request bodies",
                "private keys",
                "signatures",
            )
        ),
    }
    details = {
        "route": "POST /api/v1" + route,
        "requiredCapabilities": ["vault.identities.read", "vault.identities.use"],
        "checks": checks,
        "redaction": {
            "rawRequestBodiesExcluded": True,
            "identityPrivateMaterialRedacted": True,
            "signatureValuesRedacted": True,
        },
        "sources": {
            "contract": display_path(
                workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java",
                workspace,
            ),
            "appVaultHandler": display_path(
                workspace
                / "platform-api/src/main/java/network/crypta/platform/api/appvault/AppVaultApiHandler.java",
                workspace,
            ),
            "docs": [
                display_path(workspace / "docs/app-secret-and-identity-vault.md", workspace),
                display_path(workspace / "docs/platform-api-contract.md", workspace),
                display_path(workspace / "docs/release-certification.md", workspace),
            ],
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-platform.identity-profile-publish",
            root_consequence(settings, "fail"),
            True,
            "Identity profile-document publish route evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.identity-profile-publish",
        "pass",
        True,
        "Identity profile-document publish route evidence passed.",
        source,
        details,
    )


def collect_generated_document_insert_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    route = "/queue/inserts/app-document"
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/platform-api-contract.md",
            "docs/platform-api-surface.md",
            "docs/platform-sdk-js.md",
            "docs/release-certification.md",
        )
    )
    contract_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    router_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java"
    )
    handler_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/queue/QueueApiHandler.java"
    )
    sdk_text = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    tests_text = "\n".join(
        read_source(path)
        for path in sorted((workspace / "platform-api/src/test/java").rglob("*.java"))
        if "Queue" in path.name or "Capabilities" in path.name or "Contract" in path.name
    )
    lower_docs = docs_text.lower()
    source_text = "\n".join((contract_text, router_text, handler_text, sdk_text, tests_text))
    checks = {
        "routeDocumented": "post /api/v1/queue/inserts/app-document" in lower_docs,
        "generatedDocumentScopeDocumented": (
            "app-generated document" in lower_docs and "local file path" in lower_docs
        ),
        "requiredCapabilitiesDocumented": (
            "content.insert.app-document" in docs_text and "queue.write" in docs_text
        ),
        "routeInContractOrRouter": route in source_text,
        "routeUsesAppDocumentInsertAndQueueWrite": (
            route in contract_text
            and "CONTENT_INSERT_APP_DOCUMENT" in contract_text
            and "QUEUE_WRITE" in contract_text
        ),
        "handlerOrTestEvidencePresent": "app-document" in handler_text
        or "app-document" in tests_text,
        "sdkOrGenericPostDocumented": (
            "queue/inserts/app-document" in sdk_text
            or "queue/inserts/app-document" in docs_text
        ),
        "redactionDocumented": all(
            phrase in lower_docs
            for phrase in (
                "raw request bodies",
                "private insert uris",
                "absolute staging paths",
            )
        ),
    }
    details = {
        "route": "POST /api/v1" + route,
        "requiredCapabilities": ["content.insert.app-document", "queue.write"],
        "checks": checks,
        "redaction": {
            "rawRequestBodiesExcluded": True,
            "privateInsertUrisExcluded": True,
            "absoluteStagingPathsExcluded": True,
            "signatureValuesRedacted": True,
        },
        "sources": {
            "contract": display_path(
                workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java",
                workspace,
            ),
            "queueHandler": display_path(
                workspace
                / "platform-api/src/main/java/network/crypta/platform/api/queue/QueueApiHandler.java",
                workspace,
            ),
            "docs": [
                display_path(workspace / "docs/platform-api-contract.md", workspace),
                display_path(workspace / "docs/platform-api-surface.md", workspace),
                display_path(workspace / "docs/release-certification.md", workspace),
            ],
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-platform.generated-document-insert",
            root_consequence(settings, "fail"),
            True,
            "App-generated document insert route evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.generated-document-insert",
        "pass",
        True,
        "App-generated document insert route evidence passed.",
        source,
        details,
    )


def collect_content_fetch_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    route = "/content/fetch"
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/platform-api-contract.md",
            "docs/platform-api-surface.md",
            "docs/platform-sdk-js.md",
            "docs/app-permissions-and-audit.md",
            "docs/feed-reader-reference-app.md",
            "docs/release-certification.md",
        )
    )
    contract_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    router_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java"
    )
    handler_text = "\n".join(
        read_source(path)
        for path in (
            workspace / "platform-api/src/main/java/network/crypta/platform/api/content/ContentApiHandler.java",
            workspace / "platform-api/src/main/java/network/crypta/platform/api/queue/QueueApiHandler.java",
        )
    )
    sdk_text = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    tests_text = "\n".join(
        read_source(path)
        for path in sorted((workspace / "platform-api/src/test/java").rglob("*.java"))
        if "Content" in path.name or "Capabilities" in path.name or "Contract" in path.name
    )
    lower_docs = docs_text.lower()
    source_text = "\n".join((contract_text, router_text, handler_text, sdk_text, tests_text))
    checks = {
        "routeDocumented": "post /api/v1/content/fetch" in lower_docs,
        "fetchScopeDocumented": "feed" in lower_docs and "content.fetch" in docs_text,
        "requiredCapabilitiesDocumented": "content.fetch" in docs_text,
        "routeInContractOrRouter": route in source_text,
        "routeUsesContentFetchCapability": (
            route in contract_text
            and ("CONTENT_FETCH" in contract_text or "content.fetch" in contract_text)
        ),
        "handlerOrTestEvidencePresent": (
            "content/fetch" in handler_text
            or "contentFetch" in handler_text
            or "ContentFetch" in handler_text
            or "content/fetch" in tests_text
            or "contentFetch" in tests_text
            or "ContentFetch" in tests_text
        ),
        "sdkFeedHelpersPresentOrDocumented": (
            "CryptaPlatform.feed" in sdk_text
            or "CryptaPlatform.feed" in docs_text
            or "content/fetch" in sdk_text
            or "content/fetch" in docs_text
        ),
        "redactionDocumented": all(
            phrase in lower_docs
            for phrase in (
                "raw feed bodies",
                "raw request bodies",
                "private insert uris",
                "browser-session tokens",
                "form passwords",
                "local paths",
            )
        ),
    }
    details = {
        "route": "POST /api/v1" + route,
        "requiredCapabilities": ["content.fetch"],
        "checks": checks,
        "redaction": {
            "rawFeedBodiesExcluded": True,
            "rawRequestBodiesExcluded": True,
            "privateInsertUrisExcluded": True,
            "appProcessTokensRedacted": True,
            "browserSessionTokensRedacted": True,
            "formPasswordsRedacted": True,
            "localPathsSanitized": True,
        },
        "sources": {
            "contract": display_path(
                workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java",
                workspace,
            ),
            "docs": [
                display_path(workspace / "docs/platform-api-contract.md", workspace),
                display_path(workspace / "docs/platform-api-surface.md", workspace),
                display_path(workspace / "docs/platform-sdk-js.md", workspace),
                display_path(workspace / "docs/feed-reader-reference-app.md", workspace),
                display_path(workspace / "docs/release-certification.md", workspace),
            ],
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-platform.content-fetch",
            root_consequence(settings, "fail"),
            True,
            "Content fetch route evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.content-fetch",
        "pass",
        True,
        "Content fetch route evidence passed.",
        source,
        details,
    )


def collect_content_subscription_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/platform-api-contract.md",
            "docs/platform-api-surface.md",
            "docs/platform-sdk-js.md",
            "docs/app-permissions-and-audit.md",
            "docs/feed-reader-reference-app.md",
            "docs/release-certification.md",
            "docs/app-platform-beta-known-limitations.md",
        )
    )
    contract_source = workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    capabilities_source = (
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiCapabilities.java"
    )
    router_source = workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java"
    content_routes_source = (
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContentRoutes.java"
    )
    service_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionService.java"
    )
    subscription_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscription.java"
    )
    handler_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionsApiHandler.java"
    )
    source_validator_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionSource.java"
    )
    sdk_source = (
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    router_test_source = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/PlatformApiContentSubscriptionsRouterTest.java"
    )
    service_test_source = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionServiceTest.java"
    )
    contract_text = read_source(contract_source)
    capabilities_text = read_source(capabilities_source)
    router_text = read_source(router_source)
    content_routes_text = router_text + "\n" + read_source(content_routes_source)
    service_text = read_source(service_source)
    subscription_text = read_source(subscription_source)
    handler_text = read_source(handler_source)
    source_validator_text = read_source(source_validator_source)
    sdk_text = read_source(sdk_source)
    tests_text = read_source(router_test_source) + "\n" + read_source(service_test_source)
    lower_docs = docs_text.lower()
    routes = (
        "/content/subscriptions",
        "/content/subscriptions/{subscriptionId}",
        "/content/subscriptions/{subscriptionId}/refresh",
        "/content/subscriptions/{subscriptionId}/pause",
        "/content/subscriptions/{subscriptionId}/resume",
    )
    checks = {
        "currentContractVersionV9": (
            "CURRENT_CONTRACT_VERSION = 9" in contract_text
            or "CURRENT_CONTRACT_VERSION = 10" in contract_text
            or "CURRENT_CONTRACT_VERSION = 11" in contract_text
            or "CURRENT_CONTRACT_VERSION = 12" in contract_text
            or "CURRENT_CONTRACT_VERSION = 13" in contract_text
            or "CURRENT_CONTRACT_VERSION = 14" in contract_text
            or "CURRENT_CONTRACT_VERSION = 15" in contract_text
            or "CURRENT_CONTRACT_VERSION = 16" in contract_text
        ),
        "capabilityDescriptorPresent": (
            "CONTENT_SUBSCRIBE" in contract_text
            and "CONTENT_SUBSCRIPTIONS_CONTRACT_VERSION = 8" in contract_text
            and "CONTENT_SUBSCRIBE" in capabilities_text
            and "content.subscribe" in capabilities_text
        ),
        "routesPresent": (
            all(route in contract_text for route in routes)
            and "content.subscriptions.create" in contract_text
            and "content.subscriptions.refresh" in contract_text
            and "content.subscriptions.delete" in contract_text
            and "routeContentSubscriptionsRequest" in content_routes_text
        ),
        "capabilityGatesPresent": (
            "CONTENT_SUBSCRIBE" in contract_text
            and "CONTENT_FETCH" in contract_text
            and "ContentSubscriptionService.CAPABILITY_CONTENT_SUBSCRIBE" in tests_text
            and "ContentSubscriptionService.CAPABILITY_CONTENT_FETCH" in tests_text
            and "route_whenAppLacksContentSubscribe_expectForbidden" in tests_text
            and "route_whenAppLacksContentFetchForCreate_expectForbidden" in tests_text
        ),
        "appPrincipalScoped": (
            "requireAppPrincipalId(request)" in content_routes_text
            and "PlatformApiPrincipal.hostOperator()" in tests_text
            and "route_whenAppReadsAnotherAppsSubscription_expectNotFound" in tests_text
        ),
        "serviceUnavailableStable": (
            "content_subscription_service_unavailable" in content_routes_text
            and "503" in content_routes_text
        ),
        "sourceValidationUskOnly": (
            "USK@" in source_validator_text
            and "crypta:" in source_validator_text
            and "hasDisallowedScheme" in source_validator_text
            and "containsWhitespace" in source_validator_text
            and "unsupported_content_subscription_source" in source_validator_text
            and ("unsupported" in tests_text or "Unsupported" in tests_text)
        ),
        "limitsAndMetadataOnly": (
            "perAppSubscriptionLimit" in service_text
            and "globalSubscriptionLimit" in service_text
            and "maxBytes" in service_text
            and "timeoutMillis" in service_text
            and "contentSha256" in service_text
            and "bytes.length" in service_text
            and "raw fetched content is digested and then discarded" in service_text
        ),
        "sdkHelpersPresent": (
            "CryptaPlatform.content.subscriptions" in docs_text
            and "content/subscriptions" in sdk_text
            and "contentSubscriptionPathSegment" in sdk_text
            and "apiDeleteForm" in sdk_text
        ),
        "docsDescribeRedactionAndNonGoals": all(
            phrase in lower_docs
            for phrase in (
                "raw fetched content",
                "raw request bodies",
                "browser-session tokens",
                "private insert uris",
                "queue html",
                "arbitrary http/https",
                "generic crawler",
            )
        ),
    }
    details = {
        "routes": [
            "GET /api/v1/content/subscriptions",
            "POST /api/v1/content/subscriptions",
            "GET /api/v1/content/subscriptions/{subscriptionId}",
            "POST /api/v1/content/subscriptions/{subscriptionId}/refresh",
            "POST /api/v1/content/subscriptions/{subscriptionId}/pause",
            "POST /api/v1/content/subscriptions/{subscriptionId}/resume",
            "DELETE /api/v1/content/subscriptions/{subscriptionId}",
        ],
        "requiredCapabilities": ["content.subscribe", "content.fetch for create/refresh"],
        "sourceScope": "USK@ and crypta:USK@ only",
        "checks": checks,
        "redaction": {
            "rawFetchedContentExcluded": True,
            "rawRequestBodiesExcluded": True,
            "browserSessionTokensRedacted": True,
            "appProcessTokensRedacted": True,
            "formPasswordsRedacted": True,
            "privateInsertUrisExcluded": True,
            "privateKeysExcluded": True,
            "absolutePathsExcluded": True,
            "queueHtmlExcluded": True,
        },
        "sources": {
            "contract": display_path(contract_source, workspace),
            "router": display_path(router_source, workspace),
            "contentRoutes": display_path(content_routes_source, workspace),
            "service": display_path(service_source, workspace),
            "handler": display_path(handler_source, workspace),
            "sourceValidator": display_path(source_validator_source, workspace),
            "sdk": display_path(sdk_source, workspace),
            "tests": [
                display_path(router_test_source, workspace),
                display_path(service_test_source, workspace),
            ],
        },
    }
    errors = [key for key, passed in checks.items() if passed is not True]
    if errors:
        return EvidenceItem(
            "app-platform.content-subscriptions",
            root_consequence(settings, "fail"),
            True,
            "Content subscription API evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.content-subscriptions",
        "pass",
        True,
        "Content subscription API evidence passed.",
        source,
        details,
    )


def collect_content_subscription_scheduler_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    scheduler_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionScheduler.java"
    )
    scheduler_config_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionSchedulerConfig.java"
    )
    service_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionService.java"
    )
    subscription_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscription.java"
    )
    store_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/FileContentSubscriptionStore.java"
    )
    pressure_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionPressureGate.java"
    )
    runtime_source = (
        workspace
        / "bridge-http-runtime/src/main/java/network/crypta/clients/http/bridge/CoreHttpShellRuntimeSupport.java"
    )
    scheduler_test_source = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionSchedulerTest.java"
    )
    service_test_source = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionServiceTest.java"
    )
    store_test_source = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/content/subscriptions/FileContentSubscriptionStoreTest.java"
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/platform-api-contract.md",
            "docs/platform-api-surface.md",
            "docs/release-certification.md",
            "docs/app-platform-beta-known-limitations.md",
        )
    )
    scheduler_text = read_source(scheduler_source)
    scheduler_config_text = read_source(scheduler_config_source)
    service_text = read_source(service_source)
    subscription_text = read_source(subscription_source)
    store_text = read_source(store_source)
    pressure_text = read_source(pressure_source)
    runtime_text = read_source(runtime_source)
    tests_text = "\n".join(
        read_source(path)
        for path in (scheduler_test_source, service_test_source, store_test_source)
    )
    lower_docs = docs_text.lower()
    checks = {
        "schedulerSourcePresent": (
            "public final class ContentSubscriptionScheduler" in scheduler_text
            and "ContentSubscriptionSchedulerConfig" in scheduler_text
            and "ContentSubscriptionPressureGate" in scheduler_text
        ),
        "deterministicTickAndNoOverlap": (
            "tick(Instant now)" in scheduler_text
            and "AtomicBoolean running" in scheduler_text
            and "compareAndSet(false, true)" in scheduler_text
            and "alreadyRunning" in scheduler_text
            and "overlapping" in tests_text
        ),
        "backgroundLifecycle": (
            "scheduleWithFixedDelay" in scheduler_text
            and "config.initialDelay().plus(jitter())" in scheduler_text
            and "shutdownNow()" in scheduler_text
            and "contentSubscriptionScheduler::close" in runtime_text
        ),
        "conservativeLimits": (
            "perTickFetchLimit" in scheduler_text
            and "perAppSubscriptionLimit" in scheduler_config_text
            and "globalSubscriptionLimit" in scheduler_config_text
            and "minimumPollInterval" in scheduler_config_text
            and "maximumFailureBackoff" in scheduler_config_text
            and "CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_PER_TICK_FETCH_LIMIT"
            in scheduler_config_text
        ),
        "dedupeAndMetadataOnly": (
            "contentChanged(" in service_text
            and "contentSha256" in subscription_text
            and "lastSeenEdition" in subscription_text
            and "lastSeenResolvedUri" in subscription_text
            and "updateCount" in subscription_text
            and "raw fetched content is digested and then discarded" in service_text
        ),
        "failureBackoff": (
            "failureBackoff(" in service_text
            and "withFailure" in service_text
            and "lastErrorCode" in store_text
            and "content_fetch_failed" in service_text
        ),
        "pressureGateStableSignals": (
            "QueueSupportPort" in pressure_text
            and "RequestQueuePort" in pressure_text
            and "isQueueBackendEnabled()" in pressure_text
            and "isPersistenceDatabaseKilled()" in pressure_text
            and "stopping()" in pressure_text
            and "awaitingPassword()" in pressure_text
            and "queueHtml" not in pressure_text
        ),
        "durablePathFreeStore": (
            "public final class FileContentSubscriptionStore" in store_text
            and "ATOMIC_MOVE" in store_text
            and "source URIs are never used as file names" in store_text
            and "content-subscriptions" in runtime_text
            and "layout.dataDir().resolve(\"apps\").resolve(\"content-subscriptions\")"
            in runtime_text
        ),
        "runtimeWiring": (
            "createContentSubscriptionService(" in runtime_text
            and "createContentSubscriptionScheduler(" in runtime_text
            and "contentSubscriptionScheduler.start()" in runtime_text
            and "contentSubscriptionService()" in runtime_text
        ),
        "focusedTestsPresent": (
            "tick_whenSubscriptionIsDue_expectOneBoundedFetchAndUpdatedMetadata" in tests_text
            and "tick_whenQueueBackendUnavailable_expectSafePressureSkip" in tests_text
            and "refresh_whenContentMetadataChanges_expectDigestEditionAndDedupe" in tests_text
            and "writeAndRead_whenSubscriptionContainsSourceUri_expectPathUsesAppAndSubscriptionIdsOnly"
            in tests_text
        ),
        "docsDescribeSchedulerRedaction": all(
            phrase in lower_docs
            for phrase in (
                "network-content.subscription-scheduler",
                "queue pressure",
                "no queue html",
                "raw fetched content",
                "path-free",
            )
        ),
    }
    details = {
        "policy": "bounded USK-only background polling with durable metadata, per-app/global/per-tick limits, and explicit pressure skips",
        "liveNodeRequired": False,
        "checks": checks,
        "sources": {
            "scheduler": display_path(scheduler_source, workspace),
            "schedulerConfig": display_path(scheduler_config_source, workspace),
            "service": display_path(service_source, workspace),
            "subscription": display_path(subscription_source, workspace),
            "store": display_path(store_source, workspace),
            "pressureGate": display_path(pressure_source, workspace),
            "runtime": display_path(runtime_source, workspace),
            "tests": [
                display_path(scheduler_test_source, workspace),
                display_path(service_test_source, workspace),
                display_path(store_test_source, workspace),
            ],
        },
    }
    errors = [key for key, passed in checks.items() if passed is not True]
    if errors:
        return EvidenceItem(
            "network-content.subscription-scheduler",
            root_consequence(settings, "fail"),
            True,
            "Content subscription scheduler evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "network-content.subscription-scheduler",
        "pass",
        True,
        "Content subscription scheduler passed deterministic offline evidence checks.",
        source,
        details,
    )


def collect_app_data_store_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    source_files = {
        "contract": workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java",
        "capabilities": workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiCapabilities.java",
        "router": workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java",
        "routes": workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiAppDataRoutes.java",
        "service": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataService.java",
        "exportPayload": workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataExportPayload.java",
        "fileStore": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/FileAppDataStore.java",
        "config": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataStoreConfig.java",
        "handler": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataApiHandler.java",
        "runtime": workspace
        / "bridge-http-runtime/src/main/java/network/crypta/clients/http/bridge/CoreHttpShellRuntimeSupport.java",
        "sdk": workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js",
        "docs": workspace / "docs/app-data-store.md",
        "contractDocs": workspace / "docs/platform-api-contract.md",
        "apiDocs": workspace / "docs/platform-api-surface.md",
        "routerTest": workspace / "platform-api/src/test/java/network/crypta/platform/api/PlatformApiAppDataRouterTest.java",
        "serviceTest": workspace
        / "platform-api/src/test/java/network/crypta/platform/api/appdata/AppDataServiceTest.java",
        "fileStoreTest": workspace
        / "platform-api/src/test/java/network/crypta/platform/api/appdata/FileAppDataStoreTest.java",
        "uninstallOptions": workspace
        / "platform-apphost/src/main/java/network/crypta/platform/apphost/AppUninstallOptions.java",
        "localAppHost": workspace
        / "platform-apphost/src/main/java/network/crypta/platform/apphost/runtime/LocalProcessAppHost.java",
    }
    text = {name: read_source(path) for name, path in source_files.items()}
    required_routes = (
        "/app-data/status",
        "/app-data/namespaces",
        "/app-data/namespaces/{namespace}",
        "/app-data/namespaces/{namespace}/schema",
        "/app-data/records",
        "/app-data/records/{namespace}/{key}",
        "/app-data/export",
        "/app-data/import",
    )
    checks = {
        "contractV9AndCapabilities": (
            (
                "CURRENT_CONTRACT_VERSION = 9" in text["contract"]
                or "CURRENT_CONTRACT_VERSION = 10" in text["contract"]
                or "CURRENT_CONTRACT_VERSION = 11" in text["contract"]
                or "CURRENT_CONTRACT_VERSION = 12" in text["contract"]
                or "CURRENT_CONTRACT_VERSION = 13" in text["contract"]
                or "CURRENT_CONTRACT_VERSION = 14" in text["contract"]
                or "CURRENT_CONTRACT_VERSION = 15" in text["contract"]
                or "CURRENT_CONTRACT_VERSION = 16" in text["contract"]
            )
            and "APP_DATA_STORE_CONTRACT_VERSION = 9" in text["contract"]
            and "app.data.read" in text["capabilities"]
            and "app.data.write" in text["capabilities"]
            and all(route in text["contract"] for route in required_routes)
        ),
        "routesRequireAppPrincipalAndCapabilities": (
            "PlatformApiAppDataRoutes" in text["router"]
            and "requireAppPrincipalId" in text["routes"]
            and "app.data.read" in text["capabilities"]
            and "app.data.write" in text["capabilities"]
            and (
                "PlatformApiCapabilities.APP_DATA_READ" in text["contract"]
                or "app.data.read" in text["contract"]
            )
            and (
                "PlatformApiCapabilities.APP_DATA_WRITE" in text["contract"]
                or "app.data.write" in text["contract"]
            )
        ),
        "fileBackedStoreIsPathSafeAndAtomic": (
            "sha256" in text["fileStore"].lower()
            and "ATOMIC_MOVE" in text["fileStore"]
            and "current.properties" in text["fileStore"]
            and ".cryptad-app-data" in text["fileStore"]
            and "value.bin" in text["fileStore"]
        ),
        "serviceBoundsQuotaAndImportExport": (
            "maxRecordBytes" in text["config"]
            and "maxRecordsPerApp" in text["config"]
            and "maxNamespacesPerApp" in text["config"]
            and "maxExportBytes" in text["config"]
            and "maxImportBytes" in text["config"]
            and "quota.data.bytes" in text["config"]
            and "app_data_import_app_mismatch" in text["exportPayload"]
        ),
        "schemaMigrationMetadata": (
            "updateSchema" in text["service"]
            and "fromSchemaVersion" in text["service"]
            and "toSchemaVersion" in text["service"]
            and "lastMigrationAt" in text["service"]
        ),
        "sdkHelpersExistAndAvoidBrowserStorage": (
            "data: Object.freeze" in text["sdk"]
            and "putAppDataJson" in text["sdk"]
            and "getAppDataJson" in text["sdk"]
            and "app-data/export" in text["sdk"]
            and "app-data/import" in text["sdk"]
            and "localStorage" not in text["sdk"]
            and "sessionStorage" not in text["sdk"]
        ),
        "testsCoverCoreSecurityAndPersistence": (
            "route_whenAppReadsAnotherAppsRecord_expectNotFound" in text["routerTest"]
            and "route_whenCapabilityMissingOrServiceUnavailable_expectDeniedOr503" in text["routerTest"]
            and "putRecord_whenIdentifierContainsTraversal_expectPathFreeValidationError" in text["serviceTest"]
            and "exportImport_whenPayloadRoundTrips_expectValuesCopiedAndOtherAppRejected" in text["serviceTest"]
            and "writeRecord_whenUnreferencedGenerationExists_expectCurrentRecordUnaffected" in text["fileStoreTest"]
        ),
        "runtimeAndUninstallWired": (
            "createAppDataService" in text["runtime"]
            and "durable-app-data" in text["runtime"]
            and "storeUsageOutsideAppDataDir" in text["service"]
            and "preserveData" in text["uninstallOptions"]
            and "options.preserveData()" in text["localAppHost"]
        ),
        "docsCoverLimitsAndRedaction": (
            "app.data.read" in text["docs"]
            and "cryptad.appData.maxRecordBytes" in text["docs"]
            and "Export and import" in text["docs"]
            and "Redaction rules" in text["docs"]
            and "not a filesystem API" in text["docs"]
            and "app-data" in text["contractDocs"]
            and "App data" in text["apiDocs"]
        ),
    }
    details = {
        "checks": checks,
        "routes": list(required_routes),
        "capabilities": ["app.data.read", "app.data.write"],
        "redaction": {
            "rawValuesExcludedFromEvidence": True,
            "rawRequestBodiesExcluded": True,
            "tokensExcluded": True,
            "privateInsertUrisExcluded": True,
            "absolutePathsExcluded": True,
        },
    }
    errors = [f"app data store check failed: {name}" for name, passed in checks.items() if passed is not True]
    if errors:
        return EvidenceItem(
            "app-platform.durable-app-data-store",
            root_consequence(settings, "fail"),
            True,
            "Durable app-data store evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.durable-app-data-store",
        "pass",
        True,
        "Durable app-data store evidence passed.",
        source,
        details,
    )


def collect_app_data_backup_restore_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    source_files = {
        "service": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataService.java",
        "workflow": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataBackupRestoreWorkflow.java",
        "store": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataStore.java",
        "fileStore": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/FileAppDataStore.java",
        "memoryStore": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/InMemoryAppDataStore.java",
        "bundle": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataBackupBundle.java",
        "entry": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataBackupEntry.java",
        "manifest": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataBackupManifest.java",
        "options": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataBackupOptions.java",
        "restoreMode": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataRestoreMode.java",
        "restorePlan": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataRestorePlan.java",
        "restoreResult": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataRestoreResult.java",
        "operatorRoutes": workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiOperatorRoutes.java",
        "toadlet": workspace / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/PlatformApiToadlet.java",
        "redactor": workspace / "platform-api/src/main/java/network/crypta/platform/api/operator/OperatorSupportRedactor.java",
        "serviceTest": workspace / "platform-api/src/test/java/network/crypta/platform/api/appdata/AppDataServiceTest.java",
        "fileStoreTest": workspace / "platform-api/src/test/java/network/crypta/platform/api/appdata/FileAppDataStoreTest.java",
        "operatorRoutesTest": workspace / "platform-api/src/test/java/network/crypta/platform/api/PlatformApiOperatorRoutesTest.java",
        "toadletTest": workspace / "src/test/java/network/crypta/clients/http/PlatformApiToadletTest.java",
        "redactorTest": workspace / "platform-api/src/test/java/network/crypta/platform/api/operator/OperatorSupportRedactorTest.java",
        "webShell": workspace / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js",
        "webShellIndex": workspace / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/index.html",
        "webShellTest": workspace / "platform-web-shell/src/test/java/network/crypta/platform/webshell/WebShellResourcesTest.java",
        "backupDoc": workspace / "docs/app-data-backup-restore-portability.md",
        "appDataDoc": workspace / "docs/app-data-store.md",
        "operatorDoc": workspace / "docs/operator-beta-dashboard.md",
        "developerPortal": workspace / "docs/app-platform-developer-portal.md",
        "releaseDoc": workspace / "docs/release-certification.md",
        "certReadme": workspace / "tools/release-certification/README.md",
        "profileReadme": workspace / "apps/profile-publisher/README.md",
        "feedReadme": workspace / "apps/feed-reader/README.md",
        "socialReadme": workspace / "apps/social-inbox/README.md",
        "trustReadme": workspace / "apps/trust-graph/README.md",
    }
    text = {name: read_source(path) for name, path in source_files.items()}
    docs_text = "\n".join(
        text[name]
        for name in ("backupDoc", "appDataDoc", "operatorDoc", "developerPortal", "releaseDoc", "certReadme")
    )
    reference_docs_text = "\n".join(
        text[name] for name in ("profileReadme", "feedReadme", "socialReadme", "trustReadme")
    )
    model_text = "\n".join(
        text[name]
        for name in (
            "bundle",
            "entry",
            "manifest",
            "options",
            "restoreMode",
            "restorePlan",
            "restoreResult",
        )
    )
    checks = {
        "versionedEnvelopeModels": (
            "record AppDataBackupBundle" in text["bundle"]
            and "record AppDataBackupEntry" in text["entry"]
            and "record AppDataBackupManifest" in text["manifest"]
            and "CURRENT_BACKUP_VERSION = 1" in text["manifest"]
            and "crypta-app-data-backup" in text["manifest"]
            and "sensitiveUserData" in text["manifest"]
            and "ENCRYPTION_MODE_NONE" in text["manifest"]
            and "unsupported_backup_encryption" in text["manifest"]
        ),
        "metadataToStringAndPlanOmitRawValues": (
            "export.toJsonValue()" in text["entry"]
            and "return \"AppDataBackupBundle[" in text["bundle"]
            and "return \"AppDataBackupEntry[" in text["entry"]
            and "record AppDataRestorePlan" in text["restorePlan"]
            and "record AppDataRestoreResult" in text["restoreResult"]
            and "without raw backup values" in text["restorePlan"]
            and "without raw backup values" in text["restoreResult"]
            and '"export"' not in text["restorePlan"]
            and '"payloadBase64"' not in text["restorePlan"]
            and '"export"' not in text["restoreResult"]
            and '"payloadBase64"' not in text["restoreResult"]
        ),
        "storeListsKnownAppIds": (
            "listAppIds()" in text["store"]
            and "List<String> listAppIds()" in text["fileStore"]
            and "List<String> listAppIds()" in text["memoryStore"]
            and "listAppIds_whenStoreHasKnownAndMalformedDirectories_expectOnlyNormalizedIds"
            in text["fileStoreTest"]
        ),
        "serviceExportsSingleAndAllBackups": (
            "exportBackup" in text["service"]
            and "backupRestoreWorkflow.exportBackup" in text["service"]
            and "createBackupBundle" in text["workflow"]
            and "AppDataBackupOptions.SCOPE_SINGLE_APP" in text["workflow"]
            and "AppDataBackupOptions.SCOPE_ALL_APPS" in text["workflow"]
            and "listStoreAppIds()" in text["workflow"]
            and "payloadBase64" in text["workflow"]
            and "exportBackup_whenSingleAppRequested_expectVersionedEnvelopeAndMetadataOnlyToString"
            in text["serviceTest"]
            and "exportBackup_whenAllAppsRequested_expectKnownAppIdsSorted" in text["serviceTest"]
        ),
        "restoreModesPlanAndCommitReuseValidation": (
            "enum AppDataRestoreMode" in text["restoreMode"]
            and "MERGE(\"merge\")" in text["restoreMode"]
            and "REPLACE_NAMESPACE(\"replaceNamespace\")" in text["restoreMode"]
            and "REPLACE_APP(\"replaceApp\")" in text["restoreMode"]
            and "planRestore" in text["service"]
            and "restoreBackup" in text["service"]
            and "preflightImport" in text["service"]
            and "preflightReplaceApp" in text["service"]
            and "replaceImportedNamespaces" in text["service"]
            and "replaceAppData" in text["service"]
            and "restoreBackup_whenReplaceApp_expectTargetAppClearedAndOtherAppsPreserved"
            in text["serviceTest"]
            and "restorePlan_whenBackupContainsRawValues_expectMetadataOnlyPlan" in text["serviceTest"]
        ),
        "operatorOnlyRoutesAndAppPrincipalDenied": (
            "operator/app-data" in text["operatorRoutes"]
            and '"backups".equals(segments.get(2))' in text["operatorRoutes"]
            and "methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE)" in text["operatorRoutes"]
            and '"restore".equals(segments.get(2))' in text["operatorRoutes"]
            and (
                'case "plan"' in text["operatorRoutes"]
                or '"plan".equals(segments.get(3))' in text["operatorRoutes"]
            )
            and "appDataService.planRestore" in text["operatorRoutes"]
            and "requireHostOperator(request)" in text["operatorRoutes"]
            and "app_data_service_unavailable" in text["operatorRoutes"]
            and "requiresOperatorFormPassword" in text["toadlet"]
            and '"backups".equals(pathSegments.get(2))' in text["toadlet"]
            and "/operator/app-data/backups" in text["toadletTest"]
            and "route_whenOperatorUsesAppDataBackupRestore_expectSensitiveBackupAndMetadataPlan"
            in text["operatorRoutesTest"]
            and "route_whenAppPrincipalRequestsAppDataBackupRestore_expectForbidden"
            in text["operatorRoutesTest"]
        ),
        "supportRedactionRecognizesBackupPayloads": (
            "crypta-app-data-backup" in text["redactor"]
            and "REDACTED_APP_DATA_BACKUP" in text["redactor"]
            and "backupbundle" in text["redactor"].lower()
            and "payloadbase64" in text["redactor"].lower()
            and "redact_whenBackupPayloadAccidentallyEntersSupportBundle_expectWholeBackupRedacted"
            in text["redactorTest"]
        ),
        "webShellExposesBackupRestoreAndNoPersistentBackupStorage": (
            "Download all app-data backup" in text["webShellIndex"]
            and "Sensitive backup payload" in text["webShellIndex"]
            and "function downloadAllAppDataBackup()" in text["webShell"]
            and "function submitAppDataRestoreForm(form, restoreAction, statusSetter)" in text["webShell"]
            and "operator/app-data/backups" in text["webShell"]
            and "operator/app-data/restore/plan" in text["webShell"]
            and "operator/app-data/restore" in text["webShell"]
            and "function appDataBackupPayloadBlob(response)" in text["webShell"]
            and "urlSafeBase64ToBytes(payloadBase64)" in text["webShell"]
            and 'downloadAppDataBackupPayload(response, "all-apps", "")' in text["webShell"]
            and 'downloadAppDataBackupPayload(response, "single-app", appId)' in text["webShell"]
            and "localStorage" in text["webShell"]
            and "backupPayload" in text["webShell"]
            and "sessionStorage" not in text["webShell"]
            and "IndexedDB" not in text["webShell"]
            and "Export backup before delete" in text["webShell"]
            and "assertAppDataBackupRestoreMarkersPresent(script)" in text["webShellTest"]
        ),
        "docsCoverFormatModesSensitivityAndExclusions": (
            "backupVersion" in docs_text
            and "crypta-app-data-backup" in docs_text
            and "single-app" in docs_text
            and "all-apps" in docs_text
            and "merge" in docs_text
            and "replaceNamespace" in docs_text
            and "replaceApp" in docs_text
            and "sensitive user data" in docs_text
            and "encryption.mode = none" in docs_text
            and "vault secrets" in docs_text
            and "private identity material" in docs_text
            and "support bundles" in docs_text
            and "release evidence" in docs_text
            and "operator-beta.app-data-backup-restore" in docs_text
            and "app-data.backup-restore-portability" in docs_text
        ),
        "firstPartyDocsDescribePortableScope": (
            reference_docs_text.count("App-data backup scope") >= 4
            and "vault private identity material" in reference_docs_text
            and "app-service tokens" in reference_docs_text
            and "UI-local" in reference_docs_text
        ),
    }
    details = {
        "checks": checks,
        "backupVersion": 1,
        "encryptionModesSupported": ["none"],
        "restoreModes": ["merge", "replaceNamespace", "replaceApp"],
        "operatorRouteTemplates": [
            "POST /api/v1/operator/app-data/backups appId=<app-id>",
            "POST /api/v1/operator/app-data/backups scope=all",
            "POST /api/v1/operator/app-data/restore/plan",
            "POST /api/v1/operator/app-data/restore",
        ],
        "redaction": {
            "rawBackupPayloadsExcludedFromEvidence": True,
            "supportBundlesExcludeBackupPayloads": True,
            "tokensExcluded": True,
            "privateInsertUrisExcluded": True,
            "absolutePathsExcluded": True,
        },
        "sources": {name: display_path(path, workspace) for name, path in source_files.items()},
    }
    errors = [key for key, passed in checks.items() if passed is not True]
    if errors:
        return EvidenceItem(
            "app-data.backup-restore-portability",
            root_consequence(settings, "fail"),
            True,
            "App-data backup/restore portability evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-data.backup-restore-portability",
        "pass",
        True,
        "App-data backup/restore portability evidence passed deterministic checks.",
        source,
        details,
    )


def read_json_file(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def ui_lint_report_errors(lint_json: dict[str, Any] | None, expected_app_id: str) -> list[str]:
    if lint_json is None:
        return [f"crypta-app ui lint JSON missing or malformed for {expected_app_id}"]
    errors: list[str] = []
    if lint_json.get("appId") != expected_app_id:
        errors.append(f"crypta-app ui lint JSON appId mismatch for {expected_app_id}")
    if lint_json.get("uiMode") != "static":
        errors.append(f"crypta-app ui lint JSON uiMode mismatch for {expected_app_id}")
    if lint_json.get("applicable") is not True:
        errors.append(f"crypta-app ui lint JSON applicability mismatch for {expected_app_id}")
    summary = lint_json.get("summary")
    if not isinstance(summary, dict):
        errors.append(
            f"crypta-app ui lint JSON summary missing or malformed for {expected_app_id}"
        )
    else:
        error_count = summary.get("errors")
        if not isinstance(error_count, int) or isinstance(error_count, bool) or error_count != 0:
            errors.append(f"crypta-app ui lint JSON reports nonzero errors for {expected_app_id}")
    findings = lint_json.get("findings")
    if not isinstance(findings, list):
        errors.append(
            f"crypta-app ui lint JSON findings missing or malformed for {expected_app_id}"
        )
    elif any(
        isinstance(finding, dict) and str(finding.get("severity", "")).lower() == "error"
        for finding in findings
    ):
        errors.append(
            f"crypta-app ui lint JSON findings include error severity for {expected_app_id}"
        )
    return errors


def collect_app_ui_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    source_ok, source_errors, source_details = check_source_static_ui(settings)
    staged_errors: list[str] = []
    staged_details: dict[str, Any] = {}
    for spec in first_party_app_specs(settings):
        static_dir = spec["stagedDir"] / "static"
        errors, details = validate_static_ui_files(static_dir, settings)
        staged_errors.extend(f"{spec['appId']}: {error}" for error in errors)
        staged_details[spec["appId"]] = details
    errors = source_errors + staged_errors
    details = {"sourceStaticUi": source_details, "stagedStaticUi": staged_details}
    if errors:
        return EvidenceItem(
            "app-ui.smoke",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "App-owned UI or SDK smoke found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem("app-ui.smoke", "pass", True, "App-owned UI and SDK smoke passed.", source, details)


def collect_reference_content_app_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "site-publisher"
        ),
        None,
    )
    details: dict[str, Any] = {
        "appId": "site-publisher",
        "checks": {},
    }
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-apps.content",
            root_consequence(settings, "fail"),
            True,
            "Site Publisher first-party app spec is missing.",
            source,
            details,
        )

    app_dir = settings.workspace_root / "apps/site-publisher"
    source_static_dir = spec["sourceDir"] / "static"
    staged_static_dir = spec["stagedDir"] / "static"
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    source_index = read_source(source_static_dir / "index.html")
    source_app_js = read_source(source_static_dir / "app.js")
    app_readme = read_source(app_dir / "README.md")
    manifest: dict[str, str] = {}
    manifest_permissions: set[str] = set()
    if manifest_path.is_file():
        try:
            manifest = parse_properties(manifest_path)
            manifest_permissions = parse_permission_set(manifest.get("app.permissions", ""))
        except ValueError as exc:
            errors.append(str(exc))
    details.update(
        {
            "sourceDir": display_path(spec["sourceDir"], settings.workspace_root),
            "stagedDir": display_path(spec["stagedDir"], settings.workspace_root),
            "expectedPermissions": sorted(spec["permissions"]),
        }
    )
    checks = details["checks"]
    checks["moduleExists"] = app_dir.is_dir()
    checks["stagedManifestPresent"] = manifest_path.is_file()
    checks["sourceStaticUiPresent"] = (source_static_dir / "index.html").is_file() and (
        source_static_dir / "app.js"
    ).is_file()
    checks["stagedSdkPresent"] = (staged_static_dir / "crypta-platform.js").is_file()
    checks["stagedDesignSystemPresent"] = all(
        (staged_static_dir / "crypta-ui" / asset_name).is_file()
        for asset_name in design_system_asset_names()
    )
    checks["usesContentInsertDirectory"] = "CryptaPlatform.content.insertDirectory" in source_app_js
    checks["usesContentInsertFile"] = "CryptaPlatform.content.insertFile" in source_app_js
    checks["usesUploadQueueSnapshot"] = "CryptaPlatform.queue.snapshot" in source_app_js
    checks["usesSdkBootstrap"] = "CryptaPlatform.bootstrap.load({ appId })" in source_app_js
    checks["noRawAdminApiReference"] = "/api/v1/" not in source_app_js
    checks["noPersistentBrowserStorage"] = all(
        forbidden not in source_app_js
        for forbidden in ("localStorage.setItem", "sessionStorage.setItem")
    )
    checks["noVaultCapabilitiesDeclared"] = bool(manifest) and not any(
        permission.startswith("vault.") for permission in manifest_permissions
    )
    disclosure = permission_disclosure_block(source_index)
    mentioned_permissions = set(
        re.findall(r"\b[a-z][a-z0-9._-]*\.[a-z][a-z0-9._-]*\b", disclosure)
    )
    checks["permissionDisclosureMentionsDeclaredPermissions"] = manifest_permissions.issubset(
        mentioned_permissions
    )
    checks["identityProfileDemoDocumentedFutureWork"] = (
        "Identity-backed" in app_readme and "future work" in app_readme
    )
    if manifest:
        details["manifest"] = {
            "appId": manifest.get("app.id"),
            "name": manifest.get("app.name"),
            "uiMode": manifest.get("app.ui.mode"),
            "uiEntry": manifest.get("app.ui.entry"),
            "permissions": sorted(manifest_permissions),
            "apiMinimumVersion": manifest.get("api.minimumVersion"),
            "apiMaximumTestedVersion": manifest.get("api.maximumTestedVersion"),
        }
        checks["manifestDeclaresSitePublisher"] = (
            manifest.get("app.id") == "site-publisher"
            and manifest.get("app.name") == "Site Publisher"
            and manifest.get("app.ui.mode") == "static"
            and manifest.get("app.ui.entry") == "static/index.html"
        )
        checks["manifestDeclaresContentPermissions"] = spec["permissions"].issubset(
            manifest_permissions
        )
    else:
        checks["manifestDeclaresSitePublisher"] = False
        checks["manifestDeclaresContentPermissions"] = False

    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"reference content app check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-apps.content",
            root_consequence(settings, "fail"),
            True,
            "Site Publisher reference content app evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-apps.content",
        "pass",
        True,
        "Site Publisher reference content app evidence passed.",
        source,
        details,
    )


def collect_profile_publisher_reference_app_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "profile-publisher"
        ),
        None,
    )
    details: dict[str, Any] = {
        "appId": "profile-publisher",
        "checks": {},
        "expectedPermissions": sorted(PROFILE_PUBLISHER_PERMISSIONS),
    }
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.profile-publisher",
            root_consequence(settings, "fail"),
            True,
            "Profile Publisher first-party app spec is missing.",
            source,
            details,
        )

    app_dir = settings.workspace_root / "apps/profile-publisher"
    source_static_dir = spec["sourceDir"] / "static"
    staged_static_dir = spec["stagedDir"] / "static"
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    source_index = read_source(source_static_dir / "index.html")
    source_app_js = read_source(source_static_dir / "app.js")
    app_readme = read_source(app_dir / "README.md")
    manifest: dict[str, str] = {}
    manifest_permissions: set[str] = set()
    if manifest_path.is_file():
        try:
            manifest = parse_properties(manifest_path)
            manifest_permissions = parse_permission_set(manifest.get("app.permissions", ""))
        except ValueError as exc:
            errors.append(str(exc))
    details.update(
        {
            "sourceDir": display_path(spec["sourceDir"], settings.workspace_root),
            "stagedDir": display_path(spec["stagedDir"], settings.workspace_root),
        }
    )
    checks = details["checks"]
    checks["moduleExists"] = app_dir.is_dir()
    checks["stagedManifestPresent"] = manifest_path.is_file()
    checks["sourceStaticUiPresent"] = (source_static_dir / "index.html").is_file() and (
        source_static_dir / "app.js"
    ).is_file()
    checks["stagedSdkPresent"] = (staged_static_dir / "crypta-platform.js").is_file()
    checks["stagedDesignSystemPresent"] = all(
        (staged_static_dir / "crypta-ui" / asset_name).is_file()
        for asset_name in design_system_asset_names()
    )
    checks["usesSdkBootstrap"] = "CryptaPlatform.bootstrap.load" in source_app_js
    checks["usesBrowserSafeIdentityCreation"] = (
        "app-vault/identities" in source_app_js
        or "createVaultIdentity" in source_app_js
        or "createIdentity" in source_app_js
        or "vault.identities.create" in source_app_js
    )
    checks["usesProfileDocumentRoute"] = (
        "profile-document" in source_app_js or "profileDocument" in source_app_js
    )
    checks["usesGeneratedDocumentInsertRoute"] = (
        "queue/inserts/app-document" in source_app_js
        or "insertAppDocument" in source_app_js
        or "publishSnapshot" in source_app_js
    )
    checks["usesUploadQueueSnapshot"] = "CryptaPlatform.queue.snapshot" in source_app_js
    checks["usesAppDataHelpers"] = (
        "CryptaPlatform.data.records.getJson" in source_app_js
        and "CryptaPlatform.data.records.putJson" in source_app_js
        and "lastPublishedProfileUri" in source_app_js
    )
    checks["noRawAdminApiReference"] = "/api/v1/" not in source_app_js
    checks["noPersistentBrowserStorage"] = all(
        forbidden not in source_app_js
        for forbidden in ("localStorage.setItem", "sessionStorage.setItem")
    )
    disclosure = permission_disclosure_block(source_index)
    mentioned_permissions = set(
        re.findall(r"\b[a-z][a-z0-9._-]*\.[a-z][a-z0-9._-]*\b", disclosure)
    )
    checks["permissionDisclosureMentionsDeclaredPermissions"] = manifest_permissions.issubset(
        mentioned_permissions
    )
    checks["readmeDocumentsProfilePublishingFlow"] = (
        "Profile Publisher" in app_readme
        and "profile-document" in app_readme
        and "app-document" in app_readme
        and "app-data" in app_readme
    )
    if manifest:
        details["manifest"] = {
            "appId": manifest.get("app.id"),
            "name": manifest.get("app.name"),
            "uiMode": manifest.get("app.ui.mode"),
            "uiEntry": manifest.get("app.ui.entry"),
            "permissions": sorted(manifest_permissions),
            "apiMinimumVersion": manifest.get("api.minimumVersion"),
            "apiMaximumTestedVersion": manifest.get("api.maximumTestedVersion"),
        }
        checks["manifestDeclaresProfilePublisher"] = (
            manifest.get("app.id") == "profile-publisher"
            and manifest.get("app.name") == "Profile Publisher"
            and manifest.get("app.ui.mode") == "static"
            and manifest.get("app.ui.entry") == "static/index.html"
        )
        checks["manifestDeclaresProfilePermissions"] = PROFILE_PUBLISHER_PERMISSIONS.issubset(
            manifest_permissions
        )
        checks["manifestUsesAppDataContract"] = (
            manifest.get("api.minimumVersion") == "9"
            and manifest.get("api.maximumTestedVersion")
            == str(CURRENT_PLATFORM_API_CONTRACT_VERSION)
        )
        checks["manifestAvoidsUnneededVaultManagement"] = not any(
            permission in manifest_permissions
            for permission in (
                "vault.secrets.read",
                "vault.secrets.write",
                "vault.identities.manage",
            )
        )
    else:
        checks["manifestDeclaresProfilePublisher"] = False
        checks["manifestDeclaresProfilePermissions"] = False
        checks["manifestUsesAppDataContract"] = False
        checks["manifestAvoidsUnneededVaultManagement"] = False

    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"profile publisher app check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.profile-publisher",
            root_consequence(settings, "fail"),
            True,
            "Profile Publisher reference app evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.profile-publisher",
        "pass",
        True,
        "Profile Publisher reference app evidence passed.",
        source,
        details,
    )


def collect_feed_reader_reference_app_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "feed-reader"
        ),
        None,
    )
    details: dict[str, Any] = {
        "appId": "feed-reader",
        "checks": {},
        "expectedPermissions": sorted(FEED_READER_PERMISSIONS),
    }
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.feed-reader",
            root_consequence(settings, "fail"),
            True,
            "Feed Reader first-party app spec is missing.",
            source,
            details,
        )

    app_dir = settings.workspace_root / "apps/feed-reader"
    source_static_dir = spec["sourceDir"] / "static"
    staged_static_dir = spec["stagedDir"] / "static"
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    source_index = read_source(source_static_dir / "index.html")
    source_app_js = read_source(source_static_dir / "app.js")
    reference_doc = read_source(settings.workspace_root / "docs/feed-reader-reference-app.md")
    manifest: dict[str, str] = {}
    manifest_permissions: set[str] = set()
    if manifest_path.is_file():
        try:
            manifest = parse_properties(manifest_path)
            manifest_permissions = parse_permission_set(manifest.get("app.permissions", ""))
        except ValueError as exc:
            errors.append(str(exc))
    details.update(
        {
            "sourceDir": display_path(spec["sourceDir"], settings.workspace_root),
            "stagedDir": display_path(spec["stagedDir"], settings.workspace_root),
        }
    )
    checks = details["checks"]
    checks["moduleExists"] = app_dir.is_dir()
    checks["stagedManifestPresent"] = manifest_path.is_file()
    checks["sourceStaticUiPresent"] = (source_static_dir / "index.html").is_file() and (
        source_static_dir / "app.js"
    ).is_file()
    checks["stagedSdkPresent"] = (staged_static_dir / "crypta-platform.js").is_file()
    checks["stagedDesignSystemPresent"] = all(
        (staged_static_dir / "crypta-ui" / asset_name).is_file()
        for asset_name in design_system_asset_names()
    )
    checks["usesSdkBootstrap"] = "CryptaPlatform.bootstrap.load" in source_app_js
    checks["usesContentFetchRouteOrHelper"] = (
        "CryptaPlatform.content.fetchText" in source_app_js
        or "CryptaPlatform.content.fetchBase64" in source_app_js
        or "CryptaPlatform.feed.fetchSnapshot" in source_app_js
        or "content/fetch" in source_app_js
    )
    checks["usesContentSubscriptionHelpers"] = (
        "CryptaPlatform.content.subscriptions" in source_app_js
        and "content.subscriptions.list" in source_app_js
        and "content.subscriptions.refresh" in source_app_js
    )
    checks["usesGeneratedDocumentInsertRoute"] = (
        "queue/inserts/app-document" in source_app_js
        or "insertAppDocument" in source_app_js
        or "publishSnapshot" in source_app_js
    )
    checks["usesUploadQueueSnapshot"] = "CryptaPlatform.queue.snapshot" in source_app_js
    checks["usesAppDataHelpers"] = (
        "CryptaPlatform.data.records.getJson" in source_app_js
        and "CryptaPlatform.data.records.putJson" in source_app_js
        and "lastPublisherDraft" in source_app_js
    )
    checks["noRawAdminApiReference"] = "/api/v1/" not in source_app_js
    checks["noPersistentBrowserStorage"] = all(
        forbidden not in source_app_js
        for forbidden in ("localStorage.setItem", "sessionStorage.setItem")
    )
    checks["noTabOnlyFollowTimer"] = "setInterval" not in source_app_js
    checks["docsDescribeFeedReaderFlow"] = (
        "Feed Reader" in reference_doc
        and "POST /api/v1/content/fetch" in reference_doc
        and "content.subscribe" in reference_doc
        and "content.fetch" in reference_doc
        and "app.data.read" in reference_doc
        and "raw feed bodies" in reference_doc
    )
    disclosure = permission_disclosure_block(source_index)
    mentioned_permissions = set(
        re.findall(r"\b[a-z][a-z0-9._-]*\.[a-z][a-z0-9._-]*\b", disclosure)
    )
    checks["permissionDisclosureMentionsDeclaredPermissions"] = manifest_permissions.issubset(
        mentioned_permissions
    )
    if manifest:
        details["manifest"] = {
            "appId": manifest.get("app.id"),
            "name": manifest.get("app.name"),
            "uiMode": manifest.get("app.ui.mode"),
            "uiEntry": manifest.get("app.ui.entry"),
            "permissions": sorted(manifest_permissions),
            "apiMinimumVersion": manifest.get("api.minimumVersion"),
            "apiMaximumTestedVersion": manifest.get("api.maximumTestedVersion"),
        }
        checks["manifestDeclaresFeedReader"] = (
            manifest.get("app.id") == "feed-reader"
            and manifest.get("app.name") == "Feed Reader & Publisher"
            and manifest.get("app.ui.mode") == "static"
            and manifest.get("app.ui.entry") == "static/index.html"
        )
        checks["manifestDeclaresFeedPermissions"] = FEED_READER_PERMISSIONS.issubset(
            manifest_permissions
        )
        checks["manifestUsesCertifiedApiRange"] = (
            manifest.get("api.minimumVersion") == "9"
            and manifest.get("api.maximumTestedVersion")
            == str(CURRENT_PLATFORM_API_CONTRACT_VERSION)
        )
    else:
        checks["manifestDeclaresFeedReader"] = False
        checks["manifestDeclaresFeedPermissions"] = False
        checks["manifestUsesCertifiedApiRange"] = False

    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"feed reader app check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.feed-reader",
            root_consequence(settings, "fail"),
            True,
            "Feed Reader reference app evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.feed-reader",
        "pass",
        True,
        "Feed Reader reference app evidence passed.",
        source,
        details,
    )


def collect_feed_reader_subscription_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "feed-reader"
        ),
        None,
    )
    details: dict[str, Any] = {
        "appId": "feed-reader",
        "checks": {},
        "expectedPermissions": sorted(FEED_READER_PERMISSIONS),
    }
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.feed-reader-subscriptions",
            root_consequence(settings, "fail"),
            True,
            "Feed Reader subscription evidence is missing its first-party app spec.",
            source,
            details,
        )

    workspace = settings.workspace_root
    source_static_dir = spec["sourceDir"] / "static"
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    source_index = read_source(source_static_dir / "index.html")
    source_app_js = read_source(source_static_dir / "app.js")
    reference_doc = read_source(workspace / "docs/feed-reader-reference-app.md")
    sdk_text = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    catalog_docs = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/app-catalogs.md",
            "docs/first-party-beta-catalog.md",
            "docs/release-certification.md",
        )
    )
    manifest: dict[str, str] = {}
    manifest_permissions: set[str] = set()
    if manifest_path.is_file():
        try:
            manifest = parse_properties(manifest_path)
            manifest_permissions = parse_permission_set(manifest.get("app.permissions", ""))
        except ValueError as exc:
            errors.append(str(exc))
    checks = details["checks"]
    checks["manifestDeclaresSubscribeAndV9"] = (
        manifest.get("app.id") == "feed-reader"
        and FEED_READER_PERMISSIONS.issubset(manifest_permissions)
        and manifest.get("api.minimumVersion") == "9"
        and manifest.get("api.maximumTestedVersion")
        == str(CURRENT_PLATFORM_API_CONTRACT_VERSION)
    )
    checks["uiDisclosesSubscribePermission"] = (
        "content.subscribe" in permission_disclosure_block(source_index)
        and (
            "Create platform USK subscription" in source_index
            or "content.subscriptions.create" in source_app_js
        )
    )
    checks["appUsesPlatformSubscriptionWorkflow"] = (
        "CryptaPlatform.content.subscriptions.create" in source_app_js
        and "CryptaPlatform.content.subscriptions.list" in source_app_js
        and "CryptaPlatform.content.subscriptions.refresh" in source_app_js
        and (
            "CryptaPlatform.content.subscriptions.pause" in source_app_js
            or 'mutateSubscription(subscriptionId, "pause"' in source_app_js
        )
        and (
            "CryptaPlatform.content.subscriptions.resume" in source_app_js
            or 'mutateSubscription(subscriptionId, "resume"' in source_app_js
        )
        and "CryptaPlatform.content.subscriptions.remove" in source_app_js
        and "lastSeenResolvedUri" in source_app_js
    )
    checks["noTabLocalFollowLoop"] = "setInterval" not in source_app_js
    checks["onDemandRenderStillUsesContentFetch"] = (
        "CryptaPlatform.content.fetchText" in source_app_js
        and "CryptaPlatform.feed.fetchSnapshot" in source_app_js
    )
    checks["sdkHelpersAvailable"] = (
        "subscriptions: Object.freeze" in sdk_text
        and "createContentSubscription" in sdk_text
        and "removeContentSubscription" in sdk_text
    )
    checks["docsDescribeSubscriptionFlow"] = (
        "content.subscribe" in reference_doc
        and "durable" in reference_doc.lower()
        and "metadata" in reference_doc.lower()
        and "raw feed bodies" in reference_doc
        and "reference-app.feed-reader-subscriptions" in catalog_docs
    )
    details["manifest"] = {
        "permissions": sorted(manifest_permissions),
        "apiMinimumVersion": manifest.get("api.minimumVersion"),
        "apiMaximumTestedVersion": manifest.get("api.maximumTestedVersion"),
    }
    details["redaction"] = {
        "rawFeedBodiesExcluded": True,
        "rawRequestBodiesExcluded": True,
        "tokensExcluded": True,
        "absolutePathsExcluded": True,
        "subscriptionMetadataOnly": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"feed reader subscription check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.feed-reader-subscriptions",
            root_consequence(settings, "fail"),
            True,
            "Feed Reader subscription workflow evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.feed-reader-subscriptions",
        "pass",
        True,
        "Feed Reader subscription workflow evidence passed.",
        source,
        details,
    )


def collect_feed_reader_app_data_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "feed-reader"
        ),
        None,
    )
    details: dict[str, Any] = {"appId": "feed-reader", "checks": {}}
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.feed-reader-app-data",
            root_consequence(settings, "fail"),
            True,
            "Feed Reader app-data evidence is missing its first-party app spec.",
            source,
            details,
        )
    workspace = settings.workspace_root
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    index = read_source(spec["sourceDir"] / "static/index.html")
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "apps/feed-reader/README.md",
            "docs/feed-reader-reference-app.md",
            "docs/app-data-store.md",
            "docs/release-certification.md",
        )
    )
    manifest = parse_properties(manifest_path) if manifest_path.is_file() else {}
    permissions = parse_permission_set(manifest.get("app.permissions", ""))
    checks = details["checks"]
    checks["manifestUsesAppDataContract"] = (
        manifest.get("api.minimumVersion") == "9"
        and manifest.get("api.maximumTestedVersion")
        == str(CURRENT_PLATFORM_API_CONTRACT_VERSION)
        and {"app.data.read", "app.data.write"}.issubset(permissions)
    )
    checks["usesSdkJsonRecordHelpers"] = (
        "CryptaPlatform.data.records.getJson" in app_js
        and "CryptaPlatform.data.records.putJson" in app_js
    )
    checks["persistsBoundedReaderState"] = all(
        fragment in app_js
        for fragment in (
            "const maxSources",
            "maxRememberedSnapshots",
            'const dataNamespace = "ui-state"',
            'const dataStateKey = "reader-state"',
            "lastPublisherDraft",
            "selectedSourceId",
            "fetchedSnapshots",
        )
    )
    checks["permissionDisclosureMentionsAppData"] = (
        "app.data.read" in permission_disclosure_block(index)
        and "app.data.write" in permission_disclosure_block(index)
    )
    checks["docsAndEvidenceMentionDurableAppData"] = (
        "reference-app.feed-reader-app-data" in docs_text
        and "app-data" in docs_text
        and "app.data.read" in docs_text
        and "raw feed bodies" in docs_text
    )
    checks["noBrowserStorageOrRawAdminPath"] = (
        "/api/v1/" not in app_js
        and "localStorage.setItem" not in app_js
        and "sessionStorage.setItem" not in app_js
    )
    details["redaction"] = {
        "rawFeedBodiesExcluded": True,
        "rawAppDataValuesExcluded": True,
        "privateInsertUrisExcluded": True,
        "absolutePathsExcluded": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"feed reader app-data check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.feed-reader-app-data",
            root_consequence(settings, "fail"),
            True,
            "Feed Reader durable app-data evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.feed-reader-app-data",
        "pass",
        True,
        "Feed Reader durable app-data evidence passed.",
        source,
        details,
    )


def collect_profile_publisher_app_data_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "profile-publisher"
        ),
        None,
    )
    details: dict[str, Any] = {"appId": "profile-publisher", "checks": {}}
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.profile-publisher-app-data",
            root_consequence(settings, "fail"),
            True,
            "Profile Publisher app-data evidence is missing its first-party app spec.",
            source,
            details,
        )
    workspace = settings.workspace_root
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    index = read_source(spec["sourceDir"] / "static/index.html")
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "apps/profile-publisher/README.md",
            "docs/app-platform-developer-portal.md",
            "docs/app-data-store.md",
            "docs/release-certification.md",
        )
    )
    manifest = parse_properties(manifest_path) if manifest_path.is_file() else {}
    permissions = parse_permission_set(manifest.get("app.permissions", ""))
    checks = details["checks"]
    checks["manifestUsesAppDataContract"] = (
        manifest.get("api.minimumVersion") == "9"
        and manifest.get("api.maximumTestedVersion")
        == str(CURRENT_PLATFORM_API_CONTRACT_VERSION)
        and {"app.data.read", "app.data.write"}.issubset(permissions)
    )
    checks["usesSdkJsonRecordHelpers"] = (
        "CryptaPlatform.data.records.getJson" in app_js
        and "CryptaPlatform.data.records.putJson" in app_js
    )
    checks["persistsBoundedDraftState"] = all(
        fragment in app_js
        for fragment in (
            'const dataNamespace = "profile-draft"',
            'const dataStateKey = "publisher-state"',
            "maxRecentActions",
            "lastPublishedProfileUri",
            "recentActions",
            "selectedIdentityId",
        )
    )
    checks["permissionDisclosureMentionsAppData"] = (
        "app.data.read" in permission_disclosure_block(index)
        and "app.data.write" in permission_disclosure_block(index)
    )
    checks["docsAndEvidenceMentionDurableAppData"] = (
        "reference-app.profile-publisher-app-data" in docs_text
        and "app-data" in docs_text
        and "AppVault" in docs_text
        and "app.data.write" in docs_text
    )
    checks["noBrowserStorageOrSecretPersistence"] = (
        "localStorage.setItem" not in app_js
        and "sessionStorage.setItem" not in app_js
        and "privateKey" not in app_js
        and "seed" not in app_js
    )
    details["redaction"] = {
        "rawProfileDraftExcluded": True,
        "identityPrivateMaterialExcluded": True,
        "privateInsertUrisExcluded": True,
        "absolutePathsExcluded": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"profile publisher app-data check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.profile-publisher-app-data",
            root_consequence(settings, "fail"),
            True,
            "Profile Publisher durable app-data evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.profile-publisher-app-data",
        "pass",
        True,
        "Profile Publisher durable app-data evidence passed.",
        source,
        details,
    )


def collect_trust_graph_reference_app_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "trust-graph"
        ),
        None,
    )
    details: dict[str, Any] = {
        "appId": "trust-graph",
        "checks": {},
        "expectedPermissions": sorted(TRUST_GRAPH_PERMISSIONS),
    }
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.trust-graph",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph Local RC first-party app spec is missing.",
            source,
            details,
        )

    app_dir = settings.workspace_root / "apps/trust-graph"
    source_static_dir = spec["sourceDir"] / "static"
    staged_static_dir = spec["stagedDir"] / "static"
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    source_index = read_source(source_static_dir / "index.html")
    source_app_js = read_source(source_static_dir / "app.js")
    app_readme = read_source(app_dir / "README.md")
    reference_doc = read_source(settings.workspace_root / "docs/trust-graph-preview.md")
    normalized_reference_doc = normalized_source_text(reference_doc)
    manifest: dict[str, str] = {}
    manifest_permissions: set[str] = set()
    if manifest_path.is_file():
        try:
            manifest = parse_properties(manifest_path)
            manifest_permissions = parse_permission_set(manifest.get("app.permissions", ""))
        except ValueError as exc:
            errors.append(str(exc))
    details.update(
        {
            "sourceDir": display_path(spec["sourceDir"], settings.workspace_root),
            "stagedDir": display_path(spec["stagedDir"], settings.workspace_root),
        }
    )
    checks = details["checks"]
    checks["moduleExists"] = app_dir.is_dir()
    checks["stagedManifestPresent"] = manifest_path.is_file()
    checks["sourceStaticUiPresent"] = (source_static_dir / "index.html").is_file() and (
        source_static_dir / "app.js"
    ).is_file()
    checks["stagedSdkPresent"] = (staged_static_dir / "crypta-platform.js").is_file()
    checks["stagedDesignSystemPresent"] = all(
        (staged_static_dir / "crypta-ui" / asset_name).is_file()
        for asset_name in design_system_asset_names()
    )
    checks["usesSdkBootstrap"] = "CryptaPlatform.bootstrap.load" in source_app_js
    checks["usesTrustHelpers"] = all(
        fragment in source_app_js
        for fragment in (
            "CryptaPlatform.trust.status",
            "CryptaPlatform.trust.anchors.list",
            "CryptaPlatform.trust.importStatement",
            "CryptaPlatform.trust.exchange.fetchAndImport",
            "CryptaPlatform.trust.audit.list",
            "CryptaPlatform.trust.score",
            "CryptaPlatform.trust.exchange.publish",
        )
    )
    checks["usesBoundedTrustSigningHelper"] = (
        "CryptaPlatform.trust.exchange.publish" in source_app_js
    )
    checks["usesTrustExchangeAndQueuePreview"] = (
        "CryptaPlatform.trust.exchange.fetchAndImport" in source_app_js
        and "CryptaPlatform.trust.exchange.subscriptions." in source_app_js
        and "CryptaPlatform.queue.snapshot" in source_app_js
    )
    checks["usesAppDataPreviewState"] = (
        "CryptaPlatform.data.records.getJson" in source_app_js
        and "CryptaPlatform.data.records.putJson" in source_app_js
        and "recentImports" in source_app_js
    )
    checks["noRawAdminApiReference"] = "/api/v1/" not in source_app_js
    checks["noPersistentBrowserStorage"] = all(
        forbidden not in source_app_js
        for forbidden in ("localStorage.setItem", "sessionStorage.setItem")
    )
    disclosure = permission_disclosure_block(source_index)
    mentioned_permissions = set(
        re.findall(r"\b[a-z][a-z0-9._-]*\.[a-z][a-z0-9._-]*\b", disclosure)
    )
    checks["permissionDisclosureMentionsDeclaredPermissions"] = manifest_permissions.issubset(
        mentioned_permissions
    )
    checks["docsDescribePreviewLimits"] = (
        "trust graph local rc" in normalized_reference_doc
        and "local anchors" in normalized_reference_doc
        and "no crawling" in normalized_reference_doc
        and "no global moderation" in normalized_reference_doc
        and (
            "local anchors only" in normalized_reference_doc
            or "trust anchors are local" in normalized_reference_doc
        )
        and "trust.read" in normalized_reference_doc
        and "trust.write" in normalized_reference_doc
        and "ui-local" in normalized_reference_doc
    )
    checks["docsDescribeTrustScoreService"] = (
        "trust score service" in normalized_reference_doc
        and "trust.score" in normalized_reference_doc
        and (
            "operator-approved app-service grants" in normalized_reference_doc
            or (
                "operator-reviewed grant bundles" in normalized_reference_doc
                and "active app-service grants" in normalized_reference_doc
            )
        )
        and "read-only" in normalized_reference_doc
    )
    checks["readmeDocumentsTrustFlow"] = (
        "Trust Graph Local RC" in app_readme
        and "trust-statement" in app_readme
        and "not global truth" in app_readme
        and "app-data" in app_readme
    )
    if manifest:
        details["manifest"] = {
            "appId": manifest.get("app.id"),
            "name": manifest.get("app.name"),
            "uiMode": manifest.get("app.ui.mode"),
            "uiEntry": manifest.get("app.ui.entry"),
            "permissions": sorted(manifest_permissions),
            "apiMinimumVersion": manifest.get("api.minimumVersion"),
            "apiMaximumTestedVersion": manifest.get("api.maximumTestedVersion"),
            "experimentalCapabilitiesAccepted": manifest.get(
                "api.experimentalCapabilitiesAccepted"
            ),
            "providedServices": manifest.get("app.services.provides"),
            "trustScoreService": manifest.get("app.service.trust-score.id"),
        }
        checks["manifestDeclaresTrustGraph"] = (
            manifest.get("app.id") == "trust-graph"
            and manifest.get("app.name") == "Trust Graph Local RC"
            and manifest.get("app.ui.mode") == "static"
            and manifest.get("app.ui.entry") == "static/index.html"
        )
        checks["manifestDeclaresTrustPermissions"] = TRUST_GRAPH_PERMISSIONS.issubset(
            manifest_permissions
        )
        checks["manifestUsesContractV10ThroughCurrent"] = (
            manifest.get("api.minimumVersion") == "10"
            and manifest.get("api.maximumTestedVersion")
            == str(CURRENT_PLATFORM_API_CONTRACT_VERSION)
            and manifest.get("api.experimentalCapabilitiesAccepted") == "true"
        )
        checks["manifestAdvertisesTrustScoreService"] = (
            manifest.get("app.services.provides") == "trust-score"
            and manifest.get("app.service.trust-score.id") == "trust.score"
            and manifest.get("app.service.trust-score.kind") == "platform-adapter"
            and manifest.get("app.service.trust-score.adapter") == "trust-graph.score"
            and manifest.get("app.service.trust-score.scopes") == "score.read"
        )
    else:
        checks["manifestDeclaresTrustGraph"] = False
        checks["manifestDeclaresTrustPermissions"] = False
        checks["manifestUsesContractV10ThroughCurrent"] = False
        checks["manifestAdvertisesTrustScoreService"] = False

    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"trust graph app check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.trust-graph",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph Local RC reference app evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.trust-graph",
        "pass",
        True,
        "Trust Graph Local RC reference app evidence passed.",
        source,
        details,
    )


def collect_trust_graph_app_data_preview_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "trust-graph"
        ),
        None,
    )
    details: dict[str, Any] = {"appId": "trust-graph", "checks": {}}
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.trust-graph-app-data-preview",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph app-data preview evidence is missing its first-party app spec.",
            source,
            details,
        )
    workspace = settings.workspace_root
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    index = read_source(spec["sourceDir"] / "static/index.html")
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "apps/trust-graph/README.md",
            "docs/trust-graph-preview.md",
            "docs/app-data-store.md",
            "docs/release-certification.md",
        )
    )
    docs_text_lower = normalized_source_text(docs_text)
    manifest = parse_properties(manifest_path) if manifest_path.is_file() else {}
    permissions = parse_permission_set(manifest.get("app.permissions", ""))
    checks = details["checks"]
    checks["manifestUsesAppDataContract"] = (
        manifest.get("api.minimumVersion") == "10"
        and manifest.get("api.maximumTestedVersion")
        == str(CURRENT_PLATFORM_API_CONTRACT_VERSION)
        and {"app.data.read", "app.data.write"}.issubset(permissions)
    )
    checks["usesSdkJsonRecordHelpers"] = (
        "CryptaPlatform.data.records.getJson" in app_js
        and "CryptaPlatform.data.records.putJson" in app_js
    )
    checks["persistsOnlyUiLocalPreviewState"] = all(
        fragment in app_js
        for fragment in (
            'const dataNamespace = "ui-state"',
            'const dataStateKey = "preview-state"',
            "lastDraft",
            "recentImports",
            "normalizeImportSummary",
        )
    ) and "privateInsertUri" not in app_js
    checks["permissionDisclosureMentionsAppData"] = (
        "app.data.read" in permission_disclosure_block(index)
        and "app.data.write" in permission_disclosure_block(index)
    )
    checks["docsSeparateAppDataAndTrustBackend"] = (
        "reference-app.trust-graph-app-data-preview" in docs_text
        and "ui-local" in docs_text_lower
        and (
            "separate from the platform trust graph backend" in docs_text_lower
            or (
                "app data remains separate" in docs_text_lower
                and "platform trust graph service state" in docs_text_lower
            )
        )
        and "durable local backend" in docs_text_lower
        and (
            "not a full web of trust" in docs_text_lower
            or (
                "does not crawl the network" in docs_text_lower
                and "no global moderation" in docs_text_lower
            )
        )
    )
    checks["noBrowserStorageOrRawAdminPath"] = (
        "/api/v1/" not in app_js
        and "localStorage.setItem" not in app_js
        and "sessionStorage.setItem" not in app_js
    )
    details["redaction"] = {
        "rawTrustStatementsExcluded": True,
        "uiLocalSummariesOnly": True,
        "identityPrivateMaterialExcluded": True,
        "absolutePathsExcluded": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"trust graph app-data preview check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.trust-graph-app-data-preview",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph app-data preview evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.trust-graph-app-data-preview",
        "pass",
        True,
        "Trust Graph UI-local app-data preview evidence passed.",
        source,
        details,
    )


def collect_trust_graph_preview_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    contract_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    capabilities_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiCapabilities.java"
    )
    router_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java"
    )
    route_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiTrustGraphRoutes.java"
    )
    handler_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/trust/TrustGraphApiHandler.java"
    )
    sdk_text = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    devtools_text = read_source(
        workspace
        / "platform-devtools/src/main/java/network/crypta/platform/devtools/devserver/MockPlatformApi.java"
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/trust-graph-preview.md",
            "docs/platform-api-contract.md",
            "docs/platform-sdk-js.md",
            "docs/app-permissions-and-audit.md",
            "docs/release-certification.md",
        )
    )
    normalized_docs_text = normalized_source_text(docs_text)
    route_source_text = router_text + "\n" + route_text
    checks = {
        "contractVersionV7": "TRUST_GRAPH_PREVIEW_CONTRACT_VERSION = 7" in contract_text,
        "capabilitiesPresent": "trust.read" in capabilities_text and "trust.write" in capabilities_text,
        "routesPresent": all(
            route in contract_text
            for route in (
                "/trust-graph/status",
                "/trust-graph/anchors",
                "/trust-graph/import",
                "/trust-graph/subjects",
                "/trust-graph/statements",
                "/trust-graph/score",
            )
        )
        and "trust-graph" in router_text
        and all(
            f'"{resource}"' in route_source_text or f"/trust-graph/{resource}" in route_source_text
            for resource in ("status", "anchors", "import", "subjects", "statements", "score")
        ),
        "capabilityGatesPresent": (
            "PlatformApiCapabilities.TRUST_READ" in contract_text
            and "PlatformApiCapabilities.TRUST_WRITE" in contract_text
        ),
        "handlerUsesTrustGraphModule": (
            "TrustStatementParser.parse" in handler_text
            and "TrustGraphScorer" in handler_text
            and "InMemoryTrustGraphStore" in handler_text
        ),
        "sdkTrustHelpersPresent": all(
            fragment in sdk_text
            for fragment in (
                "function trustStatus",
                "function addTrustAnchor",
                "function importTrustStatement",
                "function trustScore",
                "function publishTrustStatement",
            )
        ),
        "mockEndpointsPresent": all(
            fragment in devtools_text
            for fragment in (
                "/trust-graph/status",
                "/trust-graph/anchors",
                "/trust-graph/import",
                "/trust-graph/score",
            )
        ),
        "docsDescribeLimits": (
            "not a full web of trust" in normalized_docs_text
            and "old weboftrust plugin" in normalized_docs_text
            and "no fnp/fcp/wire protocol" in normalized_docs_text
            and "trust.read" in normalized_docs_text
            and "trust.write" in normalized_docs_text
        ),
        "redactionDocumented": (
            "raw trust statement bodies" in normalized_docs_text
            and "browser-session tokens" in normalized_docs_text
            and "form passwords" in normalized_docs_text
        ),
    }
    details = {"checks": checks, "routes": ["trust-graph/status", "trust-graph/score"]}
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-platform.trust-graph-preview",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph Preview Platform API evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.trust-graph-preview",
        "pass",
        True,
        "Trust Graph Preview Platform API evidence passed.",
        source,
        details,
    )


def collect_trust_graph_rc_scope_and_safety_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    trustgraph_dir = workspace / "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph"
    trustgraph_test_dir = workspace / "platform-trustgraph/src/test/java/network/crypta/platform/trustgraph"
    api_dir = workspace / "platform-api/src/main/java/network/crypta/platform/api"
    contract_text = read_source(api_dir / "PlatformApiContract.java")
    route_text = read_source(api_dir / "PlatformApiTrustGraphRoutes.java")
    handler_text = read_source(api_dir / "trust/TrustGraphApiHandler.java")
    app_service_adapter_text = read_source(
        api_dir / "appservices/TrustGraphScoreAppServiceAdapter.java"
    )
    store_text = read_source(trustgraph_dir / "TrustGraphStore.java")
    file_store_text = read_source(trustgraph_dir / "FileTrustGraphStore.java")
    memory_store_text = read_source(trustgraph_dir / "InMemoryTrustGraphStore.java")
    lifecycle_status_text = read_source(trustgraph_dir / "TrustStatementLifecycleStatus.java")
    lifecycle_record_text = read_source(trustgraph_dir / "TrustStatementLifecycleRecord.java")
    scorer_text = read_source(trustgraph_dir / "TrustGraphScorer.java")
    evidence_text = read_source(trustgraph_dir / "TrustGraphEvidence.java")
    score_text = read_source(trustgraph_dir / "TrustGraphScore.java")
    scorer_test_text = read_source(trustgraph_test_dir / "TrustGraphScorerTest.java")
    store_test_text = read_source(trustgraph_test_dir / "FileTrustGraphStoreTest.java")
    router_test_text = read_source(
        workspace / "platform-api/src/test/java/network/crypta/platform/api/TrustGraphApiRouterTest.java"
    )
    sdk_text = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    app_index = read_source(workspace / "apps/trust-graph/src/staged/static/index.html")
    app_js = read_source(workspace / "apps/trust-graph/src/staged/static/app.js")
    web_shell_text = read_source(
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/trust-graph-preview.md",
            "docs/app-platform-developer-portal.md",
            "docs/operator-beta-dashboard.md",
            "docs/release-certification.md",
            "tools/release-certification/README.md",
            "apps/trust-graph/README.md",
        )
    )
    ui_text = app_index + "\n" + app_js + "\n" + web_shell_text
    normalized_ui_text = normalized_source_text(ui_text)
    docs_lower = normalized_source_text(docs_text)
    checks = {
        "contractV15AndRoutesPresent": (
            "CURRENT_CONTRACT_VERSION = 16" in contract_text
            and "TRUST_GRAPH_RC_SCOPE_CONTRACT_VERSION = 15" in contract_text
            and "/trust-graph/statements/{fingerprint}" in contract_text
            and "/trust-graph/statements/{fingerprint}/deprecate" in contract_text
            and "/trust-graph/statements/{fingerprint}/revoke" in contract_text
            and "/trust-graph/statements/{fingerprint}/reactivate" in contract_text
            and "routeNestedResourceAction" in route_text
        ),
        "statusExposesLocalRcScope": all(
            fragment in handler_text
            for fragment in (
                '"trust-graph-local-rc"',
                '"local-rc"',
                "localAnchorsOnly",
                "importedStatementsOnly",
                "noCrawling",
                "noGlobalModeration",
                "noBlocking",
                "noRoutingDecisions",
                "noLegacyWoTCompatibility",
                "statementLifecycleJson",
                "maxEvidenceRows",
            )
        ),
        "lifecycleModelPresent": all(
            fragment in lifecycle_status_text + lifecycle_record_text
            for fragment in (
                "ACTIVE",
                "DEPRECATED",
                "REVOKED",
                "operator-local policy",
                "statementFingerprint",
                "reasonCode",
                "replacementUri",
                "actorAppId",
            )
        ),
        "storesPersistLifecycleAndSourceMetadata": all(
            fragment in store_text + file_store_text + memory_store_text
            for fragment in (
                "updateLifecycle",
                "lifecycleRecords",
                "sourceUriKind",
                "subscriptionId",
                "lastSeenAt",
                "maxLifecycleRecords",
                "writeLifecycleRecord",
                "loadLifecycleRecords",
                "normalizeSubscriptionId",
            )
        ),
        "testsCoverLifecyclePersistenceAndApi": (
            "reopen_whenStatementRevokedAndReimported_expectLifecycleDurableAndPreserved"
            in store_test_text
            and "route_whenWriterRevokesImportedStatement_expectLifecycleVisibleAndReimportDoesNotErase"
            in router_test_text
            and "route_whenReaderAttemptsLifecycleMutation_expectForbiddenBeforeHandler"
            in router_test_text
        ),
        "scorerExcludesUnsafeEvidenceWithReasons": all(
            fragment in scorer_text + evidence_text + score_text + scorer_test_text
            for fragment in (
                "nonContributingReasons",
                "unanchored",
                "unverified",
                "expired",
                "zero-confidence",
                "revoked",
                "deprecated",
                "evidenceTruncated",
                "MAX_EVIDENCE_ROWS",
                "score_whenAnchoredStatementRevoked_expectLifecycleBlocksContribution",
                "score_whenAnchoredStatementDeprecated_expectLifecycleBlocksContribution",
            )
        ),
        "sdkLifecycleHelpersPresent": all(
            fragment in sdk_text
            for fragment in (
                "function getTrustStatement",
                "function deprecateTrustStatement",
                "function revokeTrustStatement",
                "function reactivateTrustStatement",
                "trust-graph/statements/",
                "normalizeTrustLifecycleMutation",
                "subscriptionId",
            )
        ),
        "uiAndWebShellWarnLocalOnly": all(
            fragment in normalized_ui_text
            for fragment in (
                "trust graph local rc",
                "local trust only",
                "not global truth",
                "not moderation",
                "not blocking",
                "not routing policy",
                "no legacy wot",
                "statement lifecycle",
                "noncontributingreasons",
                "evidencetruncated",
            )
        )
        and "innerHTML" not in app_js,
        "trustScoreServiceRemainsReadOnly": (
            "TrustGraphApiHandler#score" in app_service_adapter_text
            and "redactedScore" in app_service_adapter_text
            and "updateLifecycle" not in app_service_adapter_text
            and "trust.write" not in app_service_adapter_text
            and "score.read" in app_service_adapter_text
        ),
        "docsDescribeRcNonGoalsAndRedaction": all(
            fragment in docs_lower
            for fragment in (
                "local rc",
                "no crawling",
                "no global moderation",
                "not blocking",
                "no routing decisions",
                "no legacy",
                "deprecated",
                "revoked",
                "non-contribution reason",
                "raw fetched content",
                "private insert uri",
                "app-platform.trust-graph-rc-scope-and-safety",
            )
        ),
    }
    details = {
        "checks": checks,
        "routes": [
            "GET /trust-graph/status",
            "GET /trust-graph/statements/{fingerprint}",
            "POST /trust-graph/statements/{fingerprint}/deprecate",
            "POST /trust-graph/statements/{fingerprint}/revoke",
            "POST /trust-graph/statements/{fingerprint}/reactivate",
        ],
        "scope": {
            "localAnchorsOnly": True,
            "importedStatementsOnly": True,
            "noCrawling": True,
            "noGlobalModeration": True,
            "noBlocking": True,
            "noRoutingDecisions": True,
            "noLegacyWoTCompatibility": True,
        },
        "redaction": {
            "rawStatementBodiesExcluded": True,
            "rawFetchedContentExcluded": True,
            "privateInsertUrisExcluded": True,
            "tokensExcluded": True,
            "absolutePathsExcluded": True,
            "rawAppDataBackupsExcluded": True,
        },
    }
    errors = [name for name, passed in checks.items() if passed is not True]
    if errors:
        return EvidenceItem(
            "app-platform.trust-graph-rc-scope-and-safety",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph Local RC scope and safety evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.trust-graph-rc-scope-and-safety",
        "pass",
        True,
        "Trust Graph Local RC scope and safety evidence passed.",
        source,
        details,
    )


def collect_trust_graph_durable_store_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    trustgraph_dir = workspace / "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph"
    api_dir = workspace / "platform-api/src/main/java/network/crypta/platform/api"
    bridge_text = read_source(
        workspace
        / "bridge-http-runtime/src/main/java/network/crypta/clients/http/bridge/CoreHttpShellRuntimeSupport.java"
    )
    store_text = read_source(trustgraph_dir / "FileTrustGraphStore.java")
    config_text = read_source(trustgraph_dir / "TrustGraphStoreConfig.java")
    audit_text = read_source(trustgraph_dir / "TrustGraphAuditEvent.java")
    store_test_text = read_source(
        workspace
        / "platform-trustgraph/src/test/java/network/crypta/platform/trustgraph/FileTrustGraphStoreTest.java"
    )
    shared_services_text = read_source(api_dir / "PlatformApiSharedAppServices.java")
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/trust-graph-preview.md",
            "docs/platform-api-contract.md",
            "docs/release-certification.md",
        )
    )
    normalized_docs_text = normalized_source_text(docs_text)
    checks = {
        "fileBackedStorePresent": (
            "class FileTrustGraphStore" in store_text and "implements TrustGraphStore" in store_text
        ),
        "persistsAnchorsStatementsAndAudit": all(
            fragment in store_text for fragment in ('"anchors"', '"statements"', '"audit"')
        ),
        "usesAtomicCrashSafeWrites": (
            "createTempFile" in store_text and "ATOMIC_MOVE" in store_text and "force(" in store_text
        ),
        "capsConfigured": all(
            fragment in config_text
            for fragment in (
                "maxStatements",
                "maxAnchors",
                "maxAuditEntries",
                "maxStoredDocumentBytes",
            )
        ),
        "redactedAuditModelPresent": (
            "record TrustGraphAuditEvent" in audit_text
            and "sourceUriHash" in audit_text
            and "sourceSummary" in audit_text
            and "signatureVerified" in audit_text
        ),
        "runtimeInjectsDurableStore": (
            "new FileTrustGraphStore" in bridge_text
            and 'resolve("apps")' in bridge_text
            and 'resolve("trust-graph")' in bridge_text
            and "new TrustGraphApiHandler" in bridge_text
        ),
        "sharedServicesCarryTrustHandler": (
            "TrustGraphApiHandler trustGraphApiHandler" in shared_services_text
        ),
        "durabilityTestsPresent": all(
            fragment in store_test_text
            for fragment in (
                "reopen_whenAnchorStored_expectAnchorDurable",
                "reopen_whenVerifiedStatementAndAnchorStored_expectScoreUsesDurableState",
                "importStatement_whenSameDocumentImportedTwice_expectMetadataReplacedWithoutDuplicate",
                "retention_whenCapsExceeded_expectOldestRecordsEvicted",
                "reopen_whenPersistedRecordIsCorrupt_expectRecordIgnoredSafely",
                "auditEvents_whenStoredAndReopened_expectBoundedNewestFirstAndRedacted",
                "auditEvents_whenDuplicateEventsEvicted_expectOnlyOnePersistedDuplicateDeleted",
            )
        ),
        "docsDescribeDurableLocalBackend": (
            (
                "durable file-backed preview store" in normalized_docs_text
                or "durable file-backed store" in normalized_docs_text
            )
            and "persists local trust anchors" in normalized_docs_text
            and "raw fetched content" in normalized_docs_text
            and "private insert uris" in normalized_docs_text
        ),
    }
    details = {
        "checks": checks,
        "storeType": "file",
        "safeFields": [
            "documentFingerprint",
            "payloadHash",
            "source",
            "sourceSummary",
            "signatureVerified",
        ],
        "redaction": {
            "rawTrustStatementsExcluded": True,
            "rawFetchedContentExcluded": True,
            "privateInsertUrisExcluded": True,
            "absolutePathsExcluded": True,
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-platform.trust-graph-durable-store",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph durable store evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.trust-graph-durable-store",
        "pass",
        True,
        "Trust Graph durable store evidence passed.",
        source,
        details,
    )


def collect_trust_graph_exchange_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    contract_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    router_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java"
    )
    route_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiTrustGraphRoutes.java"
    )
    handler_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/trust/TrustGraphApiHandler.java"
    )
    capabilities_test_text = read_source(
        workspace / "platform-api/src/test/java/network/crypta/platform/api/PlatformApiCapabilitiesTest.java"
    )
    router_test_text = read_source(
        workspace / "platform-api/src/test/java/network/crypta/platform/api/TrustGraphApiRouterTest.java"
    )
    sdk_text = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    sdk_test_text = read_source(
        workspace
        / "platform-sdk-js/src/test/java/network/crypta/platform/sdk/js/CryptaPlatformSdkResourceTest.java"
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/trust-graph-preview.md",
            "docs/platform-api-contract.md",
            "docs/platform-sdk-js.md",
            "docs/app-permissions-and-audit.md",
            "docs/release-certification.md",
        )
    )
    docs_text_lower = docs_text.lower()
    docs_text_compact = " ".join(docs_text_lower.split())
    route_source_text = router_text + "\n" + route_text
    checks = {
        "contractVersionV10": (
            "CURRENT_CONTRACT_VERSION = 16" in contract_text
            and "TRUST_GRAPH_EXCHANGE_CONTRACT_VERSION = 10" in contract_text
        ),
        "contractDescriptorsPresent": (
            "/trust-graph/import-uri" in contract_text
            and "/trust-graph/audit" in contract_text
            and "PlatformApiCapabilities.CONTENT_FETCH" in contract_text
            and "PlatformApiCapabilities.TRUST_READ" in contract_text
            and "PlatformApiCapabilities.TRUST_WRITE" in contract_text
        ),
        "routerRoutesPresent": (
            "importUri" in route_source_text
            and "/trust-graph/import-uri" in contract_text
            and 'envelope("audit"' in route_source_text
        ),
        "handlerUsesBoundedContentFetch": (
            "ContentFetchPort" in handler_text
            and "ContentApiHandler" in handler_text
            and "maxStoredDocumentBytes" in handler_text
            and "format" in handler_text
        ),
        "auditIsRedacted": (
            "TrustGraphAuditEvent" in handler_text
            and "redactedUriSummary" in handler_text
            and "sourceUriHash" in handler_text
        ),
        "capabilityTestsPresent": (
            (
                "trust-graph/import-uri" in capabilities_test_text
                or 'List.of("trust-graph", "import-uri")' in capabilities_test_text
            )
            and "content.fetch" in capabilities_test_text
            and (
                "trust-graph/audit" in capabilities_test_text
                or 'List.of("trust-graph", "audit")' in capabilities_test_text
            )
        ),
        "routerTestsPresent": (
            "route_whenImportUriHasContentFetchCapability" in router_test_text
            and "route_whenAuditReadAfterImport" in router_test_text
        ),
        "sdkExchangeHelpersPresent": all(
            fragment in sdk_text
            for fragment in (
                "function importTrustUri",
                "function trustAudit",
                "function publishTrustStatement",
                "function fetchAndImportTrustStatement",
                "function createTrustSubscription",
            )
        ),
        "sdkTestsPresent": (
            "classpathResource_whenTrustExchangeHelpersRequested" in sdk_test_text
            and "classpathResource_whenTrustExchangePublishSignsStatement" in sdk_test_text
        ),
        "docsDescribeExchangeLimits": (
            "contract v10" in docs_text_compact
            and (
                "does not crawl the network" in docs_text_compact
                or "does not discover statements by walking the network" in docs_text_compact
                or "no crawling" in docs_text_compact
                or "network crawling" in docs_text_compact
                or "does not crawl the network globally" in docs_text_compact
                or "global network crawling" in docs_text_compact
                or "background crawler" in docs_text_compact
            )
            and "raw fetched content" in docs_text_compact
            and "private insert uris" in docs_text_compact
        ),
    }
    details = {
        "checks": checks,
        "routes": ["POST /trust-graph/import-uri", "GET /trust-graph/audit"],
        "capabilities": ["trust.read", "trust.write", "content.fetch"],
        "redaction": {
            "rawFetchedContentExcluded": True,
            "rawTrustStatementsExcluded": True,
            "privateInsertUrisExcluded": True,
            "tokensExcluded": True,
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-platform.trust-graph-exchange",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph exchange evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.trust-graph-exchange",
        "pass",
        True,
        "Trust Graph exchange evidence passed.",
        source,
        details,
    )


def collect_trust_graph_durable_exchange_reference_app_evidence(
    settings: Settings,
) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "trust-graph"
        ),
        None,
    )
    details: dict[str, Any] = {"appId": "trust-graph", "checks": {}}
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.trust-graph-durable-exchange",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph durable exchange app evidence is missing its first-party app spec.",
            source,
            details,
        )
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    index = read_source(spec["sourceDir"] / "static/index.html")
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    manifest = parse_properties(manifest_path) if manifest_path.is_file() else {}
    permissions = parse_permission_set(manifest.get("app.permissions", ""))
    queue_preview_text = ""
    if "function renderQueue" in app_js and "function renderAudit" in app_js:
        queue_preview_text = app_js.split("function renderQueue", 1)[1].split(
            "function renderAudit", 1
        )[0]
    publication_summary_text = ""
    if "function publicationSummary" in app_js and "function queueSnapshotSummary" in app_js:
        publication_summary_text = app_js.split("function publicationSummary", 1)[1].split(
            "function queueSnapshotSummary", 1
        )[0]
    checks = details["checks"]
    checks["manifestUsesContractV10ThroughCurrent"] = (
        manifest.get("api.minimumVersion") == "10"
        and manifest.get("api.maximumTestedVersion")
        == str(CURRENT_PLATFORM_API_CONTRACT_VERSION)
    )
    checks["manifestDeclaresExchangePermissions"] = {
        "trust.read",
        "trust.write",
        "content.fetch",
        "content.subscribe",
        "content.insert.app-document",
        "queue.write",
        "vault.identities.use",
    }.issubset(permissions)
    checks["uiShowsDurabilityExchangeAndAudit"] = all(
        fragment in index
        for fragment in (
            "platform trust graph backend",
            "Exchange uses content fetch, insert, and subscription APIs",
            "Subscriptions",
            "Audit",
            "not global truth",
        )
    )
    checks["usesSdkExchangeHelpers"] = all(
        fragment in app_js
        for fragment in (
            "CryptaPlatform.trust.exchange.fetchAndImport",
            "CryptaPlatform.trust.exchange.publish",
            "CryptaPlatform.trust.exchange.subscriptions.list",
            "CryptaPlatform.trust.exchange.subscriptions.create",
            "CryptaPlatform.trust.audit.list",
        )
    )
    checks["noRawApiOrManualFetch"] = (
        "/api/v1/" not in app_js and "CryptaPlatform.content.fetchText" not in app_js
    )
    checks["noPersistentBrowserStorage"] = (
        "localStorage.setItem" not in app_js and "sessionStorage.setItem" not in app_js
    )
    checks["privateInsertUriNotPersisted"] = (
        "privateInsertUri" not in app_js
        and "lastDraft.publish = { authorIdentity" in app_js
        and "insertUri" not in app_js.split("lastDraft.publish = { authorIdentity", 1)[1].split("};", 1)[0]
    )
    checks["queuePreviewDoesNotShowInsertUri"] = (
        bool(queue_preview_text)
        and bool(publication_summary_text)
        and "insertUri" not in queue_preview_text
        and "insertUri" not in publication_summary_text
    )
    details["redaction"] = {
        "rawFetchedContentExcluded": True,
        "privateInsertUrisExcluded": True,
        "rawTrustStatementsExcludedFromUriImport": True,
        "browserStorageExcluded": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"trust graph durable exchange app check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.trust-graph-durable-exchange",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph durable exchange reference app evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.trust-graph-durable-exchange",
        "pass",
        True,
        "Trust Graph durable exchange reference app evidence passed.",
        source,
        details,
    )


def collect_trust_statement_signing_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    contract_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    vault_router_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiVaultRouter.java"
    )
    vault_handler_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appvault/AppVaultApiHandler.java"
    )
    request_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appvault/TrustStatementRequest.java"
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/trust-graph-preview.md",
            "docs/app-secret-and-identity-vault.md",
            "docs/SECURITY.md",
            "docs/release-certification.md",
        )
    )
    checks = {
        "routeInContract": "/app-vault/identities/{identityId}/trust-statement" in contract_text,
        "capabilitiesInContract": all(
            fragment in contract_text
            for fragment in (
                "PlatformApiCapabilities.TRUST_WRITE",
                "PlatformApiCapabilities.VAULT_IDENTITIES_READ",
                "PlatformApiCapabilities.VAULT_IDENTITIES_USE",
            )
        ),
        "routerDispatchesBoundedRoute": "trust-statement" in vault_router_text,
        "handlerSignsCanonicalPayload": (
            "TrustStatementRequest.fromQuery" in vault_handler_text
            and "TrustStatementCanonicalizer.canonicalPayloadBytes" in request_text
            and "TrustDocumentTypes.TRUST_STATEMENT_V1" in vault_handler_text
        ),
        "notGenericSigningRoute": (
            "not an arbitrary signing API" in request_text
            or "not generic arbitrary signing" in docs_text
        ),
        "docsRedactPrivateMaterial": (
            "private keys" in docs_text
            and "raw request bodies" in docs_text
            and "raw signatures" in docs_text
        ),
    }
    details = {"checks": checks, "route": "app-vault/identities/{identityId}/trust-statement"}
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-platform.trust-statement-signing",
            root_consequence(settings, "fail"),
            True,
            "Trust statement signing evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.trust-statement-signing",
        "pass",
        True,
        "Trust statement signing evidence passed.",
        source,
        details,
    )


def social_inbox_spec(settings: Settings) -> dict[str, Any] | None:
    return next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "social-inbox"
        ),
        None,
    )


def collect_social_message_signing_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    contract_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    vault_router_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiVaultRouter.java"
    )
    vault_handler_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appvault/AppVaultApiHandler.java"
    )
    request_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appvault/SocialMessageRequest.java"
    )
    builder_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appvault/SignedSocialMessageDocumentBuilder.java"
    )
    sdk_text = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    tests_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "platform-api/src/test/java/network/crypta/platform/api/appvault/SocialMessageRequestTest.java",
            "platform-api/src/test/java/network/crypta/platform/api/appvault/SignedSocialMessageDocumentBuilderTest.java",
            "platform-api/src/test/java/network/crypta/platform/api/AppVaultApiRouterTest.java",
            "platform-sdk-js/src/test/java/network/crypta/platform/sdk/js/CryptaPlatformSdkResourceTest.java",
        )
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/social-inbox-reference-app.md",
            "docs/app-secret-and-identity-vault.md",
            "docs/platform-api-contract.md",
            "docs/release-certification.md",
        )
    )
    checks = {
        "routeInContract": "/app-vault/identities/{identityId}/social-message" in contract_text,
        "contractVersionV11": "CURRENT_CONTRACT_VERSION = 16" in contract_text
        and "SOCIAL_MESSAGE_CONTRACT_VERSION = 11" in contract_text,
        "capabilitiesInContract": all(
            fragment in contract_text
            for fragment in (
                "PlatformApiCapabilities.VAULT_IDENTITIES_READ",
                "PlatformApiCapabilities.VAULT_IDENTITIES_USE",
            )
        ),
        "routerDispatchesBoundedRoute": "social-message" in vault_router_text,
        "handlerUsesFixedDomainAppVaultSigning": (
            "SocialMessageRequest.fromQuery" in vault_handler_text
            and "SocialMessageRequest.SIGNING_PURPOSE" in vault_handler_text
            and "signDomainSeparatedPayload" in vault_handler_text
        ),
        "requestRejectsGenericSigningInputs": (
            "ALLOWED_PARAMETERS" in request_text
            and "purpose" in tests_text
            and "payloadBase64" in tests_text
            and "crypta.social.message.v1" in request_text
        ),
        "builderReturnsPublicDocumentOnly": (
            "publicKeyBase64" in builder_text
            and "signatureBase64" in builder_text
            and "domainSeparatedPayload" in tests_text
            and "privateKey" in tests_text
        ),
        "sdkHelperUsesBoundedRoute": (
            "createSocialMessageDocument" in sdk_text
            and "/social-message" in sdk_text
            and "normalizeSocialMessageDocument" in sdk_text
        ),
        "docsDescribeBoundedSigningBoundary": (
            "crypta.social.message.v1" in docs_text
            and "not a generic browser signing API" in docs_text
            and "private key material" in docs_text
        ),
    }
    details = {
        "checks": checks,
        "route": "app-vault/identities/{identityId}/social-message",
        "domain": "crypta.social.message.v1",
        "contractVersion": 11,
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-platform.social-message-signing",
            root_consequence(settings, "fail"),
            True,
            "Social message signing evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.social-message-signing",
        "pass",
        True,
        "Social message signing evidence passed.",
        source,
        details,
    )


def collect_social_inbox_reference_app_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = social_inbox_spec(settings)
    details: dict[str, Any] = {
        "appId": "social-inbox",
        "checks": {},
        "expectedPermissions": sorted(SOCIAL_INBOX_PERMISSIONS),
    }
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.social-inbox",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox first-party app spec is missing.",
            source,
            details,
        )

    workspace = settings.workspace_root
    app_dir = workspace / "apps/social-inbox"
    source_static_dir = spec["sourceDir"] / "static"
    staged_static_dir = spec["stagedDir"] / "static"
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    source_index = read_source(source_static_dir / "index.html")
    source_app_js = read_source(source_static_dir / "app.js")
    app_readme = read_source(app_dir / "README.md")
    reference_doc = read_source(workspace / "docs/social-inbox-reference-app.md")
    manifest: dict[str, str] = {}
    manifest_permissions: set[str] = set()
    if manifest_path.is_file():
        try:
            manifest = parse_properties(manifest_path)
            manifest_permissions = parse_permission_set(manifest.get("app.permissions", ""))
        except ValueError as exc:
            errors.append(str(exc))
    details.update(
        {
            "sourceDir": display_path(spec["sourceDir"], workspace),
            "stagedDir": display_path(spec["stagedDir"], workspace),
        }
    )
    disclosure = permission_disclosure_block(source_index)
    mentioned_permissions = set(
        re.findall(r"\b[a-z][a-z0-9._-]*\.[a-z][a-z0-9._-]*\b", disclosure)
    )
    checks = details["checks"]
    checks["moduleExists"] = app_dir.is_dir()
    checks["stagedManifestPresent"] = manifest_path.is_file()
    checks["sourceStaticUiPresent"] = (source_static_dir / "index.html").is_file() and (
        source_static_dir / "app.js"
    ).is_file()
    checks["stagedSdkPresent"] = (staged_static_dir / "crypta-platform.js").is_file()
    checks["stagedDesignSystemPresent"] = all(
        (staged_static_dir / "crypta-ui" / asset_name).is_file()
        for asset_name in design_system_asset_names()
    )
    checks["usesSdkBootstrap"] = "CryptaPlatform.bootstrap.load({ appId })" in source_app_js
    checks["usesAppVaultIdentityFlow"] = all(
        fragment in source_app_js
        for fragment in (
            "CryptaPlatform.vault.identities.list",
            "CryptaPlatform.vault.identities.create",
            "CryptaPlatform.vault.identities.createSocialMessageDocument",
        )
    )
    checks["usesProfileMetadataFlow"] = "createProfileDocument" in source_app_js
    checks["usesGeneratedOutboxInsert"] = (
        "CryptaPlatform.content.insertAppDocument" in source_app_js
        and "application/vnd.crypta.social.outbox+json" in source_app_js
        and "social-outbox.json" in source_app_js
    )
    checks["usesSubscriptionAndFetchFlow"] = all(
        fragment in source_app_js
        for fragment in (
            "CryptaPlatform.content.subscriptions.create",
            "CryptaPlatform.content.subscriptions.refresh",
            "CryptaPlatform.content.subscriptions.pause",
            "CryptaPlatform.content.subscriptions.resume",
            "CryptaPlatform.content.subscriptions.remove",
            "CryptaPlatform.content.fetchText",
            "lastSeenResolvedUri",
        )
    )
    checks["usesDurableAppData"] = all(
        fragment in source_app_js
        for fragment in (
            "CryptaPlatform.data.records.getJson",
            "CryptaPlatform.data.records.putJson",
            "ui-state\", \"social-inbox\"",
            "social\", \"sources\"",
            "social\", \"outbox-summary\"",
            "social\", \"imported-message-index\"",
            "social\", \"read-state\"",
            "social\", \"drafts\"",
        )
    )
    checks["usesTrustAnnotations"] = (
        "CryptaPlatform.services.invoke" in source_app_js
        and "CryptaPlatform.services.bundles.request" in source_app_js
        and "trustScoreProviderAppId = \"trust-graph\"" in source_app_js
        and "trustScoreServiceId = \"trust.score\"" in source_app_js
        and "trustScoreContext = \"message-author\"" in source_app_js
        and "subjectKind: \"identity\"" in source_app_js
        and "CryptaPlatform.trust.score" not in source_app_js
    )
    checks["usesQueueSummary"] = "CryptaPlatform.queue.snapshot" in source_app_js
    checks["permissionDisclosureMentionsDeclaredPermissions"] = manifest_permissions.issubset(
        mentioned_permissions
    )
    checks["previewAndNonGoalCopyPresent"] = all(
        fragment in source_index + "\n" + app_readme + "\n" + reference_doc
        for fragment in (
            "social/mail-like",
            "migration",
            "not full WoT",
            "Freetalk",
            "Sone",
            "Freemail",
            "encrypted mail",
            "daemon-core message store",
            "network protocol",
        )
    )
    checks["noRawAdminOrBrowserStorage"] = all(
        forbidden not in source_app_js
        for forbidden in (
            "/api/v1/",
            "localStorage",
            "sessionStorage",
            "indexedDB",
            "document.cookie",
            "innerHTML",
            "insertAdjacentHTML",
            "CRYPTAD_APP_TOKEN",
        )
    )
    if manifest:
        details["manifest"] = {
            "appId": manifest.get("app.id"),
            "name": manifest.get("app.name"),
            "uiMode": manifest.get("app.ui.mode"),
            "uiEntry": manifest.get("app.ui.entry"),
            "permissions": sorted(manifest_permissions),
            "apiMinimumVersion": manifest.get("api.minimumVersion"),
            "apiMaximumTestedVersion": manifest.get("api.maximumTestedVersion"),
            "experimentalCapabilitiesAccepted": manifest.get(
                "api.experimentalCapabilitiesAccepted"
            ),
            "serviceRequests": manifest.get("app.services.requests"),
            "trustScoreRequest": manifest.get("app.service-request.trust-score.service"),
        }
        checks["manifestDeclaresSocialInbox"] = (
            manifest.get("app.id") == "social-inbox"
            and manifest.get("app.name") in SOCIAL_INBOX_DISPLAY_NAMES
            and manifest.get("app.ui.mode") == "static"
            and manifest.get("app.ui.entry") == "static/index.html"
        )
        checks["manifestDeclaresSocialPermissions"] = SOCIAL_INBOX_PERMISSIONS.issubset(
            manifest_permissions
        )
        checks["manifestUsesContractV16"] = (
            manifest.get("api.minimumVersion") == "16"
            and manifest.get("api.maximumTestedVersion")
            == str(CURRENT_PLATFORM_API_CONTRACT_VERSION)
            and manifest.get("api.experimentalCapabilitiesAccepted") == "true"
        )
        checks["manifestDeclaresTrustScoreServiceRequest"] = (
            manifest.get("app.services.requests") == "trust-score"
            and manifest.get("app.service-request.trust-score.provider") == "trust-graph"
            and manifest.get("app.service-request.trust-score.service") == "trust.score"
            and manifest.get("app.service-request.trust-score.scopes") == "score.read"
            and manifest.get("app.service-request.trust-score.contexts") == "message-author"
        )
    else:
        checks["manifestDeclaresSocialInbox"] = False
        checks["manifestDeclaresSocialPermissions"] = False
        checks["manifestUsesContractV16"] = False
        checks["manifestDeclaresTrustScoreServiceRequest"] = False

    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"social inbox app check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.social-inbox",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox reference app evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.social-inbox",
        "pass",
        True,
        "Social Inbox reference app evidence passed.",
        source,
        details,
    )


def collect_social_inbox_signed_message_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = social_inbox_spec(settings)
    details: dict[str, Any] = {"appId": "social-inbox", "checks": {}}
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.social-inbox-signed-message",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox signed-message evidence is missing its first-party app spec.",
            source,
            details,
        )
    workspace = settings.workspace_root
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    reference_doc = read_source(workspace / "docs/social-inbox-reference-app.md")
    request_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appvault/SocialMessageRequest.java"
    )
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    manifest = parse_properties(manifest_path) if manifest_path.is_file() else {}
    permissions = parse_permission_set(manifest.get("app.permissions", ""))
    checks = details["checks"]
    checks["manifestAllowsBoundedSigning"] = (
        {"vault.identities.read", "vault.identities.use"}.issubset(permissions)
        and manifest.get("api.minimumVersion") in {"11", "12", "16"}
    )
    checks["usesSdkBoundedSigner"] = (
        "CryptaPlatform.vault.identities.createSocialMessageDocument" in app_js
        and "ensureSignedSocialMessage" in app_js
        and "signature.domain !== socialMessageType" in app_js
    )
    checks["verifiesImportedMessageSignatures"] = (
        "verifySocialMessageSignature" in app_js
        and "canonicalSocialMessagePayload" in app_js
        and "expectedSocialMessageId" in app_js
        and "canonicalSocialMessageIdPayload" in app_js
        and "messageIdPattern" in app_js
        and "Social message id does not match canonical payload." in app_js
        and "window.crypto.subtle.verify" in app_js
        and "signature.publicKeyFingerprint !== message.authorFingerprint" in app_js
        and "const publicKeyBytes = decodeBase64(signature.publicKeyBase64" in app_js
        and "const publicKeyFingerprint = await sha256Hex(publicKeyBytes)" in app_js
        and "publicKeyFingerprint !== stringValue(signature.publicKeyFingerprint)" in app_js
    )
    checks["documentShapeIsBounded"] = all(
        fragment in request_text
        for fragment in (
            "MAX_BODY_LENGTH = 4096",
            "MAX_SUBJECT_LENGTH = 160",
            "MAX_TAG_COUNT = 12",
            "MAX_SIGNED_PAYLOAD_BYTES",
            "FORMAT_TEXT_PLAIN",
        )
    ) and "requireIsoTimestamp" in app_js
    checks["docsDescribeSignedMessageFormat"] = (
        "Signed social message document" in reference_doc
        and "crypta.social.message.v1" in reference_doc
        and "domain-separated" in reference_doc
    )
    details["redaction"] = {
        "privateIdentityMaterialExcluded": True,
        "genericSigningInputsExcluded": True,
        "rawSignatureValuesExcluded": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"social inbox signed-message check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.social-inbox-signed-message",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox signed-message evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.social-inbox-signed-message",
        "pass",
        True,
        "Social Inbox signed-message evidence passed.",
        source,
        details,
    )


def collect_social_inbox_subscriptions_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = social_inbox_spec(settings)
    details: dict[str, Any] = {"appId": "social-inbox", "checks": {}}
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.social-inbox-subscriptions",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox subscription evidence is missing its first-party app spec.",
            source,
            details,
        )
    workspace = settings.workspace_root
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    index = read_source(spec["sourceDir"] / "static/index.html")
    reference_doc = read_source(workspace / "docs/social-inbox-reference-app.md")
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    manifest = parse_properties(manifest_path) if manifest_path.is_file() else {}
    permissions = parse_permission_set(manifest.get("app.permissions", ""))
    checks = details["checks"]
    checks["manifestDeclaresSubscriptionPermissions"] = {
        "content.fetch",
        "content.subscribe",
    }.issubset(permissions)
    checks["uiDisclosesSubscriptionWorkflow"] = (
        "content.subscribe" in permission_disclosure_block(index)
        and "USK social sources" in index
        and "Sources and subscriptions" in index
    )
    checks["appUsesPlatformSubscriptionLifecycle"] = all(
        fragment in app_js
        for fragment in (
            "CryptaPlatform.content.subscriptions.create",
            "CryptaPlatform.content.subscriptions.list",
            "CryptaPlatform.content.subscriptions.refresh",
            "CryptaPlatform.content.subscriptions.pause",
            "CryptaPlatform.content.subscriptions.resume",
            "CryptaPlatform.content.subscriptions.remove",
            "isSocialSourceUri",
            "lastSeenResolvedUri",
            "updateCount",
            "lastError",
        )
    )
    checks["manualFetchUsesBoundedContentFetch"] = (
        "CryptaPlatform.content.fetchText" in app_js
        and "maxFetchedDocumentChars" in app_js
        and "parseJsonObject" in app_js
    )
    checks["docsDescribeDurableUskSources"] = (
        "content.subscribe" in reference_doc
        and "durable" in reference_doc.lower()
        and "USK" in reference_doc
        and "raw fetched content" in reference_doc
    )
    details["redaction"] = {
        "rawFetchedContentExcluded": True,
        "sourceMetadataOnly": True,
        "absolutePathsExcluded": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"social inbox subscription check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.social-inbox-subscriptions",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox subscription evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.social-inbox-subscriptions",
        "pass",
        True,
        "Social Inbox subscription evidence passed.",
        source,
        details,
    )


def collect_social_inbox_app_data_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = social_inbox_spec(settings)
    details: dict[str, Any] = {"appId": "social-inbox", "checks": {}}
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.social-inbox-app-data",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox app-data evidence is missing its first-party app spec.",
            source,
            details,
        )
    workspace = settings.workspace_root
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    index = read_source(spec["sourceDir"] / "static/index.html")
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "apps/social-inbox/README.md",
            "docs/social-inbox-reference-app.md",
            "docs/app-data-store.md",
            "docs/release-certification.md",
        )
    )
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    manifest = parse_properties(manifest_path) if manifest_path.is_file() else {}
    permissions = parse_permission_set(manifest.get("app.permissions", ""))
    checks = details["checks"]
    checks["manifestDeclaresAppDataPermissions"] = {
        "app.data.read",
        "app.data.write",
    }.issubset(permissions)
    checks["usesSdkJsonRecordHelpers"] = (
        "CryptaPlatform.data.records.getJson" in app_js
        and "CryptaPlatform.data.records.putJson" in app_js
    )
    checks["persistsNamedBoundedRecords"] = all(
        fragment in app_js
        for fragment in (
            "ui-state\", \"social-inbox\"",
            "social\", \"sources\"",
            "social\", \"outbox-summary\"",
            "social\", \"imported-message-index\"",
            "social\", \"read-state\"",
            "social\", \"drafts\"",
            "maxSources",
            "maxImportedMessages",
            "maxReadStateEntries",
            "boundedDrafts",
            "boundedReadState",
            "Object.create(null)",
            "isSafeMessageId",
        )
    )
    checks["signingDoesNotOverwritePublishSummary"] = (
        "persistOutboxSummary(await localOutboxSummary())" not in app_js
        and "await persistOutboxSummary(summary)" in app_js
    )
    checks["storesSafeSummariesOnly"] = all(
        fragment in app_js
        for fragment in (
            "bodySha256",
            "bodyPreview",
            "signatureSha256",
            "insertUriRedaction",
            "redactedInsertUri",
            "uriHash",
            "uriSummary",
            "publicSourceUriHash",
            "publicSourceUriSummary",
        )
    ) and "privateInsertUri" not in app_js and not re.search(r"\bsource\.uri\b", app_js)
    checks["permissionDisclosureMentionsAppData"] = (
        "app.data.read" in permission_disclosure_block(index)
        and "app.data.write" in permission_disclosure_block(index)
    )
    checks["docsDescribePrivacyRules"] = (
        "reference-app.social-inbox-app-data" in docs_text
        and "private insert URIs" in docs_text
        and "raw source URIs" in docs_text
        and "browser-session tokens" in docs_text
        and "raw fetched documents" in docs_text
    )
    checks["noBrowserStorageOrRawAdminPath"] = (
        "/api/v1/" not in app_js
        and "localStorage" not in app_js
        and "sessionStorage" not in app_js
        and "document.cookie" not in app_js
    )
    details["redaction"] = {
        "rawMessageBodiesExcludedFromEvidence": True,
        "rawFetchedDocumentsExcluded": True,
        "privateInsertUrisExcluded": True,
        "tokensExcluded": True,
        "localPathsExcluded": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"social inbox app-data check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.social-inbox-app-data",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox app-data evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.social-inbox-app-data",
        "pass",
        True,
        "Social Inbox app-data evidence passed.",
        source,
        details,
    )


def collect_social_inbox_trust_annotation_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = social_inbox_spec(settings)
    details: dict[str, Any] = {"appId": "social-inbox", "checks": {}}
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.social-inbox-trust-annotations",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox trust annotation evidence is missing its first-party app spec.",
            source,
            details,
        )
    workspace = settings.workspace_root
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    index = read_source(spec["sourceDir"] / "static/index.html")
    reference_doc = read_source(workspace / "docs/social-inbox-reference-app.md")
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    manifest = parse_properties(manifest_path) if manifest_path.is_file() else {}
    permissions = parse_permission_set(manifest.get("app.permissions", ""))
    checks = details["checks"]
    checks["manifestDeclaresAppServiceCapabilities"] = (
        {"app.services.read", "app.services.call"}.issubset(permissions)
        and "trust.read" not in permissions
    )
    checks["manifestDeclaresTrustScoreRequest"] = (
        manifest.get("app.service-request.trust-score.provider") == "trust-graph"
        and manifest.get("app.service-request.trust-score.service") == "trust.score"
        and manifest.get("app.service-request.trust-score.scopes") == "score.read"
        and manifest.get("app.service-request.trust-score.contexts") == "message-author"
    )
    checks["appQueriesAuthorScores"] = (
        "CryptaPlatform.services.invoke" in app_js
        and "CryptaPlatform.services.grants.list" in app_js
        and "CryptaPlatform.services.bundles.request" in app_js
        and "subjectKind: \"identity\"" in app_js
        and "trustScoreContext = \"message-author\"" in app_js
        and "authorFingerprint" in app_js
        and "CryptaPlatform.trust.score" not in app_js
    )
    checks["uiShowsNeutralAndScoredStates"] = (
        "Trust score unavailable / grant required" in app_js
        and "Trust score unavailable / grant revoked" in app_js
        and "evidenceCount" in app_js
        and "Request trust grant" in index
        and "Refresh trust" in index
    )
    checks["unknownScoresRemainUnscored"] = (
        "optionalNumberField" in app_js
        and "contributingEvidenceCount" in app_js
        and "[\"trusted\", \"distrusted\", \"mixed\"].includes(trustStatus)" in app_js
        and "return { status: \"unscored\", summary: \"No local trust evidence.\" }" in app_js
    )
    checks["docsFrameScoresAsAnnotations"] = (
        ("Trust Graph Preview" in reference_doc or "Trust Graph Local RC" in reference_doc)
        and "message-author" in reference_doc
        and "Trust Score Service grant" in reference_doc
        and "not a moderation decision" in reference_doc
    )
    details["redaction"] = {
        "trustEvidenceSummariesOnly": True,
        "messageBodiesExcludedFromEvidence": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"social inbox trust annotation check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.social-inbox-trust-annotations",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox trust annotation evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.social-inbox-trust-annotations",
        "pass",
        True,
        "Social Inbox trust annotation evidence passed.",
        source,
        details,
    )


def collect_social_inbox_rc_threading_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = social_inbox_spec(settings)
    details: dict[str, Any] = {
        "appId": "social-inbox",
        "checks": {},
        "sourceFiles": [
            "apps/social-inbox/src/staged/static/app.js",
            "apps/social-inbox/src/staged/static/index.html",
            "apps/social-inbox/src/staged/cryptad-app.properties.template",
            "docs/social-inbox-reference-app.md",
            "apps/social-inbox/README.md",
        ],
        "redaction": {
            "rawMessageBodiesExcluded": True,
            "rawFetchedContentExcluded": True,
            "rawSignaturesExcluded": True,
            "privateInsertUrisExcluded": True,
            "tokensExcluded": True,
            "privateKeysExcluded": True,
            "absolutePathsExcluded": True,
        },
    }
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.social-inbox-rc-threading",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox RC threading evidence is missing its first-party app spec.",
            source,
            details,
        )

    workspace = settings.workspace_root
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    index = read_source(spec["sourceDir"] / "static/index.html")
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "apps/social-inbox/README.md",
            "docs/social-inbox-reference-app.md",
            "tools/release-certification/README.md",
        )
    )
    docs_lower = normalized_source_text(docs_text)
    source_manifest_path = spec["sourceDir"] / "cryptad-app.properties.template"
    staged_manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    source_manifest = parse_properties(source_manifest_path) if source_manifest_path.is_file() else {}
    staged_manifest = parse_properties(staged_manifest_path) if staged_manifest_path.is_file() else {}
    manifest = staged_manifest or source_manifest
    migration_names = parse_permission_set(manifest.get("app.data.migrations", ""))
    checks = details["checks"]
    checks["threadBuildingLogic"] = all(
        fragment in app_js
        for fragment in (
            "buildThreadIndex",
            "normalizeReplyReference",
            "messageThreadRootId",
            "threadSortKey",
            "messageSortKey",
            "threadUnreadCount",
            "threadContainsMessage",
            "replyTo",
        )
    ) and any(fragment in app_js.lower() for fragment in ("cycle", "visited", "visiting"))
    checks["threadRenderingIsBoundedAndDomSafe"] = (
        all(
            fragment in app_js
            for fragment in (
                "maxThreadDepth",
                "maxRenderedThreadMessages",
                "textContent",
                "replaceChildren",
            )
        )
        and "innerHTML" not in app_js
        and "insertAdjacentHTML" not in app_js
    )
    checks["replyActionUsesExistingReplyTo"] = (
        "Reply" in app_js + index
        and "replyTo" in app_js
        and "createSocialMessageDocument" in app_js
        and "reply-message" not in app_js
    )
    checks["channelFilteringIsLocal"] = (
        "All channels" in app_js + index
        and all(
            fragment in app_js
            for fragment in (
                "channelFilter",
                "selectedChannel",
                "maxImportedChannelLength",
                "general",
            )
        )
    )
    checks["boundedLocalSearch"] = all(
        fragment in app_js
        for fragment in (
            "maxSearchQueryLength",
            "threadContainsMessage",
            "searchQuery",
            "bodyPreview",
            "sourceLabel",
        )
    )
    checks["threadActionsPersistSafeState"] = (
        all(
            fragment in app_js
            for fragment in (
                "markThreadRead",
                "markThreadUnread",
                "archiveThread",
                "toggleThreadPin",
                "isSafeMessageId",
                "boundedReadState",
            )
        )
        and "read-state" in app_js
    )
    checks["authorProfileDisplayIsSafe"] = all(
        fragment in app_js
        for fragment in (
            "authorLabel",
            "authorFingerprint",
            "profileUri",
            "optionalCryptaContentUri",
            "copyProfileUri",
        )
    )
    checks["dedupePreservesSafeSourceSummaries"] = all(
        fragment in app_js
        for fragment in (
            "seenCount",
            "firstImportedAt",
            "lastSeenAt",
            "sourcesSeen",
            "sourceSummariesForDedupe",
            "sourceUriHash",
        )
    )
    checks["subscriptionRefreshUxIsExplicit"] = all(
        fragment in app_js + index
        for fragment in (
            "refreshAllSources",
            "lastCheckedAt",
            "lastSeenEdition",
            "updateCount",
            "lastError",
        )
    )
    checks["trustGraphMediatedOnly"] = (
        all(
            fragment in app_js
            for fragment in (
                "CryptaPlatform.services.get",
                "CryptaPlatform.services.grants.list",
                "CryptaPlatform.services.bundles.request",
                "CryptaPlatform.services.invoke",
            )
        )
        and "CryptaPlatform.trust.score" not in app_js
        and "/api/v1/trust-graph/score" not in app_js
        and "/api/v1/" not in app_js
    )
    checks["noUnsafeBrowserPersistenceOrExecution"] = all(
        forbidden not in app_js
        for forbidden in (
            "localStorage",
            "sessionStorage",
            "indexedDB",
            "document.cookie",
            "eval(",
            "new Function",
        )
    )
    checks["manifestUsesNonBlockingSchemaContract"] = (
        manifest.get("app.data.schema.current") == "1"
        and manifest.get("app.data.schema.namespaces") == "ui-state,social"
        and manifest.get("app.data.schema.namespace.ui-state.current") == "1"
        and manifest.get("app.data.schema.namespace.social.current") == "1"
        and not migration_names
        and "migrate-social-inbox-data.sh" not in "\n".join(
            f"{key}={value}" for key, value in manifest.items()
        )
    )
    checks["appWritesExistingSchemaVersion"] = (
        "const dataSchemaVersion = 1" in app_js
        and "schemaVersion: dataSchemaVersion" in app_js
    )
    checks["docsFrameRcReferenceAndNonGoals"] = (
        ("social inbox rc" in docs_lower or "social inbox reference" in docs_lower)
        and "thread" in docs_lower
        and "read state" in docs_lower
        and "trust graph" in docs_lower
        and "annotations only" in docs_lower
        and "encrypted mail" in docs_lower
        and "freetalk" in docs_lower
        and "sone" in docs_lower
        and "freemail" in docs_lower
        and ("full wot" in docs_lower or "full web of trust" in docs_lower)
        and ("daemon-core message" in docs_lower or "outside daemon core" in docs_lower)
    )
    checks["evidenceIdDocumented"] = "reference-app.social-inbox-rc-threading" in docs_text
    details["manifest"] = {
        "appId": manifest.get("app.id"),
        "name": manifest.get("app.name"),
        "schemaVersion": manifest.get("app.data.schema.current"),
        "namespaces": manifest.get("app.data.schema.namespaces"),
        "migrations": sorted(migration_names),
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"social inbox RC threading check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.social-inbox-rc-threading",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox RC threading evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.social-inbox-rc-threading",
        "pass",
        True,
        "Social Inbox RC threading evidence passed.",
        source,
        details,
    )


def collect_social_mail_migration_preview_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    app_js = read_source(workspace / "apps/social-inbox/src/staged/static/app.js")
    index = read_source(workspace / "apps/social-inbox/src/staged/static/index.html")
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/social-inbox-reference-app.md",
            "docs/app-platform-developer-portal.md",
            "docs/app-platform-beta-tutorials.md",
            "docs/app-platform-beta-known-limitations.md",
            "docs/app-permissions-and-audit.md",
            "docs/release-certification.md",
            "tools/release-certification/README.md",
        )
    )
    docs_lower = docs_text.lower()
    checks = {
        "migrationFramingPresent": (
            "social/mail-like" in docs_text
            and ("reference app" in docs_lower or "migration" in docs_lower)
            and ("outside the daemon" in docs_lower or "outside daemon core" in docs_lower)
        ),
        "nonGoalsDocumented": all(
            fragment in docs_text
            for fragment in (
                "old plugin ABI compatibility",
                "Freetalk",
                "Sone",
                "Freemail",
                "encrypted mail",
                "network protocol change",
                "daemon-core message protocol",
            )
        ),
        "appComposesExpectedPlatformSurfaces": all(
            fragment in app_js
            for fragment in (
                "createSocialMessageDocument",
                "insertAppDocument",
                "content.subscriptions",
                "data.records",
                "services.invoke",
            )
        ),
        "uiStatesPreviewBoundary": (
            "Reference app scope" in index
            and "not Freetalk, Sone, Freemail" in index
            and "does not add a daemon-core message store" in index
        ),
        "evidenceIdsDocumented": all(
            evidence_id in docs_text
            for evidence_id in (
                "reference-app.social-inbox",
                "reference-app.social-inbox-signed-message",
                "reference-app.social-inbox-subscriptions",
                "reference-app.social-inbox-app-data",
                "reference-app.social-inbox-trust-annotations",
                "migration.social-mail-preview",
            )
        ),
    }
    details = {
        "checks": checks,
        "redaction": {
            "rawMessageBodiesExcluded": True,
            "rawFetchedContentExcluded": True,
            "rawRequestBodiesExcluded": True,
            "rawSignaturesExcluded": True,
            "privateInsertUrisExcluded": True,
            "privateIdentityMaterialExcluded": True,
            "tokensExcluded": True,
            "localPathsExcluded": True,
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "migration.social-mail-preview",
            root_consequence(settings, "fail"),
            True,
            "Social/mail migration preview evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "migration.social-mail-preview",
        "pass",
        True,
        "Social/mail migration preview evidence passed.",
        source,
        details,
    )


def collect_legacy_plugin_migration_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    guide_path = workspace / "docs/legacy-plugin-migration-guide.md"
    plugin_status_path = workspace / "docs/plugin-system.md"
    portal_path = workspace / "docs/app-platform-developer-portal.md"
    beta_limits_path = workspace / "docs/app-platform-beta-known-limitations.md"
    guide_text = read_source(guide_path)
    guide_lower = guide_text.lower()
    developer_docs_text = read_source(portal_path) + "\n" + read_source(beta_limits_path)
    checks = {
        "guideExists": guide_path.is_file(),
        "oldRuntimeRemoved": "old plugin runtime" in guide_lower and "removed" in guide_lower,
        "noOldPluginAbiCompatibility": "old plugin ABI compatibility" in guide_text,
        "noFcpPluginCommandCompatibility": "old FCP plugin command compatibility" in guide_text,
        "webOfTrustMigration": "WebOfTrust-like" in guide_text or "WoT-like" in guide_text,
        "freetalkSoneMigration": "Freetalk/Sone-like" in guide_text,
        "freemailMigration": "Freemail-like" in guide_text,
        "trustGraphPreview": "Trust Graph Preview" in guide_text,
        "socialInboxReference": "Social Inbox RC" in guide_text
        or "Social Inbox reference" in guide_text,
        "appVault": "app vault" in guide_lower or "AppVault" in guide_text,
        "appData": "app data" in guide_lower or "app-data" in guide_lower,
        "contentSubscriptions": "content subscriptions" in guide_lower,
        "appServiceGrants": "app-service grant" in guide_lower,
        "signedCatalog": "signed catalog" in guide_lower,
        "reviewGovernance": "review receipt" in guide_lower
        or "review governance" in guide_lower,
        "pluginSystemLinksGuide": "legacy-plugin-migration-guide.md" in read_source(plugin_status_path),
        "developerOrBetaDocsLinkGuide": "legacy-plugin-migration-guide.md" in developer_docs_text,
    }
    details = {
        "guide": display_path(guide_path, workspace),
        "linkedDocs": [
            display_path(plugin_status_path, workspace),
            display_path(portal_path, workspace),
            display_path(beta_limits_path, workspace),
        ],
        "checks": checks,
        "redaction": {
            "privateInsertUrisExcluded": True,
            "tokensExcluded": True,
            "rawBodiesExcluded": True,
            "rawSignaturesExcluded": True,
            "localPathsExcluded": True,
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "legacy-plugin.migration-guide",
            root_consequence(settings, "fail"),
            True,
            "Legacy plugin migration guide evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-plugin.migration-guide",
        "pass",
        True,
        "Legacy plugin migration guide evidence passed.",
        source,
        details,
    )


def collect_legacy_plugin_social_inbox_spike_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    app_dir = workspace / "apps/social-inbox"
    manifest_path = app_dir / "src/staged/cryptad-app.properties.template"
    if not manifest_path.is_file():
        manifest_path = app_dir / "build/cryptad-app/social-inbox/cryptad-app.properties"
    manifest: dict[str, str] = {}
    manifest_permissions: set[str] = set()
    errors: list[str] = []
    if manifest_path.is_file():
        try:
            manifest = parse_properties(manifest_path)
            manifest_permissions = parse_permission_set(manifest.get("app.permissions", ""))
        except ValueError as exc:
            errors.append(str(exc))
    social_app_js = read_source(app_dir / "src/staged/static/app.js")
    social_readme = read_source(app_dir / "README.md")
    social_doc = read_source(workspace / "docs/social-inbox-reference-app.md")
    docs_text = social_readme + "\n" + social_doc
    direct_local_endpoint_reference = has_direct_local_endpoint_reference(social_app_js)
    checks = {
        "appExists": app_dir.is_dir(),
        "manifestPresent": manifest_path.is_file(),
        "manifestDeclaresExpectedCapabilities": SOCIAL_INBOX_PERMISSIONS.issubset(
            manifest_permissions
        ),
        "manifestRequestsTrustScoreService": (
            manifest.get("app.services.requests") == "trust-score"
            and manifest.get("app.service-request.trust-score.provider") == "trust-graph"
            and manifest.get("app.service-request.trust-score.service") == "trust.score"
            and manifest.get("app.service-request.trust-score.scopes") == "score.read"
            and manifest.get("app.service-request.trust-score.contexts") == "message-author"
        ),
        "usesPlatformMediatedServiceGrant": (
            "CryptaPlatform.services.get" in social_app_js
            and "CryptaPlatform.services.bundles.request" in social_app_js
            and "CryptaPlatform.services.invoke" in social_app_js
            and "trustScoreProviderAppId = \"trust-graph\"" in social_app_js
            and "trustScoreServiceId = \"trust.score\"" in social_app_js
            and "CryptaPlatform.trust.score" not in social_app_js
            and not direct_local_endpoint_reference
        ),
        "noDirectLocalEndpointReference": not direct_local_endpoint_reference,
        "docsFrameSpikeNonGoals": social_inbox_docs_frame_spike_non_goals(docs_text),
    }
    details = {
        "appId": "social-inbox",
        "manifest": display_path(manifest_path, workspace),
        "expectedPermissions": sorted(SOCIAL_INBOX_PERMISSIONS),
        "declaredPermissions": sorted(manifest_permissions),
        "checks": checks,
        "redaction": {
            "ambientLocalhostTrustExcluded": not direct_local_endpoint_reference,
            "rawMessageBodiesExcluded": True,
            "rawFetchedContentExcluded": True,
            "rawSignaturesExcluded": True,
            "privateInsertUrisExcluded": True,
            "tokensExcluded": True,
            "localPathsExcluded": True,
        },
    }
    errors.extend(name for name, passed in checks.items() if not passed)
    if errors:
        return EvidenceItem(
            "legacy-plugin.social-inbox-spike",
            root_consequence(settings, "fail"),
            True,
            "Legacy plugin Social Inbox migration spike evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-plugin.social-inbox-spike",
        "pass",
        True,
        "Legacy plugin Social Inbox migration spike evidence passed.",
        source,
        details,
    )


def legacy_counts_from_registry_text(text: str) -> dict[str, int]:
    start = text.index("List.of(")
    end = text.index("private static final Map", start)
    block = text[start:end]
    return {
        "PRIMARY_REPLACED": len(
            re.findall(
                r"\n\s+(?:diagnosticFallbackReplacement|securityLevelsWave3Redirect|replaced|wave\d+Redirect)\(",
                block,
            )
        ),
        "PENDING": len(re.findall(r"\n\s+pendingWizard\(", block)) + len(re.findall(r"\n\s+pending\(", block)),
        "RETAINED": len(re.findall(r"\n\s+retained\(", block)),
        "INFRASTRUCTURE": len(re.findall(r"\n\s+infrastructure\(", block)),
    }


def java_method_body(text: str, method_name: str) -> str:
    pattern = re.compile(
        r"\b(?:public|private)\s+static\s+[\w<>, ?]+\s+"
        + re.escape(method_name)
        + r"\s*\([^)]*\)\s*\{",
        re.DOTALL,
    )
    match = pattern.search(text)
    if match is None:
        return ""
    open_brace = match.end() - 1
    depth = 0
    for offset in range(open_brace, len(text)):
        char = text[offset]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace + 1 : offset]
    return ""


def legacy_fallback_link_checks(text: str) -> dict[str, bool]:
    fallback_body = java_method_body(text, "webShellFallbackSurfaces")
    replaced_body = java_method_body(text, "diagnosticFallbackReplacement") or java_method_body(
        text, "replaced"
    )
    navigation_body = java_method_body(text, "shouldPromoteInLegacyNavigation")
    replaced_marks_no_fallback = "FALLBACK_POLICY_RENDER_LEGACY" in replaced_body and bool(
        re.search(r",\s*true\s*,\s*false\s*\)\s*;", replaced_body, re.DOTALL)
    )
    fallback_filters_include_flag = bool(
        re.search(r"\.filter\s*\(\s*LegacyAdminSurface::includeInWebShellFallbackLinks\s*\)", fallback_body)
    )
    fallback_filters_primary_state = bool(
        re.search(r"state\(\)\s*!=\s*LegacyAdminRetirementState\.PRIMARY_REPLACED", fallback_body)
    )
    navigation_excludes_primary = bool(
        re.search(r"state\(\)\s*!=\s*LegacyAdminRetirementState\.PRIMARY_REPLACED", navigation_body)
    )
    primary_replaced_excluded = fallback_filters_primary_state or (
        fallback_filters_include_flag and replaced_marks_no_fallback
    )
    return {
        "fallbackMethodFound": bool(fallback_body),
        "replacedHelperFound": bool(replaced_body),
        "replacedHelperDisablesFallbackLinks": replaced_marks_no_fallback,
        "fallbackFiltersIncludeFlag": fallback_filters_include_flag,
        "fallbackFiltersPrimaryState": fallback_filters_primary_state,
        "primaryReplacedExcludedFromFallbackLinks": primary_replaced_excluded,
        "primaryReplacedAbsentFromPrimaryNavigation": navigation_excludes_primary,
    }


def collect_legacy_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    registry = settings.workspace_root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java"
    docs = settings.workspace_root / "docs/legacy-retirement-plan.md"
    errors: list[str] = []
    details: dict[str, Any] = {}
    if not registry.is_file():
        errors.append("LegacyAdminRetirementRegistry.java is missing")
    else:
        registry_text = registry.read_text(encoding="utf-8")
        counts = legacy_counts_from_registry_text(registry_text)
        fallback_checks = legacy_fallback_link_checks(registry_text)
        details["stateCounts"] = counts
        details["totalRegisteredSurfaces"] = sum(counts.values())
        details["primaryReplacedSurfaces"] = counts["PRIMARY_REPLACED"]
        details["pendingSurfaces"] = counts["PENDING"]
        details["retainedSurfaces"] = counts["RETAINED"]
        details["fallbackLinkChecks"] = fallback_checks
        details["primaryReplacedAbsentFromFallbackLinks"] = fallback_checks[
            "primaryReplacedExcludedFromFallbackLinks"
        ]
        details["primaryReplacedAbsentFromPrimaryNavigation"] = fallback_checks[
            "primaryReplacedAbsentFromPrimaryNavigation"
        ]
        docs_text = re.sub(r"\s+", " ", docs.read_text(encoding="utf-8")) if docs.is_file() else ""
        details["retainedPendingRoutesDocumented"] = (
            "retained and pending legacy routes remain reachable" in docs_text.lower()
        )
        if counts["PRIMARY_REPLACED"] < 1:
            errors.append("No PRIMARY_REPLACED surfaces were found")
        if not details["primaryReplacedAbsentFromFallbackLinks"]:
            errors.append("PRIMARY_REPLACED surfaces may still appear in Web Shell fallback links")
        if not details["primaryReplacedAbsentFromPrimaryNavigation"]:
            errors.append("PRIMARY_REPLACED surfaces may still appear in primary legacy navigation")
        if not details["retainedPendingRoutesDocumented"]:
            errors.append("Retained/pending legacy route behavior is not documented")
    if errors:
        return EvidenceItem("legacy.retirement", "fail", True, "Legacy-admin retirement evidence is incomplete.", source, {"errors": errors, **details})
    return EvidenceItem("legacy.retirement", "pass", True, "Legacy-admin retirement map is visible and stable.", source, details)


def legacy_removal_wave_one_ids(registry_text: str) -> list[str]:
    return re.findall(r"\n\s+wave1Redirect\(\s*\"([^\"]+)\"", registry_text)


def legacy_removal_wave_two_ids(registry_text: str) -> list[str]:
    return re.findall(r"\n\s+wave2Redirect\(\s*\"([^\"]+)\"", registry_text)


def legacy_removal_wave_three_ids(registry_text: str) -> list[str]:
    ids = re.findall(r"\n\s+wave3Redirect\(\s*\"([^\"]+)\"", registry_text)
    if re.search(r"\n\s+securityLevelsWave3Redirect\(\s*\)", registry_text):
        ids.insert(0, "security-levels")
    return ids


def legacy_scope_expansion_wave_two_ids(registry_text: str) -> list[str]:
    try:
        start = registry_text.index("List.of(")
        end = registry_text.index("private static final Map", start)
    except ValueError:
        return []
    block = registry_text[start:end]
    matches = re.findall(
        r"\n\s+(?:wave1Redirect|wave2Redirect)\(\s*\"([^\"]+)\"(?:(?!\n\s+(?:wave1Redirect|wave2Redirect|replaced|pending|retained|infrastructure)\().)*?REMOVAL_WAVE_2",
        block,
        re.DOTALL,
    )
    return matches


def collect_legacy_removal_wave_one_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    root = settings.workspace_root
    files = {
        "registry": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java",
        "policy": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRemovalPolicy.java",
        "response": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminReplacementResponse.java",
        "recorder": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminUsageRecorder.java",
        "usageDto": root / "runtime-spi/src/main/java/network/crypta/runtime/spi/LegacyAdminSurfaceUsage.java",
        "diagnostics": root / "platform-api/src/main/java/network/crypta/platform/api/diagnostics/DiagnosticsApiHandler.java",
        "docs": root / "docs/legacy-retirement-plan.md",
    }
    text: dict[str, str] = {}
    missing = []
    for key, path in files.items():
        if not path.is_file():
            missing.append(key)
            text[key] = ""
        else:
            text[key] = path.read_text(encoding="utf-8")

    wave_ids = legacy_removal_wave_one_ids(text["registry"])
    checks = {
        "waveOneIdsMatch": wave_ids == list(LEGACY_REMOVAL_WAVE_ONE_IDS),
        "redirectModeDeclared": "LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT" in text["registry"],
        "canonicalOnlyPolicy": "matchesCanonicalPageOrSlashlessAlias" in text["policy"],
        "safeReadRedirects": "GET" in text["policy"] and "HEAD" in text["policy"] and "redirect(" in text["policy"],
        "mutatingRequestsBlocked": "BLOCKED_MUTATING_REQUEST" in text["policy"] or "blockedMutation" in text["policy"],
        "replacementAvailabilityGate": "replacementAvailable" in text["policy"]
        and "isStaticAppUiAvailable" in text["policy"]
        and "primaryUiRoot" in text["policy"],
        "replacementResponsesRecorded": "REPLACEMENT_RESPONSE" in text["recorder"] or "REPLACEMENT_RESPONSE" in text["policy"],
        "diagnosticsCarriesReplacementCounter": "replacementResponseCount" in text["diagnostics"] and "replacementResponseCount" in text["usageDto"],
        "diagnosticsCarriesBlockedCounter": "blockedMutatingRequestCount" in text["diagnostics"] and "blockedMutatingRequestCount" in text["usageDto"],
        "diagnosticsCarriesFallbackCounter": "fallbackRenderCount" in text["diagnostics"] and "fallbackRenderCount" in text["usageDto"],
        "docsDescribeWave": "legacy-admin.removal-wave-1" in text["docs"],
        "docsDescribeAvailabilityFallback": "replacement is reachable" in text["docs"]
        or "replacement is unavailable" in text["docs"],
        "docsRetainBrowse": "FProxy browse remains retained" in text["docs"],
        "liveNodeNotRequired": True,
    }
    redaction = {
        "queryStringsExcluded": True,
        "requestBodiesExcluded": True,
        "formPasswordsExcluded": True,
        "remoteAddressesExcluded": True,
        "tokensExcluded": True,
        "privateUrisExcluded": True,
        "localPathsExcluded": True,
    }
    details = {
        "removedByDefaultRouteIds": wave_ids,
        "expectedRouteIds": list(LEGACY_REMOVAL_WAVE_ONE_IDS),
        "replacementUrls": {
            "queue-downloads": "/apps/queue-manager/",
            "queue-uploads": "/apps/queue-manager/",
            "file-insert": "/apps/publisher/",
            "local-file-insert": "/apps/publisher/",
            "friends": "/app/node/#peers",
            "add-friend": "/app/node/#peers",
            "strangers": "/app/node/#peers",
            "connectivity": "/app/node/#connectivity",
        },
        "statusBehavior": {
            "safeRead": "303 See Other when replacement is available; legacy fallback when unavailable",
            "mutating": "410 Gone when replacement is available; legacy fallback when unavailable",
        },
        "liveNodeRequired": False,
        "checks": checks,
        "redaction": redaction,
        "missingSources": missing,
    }
    errors = [name for name, passed in checks.items() if not passed]
    errors.extend(f"missing {name}" for name in missing)
    if errors:
        return EvidenceItem(
            "legacy-admin.removal-wave-1",
            "fail",
            True,
            "Legacy-admin removal wave 1 evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-admin.removal-wave-1",
        "pass",
        True,
        "Legacy-admin removal wave 1 replacement behavior is documented and observable.",
        source,
        details,
    )


def collect_legacy_removal_wave_two_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    root = settings.workspace_root
    files = {
        "registry": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java",
        "policy": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRemovalPolicy.java",
        "response": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminReplacementResponse.java",
        "recorder": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminUsageRecorder.java",
        "usageDto": root / "runtime-spi/src/main/java/network/crypta/runtime/spi/LegacyAdminSurfaceUsage.java",
        "diagnostics": root / "platform-api/src/main/java/network/crypta/platform/api/diagnostics/DiagnosticsApiHandler.java",
        "docs": root / "docs/legacy-retirement-plan.md",
    }
    text: dict[str, str] = {}
    missing = []
    for key, path in files.items():
        if not path.is_file():
            missing.append(key)
            text[key] = ""
        else:
            text[key] = path.read_text(encoding="utf-8")

    wave_ids = legacy_removal_wave_two_ids(text["registry"])
    scope_expansion_ids = legacy_scope_expansion_wave_two_ids(text["registry"])
    checks = {
        "waveTwoIdsMatch": wave_ids == list(LEGACY_REMOVAL_WAVE_TWO_IDS),
        "waveOneIdsStable": legacy_removal_wave_one_ids(text["registry"]) == list(LEGACY_REMOVAL_WAVE_ONE_IDS),
        "scopeExpansionIdsMatch": scope_expansion_ids == list(LEGACY_REMOVAL_WAVE_TWO_SCOPE_EXPANSION_IDS),
        "redirectModeDeclared": "LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT" in text["registry"],
        "routeScopeDeclared": "LegacyAdminRemovalScope" in text["registry"] and "matchesRemovalScope" in text["policy"],
        "explicitChildrenDeclared": "EXPLICIT_CHILDREN" in text["registry"] and "explicitRemovalChildPaths" in text["policy"],
        "prefixFamilyDeclared": "PREFIX_FAMILY" in text["registry"],
        "safeReadReplacementResponses": "GET" in text["policy"]
        and "HEAD" in text["policy"]
        and ("redirect(" in text["policy"] or "gone(" in text["policy"]),
        "partialMutationFallbackDocumented": "blockMutatingRequests" in text["policy"]
        and "mutating legacy alert" in text["docs"].lower()
        and "installer and package-store" in text["docs"].lower(),
        "mutatingRequestsBlockedWhereCovered": "BLOCKED_MUTATING_REQUEST" in text["policy"]
        or "blockedMutation" in text["policy"],
        "replacementAvailabilityGate": "replacementAvailable" in text["policy"]
        and "isStaticAppUiAvailable" in text["policy"]
        and "primaryUiRoot" in text["policy"],
        "diagnosticsCarriesReplacementCounter": "replacementResponseCount" in text["diagnostics"] and "replacementResponseCount" in text["usageDto"],
        "diagnosticsCarriesBlockedCounter": "blockedMutatingRequestCount" in text["diagnostics"] and "blockedMutatingRequestCount" in text["usageDto"],
        "diagnosticsCarriesFallbackCounter": "fallbackRenderCount" in text["diagnostics"] and "fallbackRenderCount" in text["usageDto"],
        "diagnosticsCarriesScopeMetadata": "removalScope" in text["diagnostics"]
        and "scopeExpandedInWave" in text["diagnostics"]
        and "removalScope" in text["usageDto"]
        and "scopeExpandedInWave" in text["usageDto"],
        "docsDescribeWave": "legacy-admin.removal-wave-2" in text["docs"],
        "docsDescribeAvailabilityFallback": "replacement is reachable" in text["docs"]
        or "replacement is unavailable" in text["docs"],
        "docsRetainBrowse": "FProxy browse remains retained" in text["docs"],
        "docsRetainDiagnosticExport": "raw diagnostic export remains retained" in text["docs"],
        "liveNodeNotRequired": True,
    }
    retained_browse_safety = {
        "fproxyBrowseRootOutOfScope": "/" not in wave_ids,
        "contentFilterOutOfScope": "content-filter" not in wave_ids,
        "wizardOutOfScope": "first-time-wizard" not in wave_ids,
        "nodeToNodeMessageOutOfScope": "node-to-node-message" not in wave_ids,
        "diagnosticPlainTextRetained": "diagnostic" not in wave_ids,
    }
    redaction = {
        "queryStringsExcluded": True,
        "requestBodiesExcluded": True,
        "formPasswordsExcluded": True,
        "remoteAddressesExcluded": True,
        "tokensExcluded": True,
        "privateUrisExcluded": True,
        "localPathsExcluded": True,
    }
    details = {
        "removedByDefaultRouteIds": wave_ids,
        "expectedRouteIds": list(LEGACY_REMOVAL_WAVE_TWO_IDS),
        "scopeExpandedRouteIds": scope_expansion_ids,
        "expectedScopeExpandedRouteIds": list(LEGACY_REMOVAL_WAVE_TWO_SCOPE_EXPANSION_IDS),
        "replacementUrls": {
            "alerts": "/app/node/#alerts",
            "config": "/app/node/#config",
            "core-update": "/app/node/#updates",
            "statistics": "/app/node/#diagnostics",
            "queue-downloads": "/apps/queue-manager/",
            "queue-uploads": "/apps/queue-manager/",
        },
        "statusBehavior": {
            "safeRead": "303 See Other when replacement is available; legacy fallback when unavailable",
            "mutating": "410 Gone only for covered mutations when replacement is available; partial legacy actions remain fallback",
        },
        "actionCoverage": {
            "alerts": "safe reads redirect; legacy POST fallback remains for bulk dismiss and node-message deletion",
            "config": "safe reads and config POST mutations are removed by default when Web Shell config is available",
            "core-update": "safe reads redirect; legacy POST fallback remains for installer and package-store actions",
            "statistics": "safe reads redirect for overview and requesters HTML; raw diagnostic export is retained",
            "queue": "canonical routes plus reviewed count and key-list helpers redirect when Queue Manager is available",
        },
        "retainedBrowseSafety": retained_browse_safety,
        "liveNodeRequired": False,
        "checks": checks,
        "redaction": redaction,
        "missingSources": missing,
    }
    errors = [name for name, passed in checks.items() if not passed]
    errors.extend(f"retainedBrowseSafety.{name}" for name, passed in retained_browse_safety.items() if not passed)
    errors.extend(f"missing {name}" for name in missing)
    if errors:
        return EvidenceItem(
            "legacy-admin.removal-wave-2",
            "fail",
            True,
            "Legacy-admin removal wave 2 evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-admin.removal-wave-2",
        "pass",
        True,
        "Legacy-admin removal wave 2 replacement behavior is documented and observable.",
        source,
        details,
    )


def collect_legacy_removal_wave_three_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    root = settings.workspace_root
    files = {
        "registry": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java",
        "policy": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRemovalPolicy.java",
        "response": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminReplacementResponse.java",
        "webshellToadlet": root
        / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/WebShellToadlet.java",
        "bootstrap": root
        / "platform-web-shell/src/main/java/network/crypta/platform/webshell/bootstrap/WebShellBootstrap.java",
        "bootstrapJson": root
        / "platform-web-shell/src/main/java/network/crypta/platform/webshell/bootstrap/WebShellBootstrapJson.java",
        "webshell": root
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js",
        "docs": root / "docs/legacy-retirement-plan.md",
    }
    text: dict[str, str] = {}
    missing = []
    for key, path in files.items():
        if not path.is_file():
            missing.append(key)
            text[key] = ""
        else:
            text[key] = path.read_text(encoding="utf-8")

    wave_ids = legacy_removal_wave_three_ids(text["registry"])
    docs_lower = text["docs"].lower()
    checks = {
        "waveThreeIdsMatch": wave_ids == list(LEGACY_REMOVAL_WAVE_THREE_IDS),
        "waveOneIdsStable": legacy_removal_wave_one_ids(text["registry"]) == list(LEGACY_REMOVAL_WAVE_ONE_IDS),
        "waveTwoIdsStable": legacy_removal_wave_two_ids(text["registry"]) == list(LEGACY_REMOVAL_WAVE_TWO_IDS),
        "waveThreeConstantPresent": "REMOVAL_WAVE_3" in text["registry"],
        "removedSinceMarkerPresent": "phase-8-pr-244" in text["registry"],
        "securityReplacementUrl": (
            "SHELL_SECURITY_URL" in text["registry"]
            or "/app/node/#security" in text["registry"]
        )
        and "/app/node/#security" in text["docs"],
        "securityMutatingFallbackDeclared": "security-levels" in text["registry"]
        and (
            "canonicalMutationFallback()" in text["registry"]
            or "mutating-legacy-fallback" in text["registry"]
        ),
        "securityLegacyFallbackMarkerDeclared": "legacyFallback=security-levels" in text["policy"]
        and "legacyFallback=security-levels" in text["webshell"]
        and "Open the legacy security page" in text["webshell"],
        "securityFallbackLinkDiscoverable": "function renderSecurityLegacyFallbackAction()" in text["webshell"]
        and "sections.security.append(renderSecurityLegacyFallbackAction())" in text["webshell"]
        and "Open legacy password and recovery forms" in text["webshell"]
        and "Security panel" in text["docs"],
        "securityFallbackPathFromBootstrap": "bootstrap.legacySecurityLevelsPath" in text["webshell"]
        and 'legacySecurityLevelsPath + "?legacyFallback=security-levels"' in text["webshell"]
        and "legacySecurityLevelsPath" in text["bootstrap"]
        and '"legacySecurityLevelsPath"' in text["bootstrapJson"],
        "securityFallbackAllowsSlashlessPath": "normalizeLocalPath(" in text["webshell"]
        and "bootstrap.legacySecurityLevelsPath" in text["webshell"]
        and "requireLegacySecurityLevelsPath(legacySecurityLevelsPath" in text["bootstrap"],
        "securityFallbackPathFromRegistry": 'LegacyAdminRetirementRegistry.require("security-levels").legacyPath()'
        in text["webshellToadlet"]
        and "WebShellBootstrap.nodeManagement(legacySecurityLevelsPath" in text["webshellToadlet"],
        "securityFallbackPathNotHardCoded": '"/seclevels/?legacyFallback=security-levels"'
        not in text["webshell"],
        "securityCanonicalScopeOnly": "CANONICAL_AND_SLASHLESS_ALIAS" in text["registry"]
        and "prefix-family matching" in docs_lower,
        "policyRoutesSecurityThroughWebShell": '"security-levels"' in text["policy"]
        and "webShellReplacementAvailable" in text["policy"],
        "safeReadReplacementResponses": "GET" in text["policy"]
        and "HEAD" in text["policy"]
        and "redirect(" in text["policy"],
        "mutatingFallbackDocumented": "master-password" in docs_lower
        and "high physical security" in docs_lower
        and "recovery" in docs_lower
        and "legacy fallback remains" in docs_lower,
        "safeReadFallbackDocumented": "bootstrap-resolved explicit fallback link" in docs_lower
        and "arbitrary query strings still receive" in docs_lower,
        "docsDescribeWave": "legacy-admin.removal-wave-3" in text["docs"],
        "docsRetainBrowse": "FProxy browse" in text["docs"]
        and "content rendering" in text["docs"],
        "docsRetainContentFilter": "Content filter" in text["docs"]
        or "content filter" in docs_lower,
        "docsRetainDiagnosticExport": "raw diagnostic export" in docs_lower,
        "docsRetainStartupWizard": "Startup wizard" in text["docs"]
        and "emergency fallback" in docs_lower,
        "docsLeaveNodeToNodePending": "Node-to-node messages" in text["docs"],
        "liveNodeNotRequired": True,
    }
    retained_browse_safety = {
        "fproxyBrowseRootOutOfScope": "/" not in wave_ids,
        "contentFilterOutOfScope": "content-filter" not in wave_ids,
        "wizardOutOfScope": "first-time-wizard" not in wave_ids,
        "nodeToNodeMessageOutOfScope": "node-to-node-message" not in wave_ids,
        "diagnosticPlainTextRetained": "diagnostic" not in wave_ids,
    }
    redaction = {
        "queryStringsExcluded": True,
        "formPasswordsExcluded": True,
        "tokensExcluded": True,
        "privateUrisExcluded": True,
        "requestBodiesExcluded": True,
        "rawFetchedBodiesExcluded": True,
        "rawSignaturesExcluded": True,
        "localPathsExcluded": True,
    }
    details = {
        "removedByDefaultRouteIds": wave_ids,
        "expectedRouteIds": list(LEGACY_REMOVAL_WAVE_THREE_IDS),
        "replacementUrls": {"security-levels": "/app/node/#security"},
        "fallbackUrlSource": "Web Shell bootstrap legacySecurityLevelsPath from the registry security-levels legacy path",
        "statusBehavior": {
            "safeRead": "303 See Other when Web Shell security is available; legacy fallback when unavailable",
            "mutating": "legacy fallback remains for partial master-password, recovery, and high-physical-security flows",
        },
        "retainedBrowseSafety": retained_browse_safety,
        "liveNodeRequired": False,
        "checks": checks,
        "redaction": redaction,
        "missingSources": missing,
    }
    errors = [name for name, passed in checks.items() if not passed]
    errors.extend(f"retainedBrowseSafety.{name}" for name, passed in retained_browse_safety.items() if not passed)
    errors.extend(f"missing {name}" for name in missing)
    if errors:
        return EvidenceItem(
            "legacy-admin.removal-wave-3",
            "fail",
            True,
            "Legacy-admin removal wave 3 evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-admin.removal-wave-3",
        "pass",
        True,
        "Legacy-admin removal wave 3 replacement behavior is documented and observable.",
        source,
        details,
    )


def collect_sandbox_provider_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    sandbox_dir = settings.workspace_root / "platform-apphost/src/main/java/network/crypta/platform/apphost/sandbox"
    sandbox_test_dir = settings.workspace_root / "platform-apphost/src/test/java/network/crypta/platform/apphost/sandbox"
    expected_files = {
        "providerSource": sandbox_dir / "BubblewrapSandboxProvider.java",
        "commandBuilderSource": sandbox_dir / "BubblewrapCommandBuilder.java",
        "availabilitySource": sandbox_dir / "BubblewrapAvailability.java",
        "registrySource": sandbox_dir / "AppSandboxProviders.java",
        "providerTest": sandbox_test_dir / "BubblewrapSandboxProviderTest.java",
    }
    checks: dict[str, Any] = {}
    errors: list[str] = []
    for key, path in expected_files.items():
        exists = path.is_file()
        checks[key] = {
            "present": exists,
            "path": display_path(path, settings.workspace_root),
        }
        if not exists:
            errors.append(f"{key} is missing")
    provider_text = expected_files["providerSource"].read_text(encoding="utf-8") if expected_files["providerSource"].is_file() else ""
    builder_text = expected_files["commandBuilderSource"].read_text(encoding="utf-8") if expected_files["commandBuilderSource"].is_file() else ""
    registry_text = expected_files["registrySource"].read_text(encoding="utf-8") if expected_files["registrySource"].is_file() else ""
    test_text = expected_files["providerTest"].read_text(encoding="utf-8") if expected_files["providerTest"].is_file() else ""
    checks["enforcedSupportLevel"] = "AppSandboxSupportLevel.ENFORCED" in provider_text
    checks["bubblewrapProviderName"] = 'PROVIDER_NAME = "bubblewrap"' in provider_text
    checks["restrictedProcessRegistry"] = "BubblewrapSandboxProvider" in registry_text
    checks["environmentPassThrough"] = "checkedContext.environment()" in provider_text
    checks["noSetenvCommand"] = 'command.add("--setenv")' not in provider_text + builder_text
    checks["offlineProviderTests"] = "BubblewrapSandboxProviderTest" in test_text
    for key in (
        "enforcedSupportLevel",
        "bubblewrapProviderName",
        "restrictedProcessRegistry",
        "environmentPassThrough",
        "noSetenvCommand",
        "offlineProviderTests",
    ):
        if not checks[key]:
            errors.append(f"{key} check failed")
    gradle_result = gradle_command(
        settings,
        [
            ":platform-apphost:test",
            "--tests",
            "*BubblewrapSandboxProviderTest",
            "--tests",
            "*AppSandboxProvidersTest",
        ],
        "gradle-apphost-sandbox-provider",
    )
    details: dict[str, Any] = {
        "mode": "restricted-process",
        "provider": "bubblewrap",
        "supportLevel": "enforced",
        "liveBubblewrapRequired": False,
        "hostBubblewrapProbe": {"enabled": False},
        "checks": checks,
        "contractTestsCommand": command_details(gradle_result, settings),
    }
    if gradle_result is not None and gradle_result.exit_code != 0:
        errors.append("platform-apphost sandbox provider tests failed")
    if gradle_result is None and settings.mode == "release-candidate":
        errors.append("platform-apphost sandbox provider tests were skipped")
    if errors:
        return EvidenceItem(
            "apphost.sandbox-provider",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "AppHost sandbox provider evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "apphost.sandbox-provider",
        "pass",
        True,
        "AppHost sandbox provider contract passed using deterministic offline evidence.",
        source,
        details,
    )


def read_source(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def java_source_without_comments(source: str) -> str:
    """Return Java source with line and block comments removed.

    Certification source checks often need to prove that serialized field names
    are safe. Redaction policy comments may legitimately mention tokens, paths,
    or other forbidden payloads, so callers should strip comments before checking
    Java identifiers or JSON keys.
    """
    result: list[str] = []
    index = 0
    in_string = False
    in_char = False
    escaped = False
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if in_string or in_char:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif in_string and char == '"':
                in_string = False
            elif in_char and char == "'":
                in_char = False
            index += 1
            continue
        if char == '"':
            in_string = True
            result.append(char)
            index += 1
            continue
        if char == "'":
            in_char = True
            result.append(char)
            index += 1
            continue
        if char == "/" and next_char == "/":
            index += 2
            while index < len(source) and source[index] not in "\r\n":
                index += 1
            result.append("\n")
            continue
        if char == "/" and next_char == "*":
            index += 2
            while index + 1 < len(source) and not (
                source[index] == "*" and source[index + 1] == "/"
            ):
                if source[index] in "\r\n":
                    result.append("\n")
                index += 1
            index = min(index + 2, len(source))
            continue
        result.append(char)
        index += 1
    return "".join(result)


def split_java_top_level_commas(source: str) -> list[str]:
    parts: list[str] = []
    start = 0
    angle_depth = 0
    paren_depth = 0
    bracket_depth = 0
    for index, char in enumerate(source):
        if char == "<":
            angle_depth += 1
        elif char == ">" and angle_depth > 0:
            angle_depth -= 1
        elif char == "(":
            paren_depth += 1
        elif char == ")" and paren_depth > 0:
            paren_depth -= 1
        elif char == "[":
            bracket_depth += 1
        elif char == "]" and bracket_depth > 0:
            bracket_depth -= 1
        elif char == "," and angle_depth == 0 and paren_depth == 0 and bracket_depth == 0:
            parts.append(source[start:index].strip())
            start = index + 1
    parts.append(source[start:].strip())
    return [part for part in parts if part]


def java_record_component_names(source: str, record_name: str) -> set[str]:
    source_without_comments = java_source_without_comments(source)
    match = re.search(
        rf"\brecord\s+{re.escape(record_name)}\s*\((?P<components>.*?)\)\s*\{{",
        source_without_comments,
        re.DOTALL,
    )
    if not match:
        return set()
    names: set[str] = set()
    for component in split_java_top_level_commas(match.group("components")):
        name_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", component)
        if name_match:
            names.add(name_match.group(1))
    return names


def java_json_field_names(source: str) -> set[str]:
    source_without_comments = java_source_without_comments(source)
    return set(re.findall(r'\bjson\.put\(\s*"([^"]+)"', source_without_comments))


def app_service_bundle_public_fields_are_safe(bundle_source: str) -> bool:
    public_fields = java_record_component_names(bundle_source, "AppServiceGrantBundle")
    public_fields.update(java_json_field_names(bundle_source))
    forbidden_fragments = (
        "token",
        "path",
        "privateinserturi",
        "privatekey",
        "subjecturi",
        "requestbody",
        "rawbody",
        "providerstate",
        "processstate",
        "appdatabackup",
    )
    return bool(public_fields) and not any(
        fragment in field_name.lower()
        for field_name in public_fields
        for fragment in forbidden_fragments
    )


def source_contains_markup_fixture(source: str, fixture: str) -> bool:
    return fixture in source or fixture.replace('"', '\\"') in source


def public_beta_security_item(
    settings: Settings,
    evidence_id: str,
    pass_summary: str,
    checks: dict[str, bool],
    details: dict[str, Any],
) -> EvidenceItem:
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            evidence_id,
            root_consequence(settings, "fail"),
            True,
            f"{evidence_id} evidence is incomplete.",
            summary_source(settings),
            {"errors": errors, **details},
        )
    return EvidenceItem(evidence_id, "pass", True, pass_summary, summary_source(settings), details)


def public_beta_redaction_fuzz_checks(settings: Settings) -> dict[str, Any]:
    raw = {
        "auditEvent": PUBLIC_BETA_SECURITY_SENSITIVE_FIXTURES,
        "transparencyLog": {
            "recordCount": 2,
            "latestHash": "sha256:0123456789abcdef",
            "reviewerKeyId": "reviewer-local-public",
            "policyId": "crypta-app-review-v1",
            "rawSignatureValue": "MEUCIQD...",
            "localEvidencePath": "/home/alice/.crypta/reviews/evidence.json",
        },
        "webShellSummary": (
            "Authorization: Bearer host-or-app-secret\n"
            "raw fetched body: <script>alert(1)</script>\n"
            "raw trust statement body: signed-trust-document\n"
            "raw message body: private-social-body"
        ),
    }
    redacted = sanitize_value(raw, settings.workspace_root, "releaseEvidence")
    encoded = json.dumps(redacted, sort_keys=True)
    fixture_leaks = [
        value for value in PUBLIC_BETA_SECURITY_SENSITIVE_FIXTURES if value and value in encoded
    ]
    high_risk_leaks = [
        value
        for value in (
            "browser-session-secret",
            "form-secret",
            "host-or-app-secret",
            "PRIVATE-INSERT-URI",
            "BEGIN PRIVATE KEY",
            "BEGIN OPENSSH PRIVATE KEY",
            "pem-private-key-body",
            "truncated-pem-private-key-body",
            "END PRIVATE KEY",
            "private-document",
            "signed-trust-document",
            "private-social-body",
            "/home/alice/.crypta",
            r"C:\Users\Alice",
            "<script>alert(1)</script>",
            "MEUCIQD",
        )
        if value in encoded
    ]
    return {
        "redacted": redacted,
        "encoded": encoded,
        "fixtureLeaks": fixture_leaks,
        "highRiskLeaks": high_risk_leaks,
        "placeholdersPresent": "<redacted>" in encoded or "<redacted-uri>" in encoded,
        "publicMetadataRetained": "reviewer-local-public" in encoded
        and "sha256:0123456789abcdef" in encoded,
    }


def collect_public_beta_security_evidence(settings: Settings) -> list[EvidenceItem]:
    workspace = settings.workspace_root
    app_ui_headers = read_source(
        workspace
        / "platform-app-ui/src/main/java/network/crypta/platform/appui/AppUiSecurityHeaders.java"
    )
    app_ui_headers_test = read_source(
        workspace
        / "platform-app-ui/src/test/java/network/crypta/platform/appui/AppUiSecurityHeadersTest.java"
    )
    web_shell = read_source(
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    web_shell_test = read_source(
        workspace
        / "platform-web-shell/src/test/java/network/crypta/platform/webshell/WebShellResourcesTest.java"
    )
    content_policy = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/ContentFetchPolicy.java"
    )
    content_handler = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/ContentApiHandler.java"
    )
    content_tests = "\n".join(
        read_source(path)
        for path in sorted((workspace / "platform-api/src/test/java").rglob("*Content*.java"))
    )
    feed_app = read_source(workspace / "apps/feed-reader/src/staged/static/app.js")
    feed_tests = "\n".join(
        read_source(path)
        for path in sorted((workspace / "apps/feed-reader/src/test/java").rglob("*.java"))
    )
    social_app = read_source(workspace / "apps/social-inbox/src/staged/static/app.js")
    social_tests = "\n".join(
        read_source(path)
        for path in sorted((workspace / "apps/social-inbox/src/test/java").rglob("*.java"))
    )
    profile_app = read_source(workspace / "apps/profile-publisher/src/staged/static/app.js")
    profile_tests = "\n".join(
        read_source(path)
        for path in sorted((workspace / "apps/profile-publisher/src/test/java").rglob("*.java"))
    )
    trust_sources = "\n".join(
        read_source(path)
        for path in (
            workspace
            / "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph/TrustStatementParser.java",
            workspace
            / "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph/TrustStatementValidator.java",
            workspace
            / "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph/TrustGraphStoreSanitizer.java",
            workspace
            / "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph/TrustStatementPayload.java",
            workspace
            / "platform-api/src/main/java/network/crypta/platform/api/trust/TrustGraphApiHandler.java",
            workspace
            / "platform-api/src/main/java/network/crypta/platform/api/appvault/TrustStatementRequest.java",
        )
    )
    trust_tests = "\n".join(
        read_source(path)
        for path in (
            workspace
            / "platform-trustgraph/src/test/java/network/crypta/platform/trustgraph/TrustStatementParserTest.java",
            workspace
            / "platform-api/src/test/java/network/crypta/platform/api/TrustGraphApiRouterTest.java",
            workspace / "platform-api/src/test/java/network/crypta/platform/api/AppVaultApiRouterTest.java",
        )
    )
    apphost_source = read_source(
        workspace
        / "platform-apphost/src/main/java/network/crypta/platform/apphost/runtime/LocalProcessAppHost.java"
    )
    apphost_tests = read_source(
        workspace
        / "platform-apphost/src/test/java/network/crypta/platform/apphost/runtime/LocalProcessAppHostTest.java"
    )
    sandbox_sources = "\n".join(
        read_source(path)
        for path in sorted(
            (
                workspace
                / "platform-apphost/src/main/java/network/crypta/platform/apphost/sandbox"
            ).glob("*.java")
        )
    )
    sandbox_tests = "\n".join(
        read_source(path)
        for path in sorted(
            (
                workspace
                / "platform-apphost/src/test/java/network/crypta/platform/apphost/sandbox"
            ).glob("*.java")
        )
    )
    appreview_source = "\n".join(
        read_source(path)
        for path in sorted(
            (workspace / "platform-appcatalog/src/main/java").rglob("*Review*.java")
        )
    )
    appreview_tests = "\n".join(
        read_source(path)
        for path in sorted(
            (workspace / "platform-appcatalog/src/test/java").rglob("*Review*.java")
        )
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/SECURITY.md",
            "docs/app-owned-ui.md",
            "docs/app-ui-design-system.md",
            "docs/app-permissions-and-audit.md",
            "docs/feed-reader-reference-app.md",
            "docs/social-inbox-reference-app.md",
            "docs/trust-graph-preview.md",
            "docs/apphost-runtime-hardening.md",
            "docs/app-platform-beta-known-limitations.md",
            "docs/release-certification.md",
        )
    )
    redaction_checks = public_beta_redaction_fuzz_checks(settings)
    return [
        public_beta_security_item(
            settings,
            "public-beta-security.app-ui-csp",
            "Static app UI CSP and defensive header evidence passed.",
            {
                "defaultNone": "default-src " in app_ui_headers and "'none'" in app_ui_headers,
                "localScriptStyleConnect": all(
                    marker in app_ui_headers for marker in ("script-src", "style-src", "connect-src")
                ),
                "blockedDangerousDirectives": all(
                    marker in app_ui_headers
                    for marker in ("object-src", "base-uri", "worker-src", "frame-src", "manifest-src")
                ),
                "defensiveHeaders": all(
                    marker in app_ui_headers
                    for marker in (
                        "permissions-policy",
                        "cross-origin-resource-policy",
                        "nosniff",
                        "no-referrer",
                    )
                ),
                "safeOriginTests": all(
                    marker in app_ui_headers_test
                    for marker in ("admin.example", "0.0.0.0", "127.0.0.1.attacker.example", "user:pass@", "ftp://")
                ),
                "docsUpdated": "default-src 'none'" in docs_text
                and "CSP is a browser mitigation" in docs_text,
            },
            {"sources": ["platform-app-ui", "docs/app-owned-ui.md"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.app-origin-policy",
            "Web Shell app-origin launch policy evidence passed.",
            {
                "registeredLoopbackOrigin": "function registeredAppUiOrigin(app)" in web_shell
                and "127.0.0.1" in web_shell,
                "rejectsCredentials": "url.username" in web_shell and "url.password" in web_shell,
                "rejectsSearchHash": "url.search !== \"\"" in web_shell
                and "url.hash !== \"\"" in web_shell,
                "sameOriginFallbackOnly": "safeSameOriginAppUiHref" in web_shell and "/apps/" in web_shell,
                "probeCorsSafe": "credentials: \"omit\"" in web_shell and "mode: \"cors\"" in web_shell,
                "sourceTests": "assertAppUiOriginHardeningMarkersPresent" in web_shell_test,
            },
            {"sources": ["platform-web-shell"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.content-fetch-bounds",
            "Content fetch bound and URI-family evidence passed.",
            {
                "sharedPolicy": "class ContentFetchPolicy" in content_policy,
                "contentKeyFamiliesOnly": all(
                    marker in content_policy for marker in ("CHK@", "SSK@", "USK@", "KSK@", "crypta:")
                ),
                "rejectsExternalSources": all(
                    marker in content_tests
                    for marker in ("http://", "https://", "file://", "//example.invalid", "C:\\\\Users")
                ),
                "hardBounds": "HARD_APP_FETCH_MAX_BYTES" in content_policy
                and "HARD_APP_FETCH_TIMEOUT_MILLIS" in content_policy,
                "strictUtf8": "CodingErrorAction.REPORT" in content_handler
                and "unsupported_content_encoding" in content_handler,
                "redactedErrors": "content_fetch_failed" in content_handler and "SECRET" in content_tests,
            },
            {"sources": ["platform-api", "runtime-spi"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.feed-sanitization",
            "Feed Reader sanitization evidence passed.",
            {
                "textRendering": "textContent" in feed_app,
                "noHtmlInjection": "innerHTML" not in feed_app and "insertAdjacentHTML" not in feed_app,
                "activeMarkupNeutralized": all(
                    marker in feed_app for marker in ("srcdoc", "iframe", "base", "svg")
                ),
                "cryptaUriValidation": "normalizedCryptaContentUri" in feed_app,
                "adversarialFixtures": all(
                    source_contains_markup_fixture(feed_tests, marker)
                    for marker in PUBLIC_BETA_SECURITY_MARKUP_FIXTURES
                ),
            },
            {"sources": ["apps/feed-reader"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.social-inbox-sanitization",
            "Social Inbox sanitization evidence passed.",
            {
                "textRendering": "textContent" in social_app,
                "noHtmlInjection": "innerHTML" not in social_app and "insertAdjacentHTML" not in social_app,
                "cryptaUriValidation": "normalizedCryptaContentUri" in social_app,
                "boundedFields": all(
                    marker in social_app
                    for marker in (
                        "maxDraftBodyLength",
                        "maxImportedSubjectLength",
                        "maxAuthorLabelLength",
                        "maxImportedMessages",
                    )
                )
                and ("maxImportedBodyPreviewLength" in social_app),
                "adversarialFixtures": all(
                    source_contains_markup_fixture(social_tests, marker)
                    for marker in PUBLIC_BETA_SECURITY_MARKUP_FIXTURES
                ),
            },
            {"sources": ["apps/social-inbox"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.profile-sanitization",
            "Profile Publisher sanitization evidence passed.",
            {
                "textRendering": "textContent" in profile_app,
                "noHtmlInjection": "innerHTML" not in profile_app and "insertAdjacentHTML" not in profile_app,
                "activeMarkupNeutralized": all(
                    marker in profile_app for marker in ("srcdoc", "iframe", "base", "svg")
                ),
                "bounds": all(
                    marker in profile_app
                    for marker in (
                        "maxProfileTextLength",
                        "maxProfileBioLength",
                        "maxContentUriLength",
                        "maxRecentActions",
                    )
                ),
                "websiteTextPreserved": "optionalProfileWebsite" in profile_app
                and "website.length > maxContentUriLength" in profile_app
                and "website: optionalProfileWebsite" in profile_app,
                "privateMaterialExcluded": all(
                    marker not in profile_app for marker in ("privateKey", "seedPhrase", "rawSignature")
                ),
                "sourceTests": "textContent" in profile_tests and "innerHTML" in profile_tests,
            },
            {"sources": ["apps/profile-publisher"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.trust-statement-hardening",
            "Trust statement parser, signing, and audit hardening evidence passed.",
            {
                "byteCap": "MAX_DOCUMENT_BYTES" in trust_sources,
                "unknownFields": "rejectUnknown" in trust_sources,
                "isoControlRejected": "Character.isISOControl" in trust_sources,
                "rangeChecks": "requireScore" in trust_sources and "requireConfidence" in trust_sources,
                "expiresAfterIssued": "expiresAt.isAfter(issuedAt)" in trust_sources,
                "unsupportedSigningParameters": "SUPPORTED_PARAMETERS" in trust_sources,
                "redactedRejectedAudit": "redactedRejectedUriSummary" in trust_sources
                and "uri:redacted" in trust_tests,
                "maliciousTests": all(
                    marker in trust_tests for marker in ("\\u0000", "\\u0085", "50.5", "token=secret")
                ),
            },
            {"sources": ["platform-trustgraph", "platform-api"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.apphost-env-minimization",
            "AppHost launch environment minimization evidence passed.",
            {
                "clearsEnvironment": "environment.clear()" in apphost_source,
                "documentedAppVariables": all(
                    marker in apphost_source
                    for marker in (
                        "CRYPTAD_APP_ID",
                        "CRYPTAD_APP_TOKEN",
                        "CRYPTAD_APP_PERMISSIONS",
                        "CRYPTAD_APP_UI_MODE",
                    )
                ),
                "deterministicUnixPath": "safeUnixPath" in apphost_source
                and "BASE_UNIX_PATH_ENTRIES" in apphost_source,
                "secretEnvTests": all(
                    marker in apphost_tests
                    for marker in (
                        "JAVA_TOOL_OPTIONS",
                        "LD_PRELOAD",
                        "AWS_SECRET_ACCESS_KEY",
                        "OPENAI_API_KEY",
                        "SSH_AUTH_SOCK",
                        "PRIVATE_KEY",
                        "CRYPTAD_APPHOST_BWRAP",
                    )
                ),
                "docsBoundary": "Public-beta certification treats the environment allow-list"
                in docs_text,
            },
            {"sources": ["platform-apphost"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.sandbox-host-checks",
            "Sandbox provider host-check and fail-closed evidence passed.",
            {
                "pathFreeAvailability": "path-free" in sandbox_sources.lower(),
                "failClosedRequired": "RequiredRestrictedProcess" in sandbox_tests
                and "expectFailClosed" in sandbox_tests,
                "preflightFailure": "PreflightFails" in sandbox_tests,
                "commandContainmentFlags": all(
                    marker in sandbox_tests
                    for marker in (
                        "--die-with-parent",
                        "--new-session",
                        "--unshare-pid",
                        "--unshare-ipc",
                        "--ro-bind",
                        "--bind",
                    )
                ),
                "tokenNotInCommand": "CRYPTAD_APP_TOKEN" in sandbox_tests
                and "assertFalse(commandText.contains" in sandbox_tests,
                "noOverclaim": "network isolation" in docs_text
                and "does not enforce CPU, memory, or network isolation" in docs_text,
            },
            {"sources": ["platform-apphost/src/main/java/network/crypta/platform/apphost/sandbox"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.audit-redaction-fuzz",
            "Audit and release evidence redaction fuzz fixtures passed.",
            {
                "noFixtureLeaks": not redaction_checks["fixtureLeaks"],
                "noHighRiskLeaks": not redaction_checks["highRiskLeaks"],
                "placeholdersPresent": bool(redaction_checks["placeholdersPresent"]),
                "publicMetadataRetained": bool(redaction_checks["publicMetadataRetained"]),
                "docsBoundary": "Public-beta release evidence is redacted evidence" in docs_text,
            },
            {"redaction": {k: v for k, v in redaction_checks.items() if k != "encoded"}},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.transparency-log-privacy",
            "App-review governance and transparency-log privacy evidence passed.",
            {
                "sourcePresent": "Transparency" in appreview_source,
                "privacyTests": "raw public key" in appreview_tests.lower()
                or "rawPublicKey" in appreview_tests,
                "redactedSummaries": all(
                    marker in docs_text
                    for marker in (
                        "record counts",
                        "latest hashes",
                        "raw receipt signatures",
                        "catalog scratch paths",
                    )
                ),
                "localLogScoped": "local transparency log" in docs_text
                and "not a global public log" in docs_text,
                "noKnownPrivateFixtures": not redaction_checks["highRiskLeaks"],
            },
            {"sources": ["platform-appcatalog", "docs/SECURITY.md", "docs/release-certification.md"]},
        ),
    ]


def collect_app_update_lifecycle_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    apphost_source = (
        settings.workspace_root
        / "platform-apphost/src/main/java/network/crypta/platform/apphost/runtime/LocalProcessAppHost.java"
    )
    catalog_handler_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    )
    update_service_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateService.java"
    )
    update_handler_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdatesApiHandler.java"
    )
    update_policy_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdatePolicyMode.java"
    )
    update_candidate_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateCandidate.java"
    )
    update_status_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateCandidateStatus.java"
    )
    update_service_test_source = (
        settings.workspace_root
        / "platform-api/src/test/java/network/crypta/platform/api/appupdates/AppUpdateServiceTest.java"
    )
    router_test_source = settings.workspace_root / "src/test/java/network/crypta/platform/api/PlatformApiRouterTest.java"
    lifecycle_doc = settings.workspace_root / "docs/app-update-lifecycle.md"
    apphost_text = read_source(apphost_source)
    catalog_text = read_source(catalog_handler_source)
    update_service_text = read_source(update_service_source)
    update_handler_text = read_source(update_handler_source)
    policy_text = read_source(update_policy_source)
    candidate_text = read_source(update_candidate_source)
    status_text = read_source(update_status_source)
    update_service_test_text = read_source(update_service_test_source)
    router_test_text = read_source(router_test_source)
    doc_text = read_source(lifecycle_doc)
    checks = {
        "apphostUpdateEntryPoint": "updateFromDirectory" in apphost_text,
        "policyModes": (
            'MANUAL("manual")' in policy_text
            and 'STAGE("stage")' in policy_text
            and 'APPLY_WHEN_STOPPED("apply_when_stopped")' in policy_text
        ),
        "managedStageCopyBeforeValidation": (
            "copyDirectoryTree(stagingRoot, temporaryInstallRoot)" in apphost_text
            and "verifyCopiedBundle(temporaryInstallRoot)" in apphost_text
            and "validateCopiedBundle(temporaryInstallRoot)" in apphost_text
        ),
        "matchingAppIdGate": "requireMatchingUpdateTarget(normalizedAppId, manifest)" in apphost_text,
        "hostApplyWhenStoppedGate": (
            "liveRunningProcess(normalizedAppId) != null" in apphost_text
            and "cannot update a running app" in apphost_text
        ),
        "updateApplyRunningConflictTest": (
            "apply_whenAppStartsAfterPrecheck_expectConflictNotServerError"
            in update_service_test_text
            and '"cannot update a running app: " + APP_ID' in update_service_test_text
            and 'assertEquals("app_running", exception.errorCode())' in update_service_test_text
        ),
        "updateApplyRunningConflictRouteTest": (
            "route_whenAppUpdateApplyRequestedWhileRunning_expectConflictJson" in router_test_text
            and 'List.of("apps", APP_ID, "updates", "apply")' in router_test_text
            and "assertEquals(409, response.statusCode())" in router_test_text
            and 'verify(appHost, never()).updateFromDirectory(APP_ID, stagedDir)' in router_test_text
            and "app_running" in router_test_text
        ),
        "catalogVersionComparison": (
            "versionDifferent(" in catalog_text
            and "updateAvailable(" in catalog_text
            and '"versionDifferent"' in catalog_text
            and '"updateAvailable"' in catalog_text
        ),
        "candidateDetectionSemantics": (
            'AVAILABLE("available")' in status_text
            and 'STAGED("staged")' in status_text
            and 'BLOCKED("blocked")' in status_text
            and 'INCOMPATIBLE("incompatible")' in status_text
            and 'AMBIGUOUS("ambiguous")' in status_text
            and 'ROLLBACK_AVAILABLE("rollback_available")' in status_text
        ),
        "candidateReviewMetadata": '"review"' in candidate_text and "reviewSummary" in candidate_text,
        "candidateCompatibilityMetadata": (
            '"apiCompatibility"' in candidate_text and "apiCompatibility" in candidate_text
        ),
        "permissionDeltaReview": (
            "permissionDelta" in candidate_text and '"permissionDelta"' in candidate_text
        ),
        "lifecycleHandlerRoutesStageAndApply": (
            "Map<String, Object> stage(String appId)" in update_handler_text
            and "return updateService.stage(appId)" in update_handler_text
            and (
                "Map<String, Object> apply(String appId, Map<String, List<String>> queryParameters)"
                in update_handler_text
            )
            and (
                "return updateService.apply(appId, applyOptions(queryParameters))"
                in update_handler_text
            )
        ),
        "lifecycleServiceStagesVerifiedPlan": (
            "public synchronized Map<String, Object> stage(String appId)" in update_service_text
            and (
                "catalogManager.prepareInstallPlan(candidate.catalogId(), appId)"
                in update_service_text
            )
            and "planDiffersFromCandidate(candidate, installed, plan)" in update_service_text
        ),
        "lifecycleServiceApplyDelegatesToAppHost": (
            (
                "public synchronized Map<String, Object> apply(String appId, ApplyOptions options)"
                in update_service_text
            )
            and (
                "appHost.updateFromDirectory(normalizedAppId, staged.stagedBundleDirectory())"
                in update_service_text
            )
            and "closeStage(normalizedAppId)" in update_service_text
        ),
        "manualApplyPolicyDocumented": (
            "apply_when_stopped" in doc_text
            and "manual" in doc_text
            and "stage" in doc_text
            and "Silent automatic update is not the default" in doc_text
            and "requires an operator or explicit API caller" in doc_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "policy": "manual/stage/apply_when_stopped",
        "silentAutoUpdateDefault": False,
        "liveNodeRequired": False,
        "checks": checks,
        "sources": {
            "apphost": display_path(apphost_source, settings.workspace_root),
            "catalogHandler": display_path(catalog_handler_source, settings.workspace_root),
            "updateService": display_path(update_service_source, settings.workspace_root),
            "updateHandler": display_path(update_handler_source, settings.workspace_root),
            "updatePolicy": display_path(update_policy_source, settings.workspace_root),
            "updateCandidate": display_path(update_candidate_source, settings.workspace_root),
            "updateStatus": display_path(update_status_source, settings.workspace_root),
            "updateServiceTest": display_path(update_service_test_source, settings.workspace_root),
            "routerTest": display_path(router_test_source, settings.workspace_root),
            "lifecycleDoc": display_path(lifecycle_doc, settings.workspace_root),
        },
    }
    if errors:
        return EvidenceItem(
            "app-update.lifecycle",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "App-update lifecycle evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-update.lifecycle",
        "pass",
        True,
        "App-update lifecycle policy passed deterministic offline evidence checks.",
        source,
        details,
    )


def collect_app_update_scheduler_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    scheduler_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateScheduler.java"
    )
    scheduler_config_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateSchedulerConfig.java"
    )
    scheduler_state_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateSchedulerState.java"
    )
    scheduler_store_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/FileAppUpdateSchedulerStore.java"
    )
    update_service_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateService.java"
    )
    scheduler_test_source = (
        settings.workspace_root
        / "platform-api/src/test/java/network/crypta/platform/api/appupdates/AppUpdateSchedulerTest.java"
    )
    scheduler_config_test_source = (
        settings.workspace_root
        / "platform-api/src/test/java/network/crypta/platform/api/appupdates/AppUpdateSchedulerConfigTest.java"
    )
    runtime_source = (
        settings.workspace_root
        / "bridge-http-runtime/src/main/java/network/crypta/clients/http/bridge/CoreHttpShellRuntimeSupport.java"
    )
    web_shell_source = (
        settings.workspace_root
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    lifecycle_doc = settings.workspace_root / "docs/app-update-lifecycle.md"
    scheduler_text = read_source(scheduler_source)
    scheduler_config_text = read_source(scheduler_config_source)
    scheduler_state_text = read_source(scheduler_state_source)
    scheduler_store_text = read_source(scheduler_store_source)
    update_service_text = read_source(update_service_source)
    scheduler_test_text = read_source(scheduler_test_source)
    scheduler_config_test_text = read_source(scheduler_config_test_source)
    runtime_text = read_source(runtime_source)
    web_shell_text = read_source(web_shell_source)
    doc_text = read_source(lifecycle_doc)
    checks = {
        "schedulerSourcePresent": (
            "public final class AppUpdateScheduler" in scheduler_text
            and "AppUpdateSchedulerConfig" in scheduler_text
            and "AppUpdateSchedulerStore" in scheduler_text
        ),
        "schedulerConfigPresent": (
            "CRYPTAD_APPUPDATES_SCHEDULER_ENABLED" in scheduler_config_text
            and "cryptad.appupdates.scheduler.appCheckIntervalSeconds" in scheduler_config_text
            and "defaults()" in scheduler_config_text
            and "true," in scheduler_config_text
            and "from(Map<?, ?> properties, Map<String, String> environment)" in scheduler_config_text
            and "from_whenValuesMalformed_expectDefaultsRetained" in scheduler_config_test_text
        ),
        "schedulerSummaryPublished": (
            'json.put("scheduler", schedulerSummaryProvider.schedulerSummary(appId))'
            in update_service_text
            and '"lastCheckAt"' in scheduler_state_text
            and '"nextCheckAt"' in scheduler_state_text
            and '"failureCount"' in scheduler_state_text
            and '"lastErrorCode"' in scheduler_state_text
            and '"concurrency"' in scheduler_state_text
        ),
        "schedulerCatalogRefresh": (
            "catalogManager.listCatalogs()" in scheduler_text
            and "catalogManager.refresh(catalog.catalogId())" in scheduler_text
            and "MESSAGE_CATALOG_REFRESH_FAILED" in scheduler_text
        ),
        "schedulerDelegatesToUpdateCheck": (
            "updateService.check(state.appId(), false)" in scheduler_text
            and "updateService.stage(" not in scheduler_text
            and "updateService.apply(" not in scheduler_text
            and "appHost.updateFromDirectory(" not in scheduler_text
            and "catalogManager.prepareInstallPlan(" not in scheduler_text
        ),
        "schedulerManualPolicyDoesNotMutate": (
            "tick_whenManualPolicy_expectCheckOnlyAndNoStageOrApply" in scheduler_test_text
            and "verify(catalogManager, never()).prepareInstallPlan" in scheduler_test_text
            and "verify(appHost, never()).updateFromDirectory" in scheduler_test_text
        ),
        "schedulerPolicyDrivenChecks": (
            "tick_whenStagePolicy_expectVerifiedCandidateStagedByServicePolicy"
            in scheduler_test_text
            and "tick_whenApplyWhenStoppedPolicy_expectStoppedAppAppliedByServicePolicy"
            in scheduler_test_text
            and "tick_whenApplyWhenStoppedPolicyAndAppRunning_expectRunningAppNotStoppedOrUpdated"
            in scheduler_test_text
            and "Policy skipped apply because the app is running." in scheduler_test_text
        ),
        "schedulerFailureContained": (
            "tick_whenCheckFails_expectSanitizedFailureAndBackoff" in scheduler_test_text
            and "tick_whenCatalogRefreshFails_expectFailureContainedAndAppsStillChecked"
            in scheduler_test_text
            and "catalog_refresh_failed" in scheduler_text
            and "Scheduler update check failed." in scheduler_text
        ),
        "schedulerDurableStore": (
            "public final class FileAppUpdateSchedulerStore" in scheduler_store_text
            and "ATOMIC_MOVE" in scheduler_store_text
            and "update-scheduler" in runtime_text
            and "layout.dataDir().resolve(\"apps\").resolve(\"update-scheduler\")" in runtime_text
        ),
        "schedulerPerAppSerialized": (
            "AtomicBoolean running" in scheduler_text
            and "alreadyRunning" in scheduler_text
            and "per-app-serialized" in scheduler_state_text
            and "summary_whenSchedulerStatePresent_expectPathFreeSchedulerSummary"
            in scheduler_test_text
        ),
        "schedulerPathAndPrivateDataFree": (
            "summary_whenSchedulerStatePresent_expectPathFreeSchedulerSummary" in scheduler_test_text
            and "secret-token" in scheduler_test_text
            and "contains(tempDir.toString())" in scheduler_test_text
            and "catalog scratch" in scheduler_state_text
            and "staged bundle path" in scheduler_state_text
        ),
        "schedulerRuntimeWiring": (
            "createAppUpdateScheduler(" in runtime_text
            and "appUpdateService.setSchedulerSummaryProvider(appUpdateScheduler::summary)"
            in runtime_text
            and "appUpdateScheduler.start()" in runtime_text
            and "createAppUpdateSchedulerShutdownJob" in runtime_text
        ),
        "schedulerWebShellDisplay": (
            "Scheduler status" in web_shell_text
            and "Scheduler failures" in web_shell_text
            and "Last scheduler error" in web_shell_text
        ),
        "schedulerLifecycleDocumented": (
            "background scheduler" in doc_text.lower()
            and "manual remains the default" in doc_text.lower()
            and "AppUpdateService.check" in doc_text
            and "app-update.scheduler" in doc_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "policy": "manual default; policy-driven stage/apply only after explicit selection",
        "silentAutoUpdateDefault": False,
        "liveNodeRequired": False,
        "checks": checks,
        "sources": {
            "scheduler": display_path(scheduler_source, settings.workspace_root),
            "schedulerConfig": display_path(scheduler_config_source, settings.workspace_root),
            "schedulerState": display_path(scheduler_state_source, settings.workspace_root),
            "schedulerStore": display_path(scheduler_store_source, settings.workspace_root),
            "updateService": display_path(update_service_source, settings.workspace_root),
            "schedulerTest": display_path(scheduler_test_source, settings.workspace_root),
            "schedulerConfigTest": display_path(
                scheduler_config_test_source, settings.workspace_root
            ),
            "runtime": display_path(runtime_source, settings.workspace_root),
            "webShell": display_path(web_shell_source, settings.workspace_root),
            "lifecycleDoc": display_path(lifecycle_doc, settings.workspace_root),
        },
    }
    if errors:
        return EvidenceItem(
            "app-update.scheduler",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "App-update scheduler evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-update.scheduler",
        "pass",
        True,
        "App-update background scheduler passed deterministic offline evidence checks.",
        source,
        details,
    )


def collect_app_update_live_catalog_refresh_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    scheduler_source = (
        workspace / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateScheduler.java"
    )
    update_service_source = (
        workspace / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateService.java"
    )
    scheduler_test_source = (
        workspace / "platform-api/src/test/java/network/crypta/platform/api/appupdates/AppUpdateSchedulerTest.java"
    )
    catalog_routes_source = (
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiAppRoutes.java"
    )
    catalog_handler_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    )
    lifecycle_doc = workspace / "docs/app-update-lifecycle.md"
    catalog_doc = workspace / "docs/app-catalogs.md"
    scheduler_text = read_source(scheduler_source)
    update_service_text = read_source(update_service_source)
    scheduler_test_text = read_source(scheduler_test_source)
    catalog_routes_text = read_source(catalog_routes_source)
    catalog_handler_text = read_source(catalog_handler_source)
    docs_text = read_source(lifecycle_doc) + "\n" + read_source(catalog_doc)
    checks = {
        "refreshBeforeCandidateDiscovery": (
            "catalogManager.listCatalogs()" in scheduler_text
            and "catalogManager.refresh(catalog.catalogId())" in scheduler_text
            and "updateService.check(state.appId(), false)" in scheduler_text
            and "inOrder(catalogManager, updateService)" in scheduler_test_text
        ),
        "refreshFailureContained": (
            "MESSAGE_CATALOG_REFRESH_FAILED" in scheduler_text
            and "tick_whenCatalogRefreshFails_expectFailureContainedAndAppsStillChecked"
            in scheduler_test_text
        ),
        "schedulerDoesNotApplyDirectly": (
            "updateService.stage(" not in scheduler_text
            and "updateService.apply(" not in scheduler_text
            and "appHost.updateFromDirectory(" not in scheduler_text
            and "catalogManager.prepareInstallPlan(" not in scheduler_text
        ),
        "manualPolicyStillDefault": (
            "manual remains the default" in scheduler_text.lower()
            and "tick_whenManualPolicy_expectCheckOnlyAndNoStageOrApply" in scheduler_test_text
            and "verify(catalogManager, never()).prepareInstallPlan" in scheduler_test_text
        ),
        "policyDrivenUpdatesStayInService": (
            "check(state.appId(), false)" in scheduler_text
            and "check(" in update_service_text
            and "stage(" in update_service_text
            and "apply(" in update_service_text
        ),
        "manualRefreshRouteExists": (
            '"refresh".equals(action)' in catalog_routes_text
            and '"/app-catalogs/{catalogId}/refresh"' in read_source(
                workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
            )
            and "refresh(catalogId)" in catalog_handler_text
        ),
        "schedulerSummaryPrivacyGuard": (
            "summary_whenSchedulerStatePresent_expectPathFreeSchedulerSummary"
            in scheduler_test_text
            and "secret-token" in scheduler_test_text
            and "contains(tempDir.toString())" in scheduler_test_text
        ),
        "docsCoverLiveCatalogRefresh": (
            "live USK catalog" in docs_text
            and "catalog refresh" in docs_text.lower()
            and "last verified" in docs_text.lower()
            and "manual remains the default" in docs_text.lower()
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "liveNodeRequired": False,
        "policy": "manual default; scheduler refreshes catalogs before candidate discovery",
        "silentAutoUpdateDefault": False,
        "checks": checks,
        "sources": {
            "scheduler": display_path(scheduler_source, workspace),
            "updateService": display_path(update_service_source, workspace),
            "schedulerTest": display_path(scheduler_test_source, workspace),
            "catalogRoutes": display_path(catalog_routes_source, workspace),
            "catalogHandler": display_path(catalog_handler_source, workspace),
            "lifecycleDoc": display_path(lifecycle_doc, workspace),
            "catalogDoc": display_path(catalog_doc, workspace),
        },
    }
    if errors:
        return EvidenceItem(
            "app-update.live-catalog-refresh",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Live catalog refresh scheduler evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-update.live-catalog-refresh",
        "pass",
        True,
        "Live catalog refresh scheduler evidence passed deterministic checks.",
        source,
        details,
    )


def collect_app_update_rollback_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    apphost_source = (
        settings.workspace_root
        / "platform-apphost/src/main/java/network/crypta/platform/apphost/runtime/LocalProcessAppHost.java"
    )
    apphost_test_source = (
        settings.workspace_root
        / "platform-apphost/src/test/java/network/crypta/platform/apphost/runtime/LocalProcessAppHostTest.java"
    )
    lifecycle_doc = settings.workspace_root / "docs/app-update-lifecycle.md"
    apphost_text = read_source(apphost_source)
    apphost_test_text = read_source(apphost_test_source)
    doc_text = read_source(lifecycle_doc)
    checks = {
        "managedBackupAllocated": (
            "TEMP_UPDATE_BACKUP_PREFIX" in apphost_text
            and "temporaryManagedPath(installedAppsDir, TEMP_UPDATE_BACKUP_PREFIX" in apphost_text
        ),
        "durableRollbackRoot": (
            "rollbackRootFor" in apphost_text
            and "ensureRollbackAppsDirectory" in apphost_text
            and "rollbackStatus" in apphost_text
        ),
        "installedBundleRecordedForRollback": (
            "moveIntoPlace(installedRoot, backupRoot)" in apphost_text
            and "moveIntoPlace(backupRoot, rollbackRoot)" in apphost_text
        ),
        "restorePreviousBundleOnReplacementFailure": (
            "restoreInstalledBundle(installedRoot, backupRoot, updateFailure)" in apphost_text
            and "restorePreviousRollback(" in apphost_text
        ),
        "manualRollbackSwapsBundles": (
            "swapInstalledBundleWithRollback" in apphost_text
            and "moveIntoPlace(rollbackRoot, installedRoot)" in apphost_text
            and "moveIntoPlace(currentInstallBackupRoot, rollbackRoot)" in apphost_text
        ),
        "replacementCommitToleratesPreviousRecordCleanupFailure": (
            "deleteBackupAfterSuccessfulReplacement" in apphost_text
            and "simulated backup cleanup failure" in apphost_test_text
            and "cleanupAttempts.incrementAndGet()" in apphost_test_text
            and 'resolve("first").resolve(SAMPLE_APP_ID)' in apphost_test_text
            and "assertEquals(0, cleanupAttempts.get())" in apphost_test_text
            and 'resolve("second").resolve(SAMPLE_APP_ID)' in apphost_test_text
            and "firstUpdate.manifest().appVersion()" in apphost_test_text
            and "assertEquals(1, cleanupAttempts.get())" in apphost_test_text
            and "expectPreviousBundleRecordedForRollback" in apphost_test_text
        ),
        "mutableDirectoriesPreservedByUpdate": (
            "preserve-data.txt" in apphost_test_text
            and "preserve-cache.txt" in apphost_test_text
            and "preserve-run.txt" in apphost_test_text
        ),
        "mutableDirectoriesPreservedByRollback": (
            "rollback-data.txt" in apphost_test_text
            and "rollback-cache.txt" in apphost_test_text
            and "rollback-run.txt" in apphost_test_text
        ),
        "rollbackHealthGate": (
            "cannot rollback a running app" in apphost_text
            and "rollback_whenAppIsRunning_expectFailureAndInstalledBundleUnchanged" in apphost_test_text
        ),
        "rollbackMetadataPathFree": (
            "rollbackStatus_whenRecordExists_expectMetadataOmitsTokensAndHostPaths" in apphost_test_text
        ),
        "rollbackScopeDocumented": (
            "Rollback covers only the immutable installed bundle" in doc_text
            and "Rollback does not roll back" in doc_text
            and "app data directories" in doc_text
            and "app cache directories" in doc_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "rollbackScope": "installed-bundle-only",
        "preservesDataCacheRun": True,
        "liveNodeRequired": False,
        "checks": checks,
        "sources": {
            "apphost": display_path(apphost_source, settings.workspace_root),
            "apphostTest": display_path(apphost_test_source, settings.workspace_root),
            "lifecycleDoc": display_path(lifecycle_doc, settings.workspace_root),
        },
    }
    if errors:
        return EvidenceItem(
            "app-update.rollback",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "App-update rollback evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-update.rollback",
        "pass",
        True,
        "App-update rollback scope passed deterministic offline evidence checks.",
        source,
        details,
    )


def collect_app_update_data_migration_contract_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    source_files = {
        "schemaContract": workspace
        / "platform-appdist/src/main/java/network/crypta/platform/appdist/AppDataSchemaContract.java",
        "namespaceSchema": workspace
        / "platform-appdist/src/main/java/network/crypta/platform/appdist/AppDataNamespaceSchema.java",
        "migrationStep": workspace
        / "platform-appdist/src/main/java/network/crypta/platform/appdist/AppDataMigrationStep.java",
        "migrationCommand": workspace
        / "platform-appdist/src/main/java/network/crypta/platform/appdist/AppDataMigrationCommand.java",
        "manifestParser": workspace
        / "platform-appdist/src/main/java/network/crypta/platform/appdist/AppBundleManifestParser.java",
        "structureValidator": workspace
        / "platform-appdist/src/main/java/network/crypta/platform/appdist/AppBundleStructureValidator.java",
        "structureValidatorTest": workspace
        / "platform-appdist/src/test/java/network/crypta/platform/appdist/AppBundleStructureValidatorTest.java",
        "manifestParserTest": workspace
        / "platform-appdist/src/test/java/network/crypta/platform/appdist/AppBundleManifestParserTest.java",
        "appHostManifest": workspace
        / "platform-apphost/src/main/java/network/crypta/platform/apphost/manifest/AppManifest.java",
        "appHostManifestParser": workspace
        / "platform-apphost/src/main/java/network/crypta/platform/apphost/manifest/AppManifestParser.java",
        "appDataService": workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataService.java",
        "appDataSnapshot": workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataUpdateSnapshot.java",
        "appDataServiceTest": workspace
        / "platform-api/src/test/java/network/crypta/platform/api/appdata/AppDataServiceTest.java",
        "migrationPlan": workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppDataMigrationPlan.java",
        "migrationRunner": workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppDataMigrationRunner.java",
        "migrationRunnerTest": workspace
        / "platform-api/src/test/java/network/crypta/platform/api/appupdates/AppDataMigrationRunnerTest.java",
        "updateCandidate": workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateCandidate.java",
        "updateService": workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateService.java",
        "updateHandler": workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdatesApiHandler.java",
        "updateServiceTest": workspace
        / "platform-api/src/test/java/network/crypta/platform/api/appupdates/AppUpdateServiceTest.java",
        "catalogManager": workspace
        / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog/AppCatalogManager.java",
        "catalogManagerTest": workspace
        / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog/AppCatalogManagerTest.java",
        "webShell": workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js",
        "feedScript": workspace / "apps/feed-reader/src/staged/bin/migrate-feed-data.sh",
        "trustScript": workspace / "apps/trust-graph/src/staged/bin/migrate-preview-data.sh",
    }
    text = {name: read_source(path) for name, path in source_files.items()}
    feed_manifest = read_first_manifest(
        workspace,
        "feed-reader",
        "apps/feed-reader/src/staged/cryptad-app.properties.template",
    )
    trust_manifest = read_first_manifest(
        workspace,
        "trust-graph",
        "apps/trust-graph/src/staged/cryptad-app.properties.template",
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/app-upgrade-data-migrations.md",
            "docs/app-update-lifecycle.md",
            "docs/app-data-store.md",
            "docs/app-distribution.md",
            "docs/app-platform-developer-portal.md",
            "docs/release-certification.md",
            "docs/production-first-party-catalog-channels.md",
            "tools/release-certification/README.md",
        )
    )
    dry_run_index = text["updateService"].find("AppDataMigrationRunner.Mode.DRY_RUN")
    staged_index = text["updateService"].find("new StagedUpdate")
    apply_verify_index = text["updateService"].find("verifyStagedBundleBeforeApply")
    apply_dry_run_index = text["updateService"].find("runApplyDryRunOrReject")
    barrier_index = text["updateService"].find("beginUpdateMigrationWriteBarrier")
    snapshot_index = text["updateService"].find("appDataSnapshot = createUpdateSnapshot")
    replacement_index = text["updateService"].find("appHost.updateFromDirectory")
    checks = {
        "manifestModelsAndParser": (
            "record AppDataSchemaContract" in text["schemaContract"]
            and "record AppDataNamespaceSchema" in text["namespaceSchema"]
            and "record AppDataMigrationStep" in text["migrationStep"]
            and "record AppDataMigrationCommand" in text["migrationCommand"]
            and "app.data.schema.current" in text["manifestParser"]
            and "app.data.migration." in text["manifestParser"]
            and "dataSchemaContract" in text["manifestParser"]
        ),
        "manifestValidationRejectsUnsafeMetadata": (
            "must stay under the app root" in text["migrationCommand"]
            and "WINDOWS_DRIVE_PREFIX_PATTERN" in text["migrationCommand"]
            and "AppDataNamespaceSchema.normalizeNamespace" in text["migrationStep"]
            and "toSchemaVersion <= fromSchemaVersion" in text["migrationStep"]
            and "unsupported app.data manifest property" in text["manifestParser"]
            and "app.data.migrations requires app.data.schema.current or app.data.schema.namespaces"
            in text["manifestParser"]
            and "app.data migration target exceeds declared schema" in text["manifestParser"]
            and "parseContent_whenMigrationDeclaresNoTargetSchema_expectFailure"
            in text["manifestParserTest"]
            and "parseContent_whenGlobalMigrationTargetExceedsSchema_expectFailure"
            in text["manifestParserTest"]
            and "parseContent_whenMigrationCommandEscapesBundle_expectFailure"
            in text["manifestParserTest"]
            and "parseContent_whenMigrationFieldIsUnknown_expectFailure"
            in text["manifestParserTest"]
        ),
        "signedBundleStructureChecksEntrypoints": (
            "step.command().path()" in text["structureValidator"]
            and "Files.isRegularFile" in text["structureValidator"]
            and "Files.isExecutable" not in text["structureValidator"]
            and "NOFOLLOW_LINKS" in text["structureValidator"]
            and "validate_whenMigrationCommandIsRegularNonExecutableFile_expectAccepted"
            in text["structureValidatorTest"]
            and "migration command is not executable" in text["migrationRunner"]
            and "run_whenMigrationCommandIsNotExecutable_expectFailsBeforeCompletion"
            in text["migrationRunnerTest"]
        ),
        "appHostCarriesSignedContract": (
            "dataSchemaContract" in text["appHostManifest"]
            and "manifest.dataSchemaContract()" in text["appHostManifestParser"]
        ),
        "internalSnapshotPrimitives": (
            "record AppDataUpdateSnapshot" in text["appDataSnapshot"]
            and "createUpdateSnapshot" in text["appDataService"]
            and "restoreUpdateSnapshot" in text["appDataService"]
            and "discardUpdateSnapshot" in text["appDataService"]
            and "app_data_snapshot_too_large" in text["appDataService"]
            and "createUpdateSnapshot_whenOtherAppHasData_expectSnapshotIsAppScoped"
            in text["appDataServiceTest"]
            and "restoreUpdateSnapshot_whenDataChangedAfterSnapshot_expectOriginalStateRestored"
            in text["appDataServiceTest"]
        ),
        "migrationRunnerIsShellFreeAndScoped": (
            "ProcessBuilder(commandLine(command))" in text["migrationRunner"]
            and "environment().clear()" in text["migrationRunner"]
            and "CRYPTA_APP_MIGRATION_MODE" in text["migrationRunner"]
            and "CRYPTA_APP_MIGRATION_NAMESPACE" in text["migrationRunner"]
            and "CRYPTA_APP_MIGRATION_INPUT" in text["migrationRunner"]
            and "CRYPTA_APP_MIGRATION_OUTPUT" in text["migrationRunner"]
            and "MigrationDataAccess" in text["migrationRunner"]
            and "importUpdateMigrationPayload" in text["appDataService"]
            and "MAX_CAPTURE_BYTES" in text["migrationRunner"]
            and 'List.of("/bin/sh"' not in text["migrationRunner"]
        ),
        "migrationRunnerFailsClosedWithoutContainment": (
            "ProcessBoundary" in text["migrationRunner"]
            and "new AppEnv()" in text["migrationRunner"]
            and "Process groups alone are not sufficient" in text["migrationRunner"]
            and "return unsupported();" in text["migrationRunner"]
            and "migration process containment is unavailable" in text["migrationRunner"]
            and "OUTPUT_DRAIN_TIMEOUT_MILLIS" in text["migrationRunner"]
            and "terminateProcessGroup" not in text["migrationRunner"]
            and "run_whenOnlyProcessGroupCleanupCouldBeBypassed_expectFailsClosedBeforeCommand"
            in text["migrationRunnerTest"]
            and "run_whenProcessBoundaryUnavailable_expectFailsClosedBeforeCommand"
            in text["migrationRunnerTest"]
        ),
        "updateSummariesExposeSafePlan": (
            '"dataMigration"' in text["updateCandidate"]
            and '"dataMigration"' in text["updateService"]
            and "AppDataMigrationPlan" in text["migrationPlan"]
            and "toJsonValue()" in text["migrationPlan"]
            and '"namespaces"' in text["migrationPlan"]
            and '"blockReason"' in text["migrationPlan"]
            and '"requiresStopped"' in text["migrationPlan"]
            and 'json.put("command"' not in text["migrationPlan"]
        ),
        "dryRunRunsBeforeStagingApply": (
            dry_run_index >= 0
            and staged_index > dry_run_index
            and apply_verify_index >= 0
            and apply_dry_run_index > apply_verify_index
            and "verifyStagedBundleBeforeStageDryRun" in text["updateService"]
            and "verifyStagedBundleAfterApplyDryRun" in text["updateService"]
            and "ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED" in text["updateService"]
            and "recordMigrationDryRunFailure" in text["updateService"]
            and "catalogManager.verifyInstallPlan" in text["updateService"]
            and "verifyInstallPlan" in text["catalogManager"]
            and "verifyInstallPlan_whenStagedBundleTampered_expectInvalidAppBundle"
            in text["catalogManagerTest"]
            and "stage_whenSchemaIncreaseHasNoMigrationStep_expectBlockedBeforeBundleReplacement"
            in text["updateServiceTest"]
            and "stage_whenStagedMigrationBundleVerificationFails_expectDryRunBlockedBeforeRunner"
            in text["updateServiceTest"]
            and "apply_whenStagedMigrationBundleVerificationFails_expectDryRunBlockedBeforeRunner"
            in text["updateServiceTest"]
            and "apply_whenMigrationDryRunMutatesStagedBundle_expectReverifiedBeforeInstall"
            in text["updateServiceTest"]
        ),
        "dryRunUsesTargetManifestQuota": (
            "targetManifest.dataQuotaBytes()" in text["updateService"]
            and "targetDataQuotaBytes" in text["appDataService"]
            and "ManifestQuotaCheck.targetManifest" in text["appDataService"]
            and "preflightUpdateMigrationDryRunPayloads" in text["appDataService"]
            and "advanceUpdateMigrationDryRunPayload_whenTargetManifestRaisesQuota_expectTargetQuotaUsed"
            in text["appDataServiceTest"]
            and "preflightUpdateMigrationDryRunPayloads_whenCombinedOutputExceedsRecordQuota_expectQuotaError"
            in text["appDataServiceTest"]
            and "stage_whenTargetManifestRaisesDataQuota_expectDryRunUsesTargetQuota"
            in text["updateServiceTest"]
        ),
        "chainedDryRunPreservesNamespaceTotals": (
            "withImportedRecordTotals" in text["appDataService"]
            and "recordCount" in text["appDataService"]
            and "totalBytes" in text["appDataService"]
            and "advanceUpdateMigrationDryRunPayload_whenChainedDryRun_expectNamespaceTotalsMatchRecords"
            in text["appDataServiceTest"]
            and "importedValueBytes" in text["appDataServiceTest"]
        ),
        "missingPathAndRollbackRiskBlock": (
            "STATUS_MISSING_MIGRATION" in text["migrationPlan"]
            and "ERROR_APP_DATA_MIGRATION_MISSING" in text["updateService"]
            and "ERROR_APP_DATA_MIGRATION_REVIEW_REQUIRED" in text["updateService"]
            and "ERROR_APP_DATA_MIGRATION_REQUIRES_STOPPED" in text["updateService"]
            and "ERROR_APP_DATA_MIGRATION_SANDBOX_UNAVAILABLE" in text["updateService"]
            and "targetManifest.sandboxPolicy().required()" in text["updateService"]
            and "isAutomaticPolicyMigrationSkip" in text["updateService"]
            and "bestMigrationPath" in text["updateService"]
            and "migrationAcknowledged" in text["updateHandler"]
            and "stage_whenMigrationRollbackIncompatibleWithoutAcknowledgement_expectReviewRequired"
            in text["updateServiceTest"]
            and "stage_whenStoppedRequiredMigrationAndAppRunning_expectBlockedBeforeDryRun"
            in text["updateServiceTest"]
            and "check_whenStagePolicyMigrationPathMissing_expectCandidateSummaryWithoutCheckFailure"
            in text["updateServiceTest"]
            and "check_whenStagePolicyMigrationDryRunFails_expectCandidateSummaryWithoutCheckFailure"
            in text["updateServiceTest"]
            and "check_whenStagePolicyMigrationDryRunThrows_expectCandidateSummaryWithoutCheckFailure"
            in text["updateServiceTest"]
            and "check_whenApplyWhenStoppedPolicyMigrationDryRunFails_expectCandidateSummaryWithoutApply"
            in text["updateServiceTest"]
            and "stage_whenMigrationBundleRequestsOptionalSandbox_expectDryRunAndStage"
            in text["updateServiceTest"]
            and "check_whenApplyWhenStoppedPolicySandboxMigration_expectCandidateSummaryWithoutApply"
            in text["updateServiceTest"]
            and "stage_whenMigrationHasDeadEndBranch_expectCompletePathSelected"
            in text["updateServiceTest"]
            and "stage_whenCompatibleChainCompetesWithIncompatibleDirectStep_expectCompatiblePathSelected"
            in text["updateServiceTest"]
        ),
        "snapshotBeforeReplacementAndRestoreOnFailure": (
            barrier_index >= 0
            and snapshot_index > barrier_index
            and replacement_index > snapshot_index
            and "closeUpdateMigrationWriteBarrier" in text["updateService"]
            and "shouldHoldApplyMigrationWriteBarrier" in text["updateService"]
            and "targetManifest.dataSchemaContract().declared()" in text["updateService"]
            and "runApplyMigrationOrRollback" in text["updateService"]
            and "rollbackAndRestoreSnapshot" in text["updateService"]
            and "markRollbackFailed" in text["updateService"]
            and "restoreUpdateSnapshot" in text["updateService"]
            and "Migration scratch cleanup is best effort" in text["updateService"]
            and "apply_whenMigrationRequiredAndRunnerPasses_expectSnapshotApplyAndSchemaMetadata"
            in text["updateServiceTest"]
            and "apply_whenChainedMigrationRunner_expectEachStepAppliedBeforeNextStep"
            in text["updateServiceTest"]
            and "apply_whenMigrationContractHasNoExistingDataAndWriteAppearsBeforeReplacement_expectWriteRejected"
            in text["updateServiceTest"]
            and "apply_whenMigrationApplyFailsAndBundleRollbackFails_expectMigrationFailurePreserved"
            in text["updateServiceTest"]
        ),
        "appDataWritesBlockedDuringMigrationApply": (
            "beginUpdateMigrationWriteBarrier" in text["appDataService"]
            and "app_data_migration_in_progress" in text["appDataService"]
            and "rejectIfUpdateMigrationWriteBarrierActive" in text["appDataService"]
            and "appFacingWrites_whenUpdateMigrationWriteBarrierActive_expectMigrationInProgressConflict"
            in text["appDataServiceTest"]
            and "updateMigrationImport_whenWriteBarrierActive_expectInternalMigrationWritesAllowed"
            in text["appDataServiceTest"]
            and "apply_whenAppDataWriteAttemptsDuringMigrationWindow_expectWriteRejectedAndBarrierReleased"
            in text["updateServiceTest"]
            and "apply_whenAppDataWriteAttemptsDuringFinalMigrationDryRun_expectWriteRejected"
            in text["updateServiceTest"]
        ),
        "webShellRendersMigrationStatus": (
            "App-data migration plan" in text["webShell"]
            and "migrationAcknowledged" in text["webShell"]
            and "migration-step-list" in text["webShell"]
            and "App-data migration blocker" in text["webShell"]
        ),
        "feedReaderDeclaresMigrationExample": (
            feed_manifest.get("app.data.schema.current") == "2"
            and feed_manifest.get("app.data.schema.namespace.ui-state.current") == "2"
            and feed_manifest.get("app.data.migration.ui-state-v1-v2.from") == "1"
            and feed_manifest.get("app.data.migration.ui-state-v1-v2.to") == "2"
            and feed_manifest.get("app.data.migration.ui-state-v1-v2.command")
            == "bin/migrate-feed-data.sh"
            and feed_manifest.get("app.data.migration.ui-state-v1-v2.rollbackCompatible")
            == "false"
            and "CRYPTA_APP_MIGRATION_MODE" in text["feedScript"]
            and "CRYPTA_APP_MIGRATION_INPUT" in text["feedScript"]
            and "CRYPTA_APP_MIGRATION_OUTPUT" in text["feedScript"]
            and "ui-state" in text["feedScript"]
            and "dry-run" in text["feedScript"]
            and "apply" in text["feedScript"]
        ),
        "trustGraphDeclaresMigrationExample": (
            trust_manifest.get("app.data.schema.current") == "2"
            and trust_manifest.get("app.data.schema.namespace.ui-state.current") == "2"
            and trust_manifest.get("app.data.migration.ui-state-v1-v2.from") == "1"
            and trust_manifest.get("app.data.migration.ui-state-v1-v2.to") == "2"
            and trust_manifest.get("app.data.migration.ui-state-v1-v2.command")
            == "bin/migrate-preview-data.sh"
            and trust_manifest.get("app.data.migration.ui-state-v1-v2.rollbackCompatible")
            == "false"
            and "CRYPTA_APP_MIGRATION_MODE" in text["trustScript"]
            and "CRYPTA_APP_MIGRATION_INPUT" in text["trustScript"]
            and "CRYPTA_APP_MIGRATION_OUTPUT" in text["trustScript"]
            and "ui-state" in text["trustScript"]
            and "dry-run" in text["trustScript"]
            and "apply" in text["trustScript"]
        ),
        "redactionAndDocsCoverScope": (
            "app-update.data-migration-contract" in docs_text
            and "rollback snapshot" in docs_text.lower()
            and "PR-250" in docs_text
            and "raw app-data values" in docs_text
            and "private insert URIs" in docs_text
            and "channel_policy_blocked" in text["updateService"]
            and "catalog.production-channels" in docs_text
        ),
    }
    details = {
        "checks": checks,
        "referenceApps": {
            "feed-reader": {
                "schema": feed_manifest.get("app.data.schema.current"),
                "migration": feed_manifest.get("app.data.migrations"),
            },
            "trust-graph": {
                "schema": trust_manifest.get("app.data.schema.current"),
                "migration": trust_manifest.get("app.data.migrations"),
            },
        },
        "redaction": {
            "rawAppDataValuesExcluded": True,
            "rawCommandLogsExcluded": True,
            "tokensExcluded": True,
            "privateInsertUrisExcluded": True,
            "stagingPathsExcluded": True,
        },
        "sources": {
            name: display_path(path, workspace) for name, path in source_files.items()
        },
    }
    errors = [key for key, passed in checks.items() if passed is not True]
    if errors:
        return EvidenceItem(
            "app-update.data-migration-contract",
            root_consequence(settings, "fail"),
            True,
            "App-data migration contract evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-update.data-migration-contract",
        "pass",
        True,
        "App-data migration contract evidence passed deterministic checks.",
        source,
        details,
    )


def read_first_manifest(workspace: Path, app_id: str, preferred: str) -> dict[str, str]:
    candidates = (
        workspace / preferred,
        workspace / f"apps/{app_id}/build/cryptad-app/{app_id}/cryptad-app.properties",
    )
    for path in candidates:
        if path.is_file():
            try:
                return parse_properties(path)
            except ValueError:
                return {}
    return {}


OPERATOR_BETA_EVIDENCE_IDS = (
    "operator-beta.dashboard",
    "operator-beta.catalog-health",
    "operator-beta.app-update-recovery",
    "operator-beta.subscription-recovery",
    "operator-beta.trust-review-warnings",
    "operator-beta.app-data-quota-warnings",
    "operator-beta.app-data-backup-restore",
    "operator-beta.support-bundle-redaction",
    "operator-beta.web-shell",
)


def operator_beta_evidence_item(
    settings: Settings,
    evidence_id: str,
    checks: dict[str, bool],
    pass_summary: str,
    details: dict[str, Any],
) -> EvidenceItem:
    errors = [key for key, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            evidence_id,
            root_consequence(settings, "fail"),
            True,
            f"{evidence_id} evidence is incomplete.",
            summary_source(settings),
            {"errors": errors, **details},
        )
    return EvidenceItem(evidence_id, "pass", True, pass_summary, summary_source(settings), details)


def collect_operator_beta_evidence(settings: Settings) -> list[EvidenceItem]:
    workspace = settings.workspace_root
    service_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/operator/OperatorBetaDashboardService.java"
    )
    routes_source = workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiOperatorRoutes.java"
    router_source = workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java"
    redactor_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/operator/OperatorSupportRedactor.java"
    )
    subscription_service_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionService.java"
    )
    operator_routes_test_source = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/PlatformApiOperatorRoutesTest.java"
    )
    redactor_test_source = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/operator/OperatorSupportRedactorTest.java"
    )
    toadlet_source = (
        workspace / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/PlatformApiToadlet.java"
    )
    toadlet_test_source = workspace / "src/test/java/network/crypta/clients/http/PlatformApiToadletTest.java"
    web_shell_source = (
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    web_shell_index_source = (
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/index.html"
    )
    web_shell_test_source = (
        workspace
        / "platform-web-shell/src/test/java/network/crypta/platform/webshell/WebShellResourcesTest.java"
    )
    docs_source = workspace / "docs/operator-beta-dashboard.md"
    beta_program_doc = workspace / "docs/app-platform-beta-program.md"
    limitations_doc = workspace / "docs/app-platform-beta-known-limitations.md"
    api_surface_doc = workspace / "docs/platform-api-surface.md"

    service_text = read_source(service_source)
    routes_text = read_source(routes_source)
    router_text = read_source(router_source)
    redactor_text = read_source(redactor_source)
    subscription_service_text = read_source(subscription_service_source)
    operator_routes_test_text = read_source(operator_routes_test_source)
    redactor_test_text = read_source(redactor_test_source)
    toadlet_text = read_source(toadlet_source)
    toadlet_test_text = read_source(toadlet_test_source)
    web_shell_text = read_source(web_shell_source)
    web_shell_index_text = read_source(web_shell_index_source)
    web_shell_test_text = read_source(web_shell_test_source)
    docs_text = read_source(docs_source)
    beta_program_text = read_source(beta_program_doc)
    limitations_text = read_source(limitations_doc)
    api_surface_text = read_source(api_surface_doc)
    form_password_redaction_test = (
        "FORM_FIELD_ASSIGNMENT" in operator_routes_test_text
        and '"form" + "Pass" + "word=secret-value"' in operator_routes_test_text
        and "contains(FORM_FIELD_ASSIGNMENT)" in operator_routes_test_text
    )
    shared_details = {
        "liveNodeRequired": False,
        "hostOperatorOnly": True,
        "operatorRoutesExcludedFromAppContract": True,
        "sources": {
            "service": display_path(service_source, workspace),
            "routes": display_path(routes_source, workspace),
            "router": display_path(router_source, workspace),
            "redactor": display_path(redactor_source, workspace),
            "subscriptionService": display_path(subscription_service_source, workspace),
            "operatorRoutesTest": display_path(operator_routes_test_source, workspace),
            "redactorTest": display_path(redactor_test_source, workspace),
            "toadlet": display_path(toadlet_source, workspace),
            "toadletTest": display_path(toadlet_test_source, workspace),
            "webShell": display_path(web_shell_source, workspace),
            "webShellIndex": display_path(web_shell_index_source, workspace),
            "webShellTest": display_path(web_shell_test_source, workspace),
            "docs": display_path(docs_source, workspace),
        },
    }

    evidence_specs = [
        (
            "operator-beta.dashboard",
            {
                "dashboardRoute": (
                    '"beta-dashboard".equals(resource)' in routes_text
                    and "dashboardService.dashboard()" in routes_text
                    and 'case "operator" -> operatorRoutes.route(segments, request);' in router_text
                ),
                "hostOperatorOnly": (
                    "requireHostOperator(request)" in routes_text
                    and "host_operator_required" in routes_text
                    and "route_whenAppPrincipalRequestsOperatorDashboard_expectForbiddenBeforeDispatch"
                    in operator_routes_test_text
                ),
                "dashboardSections": all(
                    fragment in service_text
                    for fragment in (
                        '"overallStatus"',
                        '"summary"',
                        '"catalogs"',
                        '"apps"',
                        '"subscriptions"',
                        '"trustGraph"',
                        '"appServices"',
                        '"legacyAdmin"',
                        '"diagnostics"',
                        '"recoveryActions"',
                    )
                ),
                "docs": "operator-beta.dashboard" in docs_text and "host/operator-only" in docs_text,
            },
            "Operator beta dashboard route, auth, and section evidence passed.",
        ),
        (
            "operator-beta.catalog-health",
            {
                "catalogSummary": (
                    "catalogSummary(Map<String, Object> catalog)" in service_text
                    and '"trustedCatalogKeyStatus"' in service_text
                    and '"lastFetchStatus"' in service_text
                    and '"recommendedFirstPartyPresent"' in service_text
                    and "safeSourceDisplay(source, sourceKind)" in service_text
                ),
                "catalogRecoveryAction": (
                    '"refresh-catalog"' in service_text
                    and '"app-catalogs/" + encodePathSegment(catalogId) + "/refresh"' in service_text
                ),
                "catalogUi": "function renderBetaCatalogs(catalogs)" in web_shell_text,
                "docs": "operator-beta.catalog-health" in docs_text,
            },
            "Operator beta catalog health evidence passed.",
        ),
        (
            "operator-beta.app-update-recovery",
            {
                "appRecoveryActions": all(
                    fragment in service_text
                    for fragment in (
                        '"check-app-update"',
                        '"stage-app-update"',
                        '"apply-app-update"',
                        '"rollback-app"',
                        '"open-app-logs"',
                    )
                ),
                "noPreserveUninstallInUi": (
                    "operatorRecoveryActionVisible(action)" in web_shell_text
                    and 'actionId !== "preserve-data-uninstall"' in web_shell_text
                ),
                "appRecoveryUi": "function renderBetaApps(apps)" in web_shell_text,
                "docs": "operator-beta.app-update-recovery" in docs_text,
            },
            "Operator beta app-update recovery evidence passed.",
        ),
        (
            "operator-beta.subscription-recovery",
            {
                "operatorList": "listAllForOperator()" in subscription_service_text,
                "subscriptionRoutes": all(
                    fragment in routes_text for fragment in ('case "refresh"', 'case "pause"', 'case "resume"')
                ),
                "subscriptionActions": all(
                    fragment in service_text
                    for fragment in (
                        '"refresh-subscription"',
                        '"pause-subscription"',
                        '"resume-subscription"',
                        '"operator/subscriptions/"',
                    )
                ),
                "formPasswordGuard": (
                    "requiresOperatorFormPassword" in toadlet_text
                    and "/operator/subscriptions/feed-reader/sub-123/refresh" in toadlet_test_text
                ),
                "appPrincipalDenied": (
                    "route_whenAppPrincipalUsesOperatorSubscriptionWrapper_expectForbidden"
                    in operator_routes_test_text
                ),
                "docs": "operator-beta.subscription-recovery" in docs_text,
            },
            "Operator beta subscription recovery evidence passed.",
        ),
        (
            "operator-beta.trust-review-warnings",
            {
                "trustPreviewWarning": (
                    "Trust Graph Local RC is local operator-curated state only"
                    in service_text
                    and '"previewOnly"' in service_text
                    and '"completeWot"' in service_text
                    and '"scope"' in service_text
                    and '"statementLifecycle"' in service_text
                ),
                "appReviewSurface": (
                    '"reviewTrust"' in service_text
                    and "renderBetaTrustAndServices(trustGraph, appServices)" in web_shell_text
                    and "Trust Graph Local RC" in web_shell_text
                ),
                "docs": (
                    "operator-beta.trust-review-warnings" in docs_text
                    and "not global truth" in docs_text
                ),
            },
            "Operator beta trust and review-warning evidence passed.",
        ),
        (
            "operator-beta.app-data-quota-warnings",
            {
                "appDataSummary": "appDataSummary(appId)" in service_text and '"appData"' in service_text,
                "quotaWarnings": (
                    "app_data_quota_unavailable" in service_text
                    and "apphost_quota_over_limit" in service_text
                    and '"quotaWarningCount"' in service_text
                ),
                "quotaUi": (
                    '"Quota warnings"' in web_shell_text
                    and '"Data quota"' in web_shell_text
                    and "quota.dataOverLimit || quota.cacheOverLimit" in web_shell_text
                ),
                "docs": "operator-beta.app-data-quota-warnings" in docs_text,
            },
            "Operator beta app-data and quota-warning evidence passed.",
        ),
        (
            "operator-beta.app-data-backup-restore",
            {
                "backupRestoreRoutes": (
                    "routeAppDataBackup" in routes_text
                    and "methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE)" in routes_text
                    and "routeAppDataRestoreCommit" in routes_text
                    and "routeAppDataRestore(" in routes_text
                    and "app_data_service_unavailable" in routes_text
                    and "requireHostOperator(request)" in routes_text
                ),
                "formPasswordGuard": (
                    "requiresOperatorFormPassword" in toadlet_text
                    and "/operator/app-data/backups" in toadlet_test_text
                    and "/operator/app-data/restore/plan" in toadlet_test_text
                    and "/operator/app-data/restore" in toadlet_test_text
                ),
                "appPrincipalDenied": (
                    "route_whenAppPrincipalRequestsAppDataBackupRestore_expectForbidden"
                    in operator_routes_test_text
                ),
                "webShellControls": (
                    "downloadAllAppDataBackup()" in web_shell_text
                    and "submitAppDataRestoreForm(" in web_shell_text
                    and "setBetaDashboardStatus" in web_shell_text
                    and "Export backup before delete" in web_shell_text
                    and 'id="all-app-data-backup-button"' in web_shell_index_text
                    and 'id="operator-app-data-restore-form"' in web_shell_index_text
                ),
                "resourceTests": (
                    "assertAppDataBackupRestoreMarkersPresent(script)" in web_shell_test_text
                ),
                "docs": (
                    "operator-beta.app-data-backup-restore" in docs_text
                    and "app-data.backup-restore-portability" in docs_text
                ),
            },
            "Operator beta app-data backup/restore evidence passed.",
        ),
        (
            "operator-beta.support-bundle-redaction",
            {
                "supportBundleRoute": (
                    '"support-bundle".equals(resource)' in routes_text
                    and "dashboardService.supportBundle()" in routes_text
                ),
                "redactorApplied": (
                    "OperatorSupportRedactor.redact(dashboard)" in service_text
                    and "OperatorSupportRedactor.redact(diagnostics)" in service_text
                    and "OperatorSupportRedactor.redact(recentAudit)" in service_text
                ),
                "sensitiveFieldsOmitted": all(
                    fragment in redactor_text
                    for fragment in (
                        '"formpassword"',
                        '"browsersession"',
                        '"requestbody"',
                        '"rawbody"',
                        '"sourcepath"',
                        '"rollbackpath"',
                    )
                ),
                "redactionTests": (
                    "route_whenSupportBundleIncludesSensitiveDiagnostics_expectRedactedOutput"
                    in operator_routes_test_text
                    and "/work/private/catalog" in operator_routes_test_text
                    and form_password_redaction_test
                    and "redact_whenNestedSecretsPathsAndContentUrisPresent_expectUnsafeValuesRemoved"
                    in redactor_test_text
                    and "/work/cryptad/private.txt" in redactor_test_text
                    and "query-secret" in redactor_test_text
                ),
                "docs": (
                    "operator-beta.support-bundle-redaction" in docs_text
                    and "reviewed by the operator before sharing" in docs_text
                    and "raw request bodies" in limitations_text
                ),
            },
            "Operator beta support-bundle redaction evidence passed.",
        ),
        (
            "operator-beta.web-shell",
            {
                "panelMarkup": (
                    'id="beta-dashboard"' in web_shell_index_text
                    and 'id="beta-dashboard-body"' in web_shell_index_text
                    and 'id="support-bundle-download-button"' in web_shell_index_text
                ),
                "loadsOperatorEndpoints": (
                    'loadJson(apiUrl("operator/beta-dashboard"))' in web_shell_text
                    and 'loadJson(apiUrl("operator/support-bundle"))' in web_shell_text
                ),
                "supportControls": all(
                    fragment in web_shell_text
                    for fragment in (
                        "downloadSupportBundle()",
                        "copySupportSummary()",
                        "supportBundleSnapshot",
                    )
                ),
                "recoverySubmitHandler": (
                    "submitOperatorRecoveryAction(form)" in web_shell_text
                    and 'sections.betaDashboard.addEventListener("submit"' in web_shell_text
                ),
                "resourceTests": (
                    "assertBetaDashboardMarkersPresent(script)" in web_shell_test_text
                    and "assertBetaDashboardLoadSequencing(script)" in web_shell_test_text
                ),
                "docs": (
                    "operator-beta.web-shell" in docs_text
                    and "Operator beta dashboard" in beta_program_text
                    and "Operator" in api_surface_text
                ),
            },
            "Operator beta Web Shell evidence passed.",
        ),
    ]

    return [
        operator_beta_evidence_item(
            settings,
            evidence_id,
            checks,
            pass_summary,
            {**shared_details, "checks": checks},
        )
        for evidence_id, checks, pass_summary in evidence_specs
    ]


def build_http_request(
    method: str, url: str, form_password: str = "", data: dict[str, str] | None = None
) -> urllib.request.Request:
    payload: bytes | None = None
    headers = {"Accept": "application/json"}
    params = data or {}
    if method in {"POST", "DELETE"} and form_password:
        params = {**params, "formPassword": form_password}
    if method in {"POST", "DELETE"} and params:
        payload = urllib.parse.urlencode(params).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif params:
        url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    return urllib.request.Request(url, data=payload, method=method, headers=headers)


def http_request_json(
    method: str, url: str, form_password: str = "", data: dict[str, str] | None = None
) -> tuple[int, Any]:
    request = build_http_request(method, url, form_password, data)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            value = json.loads(body) if body else {}
        except json.JSONDecodeError:
            value = {"error": {"message": body[:200]}}
        return exc.code, value


def diagnostics_body_summary(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        return {"diagnosticsBodyType": type(body).__name__}
    summary: dict[str, Any] = {}
    section_count = body.get("sectionCount")
    if isinstance(section_count, int):
        summary["sectionCount"] = section_count
    sections = body.get("sections")
    if isinstance(sections, list):
        summary["sectionCount"] = len(sections)
    legacy_admin = body.get("legacyAdmin")
    if isinstance(legacy_admin, dict):
        surfaces = legacy_admin.get("surfaces")
        if isinstance(surfaces, list):
            summary["legacyAdminSurfaceCount"] = len(surfaces)
            counts = [
                surface.get("count")
                for surface in surfaces
                if isinstance(surface, dict) and isinstance(surface.get("count"), int)
            ]
            summary["legacyAdminTotalCount"] = sum(counts)
            for output_key, field_name in (
                ("legacyAdminReplacementResponseTotal", "replacementResponseCount"),
                ("legacyAdminBlockedMutatingRequestTotal", "blockedMutatingRequestCount"),
                ("legacyAdminFallbackRenderTotal", "fallbackRenderCount"),
                ("legacyAdminRetainedOrPendingRenderTotal", "retainedOrPendingRenderCount"),
            ):
                summary[output_key] = sum(
                    surface.get(field_name)
                    for surface in surfaces
                    if isinstance(surface, dict) and isinstance(surface.get(field_name), int)
                )
    if not summary:
        summary["diagnosticsBodyReceived"] = True
    return summary


def live_response_details(path: str, body: Any, workspace_root: Path) -> dict[str, Any]:
    if path == "/diagnostics":
        return {"bodySummary": diagnostics_body_summary(body)}
    return {"body": sanitize_value(body, workspace_root)}


def collect_live_cleanup_steps(root: str, settings: Settings) -> list[dict[str, Any]]:
    cleanup_steps: list[dict[str, Any]] = []
    for method, path in (("POST", "/apps/cert-smoke/stop"), ("DELETE", "/apps/cert-smoke")):
        cleanup_step: dict[str, Any] = {"method": method, "path": path}
        try:
            status, body = http_request_json(method, root + path, settings.live_form_password, {})
            cleanup_step["status"] = status
            cleanup_step.update(live_response_details(path, body, settings.workspace_root))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            cleanup_step["error"] = scrub_text(str(exc), settings.workspace_root)
        cleanup_steps.append(cleanup_step)
    return cleanup_steps


def failed_live_evidence(
    source: str,
    details: dict[str, Any],
    root: str,
    settings: Settings,
    installed: bool,
    summary: str = "Live AppHost lifecycle smoke failed.",
) -> EvidenceItem:
    if installed:
        details["cleanupSteps"] = collect_live_cleanup_steps(root, settings)
    return EvidenceItem("apphost.live", "fail", False, summary, source, details)


def collect_live_evidence(settings: Settings, sample_paths: dict[str, Path]) -> EvidenceItem:
    source = summary_source(settings)
    if not settings.live:
        return EvidenceItem("apphost.live", "skip", False, "Live AppHost lifecycle smoke was not requested.", source, {"enabled": False})
    details: dict[str, Any] = {"enabled": True, **live_base_url_details(settings.live_base_url)}
    if not settings.live_base_url:
        return EvidenceItem("apphost.live", "fail", False, "Live AppHost smoke was requested without CRYPTAD_CERT_NODE_BASE_URL.", source, details)
    host = urllib.parse.urlparse(settings.live_base_url).hostname or ""
    if not is_local_live_host(host):
        return EvidenceItem("apphost.live", "fail", False, "Live AppHost smoke only records localhost node evidence.", source, details)
    if not settings.live_form_password:
        return EvidenceItem("apphost.live", "fail", False, "Live AppHost smoke was requested without CRYPTAD_CERT_FORM_PASSWORD.", source, details)
    staged_dir = sample_paths.get("bundleDir")
    if not staged_dir or not staged_dir.is_dir():
        return EvidenceItem("apphost.live", "fail", False, "Live AppHost smoke needs the generated sample staged bundle.", source, details)
    root = settings.live_base_url.rstrip("/") + "/api/v1"
    steps: list[dict[str, Any]] = []
    installed = False
    try:
        for method, path, data in (
            ("GET", "/apps", {}),
            ("DELETE", "/apps/cert-smoke", {}),
            ("POST", "/apps/install", {"stagedDir": str(staged_dir.resolve())}),
            ("GET", "/apps/cert-smoke/runtime", {}),
            ("POST", "/apps/cert-smoke/start", {}),
            ("GET", "/apps/cert-smoke/runtime", {}),
            ("POST", "/apps/cert-smoke/stop", {}),
            ("POST", "/apps/cert-smoke/update", {"stagedDir": str(staged_dir.resolve())}),
            ("DELETE", "/apps/cert-smoke", {}),
            ("GET", "/diagnostics", {}),
        ):
            status, body = http_request_json(method, root + path, settings.live_form_password, data)
            step = {"method": method, "path": path, "status": status}
            step.update(live_response_details(path, body, settings.workspace_root))
            steps.append(step)
            if status >= 400 and not (method == "DELETE" and path == "/apps/cert-smoke" and status == 404):
                details["steps"] = steps
                return failed_live_evidence(source, details, root, settings, installed)
            if method == "POST" and path == "/apps/install":
                installed = True
            elif method == "DELETE" and path == "/apps/cert-smoke" and status < 500:
                installed = False
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        details["steps"] = steps
        details["error"] = scrub_text(str(exc), settings.workspace_root)
        return failed_live_evidence(source, details, root, settings, installed)
    details["steps"] = steps
    return EvidenceItem("apphost.live", "pass", False, "Live AppHost install/start/status/stop/update/uninstall smoke passed.", source, details)


def overall_status(mode: str, evidence: list[EvidenceItem]) -> str:
    if any(item.required_for_release_candidate and item.status == "fail" for item in evidence):
        return "fail"
    if mode == "release-candidate" and any(
        item.required_for_release_candidate and item.status in {"missing", "skip"} for item in evidence
    ):
        return "fail"
    if any(
        item.status in {"warn", "missing", "fail"} or (item.required_for_release_candidate and item.status == "skip")
        for item in evidence
    ):
        return "warn"
    return "pass"


def render_report(summary: dict[str, Any]) -> str:
    lines = [
        "# App Platform Smoke Report",
        "",
        f"- Mode: `{summary['mode']}`",
        f"- Status: `{summary['status']}`",
        f"- Generated: `{summary['generatedAt']}`",
        "",
        "| Evidence | Status | Required for RC | Summary |",
        "| --- | --- | --- | --- |",
    ]
    for item in summary["evidence"]:
        summary_text = str(item["summary"]).replace("|", "\\|")
        lines.append(
            f"| `{item['id']}` | `{item['status']}` | "
            f"{'yes' if item['requiredForReleaseCandidate'] else 'no'} | "
            f"{summary_text} |"
        )
    lines.append("")
    return "\n".join(lines)


def build_summary(settings: Settings, evidence: list[EvidenceItem]) -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "mode": settings.mode,
        "status": overall_status(settings.mode, evidence),
        "generatedAt": utc_now(),
        "summaryPath": display_path(settings.out_dir / SUMMARY_FILE_NAME, settings.workspace_root, settings.out_dir),
        "reportPath": display_path(settings.out_dir / REPORT_FILE_NAME, settings.workspace_root, settings.out_dir),
        "evidence": [item.to_json() for item in evidence],
        "redaction": {
            "secretMaterialRedacted": True,
            "formPasswordsRedacted": True,
            "rawFeedBodiesExcluded": True,
            "rawRequestBodiesExcluded": True,
            "privateInsertUrisExcluded": True,
            "appProcessTokensRedacted": True,
            "browserSessionTokensRedacted": True,
            "signatureValuesRedacted": True,
            "reviewerKeyMaterialRedacted": True,
            "reviewTransparencyPathsExcluded": True,
            "rawUpdateRollbackOutputsExcluded": True,
            "rawAppDataBackupsExcluded": True,
            "absolutePathsSanitized": True,
        },
    }


def run(settings: Settings) -> tuple[dict[str, Any], int]:
    settings.out_dir.mkdir(parents=True, exist_ok=True)
    remove_existing_path(settings.out_dir / "artifacts")
    cli = find_cli(settings)
    cli_item, sample_paths = collect_cli_evidence(settings, cli)
    cli = sample_paths.get("cli") if sample_paths.get("cli") else find_cli(settings)
    evidence = [
        collect_first_party_evidence(settings, cli if isinstance(cli, Path) else None),
        cli_item,
        collect_developer_beta_toolkit_evidence(settings),
        collect_platform_api_contract_evidence(settings, cli if isinstance(cli, Path) else None, sample_paths),
        *collect_app_services_evidence(settings),
        collect_app_vault_evidence(settings),
        collect_identity_profile_publish_evidence(settings),
        collect_generated_document_insert_evidence(settings),
        collect_content_fetch_evidence(settings),
        collect_content_subscription_evidence(settings),
        collect_content_subscription_scheduler_evidence(settings),
        collect_app_data_store_evidence(settings),
        collect_app_data_backup_restore_evidence(settings),
        collect_trust_graph_preview_evidence(settings),
        collect_trust_graph_rc_scope_and_safety_evidence(settings),
        collect_trust_graph_durable_store_evidence(settings),
        collect_trust_graph_exchange_evidence(settings),
        collect_trust_statement_signing_evidence(settings),
        collect_social_message_signing_evidence(settings),
        collect_signed_bundle_evidence(settings, sample_paths),
        collect_catalog_evidence(settings, sample_paths),
        collect_live_usk_catalog_publication_evidence(settings, sample_paths),
        collect_first_party_beta_catalog_evidence(settings),
        collect_production_catalog_channels_evidence(settings),
        collect_live_usk_source_verification_evidence(settings),
        collect_app_review_receipt_evidence(settings),
        collect_app_review_policy_evidence(settings),
        collect_app_review_governance_evidence(settings),
        collect_app_review_reviewer_key_lifecycle_evidence(settings),
        collect_app_review_transparency_log_evidence(settings),
        collect_app_review_history_api_evidence(settings),
        collect_app_review_first_party_catalog_evidence(settings, sample_paths),
        collect_app_review_first_party_chain_evidence(settings),
        collect_app_ui_design_system_evidence(settings),
        collect_app_ui_lint_evidence(settings, cli if isinstance(cli, Path) else None),
        collect_app_ui_first_party_adoption_evidence(settings),
        collect_app_ui_evidence(settings),
        collect_reference_content_app_evidence(settings),
        collect_profile_publisher_reference_app_evidence(settings),
        collect_profile_publisher_app_data_evidence(settings),
        collect_social_inbox_reference_app_evidence(settings),
        collect_social_inbox_signed_message_evidence(settings),
        collect_social_inbox_subscriptions_evidence(settings),
        collect_social_inbox_app_data_evidence(settings),
        collect_social_inbox_trust_annotation_evidence(settings),
        collect_social_inbox_rc_threading_evidence(settings),
        collect_social_mail_migration_preview_evidence(settings),
        collect_legacy_plugin_migration_evidence(settings),
        collect_legacy_plugin_social_inbox_spike_evidence(settings),
        collect_feed_reader_reference_app_evidence(settings),
        collect_feed_reader_subscription_evidence(settings),
        collect_feed_reader_app_data_evidence(settings),
        collect_trust_graph_reference_app_evidence(settings),
        collect_trust_graph_durable_exchange_reference_app_evidence(settings),
        collect_trust_graph_app_data_preview_evidence(settings),
        collect_legacy_evidence(settings),
        collect_legacy_removal_wave_one_evidence(settings),
        collect_legacy_removal_wave_two_evidence(settings),
        collect_legacy_removal_wave_three_evidence(settings),
        collect_sandbox_provider_evidence(settings),
        *collect_public_beta_security_evidence(settings),
        collect_app_update_lifecycle_evidence(settings),
        collect_app_update_scheduler_evidence(settings),
        collect_app_update_live_catalog_refresh_evidence(settings),
        collect_app_update_rollback_evidence(settings),
        collect_app_update_data_migration_contract_evidence(settings),
        *collect_operator_beta_evidence(settings),
        collect_live_evidence(settings, sample_paths),
    ]
    sanitized_evidence = [
        EvidenceItem(
            item.id,
            item.status,
            item.required_for_release_candidate,
            scrub_text(item.summary, settings.workspace_root),
            item.source,
            dict(sanitize_value(item.details, settings.workspace_root)),
        )
        for item in evidence
    ]
    summary = build_summary(settings, sanitized_evidence)
    write_json(settings.out_dir / SUMMARY_FILE_NAME, summary)
    write_text(settings.out_dir / REPORT_FILE_NAME, render_report(summary))
    exit_code = 1 if settings.mode == "release-candidate" and summary["status"] == "fail" else 0
    return summary, exit_code


def settings_from_args(args: argparse.Namespace) -> Settings:
    workspace = args.workspace_root.resolve()
    out_dir = (workspace / args.out_dir).resolve() if not args.out_dir.is_absolute() else args.out_dir.resolve()
    mode = args.mode or os.environ.get("CRYPTAD_CERT_MODE", "pr")
    if mode not in MODES:
        raise SystemExit(f"--mode must be one of {', '.join(MODES)}")
    live = args.live or os.environ.get("CRYPTAD_CERT_APP_SMOKE_LIVE") == "1"
    cli_path = args.cli_path.resolve() if args.cli_path else None
    return Settings(
        workspace_root=workspace,
        out_dir=out_dir,
        mode=mode,
        skip_gradle=args.skip_gradle,
        cli_path=cli_path,
        live=live,
        live_base_url=args.node_base_url or os.environ.get("CRYPTAD_CERT_NODE_BASE_URL", ""),
        live_form_password=os.environ.get("CRYPTAD_CERT_FORM_PASSWORD", ""),
        timeout_seconds=args.timeout_seconds,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run Python-only self-tests.")
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--mode", choices=MODES, default=None)
    parser.add_argument("--skip-gradle", action="store_true", help="Do not invoke Gradle tasks.")
    parser.add_argument("--cli-path", type=Path, help="Path to an installed crypta-app launcher.")
    parser.add_argument("--live", action="store_true", help="Run optional live-node AppHost lifecycle smoke.")
    parser.add_argument("--node-base-url", default="", help="Live-node base URL for optional AppHost smoke.")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    return parser


def run_self_test(repo_root: Path) -> None:
    fixture_dir = repo_root / "tools/release-certification/fixtures"
    catalog_fixture = fixture_dir / "self-test-catalog.properties"
    registry_fixture = fixture_dir / "self-test-legacy-registry.java-fragment"
    catalog = parse_properties(catalog_fixture)
    assert catalog["catalog.id"] == "cert-smoke"
    assert "feed-reader" in parse_permission_set(catalog["catalog.entries"])
    assert "social-inbox" in parse_permission_set(catalog["catalog.entries"])
    assert "trust-graph" in parse_permission_set(catalog["catalog.entries"])
    assert catalog["app.cert-smoke.bundle.sha256"] == "0" * 64
    assert catalog["app.feed-reader.permissions"] == (
        "content.fetch,content.subscribe,content.insert.app-document,queue.read,queue.write,"
        "app.data.read,app.data.write"
    )
    assert catalog["app.feed-reader.api.minimumVersion"] == "9"
    assert catalog["app.feed-reader.api.maximumTestedVersion"] == str(
        CURRENT_PLATFORM_API_CONTRACT_VERSION
    )
    assert catalog["app.social-inbox.permissions"] == (
        "vault.identities.read,vault.identities.create,vault.identities.use,content.fetch,"
        "content.subscribe,content.insert.app-document,queue.read,queue.write,app.data.read,"
        "app.data.write,app.services.read,app.services.call"
    )
    assert catalog["app.social-inbox.api.minimumVersion"] == "16"
    assert catalog["app.social-inbox.api.maximumTestedVersion"] == str(
        CURRENT_PLATFORM_API_CONTRACT_VERSION
    )
    assert catalog["app.trust-graph.permissions"] == (
        "trust.read,trust.write,content.fetch,content.subscribe,content.insert.app-document,"
        "queue.read,queue.write,vault.identities.read,vault.identities.create,vault.identities.use,"
        "app.data.read,app.data.write"
    )
    assert catalog["app.trust-graph.api.minimumVersion"] == "10"
    assert catalog["app.trust-graph.api.maximumTestedVersion"] == str(
        CURRENT_PLATFORM_API_CONTRACT_VERSION
    )
    registry_text = registry_fixture.read_text(encoding="utf-8")
    counts = legacy_counts_from_registry_text(registry_text)
    assert counts == {
        "PRIMARY_REPLACED": 13,
        "PENDING": 2,
        "RETAINED": 1,
        "INFRASTRUCTURE": 1,
    }, counts
    assert legacy_removal_wave_three_ids(registry_text) == ["security-levels"]
    extra_wave_three_text = registry_text.replace(
        "securityLevelsWave3Redirect()",
        'securityLevelsWave3Redirect(),\n'
        '          wave3Redirect("diagnostic", "Diagnostic", "/diagnostic/", '
        '"/app/node/#diagnostics", "Shell diagnostics", "Wrong.", false)',
    )
    assert legacy_removal_wave_three_ids(extra_wave_three_text) != list(
        LEGACY_REMOVAL_WAVE_THREE_IDS
    )
    fallback_checks = legacy_fallback_link_checks(registry_text)
    assert fallback_checks["primaryReplacedExcludedFromFallbackLinks"] is True, fallback_checks
    assert fallback_checks["primaryReplacedAbsentFromPrimaryNavigation"] is True, fallback_checks
    unsafe_registry_text = registry_text.replace("true,\n        false);", "true,\n        true);", 1)
    unsafe_fallback_checks = legacy_fallback_link_checks(unsafe_registry_text)
    assert unsafe_fallback_checks["primaryReplacedExcludedFromFallbackLinks"] is False, unsafe_fallback_checks
    assert legacy_scope_expansion_wave_two_ids("") == []
    assert legacy_scope_expansion_wave_two_ids("final class LegacyAdminRetirementRegistry {}") == []
    assert social_inbox_docs_frame_spike_non_goals(
        "This is a migration spike, not a production social network, mail protocol, "
        "full WoT implementation, Freetalk/Sone/Freemail compatibility layer, "
        "encrypted mail transport, and daemon-core message store."
    )
    assert social_inbox_docs_frame_spike_non_goals(
        "This is a migration spike, not a full Web of Trust, not Freetalk, not Sone, "
        "not Freemail, not encrypted mail, and not a daemon message store."
    )
    assert not social_inbox_docs_frame_spike_non_goals(
        "This is a migration spike with Freetalk, Sone, Freemail, encrypted mail, "
        "and daemon-core message store non-goals but no WoT limitation."
    )
    parser_options = {
        option
        for action in build_parser()._actions
        for option in action.option_strings
    }
    assert "--form-password" not in parser_options, parser_options
    previous_form_password = os.environ.get("CRYPTAD_CERT_FORM_PASSWORD")
    os.environ["CRYPTAD_CERT_FORM_PASSWORD"] = "env-only-form-password"
    try:
        env_settings = settings_from_args(
            build_parser().parse_args(
                [
                    "--workspace-root",
                    str(repo_root),
                    "--out-dir",
                    "build/release-certification/app-platform-smoke",
                    "--live",
                ]
            )
        )
    finally:
        if previous_form_password is None:
            os.environ.pop("CRYPTAD_CERT_FORM_PASSWORD", None)
        else:
            os.environ["CRYPTAD_CERT_FORM_PASSWORD"] = previous_form_password
    assert env_settings.live_form_password == "env-only-form-password", env_settings
    redacted_secret_command = redact_command(
        [
            "crypta-app",
            "sign",
            "--private-key-file",
            "/mnt/secrets/prod-key.pem",
            "--private-key-base64",
            "base64-secret",
        ],
        env_settings,
    )
    assert redacted_secret_command == [
        "crypta-app",
        "sign",
        "--private-key-file",
        "<redacted>",
        "--private-key-base64",
        "<redacted>",
    ], redacted_secret_command
    assert "prod-key.pem" not in json.dumps(redacted_secret_command), redacted_secret_command
    assert normalize_static_script_ref("./app.js?cache=1#main") == "app.js"
    with tempfile.TemporaryDirectory(prefix="cryptad-app-script-order-self-test-") as static_name:
        static_dir = Path(static_name)
        (static_dir / "index.html").write_text(
            '<script src="app.js"></script><script src="crypta-platform.js"></script>\n',
            encoding="utf-8",
        )
        (static_dir / "app.js").write_text(
            'CryptaPlatform.bootstrap.load({ appId: "cert-smoke" });\n',
            encoding="utf-8",
        )
        canonical_sdk = repo_root / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
        if canonical_sdk.is_file():
            shutil.copy2(canonical_sdk, static_dir / "crypta-platform.js")
        else:
            (static_dir / "crypta-platform.js").write_text(
                'window.CryptaPlatform={}; X="X-Crypta-App-Session";\n',
                encoding="utf-8",
            )
        script_errors, _ = validate_static_ui_files(static_dir, env_settings)
    assert "index.html must load crypta-platform.js before app.js" in script_errors, script_errors
    with tempfile.TemporaryDirectory(prefix="cryptad-app-adoption-self-test-") as adoption_name:
        adoption_static_dir = Path(adoption_name)
        adoption_static_dir.joinpath("index.html").write_text(
            '<!doctype html><html lang="en"><head>'
            '<link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css">'
            '<link rel="stylesheet" href="./crypta-ui/crypta-ui.css">'
            '<link rel="stylesheet" href="./app.css">'
            '</head><body class="cr-app"><main class="cr-shell">'
            '<section class="cr-permission-summary" data-crypta-permission-summary>'
            "<code>queue.read</code>"
            "</section></main></body></html>\n",
            encoding="utf-8",
        )
        adoption_errors, adoption_details = source_ui_adoption_details(
            adoption_static_dir,
            {"queue.read", "queue.write"},
            env_settings,
        )
    assert (
        "permission disclosure omits declared permissions: queue.write" in adoption_errors
    ), adoption_errors
    assert adoption_details["omittedPermissions"] == ["queue.write"], adoption_details
    scrubbed = scrub_text("key file /mnt/secrets/signing/key.pem token=hunter2 USK@private/insert", repo_root)
    assert "/mnt/secrets/signing/key.pem" not in scrubbed
    assert "hunter2" not in scrubbed
    assert "USK@private" not in scrubbed
    signature_scrubbed = scrub_text(
        "signature.value.base64=raw-signature signature.algorithm=Ed25519",
        repo_root,
    )
    assert "raw-signature" not in signature_scrubbed, signature_scrubbed
    assert "Ed25519" in signature_scrubbed, signature_scrubbed
    body_label_scrubbed = scrub_text(
        "raw trust statement body: signed-trust-document\n"
        "raw message body: private-social-body\n"
        "request body: form-password=secret\n"
        "raw feed body: <script>alert(1)</script>",
        repo_root,
    )
    for forbidden in (
        "signed-trust-document",
        "private-social-body",
        "form-password=secret",
        "<script>alert(1)</script>",
    ):
        assert forbidden not in body_label_scrubbed, body_label_scrubbed
    assert "raw trust statement body: <redacted>" in body_label_scrubbed, body_label_scrubbed
    assert "raw message body: <redacted>" in body_label_scrubbed, body_label_scrubbed
    safe_bundle_source = (
        "record AppServiceGrantBundle(String bundleId) { "
        "/* comments can mention tokens and local paths */ "
        "void toJson(java.util.Map<String,Object> json) { json.put(\"bundleId\", bundleId); } }"
    )
    unsafe_bundle_source = (
        "record AppServiceGrantBundle(String bundleId, String tokenPath) { "
        "void toJson(java.util.Map<String,Object> json) { json.put(\"tokenPath\", tokenPath); } }"
    )
    assert app_service_bundle_public_fields_are_safe(safe_bundle_source), safe_bundle_source
    assert not app_service_bundle_public_fields_are_safe(unsafe_bundle_source), unsafe_bundle_source
    pem_scrubbed = scrub_text(
        "-----BEGIN PRIVATE KEY-----\n"
        "pem-private-key-body\n"
        "-----END PRIVATE KEY-----\n"
        "public reviewer key id remains",
        repo_root,
    )
    for forbidden in ("BEGIN PRIVATE KEY", "pem-private-key-body", "END PRIVATE KEY"):
        assert forbidden not in pem_scrubbed, pem_scrubbed
    assert "public reviewer key id remains" in pem_scrubbed, pem_scrubbed
    truncated_pem_scrubbed = scrub_text(
        "before\n"
        "-----BEGIN PRIVATE KEY-----\n"
        "truncated-pem-private-key-body\n"
        "more-private-key-body",
        repo_root,
    )
    for forbidden in (
        "BEGIN PRIVATE KEY",
        "truncated-pem-private-key-body",
        "more-private-key-body",
    ):
        assert forbidden not in truncated_pem_scrubbed, truncated_pem_scrubbed
    assert "before" in truncated_pem_scrubbed, truncated_pem_scrubbed
    repo_tmp_path = repo_root / "build/tmp-release-certification/app-platform-smoke/summary.json"
    assert (
        scrub_text(str(repo_tmp_path), repo_root)
        == "<repo>/build/tmp-release-certification/app-platform-smoke/summary.json"
    )
    with tempfile.TemporaryDirectory(prefix="cryptad-app-smoke-symlink-target-") as target_name:
        with tempfile.TemporaryDirectory(prefix="cryptad-app-smoke-symlink-parent-") as link_parent_name:
            symlink_root = Path(link_parent_name) / "repo-link"
            try:
                symlink_root.symlink_to(Path(target_name), target_is_directory=True)
            except (NotImplementedError, OSError):
                symlink_root = None
            if symlink_root is not None:
                symlink_repo_root = symlink_root / "repo"
                symlink_path = symlink_repo_root / "build/tmp-release-certification/app-platform-smoke/summary.json"
                assert (
                    scrub_text(str(symlink_path), symlink_repo_root)
                    == "<repo>/build/tmp-release-certification/app-platform-smoke/summary.json"
                )
    assert (
        normalize_redacted_separators(r"<repo>\build\tmp-release-certification\app-platform-smoke\summary.json")
        == "<repo>/build/tmp-release-certification/app-platform-smoke/summary.json"
    )
    windows_scrubbed = scrub_text(
        r"key file D:\keys\signing.pem and \\builder\share\certs\catalog.pem",
        repo_root,
    )
    assert r"D:\keys" not in windows_scrubbed, windows_scrubbed
    assert r"\\builder\share" not in windows_scrubbed, windows_scrubbed
    assert "<path>/signing.pem" in windows_scrubbed, windows_scrubbed
    assert "<path>/catalog.pem" in windows_scrubbed, windows_scrubbed
    file_uri_scrubbed = scrub_text(
        "metadata file:///home/alice/signing/key.pem file:///D:/keys/catalog.pem",
        repo_root,
    )
    assert "/home/alice/signing" not in file_uri_scrubbed, file_uri_scrubbed
    assert "D:/keys" not in file_uri_scrubbed, file_uri_scrubbed
    assert "file://<path>/key.pem" in file_uri_scrubbed, file_uri_scrubbed
    assert "file://<path>/catalog.pem" in file_uri_scrubbed, file_uri_scrubbed
    route_scrubbed = scrub_text(
        "/apps/install /apps/cert-smoke/runtime /api/v1/diagnostics "
        "/app-data/status /app-data/records/{namespace}/{key} "
        "/content/fetch /content/subscriptions/{subscriptionId}/refresh "
        "/queue/inserts/app-document /trust-graph/import-uri /mnt/secrets/signing/key.pem",
        repo_root,
    )
    assert "/apps/install" in route_scrubbed, route_scrubbed
    assert "/apps/cert-smoke/runtime" in route_scrubbed, route_scrubbed
    assert "/api/v1/diagnostics" in route_scrubbed, route_scrubbed
    assert "/app-data/status" in route_scrubbed, route_scrubbed
    assert "/app-data/records/{namespace}/{key}" in route_scrubbed, route_scrubbed
    assert "/content/fetch" in route_scrubbed, route_scrubbed
    assert "/content/subscriptions/{subscriptionId}/refresh" in route_scrubbed, route_scrubbed
    assert "/queue/inserts/app-document" in route_scrubbed, route_scrubbed
    assert "/trust-graph/import-uri" in route_scrubbed, route_scrubbed
    assert "/mnt/secrets/signing/key.pem" not in route_scrubbed, route_scrubbed
    assert "<path>/key.pem" in route_scrubbed, route_scrubbed
    content_root_path_scrubbed = scrub_text("/content/cryptad/build/key.pem", repo_root)
    queue_root_path_scrubbed = scrub_text("/queue/cryptad/build/token.txt", repo_root)
    assert "/content/cryptad" not in content_root_path_scrubbed, content_root_path_scrubbed
    assert "/queue/cryptad" not in queue_root_path_scrubbed, queue_root_path_scrubbed
    assert "<path>/key.pem" in content_root_path_scrubbed, content_root_path_scrubbed
    assert "<path>/token.txt" in queue_root_path_scrubbed, queue_root_path_scrubbed
    content_workspace_scrubbed = scrub_text(
        "/content/cryptad/build/app-platform-smoke/summary.json",
        Path("/content/cryptad"),
    )
    assert (
        content_workspace_scrubbed == "<repo>/build/app-platform-smoke/summary.json"
    ), content_workspace_scrubbed
    signing_metadata = sanitize_value(
        {
            "privateKeyPresent": False,
            "privateKeySource": "missing",
            "publicKeyPresent": True,
            "publicKeySource": "environment",
            "secretMaterialRedacted": True,
            "privateKey": "actual-secret",
            "privateKeyFile": "/mnt/secrets/signing/key.pem",
            "token": "runtime-token",
            "path": "/apps/cert-smoke/runtime",
        },
        repo_root,
    )
    assert signing_metadata["privateKeyPresent"] is False, signing_metadata
    assert signing_metadata["privateKeySource"] == "missing", signing_metadata
    assert signing_metadata["publicKeyPresent"] is True, signing_metadata
    assert signing_metadata["publicKeySource"] == "environment", signing_metadata
    assert signing_metadata["secretMaterialRedacted"] is True, signing_metadata
    assert signing_metadata["privateKey"] == "<redacted>", signing_metadata
    assert signing_metadata["privateKeyFile"] == "<redacted>", signing_metadata
    assert signing_metadata["token"] == "<redacted>", signing_metadata
    assert signing_metadata["path"] == "/apps/cert-smoke/runtime", signing_metadata
    vault_metadata = sanitize_value(
        {
            "capabilities": list(APP_VAULT_CAPABILITIES),
            "secretValue": "stored-secret",
            "identityPrivateKey": "private-identity-key",
            "identitySeed": "identity-seed",
            "recoveryPhrase": "alpha beta gamma",
            "mnemonicPhrase": "delta epsilon zeta",
            "accountMnemonic": "eta theta iota",
            "publicIdentityId": "identity-public-id",
        },
        repo_root,
    )
    assert vault_metadata["capabilities"] == list(APP_VAULT_CAPABILITIES), vault_metadata
    assert vault_metadata["secretValue"] == "<redacted>", vault_metadata
    assert vault_metadata["identityPrivateKey"] == "<redacted>", vault_metadata
    assert vault_metadata["identitySeed"] == "<redacted>", vault_metadata
    assert vault_metadata["recoveryPhrase"] == "<redacted>", vault_metadata
    assert vault_metadata["mnemonicPhrase"] == "<redacted>", vault_metadata
    assert vault_metadata["accountMnemonic"] == "<redacted>", vault_metadata
    assert vault_metadata["publicIdentityId"] == "identity-public-id", vault_metadata
    vault_scrubbed = scrub_text(
        '{"identitySeed":"seed-secret","recoveryPhrase":"alpha beta","mnemonicPhrase":"delta epsilon",'
        '"accountMnemonic":"eta theta","secretValue":"vault-secret"} '
        "capability=vault.secrets.read",
        repo_root,
    )
    for forbidden in ("seed-secret", "alpha beta", "delta epsilon", "eta theta", "vault-secret"):
        assert forbidden not in vault_scrubbed, vault_scrubbed
    assert "vault.secrets.read" in vault_scrubbed, vault_scrubbed
    sandbox_check_metadata = sanitize_value(
        {
            "enforcedSupportLevel": True,
            "noSetenvCommand": True,
            "enforcedStatusToken": True,
        },
        repo_root,
    )
    assert sandbox_check_metadata["enforcedSupportLevel"] is True, sandbox_check_metadata
    assert sandbox_check_metadata["noSetenvCommand"] is True, sandbox_check_metadata
    assert sandbox_check_metadata["enforcedStatusToken"] == "<redacted>", sandbox_check_metadata
    feed_body_metadata = sanitize_value(
        {
            "rawFeedBody": "<feed><entry>private body</entry></feed>",
            "rawFeedBodyBase64": "opaque-feed-body-base64",
            "rawRequestBody": "uri=SSK@private",
            "requestBodyText": "opaque-request-body-text",
            "feedContentPreview": "opaque-feed-preview",
            "rawFeedBodySource": "opaque-feed-body-source",
            "requestBodySource": "opaque-request-body-source",
            "rawTrustStatementBody": '{"type":"crypta.trust.statement.v1","signature":{"value":"sig"}}',
            "trustStatementBodies": ["signed trust statement body"],
            "trustStatementPayload": {"signature": {"value": "trust-signature"}},
            "rawTrustStatementBodySource": "opaque-trust-body-source",
            "trustStatementBodiesExcluded": True,
            "feedSummary": "3 entries",
            "rawFeedBodyRedacted": True,
            "rawFeedBodiesExcluded": True,
            "rawMessageBodiesExcludedFromEvidence": True,
        },
        repo_root,
    )
    assert feed_body_metadata["rawFeedBody"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["rawFeedBodyBase64"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["rawRequestBody"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["requestBodyText"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["feedContentPreview"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["rawFeedBodySource"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["requestBodySource"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["rawTrustStatementBody"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["trustStatementBodies"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["trustStatementPayload"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["rawTrustStatementBodySource"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["trustStatementBodiesExcluded"] is True, feed_body_metadata
    assert feed_body_metadata["feedSummary"] == "3 entries", feed_body_metadata
    assert feed_body_metadata["rawFeedBodyRedacted"] is True, feed_body_metadata
    assert feed_body_metadata["rawFeedBodiesExcluded"] is True, feed_body_metadata
    assert feed_body_metadata["rawMessageBodiesExcludedFromEvidence"] is True, feed_body_metadata
    credential_scrubbed = scrub_text(
        'Authorization: Bearer app-secret\n'
        'Cookie: session=abc; csrf=def\n'
        '{"token":"json-secret","authorization":"Bearer json-secret","password":"pw",'
        '"X-Crypta-App-Session":"browser-session"} '
        "authorization=Bearer inline-secret "
        "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64=base64-secret "
        "privateKeyBase64=key-secret clientSecret=client-secret api_password=api-secret "
        "privateKeyPresent=false",
        repo_root,
    )
    for forbidden in (
        "Bearer app-secret",
        "session=abc",
        "csrf=def",
        "json-secret",
        '"pw"',
        "browser-session",
        "inline-secret",
        "base64-secret",
        "key-secret",
        "client-secret",
        "api-secret",
    ):
        assert forbidden not in credential_scrubbed, credential_scrubbed
    assert "Authorization: <redacted>" in credential_scrubbed, credential_scrubbed
    assert "Cookie: <redacted>" in credential_scrubbed, credential_scrubbed
    assert '"token":"<redacted>"' in credential_scrubbed, credential_scrubbed
    assert "authorization=<redacted>" in credential_scrubbed, credential_scrubbed
    assert "privateKeyPresent=false" in credential_scrubbed, credential_scrubbed
    delete_request = build_http_request(
        "DELETE", "http://127.0.0.1:8888/api/v1/apps/cert-smoke", "hunter2"
    )
    assert delete_request.data == b"formPassword=hunter2"
    assert "formPassword" not in delete_request.full_url
    assert delete_request.get_header("Content-type") == "application/x-www-form-urlencoded"

    get_request = build_http_request(
        "GET", "http://127.0.0.1:8888/api/v1/apps", data={"page": "one"}
    )
    assert get_request.data is None
    assert get_request.full_url.endswith("?page=one")
    remote_live_settings = Settings(
        workspace_root=repo_root.resolve(),
        out_dir=(repo_root / DEFAULT_OUT_DIR).resolve(),
        mode="pr",
        skip_gradle=True,
        cli_path=None,
        live=True,
        live_base_url="https://node.example.invalid:9443/admin?token=hunter2",
        live_form_password="secret",
        timeout_seconds=1,
    )
    remote_item = collect_live_evidence(remote_live_settings, {})
    remote_encoded = json.dumps(remote_item.to_json(), sort_keys=True)
    assert remote_item.status == "fail", remote_item
    assert "<redacted-remote-url>" in remote_encoded, remote_encoded
    for forbidden in ("node.example.invalid", "hunter2", "https://"):
        assert forbidden not in remote_encoded, f"remote live URL leaked {forbidden}"
    assert (
        overall_status(
            "release-candidate",
            [EvidenceItem("catalog.smoke", "missing", True, "missing", "<repo>/summary.json", {})],
        )
        == "fail"
    )
    assert (
        overall_status(
            "pr",
            [EvidenceItem("catalog.smoke", "missing", True, "missing", "<repo>/summary.json", {})],
        )
        == "warn"
    )
    assert (
        overall_status(
            "pr",
            [EvidenceItem("apphost.live", "skip", False, "not requested", "<repo>/summary.json", {})],
        )
        == "pass"
    )
    assert (
        overall_status(
            "release-candidate",
            [
                EvidenceItem("catalog.smoke", "pass", True, "passed", "<repo>/summary.json", {}),
                EvidenceItem("apphost.live", "skip", False, "not requested", "<repo>/summary.json", {}),
            ],
        )
        == "pass"
    )
    with tempfile.TemporaryDirectory(prefix="cryptad-app-review-key-self-test-") as key_temp:
        key_dir = Path(key_temp)
        base64_key = base64.b64encode(b"review-public-key").decode("ascii")
        base64_key_file = key_dir / "reviewer-public-base64.txt"
        base64_key_file.write_text("\n".join((base64_key[:8], base64_key[8:])), encoding="utf-8")
        assert (
            reviewer_public_key_base64(
                {"publicBase64": False, "publicFile": str(base64_key_file)}
            )
            == base64_key
        )
        raw_key = b"\xff\x00review-public-key"
        raw_key_file = key_dir / "reviewer-public.der"
        raw_key_file.write_bytes(raw_key)
        assert reviewer_public_key_base64(
            {"publicBase64": False, "publicFile": str(raw_key_file)}
        ) == base64.b64encode(raw_key).decode("ascii")
    with tempfile.TemporaryDirectory(prefix="cryptad-app-smoke-self-test-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        python_fake_cli = workspace / "crypta-app-fake.py"
        python_fake_cli.write_text(fake_cli_python_source(), encoding="utf-8")
        python_contract = workspace / "python-fake-contract.json"
        python_fake_result = subprocess.run(
            [
                sys.executable,
                str(python_fake_cli),
                "api",
                "snapshot",
                "--output",
                str(python_contract),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert python_fake_result.returncode == 0, python_fake_result.stderr
        assert json.loads(python_contract.read_text(encoding="utf-8"))["contract"][
            "contractVersion"
        ] == CURRENT_PLATFORM_API_CONTRACT_VERSION
        fake_cli = make_fake_cli(workspace)
        settings = Settings(
            workspace_root=workspace.resolve(),
            out_dir=(workspace / DEFAULT_OUT_DIR).resolve(),
            mode="pr",
            skip_gradle=True,
            cli_path=fake_cli,
            live=False,
            live_base_url="",
            live_form_password="",
            timeout_seconds=60,
        )
        summary, exit_code = run(settings)
        assert exit_code == 0, summary
        assert summary["status"] in {"pass", "warn"}, summary
        evidence_by_id = {item["id"]: item for item in summary["evidence"]}
        assert evidence_by_id["app-platform.first-party"]["status"] == "pass"
        assert evidence_by_id["app-platform.devtools-cli"]["status"] == "pass"
        toolkit_item = evidence_by_id["app-platform.developer-beta-toolkit"]
        assert toolkit_item["status"] == "pass", toolkit_item
        assert toolkit_item["details"]["checks"]["devCommand"] is True, toolkit_item
        assert toolkit_item["details"]["checks"]["templates"]["queue-dashboard"] is True, toolkit_item
        assert evidence_by_id["legacy-admin.removal-wave-1"]["status"] == "pass"
        assert evidence_by_id["legacy-admin.removal-wave-1"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-admin.removal-wave-2"]["status"] == "pass"
        assert evidence_by_id["legacy-admin.removal-wave-2"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-admin.removal-wave-3"]["status"] == "pass"
        assert evidence_by_id["legacy-admin.removal-wave-3"]["requiredForReleaseCandidate"] is True
        contract_item = evidence_by_id["platform-api.contract"]
        assert contract_item["status"] == "pass", contract_item
        vault_item = evidence_by_id["app-vault.capabilities"]
        assert vault_item["status"] == "pass", vault_item
        assert vault_item["requiredForReleaseCandidate"] is True, vault_item
        assert vault_item["details"]["capabilities"] == list(APP_VAULT_CAPABILITIES), vault_item
        for evidence_id in (
            "app-services.registry",
            "app-services.grants",
            "app-services.dependency-graph",
            "app-services.grant-bundles",
            "app-services.grant-expiry-renewal",
            "app-services.provider-revalidation",
            "app-services.trust-score-provider",
            "reference-app.social-inbox-service-grant",
            "reference-app.social-inbox-service-dependency",
            "app-services.web-shell",
            "app-services.redaction",
            "app-services.dependency-redaction",
        ):
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id[evidence_id]
        assert evidence_by_id["app-platform.identity-profile-publish"]["status"] == "pass"
        assert evidence_by_id["app-platform.generated-document-insert"]["status"] == "pass"
        assert evidence_by_id["app-platform.content-fetch"]["status"] == "pass"
        assert evidence_by_id["app-platform.content-subscriptions"]["status"] == "pass"
        assert evidence_by_id["network-content.subscription-scheduler"]["status"] == "pass"
        assert evidence_by_id["app-platform.durable-app-data-store"]["status"] == "pass"
        backup_restore_item = evidence_by_id["app-data.backup-restore-portability"]
        assert backup_restore_item["status"] == "pass", backup_restore_item
        assert backup_restore_item["requiredForReleaseCandidate"] is True
        assert backup_restore_item["details"]["backupVersion"] == 1, backup_restore_item
        assert backup_restore_item["details"]["restoreModes"] == [
            "merge",
            "replaceNamespace",
            "replaceApp",
        ], backup_restore_item
        contract_details = contract_item["details"]
        assert (
            contract_details["contractVersion"] == CURRENT_PLATFORM_API_CONTRACT_VERSION
        ), contract_item
        assert contract_details["capabilityCount"] == 11, contract_item
        assert contract_details["endpointCount"] == 35, contract_item
        assert contract_details["appServicesContract"]["missingCapabilities"] == [], contract_item
        assert contract_details["appServicesContract"]["missingEndpoints"] == [], contract_item
        assert contract_details["stableCapabilities"] == [
            "app.data.read",
            "app.data.write",
            "content.fetch",
            "platform.contract.read",
            "queue.read",
            "trust.read",
            "trust.write",
        ], contract_item
        assert contract_details["stableEndpoints"] == [
            "DELETE /app-data/namespaces/{namespace}",
            "DELETE /app-data/records/{namespace}/{key}",
            "GET /app-data/export",
            "GET /app-data/namespaces",
            "GET /app-data/namespaces/{namespace}",
            "GET /app-data/records",
            "GET /app-data/records/{namespace}/{key}",
            "GET /app-data/status",
            "GET /queue",
            "GET /trust-graph/audit",
            "POST /app-data/import",
            "POST /app-data/namespaces/{namespace}/schema",
            "POST /app-data/records",
            "POST /trust-graph/import-uri",
        ], contract_item
        assert contract_details["snapshotCommand"]["exitCode"] == 0, contract_item
        assert contract_details["verifier"]["cert-smoke"]["exitCode"] == 0, contract_item
        assert evidence_by_id["catalog.smoke"]["status"] in {"warn", "pass"}
        assert evidence_by_id["catalog.live-usk-publication"]["status"] == "pass"
        first_party_beta_item = evidence_by_id["app-catalog.first-party-beta"]
        assert first_party_beta_item["status"] == "pass", first_party_beta_item
        assert first_party_beta_item["details"]["catalogId"] == "crypta-first-party-beta"
        assert first_party_beta_item["details"]["requiredFirstPartyApps"] == list(APP_IDS)
        production_channels_item = evidence_by_id["catalog.production-channels"]
        assert production_channels_item["status"] == "pass", production_channels_item
        assert production_channels_item["details"]["channels"] == [
            "stable",
            "beta",
            "nightly",
            "deprecated",
        ]
        assert evidence_by_id["catalog.live-usk-source-verification"]["status"] == "pass"
        assert evidence_by_id["app-ui.design-system"]["status"] == "pass"
        assert evidence_by_id["app-ui.lint"]["status"] == "pass"
        assert evidence_by_id["app-ui.first-party-adoption"]["status"] == "pass"
        assert evidence_by_id["reference-apps.content"]["status"] == "pass"
        assert evidence_by_id["reference-app.profile-publisher"]["status"] == "pass"
        assert evidence_by_id["reference-app.profile-publisher-app-data"]["status"] == "pass"
        assert evidence_by_id["reference-app.social-inbox"]["status"] == "pass"
        assert evidence_by_id["reference-app.social-inbox-signed-message"]["status"] == "pass"
        assert evidence_by_id["reference-app.social-inbox-subscriptions"]["status"] == "pass"
        assert evidence_by_id["reference-app.social-inbox-app-data"]["status"] == "pass"
        assert evidence_by_id["reference-app.social-inbox-trust-annotations"]["status"] == "pass"
        assert evidence_by_id["reference-app.social-inbox-rc-threading"]["status"] == "pass"
        assert (
            evidence_by_id["reference-app.social-inbox-rc-threading"]["requiredForReleaseCandidate"]
            is True
        )
        assert evidence_by_id["migration.social-mail-preview"]["status"] == "pass"
        assert evidence_by_id["legacy-plugin.migration-guide"]["status"] == "pass"
        assert evidence_by_id["legacy-plugin.social-inbox-spike"]["status"] == "pass"
        social_inbox_app_js = workspace / "apps/social-inbox/src/staged/static/app.js"
        original_social_inbox_js = social_inbox_app_js.read_text(encoding="utf-8")
        try:
            social_inbox_app_js.write_text(
                original_social_inbox_js
                + "\nfetch('http://127.0.0.1:8888/api/v1/app-services');\n",
                encoding="utf-8",
            )
            direct_local_endpoint_item = collect_legacy_plugin_social_inbox_spike_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            social_inbox_app_js.write_text(original_social_inbox_js, encoding="utf-8")
        assert direct_local_endpoint_item.status == "fail", direct_local_endpoint_item
        assert "noDirectLocalEndpointReference" in direct_local_endpoint_item.details["errors"], (
            direct_local_endpoint_item
        )
        try:
            social_inbox_app_js.write_text(
                original_social_inbox_js
                + "\nCryptaPlatform.trust.score({ subjectKind: 'identity' });\n"
                + "\nfetch('/api/v1/trust-graph/score');\n",
                encoding="utf-8",
            )
            direct_trust_route_item = collect_social_inbox_rc_threading_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            social_inbox_app_js.write_text(original_social_inbox_js, encoding="utf-8")
        assert direct_trust_route_item.status == "fail", direct_trust_route_item
        assert "social inbox RC threading check failed: trustGraphMediatedOnly" in (
            direct_trust_route_item.details["errors"]
        ), direct_trust_route_item
        assert evidence_by_id["reference-app.feed-reader"]["status"] == "pass"
        assert evidence_by_id["reference-app.feed-reader-subscriptions"]["status"] == "pass"
        assert evidence_by_id["reference-app.feed-reader-app-data"]["status"] == "pass"
        assert evidence_by_id["reference-app.trust-graph"]["status"] == "pass"
        assert evidence_by_id["reference-app.trust-graph-durable-exchange"]["status"] == "pass"
        assert evidence_by_id["reference-app.trust-graph-app-data-preview"]["status"] == "pass"
        assert evidence_by_id["app-platform.trust-graph-preview"]["status"] == "pass"
        assert (
            evidence_by_id["app-platform.trust-graph-rc-scope-and-safety"]["status"] == "pass"
        )
        assert evidence_by_id["app-platform.trust-graph-durable-store"]["status"] == "pass"
        assert evidence_by_id["app-platform.trust-graph-exchange"]["status"] == "pass"
        assert evidence_by_id["app-platform.trust-statement-signing"]["status"] == "pass"
        assert evidence_by_id["app-platform.social-message-signing"]["status"] == "pass"
        migration_guide = workspace / "docs/legacy-plugin-migration-guide.md"
        migration_guide_text = migration_guide.read_text(encoding="utf-8")
        try:
            migration_guide.unlink()
            missing_guide_item = collect_legacy_plugin_migration_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            migration_guide.write_text(migration_guide_text, encoding="utf-8")
        assert missing_guide_item.status == "fail", missing_guide_item
        assert "guideExists" in missing_guide_item.details["errors"], missing_guide_item
        registry_source = (
            workspace
            / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java"
        )
        registry_source_text = registry_source.read_text(encoding="utf-8")
        try:
            registry_source.write_text(
                registry_source_text.replace(
                    "securityLevelsWave3Redirect(),",
                    'securityLevelsWave3Redirect(),\n'
                    '          wave3Redirect("diagnostic", "Diagnostic", "/diagnostic/", '
                    '"/app/node/#diagnostics", "Shell diagnostics", "Wrong.", false),',
                ),
                encoding="utf-8",
            )
            extra_wave_three_item = collect_legacy_removal_wave_three_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            registry_source.write_text(registry_source_text, encoding="utf-8")
        assert extra_wave_three_item.status == "fail", extra_wave_three_item
        assert "waveThreeIdsMatch" in extra_wave_three_item.details["errors"], (
            extra_wave_three_item
        )
        feed_reader_app_js = workspace / "apps/feed-reader/src/staged/static/app.js"
        original_feed_reader_js = feed_reader_app_js.read_text(encoding="utf-8")
        try:
            feed_reader_app_js.write_text(
                "const appId = 'feed-reader';\n"
                "CryptaPlatform.bootstrap.load({ appId });\n"
                "CryptaPlatform.feed.parseSnapshot('{}');\n"
                "CryptaPlatform.feed.publishSnapshot({ snapshot: { type: 'crypta.feed.snapshot.v1', items: [] } });\n"
                "CryptaPlatform.queue.snapshot({ page: 'uploads' });\n",
                encoding="utf-8",
            )
            missing_fetch_settings = dataclasses.replace(settings, mode="release-candidate")
            missing_fetch_item = collect_feed_reader_reference_app_evidence(missing_fetch_settings)
        finally:
            feed_reader_app_js.write_text(original_feed_reader_js, encoding="utf-8")
        assert missing_fetch_item.status == "fail", missing_fetch_item
        assert (
            missing_fetch_item.details["checks"]["usesContentFetchRouteOrHelper"] is False
        ), missing_fetch_item
        try:
            feed_reader_app_js.write_text(
                "const appId = 'feed-reader';\n"
                "CryptaPlatform.bootstrap.load({ appId });\n"
                "CryptaPlatform.content.fetchText({ uri: 'USK@redacted/feed/0/feed.json' });\n"
                "CryptaPlatform.feed.fetchSnapshot({ uri: 'USK@redacted/feed/0/feed.json' });\n"
                "CryptaPlatform.feed.publishSnapshot({ snapshot: { type: 'crypta.feed.snapshot.v1', items: [] } });\n"
                "CryptaPlatform.queue.snapshot({ page: 'uploads' });\n",
                encoding="utf-8",
            )
            missing_subscription_settings = dataclasses.replace(settings, mode="release-candidate")
            missing_subscription_item = collect_feed_reader_subscription_evidence(
                missing_subscription_settings
            )
        finally:
            feed_reader_app_js.write_text(original_feed_reader_js, encoding="utf-8")
        assert missing_subscription_item.status == "fail", missing_subscription_item
        assert (
            missing_subscription_item.details["checks"]["appUsesPlatformSubscriptionWorkflow"]
            is False
        ), missing_subscription_item
        review_env_names = (
            "CRYPTAD_APP_REVIEWER_KEY_ID",
            "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE",
            "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64",
            "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE",
            "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64",
            "CRYPTAD_APP_REVIEW_POLICY_ID",
            "CRYPTAD_APP_REVIEW_POLICY_VERSION",
        )
        previous_review_env = {name: os.environ.get(name) for name in review_env_names}
        os.environ["CRYPTAD_APP_REVIEWER_KEY_ID"] = "cert-review"
        os.environ.pop("CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE", None)
        os.environ["CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64"] = "ZmFrZQ=="
        os.environ.pop("CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE", None)
        os.environ["CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64"] = "ZmFrZQ=="
        os.environ["CRYPTAD_APP_REVIEW_POLICY_ID"] = "crypta-app-review-v1"
        os.environ["CRYPTAD_APP_REVIEW_POLICY_VERSION"] = "1"
        try:
            first_party_review_item = collect_app_review_first_party_catalog_evidence(
                dataclasses.replace(
                    settings,
                    out_dir=(workspace / "build/first-party-review-catalog-smoke").resolve(),
                    mode="release-candidate",
                ),
                {"cli": fake_cli},
            )
        finally:
            for name, value in previous_review_env.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        assert first_party_review_item.status == "pass", first_party_review_item
        assert first_party_review_item.details["coverage"]["catalogAppsInspected"] == len(
            APP_IDS
        ), first_party_review_item
        assert first_party_review_item.details["coverage"]["trustedPositiveReceipts"] == len(
            APP_IDS
        ), first_party_review_item
        assert set(first_party_review_item.details["catalog"]["inspectedAppIds"]) == set(APP_IDS)

        def collect_ui_lint_with_fake_env(
            env_name: str, out_leaf: str
        ) -> tuple[EvidenceItem, Path]:
            previous = os.environ.get(env_name)
            os.environ[env_name] = "1"
            try:
                lint_settings = dataclasses.replace(
                    settings,
                    out_dir=(workspace / "build" / out_leaf).resolve(),
                    mode="release-candidate",
                )
                stale_json = (
                    lint_settings.out_dir / "artifacts/app-ui-lint/queue-manager.json"
                )
                stale_json.parent.mkdir(parents=True, exist_ok=True)
                stale_json.write_text(
                    json.dumps(
                        {
                            "appId": "queue-manager",
                            "uiMode": "static",
                            "applicable": True,
                            "summary": {"errors": 0, "warnings": 0, "notes": 0},
                            "findings": [],
                        },
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                return collect_app_ui_lint_evidence(lint_settings, fake_cli), stale_json
            finally:
                if previous is None:
                    os.environ.pop(env_name, None)
                else:
                    os.environ[env_name] = previous

        missing_ui_lint_item, stale_ui_lint_json = collect_ui_lint_with_fake_env(
            "CRYPTAD_APP_SMOKE_FAKE_SKIP_UI_LINT_JSON",
            "missing-ui-lint-json",
        )
        assert missing_ui_lint_item.status == "fail", missing_ui_lint_item
        assert any(
            "JSON missing or malformed" in error
            for error in missing_ui_lint_item.details["errors"]
        ), missing_ui_lint_item
        assert not stale_ui_lint_json.exists(), stale_ui_lint_json
        malformed_ui_lint_item, _ = collect_ui_lint_with_fake_env(
            "CRYPTAD_APP_SMOKE_FAKE_BAD_UI_LINT_JSON",
            "malformed-ui-lint-json",
        )
        assert malformed_ui_lint_item.status == "fail", malformed_ui_lint_item
        assert any(
            "JSON missing or malformed" in error
            for error in malformed_ui_lint_item.details["errors"]
        ), malformed_ui_lint_item
        wrong_ui_lint_item, _ = collect_ui_lint_with_fake_env(
            "CRYPTAD_APP_SMOKE_FAKE_WRONG_UI_LINT_APP",
            "wrong-ui-lint-app",
        )
        assert wrong_ui_lint_item.status == "fail", wrong_ui_lint_item
        assert any(
            "appId mismatch" in error for error in wrong_ui_lint_item.details["errors"]
        ), wrong_ui_lint_item
        errored_ui_lint_item, _ = collect_ui_lint_with_fake_env(
            "CRYPTAD_APP_SMOKE_FAKE_UI_LINT_ERRORS",
            "errored-ui-lint-report",
        )
        assert errored_ui_lint_item.status == "fail", errored_ui_lint_item
        assert any(
            "nonzero errors" in error for error in errored_ui_lint_item.details["errors"]
        ), errored_ui_lint_item
        assert evidence_by_id["apphost.sandbox-provider"]["status"] == "pass"
        assert evidence_by_id["apphost.sandbox-provider"]["details"]["liveBubblewrapRequired"] is False
        sandbox_checks = evidence_by_id["apphost.sandbox-provider"]["details"]["checks"]
        assert sandbox_checks["enforcedSupportLevel"] is True, sandbox_checks
        assert sandbox_checks["noSetenvCommand"] is True, sandbox_checks
        assert "enforcedStatusToken" not in sandbox_checks, sandbox_checks
        assert "noTokenSetenvCommand" not in sandbox_checks, sandbox_checks
        for evidence_id in PUBLIC_BETA_SECURITY_EVIDENCE_IDS:
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id[evidence_id]
        assert evidence_by_id["app-update.lifecycle"]["status"] == "pass"
        assert evidence_by_id["app-update.lifecycle"]["requiredForReleaseCandidate"] is True
        lifecycle_checks = evidence_by_id["app-update.lifecycle"]["details"]["checks"]
        assert lifecycle_checks["hostApplyWhenStoppedGate"] is True, lifecycle_checks
        assert lifecycle_checks["updateApplyRunningConflictTest"] is True, lifecycle_checks
        assert lifecycle_checks["updateApplyRunningConflictRouteTest"] is True, lifecycle_checks
        assert lifecycle_checks["candidateDetectionSemantics"] is True, lifecycle_checks
        assert lifecycle_checks["permissionDeltaReview"] is True, lifecycle_checks
        assert lifecycle_checks["lifecycleHandlerRoutesStageAndApply"] is True, lifecycle_checks
        assert lifecycle_checks["lifecycleServiceStagesVerifiedPlan"] is True, lifecycle_checks
        assert lifecycle_checks["lifecycleServiceApplyDelegatesToAppHost"] is True, lifecycle_checks
        assert evidence_by_id["app-update.scheduler"]["status"] == "pass"
        assert evidence_by_id["app-update.scheduler"]["requiredForReleaseCandidate"] is True
        scheduler_checks = evidence_by_id["app-update.scheduler"]["details"]["checks"]
        assert scheduler_checks["schedulerConfigPresent"] is True, scheduler_checks
        assert scheduler_checks["schedulerDelegatesToUpdateCheck"] is True, scheduler_checks
        assert scheduler_checks["schedulerManualPolicyDoesNotMutate"] is True, scheduler_checks
        assert scheduler_checks["schedulerPolicyDrivenChecks"] is True, scheduler_checks
        assert scheduler_checks["schedulerPerAppSerialized"] is True, scheduler_checks
        assert scheduler_checks["schedulerPathAndPrivateDataFree"] is True, scheduler_checks
        assert scheduler_checks["schedulerLifecycleDocumented"] is True, scheduler_checks
        assert evidence_by_id["app-update.live-catalog-refresh"]["status"] == "pass"
        live_catalog_refresh_checks = evidence_by_id["app-update.live-catalog-refresh"]["details"][
            "checks"
        ]
        assert (
            live_catalog_refresh_checks["schedulerSummaryPrivacyGuard"] is True
        ), live_catalog_refresh_checks
        assert all(
            isinstance(value, bool) for value in live_catalog_refresh_checks.values()
        ), live_catalog_refresh_checks
        assert evidence_by_id["app-update.rollback"]["status"] == "pass"
        assert evidence_by_id["app-update.rollback"]["requiredForReleaseCandidate"] is True
        rollback_checks = evidence_by_id["app-update.rollback"]["details"]["checks"]
        assert rollback_checks["restorePreviousBundleOnReplacementFailure"] is True, rollback_checks
        assert rollback_checks["mutableDirectoriesPreservedByUpdate"] is True, rollback_checks
        assert rollback_checks["mutableDirectoriesPreservedByRollback"] is True, rollback_checks
        migration_contract_item = evidence_by_id["app-update.data-migration-contract"]
        assert migration_contract_item["status"] == "pass", migration_contract_item
        assert migration_contract_item["requiredForReleaseCandidate"] is True
        migration_contract_checks = migration_contract_item["details"]["checks"]
        assert migration_contract_checks["manifestModelsAndParser"] is True, migration_contract_checks
        assert migration_contract_checks["snapshotBeforeReplacementAndRestoreOnFailure"] is True, (
            migration_contract_checks
        )
        assert migration_contract_checks["feedReaderDeclaresMigrationExample"] is True, (
            migration_contract_checks
        )
        assert migration_contract_checks["trustGraphDeclaresMigrationExample"] is True, (
            migration_contract_checks
        )
        for evidence_id in OPERATOR_BETA_EVIDENCE_IDS:
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id[evidence_id]
            assert evidence_by_id[evidence_id]["requiredForReleaseCandidate"] is True
        assert (
            evidence_by_id["operator-beta.support-bundle-redaction"]["details"]["checks"][
                "redactorApplied"
            ]
            is True
        )
        assert (
            evidence_by_id["operator-beta.web-shell"]["details"]["checks"]["loadsOperatorEndpoints"]
            is True
        )
        encoded = json.dumps(summary, sort_keys=True)
        for forbidden in ("CRYPTAD_APP_TOKEN=secret", "formPassword=hunter2", str(workspace)):
            assert forbidden not in encoded, f"self-test leaked {forbidden}"
        stale_log = settings.out_dir / "artifacts/logs/stale-from-previous-run.log"
        stale_log.parent.mkdir(parents=True, exist_ok=True)
        stale_log.write_text("old command output\n", encoding="utf-8")
        rerun_summary, rerun_exit_code = run(settings)
        assert rerun_exit_code == 0, rerun_summary
        assert not stale_log.exists(), stale_log
        stale_sample_dir = sample_workspace(settings) / "cert-smoke-app"
        stale_sample_dir.mkdir(parents=True, exist_ok=True)
        stale_digest = stale_sample_dir / "cryptad-app.digest"
        stale_signature = stale_sample_dir / "cryptad-app.signature"
        stale_digest.write_text("digest=stale\n", encoding="utf-8")
        stale_signature.write_text("signature=stale\n", encoding="utf-8")
        fresh_cli_item, fresh_sample_paths = collect_cli_evidence(settings, fake_cli)
        assert fresh_cli_item.status == "pass", fresh_cli_item
        assert fresh_sample_paths["bundleDir"].is_dir(), fresh_sample_paths
        assert not stale_digest.exists(), stale_digest
        assert not stale_signature.exists(), stale_signature
        fresh_launcher = fresh_sample_paths["bundleDir"] / "bin/start.sh"
        fresh_launcher_text = fresh_launcher.read_text(encoding="utf-8")
        assert "trap cleanup INT TERM" in fresh_launcher_text, fresh_launcher_text
        assert "sleep 60" in fresh_launcher_text, fresh_launcher_text
        if os.name != "nt":
            assert os.access(fresh_launcher, os.X_OK), fresh_launcher

        previous_skip_pack_output = os.environ.get("CRYPTAD_APP_SMOKE_FAKE_SKIP_PACK_OUTPUT")
        os.environ["CRYPTAD_APP_SMOKE_FAKE_SKIP_PACK_OUTPUT"] = "1"
        try:
            missing_pack_settings = dataclasses.replace(
                settings,
                out_dir=(workspace / "build/missing-pack-smoke").resolve(),
                mode="release-candidate",
            )
            stale_zip = sample_workspace(missing_pack_settings) / "cert-smoke-app-0.1.0.zip"
            stale_zip.parent.mkdir(parents=True, exist_ok=True)
            stale_zip.write_bytes(b"stale")
            missing_pack_item, _ = collect_cli_evidence(missing_pack_settings, fake_cli)
        finally:
            if previous_skip_pack_output is None:
                os.environ.pop("CRYPTAD_APP_SMOKE_FAKE_SKIP_PACK_OUTPUT", None)
            else:
                os.environ["CRYPTAD_APP_SMOKE_FAKE_SKIP_PACK_OUTPUT"] = previous_skip_pack_output
        assert missing_pack_item.status == "fail", missing_pack_item
        assert "pack-output" in missing_pack_item.details["failedSteps"], missing_pack_item
        assert missing_pack_item.details["sample"]["zipExists"] is False, missing_pack_item
        assert not stale_zip.exists(), stale_zip

        previous_skip_catalog_output = os.environ.get("CRYPTAD_APP_SMOKE_FAKE_SKIP_CATALOG_OUTPUT")
        os.environ["CRYPTAD_APP_SMOKE_FAKE_SKIP_CATALOG_OUTPUT"] = "1"
        try:
            missing_catalog_settings = dataclasses.replace(
                settings,
                out_dir=(workspace / "build/missing-catalog-smoke").resolve(),
                mode="release-candidate",
            )
            missing_catalog_zip = sample_workspace(missing_catalog_settings) / "cert-smoke-app-0.1.0.zip"
            missing_catalog_zip.parent.mkdir(parents=True, exist_ok=True)
            missing_catalog_zip.write_bytes(b"zip")
            stale_catalog_dir = sample_workspace(missing_catalog_settings) / "catalog"
            stale_catalog_dir.mkdir(parents=True, exist_ok=True)
            stale_catalog = stale_catalog_dir / "cryptad-app-catalog.properties"
            stale_signature = stale_catalog_dir / "cryptad-app-catalog.signature"
            stale_catalog.write_text("catalog.id=stale\n", encoding="utf-8")
            stale_signature.write_text("signature=stale\n", encoding="utf-8")
            missing_catalog_item = collect_catalog_evidence(
                missing_catalog_settings,
                {"cli": fake_cli, "zip": missing_catalog_zip},
            )
        finally:
            if previous_skip_catalog_output is None:
                os.environ.pop("CRYPTAD_APP_SMOKE_FAKE_SKIP_CATALOG_OUTPUT", None)
            else:
                os.environ["CRYPTAD_APP_SMOKE_FAKE_SKIP_CATALOG_OUTPUT"] = previous_skip_catalog_output
        assert missing_catalog_item.status == "fail", missing_catalog_item
        assert missing_catalog_item.details["catalogExists"] is False, missing_catalog_item
        assert not stale_catalog.exists(), stale_catalog
        assert not stale_signature.exists(), stale_signature

        review_env_names = (
            "CRYPTAD_APP_REVIEWER_KEY_ID",
            "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE",
            "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64",
            "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE",
            "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64",
            "CRYPTAD_APP_REVIEW_POLICY_ID",
            "CRYPTAD_APP_REVIEW_POLICY_VERSION",
        )
        previous_review_env = {name: os.environ.get(name) for name in review_env_names}
        os.environ["CRYPTAD_APP_REVIEWER_KEY_ID"] = "cert-review"
        os.environ.pop("CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE", None)
        os.environ["CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64"] = "ZmFrZQ=="
        os.environ["CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE"] = str(
            workspace / "missing-reviewer-public-key.pem"
        )
        os.environ.pop("CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64", None)
        os.environ["CRYPTAD_APP_REVIEW_POLICY_ID"] = "crypta-app-review-v1"
        os.environ["CRYPTAD_APP_REVIEW_POLICY_VERSION"] = "1"
        try:
            missing_review_key_settings = dataclasses.replace(
                settings,
                out_dir=(workspace / "build/missing-review-key-smoke").resolve(),
                mode="release-candidate",
            )
            missing_review_key_item = collect_app_review_first_party_catalog_evidence(
                missing_review_key_settings,
                {"cli": fake_cli, "zip": fresh_sample_paths["zip"]},
            )
        finally:
            for name, value in previous_review_env.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        assert missing_review_key_item.status == "fail", missing_review_key_item
        assert "trustedReviewerKeys" in missing_review_key_item.details, missing_review_key_item

        signing_env_names = (
            "CRYPTAD_APP_SIGNING_KEY_ID",
            "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE",
            "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64",
            "CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE",
            "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64",
        )
        previous_signing_env = {name: os.environ.get(name) for name in signing_env_names}
        os.environ["CRYPTAD_APP_SIGNING_KEY_ID"] = "cert-smoke"
        os.environ.pop("CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE", None)
        os.environ["CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64"] = "ZmFrZQ=="
        os.environ.pop("CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE", None)
        os.environ["CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64"] = "ZmFrZQ=="
        try:
            rc_skip_gradle_settings = dataclasses.replace(
                settings,
                out_dir=(workspace / "build/rc-skip-gradle-signing-smoke").resolve(),
                mode="release-candidate",
                skip_gradle=True,
            )
            rc_cli_item, rc_sample_paths = collect_cli_evidence(rc_skip_gradle_settings, fake_cli)
            assert rc_cli_item.status == "pass", rc_cli_item
            rc_signed_item = collect_signed_bundle_evidence(rc_skip_gradle_settings, rc_sample_paths)
        finally:
            for name, value in previous_signing_env.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        assert rc_signed_item.status == "fail", rc_signed_item
        assert rc_signed_item.details["firstPartySignVerifyRan"] is False, rc_signed_item
        assert "first-party sign/verify Gradle task was skipped" in rc_signed_item.details["failures"], rc_signed_item

        live_calls: list[tuple[str, str]] = []
        original_http_request_json = http_request_json

        def fake_http_request_json(
            method: str, url: str, form_password: str = "", data: dict[str, str] | None = None
        ) -> tuple[int, Any]:
            parsed_path = urllib.parse.urlparse(url).path.removeprefix("/api/v1")
            live_calls.append((method, parsed_path))
            if method == "GET" and parsed_path == "/apps":
                return 200, {"apps": []}
            if method == "DELETE" and parsed_path == "/apps/cert-smoke":
                return 404, {"missing": True}
            if method == "POST" and parsed_path == "/apps/install":
                return 200, {"installed": True}
            if method == "GET" and parsed_path == "/apps/cert-smoke/runtime":
                return 500, {"error": "boom"}
            if method == "POST" and parsed_path == "/apps/cert-smoke/stop":
                return 200, {"stopped": True}
            return 200, {}

        globals()["http_request_json"] = fake_http_request_json
        try:
            live_failure_settings = dataclasses.replace(
                settings,
                live=True,
                live_base_url="http://127.0.0.1:8888",
                live_form_password="secret",
            )
            live_bundle_dir = sample_workspace(settings) / "cert-smoke-app"
            assert live_bundle_dir.is_dir(), live_bundle_dir
            live_failure_item = collect_live_evidence(live_failure_settings, {"bundleDir": live_bundle_dir})
        finally:
            globals()["http_request_json"] = original_http_request_json
        assert live_failure_item.status == "fail", live_failure_item
        cleanup_paths = [(step["method"], step["path"]) for step in live_failure_item.details["cleanupSteps"]]
        assert ("POST", "/apps/cert-smoke/stop") in cleanup_paths, live_failure_item
        assert ("DELETE", "/apps/cert-smoke") in cleanup_paths, live_failure_item
        assert live_calls[-2:] == cleanup_paths, live_calls

        live_success_calls: list[tuple[str, str]] = []

        def fake_success_http_request_json(
            method: str, url: str, form_password: str = "", data: dict[str, str] | None = None
        ) -> tuple[int, Any]:
            parsed_path = urllib.parse.urlparse(url).path.removeprefix("/api/v1")
            live_success_calls.append((method, parsed_path))
            if method == "GET" and parsed_path == "/apps":
                return 200, {"apps": []}
            if method == "GET" and parsed_path == "/diagnostics":
                return 200, {
                    "sectionCount": 2,
                    "plainTextExport": "Peer 198.51.100.10 operator-private-line",
                    "sections": [
                        {"title": "Node", "lines": ["operator-private-line"]},
                        {"title": "Peers", "lines": ["198.51.100.10"]},
                    ],
                    "legacyAdmin": {
                        "surfaces": [
                            {
                                "id": "queue",
                                "path": "/queue/",
                                "state": "PRIMARY_REPLACED",
                                "count": 3,
                                "replacementResponseCount": 2,
                                "blockedMutatingRequestCount": 1,
                                "fallbackRenderCount": 0,
                                "retainedOrPendingRenderCount": 0,
                            },
                            {
                                "id": "stats",
                                "path": "/stats/",
                                "state": "PENDING",
                                "count": 2,
                                "replacementResponseCount": 0,
                                "blockedMutatingRequestCount": 0,
                                "fallbackRenderCount": 0,
                                "retainedOrPendingRenderCount": 2,
                            },
                        ]
                    },
                }
            return 200, {"ok": True}

        globals()["http_request_json"] = fake_success_http_request_json
        try:
            live_success_item = collect_live_evidence(live_failure_settings, {"bundleDir": live_bundle_dir})
        finally:
            globals()["http_request_json"] = original_http_request_json
        assert live_success_item.status == "pass", live_success_item
        diagnostics_step = next(
            step for step in live_success_item.details["steps"] if step["path"] == "/diagnostics"
        )
        assert diagnostics_step["bodySummary"] == {
            "sectionCount": 2,
            "legacyAdminSurfaceCount": 2,
            "legacyAdminTotalCount": 5,
            "legacyAdminReplacementResponseTotal": 2,
            "legacyAdminBlockedMutatingRequestTotal": 1,
            "legacyAdminFallbackRenderTotal": 0,
            "legacyAdminRetainedOrPendingRenderTotal": 2,
        }, diagnostics_step
        assert "body" not in diagnostics_step, diagnostics_step
        live_success_encoded = json.dumps(live_success_item.to_json(), sort_keys=True)
        for forbidden in ("plainTextExport", "operator-private-line", "198.51.100.10", "sections"):
            assert forbidden not in live_success_encoded, live_success_encoded
        assert ("GET", "/diagnostics") in live_success_calls, live_success_calls

        external_out_dir = Path(temp_name) / "external-app-smoke"
        external_settings = dataclasses.replace(settings, out_dir=external_out_dir.resolve())
        external_summary, external_exit_code = run(external_settings)
        assert external_exit_code == 0, external_summary
        assert external_summary["summaryPath"].startswith("<workdir>/"), external_summary
        assert external_summary["reportPath"].startswith("<workdir>/"), external_summary
        assert (external_out_dir / SUMMARY_FILE_NAME).is_file(), external_summary
        assert str(external_out_dir) not in json.dumps(external_summary, sort_keys=True), external_summary


def make_self_test_workspace(workspace: Path) -> None:
    sdk = workspace / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    sdk.parent.mkdir(parents=True, exist_ok=True)
    sdk.write_text(
        "window.CryptaPlatform = { data: Object.freeze({ records: Object.freeze({ getJson(){}, putJson(){} }), "
        "export(){}, import(){} }), queue: { snapshot(){} }, trust: { score(){} }, "
        "services: Object.freeze({ list: listAppServices, get: getAppService, "
        "dependencies: Object.freeze({ list: listAppServiceDependencies, get: getAppServiceDependencies }), "
        "bundles: Object.freeze({ list: listAppServiceBundles, request: requestAppServiceBundle, "
        "approve: approveAppServiceBundle, reject: rejectAppServiceBundle, renew: renewAppServiceBundle }), "
        "grants: Object.freeze({ list: listAppServiceGrants, request: requestAppServiceGrant, "
        "revoke: revokeAppServiceGrant }), invoke: invokeAppService }), "
        "vault: { identities: { create(){}, list(){}, createProfileDocument(){}, "
        "createTrustStatement(){}, createSocialMessageDocument(){} } }, "
        "content: { insertAppDocument(){}, fetchText(){}, subscriptions: Object.freeze({ list(){}, create(){}, get(){}, refresh(){}, pause(){}, resume(){}, remove(){} }) } }; "
        "function putAppDataJson(){} function getAppDataJson(){} const appDataExportPath = 'app-data/export'; "
        "const appDataImportPath = 'app-data/import'; "
        "function trustStatus(){} function addTrustAnchor(){} function importTrustStatement(){} "
        "function importTrustUri(){} function trustAudit(){} function trustScore(){} "
        "function getTrustStatement(){} function deprecateTrustStatement(){} "
        "function revokeTrustStatement(){} function reactivateTrustStatement(){} "
        "function normalizeTrustLifecycleMutation(){} "
        "const trustStatementRoute = 'trust-graph/statements/'; const subscriptionId = 'sub-redacted'; "
        "function publishTrustStatement(){} function fetchAndImportTrustStatement(){} "
        "function createTrustSubscription(){} function normalizeSocialMessageDocument(){} "
        "function listAppServices(){} function getAppService(){} "
        "function listAppServiceDependencies(){} function getAppServiceDependencies(){} "
        "function listAppServiceBundles(){} function requestAppServiceBundle(){} "
        "function approveAppServiceBundle(){} function rejectAppServiceBundle(){} "
        "function renewAppServiceBundle(){} "
        "function listAppServiceGrants(){} function requestAppServiceGrant(){} "
        "function revokeAppServiceGrant(){} function invokeAppService(){} "
        "const socialMessageRoute = '/social-message'; "
        "function createContentSubscription(){} function removeContentSubscription(){} "
        "function contentSubscriptionPathSegment(){} const path = 'content/subscriptions'; "
        "function apiDeleteForm(){} "
        "const h = 'X-Crypta-App-Session';\n",
        encoding="utf-8",
    )
    design_dir = workspace / "platform-design-system/src/main/resources/network/crypta/platform/designsystem/static"
    design_dir.mkdir(parents=True, exist_ok=True)
    (design_dir / "crypta-ui-tokens.css").write_text(":root{--cr-space-4:1rem;}\n", encoding="utf-8")
    (design_dir / "crypta-ui.css").write_text(".cr-app{}.cr-shell{}.cr-button{}\n", encoding="utf-8")
    (design_dir / "crypta-ui-components.js").write_text('window.CryptaUi={version:"1"};\n', encoding="utf-8")
    for project, app_id, display_name, launcher, permissions, app_js in (
        (
            "queue-manager",
            "queue-manager",
            "Queue Manager",
            "queue-manager.sh",
            "queue.read,queue.write",
            "CryptaPlatform.bootstrap.load({ appId: 'queue-manager' });\n",
        ),
        (
            "publisher",
            "publisher",
            "Publisher",
            "publisher.sh",
            "queue.read,queue.write,content.insert",
            "CryptaPlatform.bootstrap.load({ appId: 'publisher' });\n",
        ),
        (
            "site-publisher",
            "site-publisher",
            "Site Publisher",
            "site-publisher.sh",
            "queue.read,queue.write,content.insert",
            "const appId = 'site-publisher';\n"
            "CryptaPlatform.bootstrap.load({ appId });\n"
            "CryptaPlatform.content.insertDirectory(new FormData());\n"
            "CryptaPlatform.content.insertFile(new FormData());\n"
            "CryptaPlatform.queue.snapshot({ page: 'uploads' });\n",
        ),
        (
            "profile-publisher",
            "profile-publisher",
            "Profile Publisher",
            "profile-publisher.sh",
            "queue.read,queue.write,content.insert.app-document,vault.identities.read,"
            "vault.identities.create,vault.identities.use,app.data.read,app.data.write",
            "const appId = 'profile-publisher';\n"
            "const identityId = 'profile-self-test';\n"
            "const maxRecentActions = 5;\n"
            "const maxProfileTextLength = 512; const maxProfileBioLength = 2048; const maxContentUriLength = 1024;\n"
            "function optionalProfileWebsite(value) { const website = String(value || '').trim(); "
            "return website.length > maxContentUriLength ? '' : website; }\n"
            "const draft = { website: optionalProfileWebsite('https://example.org') };\n"
            "const dataNamespace = \"profile-draft\";\n"
            "const dataStateKey = \"publisher-state\";\n"
            "const activeMarkup = ['srcdoc', 'iframe', 'base', 'svg']; const preview = { textContent: '' };\n"
            "CryptaPlatform.bootstrap.load({ appId });\n"
            "CryptaPlatform.data.records.getJson('profile-draft', 'publisher-state');\n"
            "CryptaPlatform.data.records.putJson({ namespace: 'profile-draft', key: 'publisher-state', "
            "schemaVersion: 1, value: { lastPublishedProfileUri: '', recentActions: [], selectedIdentityId: '' } });\n"
            "CryptaPlatform.api.postForm('app-vault/identities', { label: 'Profile' });\n"
            "CryptaPlatform.api.postForm(`app-vault/identities/${identityId}/profile-document`, { profile: 'redacted' });\n"
            "CryptaPlatform.api.postForm('queue/inserts/app-document', { document: 'redacted' });\n"
            "CryptaPlatform.queue.snapshot({ page: 'uploads' });\n",
        ),
        (
            "feed-reader",
            "feed-reader",
            "Feed Reader & Publisher",
            "feed-reader.sh",
            "content.fetch,content.subscribe,content.insert.app-document,queue.read,queue.write,"
            "app.data.read,app.data.write",
            "const appId = 'feed-reader';\n"
            "const maxSources = 12;\n"
            "const maxRememberedSnapshots = 12;\n"
            "function normalizedCryptaContentUri(uri) { return String(uri).startsWith('USK@') || String(uri).startsWith('crypta:USK@') ? uri : null; }\n"
            "const activeMarkup = ['srcdoc', 'iframe', 'base', 'svg']; const feedNode = { textContent: '' };\n"
            "const dataNamespace = \"ui-state\";\n"
            "const dataStateKey = \"reader-state\";\n"
            "CryptaPlatform.bootstrap.load({ appId });\n"
            "CryptaPlatform.data.records.getJson('ui-state', 'reader-state');\n"
            "CryptaPlatform.data.records.putJson({ namespace: 'ui-state', key: 'reader-state', "
            "schemaVersion: 2, value: { lastPublisherDraft: {}, selectedSourceId: '', fetchedSnapshots: [] } });\n"
            "CryptaPlatform.content.subscriptions.list();\n"
            "CryptaPlatform.content.subscriptions.create({ uri: 'USK@redacted/feed/0/feed.json', label: 'Feed' });\n"
            "CryptaPlatform.content.subscriptions.refresh('sub-redacted');\n"
            "CryptaPlatform.content.subscriptions.pause('sub-redacted');\n"
            "CryptaPlatform.content.subscriptions.resume('sub-redacted');\n"
            "CryptaPlatform.content.subscriptions.remove('sub-redacted');\n"
            "const lastSeenResolvedUri = 'USK@redacted/feed/0/feed.json';\n"
            "CryptaPlatform.feed.fetchSnapshot({ uri: 'CHK@redacted' });\n"
            "CryptaPlatform.content.fetchText({ uri: lastSeenResolvedUri });\n"
            "CryptaPlatform.feed.publishSnapshot({ snapshot: { type: 'crypta.feed.snapshot.v1', items: [] } });\n"
            "CryptaPlatform.queue.snapshot({ page: 'uploads' });\n",
        ),
        (
            "social-inbox",
            "social-inbox",
            "Social Inbox RC",
            "social-inbox.sh",
            "vault.identities.read,vault.identities.create,vault.identities.use,content.fetch,content.subscribe,"
            "content.insert.app-document,queue.read,queue.write,app.data.read,app.data.write,"
            "app.services.read,app.services.call",
            "const appId = 'social-inbox';\n"
            "const socialMessageType = 'crypta.social.message.v1';\n"
            "const socialOutboxType = 'crypta.social.outbox.v1';\n"
            "const maxSources = 16;\n"
            "const maxImportedMessages = 160;\n"
            "const maxDraftBodyLength = 4096; const maxImportedSubjectLength = 160; const maxAuthorLabelLength = 120; const maxImportedChannelLength = 64;\n"
            "const maxImportedBodyPreviewLength = 700;\n"
            "const maxReadStateEntries = 240;\n"
            "const maxFetchedDocumentChars = 131072;\n"
            "const maxThreadDepth = 12;\n"
            "const maxRenderedThreadMessages = 160;\n"
            "const maxSearchQueryLength = 80;\n"
            "function normalizedCryptaContentUri(uri) { return String(uri).startsWith('USK@') || String(uri).startsWith('crypta:USK@') ? uri : null; }\n"
            "const socialNode = { textContent: '' };\n"
            "const messageIdPattern = /^msg-[0-9a-f]{64}$/;\n"
            "const channelFilter = 'all'; const selectedChannel = 'general'; const searchQuery = 'subject authorFingerprint bodyPreview sourceLabel';\n"
            "function normalizeReplyReference(value) { return isSafeMessageId(value) ? value : ''; }\n"
            "function messageSortKey(message) { return `${message.createdAt}:${message.messageId}`; }\n"
            "function messageThreadRootId(message, byId) { const parent = normalizeReplyReference(message.replyTo); return parent && byId.get(parent) ? parent : message.messageId; }\n"
            "function threadSortKey(thread) { return `${thread.pinned}:${thread.latestCreatedAt}:${thread.rootId}`; }\n"
            "function threadUnreadCount(thread) { return thread.messages.filter((message) => !message.read).length; }\n"
            "function threadContainsMessage(thread, query) { return String(thread.subject + thread.authorLabel + thread.authorFingerprint + thread.channel + thread.bodyPreview + thread.sourceLabel).toLowerCase().includes(query); }\n"
            "function buildThreadIndex(messages, readState) { const byId = new Map(); const visiting = new Set(); const visited = new Set(); const cycleBreak = 'cycle detection'; return { byId, visiting, visited, cycleBreak, readState }; }\n"
            "function renderThreadList(threads) { socialNode.textContent = ''; socialNode.replaceChildren(...threads.slice(0, maxRenderedThreadMessages)); }\n"
            "function markThreadRead(thread) { boundedReadState(thread.messages.map((message) => message.messageId)); }\n"
            "function markThreadUnread(thread) { boundedReadState(thread.messages.map((message) => message.messageId)); }\n"
            "function archiveThread(thread) { thread.messages.forEach((message) => isSafeMessageId(message.messageId)); }\n"
            "function toggleThreadPin(thread) { thread.pinned = !thread.pinned; }\n"
            "function copyProfileUri(uri) { return optionalCryptaContentUri(uri); }\n"
            "function refreshAllSources() { return 'Refresh all active sources'; }\n"
            "const threadSourceSummary = { seenCount: 1, firstImportedAt: '2026-01-01T00:00:00Z', lastSeenAt: '2026-01-01T00:00:00Z', sourcesSeen: [{ sourceUriHash: 'redacted', sourceLabel: 'source' }] };\n"
            "function sourceSummariesForDedupe(message) { return message.sourcesSeen || [{ sourceUriHash: 'redacted' }]; }\n"
            "const lastCheckedAt = '2026-01-01T00:00:00Z'; const lastSeenEdition = 1;\n"
            "const records = { uiState: [\"ui-state\", \"social-inbox\"], sources: [\"social\", \"sources\"], "
            "outboxSummary: [\"social\", \"outbox-summary\"], importedMessageIndex: [\"social\", \"imported-message-index\"], "
            "readState: [\"social\", \"read-state\"], drafts: [\"social\", \"drafts\"] };\n"
            "const dataSchemaVersion = 1;\n"
            "CryptaPlatform.bootstrap.load({ appId });\n"
            "CryptaPlatform.vault.identities.list();\n"
            "CryptaPlatform.vault.identities.create({ label: 'Social' });\n"
            "CryptaPlatform.vault.identities.createProfileDocument('social-self-test', { displayName: 'Social' });\n"
            "CryptaPlatform.vault.identities.createSocialMessageDocument('social-self-test', { body: 'redacted' });\n"
            "function ensureSignedSocialMessage(value) { const signature = value.signature || {}; if (signature.domain !== socialMessageType) throw new Error(); }\n"
            "async function verifySocialMessageSignature(value) { const signature = value.signature || {}; const message = value.message || {}; if (signature.publicKeyFingerprint !== message.authorFingerprint) throw new Error(); const expected = await expectedSocialMessageId(message); if (message.messageId !== expected) throw new Error('Social message id does not match canonical payload.'); const publicKeyBytes = decodeBase64(signature.publicKeyBase64, 'publicKeyBase64'); const publicKeyFingerprint = await sha256Hex(publicKeyBytes); if (publicKeyFingerprint !== stringValue(signature.publicKeyFingerprint)) throw new Error(); return window.crypto.subtle.verify(); }\n"
            "function canonicalSocialMessagePayload(value) { return value; }\n"
            "function canonicalSocialMessageIdPayload(value) { return value; }\n"
            "async function expectedSocialMessageId(value) { return 'msg-' + await sha256Hex(canonicalSocialMessageIdPayload(value)); }\n"
            "function requireIsoTimestamp(value) { return value; }\n"
            "CryptaPlatform.content.insertAppDocument({ document: { type: socialOutboxType }, contentType: 'application/vnd.crypta.social.outbox+json', targetFilename: 'social-outbox.json' });\n"
            "CryptaPlatform.content.fetchText({ uri: 'USK@redacted/social/0/social-outbox.json', maxBytes: maxFetchedDocumentChars });\n"
            "CryptaPlatform.content.subscriptions.list();\n"
            "CryptaPlatform.content.subscriptions.create({ uri: 'USK@redacted/social/0/social-outbox.json' });\n"
            "CryptaPlatform.content.subscriptions.refresh('sub-redacted');\n"
            "CryptaPlatform.content.subscriptions.pause('sub-redacted');\n"
            "CryptaPlatform.content.subscriptions.resume('sub-redacted');\n"
            "CryptaPlatform.content.subscriptions.remove('sub-redacted');\n"
            "const lastSeenResolvedUri = 'USK@redacted/social/0/social-outbox.json'; const updateCount = 1; const lastError = '';\n"
            "function isSocialSourceUri(uri) { return uri.startsWith('USK@') || uri.startsWith('crypta:USK@'); }\n"
            "function parseJsonObject(value) { return JSON.parse(value); }\n"
            "function boundedDrafts(value) { return value; }\n"
            "function isSafeMessageId(value) { return messageIdPattern.test(value); }\n"
            "function boundedReadState(value) { return Object.create(null); }\n"
            "function optionalNumberField(value) { return 0; }\n"
            "function normalizeTrustScore(score) { const trustStatus = 'unknown'; const contributingEvidenceCount = 0; if ([\"trusted\", \"distrusted\", \"mixed\"].includes(trustStatus)) return { status: \"scored\" }; return { status: \"unscored\", summary: \"No local trust evidence.\" }; }\n"
            "function markTrustScoresUnavailable(summary) { return summary; }\n"
            "async function publishOutbox() { const summary = {}; await persistOutboxSummary(summary); }\n"
            "const bodySha256 = 'redacted'; const bodyPreview = 'redacted'; const signatureSha256 = 'redacted';\n"
            "const uriHash = 'redacted'; const uriSummary = 'USK source URI redacted'; "
            "const publicSourceUriHash = 'redacted'; const publicSourceUriSummary = 'redacted';\n"
            "const insertUriRedaction = 'redacted'; function redactedInsertUri(value) { return 'redacted'; }\n"
            "CryptaPlatform.data.records.getJson('ui-state', 'social-inbox');\n"
            "CryptaPlatform.data.records.putJson({ namespace: 'social', key: 'sources', schemaVersion: dataSchemaVersion, value: [] });\n"
            "const trustScoreProviderAppId = \"trust-graph\"; const trustScoreServiceId = \"trust.score\"; const trustScoreContext = \"message-author\";\n"
            "CryptaPlatform.services.get(trustScoreProviderAppId, trustScoreServiceId);\n"
            "CryptaPlatform.services.grants.list();\n"
            "CryptaPlatform.services.bundles.request({ bundleAlias: \"trust-annotations\", includeOptional: true, purpose: 'Annotate message authors.' });\n"
            "CryptaPlatform.services.invoke(trustScoreProviderAppId, trustScoreServiceId, { subjectKind: \"identity\", subjectUri: 'fingerprint', context: trustScoreContext, scope: 'score.read' });\n"
            "const authorLabel = 'author'; const authorFingerprint = 'fingerprint'; const profileUri = 'crypta:USK@redacted/profile/0/profile.json'; const trustGrantRequired = 'Trust score unavailable / grant required.'; const trustGrantRevoked = 'Trust score unavailable / grant revoked.'; const trustGrantExpired = 'Trust score unavailable / grant expired.'; const trustGrantRevalidation = 'Trust score unavailable / grant requires operator revalidation.'; const evidenceCount = 0;\n"
            "CryptaPlatform.queue.snapshot({ page: 'uploads' });\n"
            "const dataRecords = 'data.records'; const contentSubscriptions = 'content.subscriptions'; const serviceInvocation = 'services.invoke'; const trustScore = 'trust.score';\n",
        ),
        (
            "trust-graph",
            "trust-graph",
            "Trust Graph Local RC",
            "trust-graph.sh",
            "trust.read,trust.write,content.fetch,content.subscribe,content.insert.app-document,queue.read,queue.write,"
            "vault.identities.read,vault.identities.create,vault.identities.use,app.data.read,app.data.write",
            "const appId = 'trust-graph';\n"
            "const dataNamespace = \"ui-state\";\n"
            "const dataStateKey = \"preview-state\";\n"
            "CryptaPlatform.bootstrap.load({ appId });\n"
            "function normalizeImportSummary(value) { return value; }\n"
            "function publicationSummary(value) { return value; }\n"
            "function queueSnapshotSummary(value) { return value; }\n"
            "function redactedUri(value) { return value; }\n"
            "function renderQueue(snapshot) { publicationSummary(snapshot); queueSnapshotSummary(snapshot); }\n"
            "function renderAudit() {}\n"
            "function renderSubscriptions() {}\n"
            "const state = { recentImports: [], auditEvents: [], subscriptions: [], lastDraft: {} };\n"
            "CryptaPlatform.data.records.getJson('ui-state', 'preview-state');\n"
            "CryptaPlatform.data.records.putJson({ namespace: 'ui-state', key: 'preview-state', "
            "schemaVersion: 2, value: { lastDraft: {}, recentImports: [] } });\n"
            "CryptaPlatform.trust.status();\n"
            "CryptaPlatform.trust.anchors.list();\n"
            "CryptaPlatform.trust.importStatement({ document: '{}' });\n"
            "CryptaPlatform.trust.exchange.fetchAndImport({ uri: 'CHK@redacted' });\n"
            "CryptaPlatform.trust.audit.list({ limit: 12 });\n"
            "CryptaPlatform.trust.score({ subjectKind: 'profile', subjectUri: 'USK@redacted', context: 'profile' });\n"
            "CryptaPlatform.trust.statements.get('fingerprint');\n"
            "CryptaPlatform.trust.statements.deprecate('fingerprint', { reasonCode: 'local-policy' });\n"
            "CryptaPlatform.trust.statements.revoke('fingerprint', { reasonCode: 'local-policy' });\n"
            "CryptaPlatform.trust.statements.reactivate('fingerprint');\n"
            "const nonContributingReasons = ['revoked']; const evidenceTruncated = true;\n"
            "CryptaPlatform.trust.exchange.publish({ identityId: 'trust-self-test', subjectKind: 'profile', subjectUri: 'USK@redacted', context: 'profile', score: 50, confidence: 80, insertUri: 'USK@redacted', identifier: 'trust' });\n"
            "CryptaPlatform.trust.exchange.subscriptions.list();\n"
            "CryptaPlatform.trust.exchange.subscriptions.create({ uri: 'USK@redacted/trust/0/trust.json' });\n"
            "CryptaPlatform.trust.exchange.subscriptions.refresh('sub-redacted');\n"
            "CryptaPlatform.trust.exchange.subscriptions.pause('sub-redacted');\n"
            "CryptaPlatform.trust.exchange.subscriptions.resume('sub-redacted');\n"
            "CryptaPlatform.trust.exchange.subscriptions.remove('sub-redacted');\n"
            "lastDraft.publish = { authorIdentity: 'trust-self-test', subjectKind: 'profile', subjectIdentity: 'USK@redacted', value: 50, context: 'profile' };\n"
            "CryptaPlatform.queue.snapshot({ page: 'uploads' });\n",
        ),
    ):
        source = workspace / f"apps/{project}/src/staged"
        staged = workspace / f"apps/{project}/build/cryptad-app/{app_id}"
        for root in (source, staged):
            (root / "bin").mkdir(parents=True, exist_ok=True)
            (root / "static/crypta-ui").mkdir(parents=True, exist_ok=True)
            (root / "bin" / launcher).write_text("#!/usr/bin/env sh\nexit 0\n", encoding="utf-8")
            permission_items = "".join(f"<li><code>{permission}</code></li>" for permission in permissions.split(","))
            if app_id == "trust-graph":
                extra_ui = (
                    "<p>Trust Graph Local RC. Local trust only; it is not global truth, "
                    "not moderation, not blocking, not routing policy, no legacy WoT, and no network crawling.</p>"
                    "<p>Anchors and imported statements persist through the platform trust graph backend.</p>"
                    "<p>Exchange uses content fetch, insert, and subscription APIs.</p>"
                    "<p>Trust Score Service exposes trust.score through operator-approved app-service grants.</p>"
                    "<h2>Statement lifecycle</h2><h2>Subscriptions</h2><h2>Audit</h2><p>not global truth</p>"
                )
            elif app_id == "social-inbox":
                extra_ui = (
                    "<h2>Reference app scope</h2>"
                    "<p>This social/mail-like reference app runs outside the daemon.</p>"
                    "<p>It is not full WoT and is not Freetalk, Sone, Freemail, encrypted mail, "
                    "and does not add a daemon-core message store. It makes no network protocol change.</p>"
                    "<h2>Identity</h2><h2>Compose</h2><h2>Publish outbox</h2>"
                    "<h2>USK social sources</h2><h2>Sources and subscriptions</h2>"
                    "<h2>Threaded inbox</h2><label>All channels</label><input type=\"search\">"
                    "<button>Reply</button><button>Mark thread read</button>"
                    "<button>Refresh all active sources</button><div id=\"trust-service-status\"></div>"
                    "<button>Request trust grant</button><button>Refresh trust</button>"
                )
            else:
                extra_ui = ""
            (root / "static/index.html").write_text(
                "<!doctype html><html lang=\"en\"><head>"
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                f"<title>{display_name}</title>"
                "<link rel=\"stylesheet\" href=\"./crypta-ui/crypta-ui-tokens.css\">"
                "<link rel=\"stylesheet\" href=\"./crypta-ui/crypta-ui.css\">"
                "<link rel=\"stylesheet\" href=\"./app.css\">"
                "</head><body class=\"cr-app\"><main class=\"cr-shell\">"
                f"<section class=\"cr-permission-summary\" data-crypta-permission-summary><ul>{permission_items}</ul></section>"
                f"<h1>{display_name}</h1>"
                f"{extra_ui}"
                "</main><script src=\"./crypta-platform.js\"></script><script src=\"./app.js\"></script></body></html>",
                encoding="utf-8",
            )
            (root / "static/app.js").write_text(
                app_js,
                encoding="utf-8",
            )
            (root / "static/app.css").write_text("body { color: #111; }\n", encoding="utf-8")
            if app_id == "feed-reader":
                (root / "bin/migrate-feed-data.sh").write_text(
                    "#!/usr/bin/env sh\n"
                    "case \"$CRYPTA_APP_MIGRATION_MODE\" in dry-run|apply) ;; *) exit 64;; esac\n"
                    "test \"$CRYPTA_APP_MIGRATION_NAMESPACE\" = ui-state || exit 64\n"
                    "test \"$CRYPTA_APP_MIGRATION_FROM\" = 1 || exit 64\n"
                    "test \"$CRYPTA_APP_MIGRATION_TO\" = 2 || exit 64\n"
                    "test -n \"$CRYPTA_APP_MIGRATION_INPUT\" || exit 64\n"
                    "test -n \"$CRYPTA_APP_MIGRATION_OUTPUT\" || exit 64\n"
                    "printf '%s\\n' 'feed migration schema check complete'\n",
                    encoding="utf-8",
                )
            if app_id == "trust-graph":
                (root / "bin/migrate-preview-data.sh").write_text(
                    "#!/usr/bin/env sh\n"
                    "case \"$CRYPTA_APP_MIGRATION_MODE\" in dry-run|apply) ;; *) exit 64;; esac\n"
                    "test \"$CRYPTA_APP_MIGRATION_NAMESPACE\" = ui-state || exit 64\n"
                    "test \"$CRYPTA_APP_MIGRATION_FROM\" = 1 || exit 64\n"
                    "test \"$CRYPTA_APP_MIGRATION_TO\" = 2 || exit 64\n"
                    "test -n \"$CRYPTA_APP_MIGRATION_INPUT\" || exit 64\n"
                    "test -n \"$CRYPTA_APP_MIGRATION_OUTPUT\" || exit 64\n"
                    "printf '%s\\n' 'preview migration schema check complete'\n",
                    encoding="utf-8",
                )
            for asset_name in design_system_asset_names():
                shutil.copy2(design_dir / asset_name, root / "static/crypta-ui" / asset_name)
            shutil.copy2(sdk, root / "static/crypta-platform.js")
        is_profile_publisher = app_id == "profile-publisher"
        is_feed_reader = app_id == "feed-reader"
        is_social_inbox = app_id == "social-inbox"
        is_trust_graph = app_id == "trust-graph"
        api_minimum = (
            "16"
            if is_social_inbox
            else "10" if is_trust_graph else "9" if is_feed_reader or is_profile_publisher else "3"
        )
        api_maximum = (
            str(CURRENT_PLATFORM_API_CONTRACT_VERSION)
            if is_trust_graph
            or is_feed_reader
            or is_profile_publisher
            or is_social_inbox
            or app_id == "site-publisher"
            else "4"
        )
        experimental_accepted = "true" if is_profile_publisher or is_social_inbox or is_trust_graph else "false"
        service_lines: list[str] = []
        migration_lines: list[str] = []
        if is_social_inbox:
            service_lines = [
                "app.services.requests=trust-score",
                "app.service-request.trust-score.provider=trust-graph",
                "app.service-request.trust-score.service=trust.score",
                "app.service-request.trust-score.scopes=score.read",
                "app.service-request.trust-score.contexts=message-author",
                "app.service-request.trust-score.purpose=Annotate Social Inbox message authors using the local Trust Graph Local RC score service.",
                "app.service-request.trust-score.dependency.kind=optional",
                "app.service-request.trust-score.dependency.required=false",
                "app.service-request.trust-score.dependency.featureId=trust-score-annotations",
                "app.service-request.trust-score.dependency.featureName=Trust score annotations",
                "app.service-request.trust-score.dependency.reason=Annotates message authors with a local Trust Graph score when the operator approves the service bundle.",
                "app.service-request.trust-score.dependency.degradeBehavior=disable-feature",
                "app.service-request.trust-score.dependency.minServiceVersion=1",
                "app.service-request.trust-score.dependency.maxServiceVersion=1",
                "app.service-request.trust-score.dependency.grantBundle=trust-annotations",
                "app.service-request.trust-score.dependency.grantExpiresAfter=PT720H",
            ]
            migration_lines = [
                "app.data.schema.current=1",
                "app.data.schema.namespaces=ui-state,social",
                "app.data.schema.namespace.ui-state.current=1",
                "app.data.schema.namespace.social.current=1",
            ]
        elif is_trust_graph:
            service_lines = [
                "app.services.provides=trust-score",
                "app.service.trust-score.id=trust.score",
                "app.service.trust-score.name=Trust Score Service",
                "app.service.trust-score.version=1",
                "app.service.trust-score.kind=platform-adapter",
                "app.service.trust-score.adapter=trust-graph.score",
                "app.service.trust-score.scopes=score.read",
                "app.service.trust-score.contexts=message-author,profile",
                "app.service.trust-score.description=Returns a bounded local RC Trust Graph score summary for an app-provided public subject.",
            ]
            migration_lines = [
                "app.data.schema.current=2",
                "app.data.schema.namespaces=ui-state",
                "app.data.schema.namespace.ui-state.current=2",
                "app.data.migrations=ui-state-v1-v2",
                "app.data.migration.ui-state-v1-v2.namespace=ui-state",
                "app.data.migration.ui-state-v1-v2.from=1",
                "app.data.migration.ui-state-v1-v2.to=2",
                "app.data.migration.ui-state-v1-v2.command=bin/migrate-preview-data.sh",
                "app.data.migration.ui-state-v1-v2.rollbackCompatible=false",
                "app.data.migration.ui-state-v1-v2.requiresStopped=true",
                "app.data.migration.ui-state-v1-v2.description=Validate Trust Graph Local RC UI state schema v2.",
            ]
        elif is_feed_reader:
            migration_lines = [
                "app.data.schema.current=2",
                "app.data.schema.namespaces=ui-state",
                "app.data.schema.namespace.ui-state.current=2",
                "app.data.migrations=ui-state-v1-v2",
                "app.data.migration.ui-state-v1-v2.namespace=ui-state",
                "app.data.migration.ui-state-v1-v2.from=1",
                "app.data.migration.ui-state-v1-v2.to=2",
                "app.data.migration.ui-state-v1-v2.command=bin/migrate-feed-data.sh",
                "app.data.migration.ui-state-v1-v2.rollbackCompatible=false",
                "app.data.migration.ui-state-v1-v2.requiresStopped=true",
                "app.data.migration.ui-state-v1-v2.description=Validate Feed Reader UI state schema v2.",
            ]
        manifest_text = (
            "\n".join(
                [
                    "manifest.version=1",
                    f"app.id={app_id}",
                    f"app.name={display_name}",
                    "app.version=0.1.0",
                    f"api.minimumVersion={api_minimum}",
                    f"api.maximumTestedVersion={api_maximum}",
                    f"api.experimentalCapabilitiesAccepted={experimental_accepted}",
                    f"app.exec=bin/{launcher}",
                    "app.ui.mode=static",
                    "app.ui.entry=static/index.html",
                    f"app.permissions={permissions}",
                    *service_lines,
                    *migration_lines,
                    "quota.data.bytes=0",
                    "quota.cache.bytes=0",
                ]
            )
            + "\n"
        )
        (staged / "cryptad-app.properties").write_text(manifest_text, encoding="utf-8")
        (source / "cryptad-app.properties.template").write_text(
            manifest_text.replace("app.version=0.1.0", "app.version=${appVersion}"),
            encoding="utf-8",
        )
        if app_id == "site-publisher":
            (workspace / "apps/site-publisher/README.md").write_text(
                "Site Publisher is the first content reference app. "
                "Identity-backed publishing is future work.\n",
                encoding="utf-8",
            )
        if app_id == "profile-publisher":
            (workspace / "apps/profile-publisher/README.md").write_text(
                "Profile Publisher creates an app-owned identity, calls the "
                "profile-document route, persists bounded app-data draft state in AppVault-safe form, and inserts the signed app-document "
                "without storing raw signatures in release evidence. App-data backup scope includes profile drafts and publish summaries. "
                "Backups exclude vault private identity material and app-service tokens.\n",
                encoding="utf-8",
            )
        if app_id == "feed-reader":
            (workspace / "apps/feed-reader/README.md").write_text(
                "Feed Reader uses POST /api/v1/content/fetch through SDK feed helpers, "
                "uses durable content.subscribe metadata for USK subscriptions, "
                "uses app-data for bounded local reader state, "
                "then publishes generated feed summaries without storing raw feed bodies. "
                "App-data backup scope includes feed sources, selected subscriptions, read state, and safe drafts. "
                "Backups exclude vault private identity material and app-service tokens.\n",
                encoding="utf-8",
            )
        if app_id == "social-inbox":
            (workspace / "apps/social-inbox/README.md").write_text(
                "Social Inbox RC is a social/mail-like reference app outside daemon core. "
                "It uses AppVault identities, profile-document metadata, bounded crypta.social.message.v1 "
                "domain-separated signing, generated app-document outbox publication, content.subscribe "
                "USK source metadata, durable app-data records, a non-blocking schema-1 namespace contract, local message threads, "
                "bounded local search, channel filters, read state, and Trust Graph Preview annotations only. "
                "It is not a production social network, mail protocol, full WoT implementation, "
                "Freetalk/Sone/Freemail compatibility layer, not encrypted mail, daemon-core message store, "
                "or a network protocol change, and it avoids private insert URIs, browser-session tokens, "
                "raw fetched documents, and private identity material. App-data backup scope includes sources, summaries, drafts, and read state. "
                "Release evidence includes reference-app.social-inbox-rc-threading. "
                "Backups exclude vault private identity material and app-service tokens.\n",
                encoding="utf-8",
            )
        if app_id == "trust-graph":
            (workspace / "apps/trust-graph/README.md").write_text(
                "Trust Graph Local RC creates an app-owned trust identity, signs a trust-statement "
                "through AppVault, stores UI-local app-data draft summaries, imports local anchors, "
                "and is local trust only, not global truth, moderation, blocking, routing policy, or legacy WoT. "
                "App-data backup scope includes UI-local drafts, filters, and redacted import summaries. "
                "Backups exclude vault private identity material and app-service tokens.\n",
                encoding="utf-8",
            )
    adversarial_markup_test_text = "\n".join(PUBLIC_BETA_SECURITY_MARKUP_FIXTURES)
    feed_test_dir = workspace / "apps/feed-reader/src/test/java/network/crypta/apps/feedreader"
    feed_test_dir.mkdir(parents=True, exist_ok=True)
    (feed_test_dir / "FeedReaderBundleStagingTest.java").write_text(
        "class FeedReaderBundleStagingTest { String fixtures = "
        + repr(adversarial_markup_test_text)
        + "; String rendering = \"textContent innerHTML insertAdjacentHTML\"; }\n",
        encoding="utf-8",
    )
    social_test_dir = workspace / "apps/social-inbox/src/test/java/network/crypta/apps/socialinbox"
    social_test_dir.mkdir(parents=True, exist_ok=True)
    (social_test_dir / "SocialInboxBundleStagingTest.java").write_text(
        "class SocialInboxBundleStagingTest { String fixtures = "
        + repr(adversarial_markup_test_text)
        + "; String rendering = \"textContent innerHTML insertAdjacentHTML\"; }\n",
        encoding="utf-8",
    )
    profile_test_dir = workspace / "apps/profile-publisher/src/test/java/network/crypta/apps/profilepublisher"
    profile_test_dir.mkdir(parents=True, exist_ok=True)
    (profile_test_dir / "ProfilePublisherBundleStagingTest.java").write_text(
        "class ProfilePublisherBundleStagingTest { String rendering = \"textContent innerHTML insertAdjacentHTML\"; }\n",
        encoding="utf-8",
    )
    appcatalog_dir = workspace / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    appcatalog_dir.mkdir(parents=True, exist_ok=True)
    (appcatalog_dir / "AppReviewTransparencyRecord.java").write_text(
        "record AppReviewTransparencyRecord(String reviewerKeyId, String latestHash) { "
        "String privacy = \"record counts latest hashes no raw public key bytes no raw receipt signatures no local paths\"; }\n",
        encoding="utf-8",
    )
    (appcatalog_dir / "FileAppReviewTransparencyStore.java").write_text(
        "final class FileAppReviewTransparencyStore { String reviewTransparencyLog = \"local transparency log\"; }\n",
        encoding="utf-8",
    )
    (appcatalog_dir / "AppReviewTransparencyLog.java").write_text(
        "final class AppReviewTransparencyLog { String latestHash; String recordCount; }\n",
        encoding="utf-8",
    )
    appcatalog_test_dir = workspace / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog"
    appcatalog_test_dir.mkdir(parents=True, exist_ok=True)
    (appcatalog_test_dir / "AppReviewReceiptTest.java").write_text(
        "class AppReviewReceiptTest { "
        "void evaluate_whenReviewerKeyIsRevoked_expectRevokedReviewer() {} "
        "void evaluate_whenRetiredReviewerCoversReviewedAt_expectTrustedHistoricalReview() {} "
        "void evaluate_whenRetiredReviewerHasNoValidityEnd_expectRetiredReviewer() {} "
        "void evaluate_whenPolicyVersionDoesNotMatchReviewerConstraint_expectPolicyMismatch() {} "
        "void trustedReviewerKeysLoad_whenPolicyVersionOmitsPolicyId_expectInvalidCatalogEntry() {} "
        "void transparency_whenSummarized_expectNoRawPublicKeyBytesOrPaths() { String s = \"raw public key\"; } }\n",
        encoding="utf-8",
    )
    (appcatalog_dir / "RecommendedAppCatalog.java").write_text(
        "public record RecommendedAppCatalog(String trustedCatalogKeyId) { "
        "Object source = AppCatalogSource.parse(\"crypta:USK@example/cryptad-app-catalog.properties\"); }\n",
        encoding="utf-8",
    )
    (appcatalog_dir / "RecommendedAppCatalogs.java").write_text(
        "final class RecommendedAppCatalogs { static final String FIRST_PARTY_BETA_CATALOG_ID = "
        "\"crypta-first-party-beta\"; String env = \"CRYPTAD_FIRST_PARTY_CATALOG_SOURCE "
        "CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_CATALOG_KEY_ID\"; }\n",
        encoding="utf-8",
    )
    (appcatalog_dir / "AppCatalogChannel.java").write_text(
        'enum AppCatalogChannel { STABLE("stable"), BETA("beta"), NIGHTLY("nightly"), '
        'DEPRECATED("deprecated"); AppCatalogChannel(String value) {} }\n',
        encoding="utf-8",
    )
    (appcatalog_dir / "AppCatalogProductionMetadata.java").write_text(
        "record AppCatalogProductionMetadata() { "
        "static final String defaults = \"AppCatalogChannel.STABLE AppCatalogSupportStatus.SUPPORTED\"; "
        "boolean deprecatedForAutomaticUpdates(){ return true; } }\n",
        encoding="utf-8",
    )
    (appcatalog_dir / "AppCatalog.java").write_text(
        "final class AppCatalog { static final int VERSION_PRODUCTION_CHANNELS = 3; }\n",
        encoding="utf-8",
    )
    (appcatalog_dir / "AppCatalogParser.java").write_text(
        "final class AppCatalogParser { String fields = \"VERSION_PRODUCTION_CHANNELS = 3 "
        "maximumCryptaVersion securityAdvisory replacementAppId\"; }\n",
        encoding="utf-8",
    )
    (appcatalog_dir / "AppCatalogWriter.java").write_text(
        "final class AppCatalogWriter { String fields = \"VERSION_PRODUCTION_CHANNELS = 3 "
        "maximumCryptaVersion securityAdvisory replacementAppId\"; }\n",
        encoding="utf-8",
    )
    (appcatalog_dir / "AppCatalogEntryDescriptor.java").write_text(
        "record AppCatalogEntryDescriptor() { String fields = \"maximumCryptaVersion "
        "securityAdvisory replacementAppId\"; }\n",
        encoding="utf-8",
    )
    (appcatalog_dir / "AppCatalogSecurityAdvisory.java").write_text(
        "record AppCatalogSecurityAdvisory(String id, java.net.URI uri) { }\n",
        encoding="utf-8",
    )
    (appcatalog_dir / "AppCatalogSource.java").write_text(
        "final class AppCatalogSource { Object source = CryptaCatalogUri.parse(\"crypta:USK@example/cryptad-app-catalog.properties\"); }\n",
        encoding="utf-8",
    )
    (appcatalog_dir / "CryptaCatalogUri.java").write_text(
        "final class CryptaCatalogUri { String s = \"crypta:USK@ SIGNATURE_QUERY_PREFIX "
        "signatureFetchKeyForResolvedCatalog normalizeResolvedCatalogFetchKey "
        "requireCompatibleResolvedKeyKind siblingSignatureKey(resolvedKey)\"; }\n",
        encoding="utf-8",
    )
    (appcatalog_dir / "AppCatalogFetcher.java").write_text(
        "final class AppCatalogFetcher { String s = \"ContentFetchPort "
        "signatureFetchKeyForResolvedCatalog(catalogBytes.resolvedUri()) MAX_CATALOG_BYTES "
        "MAX_SIGNATURE_BYTES\"; }\n",
        encoding="utf-8",
    )
    (appcatalog_dir / "AppCatalogArtifactDownloader.java").write_text(
        "final class AppCatalogArtifactDownloader { ContentFetchPort port; "
        "void copyCryptaArtifact() { Object key = AppCatalogSidecars.cryptaArtifactFetchKey(null); } }\n",
        encoding="utf-8",
    )
    (appcatalog_dir / "AppCatalogManager.java").write_text(
        "final class AppCatalogManager { Object downloader = new AppCatalogArtifactDownloader(contentFetchPort); "
        "String s = \"AppCatalogVerifier.verify sourceStore.write(catalog, source, fetched "
        "CATALOG_ID_MISMATCH recordRefreshFailure previous stored sidecars remain in place\"; "
        "void verifyInstallPlan(AppCatalogInstallPlan plan) { bundleExtractor.verifyStagedBundle(plan.entry(), plan.stagedBundleDirectory(), trustedKeyProvider.trustedKeys()); } }\n",
        encoding="utf-8",
    )
    appcatalog_tests = workspace / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog"
    appcatalog_tests.mkdir(parents=True, exist_ok=True)
    (appcatalog_tests / "AppCatalogManagerTest.java").write_text(
        "void entry_whenArtifactUriIsCryptaChk_expectAccepted() {}\n"
        "void prepareInstallPlan_whenCryptaArtifactUsesContentFetchPort_expectVerifiedPlan() {}\n"
        "void verifyInstallPlan_whenStagedBundleTampered_expectInvalidAppBundle() {}\n"
        "void download_whenCryptaRuntimeIsUnavailable_expectArtifactFetchUnavailable() {}\n"
        "void fetch_whenCryptaCatalogResolvesToUskEdition_expectSignatureFetchedFromResolvedEdition() {}\n"
        "void fetch_whenCryptaResolvedCatalogHasSchemePrefix_expectSignatureFetchedFromResolvedEdition() {}\n"
        "void fetch_whenCryptaResolvedCatalogChangesKeyKind_expectInvalidCatalogSource() {}\n"
        "void fetch_whenCryptaSourceUsesContentFetchPort_expectBoundedRequests() {}\n"
        "void refresh_whenCryptaFetchFails_expectPreviousVerifiedCatalogPreservedAndMetadataUpdated() {}\n"
        "void refresh_whenCryptaVerificationFailsAfterResolvedFetch_expectMetadataUsesResolvedUri() {}\n",
        encoding="utf-8",
    )
    (appcatalog_tests / "AppCatalogParserTest.java").write_text(
        "void parse_whenCatalogHasProductionChannelMetadata_expectMetadataNormalized() {}\n"
        "void parse_whenVersionTwoCatalogOmitsProductionMetadata_expectStableDefaults() {}\n",
        encoding="utf-8",
    )
    (appcatalog_tests / "AppCatalogWriterTest.java").write_text(
        "void serialize_whenVersionTwoCatalogHasProductionMetadata_expectInvalidCatalogEntry() {}\n",
        encoding="utf-8",
    )
    (appcatalog_tests / "AppCatalogEntryDescriptorTest.java").write_text(
        "void parse_whenCatalogHasProductionChannelMetadata_expectMetadataNormalized() {}\n",
        encoding="utf-8",
    )
    (appcatalog_tests / "AppCatalogMetadataTest.java").write_text(
        "void productionMetadata_whenParsed_expectStableBetaNightlyDeprecated() {}\n",
        encoding="utf-8",
    )
    (appcatalog_tests / "RecommendedAppCatalogsTest.java").write_text(
        "// first-party beta fixture\n", encoding="utf-8"
    )
    appdist_dir = workspace / "platform-appdist/src/main/java/network/crypta/platform/appdist"
    appdist_dir.mkdir(parents=True, exist_ok=True)
    (appdist_dir / "AppDataSchemaContract.java").write_text(
        "public record AppDataSchemaContract(Integer currentSchemaVersion) { "
        "String fields = \"dataSchemaContract app.data.schema.current\"; }\n",
        encoding="utf-8",
    )
    (appdist_dir / "AppDataNamespaceSchema.java").write_text(
        "public record AppDataNamespaceSchema(String namespace, int currentSchemaVersion) { "
        "static String normalizeNamespace(String namespace) { return namespace; } }\n",
        encoding="utf-8",
    )
    (appdist_dir / "AppDataMigrationStep.java").write_text(
        "public record AppDataMigrationStep(String stepId, String namespace, int fromSchemaVersion, "
        "int toSchemaVersion) { AppDataMigrationStep { "
        "AppDataNamespaceSchema.normalizeNamespace(namespace); "
        "if (toSchemaVersion <= fromSchemaVersion) throw new IllegalArgumentException(); } }\n",
        encoding="utf-8",
    )
    (appdist_dir / "AppDataMigrationCommand.java").write_text(
        "public record AppDataMigrationCommand(String pathText) { "
        "static final Object WINDOWS_DRIVE_PREFIX_PATTERN = null; "
        "String error = \"must stay under the app root\"; }\n",
        encoding="utf-8",
    )
    (appdist_dir / "AppBundleManifestParser.java").write_text(
        "final class AppBundleManifestParser { String fields = \"app.data.schema.current "
        "app.data.migration. dataSchemaContract unsupported app.data manifest property "
        "app.data.migrations requires app.data.schema.current or app.data.schema.namespaces "
        "app.data migration target exceeds declared schema\"; }\n",
        encoding="utf-8",
    )
    (appdist_dir / "AppBundleStructureValidator.java").write_text(
        "final class AppBundleStructureValidator { void validate() { "
        "Object p = step.command().path(); Files.isRegularFile(p, NOFOLLOW_LINKS); "
        "} }\n",
        encoding="utf-8",
    )
    appdist_test_dir = workspace / "platform-appdist/src/test/java/network/crypta/platform/appdist"
    appdist_test_dir.mkdir(parents=True, exist_ok=True)
    (appdist_test_dir / "AppBundleManifestParserTest.java").write_text(
        "class AppBundleManifestParserTest { "
        "void parse_whenAppDataMigrationContractPresent_expectContractParsed() {} "
        "void parseContent_whenMigrationDeclaresNoTargetSchema_expectFailure() {} "
        "void parseContent_whenGlobalMigrationTargetExceedsSchema_expectFailure() {} "
        "void parseContent_whenMigrationCommandEscapesBundle_expectFailure() {} "
        "void parseContent_whenMigrationFieldIsUnknown_expectFailure() {} }\n",
        encoding="utf-8",
    )
    (appdist_test_dir / "AppBundleStructureValidatorTest.java").write_text(
        "class AppBundleStructureValidatorTest { "
        "void validate_whenMigrationCommandIsRegularNonExecutableFile_expectAccepted() {} }\n",
        encoding="utf-8",
    )
    apphost_manifest_dir = workspace / "platform-apphost/src/main/java/network/crypta/platform/apphost/manifest"
    apphost_manifest_dir.mkdir(parents=True, exist_ok=True)
    (apphost_manifest_dir / "AppManifest.java").write_text(
        "record AppManifest(Object dataSchemaContract) {}\n", encoding="utf-8"
    )
    (apphost_manifest_dir / "AppManifestParser.java").write_text(
        "final class AppManifestParser { String s = \"manifest.dataSchemaContract()\"; }\n",
        encoding="utf-8",
    )
    api_dir = workspace / "platform-api/src/main/java/network/crypta/platform/api"
    catalog_api_dir = api_dir / "appcatalogs"
    catalog_api_dir.mkdir(parents=True, exist_ok=True)
    (catalog_api_dir / "AppCatalogsApiHandler.java").write_text(
        "final class AppCatalogsApiHandler { void listRecommendedCatalogs() {} void addRecommended() {} "
        "void summarize() { json.put(\"channel\", channel); json.put(\"supportStatus\", supportStatus); "
        "json.put(\"securityAdvisories\", securityAdvisories); json.put(\"defaultEntryChannel\", \"stable\"); "
        "json.put(\"allowedChannels\", allowedChannels); } "
        "String e = \"recommended_catalog_trusted_key_missing\"; }\n",
        encoding="utf-8",
    )
    (api_dir / "PlatformApiAppRoutes.java").write_text(
        "final class PlatformApiAppRoutes { void routeRecommendedAppCatalogs() {} "
        "void routeRecommendedAppCatalogAddOrApp() {} boolean refresh = \"refresh\".equals(action); }\n",
        encoding="utf-8",
    )
    (api_dir / "PlatformApiContract.java").write_text(
        "final class PlatformApiContract { static final int CURRENT_CONTRACT_VERSION = 16; "
        "static final int TRUST_GRAPH_PREVIEW_CONTRACT_VERSION = 7; "
        "static final int TRUST_GRAPH_EXCHANGE_CONTRACT_VERSION = 10; "
        "static final int TRUST_GRAPH_RC_SCOPE_CONTRACT_VERSION = 15; "
        "static final int SOCIAL_MESSAGE_CONTRACT_VERSION = 11; "
        "static final int CONTENT_SUBSCRIPTIONS_CONTRACT_VERSION = 8; "
        "static final int APP_DATA_STORE_CONTRACT_VERSION = 9; "
        "static final int APP_SERVICES_CONTRACT_VERSION = 12; "
        "static final int APP_SERVICE_DEPENDENCY_BUNDLES_CONTRACT_VERSION = 16; "
        "static final int PRODUCTION_CATALOG_CHANNELS_CONTRACT_VERSION = 13; "
        "String list = \"/app-catalogs/recommended\"; "
        "String add = \"/app-catalogs/recommended/{catalogId}/add\"; "
        "String refresh = \"/app-catalogs/{catalogId}/refresh\"; "
        "String listAction = \"catalogs.recommended.list\"; "
        "String addAction = \"catalogs.recommended.add\"; "
        "String profileDocument = \"/app-vault/identities/{identityId}/profile-document\"; "
        "String profileAction = \"app-vault.identities.profile-document\"; "
        "String profileReadCapability = \"VAULT_IDENTITIES_READ\"; "
        "String profileUseCapability = \"VAULT_IDENTITIES_USE\"; "
        "String createIdentity = \"/app-vault/identities\"; "
        "boolean browserSafeCreate = true; "
        "String generatedDocument = \"/queue/inserts/app-document\"; "
        "String generatedAction = \"queue.inserts.app-document\"; "
        "String contentCapability = \"CONTENT_INSERT_APP_DOCUMENT\"; "
        "String queueCapability = \"QUEUE_WRITE\"; "
        "String contentFetch = \"/content/fetch\"; "
        "String contentFetchCapability = \"CONTENT_FETCH\"; "
        "String CONTENT_FETCH = \"CONTENT_FETCH\"; "
        "String CONTENT_SUBSCRIBE = \"CONTENT_SUBSCRIBE\"; "
        "String contentSubscribe = \"content.subscribe\"; "
        "String contentSubscriptionSince = \"sinceContractVersion = 8\"; "
        "String subscriptionList = \"/content/subscriptions\"; "
        "String subscriptionRead = \"/content/subscriptions/{subscriptionId}\"; "
        "String subscriptionRefresh = \"/content/subscriptions/{subscriptionId}/refresh\"; "
        "String subscriptionPause = \"/content/subscriptions/{subscriptionId}/pause\"; "
        "String subscriptionResume = \"/content/subscriptions/{subscriptionId}/resume\"; "
        "String subscriptionCreateAction = \"content.subscriptions.create\"; "
        "String subscriptionRefreshAction = \"content.subscriptions.refresh\"; "
        "String subscriptionDeleteAction = \"content.subscriptions.delete\"; "
        "String appDataRead = \"app.data.read\"; "
        "String appDataWrite = \"app.data.write\"; "
        "String appDataStatus = \"/app-data/status\"; "
        "String appDataNamespaces = \"/app-data/namespaces\"; "
        "String appDataNamespace = \"/app-data/namespaces/{namespace}\"; "
        "String appDataSchema = \"/app-data/namespaces/{namespace}/schema\"; "
        "String appDataRecords = \"/app-data/records\"; "
        "String appDataRecord = \"/app-data/records/{namespace}/{key}\"; "
        "String appDataExport = \"/app-data/export\"; "
        "String appDataImport = \"/app-data/import\"; "
        "String trustStatus = \"/trust-graph/status\"; "
        "String trustAnchors = \"/trust-graph/anchors\"; "
        "String trustImport = \"/trust-graph/import\"; "
        "String trustImportUri = \"/trust-graph/import-uri\"; "
        "String trustAudit = \"/trust-graph/audit\"; "
        "String trustSubjects = \"/trust-graph/subjects\"; "
        "String trustStatements = \"/trust-graph/statements\"; "
        "String trustStatement = \"/trust-graph/statements/{fingerprint}\"; "
        "String trustDeprecate = \"/trust-graph/statements/{fingerprint}/deprecate\"; "
        "String trustRevoke = \"/trust-graph/statements/{fingerprint}/revoke\"; "
        "String trustReactivate = \"/trust-graph/statements/{fingerprint}/reactivate\"; "
        "String trustScore = \"/trust-graph/score\"; "
        "String trustRead = \"PlatformApiCapabilities.TRUST_READ\"; "
        "String trustWrite = \"PlatformApiCapabilities.TRUST_WRITE\"; "
        "String trustFetch = \"PlatformApiCapabilities.CONTENT_FETCH\"; "
        "String trustStatement = \"/app-vault/identities/{identityId}/trust-statement\"; "
        "String trustStatementAction = \"app-vault.identities.trust-statement\"; "
        "String socialMessage = \"/app-vault/identities/{identityId}/social-message\"; "
        "String socialMessageAction = \"app-vault.identities.social-message\"; "
        "String appServices = \"/app-services\"; "
        "String appServicesAudit = \"/app-services/audit\"; "
        "String appServicesDependencies = \"/app-services/dependencies\"; "
        "String appServicesConsumerDependencies = \"/app-services/dependencies/consumers/{consumerAppId}\"; "
        "String appServicesGrantBundles = \"/app-services/grant-bundles\"; "
        "String appServicesGrantBundleApprove = \"/app-services/grant-bundles/{bundleId}/approve\"; "
        "String appServicesGrantBundleReject = \"/app-services/grant-bundles/{bundleId}/reject\"; "
        "String appServicesGrantBundleRenew = \"/app-services/grant-bundles/{bundleId}/renew\"; "
        "String appServicesGrants = \"/app-services/grants\"; "
        "String appServicesApprove = \"/app-services/grants/{grantId}/approve\"; "
        "String appServicesRevoke = \"/app-services/grants/{grantId}/revoke\"; "
        "String appServicesProvider = \"/app-services/{providerAppId}/services\"; "
        "String appServicesDescriptor = \"/app-services/{providerAppId}/services/{serviceId}\"; "
        "String appServicesInvoke = \"/app-services/{providerAppId}/services/{serviceId}/invoke\"; "
        "String appServicesRead = \"app.services.read\"; "
        "String appServicesCall = \"app.services.call\"; "
        "String vaultRead = \"PlatformApiCapabilities.VAULT_IDENTITIES_READ\"; "
        "String vaultUse = \"PlatformApiCapabilities.VAULT_IDENTITIES_USE\"; }\n",
        encoding="utf-8",
    )
    (api_dir / "PlatformApiCapabilities.java").write_text(
        "final class PlatformApiCapabilities { static final String TRUST_READ = \"trust.read\"; "
        "static final String TRUST_WRITE = \"trust.write\"; "
        "static final String CONTENT_FETCH = \"content.fetch\"; "
        "static final String CONTENT_SUBSCRIBE = \"content.subscribe\"; "
        "static final String APP_DATA_READ = \"app.data.read\"; "
        "static final String APP_DATA_WRITE = \"app.data.write\"; "
        "static final String APP_SERVICES_READ = \"app.services.read\"; "
        "static final String APP_SERVICES_CALL = \"app.services.call\"; }\n",
        encoding="utf-8",
    )
    (api_dir / "PlatformApiRouter.java").write_text(
        "final class PlatformApiRouter { String a = \"/trust-graph/status\"; "
        "String b = \"/trust-graph/anchors\"; String c = \"/trust-graph/import\"; "
        "String d = \"/trust-graph/subjects\"; String e = \"/trust-graph/statements\"; "
        "String f = \"/trust-graph/score\"; String g = \"/trust-graph/import-uri\"; "
        "Object audit = envelope(\"audit\"); void importUri() {} "
        "void routeContentSubscriptionsRequest() { requireAppPrincipalId(request); "
        "requireAllCapabilities(ContentSubscriptionService.CAPABILITY_CONTENT_SUBSCRIBE, "
        "ContentSubscriptionService.CAPABILITY_CONTENT_FETCH); "
        "Object h = new ContentSubscriptionsApiHandler(); "
        "String unavailable = \"content_subscription_service_unavailable 503\"; } "
        "PlatformApiAppDataRoutes appDataRoutes; "
        "PlatformApiAppServiceRoutes appServiceRoutes; String route = \"app-services\"; "
        "// case \"app-services\" "
        "Object app = appServiceRoutes.route(null, null); }\n",
        encoding="utf-8",
    )
    (api_dir / "PlatformApiTrustGraphRoutes.java").write_text(
        "final class PlatformApiTrustGraphRoutes { Object routeNestedResourceAction; "
        "String routes = \"statements deprecate revoke reactivate\"; }\n",
        encoding="utf-8",
    )
    (api_dir / "PlatformApiSharedAppServices.java").write_text(
        "record PlatformApiSharedAppServices(TrustGraphApiHandler trustGraphApiHandler, "
        "AppServiceCoordinator appServiceCoordinator) {}\n",
        encoding="utf-8",
    )
    (api_dir / "PlatformApiAppServiceRoutes.java").write_text(
        "final class PlatformApiAppServiceRoutes { // Routes local app-service discovery\n"
        "Object route(Object segments, Object request) { return service.listServices(); } "
        "Object dependencies() { return service.dependencyGraph(null); } "
        "Object bundles() { approveBundle(); rejectBundle(); renewBundle(); return null; } "
        "void approveBundle() {} void rejectBundle() {} void renewBundle() {} }\n",
        encoding="utf-8",
    )
    appservices_dir = api_dir / "appservices"
    appservices_dir.mkdir(parents=True, exist_ok=True)
    (appservices_dir / "AppServiceDescriptor.java").write_text(
        "public record AppServiceDescriptor(String providerAppId, String serviceId) { "
        "String compatibilityFingerprint() { return \"fp\"; } "
        "boolean satisfiesVersionRange(Object range) { return true; } "
        "boolean hasUnsupportedScopes(Object scopes) { return false; } "
        "boolean supportsContext(String context) { return true; } }\n",
        encoding="utf-8",
    )
    (appservices_dir / "AppServiceRequestDescriptor.java").write_text(
        "public record AppServiceRequestDescriptor(String consumerAppId, String serviceId) {}\n",
        encoding="utf-8",
    )
    (appservices_dir / "AppServiceDependencyDescriptor.java").write_text(
        "record AppServiceDependencyDescriptor(String featureId) {}\n",
        encoding="utf-8",
    )
    (appservices_dir / "AppServiceDependencyKind.java").write_text(
        "enum AppServiceDependencyKind { REQUIRED, OPTIONAL }\n",
        encoding="utf-8",
    )
    (appservices_dir / "AppServiceDegradeBehavior.java").write_text(
        "enum AppServiceDegradeBehavior { DISABLE_FEATURE, WARN_ONLY, BLOCK_APP_START, BLOCK_UPDATE }\n",
        encoding="utf-8",
    )
    (appservices_dir / "AppServiceVersionRange.java").write_text(
        "record AppServiceVersionRange(String min, String max) {}\n",
        encoding="utf-8",
    )
    (appservices_dir / "AppServiceGrantBundle.java").write_text(
        "record AppServiceGrantBundle(String bundleId) { "
        "// Bundle docs may mention tokens and local paths while fields stay safe. "
        "void toJson(java.util.Map<String,Object> json) { json.put(\"bundleId\", bundleId); } }\n",
        encoding="utf-8",
    )
    (appservices_dir / "AppServiceGrantBundleStatus.java").write_text(
        "enum AppServiceGrantBundleStatus { PENDING, APPROVED, REJECTED, EXPIRED, REVALIDATION_REQUIRED }\n",
        encoding="utf-8",
    )
    (appservices_dir / "AppServiceManifestParser.java").write_text(
        "final class AppServiceManifestParser { String provides = \"app.services.provides\"; "
        "String requests = \"app.service-request.\"; "
        "String dependencyPrefix = \"app.service-request.\" + \"alias\" + \".dependency.\"; "
        "String min = dependencyPrefix + \"minServiceVersion\"; "
        "String max = dependencyPrefix + \"maxServiceVersion\"; "
        "String duration = dependencyPrefix + \"grantExpiresAfter\"; "
        "String duplicate = \"duplicate alias\"; "
        "String pathError = \"Field value must not contain local filesystem paths\"; }\n",
        encoding="utf-8",
    )
    (appservices_dir / "AppServiceGrant.java").write_text(
        "record AppServiceGrant(String grantId, String consumerAppId, String providerAppId, "
        "String serviceId, String scopes, String contexts, String purpose, String approvedAt, "
        "String revokedAt, String lastUsedAt, long useCount, String tokenFingerprint, "
        "String bundleId, String expiresAt, String renewedAt, String compatibilityFingerprint, "
        "String providerServiceVersionAtApproval) { "
        "// PR-243 does not issue raw service tokens\n"
        "String noRawToken = \"fingerprint only\"; }\n",
        encoding="utf-8",
    )
    (appservices_dir / "AppServiceGrantStatus.java").write_text(
        "enum AppServiceGrantStatus { PENDING, ACTIVE, REVOKED, INACTIVE, EXPIRED, "
        "REVALIDATION_REQUIRED; String wire = \"revalidation-required\"; }\n",
        encoding="utf-8",
    )
    (appservices_dir / "AppServiceAuditEvent.java").write_text(
        "record AppServiceAuditEvent(String subjectUriHash) { "
        "// omits raw subject URIs, raw tokens, and local paths\n"
        "}\n",
        encoding="utf-8",
    )
    (appservices_dir / "AppServiceGrantStore.java").write_text(
        "interface AppServiceGrantStore { void listBundles(); void writeBundle(); }\n",
        encoding="utf-8",
    )
    (appservices_dir / "FileAppServiceGrantStore.java").write_text(
        "class FileAppServiceGrantStore implements AppServiceGrantStore { "
        "String a = \"ATOMIC_MOVE\"; String b = \"grants\"; String c = \"audit\"; "
        "String d = \"bundles\"; public void listBundles(){} public void writeBundle(){} }\n",
        encoding="utf-8",
    )
    (appservices_dir / "InMemoryAppServiceGrantStore.java").write_text(
        "class InMemoryAppServiceGrantStore implements AppServiceGrantStore { "
        "public void listBundles(){} public void writeBundle(){} }\n",
        encoding="utf-8",
    )
    (appservices_dir / "AppServiceCoordinator.java").write_text(
        "class AppServiceCoordinator { void requestGrant(){} void approveGrant(){} void revokeGrant(){} "
        "void dependencyGraph(){} void requestBundle(){} void approveBundle(){} void rejectBundle(){} "
        "void renewBundle(){} void approveOrRenewBundle(){} void ensureDescriptorSupported(){} "
        "boolean isExpired(){ return false; } boolean approvalMetadataStillMatches(){ return false; } "
        "static final String SUPPORTED_SERVICE_KIND = \"platform-adapter\"; "
        "static final Object MAX_BUNDLE_GRANT_DURATION = null; "
        "Object descriptor = null; Object adapters = null; "
        "String fp = \"descriptor.compatibilityFingerprint() adapters.containsKey\"; "
        "String dependencyJson = \"dependencyJson providerServiceVersion request bodies\"; "
        "String a = \"App principals cannot approve app-service grants.\"; "
        "String c = \"App principals cannot approve app-service grant bundles.\"; "
        "String d = \"App principals cannot reject app-service grant bundles.\"; "
        "String e = \"App principals cannot renew app-service grant bundles.\"; "
        "String f = \"effectiveStatus(grant) == AppServiceGrantStatus.ACTIVE\"; "
        "String g = \"AppServiceGrantStatus.EXPIRED\"; "
        "String b = \"active app-service grant\"; }\n",
        encoding="utf-8",
    )
    (appservices_dir / "TrustGraphScoreAppServiceAdapter.java").write_text(
        "class TrustGraphScoreAppServiceAdapter { static final String ADAPTER_ID = \"trust-graph.score\"; "
        "// not a proxy; invokes TrustGraphApiHandler#score for score.read only\n"
        "void invoke(){ trustGraphApiHandler.score(null); json.put(\"subjectUriHash\", \"sha256:redacted\"); "
        "Object redactedScore; String scope = \"score.read\"; String completeWot = \"completeWot\"; } }\n",
        encoding="utf-8",
    )
    api_test_dir = workspace / "platform-api/src/test/java/network/crypta/platform/api"
    api_test_dir.mkdir(parents=True, exist_ok=True)
    app_vault_test_dir = api_test_dir / "appvault"
    app_vault_test_dir.mkdir(parents=True, exist_ok=True)
    (app_vault_test_dir / "SocialMessageRequestTest.java").write_text(
        "class SocialMessageRequestTest { String purpose = \"purpose\"; "
        "String payloadBase64 = \"payloadBase64\"; String type = \"crypta.social.message.v1\"; }\n",
        encoding="utf-8",
    )
    (app_vault_test_dir / "SignedSocialMessageDocumentBuilderTest.java").write_text(
        "class SignedSocialMessageDocumentBuilderTest { String domainSeparatedPayload; "
        "String privateKey; }\n",
        encoding="utf-8",
    )
    (api_test_dir / "AppVaultApiRouterTest.java").write_text(
        "class AppVaultApiRouterTest { String route = \"social-message\"; "
        "String domain = \"crypta.social.message.v1\"; String privateKey; String payloadBase64; "
        "String trustHardening = \"token=secret unsupported parameter\"; }\n",
        encoding="utf-8",
    )
    (api_test_dir / "PlatformApiCapabilitiesTest.java").write_text(
        "final class PlatformApiCapabilitiesTest { String a = \"trust-graph/import-uri content.fetch\"; "
        "String b = \"trust-graph/audit trust.read\"; String c = \"social-message vault.identities.use\"; }\n",
        encoding="utf-8",
    )
    appservices_test_dir = api_test_dir / "appservices"
    appservices_test_dir.mkdir(parents=True, exist_ok=True)
    (appservices_test_dir / "AppServiceManifestParserTest.java").write_text(
        "class AppServiceManifestParserTest { "
        "void parseProvidedServices_whenManifestDeclaresTrustScore_expectDescriptor() {} "
        "void parseServiceRequests_whenOptionalDependencyFieldsPresent_expectDependencyDescriptor() {} "
        "void parseServiceRequests_whenRequiredDependencyFieldsPresent_expectRequiredDescriptor() {} }\n",
        encoding="utf-8",
    )
    (appservices_test_dir / "AppServiceGrantStoreTest.java").write_text(
        "class AppServiceGrantStoreTest { "
        "void fileStore_whenGrantsReload_expectDeterministicOrderingAndRedactedJson() {} "
        "void fileStore_whenBundleAndGrantLifecycleFieldsReload_expectDeterministicRecords() {} "
        "void fileStore_whenAuditEventsReload_expectNewestFirstAndRedactedSubjectHash() {} }\n",
        encoding="utf-8",
    )
    (appservices_test_dir / "AppServiceCoordinatorTest.java").write_text(
        "class AppServiceCoordinatorTest { "
        "void grantLifecycle_whenApprovedThenRevoked_expectInvocationBoundary() {} "
        "void invoke_whenConsumerManifestDropsCallPermission_expectDenied() {} "
        "void requestGrant_whenProviderNotInstalled_expectProviderMissing() {} "
        "void dependencyGraph_whenProviderAvailable_expectSocialInboxTrustGraphEdge() {} "
        "void dependencyGraph_whenAppReadsOtherConsumer_expectForbidden() {} "
        "void grantBundleLifecycle_whenApprovedExpiredAndRenewed_expectInvocationBoundary() {} "
        "void approveBundle_whenRejected_expectNoActiveGrantCreated() {} "
        "void invoke_whenProviderDescriptorDriftsAfterBundleApproval_expectRevalidationRequired() {} }\n",
        encoding="utf-8",
    )
    (appservices_test_dir / "TrustGraphScoreAppServiceAdapterTest.java").write_text(
        "class TrustGraphScoreAppServiceAdapterTest { "
        "void invoke_whenScoreRequested_expectRedactedScoreSummary() { String subjectUriHash; } }\n",
        encoding="utf-8",
    )
    (api_test_dir / "PlatformApiAppServicesRouterTest.java").write_text(
        "class PlatformApiAppServicesRouterTest { "
        "void route_whenAppUsesDiscoveryGrantAndInvocation_expectGrantBoundary() {} "
        "void route_whenAppUsesDependencyAndBundleRoutes_expectScopedReviewFlow() {} }\n",
        encoding="utf-8",
    )
    (api_test_dir / "TrustGraphApiRouterTest.java").write_text(
        "final class TrustGraphApiRouterTest { void route_whenImportUriHasContentFetchCapability() {} "
        "void route_whenAuditReadAfterImport() { String summary = \"uri:redacted token=secret\"; } "
        "void route_whenWriterRevokesImportedStatement_expectLifecycleVisibleAndReimportDoesNotErase() {} "
        "void route_whenReaderAttemptsLifecycleMutation_expectForbiddenBeforeHandler() {} }\n",
        encoding="utf-8",
    )
    sdk_test_dir = workspace / "platform-sdk-js/src/test/java/network/crypta/platform/sdk/js"
    sdk_test_dir.mkdir(parents=True, exist_ok=True)
    (sdk_test_dir / "CryptaPlatformSdkResourceTest.java").write_text(
        "final class CryptaPlatformSdkResourceTest { "
        "void classpathResource_whenTrustExchangeHelpersRequested() {} "
        "void classpathResource_whenTrustExchangePublishSignsStatement() {} "
        "void classpathResource_whenSocialMessageSigned_expectBoundedVaultRoute() { "
        "String route = \"/social-message\"; String recipientFingerprint; } }\n",
        encoding="utf-8",
    )
    bridge_dir = workspace / "bridge-http-runtime/src/main/java/network/crypta/clients/http/bridge"
    bridge_dir.mkdir(parents=True, exist_ok=True)
    (bridge_dir / "CoreHttpShellRuntimeSupport.java").write_text(
        "final class CoreHttpShellRuntimeSupport { void create() { "
        "Object handler = new TrustGraphApiHandler(new FileTrustGraphStore("
        "layout.dataDir().resolve(\"apps\").resolve(\"trust-graph\"))); "
        "Object appServices = new AppServiceCoordinator(layout.dataDir().resolve(\"apps\").resolve(\"app-services\"), "
        "new TrustGraphScoreAppServiceAdapter(handler)); } }\n",
        encoding="utf-8",
    )
    appdata_api_dir = api_dir / "appdata"
    appdata_api_dir.mkdir(parents=True, exist_ok=True)
    (api_dir / "PlatformApiAppDataRoutes.java").write_text(
        "final class PlatformApiAppDataRoutes { String appId = requireAppPrincipalId(request); "
        "String route = \"app-data\"; }\n",
        encoding="utf-8",
    )
    (appdata_api_dir / "AppDataService.java").write_text(
        "final class AppDataService { static final String CAPABILITY_APP_DATA_READ = \"app.data.read\"; "
        "static final String CAPABILITY_APP_DATA_WRITE = \"app.data.write\"; "
        "boolean storeUsageOutsideAppDataDir; "
        "AppDataBackupRestoreWorkflow backupRestoreWorkflow; "
        "Object exportBackup(AppDataBackupOptions options, String sourceCryptaVersion) { return backupRestoreWorkflow.exportBackup(options, sourceCryptaVersion); } "
        "Object listStoreAppIds() { return store.listAppIds(); } "
        "Object planRestore(byte[] payload, AppDataRestoreMode mode, String appId) { preflightImport(null); preflightReplaceApp(null); return null; } "
        "Object restoreBackup(byte[] payload, AppDataRestoreMode mode, String appId) { replaceImportedNamespaces(null); replaceAppData(appId); return null; } "
        "void preflightImport(Object payload) {} void preflightReplaceApp(Object payload) {} "
        "void replaceImportedNamespaces(Object payload) {} void replaceAppData(String appId) {} "
        "void updateSchema(){ String fromSchemaVersion; String toSchemaVersion; } "
        "AutoCloseable beginUpdateMigrationWriteBarrier(String appId) { String error = \"app_data_migration_in_progress\"; rejectIfUpdateMigrationWriteBarrierActive(appId); return null; } "
        "AppDataUpdateSnapshot createUpdateSnapshot(String appId) { String e = \"app_data_snapshot_too_large\"; return null; } "
        "void restoreUpdateSnapshot(String appId, AppDataUpdateSnapshot snapshot) {} "
        "void discardUpdateSnapshot(AppDataUpdateSnapshot snapshot) {} "
        "byte[] advanceUpdateMigrationDryRunPayload(String appId, String namespace, int from, int to, String summary, byte[] payload, Long targetDataQuotaBytes) { ManifestQuotaCheck.targetManifest(targetDataQuotaBytes); return null; } "
        "void preflightUpdateMigrationDryRunPayloads(String appId, java.util.Collection<byte[]> payloads, Long targetDataQuotaBytes) { ManifestQuotaCheck.targetManifest(targetDataQuotaBytes); } "
        "Object withImportedRecordTotals(Object metadata, java.util.List<Object> records) { int recordCount = records.size(); long totalBytes = records.size(); return metadata.withTotals(recordCount, totalBytes, metadata.updatedAt()); } "
        "void importUpdateMigrationPayload(String appId, String namespace, int from, int to, byte[] payload) {} "
        "void recordUpdateMigration(String appId, String namespace, int from, int to, String summary) {} "
        "String lastMigrationAt; String quota = \"quota.data.bytes\"; }\n",
        encoding="utf-8",
    )
    (appdata_api_dir / "AppDataBackupRestoreWorkflow.java").write_text(
        "final class AppDataBackupRestoreWorkflow { "
        "Object exportBackup(AppDataBackupOptions options, String sourceCryptaVersion) { payloadBase64 = \"\"; return createBackupBundle(options); } "
        "Object createBackupBundle(AppDataBackupOptions options) { AppDataBackupOptions.SCOPE_SINGLE_APP.toString(); AppDataBackupOptions.SCOPE_ALL_APPS.toString(); listStoreAppIds(); return null; } "
        "Object listStoreAppIds() { return service.listStoreAppIds(); } }\n",
        encoding="utf-8",
    )
    (appdata_api_dir / "AppDataStore.java").write_text(
        "interface AppDataStore { java.util.List<String> listAppIds(); }\n",
        encoding="utf-8",
    )
    (appdata_api_dir / "AppDataUpdateSnapshot.java").write_text(
        "record AppDataUpdateSnapshot(String appId, Object payload, long sizeBytes) {}\n",
        encoding="utf-8",
    )
    (appdata_api_dir / "AppDataExportPayload.java").write_text(
        "final class AppDataExportPayload { "
        "String mismatch = \"app_data_import_app_mismatch\"; }\n",
        encoding="utf-8",
    )
    (appdata_api_dir / "FileAppDataStore.java").write_text(
        "final class FileAppDataStore { List<String> listAppIds() { return List.of(); } "
        "String hash = \"sha256\"; String move = \"ATOMIC_MOVE\"; "
        "String current = \"current.properties\"; String root = \".cryptad-app-data\"; "
        "String value = \"value.bin\"; }\n",
        encoding="utf-8",
    )
    (appdata_api_dir / "InMemoryAppDataStore.java").write_text(
        "final class InMemoryAppDataStore { List<String> listAppIds() { return List.of(); } }\n",
        encoding="utf-8",
    )
    (appdata_api_dir / "AppDataBackupBundle.java").write_text(
        "record AppDataBackupBundle(AppDataBackupManifest manifest, java.util.List<AppDataBackupEntry> apps) { "
        "public String toString() { return \"AppDataBackupBundle[metadata only]\"; } }\n",
        encoding="utf-8",
    )
    (appdata_api_dir / "AppDataBackupEntry.java").write_text(
        "record AppDataBackupEntry(String appId, AppDataExportPayload export) { "
        "Object json() { return export.toJsonValue(); } "
        "public String toString() { return \"AppDataBackupEntry[metadata only]\"; } }\n",
        encoding="utf-8",
    )
    (appdata_api_dir / "AppDataBackupManifest.java").write_text(
        "record AppDataBackupManifest(int backupVersion, String kind, boolean sensitiveUserData) { "
        "static final int CURRENT_BACKUP_VERSION = 1; "
        "static final String BACKUP_KIND = \"crypta-app-data-backup\"; "
        "static final String ENCRYPTION_MODE_NONE = \"none\"; "
        "static final String ERROR = \"unsupported_backup_encryption\"; }\n",
        encoding="utf-8",
    )
    (appdata_api_dir / "AppDataBackupOptions.java").write_text(
        "record AppDataBackupOptions(String scope, String appId) { "
        "static final String SCOPE_SINGLE_APP = \"single-app\"; "
        "static final String SCOPE_ALL_APPS = \"all-apps\"; }\n",
        encoding="utf-8",
    )
    (appdata_api_dir / "AppDataRestoreMode.java").write_text(
        "enum AppDataRestoreMode { MERGE(\"merge\"), REPLACE_NAMESPACE(\"replaceNamespace\"), REPLACE_APP(\"replaceApp\"); AppDataRestoreMode(String wireName) {} }\n",
        encoding="utf-8",
    )
    (appdata_api_dir / "AppDataRestorePlan.java").write_text(
        "record AppDataRestorePlan(String status) { // without raw backup values\n"
        "Object toJsonValue() { return status; } }\n",
        encoding="utf-8",
    )
    (appdata_api_dir / "AppDataRestoreResult.java").write_text(
        "record AppDataRestoreResult(String status) { // without raw backup values\n"
        "Object toJsonValue() { return status; } }\n",
        encoding="utf-8",
    )
    (appdata_api_dir / "AppDataStoreConfig.java").write_text(
        "record AppDataStoreConfig(int maxRecordBytes, int maxRecordsPerApp, "
        "int maxNamespacesPerApp, int maxExportBytes, int maxImportBytes) { "
        "String quota = \"quota.data.bytes\"; }\n",
        encoding="utf-8",
    )
    (appdata_api_dir / "AppDataApiHandler.java").write_text(
        "final class AppDataApiHandler { String fromSchemaVersion; String toSchemaVersion; }\n",
        encoding="utf-8",
    )
    app_vault_api_dir = api_dir / "appvault"
    app_vault_api_dir.mkdir(parents=True, exist_ok=True)
    (app_vault_api_dir / "AppVaultApiHandler.java").write_text(
        "final class AppVaultApiHandler { void createAppOwnedIdentity() {} "
        "void createProfileDocument() { String route = \"profile-document\"; } "
        "void createTrustStatement() { String route = \"trust-statement\"; "
        "Object request = TrustStatementRequest.fromQuery(null); "
        "String type = \"TrustDocumentTypes.TRUST_STATEMENT_V1\"; } "
        "void createSocialMessage() { String route = \"social-message\"; "
        "Object request = SocialMessageRequest.fromQuery(null); "
        "String domain = SocialMessageRequest.SIGNING_PURPOSE; "
        "Object result = signDomainSeparatedPayload(null); } }\n",
        encoding="utf-8",
    )
    (app_vault_api_dir / "TrustStatementRequest.java").write_text(
        "final class TrustStatementRequest { // not an arbitrary signing API\n"
        "Object SUPPORTED_PARAMETERS; "
        "byte[] canonicalBytes() { return TrustStatementCanonicalizer.canonicalPayloadBytes(null); } }\n",
        encoding="utf-8",
    )
    (app_vault_api_dir / "SocialMessageRequest.java").write_text(
        "final class SocialMessageRequest { static final int MAX_BODY_LENGTH = 4096; "
        "static final int MAX_SUBJECT_LENGTH = 160; static final int MAX_TAG_COUNT = 12; "
        "static final int MAX_SIGNED_PAYLOAD_BYTES = 32768; static final String FORMAT_TEXT_PLAIN = \"text/plain\"; "
        "static final String SIGNING_PURPOSE = \"crypta.social.message.v1\"; "
        "Object ALLOWED_PARAMETERS; Object fromQuery(Object query) { return null; } }\n",
        encoding="utf-8",
    )
    (app_vault_api_dir / "SignedSocialMessageDocumentBuilder.java").write_text(
        "final class SignedSocialMessageDocumentBuilder { String publicKeyBase64; "
        "String signatureBase64; }\n",
        encoding="utf-8",
    )
    (api_dir / "PlatformApiVaultRouter.java").write_text(
        "final class PlatformApiVaultRouter { String route = \"trust-statement social-message\"; }\n",
        encoding="utf-8",
    )
    trust_api_dir = api_dir / "trust"
    trust_api_dir.mkdir(parents=True, exist_ok=True)
    (trust_api_dir / "TrustGraphApiHandler.java").write_text(
        "final class TrustGraphApiHandler { Object store = new InMemoryTrustGraphStore(); "
        "Map status() { String service = \"trust-graph-local-rc\"; String mode = \"local-rc\"; "
        "String scope = \"localAnchorsOnly importedStatementsOnly noCrawling noGlobalModeration "
        "noBlocking noRoutingDecisions noLegacyWoTCompatibility\"; "
        "Object lifecycle = statementLifecycleJson(); String max = \"maxEvidenceRows\"; return null; } "
        "Object statementLifecycleJson() { return null; } "
        "void importStatement() { TrustStatementParser.parse(\"{}\"); } "
        "void importUri(ContentFetchPort port) { Object handler = new ContentApiHandler(null); "
        "String max = \"maxStoredDocumentBytes\"; String format = \"format\"; "
        "String event = \"TrustGraphAuditEvent sourceUriHash redactedUriSummary redactedRejectedUriSummary\"; } "
        "Object score = new TrustGraphScorer(null, null); }\n",
        encoding="utf-8",
    )
    trustgraph_main_dir = (
        workspace / "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph"
    )
    trustgraph_test_dir = (
        workspace / "platform-trustgraph/src/test/java/network/crypta/platform/trustgraph"
    )
    trustgraph_main_dir.mkdir(parents=True, exist_ok=True)
    trustgraph_test_dir.mkdir(parents=True, exist_ok=True)
    (trustgraph_main_dir / "TrustStatementParser.java").write_text(
        "final class TrustStatementParser { void parse() { rejectUnknown(null, null, null); } }\n",
        encoding="utf-8",
    )
    (trustgraph_main_dir / "TrustStatementValidator.java").write_text(
        "final class TrustStatementValidator { static final int MAX_DOCUMENT_BYTES = 65536; "
        "void validate(Object expiresAt, Object issuedAt) { requireScore(0); requireConfidence(0); "
        "String check = \"expiresAt.isAfter(issuedAt) Character.isISOControl\"; } }\n",
        encoding="utf-8",
    )
    (trustgraph_main_dir / "TrustGraphStoreSanitizer.java").write_text(
        "final class TrustGraphStoreSanitizer { boolean control(char ch) { return Character.isISOControl(ch); } "
        "String normalizeSubscriptionId(String value) { return value; } }\n",
        encoding="utf-8",
    )
    (trustgraph_main_dir / "TrustStatementLifecycleStatus.java").write_text(
        "enum TrustStatementLifecycleStatus { ACTIVE, DEPRECATED, REVOKED; "
        "String text = \"operator-local policy\"; }\n",
        encoding="utf-8",
    )
    (trustgraph_main_dir / "TrustStatementLifecycleRecord.java").write_text(
        "record TrustStatementLifecycleRecord(String statementFingerprint, "
        "TrustStatementLifecycleStatus status, String reasonCode, String replacementUri, "
        "String actorAppId) { String text = \"operator-local policy\"; }\n",
        encoding="utf-8",
    )
    (trustgraph_main_dir / "TrustGraphStore.java").write_text(
        "interface TrustGraphStore { void updateLifecycle(); Object lifecycle(); "
        "record StoredTrustStatement(String sourceUriKind, String subscriptionId, "
        "Object lastSeenAt) {} String normalizeSubscriptionId = \"normalizeSubscriptionId\"; }\n",
        encoding="utf-8",
    )
    (trustgraph_main_dir / "InMemoryTrustGraphStore.java").write_text(
        "final class InMemoryTrustGraphStore implements TrustGraphStore { "
        "Object lifecycleRecords; int maxLifecycleRecords; void updateLifecycle(){} "
        "String sourceUriKind; String subscriptionId; String lastSeenAt; }\n",
        encoding="utf-8",
    )
    (trustgraph_main_dir / "TrustGraphEvidence.java").write_text(
        "record TrustGraphEvidence(String lifecycleStatus, Object nonContributingReasons) {}\n",
        encoding="utf-8",
    )
    (trustgraph_main_dir / "TrustGraphScore.java").write_text(
        "record TrustGraphScore(boolean evidenceTruncated, int maxEvidenceRows) {}\n",
        encoding="utf-8",
    )
    (trustgraph_main_dir / "TrustGraphScorer.java").write_text(
        "final class TrustGraphScorer { static final int MAX_EVIDENCE_ROWS = 25; "
        "String reasons = \"nonContributingReasons unanchored unverified expired "
        "zero-confidence revoked deprecated evidenceTruncated\"; }\n",
        encoding="utf-8",
    )
    (trustgraph_main_dir / "FileTrustGraphStore.java").write_text(
        "final class FileTrustGraphStore implements TrustGraphStore { "
        "String anchors = \"anchors\"; String statements = \"statements\"; String audit = \"audit\"; "
        "Object lifecycleRecords; int maxLifecycleRecords; String sourceUriKind; "
        "String subscriptionId; String lastSeenAt; "
        "void updateLifecycle(){} void writeLifecycleRecord(){} void loadLifecycleRecords(){} "
        "void write() { String temp = \"createTempFile\"; String move = \"ATOMIC_MOVE\"; force(); } "
        "void force() {} }\n",
        encoding="utf-8",
    )
    (trustgraph_main_dir / "TrustGraphStoreConfig.java").write_text(
        "record TrustGraphStoreConfig(int maxStatements, int maxAnchors, int maxAuditEntries, "
        "int maxStoredDocumentBytes) {}\n",
        encoding="utf-8",
    )
    (trustgraph_main_dir / "TrustGraphAuditEvent.java").write_text(
        "record TrustGraphAuditEvent(String sourceUriHash, String sourceSummary, "
        "Boolean signatureVerified) {}\n",
        encoding="utf-8",
    )
    (trustgraph_test_dir / "FileTrustGraphStoreTest.java").write_text(
        "final class FileTrustGraphStoreTest { "
        "void reopen_whenAnchorStored_expectAnchorDurable() {} "
        "void reopen_whenVerifiedStatementAndAnchorStored_expectScoreUsesDurableState() {} "
        "void reopen_whenStatementRevokedAndReimported_expectLifecycleDurableAndPreserved() {} "
        "void importStatement_whenSameDocumentImportedTwice_expectMetadataReplacedWithoutDuplicate() {} "
        "void retention_whenCapsExceeded_expectOldestRecordsEvicted() {} "
        "void reopen_whenPersistedRecordIsCorrupt_expectRecordIgnoredSafely() {} "
        "void auditEvents_whenStoredAndReopened_expectBoundedNewestFirstAndRedacted() {} "
        "void auditEvents_whenDuplicateEventsEvicted_expectOnlyOnePersistedDuplicateDeleted() {} }\n",
        encoding="utf-8",
    )
    (trustgraph_test_dir / "TrustGraphScorerTest.java").write_text(
        "final class TrustGraphScorerTest { "
        "void score_whenAnchoredStatementRevoked_expectLifecycleBlocksContribution() {} "
        "void score_whenAnchoredStatementDeprecated_expectLifecycleBlocksContribution() {} "
        "String reasons = \"nonContributingReasons unanchored unverified expired "
        "zero-confidence revoked deprecated evidenceTruncated MAX_EVIDENCE_ROWS\"; }\n",
        encoding="utf-8",
    )
    (trustgraph_test_dir / "TrustStatementParserTest.java").write_text(
        "final class TrustStatementParserTest { String malicious = \"\\\\u0000 \\\\u0085 50.5 token=secret uri:redacted\"; }\n",
        encoding="utf-8",
    )
    queue_api_dir = api_dir / "queue"
    queue_api_dir.mkdir(parents=True, exist_ok=True)
    (queue_api_dir / "QueueApiHandler.java").write_text(
        "final class QueueApiHandler { void createAppGeneratedDocumentInsert() { "
        "String route = \"app-document\"; } }\n",
        encoding="utf-8",
    )
    content_api_dir = api_dir / "content"
    content_api_dir.mkdir(parents=True, exist_ok=True)
    (content_api_dir / "ContentFetchPolicy.java").write_text(
        "final class ContentFetchPolicy { static final long HARD_APP_FETCH_MAX_BYTES = 1048576; "
        "static final long HARD_APP_FETCH_TIMEOUT_MILLIS = 60000; "
        "String families = \"CHK@ SSK@ USK@ KSK@ crypta:\"; "
        "boolean unsafe(String uri) { return uri.contains(\"http://\") || uri.contains(\"https://\") || uri.contains(\"file://\"); } }\n",
        encoding="utf-8",
    )
    (content_api_dir / "ContentApiHandler.java").write_text(
        "final class ContentApiHandler { void contentFetch() { String route = \"content/fetch\"; "
        "Object coding = CodingErrorAction.REPORT; String error = \"unsupported_content_encoding content_fetch_failed\"; } }\n",
        encoding="utf-8",
    )
    content_subscriptions_dir = content_api_dir / "subscriptions"
    content_subscriptions_dir.mkdir(parents=True, exist_ok=True)
    (content_subscriptions_dir / "ContentSubscriptionService.java").write_text(
        "final class ContentSubscriptionService { "
        "static final String CAPABILITY_CONTENT_SUBSCRIBE = \"content.subscribe\"; "
        "static final String CAPABILITY_CONTENT_FETCH = \"content.fetch\"; "
        "int perAppSubscriptionLimit; int globalSubscriptionLimit; int maxBytes; int timeoutMillis; "
        "String contentSha256; int bytes.length; String lastSeenEdition; "
        "String lastSeenResolvedUri; int updateCount; "
        "// raw fetched content is digested and then discarded. "
        "void contentChanged(){} void failureBackoff(){} void withFailure(){} "
        "String error = \"content_fetch_failed\"; }\n",
        encoding="utf-8",
    )
    (content_subscriptions_dir / "ContentSubscription.java").write_text(
        "final class ContentSubscription { String contentSha256; String lastSeenEdition; "
        "String lastSeenResolvedUri; int updateCount; }\n",
        encoding="utf-8",
    )
    (content_subscriptions_dir / "ContentSubscriptionsApiHandler.java").write_text(
        "final class ContentSubscriptionsApiHandler {}\n",
        encoding="utf-8",
    )
    (content_subscriptions_dir / "ContentSubscriptionSource.java").write_text(
        "final class ContentSubscriptionSource { String usk = \"USK@\"; String crypta = \"crypta:\"; "
        "void hasDisallowedScheme(){} void containsWhitespace(){} "
        "String error = \"unsupported_content_subscription_source\"; }\n",
        encoding="utf-8",
    )
    (content_subscriptions_dir / "ContentSubscriptionScheduler.java").write_text(
        "public final class ContentSubscriptionScheduler { ContentSubscriptionSchedulerConfig c; "
        "ContentSubscriptionPressureGate p; AtomicBoolean running; "
        "void tick(Instant now) { running.compareAndSet(false, true); String alreadyRunning = \"alreadyRunning\"; } "
        "void start(){ scheduleWithFixedDelay(); config.initialDelay().plus(jitter()); } "
        "void close(){ shutdownNow(); } int perTickFetchLimit; }\n",
        encoding="utf-8",
    )
    (content_subscriptions_dir / "ContentSubscriptionSchedulerConfig.java").write_text(
        "record ContentSubscriptionSchedulerConfig(int perAppSubscriptionLimit, "
        "int globalSubscriptionLimit, int perTickFetchLimit, Object minimumPollInterval, "
        "Object maximumFailureBackoff) { String env = "
        "\"CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_PER_TICK_FETCH_LIMIT\"; }\n",
        encoding="utf-8",
    )
    (content_subscriptions_dir / "FileContentSubscriptionStore.java").write_text(
        "public final class FileContentSubscriptionStore { String move = \"ATOMIC_MOVE\"; "
        "// source URIs are never used as file names. String lastErrorCode; }\n",
        encoding="utf-8",
    )
    (content_subscriptions_dir / "ContentSubscriptionPressureGate.java").write_text(
        "public final class ContentSubscriptionPressureGate { QueueSupportPort q; RequestQueuePort r; "
        "void assess(){ q.isQueueBackendEnabled(); r.isPersistenceDatabaseKilled(); "
        "status.stopping(); status.awaitingPassword(); } }\n",
        encoding="utf-8",
    )
    platform_api_tests = workspace / "platform-api/src/test/java/network/crypta/platform/api"
    platform_api_tests.mkdir(parents=True, exist_ok=True)
    (platform_api_tests / "AppVaultProfileDocumentApiTest.java").write_text(
        "void profileDocument_whenAppUsesGrantedIdentity_expectNoPrivateKeyOrRawSignatureEvidence() { "
        "String route = \"profile-document\"; }\n",
        encoding="utf-8",
    )
    (platform_api_tests / "QueueGeneratedDocumentInsertApiTest.java").write_text(
        "void appDocument_whenAppGeneratedBodyQueued_expectNoPrivateInsertUriOrRawBodyEvidence() { "
        "String route = \"app-document\"; }\n",
        encoding="utf-8",
    )
    (platform_api_tests / "ContentFetchApiTest.java").write_text(
        "void contentFetch_whenFeedFetched_expectNoRawFeedBodyOrRequestBodyEvidence() { "
        "String route = \"content/fetch\"; String capability = \"content.fetch\"; "
        "String rejected = \"http:// https:// file:// //example.invalid C:\\\\Users SECRET\"; }\n",
        encoding="utf-8",
    )
    (platform_api_tests / "PlatformApiContentSubscriptionsRouterTest.java").write_text(
        "void route_whenAppLacksContentSubscribe_expectForbidden() { "
        "String c = \"ContentSubscriptionService.CAPABILITY_CONTENT_SUBSCRIBE\"; }\n"
        "void route_whenAppLacksContentFetchForCreate_expectForbidden() { "
        "String c = \"ContentSubscriptionService.CAPABILITY_CONTENT_FETCH\"; }\n"
        "void route_whenHostOperatorUsesSubscriptionRoute_expectForbiddenByAppScope() { "
        "PlatformApiPrincipal.hostOperator(); }\n"
        "void route_whenAppReadsAnotherAppsSubscription_expectNotFound() {}\n",
        encoding="utf-8",
    )
    (platform_api_tests / "PlatformApiAppDataRouterTest.java").write_text(
        "void route_whenAppReadsAnotherAppsRecord_expectNotFound() {}\n"
        "void route_whenCapabilityMissingOrServiceUnavailable_expectDeniedOr503() {}\n",
        encoding="utf-8",
    )
    content_subscription_tests = platform_api_tests / "content/subscriptions"
    content_subscription_tests.mkdir(parents=True, exist_ok=True)
    (content_subscription_tests / "ContentSubscriptionServiceTest.java").write_text(
        "void create_whenSourceIsUnsupported_expectBadRequest() {}\n"
        "void refresh_whenContentMetadataChanges_expectDigestEditionAndDedupe() {}\n",
        encoding="utf-8",
    )
    (content_subscription_tests / "ContentSubscriptionSchedulerTest.java").write_text(
        "void tick_whenSubscriptionIsDue_expectOneBoundedFetchAndUpdatedMetadata() {}\n"
        "void tick_whenQueueBackendUnavailable_expectSafePressureSkip() {}\n"
        "void tick_whenAlreadyRunning_expectNoOverlappingFetch() { String overlapping = \"overlapping\"; }\n",
        encoding="utf-8",
    )
    (content_subscription_tests / "FileContentSubscriptionStoreTest.java").write_text(
        "void writeAndRead_whenSubscriptionContainsSourceUri_expectPathUsesAppAndSubscriptionIdsOnly() {}\n",
        encoding="utf-8",
    )
    appdata_tests = platform_api_tests / "appdata"
    appdata_tests.mkdir(parents=True, exist_ok=True)
    (appdata_tests / "AppDataServiceTest.java").write_text(
        "void putRecord_whenIdentifierContainsTraversal_expectPathFreeValidationError() {}\n"
        "void exportImport_whenPayloadRoundTrips_expectValuesCopiedAndOtherAppRejected() {}\n"
        "void createUpdateSnapshot_whenOtherAppHasData_expectSnapshotIsAppScoped() {}\n"
        "void restoreUpdateSnapshot_whenDataChangedAfterSnapshot_expectOriginalStateRestored() {}\n"
        "void appFacingWrites_whenUpdateMigrationWriteBarrierActive_expectMigrationInProgressConflict() {}\n"
        "void updateMigrationImport_whenWriteBarrierActive_expectInternalMigrationWritesAllowed() {}\n"
        "void advanceUpdateMigrationDryRunPayload_whenTargetManifestRaisesQuota_expectTargetQuotaUsed() {}\n"
        "void preflightUpdateMigrationDryRunPayloads_whenCombinedOutputExceedsRecordQuota_expectQuotaError() {}\n"
        "void advanceUpdateMigrationDryRunPayload_whenChainedDryRun_expectNamespaceTotalsMatchRecords() { importedValueBytes(records); }\n"
        "void exportBackup_whenSingleAppRequested_expectVersionedEnvelopeAndMetadataOnlyToString() {}\n"
        "void exportBackup_whenAllAppsRequested_expectKnownAppIdsSorted() {}\n"
        "void restoreBackup_whenReplaceApp_expectTargetAppClearedAndOtherAppsPreserved() {}\n"
        "void restorePlan_whenBackupContainsRawValues_expectMetadataOnlyPlan() {}\n"
        "long importedValueBytes(java.util.List<Object> records) { return 0L; }\n",
        encoding="utf-8",
    )
    (appdata_tests / "FileAppDataStoreTest.java").write_text(
        "void writeRecord_whenUnreferencedGenerationExists_expectCurrentRecordUnaffected() {}\n"
        "void listAppIds_whenStoreHasKnownAndMalformedDirectories_expectOnlyNormalizedIds() {}\n",
        encoding="utf-8",
    )
    (platform_api_tests / "TrustGraphApiTest.java").write_text(
        "void trustGraph_whenQueried_expectNoRawTrustStatementBodiesOrSignatures() { "
        "String route = \"trust-graph/score\"; String capability = \"trust.read\"; }\n",
        encoding="utf-8",
    )
    appcatalog_api_tests = workspace / "platform-api/src/test/java/network/crypta/platform/api/appcatalogs"
    appcatalog_api_tests.mkdir(parents=True, exist_ok=True)
    (appcatalog_api_tests / "AppCatalogsApiHandlerTest.java").write_text(
        "void listRecommendedCatalogs_whenConfiguredAndTrusted_expectCanAddAndRedactedSource() {}\n"
        "void listRecommendedCatalogs_whenHttpsSourceHasQuery_expectQueryRedacted() {}\n"
        "void listRecommendedCatalogs_whenFileSourceConfigured_expectPathRedacted() {}\n",
        encoding="utf-8",
    )
    shell = workspace / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    shell.parent.mkdir(parents=True, exist_ok=True)
    shell.write_text(
        'const legacySecurityLevelsPath = normalizeLocalPath(bootstrap.legacySecurityLevelsPath, "/seclevels/");\n'
        'const legacySecurityLevelsFallbackPath = legacySecurityLevelsPath + "?legacyFallback=security-levels";\n'
        "function registeredAppUiOrigin(app){ return 'http://127.0.0.1:1234'; }\n"
        "function safeSameOriginAppUiHref(url, allowIsolatedLaunchParameter){ return '/apps/demo/'; }\n"
        "function normalizeLaunchFallbackHref(value){}\n"
        "function normalizeIsolatedLaunchHref(value){}\n"
        "function normalizeIsolatedProbeHref(value, expectedOrigin){}\n"
        "const originPolicy = 'url.username url.password url.search !== \"\" url.hash !== \"\" /apps/';\n"
        "fetch('/.well-known/cryptad-origin.json', { credentials: \"omit\", mode: \"cors\" });\n"
        "function renderRecommendedCatalogs(){}\n"
        "function renderRecommendedCatalogCard(){}\n"
        "function catalogAppChannel(){}\n"
        "function securityAdvisoryListNode(){}\n"
        "const catalogChannelSelect = 'catalog-channel-select'; const deprecatedCard = 'is-deprecated-channel';\n"
        "const path = 'app-catalogs/recommended';\n"
        "const action = 'addRecommended';\n"
        "function appServiceGrantPath(){}\n"
        "function setSecurityLegacyFallbackStatus(){ return 'Open the legacy security page'; }\n"
        "function renderSecurityLegacyFallbackAction(){ return 'Open legacy password and recovery forms'; }\n"
        "sections.security.append(renderSecurityLegacyFallbackAction());\n"
        "const grants = 'App-service grants'; const approve = 'Approve'; const revoke = 'Revoke';\n"
        "const renew = 'Renew bundle'; function renderAppServiceDependencyGraph(){}\n"
        "function renderAppServiceBundleCard(){}\n"
        "apiUrl(\"app-services\"); apiUrl(\"app-services/grants\"); "
        "apiUrl(\"app-services/dependencies\"); apiUrl(\"app-services/grant-bundles\"); "
        "apiUrl(\"app-services/audit?limit=12\");\n",
        encoding="utf-8",
    )
    app_ui_dir = workspace / "platform-app-ui/src/main/java/network/crypta/platform/appui"
    app_ui_test_dir = workspace / "platform-app-ui/src/test/java/network/crypta/platform/appui"
    app_ui_dir.mkdir(parents=True, exist_ok=True)
    app_ui_test_dir.mkdir(parents=True, exist_ok=True)
    (app_ui_dir / "AppUiSecurityHeaders.java").write_text(
        "final class AppUiSecurityHeaders { String csp = \"default-src 'none'; script-src style-src connect-src "
        "object-src base-uri worker-src frame-src manifest-src\"; String headers = "
        "\"permissions-policy cross-origin-resource-policy nosniff no-referrer\"; }\n",
        encoding="utf-8",
    )
    (app_ui_test_dir / "AppUiSecurityHeadersTest.java").write_text(
        "class AppUiSecurityHeadersTest { String unsafe = "
        "\"admin.example 0.0.0.0 127.0.0.1.attacker.example user:pass@ ftp://\"; }\n",
        encoding="utf-8",
    )
    web_shell_bootstrap_dir = (
        workspace / "platform-web-shell/src/main/java/network/crypta/platform/webshell/bootstrap"
    )
    web_shell_bootstrap_dir.mkdir(parents=True, exist_ok=True)
    (web_shell_bootstrap_dir / "WebShellBootstrap.java").write_text(
        "record WebShellBootstrap(String legacySecurityLevelsPath) { "
        "void compact(){ requireLegacySecurityLevelsPath(legacySecurityLevelsPath); } }\n",
        encoding="utf-8",
    )
    (web_shell_bootstrap_dir / "WebShellBootstrapJson.java").write_text(
        'class WebShellBootstrapJson { String key = "legacySecurityLevelsPath"; }\n',
        encoding="utf-8",
    )
    web_shell_test = (
        workspace
        / "platform-web-shell/src/test/java/network/crypta/platform/webshell/WebShellResourcesTest.java"
    )
    web_shell_test.parent.mkdir(parents=True, exist_ok=True)
    web_shell_test.write_text(
        "class WebShellResourcesTest { String grants = \"App-service grants\"; "
        "String bundles = \"grant-bundles Renew bundle renderAppServiceDependencyGraph\"; "
        "void assertAppUiOriginHardeningMarkersPresent() {} }\n",
        encoding="utf-8",
    )
    docs = workspace / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    first_party_docs = (
        "No private keys are shipped. "
        "Static app CSP uses default-src 'none'. CSP is a browser mitigation and not a process sandbox. "
        "Public-beta certification treats the environment allow-list as a release boundary. "
        "Bubblewrap filesystem containment does not enforce CPU, memory, or network isolation. "
        "Public-beta release evidence is redacted evidence. "
        "Review governance reports record counts, latest hashes, raw receipt signatures exclusions, and catalog scratch paths exclusions. "
        "The local transparency log is not a global public log. "
        "queue-manager publisher site-publisher profile-publisher social-inbox feed-reader trust-graph use permissions.rationale entries, "
        "Profile Publisher is the identity-profile reference app. "
        "Social Inbox RC is a social/mail-like reference app and migration spike outside the daemon core, outside the daemon, and not a generic browser signing API. "
        "It uses AppVault identity, bounded crypta.social.message.v1 social message signing, a Signed social message document format with domain-separated signatures, profile-document metadata, generated app-document outbox insert, "
        "durable content.subscribe USK sources, local thread reconstruction, channel filters, bounded local search, app-data read state and drafts, a non-blocking schema-1 namespace contract, and Trust Graph Preview message-author annotations only that are not a moderation decision. "
        "It is not old plugin ABI compatibility, not Freetalk, Sone, Freemail, not encrypted mail, not a full WoT, not a daemon-core message protocol, and not network protocol changes. "
        "Feed Reader & Publisher is the content subscription reference app and uses SDK helpers such as CryptaPlatform.feed.fetchSnapshot and CryptaPlatform.content.subscriptions. "
        "Trust Graph Local RC is local trust only, not global truth, not a full Web of Trust, "
        "not complete WoT, no crawling, no global moderation, not blocking, no routing decisions, "
        "and no legacy WebOfTrust, Freetalk, Sone, or Freemail compatibility. "
        "It uses trust.read, trust.write, local anchors, durable local backend storage, redacted audit, "
        "bounded trust-statement signing, lifecycle states active, deprecated, and revoked, "
        "bounded non-contribution reason codes, Trust Score Service, trust.score, "
        "operator-approved app-service grants, and read-only app-service score access. "
        "Trust anchors are local. "
        "It has no old WebOfTrust plugin compatibility. No FNP/FCP/wire protocol changes are involved. "
        "api.minimumVersion, changelog.summary, and review receipts. "
        "Maintain artifacts as crypta:CHK@artifact and set CRYPTAD_FIRST_PARTY_CATALOG_SOURCE "
        "with CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_KEY_ID and "
        "CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_CATALOG_KEY_ID. "
        "Run crypta-app publish-usk --dry-run for the offline plan, then crypta-app publish-usk --live "
        "with a private insert URI loaded from env or protected file. The live USK catalog source is "
        "crypta:USK@.../cryptad-app-catalog.properties and cryptad-app-catalog.signature is the "
        "sibling sidecar at the same USK edition. Signed catalog verification remains mandatory. "
        "Catalog refresh records last verified state, and manual remains the default update policy. "
        "POST /api/v1/app-vault/identities creates browser-safe app-owned identities with "
        "vault.identities.create. POST /api/v1/app-vault/identities/{identityId}/profile-document "
        "uses vault.identities.read and vault.identities.use for profile document signing. "
        "POST /api/v1/queue/inserts/app-document accepts app-generated document content without a "
        "local file path and requires content.insert.app-document plus queue.write. "
        "POST /api/v1/content/fetch fetches feed content and requires content.fetch. "
        "GET and POST /api/v1/content/subscriptions manage durable USK metadata and require content.subscribe; create and refresh also require content.fetch. "
        "The network-content.subscription-scheduler records path-free metadata, queue pressure, no queue HTML, and no raw fetched content. "
        "It is not a generic crawler and does not support arbitrary HTTP/HTTPS fetches. "
        "The durable app-data store exposes GET /api/v1/app-data/status, GET /api/v1/app-data/namespaces, "
        "GET and POST /api/v1/app-data/records, GET /api/v1/app-data/export, and POST /api/v1/app-data/import. "
        "App data routes are app-scoped. "
        "It requires app.data.read and app.data.write, enforces cryptad.appData.maxRecordBytes and quota bounds, "
        "is not a filesystem API, is not a generic database, and is not a secret vault. "
        "Export and import are bounded, schema migration metadata is recorded, and Redaction rules exclude raw app-data values. "
        "App-data backup and restore uses backupVersion 1 with kind crypta-app-data-backup, "
        "single-app and all-apps scope, restore modes merge, replaceNamespace, and replaceApp, "
        "sensitive user data warnings, encryption.mode = none, vault secrets and private identity material exclusions, "
        "support bundles and release evidence redaction, app-data.backup-restore-portability, and operator-beta.app-data-backup-restore. "
        "Contract v12 adds GET /api/v1/app-services, app.services.read, app.services.call, "
        "operator-approved app-service grants, and mediated trust.score invocation through Trust Score Service grants. "
        "Contract v16 adds GET /api/v1/app-services/dependencies, GET and POST /api/v1/app-services/grant-bundles, "
        "optional dependency metadata, trust-annotations, Trust score annotations, grant expiry, renewal, and provider revalidation. "
        "Contract v13 adds catalog.version=3 production catalog channels: stable, beta, nightly, and deprecated. "
        "Stable is the default automatic update channel, beta and nightly require explicit policy, "
        "channel_policy_blocked records excluded automation candidates, and deprecated entries expose "
        "replacement metadata without bypassing signed catalog verification. "
        "Contract v14 adds app-update.data-migration-contract for signed app-data schema migration declarations. "
        "Contract v15 adds app-platform.trust-graph-rc-scope-and-safety for Trust Graph Local RC scope, lifecycle, source metadata, and score safety. "
        "The app-data migration lifecycle runs a dry-run before bundle replacement, creates an internal rollback snapshot, "
        "restores app data on failed migration rollback, and keeps rollback snapshot scope app-only. "
        "It blocks missing migration paths and rollback-incompatible migrations until operator review, "
        "and PR-250 long-term backup/restore portability is handled by the operator backup envelope. "
        "It is not generic RPC, not a localhost proxy, and does not give apps ambient access to provider ports or data. "
        "It issues no raw service tokens and keeps raw request bodies out of evidence. "
        "Social Inbox uses a Trust Score Service grant for message-author annotations; revoked grants fail, and it must not fall back to\n"
        "`CryptaPlatform.trust.score`. "
        "Release evidence covers app-services.registry, app-services.grants, app-services.dependency-graph, "
        "app-services.grant-bundles, app-services.grant-expiry-renewal, app-services.provider-revalidation, "
        "app-services.trust-score-provider, reference-app.social-inbox-service-grant, "
        "reference-app.social-inbox-service-dependency, app-services.web-shell, app-services.redaction, "
        "and app-services.dependency-redaction. "
        "Feed Reader and Profile Publisher use app-data for bounded local state. "
        "Trust Graph Local RC uses UI-local app-data state separate from the platform trust graph backend. "
        "The durable local backend has a durable file-backed preview store that persists local trust anchors, imported public statements, and redacted audit entries. "
        "Contract v10 adds POST /api/v1/trust-graph/import-uri and GET /api/v1/trust-graph/audit. "
        "Exchange uses content fetch, insert, and subscription APIs and does not crawl the network globally. "
        "POST /api/v1/app-vault/identities/{identityId}/trust-statement signs bounded trust statements. "
        "POST /api/v1/app-vault/identities/{identityId}/social-message signs bounded social messages with vault.identities.read and vault.identities.use. "
        "GET /api/v1/trust-graph/status and GET /api/v1/trust-graph/score read local trust preview data. "
        "Release evidence covers reference-app.profile-publisher, "
        "reference-app.social-inbox, reference-app.social-inbox-signed-message, "
        "reference-app.social-inbox-subscriptions, reference-app.social-inbox-app-data, "
        "reference-app.social-inbox-trust-annotations, reference-app.social-inbox-rc-threading, "
        "reference-app.social-inbox-service-dependency, "
        "migration.social-mail-preview, "
        "legacy-plugin.migration-guide, legacy-plugin.social-inbox-spike, "
        "reference-app.feed-reader, reference-app.feed-reader-subscriptions, "
        "app-platform.content-fetch, app-platform.content-subscriptions, "
        "network-content.subscription-scheduler, "
        "app-platform.durable-app-data-store, reference-app.feed-reader-app-data, "
        "reference-app.profile-publisher-app-data, reference-app.trust-graph-app-data-preview, "
        "reference-app.trust-graph, reference-app.trust-graph-durable-exchange, "
        "app-platform.trust-graph-preview, app-platform.trust-graph-durable-store, "
        "app-platform.trust-graph-exchange, "
        "app-update.data-migration-contract, catalog.production-channels, "
        "app-platform.trust-statement-signing, app-platform.social-message-signing, "
        "app-platform.identity-profile-publish, and app-platform.generated-document-insert. "
        "Developers can find legacy-plugin-migration-guide.md from the app-platform portal. "
        "It excludes raw request bodies, private keys, private key material, raw signatures, private insert URIs, raw source URIs, and "
        "absolute staging paths. It also excludes raw feed bodies, raw message bodies, raw fetched content, raw fetched documents, raw trust statement bodies, browser-session tokens, "
        "form passwords, and local paths.\n"
    )
    for doc_name in (
        "app-catalogs.md",
        "app-data-backup-restore-portability.md",
        "app-data-store.md",
        "app-dev-cli.md",
        "app-platform-developer-portal.md",
        "app-platform-beta-known-limitations.md",
        "app-platform-beta-tutorials.md",
        "app-upgrade-data-migrations.md",
        "app-permissions-and-audit.md",
        "feed-reader-reference-app.md",
        "platform-api-contract.md",
        "platform-api-surface.md",
        "platform-sdk-js.md",
        "social-inbox-reference-app.md",
        "trust-graph-preview.md",
        "first-party-beta-catalog.md",
        "release-certification.md",
    ):
        (docs / doc_name).write_text(first_party_docs, encoding="utf-8")
    cert_readme = workspace / "tools/release-certification/README.md"
    cert_readme.parent.mkdir(parents=True, exist_ok=True)
    cert_readme.write_text(first_party_docs, encoding="utf-8")
    (docs / "legacy-plugin-migration-guide.md").write_text(
        "The old plugin runtime removed status is intentional. There is no old plugin ABI "
        "compatibility and no old FCP plugin command compatibility. WebOfTrust-like and WoT-like "
        "migration maps to Trust Graph Preview, durable trust graph storage, content subscriptions, "
        "app vault identity grants, app data, and app-service grants for trust.score. "
        "Freetalk/Sone-like migration maps to Social Inbox RC, Profile Publisher, Feed Reader, "
        "content subscriptions, app data, and Trust Graph annotations. Freemail-like migration uses "
        "Social Inbox as a bounded spike and is not encrypted mail transport or Freemail protocol "
        "compatibility. Distribution uses signed catalog entries, signed bundles, review receipt "
        "evidence, and review governance. The guide links to social-inbox-reference-app.md.\n",
        encoding="utf-8",
    )
    (docs / "plugin-system.md").write_text(
        "The plugin runtime has been removed. Legacy plugin migrations should use "
        "legacy-plugin-migration-guide.md and must not restore old plugin ABI compatibility.\n",
        encoding="utf-8",
    )
    registry = workspace / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java"
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text((Path(__file__).parent / "fixtures" / "self-test-legacy-registry.java-fragment").read_text(encoding="utf-8"), encoding="utf-8")
    legacy_docs = workspace / "docs/legacy-retirement-plan.md"
    legacy_docs.parent.mkdir(parents=True, exist_ok=True)
    legacy_docs.write_text(
        "legacy-admin.removal-wave-1 documents that removed routes return replacement responses "
        "when the replacement is reachable and render legacy fallback when the replacement is unavailable. "
        "legacy-admin.removal-wave-2 documents that safe reads redirect when the replacement is reachable, "
        "mutating legacy alert bulk actions and core-update installer and package-store actions remain fallback, "
        "and raw diagnostic export remains retained. legacy-admin.removal-wave-3 documents that "
        "/seclevels/ safe reads redirect to /app/node/#security when Web Shell security is "
        "available. Security-level mutating requests keep legacy fallback; legacy fallback remains "
        "for master-password, "
        "database/password-file, high physical security, and recovery flows. Wave 3 does not use "
        "prefix-family matching for security routes. A bootstrap-resolved explicit fallback link remains in "
        "the Security panel for legacy security forms, and arbitrary query strings still receive replacement redirects. "
        "Startup wizard and emergency fallback remain "
        "pending. Node-to-node messages remain pending. "
        "FProxy browse remains retained, FProxy browse and content rendering remain retained, "
        "content filter remains retained, "
        "and retained and pending legacy routes remain reachable.\n",
        encoding="utf-8",
    )
    legacy_admin_dir = workspace / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http"
    (legacy_admin_dir / "LegacyAdminRemovalPolicy.java").write_text(
        'class LegacyAdminRemovalPolicy { boolean matchesCanonicalPageOrSlashlessAlias; '
        'boolean matchesRemovalScope; boolean explicitRemovalChildPaths; '
        'boolean blockMutatingRequests; boolean replacementAvailable; '
        'boolean isStaticAppUiAvailable; boolean primaryUiRoot; '
        'String legacyFallback = "legacyFallback=security-levels"; '
        'String security = "security-levels"; boolean webShellReplacementAvailable; '
        'String s = "LegacyAdminRemovalScope EXPLICIT_CHILDREN PREFIX_FAMILY"; '
        'String m = "GET HEAD"; Object d = LegacyAdminRemovalDecision.redirect(null); '
        'Object b = LegacyAdminRemovalDecision.blockedMutation(null); }\n',
        encoding="utf-8",
    )
    (legacy_admin_dir / "LegacyAdminReplacementResponse.java").write_text(
        'class LegacyAdminReplacementResponse { String link = "replacementUrl"; }\n',
        encoding="utf-8",
    )
    (legacy_admin_dir / "WebShellToadlet.java").write_text(
        'class WebShellToadlet { Object create(Object links) { String legacySecurityLevelsPath = '
        'LegacyAdminRetirementRegistry.require("security-levels").legacyPath(); '
        'return WebShellBootstrap.nodeManagement(legacySecurityLevelsPath, links); } }\n',
        encoding="utf-8",
    )
    (legacy_admin_dir / "LegacyAdminUsageRecorder.java").write_text(
        "class LegacyAdminUsageRecorder { Object a = LegacyAdminUsageEvent.REPLACEMENT_RESPONSE; }\n",
        encoding="utf-8",
    )
    usage_dto = workspace / "runtime-spi/src/main/java/network/crypta/runtime/spi/LegacyAdminSurfaceUsage.java"
    usage_dto.parent.mkdir(parents=True, exist_ok=True)
    usage_dto.write_text(
        "record LegacyAdminSurfaceUsage(long replacementResponseCount, "
        "long blockedMutatingRequestCount, long fallbackRenderCount, "
        "long retainedOrPendingRenderCount, String removalScope, int scopeExpandedInWave) {}\n",
        encoding="utf-8",
    )
    diagnostics_handler = workspace / "platform-api/src/main/java/network/crypta/platform/api/diagnostics/DiagnosticsApiHandler.java"
    diagnostics_handler.parent.mkdir(parents=True, exist_ok=True)
    diagnostics_handler.write_text(
        "class DiagnosticsApiHandler { String a = \"replacementResponseCount "
        "blockedMutatingRequestCount fallbackRenderCount retainedOrPendingRenderCount "
        "removalScope scopeExpandedInWave\"; }\n",
        encoding="utf-8",
    )
    app_vault_doc = workspace / APP_VAULT_DOC
    app_vault_doc.write_text(
        "The app secret and identity vault defines vault.secrets.read, vault.secrets.write, "
        "vault.identities.read, vault.identities.create, vault.identities.use, and "
        "vault.identities.manage. It distinguishes app-owned identities from shared identities. "
        "Process callers use CRYPTAD_APP_TOKEN, while browser callers use app browser sessions. "
        "At-rest local protection has limits and depends on the host account. Grant lifecycle "
        "checks cover update, rollback, uninstall, and reinstall. Audit and redaction omit secret "
        "values and identity private material. Future content, social, and mail features can use "
        "the same extension point. POST /api/v1/app-vault/identities is browser-safe when the "
        "calling app has vault.identities.create. "
        "POST /api/v1/app-vault/identities/{identityId}/profile-document uses "
        "vault.identities.read and vault.identities.use to create a profile document. Evidence "
        "omits raw request bodies, private keys, and signatures.\n",
        encoding="utf-8",
    )
    devtools_dir = workspace / "platform-devtools/src/main/java/network/crypta/platform/devtools"
    devtools_dir.mkdir(parents=True, exist_ok=True)
    (devtools_dir / "DevtoolsCapabilityVocabulary.java").write_text(
        "\n".join(APP_VAULT_CAPABILITIES) + "\n",
        encoding="utf-8",
    )
    (devtools_dir / "CryptaAppCli.java").write_text(
        '@Command(name = "dev") class DevCommand {}\n'
        '@Command(name = "test") class AppTestCommand {}\n'
        '@Command(name = "generate") class KeysGenerateCommand {}\n'
        '@Command(name = "entry") class CatalogEntryCommand { String options = '
        '"--channel --support-status --security-advisory --maximum-crypta-version"; }\n'
        '@Command(name = "publish-usk") class PublishUskCommand { String dry = "--dry-run"; '
        'String live = "--live"; String insertEnv = "--private-insert-uri-env"; '
        'String insertFile = "--private-insert-uri-file"; String passwordEnv = "--form-password-env"; '
        'String passwordFile = "--form-password-file"; String s = "PublicationPlanWriter '
        'LiveUskPublicationService loadSecureText requires exactly one of --dry-run or --live"; }\n',
        encoding="utf-8",
    )
    (devtools_dir / "AppTemplateKind.java").write_text(
        "static-basic queue-dashboard publisher vault-profile\n",
        encoding="utf-8",
    )
    (devtools_dir / "AppTemplateScaffolder.java").write_text(
        "STATIC_BASIC QUEUE_DASHBOARD PUBLISHER VAULT_PROFILE\n",
        encoding="utf-8",
    )
    (devtools_dir / "AppTestSuite.java").write_text(
        "class AppTestSuite { String s = \"dev.bootstrap-smoke AppTestReport\"; }\n",
        encoding="utf-8",
    )
    (devtools_dir / "DeveloperKeyGenerator.java").write_text(
        "class DeveloperKeyGenerator { String s = \"Ed25519 trusted.keys.version=1\"; }\n",
        encoding="utf-8",
    )
    (devtools_dir / "CatalogEntryDescriptorGenerator.java").write_text(
        "class CatalogEntryDescriptorGenerator { String s = \"artifact.path permissions.rationale. "
        "--channel --support-status --security-advisory maximumCryptaVersion\"; }\n",
        encoding="utf-8",
    )
    (devtools_dir / "PublicationPlanWriter.java").write_text(
        "class PublicationPlanWriter { String s = \"Crypta Catalog USK Publication Plan\"; }\n",
        encoding="utf-8",
    )
    (devtools_dir / "PublicationInputValidator.java").write_text(
        "class PublicationInputValidator { String s = \"crypta:USK@.../ "
        "cryptad-app-catalog.properties cryptad-app-catalog.signature\"; }\n",
        encoding="utf-8",
    )
    (devtools_dir / "LiveUskPublicationService.java").write_text(
        "class LiveUskPublicationService { Object v = PublicationInputValidator.validate(); "
        "String s = \"AppCatalogVerifier.verify requirePrivateInsertUri\"; }\n",
        encoding="utf-8",
    )
    (devtools_dir / "PlatformApiLiveUskPublisher.java").write_text(
        "class PlatformApiLiveUskPublisher { String s = \"queue/inserts/directory sourcePath "
        "insertUri COMPAT_CURRENT content/fetch contentBase64 live_publish_verification_failed "
        "followRedirects(HttpClient.Redirect.NEVER)\"; }\n",
        encoding="utf-8",
    )
    (devtools_dir / "LiveUskPublicationResult.java").write_text(
        "record LiveUskPublicationResult(String catalogSha256, String signatureSha256, "
        "String catalogSigningKeyId, String catalogInsertStatus, "
        "String schedulerRefreshVerificationStatus) {}\n",
        encoding="utf-8",
    )
    (devtools_dir / "LiveUskPublicationResultWriter.java").write_text(
        "class LiveUskPublicationResultWriter { String s = \"catalogSha256 signatureSha256 "
        "catalogSigningKeyId catalogInsertStatus schedulerRefreshVerificationStatus\"; }\n",
        encoding="utf-8",
    )
    devserver_dir = devtools_dir / "devserver"
    devserver_dir.mkdir(parents=True, exist_ok=True)
    (devserver_dir / "CryptaAppDevServer.java").write_text(
        "class CryptaAppDevServer { boolean allowNonLoopback; }\n",
        encoding="utf-8",
    )
    (devserver_dir / "DevServerConfig.java").write_text(
        "class DevServerConfig { String host = \"127.0.0.1\"; }\n",
        encoding="utf-8",
    )
    (devserver_dir / "MockPlatformApi.java").write_text(
        "class MockPlatformApi { String s = \"invalid_app_browser_session X-Crypta-App-Session "
        "/trust-graph/status /trust-graph/anchors /trust-graph/import /trust-graph/score\"; }\n",
        encoding="utf-8",
    )
    toolkit_test_dir = workspace / "platform-devtools/src/test/java/network/crypta/platform/devtools"
    toolkit_test_dir.mkdir(parents=True, exist_ok=True)
    (toolkit_test_dir / "DeveloperBetaToolkitCliTest.java").write_text(
        "void test_whenFreshStaticTemplateCheckedStrict_expectPassingHumanAndJsonReport() {}\n"
        "void catalogEntryAndPublishUsk_whenSignedArtifactsPrepared_expectOfflinePlan() {}\n"
        "void devServer_whenStaticAppServed_expectBootstrapStaticAndSessionProtectedApi() {}\n"
        "void publish_whenFakePublisherSucceeds_expectSanitizedSummaryAndRetainedStaging() {}\n"
        "void publish_whenInsertIsOnlyQueued_expectStagingRetainedWithoutPathInSummary() {}\n"
        "void publish_whenPrivateInsertUriDoesNotMatchPublicSource_expectFailureWithoutPublisherOrSummary() {}\n"
        "String e = \"private insert URI must be configured by exactly one env or file source\";\n"
        "String w = \"staging_sidecars_retained_until_live_insert_completion\";\n"
        "void redaction() { assertFalse(liveSummaryText.contains(LIVE_PRIVATE_INSERT_URI)); }\n",
        encoding="utf-8",
    )
    (toolkit_test_dir / "LiveUskPublicationServiceTest.java").write_text(
        "void publish_whenFakePublisherSucceeds_expectSanitizedSummaryAndRetainedStaging() {}\n",
        encoding="utf-8",
    )
    (toolkit_test_dir / "PublicationPlanWriterTest.java").write_text(
        "void write_whenDryRun_expectPlan() {}\n",
        encoding="utf-8",
    )
    (docs / DEVELOPER_BETA_TOOLKIT_DOC.name).write_text(
        "crypta-app init --template queue-dashboard\n"
        "crypta-app dev --bundle-dir .\n"
        "crypta-app test --bundle-dir . --strict\n"
        "crypta-app keys generate\n"
        "crypta-app catalog entry\n"
        "crypta-app publish-usk --dry-run\n"
        "crypta-app publish-usk --live --private-insert-uri-env CRYPTAD_FIRST_PARTY_CATALOG_INSERT_URI "
        "--form-password-env CRYPTAD_CERT_FORM_PASSWORD\n"
        "The private insert URI is secret, cryptad-app-catalog.signature is published at the same USK, "
        "and dry-run remains available.\n",
        encoding="utf-8",
    )
    (workspace / APP_UI_DESIGN_SYSTEM_DOC).write_text(
        "crypta-platform.js loads before app.js. Static apps load crypta-ui-tokens.css, "
        "crypta-ui.css, then app.css. Use cr-shell and cr-button classes. "
        "Content-Security-Policy includes connect-src. Accessibility requires aria labels. "
        "Permission disclosure mirrors app.permissions. Run crypta-app ui lint --bundle-dir. "
        "First-party Queue Manager, Publisher, Site Publisher, and Profile Publisher use this guidance. Warnings "
        "become failure in release-candidate evidence.\n",
        encoding="utf-8",
    )
    sandbox_dir = workspace / "platform-apphost/src/main/java/network/crypta/platform/apphost/sandbox"
    sandbox_test_dir = workspace / "platform-apphost/src/test/java/network/crypta/platform/apphost/sandbox"
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    sandbox_test_dir.mkdir(parents=True, exist_ok=True)
    (sandbox_dir / "BubblewrapSandboxProvider.java").write_text(
        'class BubblewrapSandboxProvider { static final String PROVIDER_NAME = "bubblewrap"; '
        'Object level = AppSandboxSupportLevel.ENFORCED; Object env = checkedContext.environment(); '
        'String docs = "path-free status"; }\n',
        encoding="utf-8",
    )
    (sandbox_dir / "BubblewrapCommandBuilder.java").write_text(
        'class BubblewrapCommandBuilder { void command() { command.add("--die-with-parent"); '
        'command.add("--new-session"); command.add("--unshare-pid"); command.add("--unshare-ipc"); '
        'command.add("--ro-bind"); command.add("--bind"); command.add("--"); } }\n',
        encoding="utf-8",
    )
    (sandbox_dir / "BubblewrapAvailability.java").write_text(
        "class BubblewrapAvailability { }\n", encoding="utf-8"
    )
    (sandbox_dir / "AppSandboxProviders.java").write_text(
        "class AppSandboxProviders { BubblewrapSandboxProvider provider; }\n", encoding="utf-8"
    )
    (sandbox_test_dir / "BubblewrapSandboxProviderTest.java").write_text(
        "class BubblewrapSandboxProviderTest { void prepareLaunch_whenContextContainsToken_expectCommandDoesNotExposeEnvironmentValues() { "
        "String commandText = \"--die-with-parent --new-session --unshare-pid --unshare-ipc --ro-bind --bind CRYPTAD_APP_TOKEN\"; "
        "assertFalse(commandText.contains(\"secret-token\")); } }\n",
        encoding="utf-8",
    )
    (sandbox_test_dir / "AppSandboxProvidersTest.java").write_text(
        "class AppSandboxProvidersTest { void providers_whenRequiredRestrictedProcessBubblewrapPreflightFails_expectFailClosed() {} "
        "void providers_whenRequiredRestrictedProcessBubblewrapUnavailable_expectFailClosed() {} "
        "String name = \"PreflightFails RequiredRestrictedProcess expectFailClosed\"; }\n",
        encoding="utf-8",
    )
    apphost = workspace / "platform-apphost/src/main/java/network/crypta/platform/apphost/runtime/LocalProcessAppHost.java"
    apphost.parent.mkdir(parents=True, exist_ok=True)
    uninstall_options = workspace / "platform-apphost/src/main/java/network/crypta/platform/apphost/AppUninstallOptions.java"
    uninstall_options.parent.mkdir(parents=True, exist_ok=True)
    uninstall_options.write_text(
        "record AppUninstallOptions(boolean preserveData) {}\n",
        encoding="utf-8",
    )
    apphost.write_text(
        """
class LocalProcessAppHost {
  private static final String BASE_UNIX_PATH_ENTRIES = "/usr/bin:/bin";
  private static final String TEMP_UPDATE_BACKUP_PREFIX = "app-install-backup-";
  private static final String TEMP_ROLLBACK_BACKUP_PREFIX = "app-rollback-backup-";
  InstalledAppSnapshot updateFromDirectory(String appId, Path stagedAppDirectory) throws IOException {
    if (liveRunningProcess(normalizedAppId) != null) {
      throw new AppHostException("cannot update a running app: " + normalizedAppId);
    }
    Path rollbackAppsDir = ensureRollbackAppsDirectory();
    Path backupInstallRoot = temporaryManagedPath(installedAppsDir, TEMP_UPDATE_BACKUP_PREFIX + normalizedAppId + "-");
    Path rollbackRoot = rollbackRootFor(normalizedAppId);
    Path previousRollbackBackupRoot = temporaryManagedPath(rollbackAppsDir, TEMP_ROLLBACK_BACKUP_PREFIX + normalizedAppId + "-");
    copyDirectoryTree(stagingRoot, temporaryInstallRoot);
    verifyCopiedBundle(temporaryInstallRoot);
    AppManifest manifest = validateCopiedBundle(temporaryInstallRoot);
    requireMatchingUpdateTarget(normalizedAppId, manifest);
    replaceInstalledBundle(paths.installedRoot(), temporaryInstallRoot, backupInstallRoot, rollbackRoot, previousRollbackBackupRoot);
    cancelPendingRestartAfterAcceptedUpdate(normalizedAppId);
    return new InstalledAppSnapshot(manifest, paths);
  }
  Optional<AppRollbackRecord> rollbackStatus(String appId) throws IOException {
    return Optional.of(new AppRollbackRecord(appId));
  }
  InstalledAppSnapshot rollback(String appId) throws IOException {
    if (liveRunningProcess(normalizedAppId) != null) {
      throw new AppHostException("cannot rollback a running app: " + normalizedAppId);
    }
    Path rollbackRoot = rollbackRootFor(normalizedAppId);
    Path currentInstallBackupRoot = temporaryManagedPath(installedAppsDir, TEMP_UPDATE_BACKUP_PREFIX + normalizedAppId + "-");
    swapInstalledBundleWithRollback(paths.installedRoot(), rollbackRoot, currentInstallBackupRoot);
    return new InstalledAppSnapshot(manifest, paths);
  }
  void uninstall(String appId, AppUninstallOptions options) {
    if (!options.preserveData()) {
      deleteAppData(appId);
    }
  }
  void deleteAppData(String appId) {}
  void populateEnvironment(Map<String, String> environment) {
    environment.clear();
    environment.put("PATH", safeUnixPath());
    environment.put("CRYPTAD_APP_ID", "sample-app");
    environment.put("CRYPTAD_APP_TOKEN", "token");
    environment.put("CRYPTAD_APP_PERMISSIONS", "content.fetch");
    environment.put("CRYPTAD_APP_UI_MODE", "static");
  }
  String safeUnixPath() { return BASE_UNIX_PATH_ENTRIES; }
  private Path rollbackRootFor(String appId) { return layout.rollbackAppsDir().resolve(appId); }
  private Path ensureRollbackAppsDirectory() { return layout.rollbackAppsDir(); }
  private void replaceInstalledBundle(Path installedRoot, Path replacementRoot, Path backupRoot, Path rollbackRoot, Path previousRollbackBackupRoot) throws IOException {
    moveIntoPlace(installedRoot, backupRoot);
    try {
      moveIntoPlace(replacementRoot, installedRoot);
      moveIntoPlace(backupRoot, rollbackRoot);
    } catch (IOException updateFailure) {
      restoreInstalledBundle(installedRoot, backupRoot, updateFailure);
      restorePreviousRollback(rollbackRoot, previousRollbackBackupRoot, true, updateFailure);
      throw updateFailure;
    }
    deleteBackupAfterSuccessfulReplacement(previousRollbackBackupRoot, true);
  }
  private void swapInstalledBundleWithRollback(Path installedRoot, Path rollbackRoot, Path currentInstallBackupRoot) throws IOException {
    moveIntoPlace(installedRoot, currentInstallBackupRoot);
    moveIntoPlace(rollbackRoot, installedRoot);
    moveIntoPlace(currentInstallBackupRoot, rollbackRoot);
  }
  private void deleteBackupAfterSuccessfulReplacement(Path backupRoot, boolean backupPresent) throws IOException {
    throw new IOException("simulated backup cleanup failure");
  }
  private static void restoreInstalledBundle(Path installedRoot, Path backupRoot, IOException updateFailure) throws IOException {
    moveIntoPlace(backupRoot, installedRoot);
  }
  private static void restorePreviousRollback(Path rollbackRoot, Path backupRoot, boolean backupPresent, IOException updateFailure) throws IOException {
  }
}
""",
        encoding="utf-8",
    )
    apphost_test = (
        workspace
        / "platform-apphost/src/test/java/network/crypta/platform/apphost/runtime/LocalProcessAppHostTest.java"
    )
    apphost_test.parent.mkdir(parents=True, exist_ok=True)
    apphost_test.write_text(
        """
class LocalProcessAppHostTest {
  void populateEnvironment_whenHostEnvironmentContainsSecrets_expectSanitizedChildEnvironment() {
    String names = "JAVA_TOOL_OPTIONS LD_PRELOAD AWS_SECRET_ACCESS_KEY OPENAI_API_KEY SSH_AUTH_SOCK PRIVATE_KEY CRYPTAD_APPHOST_BWRAP";
  }
  void updateFromDirectory_whenInstalledStoppedApp_expectManifestAndExecutableReplacedPreservingMutableDirs() {
    String data = "preserve-data.txt";
    String cache = "preserve-cache.txt";
    String run = "preserve-run.txt";
  }
  void updateFromDirectory_whenReplacingStoppedApp_expectPreviousBundleRecordedForRollback() {
    AtomicInteger cleanupAttempts = new AtomicInteger();
    LocalProcessAppHost host = allowUnsignedHost(_ -> {
      cleanupAttempts.incrementAndGet();
      throw new IOException("simulated backup cleanup failure");
    });
    Path firstUpdatedStage =
        stageInstalledAppAt(tempDir.resolve(STAGE_UPDATE_DIR_NAME).resolve("first").resolve(SAMPLE_APP_ID));
    InstalledAppSnapshot firstUpdate = host.updateFromDirectory(SAMPLE_APP_ID, firstUpdatedStage);
    assertEquals(0, cleanupAttempts.get());
    Path secondUpdatedStage =
        stageInstalledAppAt(tempDir.resolve(STAGE_UPDATE_DIR_NAME).resolve("second").resolve(SAMPLE_APP_ID));
    host.updateFromDirectory(SAMPLE_APP_ID, secondUpdatedStage);
    assertEquals(
        firstUpdate.manifest().appVersion(),
        host.rollbackStatus(SAMPLE_APP_ID).orElseThrow().appVersion());
    assertEquals(1, cleanupAttempts.get());
  }
  void rollback_whenPreviousBundleExists_expectRestoresBundleAndPreservesMutableDirs() {
    String data = "rollback-data.txt";
    String cache = "rollback-cache.txt";
    String run = "rollback-run.txt";
  }
  void rollback_whenAppIsRunning_expectFailureAndInstalledBundleUnchanged() {}
  void rollbackStatus_whenRecordExists_expectMetadataOmitsTokensAndHostPaths() {}
}
""",
        encoding="utf-8",
    )
    appupdates_dir = workspace / "platform-api/src/main/java/network/crypta/platform/api/appupdates"
    appupdates_dir.mkdir(parents=True, exist_ok=True)
    (appupdates_dir / "AppUpdatePolicyMode.java").write_text(
        """
enum AppUpdatePolicyMode {
  MANUAL("manual"),
  STAGE("stage"),
  APPLY_WHEN_STOPPED("apply_when_stopped");
}
""",
        encoding="utf-8",
    )
    (appupdates_dir / "AppUpdateCandidateStatus.java").write_text(
        """
enum AppUpdateCandidateStatus {
  AVAILABLE("available"),
  STAGED("staged"),
  BLOCKED("blocked"),
  INCOMPATIBLE("incompatible"),
  AMBIGUOUS("ambiguous"),
  ROLLBACK_AVAILABLE("rollback_available");
}
""",
        encoding="utf-8",
    )
    (appupdates_dir / "AppUpdateCandidate.java").write_text(
        """
record AppUpdateCandidate() {
  Map<String, Object> toJsonValue() {
    json.put("channel", channel);
    json.put("supportStatus", supportStatus);
    json.put("securityAdvisories", securityAdvisories);
    json.put("allowedChannels", allowedChannels);
    json.put("review", review);
    json.put("apiCompatibility", apiCompatibility);
    json.put("permissionDelta", permissionDelta(candidatePermissions, installedPermissions));
    json.put("dataMigration", dataMigration);
    return json;
  }
  boolean dataMigrationAllowsAutomaticStage() { return dataMigration.get("blockReason") == null; }
  static Map<String, Object> reviewSummary(String status, String note) { return Map.of(); }
  static Map<String, Object> permissionDelta(List<String> candidatePermissions, List<String> local) { return Map.of(); }
}
""",
        encoding="utf-8",
    )
    (appupdates_dir / "AppDataMigrationPlan.java").write_text(
        """
record AppDataMigrationPlan() {
  static final String STATUS_MISSING_MIGRATION = "missing_migration";
	  Map<String, Object> toJsonValue() {
	    json.put("dataMigration", this);
	    json.put("namespaces", namespaces);
	    json.put("blockReason", blockReason);
	    json.put("requiresStopped", requiresStopped);
	    return json;
	  }
	  record NamespaceStep(String namespace, int from, int to, String stepId, boolean rollbackCompatible, boolean requiresStopped) {}
	}
""",
        encoding="utf-8",
    )
    (appupdates_dir / "AppDataMigrationRunner.java").write_text(
        """
	interface AppDataMigrationRunner {
	  int MAX_CAPTURE_BYTES = 4096;
	  enum Mode { DRY_RUN, APPLY }
		  interface MigrationDataAccess {}
		  default void run(Path bundleRoot, AppDataMigrationPlan plan, Mode mode, MigrationDataAccess dataAccess) throws IOException {
		    ProcessBuilder builder = new ProcessBuilder(commandLine(command));
		    new AppEnv();
		    ProcessBoundary boundary = ProcessBoundary.detect(appEnv);
		    boundary.commandLine(command);
		    return unsupported();
		    String executable = "migration command is not executable";
		    String processGroups = "Process groups alone are not sufficient";
		    String blocker = "migration process containment is unavailable";
		    long timeout = OUTPUT_DRAIN_TIMEOUT_MILLIS;
		    builder.environment().clear();
		    builder.environment().put("CRYPTA_APP_MIGRATION_MODE", "dry-run");
	    builder.environment().put("CRYPTA_APP_MIGRATION_NAMESPACE", "feeds");
    builder.environment().put("CRYPTA_APP_MIGRATION_INPUT", input.toString());
    builder.environment().put("CRYPTA_APP_MIGRATION_OUTPUT", output.toString());
  }
	}
	""",
        encoding="utf-8",
    )
    (appupdates_dir / "AppUpdatePolicy.java").write_text(
        """
class AppUpdatePolicy {
  static final Set<AppCatalogChannel> DEFAULT_ALLOWED_CHANNELS = Set.of(AppCatalogChannel.STABLE);
  boolean allowsAutomaticChannel(AppCatalogChannel channel) { return channel != AppCatalogChannel.DEPRECATED; }
  Map<String, Object> toJsonValue() { json.put("allowedChannels", DEFAULT_ALLOWED_CHANNELS); return json; }
}
""",
        encoding="utf-8",
    )
    (appupdates_dir / "AppUpdateService.java").write_text(
        """
class AppUpdateService {
  static final String ERROR_CHANNEL_POLICY_BLOCKED = "channel_policy_blocked";
	  static final String ERROR_APP_DATA_MIGRATION_MISSING = "app_data_migration_missing";
	  static final String ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED = "app_data_migration_dry_run_failed";
	  static final String ERROR_APP_DATA_MIGRATION_REVIEW_REQUIRED = "app_data_migration_review_required";
	  static final String ERROR_APP_DATA_MIGRATION_REQUIRES_STOPPED = "app_data_migration_requires_stopped";
	  static final String ERROR_APP_DATA_MIGRATION_SANDBOX_UNAVAILABLE = "app_data_migration_sandbox_unavailable";
	  AppUpdateService.SchedulerSummaryProvider schedulerSummaryProvider;

  public synchronized Map<String, Object> check(String appId, boolean includeStaged) {
    return summary(appId, installed);
  }

  public synchronized Map<String, Object> stage(String appId) {
    AppUpdateCandidate candidate = candidateOrDetect(appId, installed);
    AppCatalogInstallPlan plan = catalogManager.prepareInstallPlan(candidate.catalogId(), appId);
    if (planDiffersFromCandidate(candidate, installed, plan)) {
      throw new PlatformApiException(409, "update_candidate_changed", "changed");
    }
    AppDataMigrationPlan migrationPlan = buildMigrationPlan(appId, installed.manifest(), targetManifest);
    boolean sandboxBlock =
        targetManifest.sandboxPolicy().required()
            && targetManifest.sandboxPolicy().mode() != AppSandboxMode.NONE;
    if (migrationPlan.hasBlocker()) throw new PlatformApiException(409, ERROR_APP_DATA_MIGRATION_MISSING, "missing");
	    if (migrationPlan.operatorReviewRequired() && !migrationAcknowledged) {
	      throw new PlatformApiException(409, ERROR_APP_DATA_MIGRATION_REVIEW_REQUIRED, "review");
	    }
	    verifyStagedBundleBeforeStageDryRun(appId, candidate, plan);
	    migrationRunner.run(plan.stagedBundleDirectory(), migrationPlan, AppDataMigrationRunner.Mode.DRY_RUN, migrationDataAccess(appId, targetManifest));
	    if (!dryRunResult.success()) throw new PlatformApiException(409, ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED, "dry run");
	    bestMigrationPath(namespace, currentVersion, targetVersion, migrations);
    stageCandidate(appId, installed, candidate);
    stagedUpdates.put(appId, new StagedUpdate(candidate, plan, migrationPlan, Instant.now()));
    return summary(appId, installed);
  }

		  public synchronized Map<String, Object> apply(String appId, ApplyOptions options) {
	    verifyStagedBundleBeforeApply(staged);
	    if (shouldHoldApplyMigrationWriteBarrier(targetManifest)) {
	      targetManifest.dataSchemaContract().declared();
	      beginUpdateMigrationWriteBarrier(normalizedAppId);
	    }
	    if (migrationPlan.required()) {
	      runApplyDryRunOrReject(staged, migrationPlan, targetManifest);
	      targetManifest.dataQuotaBytes();
	      verifyStagedBundleAfterApplyDryRun(staged);
	      beginUpdateMigrationWriteBarrier(normalizedAppId);
	      appDataSnapshot = createUpdateSnapshot(normalizedAppId);
	    }
    InstalledAppSnapshot updated =
        appHost.updateFromDirectory(normalizedAppId, staged.stagedBundleDirectory());
    runApplyMigrationOrRollback(normalizedAppId, updated, migrationPlan, appDataSnapshot, healthFailureState);
    rollbackAndRestoreSnapshot(normalizedAppId, healthFailureState, appDataSnapshot);
	    appDataService.restoreUpdateSnapshot(normalizedAppId, appDataSnapshot);
	    healthFailureState.markRollbackFailed();
	    closeUpdateMigrationWriteBarrier(barrier);
	    closeStage(normalizedAppId);
	    return summary(normalizedAppId, updated);
	  }

		  void verifyStagedBundleBeforeApply(StagedUpdate staged) {
		    catalogManager.verifyInstallPlan(staged.plan());
		  }

	  boolean shouldHoldApplyMigrationWriteBarrier(AppManifest targetManifest) {
	    return targetManifest.dataSchemaContract().declared();
	  }

  void verifyStagedBundleBeforeStageDryRun(String appId, AppUpdateCandidate candidate, AppCatalogInstallPlan plan) {
    catalogManager.verifyInstallPlan(plan);
  }

  boolean isAutomaticPolicyMigrationSkip(String errorCode) {
    return ERROR_APP_DATA_MIGRATION_MISSING.equals(errorCode)
        || ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED.equals(errorCode)
        || ERROR_APP_DATA_MIGRATION_REVIEW_REQUIRED.equals(errorCode)
        || ERROR_APP_DATA_MIGRATION_REQUIRES_STOPPED.equals(errorCode)
        || ERROR_APP_DATA_MIGRATION_SANDBOX_UNAVAILABLE.equals(errorCode);
  }

	  void recordMigrationDryRunFailure(String appId, AppUpdateCandidate candidate, AppDataMigrationPlan plan, String errorCode) {
	    if (ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED.equals(errorCode)) {
	      candidates.put(appId, candidateWithMigrationPlan(candidate, plan.withDryRunFailed()));
	    }
  }

		  Map<String, Object> summary(String appId, InstalledAppSnapshot installed) {
    json.put("scheduler", schedulerSummaryProvider.schedulerSummary(appId));
    json.put("dataMigration", migrationPlan.toJsonValue());
    if (productionMetadata.deprecatedForAutomaticUpdates()) {
      throw new PlatformApiException(409, ERROR_CHANNEL_POLICY_BLOCKED, "blocked");
    }
    AppReviewReceiptVerifier.evaluate(entry, keys, policy, now);
    return json;
  }

  void closeMigrationScratch() {
    try {
      deleteRecursively(root);
    } catch (IOException _) {
      // Migration scratch cleanup is best effort; command success is reported separately.
    }
  }
}
""",
        encoding="utf-8",
    )
    (appupdates_dir / "AppUpdateSchedulerConfig.java").write_text(
        """
class AppUpdateSchedulerConfig {
  static final String ENABLED_ENV = "CRYPTAD_APPUPDATES_SCHEDULER_ENABLED";
  static final String APP_CHECK_INTERVAL_PROPERTY = "cryptad.appupdates.scheduler.appCheckIntervalSeconds";
  static AppUpdateSchedulerConfig defaults() {
    return new AppUpdateSchedulerConfig(
        true,
        Duration.ZERO,
        Duration.ofSeconds(120),
        Duration.ofSeconds(60),
        Duration.ZERO,
        Duration.ofSeconds(30),
        Duration.ofSeconds(300));
  }
  static AppUpdateSchedulerConfig from(Map<?, ?> properties, Map<String, String> environment) {
    return defaults();
  }
}
""",
        encoding="utf-8",
    )
    (appupdates_dir / "AppUpdateSchedulerState.java").write_text(
        """
class AppUpdateSchedulerState {
  Map<String, Object> toJsonValue() {
    json.put("lastCheckAt", lastCheckAt);
    json.put("nextCheckAt", nextCheckAt);
    json.put("failureCount", failureCount);
    json.put("lastErrorCode", lastErrorCode);
    json.put("concurrency", "per-app-serialized");
    return json;
  }
  // catalog scratch paths and staged bundle path values are never exposed here.
}
""",
        encoding="utf-8",
    )
    (appupdates_dir / "FileAppUpdateSchedulerStore.java").write_text(
        """
public final class FileAppUpdateSchedulerStore {
  void write(Path source, Path target) throws IOException {
    Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
  }
}
""",
        encoding="utf-8",
    )
    (appupdates_dir / "AppUpdateScheduler.java").write_text(
        """
public final class AppUpdateScheduler {
  private final AppUpdateSchedulerConfig config;
  private final AppUpdateSchedulerStore store;
  private final AtomicBoolean running = new AtomicBoolean();
  private static final String ERROR_CATALOG_REFRESH_FAILED = "catalog_refresh_failed";
  private static final String MESSAGE_CATALOG_REFRESH_FAILED =
      "Scheduler catalog refresh failed; cached verified catalogs remain in use.";
  private static final String MESSAGE_APP_CHECK_FAILED = "Scheduler update check failed.";
  // Manual remains the default; the scheduler discovers candidates and refreshes live USK catalog sources.
  AppUpdateSchedulerTickResult tick(Instant now) {
    if (!running.compareAndSet(false, true)) {
      return AppUpdateSchedulerTickResult.alreadyRunning(now);
    }
    for (AppCatalogSourceSnapshot catalog : catalogManager.listCatalogs()) {
      catalogManager.refresh(catalog.catalogId());
    }
    updateService.check(state.appId(), false);
    return result;
  }
}
""",
        encoding="utf-8",
    )
    (appupdates_dir / "AppUpdatesApiHandler.java").write_text(
        """
class AppUpdatesApiHandler {
  public Map<String, Object> stage(String appId) {
    return updateService.stage(appId);
  }

  public Map<String, Object> stage(String appId, Map<String, List<String>> queryParameters) {
    boolean migrationAcknowledged = true;
    return updateService.stage(appId, reviewAcknowledged, migrationAcknowledged);
  }

  public Map<String, Object> apply(String appId, Map<String, List<String>> queryParameters) {
    return updateService.apply(appId, applyOptions(queryParameters));
  }
}
""",
        encoding="utf-8",
    )
    appupdates_test_dir = workspace / "platform-api/src/test/java/network/crypta/platform/api/appupdates"
    appupdates_test_dir.mkdir(parents=True, exist_ok=True)
    (appupdates_test_dir / "AppUpdateServiceTest.java").write_text(
        """
class AppUpdateServiceTest {
  void apply_whenAppStartsAfterPrecheck_expectConflictNotServerError() {
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory()))
        .thenThrow(new AppHostException("cannot update a running app: " + APP_ID));
    assertEquals("app_running", exception.errorCode());
  }
		  void stage_whenSchemaIncreaseHasNoMigrationStep_expectBlockedBeforeBundleReplacement() {}
			  void apply_whenMigrationRequiredAndRunnerPasses_expectSnapshotApplyAndSchemaMetadata() {}
			  void apply_whenAppDataWriteAttemptsDuringMigrationWindow_expectWriteRejectedAndBarrierReleased() {}
			  void apply_whenAppDataWriteAttemptsDuringFinalMigrationDryRun_expectWriteRejected() {}
			  void apply_whenStagedMigrationBundleVerificationFails_expectDryRunBlockedBeforeRunner() {}
			  void apply_whenMigrationDryRunMutatesStagedBundle_expectReverifiedBeforeInstall() {}
			  void stage_whenTargetManifestRaisesDataQuota_expectDryRunUsesTargetQuota() {}
		  void apply_whenChainedMigrationRunner_expectEachStepAppliedBeforeNextStep() {}
		  void apply_whenMigrationContractHasNoExistingDataAndWriteAppearsBeforeReplacement_expectWriteRejected() {}
		  void apply_whenMigrationApplyFailsAndBundleRollbackFails_expectMigrationFailurePreserved() {}
		  void stage_whenMigrationRollbackIncompatibleWithoutAcknowledgement_expectReviewRequired() {}
			  void stage_whenStoppedRequiredMigrationAndAppRunning_expectBlockedBeforeDryRun() {}
			  void check_whenStagePolicyMigrationPathMissing_expectCandidateSummaryWithoutCheckFailure() {}
			  void check_whenStagePolicyMigrationDryRunFails_expectCandidateSummaryWithoutCheckFailure() {}
			  void check_whenStagePolicyMigrationDryRunThrows_expectCandidateSummaryWithoutCheckFailure() {}
			  void check_whenApplyWhenStoppedPolicyMigrationDryRunFails_expectCandidateSummaryWithoutApply() {}
			  void stage_whenMigrationBundleRequestsOptionalSandbox_expectDryRunAndStage() {}
		  void check_whenApplyWhenStoppedPolicySandboxMigration_expectCandidateSummaryWithoutApply() {}
		  void stage_whenStagedMigrationBundleVerificationFails_expectDryRunBlockedBeforeRunner() {}
		  void stage_whenMigrationHasDeadEndBranch_expectCompletePathSelected() {}
	  void stage_whenCompatibleChainCompetesWithIncompatibleDirectStep_expectCompatiblePathSelected() {}
	}
	""",
        encoding="utf-8",
    )
    (appupdates_test_dir / "AppDataMigrationRunnerTest.java").write_text(
        "class AppDataMigrationRunnerTest { "
        "void run_whenOnlyProcessGroupCleanupCouldBeBypassed_expectFailsClosedBeforeCommand() {} "
        "void run_whenProcessBoundaryUnavailable_expectFailsClosedBeforeCommand() {} "
        "void run_whenMigrationCommandIsNotExecutable_expectFailsBeforeCompletion() {} }\n",
        encoding="utf-8",
    )
    (appupdates_test_dir / "AppUpdateSchedulerConfigTest.java").write_text(
        """
class AppUpdateSchedulerConfigTest {
  void from_whenValuesMalformed_expectDefaultsRetained() {}
}
""",
        encoding="utf-8",
    )
    (appupdates_test_dir / "AppUpdateSchedulerTest.java").write_text(
        """
class AppUpdateSchedulerTest {
  void tick_whenCatalogAndAppAreDue_expectRefreshOnceThenDelegatesCheck() {
    Object order = inOrder(catalogManager, updateService);
  }
  void tick_whenManualPolicy_expectCheckOnlyAndNoStageOrApply() {
    verify(catalogManager, never()).prepareInstallPlan(eq(CATALOG_ID), eq(APP_ID));
    verify(appHost, never()).updateFromDirectory(eq(APP_ID), eq(tempDir));
  }
  void tick_whenStagePolicy_expectVerifiedCandidateStagedByServicePolicy() {}
  void tick_whenApplyWhenStoppedPolicy_expectStoppedAppAppliedByServicePolicy() {}
  void tick_whenApplyWhenStoppedPolicyAndAppRunning_expectRunningAppNotStoppedOrUpdated() {
    String message = "Policy skipped apply because the app is running.";
  }
  void tick_whenCheckFails_expectSanitizedFailureAndBackoff() {}
  void tick_whenCatalogRefreshFails_expectFailureContainedAndAppsStillChecked() {}
  void summary_whenSchedulerStatePresent_expectPathFreeSchedulerSummary() {
    String token = "secret-token";
    assertFalse(summary.toString().contains(tempDir.toString()));
  }
}
""",
        encoding="utf-8",
    )
    runtime_source = (
        workspace
        / "bridge-http-runtime/src/main/java/network/crypta/clients/http/bridge/CoreHttpShellRuntimeSupport.java"
    )
    runtime_source.parent.mkdir(parents=True, exist_ok=True)
    runtime_source.write_text(
        """
class CoreHttpShellRuntimeSupport {
  AppUpdateScheduler createAppUpdateScheduler() {
    return new AppUpdateScheduler(layout.dataDir().resolve("apps").resolve("update-scheduler"));
  }
  ContentSubscriptionService contentSubscriptionService() { return contentSubscriptionService; }
  ContentSubscriptionService createContentSubscriptionService() {
    return new ContentSubscriptionService(
      new FileContentSubscriptionStore(layout.dataDir().resolve("apps").resolve("content-subscriptions")));
  }
  AppDataService createAppDataService() {
    return new AppDataService(
      new FileAppDataStore(layout.dataDir().resolve("apps").resolve("durable-app-data")),
      appHost, config, true);
  }
  TrustGraphApiHandler createTrustGraphApiHandler() {
    return new TrustGraphApiHandler(
      new FileTrustGraphStore(layout.dataDir().resolve("apps").resolve("trust-graph")));
  }
  AppServiceCoordinator createAppServiceCoordinator() {
    return new AppServiceCoordinator(
      new FileAppServiceGrantStore(layout.dataDir().resolve("apps").resolve("app-services")),
      new TrustGraphScoreAppServiceAdapter(createTrustGraphApiHandler()));
  }
  ContentSubscriptionScheduler createContentSubscriptionScheduler() {
    return new ContentSubscriptionScheduler(contentSubscriptionService);
  }
  void wire() {
    appUpdateService.setSchedulerSummaryProvider(appUpdateScheduler::summary);
    appUpdateScheduler.start();
    contentSubscriptionScheduler.start();
  }
  Thread createAppUpdateSchedulerShutdownJob() { return new Thread(appUpdateScheduler::close); }
  Thread createContentSubscriptionSchedulerShutdownJob() {
    return new Thread(contentSubscriptionScheduler::close);
  }
}
""",
        encoding="utf-8",
    )
    web_shell = (
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    web_shell.parent.mkdir(parents=True, exist_ok=True)
    web_shell.write_text(
        """
function renderRecommendedCatalogs(){}
function renderRecommendedCatalogCard(){}
const legacySecurityLevelsPath = normalizeLocalPath(bootstrap.legacySecurityLevelsPath, "/seclevels/");
const legacySecurityLevelsFallbackPath = legacySecurityLevelsPath + "?legacyFallback=security-levels";
const recommendedCatalogPath = "app-catalogs/recommended";
const recommendedCatalogAction = "addRecommended";
const catalogChannelSelect = "catalog-channel-select";
function catalogAppChannel(app){}
function securityAdvisoryListNode(values){}
const deprecatedCatalogClass = "is-deprecated-channel";
function appServiceGrantPath(){}
function setSecurityLegacyFallbackStatus(){ return "Open the legacy security page"; }
function renderSecurityLegacyFallbackAction(){ return "Open legacy password and recovery forms"; }
sections.security.append(renderSecurityLegacyFallbackAction());
const appServiceTitle = "App-service grants";
const approve = "Approve";
const revoke = "Revoke";
const renewBundle = "Renew bundle";
const safeSubjectHash = "subjectUriHash";
function renderAppServiceDependencyGraph(graph){}
function renderAppServiceBundleCard(bundle){}
apiUrl("app-services");
apiUrl("app-services/grants");
apiUrl("app-services/dependencies");
apiUrl("app-services/grant-bundles");
apiUrl("app-services/audit?limit=12");
function registeredAppUiOrigin(app){ return "http://127.0.0.1:1234"; }
function safeSameOriginAppUiHref(url, allowIsolatedLaunchParameter){ return "/apps/demo/"; }
function normalizeLaunchFallbackHref(value){}
function normalizeIsolatedLaunchHref(value){}
function normalizeIsolatedProbeHref(value, expectedOrigin){}
const originPolicy = 'url.username url.password url.search !== "" url.hash !== "" /apps/';
fetch("/.well-known/cryptad-origin.json", { credentials: "omit", mode: "cors" });
definitionList([
  ["Scheduler status", scheduler.status],
  ["Scheduler failures", scheduler.failureCount],
  ["Last scheduler error", scheduler.lastErrorCode],
  ["App-data migration blocker", migrationBlockerSummary(dataMigration)],
]);
const migrationTitle = "App-data migration plan";
const migrationAcknowledged = "migrationAcknowledged";
const migrationStepList = "migration-step-list";
const storedCatalogChannel = window.localStorage.getItem("catalogChannel");
function downloadAllAppDataBackup(){ return postForm("operator/app-data/backups", new FormData()); }
function submitAppDataRestoreForm(form, restoreAction, statusSetter){}
function setBetaDashboardStatus(message){}
function downloadJsonBlob(value, fileName){ new Blob([`${formatJson(value)}\\n`]); }
function urlSafeBase64ToBytes(value){ return value; }
function appDataBackupPayloadBlob(response){ const payloadBase64 = response.payloadBase64; return new Blob([urlSafeBase64ToBytes(payloadBase64)]); }
function downloadAppDataBackupPayload(response, fallbackScope, appId){ downloadBlob(appDataBackupPayloadBlob(response)); }
downloadAppDataBackupPayload(response, "all-apps", "");
downloadAppDataBackupPayload(response, "single-app", appId);
function appDataBackupFormDataForApp(appId){ const formData = new FormData(); formData.set("appId", appId); return formData; }
function allAppDataBackupFormData(){ const formData = new FormData(); formData.set("scope", "all"); return formData; }
apiUrl("operator/app-data/restore/plan");
apiUrl("operator/app-data/restore");
const appDataRestoreFields = "payloadBase64 replaceNamespace replaceApp backupPayload Export backup before delete";
""",
        encoding="utf-8",
    )
    web_shell.write_text(
        web_shell.read_text(encoding="utf-8")
        + """
let betaDashboardLoadGeneration = 0;
let supportBundleSnapshot = null;
function renderBetaDashboard(data){}
function renderBetaCatalogs(catalogs){}
function renderBetaApps(apps){}
function renderBetaSubscriptions(subscriptions){}
function renderBetaTrustAndServices(trustGraph, appServices){}
const trustPreviewTitle = "Trust Graph Local RC";
const trustScopeText = "Local trust only; it is not global truth, not moderation, not blocking, "
  + "not routing policy, no legacy WoT, no global moderation, and no crawling.";
const trustScopeFields = "scope statementLifecycle localAnchorsOnly importedStatementsOnly "
  + "noCrawling noGlobalModeration noBlocking noRoutingDecisions noLegacyWoTCompatibility";
function renderBetaRecoveryActions(actions){}
function operatorRecoveryActionVisible(action){ const actionId = "preserve-data-uninstall"; return actionId !== "preserve-data-uninstall"; }
function loadBetaDashboardSection(){ loadJson(apiUrl("operator/beta-dashboard")); }
function loadSupportBundle(){ loadJson(apiUrl("operator/support-bundle")); supportBundleSnapshot = {}; }
function downloadSupportBundle(){}
function copySupportSummary(){}
function submitOperatorRecoveryAction(form){}
sections.betaDashboard.addEventListener("submit", async () => submitOperatorRecoveryAction(form));
const quotaText = ["Quota warnings", "Data quota"];
const quotaCheck = "quota.dataOverLimit || quota.cacheOverLimit";
""",
        encoding="utf-8",
    )
    web_shell_index = (
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/index.html"
    )
    web_shell_index.write_text(
        '<article id="beta-dashboard"><div id="beta-dashboard-body"></div>'
        '<button id="support-bundle-download-button">Download support JSON</button>'
        '<button id="all-app-data-backup-button">Download all app-data backup</button>'
        '<form id="operator-app-data-restore-form">'
        '<label>Sensitive backup payload</label><textarea name="backupPayload"></textarea>'
        '</form></article>\n',
        encoding="utf-8",
    )
    web_shell_test.write_text(
        web_shell_test.read_text(encoding="utf-8")
        + "void assertBetaDashboardMarkersPresent(String script) {} "
        "void assertBetaDashboardLoadSequencing(String script) {} "
        "void assertAppDataBackupRestoreMarkersPresent(String script) {} "
        "void calls() { assertBetaDashboardMarkersPresent(script); "
        "assertBetaDashboardLoadSequencing(script); "
        "assertAppDataBackupRestoreMarkersPresent(script); }\n",
        encoding="utf-8",
    )
    operator_dir = api_dir / "operator"
    operator_dir.mkdir(parents=True, exist_ok=True)
    (operator_dir / "OperatorBetaDashboardService.java").write_text(
        """
final class OperatorBetaDashboardService {
  Map<String, Object> dashboard() {
    dashboard.put("overallStatus", status);
    dashboard.put("summary", summary);
    dashboard.put("catalogs", catalogs);
    dashboard.put("apps", apps);
    dashboard.put("subscriptions", subscriptions);
    dashboard.put("trustGraph", trustGraph);
    dashboard.put("appServices", appServices);
    dashboard.put("legacyAdmin", legacyAdmin);
    dashboard.put("diagnostics", diagnostics);
    dashboard.put("recoveryActions", actions);
    return dashboard;
  }
  Map<String, Object> supportBundle() {
    OperatorSupportRedactor.redact(dashboard);
    OperatorSupportRedactor.redact(diagnostics);
    OperatorSupportRedactor.redact(recentAudit);
    return Map.of();
  }
  Map<String, Object> catalogSummary(Map<String, Object> catalog) {
    json.put("trustedCatalogKeyStatus", "configured");
    json.put("lastFetchStatus", status);
    json.put("recommendedFirstPartyPresent", true);
    safeSourceDisplay(source, sourceKind);
    action("refresh-catalog", "Refresh catalog", "POST", "app-catalogs/" + encodePathSegment(catalogId) + "/refresh", true);
    return json;
  }
  void appRecoveryActions() {
    action("check-app-update", "", "POST", "", true);
    action("stage-app-update", "", "POST", "", true);
    action("apply-app-update", "", "POST", "", true);
    action("rollback-app", "", "POST", "", true);
    action("open-app-logs", "", "GET", "", true);
    action("preserve-data-uninstall", "", "DELETE", "", true);
  }
  void subscriptionRecoveryActions() {
    String base = "operator/subscriptions/";
    action("refresh-subscription", "", "POST", base + "/refresh", true);
    action("pause-subscription", "", "POST", base + "/pause", true);
    action("resume-subscription", "", "POST", base + "/resume", true);
  }
  void trustGraphSummary() {
    json.put("previewOnly", true);
    json.put("completeWot", false);
    json.put("scope", scope);
    json.put("statementLifecycle", statementLifecycle);
    String warning = "Trust Graph Local RC is local operator-curated state only, not global truth, moderation, blocking, routing policy, or legacy Web of Trust compatibility.";
  }
  void appSummary(String appId) {
    appDataSummary(appId);
    json.put("appData", appData);
    String apphost = "apphost_quota_over_limit";
    String appData = "app_data_quota_unavailable";
    json.put("quotaWarningCount", 1);
    json.put("reviewTrust", reviewTrust);
  }
}
""",
        encoding="utf-8",
    )
    (operator_dir / "OperatorSupportRedactor.java").write_text(
        'final class OperatorSupportRedactor { String[] fields = {"formpassword", '
        '"browsersession", "requestbody", "rawbody", "sourcepath", "rollbackpath", '
        '"backupbundle", "payloadbase64"}; String marker = "crypta-app-data-backup"; '
        'String value = REDACTED_APP_DATA_BACKUP; }\n',
        encoding="utf-8",
    )
    (api_dir / "PlatformApiOperatorRoutes.java").write_text(
        """
final class PlatformApiOperatorRoutes {
  Object route(Object segments, Object request) {
    requireHostOperator(request);
    if ("beta-dashboard".equals(resource)) return dashboardService.dashboard();
    if ("support-bundle".equals(resource)) return dashboardService.supportBundle();
    if ("backups".equals(segments.get(2))) return routeAppDataBackup(request);
    if ("restore".equals(segments.get(2))) return routeAppDataRestore(request);
    switch (action) { case "refresh": break; case "pause": break; case "resume": break; }
    if ("plan".equals(segments.get(3))) return appDataService.planRestore(request);
    String route = "operator/app-data";
    String error = "host_operator_required app_data_service_unavailable";
    return null;
  }
  Object routeAppDataBackup(Object request) { return null; }
  Object routeAppDataBackupPostOnly(Object request) { return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE); }
  Object routeAppDataRestore(Object request) { return routeAppDataRestoreCommit(request); }
  Object routeAppDataRestoreCommit(Object request) { return null; }
}
""",
        encoding="utf-8",
    )
    (api_dir / "PlatformApiRouter.java").write_text(
        read_source(api_dir / "PlatformApiRouter.java")
        + ' case "operator" -> operatorRoutes.route(segments, request);\n',
        encoding="utf-8",
    )
    subscription_service_path = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionService.java"
    )
    subscription_service_path.write_text(
        subscription_service_path.read_text(encoding="utf-8")
        + "List<Map<String, Object>> listAllForOperator() { return listAllForScheduler(); }\n",
        encoding="utf-8",
    )
    (platform_api_tests / "PlatformApiOperatorRoutesTest.java").write_text(
        """
class PlatformApiOperatorRoutesTest {
  private static final String FORM_FIELD_ASSIGNMENT = "form" + "Pass" + "word=secret-value";
	  void route_whenAppPrincipalRequestsOperatorDashboard_expectForbiddenBeforeDispatch() {}
	  void route_whenAppPrincipalUsesOperatorSubscriptionWrapper_expectForbidden() {}
	  void route_whenAppPrincipalRequestsAppDataBackupRestore_expectForbidden() {}
	  void route_whenOperatorUsesAppDataBackupRestore_expectSensitiveBackupAndMetadataPlan() {}
	  void route_whenSupportBundleIncludesSensitiveDiagnostics_expectRedactedOutput() {
    String path = "/work/private/catalog";
    String secret = FORM_FIELD_ASSIGNMENT;
    assertFalse(response.body().contains(FORM_FIELD_ASSIGNMENT));
  }
}
""",
        encoding="utf-8",
    )
    redactor_test_dir = platform_api_tests / "operator"
    redactor_test_dir.mkdir(parents=True, exist_ok=True)
    (redactor_test_dir / "OperatorSupportRedactorTest.java").write_text(
        """
class OperatorSupportRedactorTest {
  void redact_whenNestedSecretsPathsAndContentUrisPresent_expectUnsafeValuesRemoved() {
    String path = "/work/cryptad/private.txt";
    String secret = "query-secret";
  }
  void redact_whenBackupPayloadAccidentallyEntersSupportBundle_expectWholeBackupRedacted() {}
}
""",
        encoding="utf-8",
    )
    legacy_http_dir = workspace / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http"
    legacy_http_dir.mkdir(parents=True, exist_ok=True)
    (legacy_http_dir / "PlatformApiToadlet.java").write_text(
        'final class PlatformApiToadlet { boolean requiresOperatorFormPassword() { return "backups".equals(pathSegments.get(2)); } String route = "operator/app-data/backups"; String method = "POST"; }\n',
        encoding="utf-8",
    )
    legacy_http_test_dir = workspace / "src/test/java/network/crypta/clients/http"
    legacy_http_test_dir.mkdir(parents=True, exist_ok=True)
    (legacy_http_test_dir / "PlatformApiToadletTest.java").write_text(
        'class PlatformApiToadletTest { String paths = "/operator/app-data/backups /operator/app-data/restore/plan /operator/app-data/restore /operator/subscriptions/feed-reader/sub-123/refresh"; }\n',
        encoding="utf-8",
    )
    operator_doc_text = (
        "The host/operator-only Operator beta dashboard documents operator-beta.dashboard, "
        "operator-beta.catalog-health, operator-beta.app-update-recovery, "
        "operator-beta.subscription-recovery, operator-beta.trust-review-warnings, "
        "operator-beta.app-data-quota-warnings, operator-beta.app-data-backup-restore, "
        "operator-beta.support-bundle-redaction, and operator-beta.web-shell. "
        "App-data backup restore evidence app-data.backup-restore-portability uses sensitive user data warnings. "
        "Trust Graph Local RC is local trust only, not global truth, not moderation, not blocking, not routing policy, no legacy WoT, and no crawling. "
        "Support bundles are reviewed by the operator before sharing and exclude raw request bodies and raw backup values."
    )
    (docs / "operator-beta-dashboard.md").write_text(operator_doc_text, encoding="utf-8")
    (docs / "app-platform-beta-program.md").write_text(
        "Operator beta dashboard operator-beta-ux-and-recovery\n",
        encoding="utf-8",
    )
    (docs / "platform-api-surface.md").write_text(
        read_source(docs / "platform-api-surface.md") + "\nOperator routes are host/operator-only.\n",
        encoding="utf-8",
    )
    router_test = workspace / "src/test/java/network/crypta/platform/api/PlatformApiRouterTest.java"
    router_test.parent.mkdir(parents=True, exist_ok=True)
    router_test.write_text(
        """
class PlatformApiRouterTest {
  void route_whenAppUpdateApplyRequestedWhileRunning_expectConflictJson() {
    PlatformApiResponse response =
        updateRouter.route(request("POST", List.of("apps", APP_ID, "updates", "apply"), Map.of()));
    assertEquals(409, response.statusCode());
    assertTrue(response.body().contains("\\\"code\\\":\\\"app_running\\\""));
    verify(appHost, never()).updateFromDirectory(APP_ID, stagedDir);
  }
}
""",
        encoding="utf-8",
    )
    catalog_handler = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    )
    catalog_handler.parent.mkdir(parents=True, exist_ok=True)
    catalog_handler.write_text(
        """
class AppCatalogsApiHandler {
  String recommendedCatalogError = "recommended_catalog_trusted_key_missing";
  void listRecommendedCatalogs() {}
  void addRecommended() {}
  void refresh(String catalogId) { refresh(catalogId); }
  void summarize() {
    json.put("channel", channel);
    json.put("supportStatus", supportStatus);
    json.put("securityAdvisories", securityAdvisories);
    json.put("defaultEntryChannel", "stable");
    json.put("versionDifferent", versionDifferent(entry.version(), installedVersion, installed != null));
    json.put("updateAvailable", updateAvailable(entry.version(), installedVersion, installed != null).orElse(null));
    json.put("review", summarizeReview(entry.review()));
    json.put("compatibility", summarizeCompatibility(entry.compatibility()));
    json.put("apiCompatibility", apiCompatibility(entry.compatibility().apiCompatibility(), entry.permissions()));
    json.put("permissionDelta", summarizePermissionDelta(entry.permissions(), installed));
    AppCatalogInstallPlan plan = catalogManager.prepareInstallPlan(catalogId, normalizedAppId);
    InstalledAppSnapshot updated = appHost.updateFromDirectory(entry.appId(), plan.stagedBundleDirectory());
  }
  private static boolean versionDifferent(String catalogVersion, String installedVersion, boolean installed) { return false; }
  private static Optional<Boolean> updateAvailable(String catalogVersion, String installedVersion, boolean installed) { return Optional.empty(); }
}
""",
        encoding="utf-8",
    )
    lifecycle_doc = workspace / "docs/app-update-lifecycle.md"
    lifecycle_doc.write_text(
        """
AppHost v1 uses an `apply_when_stopped` policy.
Silent automatic update is not the default.
Applying an update requires an operator or explicit API caller.
The policy modes are manual, stage, and apply_when_stopped.
The background scheduler uses AppUpdateService.check after live USK catalog refresh and manual remains the default.
Catalog refresh records the last verified signed catalog state before candidate discovery.
Release evidence is app-update.scheduler.
Rollback covers only the immutable installed bundle.
Rollback does not roll back app data directories or app cache directories.
""",
        encoding="utf-8",
    )


def fake_cli_python_source() -> str:
    return r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path


def option_value(args, name):
    for index, value in enumerate(args):
        if value == name and index + 1 < len(args):
            return args[index + 1]
    return ""


def write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def property_value(path, name):
    if not path.is_file():
        return ""
    prefix = name + "="
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped.split("=", 1)[1]
    return ""


def init_app(args):
    directory_text = option_value(args, "--dir")
    if not directory_text:
        return 2
    directory = Path(directory_text)
    (directory / "bin").mkdir(parents=True, exist_ok=True)
    (directory / "static/crypta-ui").mkdir(parents=True, exist_ok=True)
    write_text(
        directory / "cryptad-app.properties",
        "\n".join(
            [
                "manifest.version=1",
                "app.id=cert-smoke",
                "app.name=Certification Smoke",
                "app.version=0.1.0",
                "app.exec=bin/start.sh",
                "api.minimumVersion=1",
                f"api.maximumTestedVersion={CURRENT_PLATFORM_API_CONTRACT_VERSION}",
                "api.experimentalCapabilitiesAccepted=false",
                "app.ui.mode=static",
                "app.ui.entry=static/index.html",
                "app.permissions=queue.read",
            ]
        )
        + "\n",
    )
    write_text(directory / "bin/start.sh", "#!/usr/bin/env sh\nexit 0\n")
    write_text(
        directory / "static/index.html",
        '<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>Certification Smoke</title><link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css"><link rel="stylesheet" href="./crypta-ui/crypta-ui.css"><link rel="stylesheet" href="./app.css"></head><body class="cr-app"><main class="cr-shell"><section class="cr-permission-summary" data-crypta-permission-summary><code>queue.read</code></section><h1>Certification Smoke</h1></main><script src="./crypta-platform.js"></script><script src="./app.js"></script></body></html>\n',
    )
    write_text(
        directory / "static/app.js",
        'CryptaPlatform.bootstrap.load({ appId: "cert-smoke" });\n',
    )
    write_text(directory / "static/app.css", "body{}\n")
    write_text(directory / "static/crypta-ui/crypta-ui-tokens.css", ":root{--cr-space-4:1rem;}\n")
    write_text(directory / "static/crypta-ui/crypta-ui.css", ".cr-app{}.cr-shell{}.cr-button{}\n")
    write_text(directory / "static/crypta-ui/crypta-ui-components.js", 'window.CryptaUi={version:"1"};\n')
    write_text(
        directory / "static/crypta-platform.js",
        'window.CryptaPlatform={}; X="X-Crypta-App-Session";\n',
    )
    return 0


def ui_lint(args):
    output_text = option_value(args, "--json")
    bundle_text = option_value(args, "--bundle-dir")
    app_id = "cert-smoke"
    ui_mode = "static"
    if bundle_text:
        manifest = Path(bundle_text) / "cryptad-app.properties"
        app_id = property_value(manifest, "app.id") or app_id
        ui_mode = property_value(manifest, "app.ui.mode") or ui_mode
    payload = {
        "appId": app_id,
        "uiMode": ui_mode,
        "applicable": True,
        "summary": {"errors": 0, "warnings": 0, "notes": 0},
        "findings": [],
    }
    if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_WRONG_UI_LINT_APP") == "1":
        payload["appId"] = "wrong-app"
    if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_UI_LINT_ERRORS") == "1":
        payload["summary"]["errors"] = 1
        payload["findings"] = [{"id": "fake-error", "severity": "error"}]
    if output_text:
        if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_SKIP_UI_LINT_JSON") == "1":
            return 0
        if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_BAD_UI_LINT_JSON") == "1":
            write_text(Path(output_text), "{not-json\n")
            return 0
        write_text(Path(output_text), json.dumps(payload, sort_keys=True) + "\n")
    return 0


def pack_app(args):
    output_text = option_value(args, "--output")
    if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_SKIP_PACK_OUTPUT") == "1":
        return 0
    if not output_text:
        return 2
    output = Path(output_text)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(b"zip")
    return 0


def create_catalog(args):
    catalog_text = option_value(args, "--catalog-file")
    if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_SKIP_CATALOG_OUTPUT") == "1":
        return 0
    if not catalog_text:
        return 2
    entries = []
    review_receipts = []
    catalog_id = option_value(args, "--catalog-id") or "cert-smoke"
    catalog_name = option_value(args, "--name") or "Certification Smoke Apps"
    generated_at = option_value(args, "--generated-at") or "2026-05-01T00:00:00Z"
    index = 0
    while index < len(args):
        if args[index] == "--entry" and index + 1 < len(args):
            entries.append(Path(args[index + 1]))
            index += 2
            continue
        if args[index] == "--review-receipt" and index + 1 < len(args):
            review_receipts.append(Path(args[index + 1]))
            index += 2
            continue
        index += 1
    if not entries:
        entries = [Path("cert-smoke-entry.properties")]
    catalog = Path(catalog_text)
    app_ids = []
    lines = [
        "catalog.version=1",
        f"catalog.id={catalog_id}",
        f"catalog.name={catalog_name}",
        f"catalog.generatedAt={generated_at}",
    ]
    app_lines = []
    for descriptor in entries:
        app_id = property_value(descriptor, "app.id") or "cert-smoke"
        app_ids.append(app_id)
        artifact_path = Path(property_value(descriptor, "artifact.path") or "/tmp/cert-smoke.zip")
        artifact_size = artifact_path.stat().st_size if artifact_path.is_file() else 3
        app_lines.extend(
            [
                f"app.{app_id}.id={app_id}",
                f"app.{app_id}.name={property_value(descriptor, 'name') or 'Certification Smoke'}",
                f"app.{app_id}.version={property_value(descriptor, 'version') or '0.1.0'}",
                f"app.{app_id}.summary={property_value(descriptor, 'summary') or 'Certification smoke app.'}",
                f"app.{app_id}.bundle.uri={property_value(descriptor, 'bundle.uri') or 'file:///tmp/cert-smoke.zip'}",
                "app." + app_id + ".bundle.sha256=0000000000000000000000000000000000000000000000000000000000000000",
                f"app.{app_id}.bundle.size.bytes={artifact_size}",
                f"app.{app_id}.bundle.type=zip",
                f"app.{app_id}.permissions={property_value(descriptor, 'permissions') or 'queue.read'}",
            ]
        )
        if review_receipts:
            app_lines.extend(
                [
                    f"app.{app_id}.review.receipt.status=reviewed",
                    f"app.{app_id}.review.receipt.reviewer.key.id=cert-review",
                    f"app.{app_id}.review.receipt.policy.id=crypta-app-review-v1",
                    f"app.{app_id}.review.receipt.policy.version=1",
                ]
            )
    lines.append("catalog.entries=" + ",".join(app_ids))
    lines.extend(app_lines)
    write_text(catalog, "\n".join(lines) + "\n")
    return 0


def api_snapshot(args):
    output_text = option_value(args, "--output")
    if not output_text:
        return 2
    output = Path(output_text)
    write_text(
        output,
        json.dumps(
            {
                "contract": {
                    "apiVersion": "v1",
                    "contractVersion": 16,
                    "generatedBy": "cryptad",
                    "stabilityPolicy": "self-test",
                    "capabilities": [
                        {
                            "name": "queue.read",
                            "stability": "stable",
                            "sinceContractVersion": 1,
                            "deprecation": None,
                            "description": "Read queue state.",
                        },
                        {
                            "name": "platform.contract.read",
                            "stability": "stable",
                            "sinceContractVersion": 1,
                            "deprecation": None,
                            "description": "Read contract snapshots.",
                        },
                        {
                            "name": "app.data.read",
                            "stability": "stable",
                            "sinceContractVersion": 9,
                            "deprecation": None,
                            "description": "Read app-owned durable state.",
                        },
                        {
                            "name": "app.data.write",
                            "stability": "stable",
                            "sinceContractVersion": 9,
                            "deprecation": None,
                            "description": "Write app-owned durable state.",
                        },
                        {
                            "name": "content.fetch",
                            "stability": "stable",
                            "sinceContractVersion": 6,
                            "deprecation": None,
                            "description": "Fetch bounded content.",
                        },
                        {
                            "name": "trust.read",
                            "stability": "stable",
                            "sinceContractVersion": 7,
                            "deprecation": None,
                            "description": "Read local trust graph preview state.",
                        },
                        {
                            "name": "trust.write",
                            "stability": "stable",
                            "sinceContractVersion": 7,
                            "deprecation": None,
                            "description": "Mutate local trust graph preview state.",
                        },
                        {
                            "name": "vault.identities.read",
                            "stability": "experimental",
                            "sinceContractVersion": 11,
                            "deprecation": None,
                            "description": "Read app-visible identity metadata.",
                        },
                        {
                            "name": "vault.identities.use",
                            "stability": "experimental",
                            "sinceContractVersion": 11,
                            "deprecation": None,
                            "description": "Use bounded AppVault signing routes.",
                        },
                        {
                            "name": "app.services.read",
                            "stability": "experimental",
                            "sinceContractVersion": 12,
                            "deprecation": None,
                            "description": "Discover local app services and grants.",
                        },
                        {
                            "name": "app.services.call",
                            "stability": "experimental",
                            "sinceContractVersion": 12,
                            "deprecation": None,
                            "description": "Request grants and invoke approved services.",
                        },
                    ],
                    "endpoints": [
                        {
                            "routeFamily": "queue",
                            "method": "GET",
                            "routeTemplate": "/queue",
                            "actionLabel": "queue.read",
                            "requiredCapabilities": ["queue.read"],
                            "hostOperatorBypassAllowed": True,
                            "appProcessPrincipalsAllowed": True,
                            "appBrowserPrincipalsAllowed": True,
                            "stability": "stable",
                            "sinceContractVersion": 1,
                            "deprecation": None,
                            "description": "Read queue state.",
                        },
                        {"method": "GET", "routeTemplate": "/app-data/status", "stability": "stable"},
                        {"method": "GET", "routeTemplate": "/app-data/namespaces", "stability": "stable"},
                        {"method": "GET", "routeTemplate": "/app-data/namespaces/{namespace}", "stability": "stable"},
                        {"method": "POST", "routeTemplate": "/app-data/namespaces/{namespace}/schema", "stability": "stable"},
                        {"method": "DELETE", "routeTemplate": "/app-data/namespaces/{namespace}", "stability": "stable"},
                        {"method": "GET", "routeTemplate": "/app-data/records", "stability": "stable"},
                        {"method": "GET", "routeTemplate": "/app-data/records/{namespace}/{key}", "stability": "stable"},
                        {"method": "POST", "routeTemplate": "/app-data/records", "stability": "stable"},
                        {"method": "DELETE", "routeTemplate": "/app-data/records/{namespace}/{key}", "stability": "stable"},
                        {"method": "GET", "routeTemplate": "/app-data/export", "stability": "stable"},
                        {"method": "POST", "routeTemplate": "/app-data/import", "stability": "stable"},
                        {"method": "GET", "routeTemplate": "/trust-graph/audit", "stability": "stable"},
                        {"method": "POST", "routeTemplate": "/trust-graph/import-uri", "stability": "stable"},
                        {
                            "method": "GET",
                            "routeTemplate": "/trust-graph/statements/{fingerprint}",
                            "requiredCapabilities": ["trust.read"],
                            "stability": "experimental",
                            "sinceContractVersion": 15,
                        },
                        {
                            "method": "POST",
                            "routeTemplate": "/trust-graph/statements/{fingerprint}/deprecate",
                            "requiredCapabilities": ["trust.write"],
                            "stability": "experimental",
                            "sinceContractVersion": 15,
                        },
                        {
                            "method": "POST",
                            "routeTemplate": "/trust-graph/statements/{fingerprint}/revoke",
                            "requiredCapabilities": ["trust.write"],
                            "stability": "experimental",
                            "sinceContractVersion": 15,
                        },
                        {
                            "method": "POST",
                            "routeTemplate": "/trust-graph/statements/{fingerprint}/reactivate",
                            "requiredCapabilities": ["trust.write"],
                            "stability": "experimental",
                            "sinceContractVersion": 15,
                        },
                        {
                            "method": "POST",
                            "routeTemplate": "/app-vault/identities/{identityId}/social-message",
                            "requiredCapabilities": ["vault.identities.read", "vault.identities.use"],
                            "stability": "experimental",
                        },
                        {"method": "GET", "routeTemplate": "/app-services", "stability": "experimental"},
                        {"method": "GET", "routeTemplate": "/app-services/audit", "stability": "experimental"},
                        {"method": "GET", "routeTemplate": "/app-services/dependencies", "stability": "experimental"},
                        {
                            "method": "GET",
                            "routeTemplate": "/app-services/dependencies/consumers/{consumerAppId}",
                            "stability": "experimental",
                        },
                        {"method": "GET", "routeTemplate": "/app-services/grant-bundles", "stability": "experimental"},
                        {"method": "POST", "routeTemplate": "/app-services/grant-bundles", "stability": "experimental"},
                        {
                            "method": "POST",
                            "routeTemplate": "/app-services/grant-bundles/{bundleId}/approve",
                            "stability": "experimental",
                        },
                        {
                            "method": "POST",
                            "routeTemplate": "/app-services/grant-bundles/{bundleId}/reject",
                            "stability": "experimental",
                        },
                        {
                            "method": "POST",
                            "routeTemplate": "/app-services/grant-bundles/{bundleId}/renew",
                            "stability": "experimental",
                        },
                        {"method": "GET", "routeTemplate": "/app-services/grants", "stability": "experimental"},
                        {"method": "POST", "routeTemplate": "/app-services/grants", "stability": "experimental"},
                        {
                            "method": "POST",
                            "routeTemplate": "/app-services/grants/{grantId}/approve",
                            "stability": "experimental",
                        },
                        {
                            "method": "POST",
                            "routeTemplate": "/app-services/grants/{grantId}/revoke",
                            "stability": "experimental",
                        },
                        {
                            "method": "GET",
                            "routeTemplate": "/app-services/{providerAppId}/services",
                            "stability": "experimental",
                        },
                        {
                            "method": "GET",
                            "routeTemplate": "/app-services/{providerAppId}/services/{serviceId}",
                            "stability": "experimental",
                        },
                        {
                            "method": "POST",
                            "routeTemplate": "/app-services/{providerAppId}/services/{serviceId}/invoke",
                            "stability": "experimental",
                        },
                    ],
                }
            },
            sort_keys=True,
        )
        + "\n",
    )
    return 0


def main():
    if len(sys.argv) < 2:
        return 0
    command = sys.argv[1]
    args = sys.argv[2:]
    if command == "init":
        return init_app(args)
    if command == "validate":
        return 0
    if command == "ui":
        subcommand = args[0] if args else ""
        if subcommand == "lint":
            return ui_lint(args[1:])
        return 0
    if command == "pack":
        return pack_app(args)
    if command == "catalog":
        subcommand = args[0] if args else ""
        if subcommand == "create":
            return create_catalog(args[1:])
        if subcommand in {"sign", "verify"}:
            return 0
    if command == "api":
        subcommand = args[0] if args else ""
        if subcommand == "snapshot":
            return api_snapshot(args[1:])
    if command == "compat":
        return 0
    if command in {"sign", "verify"}:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def make_fake_cli(workspace: Path) -> Path:
    bin_dir = workspace / "platform-devtools/build/install/crypta-app/bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    cli = bin_dir / ("crypta-app.bat" if platform.system() == "Windows" else "crypta-app")
    if platform.system() == "Windows":
        helper = bin_dir / "crypta-app-fake.py"
        helper.write_text(fake_cli_python_source(), encoding="utf-8")
        cli.write_text(
            """@echo off
py -3 "%~dp0crypta-app-fake.py" %*
if not errorlevel 9009 exit /b %ERRORLEVEL%
python3 "%~dp0crypta-app-fake.py" %*
exit /b %ERRORLEVEL%
""",
            encoding="utf-8",
        )
    else:
        cli.write_text(
            """#!/usr/bin/env sh
set -eu
cmd="${1:-}"
if [ "$#" -gt 0 ]; then shift; fi
case "$cmd" in
  init)
    dir=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--dir" ]; then dir="$2"; shift 2; else shift; fi
    done
    mkdir -p "$dir/bin" "$dir/static/crypta-ui"
    printf '%s\n' 'manifest.version=1' 'app.id=cert-smoke' 'app.name=Certification Smoke' 'app.version=0.1.0' 'app.exec=bin/start.sh' 'api.minimumVersion=1' 'api.maximumTestedVersion=16' 'api.experimentalCapabilitiesAccepted=false' 'app.ui.mode=static' 'app.ui.entry=static/index.html' 'app.permissions=queue.read' > "$dir/cryptad-app.properties"
    printf '%s\n' '#!/usr/bin/env sh' 'exit 0' > "$dir/bin/start.sh"
    printf '%s\n' '<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>Certification Smoke</title><link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css"><link rel="stylesheet" href="./crypta-ui/crypta-ui.css"><link rel="stylesheet" href="./app.css"></head><body class="cr-app"><main class="cr-shell"><section class="cr-permission-summary" data-crypta-permission-summary><code>queue.read</code></section><h1>Certification Smoke</h1></main><script src="./crypta-platform.js"></script><script src="./app.js"></script></body></html>' > "$dir/static/index.html"
    printf '%s\n' 'CryptaPlatform.bootstrap.load({ appId: "cert-smoke" });' > "$dir/static/app.js"
    printf '%s\n' 'body{}' > "$dir/static/app.css"
    printf '%s\n' ':root{--cr-space-4:1rem;}' > "$dir/static/crypta-ui/crypta-ui-tokens.css"
    printf '%s\n' '.cr-app{}.cr-shell{}.cr-button{}' > "$dir/static/crypta-ui/crypta-ui.css"
    printf '%s\n' 'window.CryptaUi={version:"1"};' > "$dir/static/crypta-ui/crypta-ui-components.js"
    printf '%s\n' 'window.CryptaPlatform={}; X="X-Crypta-App-Session";' > "$dir/static/crypta-platform.js"
    ;;
  validate)
    exit 0
    ;;
  ui)
    sub="${1:-}"; shift || true
    if [ "$sub" = "lint" ]; then
      out=""
      bundle=""
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --json)
            out="$2"
            shift 2
            ;;
          --bundle-dir)
            bundle="$2"
            shift 2
            ;;
          *)
            shift
            ;;
        esac
      done
      if [ -n "$out" ]; then
        if [ "${CRYPTAD_APP_SMOKE_FAKE_SKIP_UI_LINT_JSON:-0}" = "1" ]; then
          exit 0
        fi
        mkdir -p "$(dirname "$out")"
        if [ "${CRYPTAD_APP_SMOKE_FAKE_BAD_UI_LINT_JSON:-0}" = "1" ]; then
          printf '%s\n' '{not-json' > "$out"
          exit 0
        fi
        app_id="cert-smoke"
        ui_mode="static"
        if [ -n "$bundle" ] && [ -f "$bundle/cryptad-app.properties" ]; then
          app_id="$(awk -F= '$1 == "app.id" {print substr($0, index($0, "=") + 1); exit}' "$bundle/cryptad-app.properties")"
          ui_mode="$(awk -F= '$1 == "app.ui.mode" {print substr($0, index($0, "=") + 1); exit}' "$bundle/cryptad-app.properties")"
          app_id="${app_id:-cert-smoke}"
          ui_mode="${ui_mode:-static}"
        fi
        if [ "${CRYPTAD_APP_SMOKE_FAKE_WRONG_UI_LINT_APP:-0}" = "1" ]; then
          app_id="wrong-app"
        fi
        error_count="0"
        findings="[]"
        if [ "${CRYPTAD_APP_SMOKE_FAKE_UI_LINT_ERRORS:-0}" = "1" ]; then
          error_count="1"
          findings='[{"id":"fake-error","severity":"error"}]'
        fi
        printf '{"appId":"%s","applicable":true,"findings":%s,"summary":{"errors":%s,"notes":0,"warnings":0},"uiMode":"%s"}\n' "$app_id" "$findings" "$error_count" "$ui_mode" > "$out"
      fi
      exit 0
    fi
    ;;
  pack)
    out=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--output" ]; then out="$2"; shift 2; else shift; fi
    done
    if [ "${CRYPTAD_APP_SMOKE_FAKE_SKIP_PACK_OUTPUT:-0}" = "1" ]; then
      exit 0
    fi
    printf 'zip' > "$out"
    ;;
  catalog)
    sub="$1"; shift
    case "$sub" in
      create)
        if [ "${CRYPTAD_APP_SMOKE_FAKE_SKIP_CATALOG_OUTPUT:-0}" = "1" ]; then
          exit 0
        fi
        python3 - "$@" <<'PY'
import sys
from pathlib import Path

args = sys.argv[1:]

def option(name, default=""):
    for index, value in enumerate(args):
        if value == name and index + 1 < len(args):
            return args[index + 1]
    return default

def values(name):
    found = []
    index = 0
    while index < len(args):
        if args[index] == name and index + 1 < len(args):
            found.append(Path(args[index + 1]))
            index += 2
        else:
            index += 1
    return found

def prop(path, name):
    if not path.is_file():
        return ""
    prefix = name + "="
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped.split("=", 1)[1]
    return ""

catalog_text = option("--catalog-file")
if not catalog_text:
    raise SystemExit(2)
catalog = Path(catalog_text)
entries = values("--entry") or [Path("cert-smoke-entry.properties")]
review_receipts = values("--review-receipt")
app_ids = []
lines = [
    "catalog.version=1",
    "catalog.id=" + option("--catalog-id", "cert-smoke"),
    "catalog.name=" + option("--name", "Certification Smoke Apps"),
    "catalog.generatedAt=" + option("--generated-at", "2026-05-01T00:00:00Z"),
]
app_lines = []
for descriptor in entries:
    app_id = prop(descriptor, "app.id") or "cert-smoke"
    app_ids.append(app_id)
    artifact = Path(prop(descriptor, "artifact.path") or "/tmp/cert-smoke.zip")
    size = artifact.stat().st_size if artifact.is_file() else 3
    app_lines.extend([
        f"app.{app_id}.id={app_id}",
        f"app.{app_id}.name={prop(descriptor, 'name') or 'Certification Smoke'}",
        f"app.{app_id}.version={prop(descriptor, 'version') or '0.1.0'}",
        f"app.{app_id}.summary={prop(descriptor, 'summary') or 'Certification smoke app.'}",
        f"app.{app_id}.bundle.uri={prop(descriptor, 'bundle.uri') or 'file:///tmp/cert-smoke.zip'}",
        f"app.{app_id}.bundle.sha256=0000000000000000000000000000000000000000000000000000000000000000",
        f"app.{app_id}.bundle.size.bytes={size}",
        f"app.{app_id}.bundle.type=zip",
        f"app.{app_id}.permissions={prop(descriptor, 'permissions') or 'queue.read'}",
    ])
    if review_receipts:
        app_lines.extend([
            f"app.{app_id}.review.receipt.status=reviewed",
            f"app.{app_id}.review.receipt.reviewer.key.id=cert-review",
            f"app.{app_id}.review.receipt.policy.id=crypta-app-review-v1",
            f"app.{app_id}.review.receipt.policy.version=1",
        ])
catalog.parent.mkdir(parents=True, exist_ok=True)
catalog.write_text("\\n".join(lines + ["catalog.entries=" + ",".join(app_ids)] + app_lines) + "\\n", encoding="utf-8")
PY
        ;;
      sign|verify)
        exit 0
        ;;
    esac
    ;;
  api)
    sub="${1:-}"
    if [ "$#" -gt 0 ]; then shift; fi
    case "$sub" in
      snapshot)
        output=""
        while [ "$#" -gt 0 ]; do
          if [ "$1" = "--output" ]; then output="$2"; shift 2; else shift; fi
        done
        if [ -z "$output" ]; then
          exit 2
        fi
        mkdir -p "$(dirname "$output")"
        cat > "$output" <<'JSON'
{
  "contract": {
    "apiVersion": "v1",
    "contractVersion": 16,
    "generatedBy": "cryptad",
    "stabilityPolicy": "self-test",
    "capabilities": [
      {
        "name": "queue.read",
        "stability": "stable",
        "sinceContractVersion": 1,
        "deprecation": null,
        "description": "Read queue state."
      },
      {
        "name": "platform.contract.read",
        "stability": "stable",
        "sinceContractVersion": 1,
        "deprecation": null,
        "description": "Read contract snapshots."
      },
      {
        "name": "app.data.read",
        "stability": "stable",
        "sinceContractVersion": 9,
        "deprecation": null,
        "description": "Read app-owned durable state."
      },
      {
        "name": "app.data.write",
        "stability": "stable",
        "sinceContractVersion": 9,
        "deprecation": null,
        "description": "Write app-owned durable state."
      },
      {
        "name": "content.fetch",
        "stability": "stable",
        "sinceContractVersion": 6,
        "deprecation": null,
        "description": "Fetch bounded content."
      },
      {
        "name": "trust.read",
        "stability": "stable",
        "sinceContractVersion": 7,
        "deprecation": null,
        "description": "Read local Trust Graph RC state and lifecycle."
      },
      {
        "name": "trust.write",
        "stability": "stable",
        "sinceContractVersion": 7,
        "deprecation": null,
        "description": "Mutate local Trust Graph RC anchors and lifecycle."
      },
      {
        "name": "vault.identities.read",
        "stability": "experimental",
        "sinceContractVersion": 11,
        "deprecation": null,
        "description": "Read app-visible identity metadata."
      },
      {
        "name": "vault.identities.use",
        "stability": "experimental",
        "sinceContractVersion": 11,
        "deprecation": null,
        "description": "Use bounded AppVault signing routes."
      },
      {
        "name": "app.services.read",
        "stability": "experimental",
        "sinceContractVersion": 12,
        "deprecation": null,
        "description": "Discover local app services and grants."
      },
      {
        "name": "app.services.call",
        "stability": "experimental",
        "sinceContractVersion": 12,
        "deprecation": null,
        "description": "Request grants and invoke approved services."
      }
    ],
    "endpoints": [
      {
        "routeFamily": "queue",
        "method": "GET",
        "routeTemplate": "/queue",
        "actionLabel": "queue.read",
        "requiredCapabilities": [
          "queue.read"
        ],
        "hostOperatorBypassAllowed": true,
        "appProcessPrincipalsAllowed": true,
        "appBrowserPrincipalsAllowed": true,
        "stability": "stable",
        "sinceContractVersion": 1,
        "deprecation": null,
        "description": "Read queue state."
      },
      {
        "method": "GET",
        "routeTemplate": "/app-data/status",
        "stability": "stable"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-data/namespaces",
        "stability": "stable"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-data/namespaces/{namespace}",
        "stability": "stable"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-data/namespaces/{namespace}/schema",
        "stability": "stable"
      },
      {
        "method": "DELETE",
        "routeTemplate": "/app-data/namespaces/{namespace}",
        "stability": "stable"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-data/records",
        "stability": "stable"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-data/records/{namespace}/{key}",
        "stability": "stable"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-data/records",
        "stability": "stable"
      },
      {
        "method": "DELETE",
        "routeTemplate": "/app-data/records/{namespace}/{key}",
        "stability": "stable"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-data/export",
        "stability": "stable"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-data/import",
        "stability": "stable"
      },
      {
        "method": "GET",
        "routeTemplate": "/trust-graph/audit",
        "stability": "stable"
      },
      {
        "method": "POST",
        "routeTemplate": "/trust-graph/import-uri",
        "stability": "stable"
      },
      {
        "method": "GET",
        "routeTemplate": "/trust-graph/statements/{fingerprint}",
        "requiredCapabilities": [
          "trust.read"
        ],
        "stability": "experimental",
        "sinceContractVersion": 15
      },
      {
        "method": "POST",
        "routeTemplate": "/trust-graph/statements/{fingerprint}/deprecate",
        "requiredCapabilities": [
          "trust.write"
        ],
        "stability": "experimental",
        "sinceContractVersion": 15
      },
      {
        "method": "POST",
        "routeTemplate": "/trust-graph/statements/{fingerprint}/revoke",
        "requiredCapabilities": [
          "trust.write"
        ],
        "stability": "experimental",
        "sinceContractVersion": 15
      },
      {
        "method": "POST",
        "routeTemplate": "/trust-graph/statements/{fingerprint}/reactivate",
        "requiredCapabilities": [
          "trust.write"
        ],
        "stability": "experimental",
        "sinceContractVersion": 15
      },
      {
        "method": "POST",
        "routeTemplate": "/app-vault/identities/{identityId}/social-message",
        "requiredCapabilities": [
          "vault.identities.read",
          "vault.identities.use"
        ],
        "stability": "experimental"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-services",
        "stability": "experimental"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-services/audit",
        "stability": "experimental"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-services/dependencies",
        "stability": "experimental"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-services/dependencies/consumers/{consumerAppId}",
        "stability": "experimental"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-services/grant-bundles",
        "stability": "experimental"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-services/grant-bundles",
        "stability": "experimental"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-services/grant-bundles/{bundleId}/approve",
        "stability": "experimental"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-services/grant-bundles/{bundleId}/reject",
        "stability": "experimental"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-services/grant-bundles/{bundleId}/renew",
        "stability": "experimental"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-services/grants",
        "stability": "experimental"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-services/grants",
        "stability": "experimental"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-services/grants/{grantId}/approve",
        "stability": "experimental"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-services/grants/{grantId}/revoke",
        "stability": "experimental"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-services/{providerAppId}/services",
        "stability": "experimental"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-services/{providerAppId}/services/{serviceId}",
        "stability": "experimental"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-services/{providerAppId}/services/{serviceId}/invoke",
        "stability": "experimental"
      }
    ]
  }
}
JSON
        ;;
      *)
        exit 2
        ;;
    esac
    ;;
  compat)
    sub="${1:-}"
    if [ "$#" -gt 0 ]; then shift; fi
    case "$sub" in
      verify)
        contract=""
        target=""
        while [ "$#" -gt 0 ]; do
          case "$1" in
            --contract)
              contract="$2"
              shift 2
              ;;
            --bundle-dir|--catalog-entry)
              target="$2"
              shift 2
              ;;
            --strict)
              shift
              ;;
            *)
              shift
              ;;
          esac
        done
        if [ -z "$contract" ] || [ ! -f "$contract" ]; then
          exit 2
        fi
        if [ -z "$target" ]; then
          exit 2
        fi
        ;;
      *)
        exit 2
        ;;
    esac
    ;;
  sign|verify)
    exit 0
    ;;
esac
""",
            encoding="utf-8",
        )
        cli.chmod(0o755)
    return cli


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        run_self_test(Path(__file__).resolve().parents[2])
        print("app-platform-smoke self-test passed")
        return 0
    settings = settings_from_args(args)
    summary, exit_code = run(settings)
    print(f"App platform smoke {summary['status']}: {settings.out_dir / SUMMARY_FILE_NAME}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
