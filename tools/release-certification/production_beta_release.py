#!/usr/bin/env python3
"""Build a redacted Crypta app-ecosystem production beta candidate.

The production beta pipeline is an orchestration layer over the existing Gradle,
``crypta-app``, app-platform smoke, live-network beta smoke, network-scale soak,
and release-certification tools.  It deliberately keeps release-key material out
of the generated artifact tree and fails closed when production beta evidence is
missing.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime as dt
import hashlib
import io
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import urllib.parse
import zipfile
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator

sys.dont_write_bytecode = True

TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
sys.path.insert(0, str(TOOL_DIR))

import release_certification  # noqa: E402


TOOL_NAME = "production-beta-release"
SCHEMA_VERSION = 1
MODES = ("developer-dry-run", "release-candidate", "production-beta")
CATALOG_CHANNELS = ("stable", "beta", "nightly", "deprecated")
OUT_DIR_SENTINEL = ".cryptad-production-beta-release-output"
PROTECTED_CLEAN_TOP_LEVELS = {".git", ".github", "apps", "docs", "tools"}
RELEASE_OUTPUT_ROOTS = ("inputs", "build", "catalog", "reviews", "evidence", "reports")
PLACEHOLDER_ARTIFACT_HOSTS = {"downloads.crypta.invalid"}
LOCAL_ARTIFACT_HOSTS = {"127.0.0.1", "localhost", "::1", "0:0:0:0:0:0:0:1"}
PRIVATE_ARTIFACT_HOST_SUFFIXES = (
    ".invalid",
    ".localhost",
    ".local",
    ".localdomain",
    ".lan",
    ".home",
    ".corp",
    ".internal",
    ".test",
    ".example",
)
ZIP_ARCHIVE_SUFFIXES = {".zip", ".jar"}
TAR_GZ_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz")
MAX_NESTED_ARCHIVE_DEPTH = 4
TEXT_SCAN_CHUNK_BYTES = 1024 * 1024
TEXT_SCAN_OVERLAP_BYTES = 64 * 1024
COMPILED_ARCHIVE_MEMBER_SUFFIXES = {
    ".a",
    ".class",
    ".dll",
    ".dylib",
    ".exe",
    ".jnilib",
    ".lib",
    ".o",
    ".obj",
    ".so",
    ".wasm",
}
FORBIDDEN_SECRET_ARTIFACT_SUFFIXES = {".p12", ".pfx", ".jks", ".keystore", ".p8", ".pkcs8"}
SECRET_ARTIFACT_BINARY_SUFFIXES = {".der", ".key", ".pem", ".bin"}
CODE_LIKE_ARTIFACT_SUFFIXES = {
    ".class",
    ".java",
    ".kt",
    ".kts",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".map",
    ".css",
    ".html",
    ".md",
}
SECRET_ARTIFACT_NAME_RE = re.compile(
    r"(?:^|[._-])(?:"
    r"private[._-]*key|"
    r"(?:app[._-]*)?signing[._-]*private(?:[._-]*key)?|"
    r"reviewer[._-]*private(?:[._-]*key)?|"
    r"private[._-]*insert[._-]*uri|"
    r"insert[._-]*uri|"
    r"app[._-]*token|"
    r"browser[._-]*session[._-]*token|"
    r"app[._-]*process[._-]*token|"
    r"form[._-]*password|"
    r"bearer[._-]*token|"
    r"github[._-]*token|"
    r"id[._-]*(?:rsa|dsa|ecdsa|ed25519)"
    r")(?:$|[._-])",
    re.IGNORECASE,
)
SECRET_ARTIFACT_COLLAPSED_NAMES = {
    "appsigningprivate",
    "appsigningprivatekey",
    "signingprivate",
    "signingprivatekey",
    "reviewerprivate",
    "reviewerprivatekey",
    "privatekey",
    "privateinserturi",
    "inserturi",
    "apptoken",
    "browsersessiontoken",
    "appprocesstoken",
    "formpassword",
    "bearertoken",
    "githubtoken",
    "idrsa",
    "iddsa",
    "idecdsa",
    "ided25519",
}
SECRET_ARTIFACT_BINARY_MARKERS = ("private", "secret", "password", "token", "inserturi")
CANONICAL_CATALOG_SIGNATURE = "cryptad-app-catalog.signature"
RELEASE_CATALOG_SIGNATURE_ALIAS = "first-party-catalog.sig"
APP_IDS = (
    "queue-manager",
    "publisher",
    "site-publisher",
    "profile-publisher",
    "social-inbox",
    "feed-reader",
    "trust-graph",
)
APP_PROJECT_DIRS = {
    "queue-manager": "apps/queue-manager",
    "publisher": "apps/publisher",
    "site-publisher": "apps/site-publisher",
    "profile-publisher": "apps/profile-publisher",
    "social-inbox": "apps/social-inbox",
    "feed-reader": "apps/feed-reader",
    "trust-graph": "apps/trust-graph",
}
FIRST_PARTY_MAINTENANCE_POLICY_FILE = Path(
    "tools/release-certification/first-party-app-maintenance-policy.json"
)
MAINTENANCE_REQUIRED_FIELDS = (
    "owner",
    "ownerUri",
    "supportLevel",
    "dataSchemaPolicy",
    "migrationPolicy",
    "backupRestore",
    "securityPolicy",
    "deprecationPolicy",
    "supportUri",
)
FIRST_PARTY_MAINTENANCE_OWNER = "crypta-core"
FIRST_PARTY_MAINTENANCE_OWNER_URI = "https://example.invalid/crypta/owners/core"
MAINTENANCE_ALLOWED_VALUES = {
    "supportLevel": {
        "core",
        "maintained",
        "reference",
        "local-rc",
        "preview",
        "maintenance",
        "deprecated",
        "unsupported",
    },
    "dataSchemaPolicy": {"stateless", "declared", "migratable", "external", "not-applicable"},
    "migrationPolicy": {
        "none",
        "declared",
        "dry-run-required",
        "operator-approved",
        "not-applicable",
    },
    "backupRestore": {
        "not-applicable",
        "export-only",
        "export-import",
        "operator-supported",
        "unsupported",
    },
    "securityPolicy": {"catalog-advisories", "project-security-policy", "unsupported"},
    "deprecationPolicy": {"none", "notice-only", "replacement-required", "security-only"},
}
FIRST_PARTY_POLICY_ALLOWED_VALUES = {
    "channel": {"stable", "beta", "nightly", "deprecated"},
    "supportStatus": {"supported", "maintenance", "experimental", "deprecated", "unsupported"},
    "deprecationStatus": {"none", "deprecated", "retired"},
}
MAINTENANCE_VERSION_BOUND_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
APP_STORE_SUBMISSION_EVIDENCE_IDS = (
    "app-store.submission-package-schema",
    "app-store.submission-cli",
    "app-store.pre-review",
    "app-store.review-decision-states",
    "app-store.review-receipt-issued",
    "app-store.rejection-record",
    "app-store.resubmission-link",
    "app-store.transparency-log",
    "app-store.catalog-candidate",
    "app-store.third-party-sample-flow",
    "app-store.redaction-clean",
)
CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS = (
    "app-platform.signed-bundles",
    "app-catalog.first-party-maintenance-policy",
    "catalog.smoke",
    "app-review.trusted-receipts",
    "app-review.first-party-catalog",
    "app-review.first-party-review-chain",
    *APP_STORE_SUBMISSION_EVIDENCE_IDS,
    "platform-api.contract",
    "platform-api.stable-baseline",
    "platform-api.stable-breaking-change-check",
    "platform-api.manifest-target-stability",
    "platform-api.first-party-stability-declarations",
    "platform-api.stable-reference-docs",
    "app-ui.lint",
    "apphost.sandbox-provider",
    "app-update.data-migration-contract",
    "app-data.backup-restore-portability",
    "catalog.security-advisories",
    "catalog.version-denylist",
    "app-review.receipt-revocation",
    "app-review.reviewer-key-compromise-flow",
    "app-update.security-denylist-gates",
    "app-services.registry",
    "app-services.grants",
    "app-services.dependency-graph",
    "app-services.grant-bundles",
    "app-services.dependency-redaction",
)
LIVE_NETWORK_REQUIRED_IDS = (
    "live-network-beta.preflight",
    "live-network-beta.catalog-usk-fetch",
    "live-network-beta.app-install-update-rollback",
    "live-network-beta.content-fetch",
    "live-network-beta.feed-subscription",
    "live-network-beta.profile-publish",
    "live-network-beta.trust-statement-publish-import",
    "live-network-beta.interop-perf-budget",
    "live-network-beta.redaction",
)
SECRET_OPTION_NAMES = {
    "--private-key-base64",
    "--private-key-file",
    "--private-key-env",
    "--reviewer-private-key-base64",
    "--reviewer-private-key-file",
    "--reviewer-private-key-env",
    "--form-password-env",
    "--private-insert-uri-env",
    "--private-insert-uri-file",
}
BAD_ARTIFACT_NAMES = {".DS_Store"}
BAD_ARTIFACT_DIRS = {"__MACOSX"}

PRIVATE_INSERT_URI_RE = re.compile(
    r"(?:"
    r"\b(?:crypta:|freenet:)?(?:SSK|USK)@[^/,\s\"'<>)]*(?:PRIVATE|INSERT|AQECAAE)[^\s\"'<>)]*"
    r"|"
    r"(?<![\w-])[\"']?(?:private[-_ ]*)?insert(?:[-_ ]*uri)?[\"']?(?![\w-])"
    r"\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?"
    r"(?:crypta:|freenet:)?(?:SSK|USK)@"
    r"(?=[A-Za-z0-9~_-]{8,},)[A-Za-z0-9~_,=-]+(?:/[^\s`'\"<>)]*)?"
    r"|"
    r"(?<![\w-])[\"']?privateInsertUri[\"']?(?![\w-])\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?"
    r"(?:crypta:|freenet:)?(?:SSK|USK)@"
    r"(?=[A-Za-z0-9~_-]{8,},)[A-Za-z0-9~_,=-]+(?:/[^\s`'\"<>)]*)?"
    r")",
    re.IGNORECASE,
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE,
)
PRIVATE_KEY_HEADER_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE)
BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE)
AUTH_HEADER_RE = re.compile(
    r"(?<![\w-])[\"']?Authorization[\"']?\s*:\s*[\"']?(?:Bearer|Basic|Digest)?\s*([^\s,'\"}]+)",
    re.IGNORECASE,
)
APP_TOKEN_VALUE_RE = re.compile(
    r"(?<![\w-])[\"']?(?:CRYPTAD_APP_TOKEN|browserSessionToken|appProcessToken|X-Crypta-App-Session|"
    r"app[-_ ]?token|browser[-_ ]?session[-_ ]?token)[\"']?(?![\w-])"
    r"\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?([^'\"\s,;&}]+)",
    re.IGNORECASE,
)
FORM_PASSWORD_VALUE_RE = re.compile(
    r"(?<![\w-])[\"']?(?:CRYPTAD_CERT_FORM_PASSWORD|formPassword|form[-_ ]?password)[\"']?(?![\w-])"
    r"\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?([^'\"\s,;&}]+)",
    re.IGNORECASE,
)
RAW_BODY_VALUE_RE = re.compile(
    r"(?<![\w-])[\"']?(?:"
    r"raw[-_ ]*(?:(?:request|response|feed|fetched|social|message|profile|trust|app[-_ ]?data)[-_ ]*)?"
    r"(?:body|document|payload|content|value|values)"
    r"|"
    r"(?:request|response|feed|fetched|social|message|profile|trust|app[-_ ]?data)[-_ ]*raw[-_ ]*"
    r"(?:body|document|payload|content|value|values)"
    r"|"
    r"(?:private|unredacted)[-_ ]*"
    r"(?:(?:request|response|feed|fetched|social|message|profile|trust|app[-_ ]?data)[-_ ]*)?"
    r"(?:body|document|payload|content|value|values)"
    r")[\"']?(?![\w-])\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?([^'\"\r\n}]+)",
    re.IGNORECASE,
)
CI_SECRET_VALUE_RE = re.compile(
    r"(?<![\w-])[\"']?(?:GITHUB_TOKEN|SONAR_TOKEN|ACTIONS_ID_TOKEN_REQUEST_TOKEN|AWS_SECRET_ACCESS_KEY|"
    r"CRYPTAD_[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PRIVATE|INSERT_URI)[A-Z0-9_]*)"
    r"[\"']?(?![\w-])\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?([^'\"\s,;&}]+)",
    re.IGNORECASE,
)
SECRET_ENV_VALUE_NAME_RE = re.compile(
    r"(?:^|_)(?:TOKEN|PASSWORD|SECRET|PRIVATE|PRIVATE_KEY|INSERT_URI|FORM_PASSWORD)(?:$|_)",
    re.IGNORECASE,
)
SECRET_ENV_VALUE_SKIP_SUFFIXES = ("_ENV", "_FILE", "_PATH", "_DIR")
SECRET_ENV_INDIRECTION_NAMES = {"CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV"}
SECRET_ENV_FILE_INDIRECTION_NAMES = {
    "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE",
    "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE",
    "CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE",
}
MIN_SECRET_ENV_VALUE_LENGTH = 6
URL_USERINFO_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@", re.IGNORECASE)
FILE_URI_RE = re.compile(r"\bfile:///[^\s\"'<>]+", re.IGNORECASE)
WINDOWS_PATH_RE = re.compile(r"(?<![A-Za-z0-9_:/.\->])[A-Za-z]:[\\/][^:*?\"<>|\r\n]+")
HOST_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->])/"
    r"(?:Users|home|work|workspace|tmp|private/tmp|var/folders|mnt|Volumes|root|opt|runner|__w)"
    r"(?:/[^\s\"'<>),;]+)+"
)
DEFAULT_REVIEW_POLICY_ID = "crypta-app-review-v1"
DEFAULT_REVIEW_POLICY_VERSION = "1"
FIXTURE_APP_SIGNING_KEY_ID = "crypta-production-beta-test-app"
FIXTURE_REVIEWER_KEY_ID = "crypta-production-beta-test-review"
SIGNING_PROFILE_ENV_KEYS = (
    "CRYPTAD_APP_SIGNING_KEY_ID",
    "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE",
    "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64",
    "CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE",
    "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64",
    "CRYPTAD_APP_REVIEWER_KEY_ID",
    "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE",
    "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64",
    "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE",
    "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64",
    "CRYPTAD_APP_REVIEW_POLICY_ID",
    "CRYPTAD_APP_REVIEW_POLICY_VERSION",
)


@dataclasses.dataclass(frozen=True)
class Settings:
    workspace_root: Path
    out_dir: Path
    mode: str
    catalog_channel: str
    artifact_base_uri: str
    require_live_network: bool
    require_sandbox_provider_tests: bool
    skip_gradle: bool
    skip_full_build: bool
    use_fixture_evidence: bool
    allow_dirty_workspace: bool
    emergency_skip_live_network: bool
    emergency_skip_build: bool
    allow_test_signing_in_production: bool
    previous_summary: Path | None
    waiver_file: Path | None
    timeout_seconds: int
    clean_out_dir: bool


@dataclasses.dataclass
class CommandResult:
    name: str
    args: list[str]
    exit_code: int
    duration_ms: int
    stdout_tail: str
    stderr_tail: str

    def ok(self) -> bool:
        return self.exit_code == 0


@dataclasses.dataclass
class SigningProfile:
    kind: str
    generated_test_keys: bool
    env: dict[str, str]
    private_paths: list[Path]
    app_key_id: str
    reviewer_key_id: str
    review_policy_id: str
    review_policy_version: str


@dataclasses.dataclass
class PipelineState:
    settings: Settings
    version: str
    started_at: str
    commands: list[CommandResult]
    warnings: list[str]
    failures: list[str]
    signing_profile: SigningProfile | None = None
    certification_exit_code: int | None = None
    workspace_status_known: bool = True
    dirty_workspace: bool = False


class ReleaseArtifactError(RuntimeError):
    """Raised when a staged release artifact source is unsafe to publish."""


def production_build_skipped(settings: Settings) -> bool:
    return settings.mode == "production-beta" and (settings.skip_gradle or settings.skip_full_build)


def release_config_non_release(settings: Settings, profile: SigningProfile | None, state: PipelineState) -> bool:
    return (
        settings.mode == "developer-dry-run"
        or settings.allow_test_signing_in_production
        or production_build_skipped(settings)
        or state.dirty_workspace
        or not state.workspace_status_known
        or bool(profile and profile.kind != "production")
    )


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_json(path: Path, value: Any) -> None:
    write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_text(path: Path, value: str) -> None:
    write_bytes(path, value.encode("utf-8"))


def write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o666)
    try:
        view = memoryview(value)
        offset = 0
        while offset < len(view):
            written = os.write(fd, view[offset:])
            if written == 0:
                raise OSError(f"short write while writing {path}")
            offset += written
    finally:
        os.close(fd)


def write_redaction_fixture_text(path: Path, value: str) -> None:
    """Write redaction self-test text, including intentionally unsafe samples."""

    write_text(path, value)


def write_redaction_fixture_bytes(path: Path, value: bytes) -> None:
    """Write redaction self-test bytes, including intentionally unsafe binary samples."""

    write_bytes(path, value)


def resolve_workspace_input_path(raw_path: str, workspace_root: Path | None) -> Path | None:
    path_text = raw_path.strip()
    if not path_text:
        return None
    path = Path(path_text)
    if path.is_absolute() or workspace_root is None:
        return path
    return workspace_root / path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_scrub(text: str, settings: Settings) -> str:
    return release_certification.scrub_text(text, settings.workspace_root, settings.out_dir)


def display_path(path: Path, settings: Settings) -> str:
    return release_certification.display_path(path, settings.workspace_root, settings.out_dir)


def relative_artifact_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def release_artifact_uri(settings: Settings, artifact: Path) -> str:
    return f"{settings.artifact_base_uri.rstrip('/')}/{relative_artifact_path(artifact, settings.out_dir)}"


def relative_workspace_parts(workspace: Path, path: Path) -> tuple[str, ...]:
    try:
        return path.relative_to(workspace).parts
    except ValueError:
        return ()


def under_default_release_output_prefix(workspace: Path, out_dir: Path) -> bool:
    parts = relative_workspace_parts(workspace, out_dir)
    return len(parts) >= 2 and parts[0] == "build" and parts[1].startswith("production-beta")


def cleanup_sentinel(out_dir: Path) -> Path:
    return out_dir / OUT_DIR_SENTINEL


def validate_clean_out_dir_target(workspace: Path, out_dir: Path) -> None:
    if not out_dir.is_dir():
        raise SystemExit("--out-dir exists and is not a directory")
    if under_default_release_output_prefix(workspace, out_dir):
        return
    if cleanup_sentinel(out_dir).is_file():
        return
    raise SystemExit(
        "--out-dir cleanup refused for an existing directory without a production beta sentinel; "
        f"use an output under build/production-beta* or rerun with --no-clean-out-dir. Sentinel: {OUT_DIR_SENTINEL}"
    )


def git_tracked_files_under(workspace: Path, out_dir: Path) -> list[str] | None:
    try:
        rel_path = out_dir.relative_to(workspace).as_posix()
    except ValueError:
        return []
    pathspec = rel_path or "."
    try:
        completed = subprocess.run(
            ["git", "ls-files", "-z", "--", pathspec],
            cwd=str(workspace),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return [path for path in completed.stdout.split("\0") if path]


def validate_out_dir_has_no_tracked_files(workspace: Path, out_dir: Path) -> None:
    tracked_files = git_tracked_files_under(workspace, out_dir)
    if tracked_files is None:
        raise SystemExit(
            "--out-dir cleanup refused because git-tracked file status could not be verified; "
            "run from a Git checkout with git available or choose a fresh dedicated output directory."
        )
    if not tracked_files:
        return
    sample = ", ".join(tracked_files[:3])
    if len(tracked_files) > 3:
        sample += ", ..."
    raise SystemExit(
        "--out-dir refused because it contains git-tracked files; choose a dedicated release output directory "
        f"under build/production-beta*. Tracked files: {sample}"
    )


def ensure_safe_out_dir(settings: Settings) -> None:
    workspace = settings.workspace_root.resolve()
    out_dir = settings.out_dir.resolve()
    if out_dir == workspace:
        raise SystemExit("--out-dir must not be the workspace root")
    if not out_dir.is_relative_to(workspace):
        raise SystemExit("--out-dir must be inside --workspace-root")
    if out_dir in {Path("/"), Path.home().resolve()}:
        raise SystemExit("--out-dir is unsafe")
    parts = relative_workspace_parts(workspace, out_dir)
    if parts and parts[0] in PROTECTED_CLEAN_TOP_LEVELS:
        raise SystemExit(f"--out-dir refused for protected workspace path: {parts[0]}")
    if out_dir.exists():
        validate_clean_out_dir_target(workspace, out_dir)
        validate_out_dir_has_no_tracked_files(workspace, out_dir)
    if out_dir.exists() and settings.clean_out_dir:
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_text(cleanup_sentinel(out_dir), "Crypta production beta release output directory.\n")


def read_project_version(workspace_root: Path) -> str:
    build_file = workspace_root / "build.gradle.kts"
    text = build_file.read_text(encoding="utf-8")
    match = re.search(r'(?m)^\s*version\s*=\s*(?:"([^"\r\n]+)"|([0-9]+))\s*(?://.*)?$', text)
    if not match:
        raise SystemExit(
            "Unable to parse project version from build.gradle.kts; expected "
            'version = "<build-number>" or version = <build-number>.'
        )
    return match.group(1) or match.group(2)


def run_command(
    state: PipelineState,
    name: str,
    args: list[str],
    env: dict[str, str] | None = None,
    timeout_seconds: int | None = None,
    allow_failure: bool = False,
) -> CommandResult:
    started = dt.datetime.now(dt.timezone.utc)
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    try:
        completed = subprocess.run(
            args,
            cwd=str(state.settings.workspace_root),
            env=merged_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout_seconds or state.settings.timeout_seconds,
        )
        exit_code = completed.returncode
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr if isinstance(exc.stderr, str) else "") + "\nCommand timed out."
    except OSError as exc:
        exit_code = 127
        stdout = ""
        stderr = str(exc)
    duration_ms = int((dt.datetime.now(dt.timezone.utc) - started).total_seconds() * 1000)
    result = CommandResult(
        name=name,
        args=redact_command(args, state.settings),
        exit_code=exit_code,
        duration_ms=duration_ms,
        stdout_tail=safe_scrub(stdout[-4000:], state.settings),
        stderr_tail=safe_scrub(stderr[-4000:], state.settings),
    )
    state.commands.append(result)
    if exit_code != 0 and not allow_failure:
        state.failures.append(f"{name} failed with exit code {exit_code}")
    return result


def redact_command(args: list[str], settings: Settings) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    for arg in args:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        if arg in SECRET_OPTION_NAMES:
            redacted.append(arg)
            redact_next = True
        elif any(marker in arg.lower() for marker in ("private-key", "password", "insert-uri", "token")) and "=" in arg:
            key, _ = arg.split("=", 1)
            redacted.append(key + "=<redacted>")
        else:
            redacted.append(safe_scrub(arg, settings))
    return redacted


def git_status_args(settings: Settings) -> list[str]:
    args = ["git", "status", "--porcelain", "--untracked-files=all"]
    try:
        out_rel = settings.out_dir.resolve().relative_to(settings.workspace_root.resolve()).as_posix()
    except ValueError:
        return args
    if not out_rel:
        return args
    return [*args, "--", ".", f":(exclude){out_rel}", f":(exclude){out_rel}/**"]


def check_workspace_clean(state: PipelineState, stage: str = "initial") -> None:
    command_name = "git-status" if stage == "initial" else f"git-status-{stage}"
    result = run_command(
        state,
        command_name,
        git_status_args(state.settings),
        timeout_seconds=60,
        allow_failure=True,
    )
    if result.exit_code != 0:
        state.workspace_status_known = False
        state.warnings.append("Git status could not be read; workspace cleanliness is unknown.")
        if state.settings.mode in {"release-candidate", "production-beta"}:
            state.failures.append(
                f"{state.settings.mode} mode requires a readable git workspace status; "
                "rerun from a git checkout before certifying release artifacts."
        )
        return
    dirty = bool(result.stdout_tail.strip())
    state.dirty_workspace = state.dirty_workspace or dirty
    strict_mode = state.settings.mode in {"release-candidate", "production-beta"}
    if dirty and strict_mode and not state.settings.allow_dirty_workspace:
        if stage == "initial":
            state.failures.append(
                f"{state.settings.mode} mode requires a clean git workspace; "
                "pass --allow-dirty-workspace only for controlled reruns."
            )
        else:
            state.failures.append(
                f"{state.settings.mode} mode requires a clean git workspace after build/staging; "
                "build tasks changed tracked or unignored workspace files."
            )
    elif dirty:
        state.warnings.append("Workspace has uncommitted changes; artifacts are marked as non-release.")


def validate_toolchain(state: PipelineState) -> None:
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info < (3, 10):
        state.failures.append(f"python3 3.10 or newer is required; found {python_version}.")
    run_command(state, "java-version", ["java", "-version"], timeout_seconds=60, allow_failure=True)
    if not state.settings.skip_gradle:
        wrapper = state.settings.workspace_root / ("gradlew.bat" if platform.system() == "Windows" else "gradlew")
        run_command(state, "gradle-version", [str(wrapper), "--version"], timeout_seconds=180)


def find_crypta_app(workspace_root: Path) -> Path | None:
    script = crypta_app_launcher_name()
    candidate = workspace_root / "platform-devtools/build/install/crypta-app/bin" / script
    return candidate if candidate.is_file() else None


def crypta_app_launcher_name() -> str:
    return "crypta-app.bat" if platform.system() == "Windows" else "crypta-app"


def gradle_wrapper(settings: Settings) -> Path:
    return settings.workspace_root / ("gradlew.bat" if platform.system() == "Windows" else "gradlew")


def run_gradle(state: PipelineState, name: str, tasks: list[str], env: dict[str, str] | None = None) -> CommandResult | None:
    if state.settings.skip_gradle:
        state.warnings.append(f"Skipped Gradle stage `{name}` by explicit request.")
        if state.settings.mode in {"release-candidate", "production-beta"} and not state.settings.emergency_skip_build:
            state.failures.append(
                f"{state.settings.mode} mode cannot skip Gradle stage `{name}` without --emergency-skip-build."
            )
        return None
    return run_command(
        state,
        name,
        [str(gradle_wrapper(state.settings)), *tasks],
        env=env,
        timeout_seconds=max(state.settings.timeout_seconds, 1800),
    )


def has_env_signing(env: dict[str, str]) -> bool:
    return bool(
        env.get("CRYPTAD_APP_SIGNING_KEY_ID", "").strip()
        and (
            env.get("CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE", "").strip()
            or env.get("CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64", "").strip()
        )
        and (
            env.get("CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE", "").strip()
            or env.get("CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64", "").strip()
        )
    )


def has_env_reviewer(env: dict[str, str]) -> bool:
    return bool(
        env.get("CRYPTAD_APP_REVIEWER_KEY_ID", "").strip()
        and (
            env.get("CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE", "").strip()
            or env.get("CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64", "").strip()
        )
        and (
            env.get("CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE", "").strip()
            or env.get("CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64", "").strip()
        )
    )


def env_value_or_default(env: dict[str, str], key: str, default: str) -> str:
    return env.get(key, "").strip() or default


def fixture_signing_env(source: dict[str, str]) -> dict[str, str]:
    env = source.copy()
    for key in SIGNING_PROFILE_ENV_KEYS:
        env.pop(key, None)
    env.update(
        {
            "CRYPTAD_APP_SIGNING_KEY_ID": FIXTURE_APP_SIGNING_KEY_ID,
            "CRYPTAD_APP_REVIEWER_KEY_ID": FIXTURE_REVIEWER_KEY_ID,
            "CRYPTAD_APP_REVIEW_POLICY_ID": DEFAULT_REVIEW_POLICY_ID,
            "CRYPTAD_APP_REVIEW_POLICY_VERSION": DEFAULT_REVIEW_POLICY_VERSION,
        }
    )
    return env


def generate_key_pair(
    state: PipelineState,
    cli: Path,
    key_dir: Path,
    key_id: str,
    basename: str,
) -> tuple[Path, Path, Path]:
    private_key = key_dir / f"{basename}-private.der"
    public_key = key_dir / f"{basename}-public.der"
    trusted_keys = key_dir / f"{basename}-trusted-app-keys.properties"
    run_command(
        state,
        f"generate-{basename}-test-key",
        [
            str(cli),
            "keys",
            "generate",
            "--key-id",
            key_id,
            "--private-key-file",
            str(private_key),
            "--public-key-file",
            str(public_key),
            "--trusted-keys-file",
            str(trusted_keys),
            "--overwrite",
        ],
        timeout_seconds=180,
    )
    return private_key, public_key, trusted_keys


def prepare_signing_profile(state: PipelineState, key_dir: Path) -> SigningProfile:
    env = os.environ.copy()
    production_keys_required = state.settings.mode == "production-beta"
    generated = False
    private_paths: list[Path] = []
    app_key_id = env.get("CRYPTAD_APP_SIGNING_KEY_ID", "").strip()
    reviewer_key_id = env.get("CRYPTAD_APP_REVIEWER_KEY_ID", "").strip()
    review_policy_id = env_value_or_default(env, "CRYPTAD_APP_REVIEW_POLICY_ID", DEFAULT_REVIEW_POLICY_ID)
    review_policy_version = env_value_or_default(env, "CRYPTAD_APP_REVIEW_POLICY_VERSION", DEFAULT_REVIEW_POLICY_VERSION)

    if state.settings.use_fixture_evidence:
        env = fixture_signing_env(env)
        state.warnings.append("Fixture evidence mode ignores ambient signing and reviewer inputs.")
        return SigningProfile(
            kind="test-fixture",
            generated_test_keys=True,
            env=env,
            private_paths=[],
            app_key_id=FIXTURE_APP_SIGNING_KEY_ID,
            reviewer_key_id=FIXTURE_REVIEWER_KEY_ID,
            review_policy_id=DEFAULT_REVIEW_POLICY_ID,
            review_policy_version=DEFAULT_REVIEW_POLICY_VERSION,
        )

    if has_env_signing(env) and has_env_reviewer(env):
        kind = "production" if state.settings.mode == "production-beta" else "configured"
        if state.settings.mode == "production-beta" and state.settings.allow_test_signing_in_production:
            kind = "configured"
            state.warnings.append(
                "Production-beta test-signing escape hatch is enabled; configured signing inputs are labelled non-production and outputs remain non-release."
            )
        return SigningProfile(
            kind=kind,
            generated_test_keys=False,
            env=env,
            private_paths=[],
            app_key_id=app_key_id,
            reviewer_key_id=reviewer_key_id,
            review_policy_id=review_policy_id,
            review_policy_version=review_policy_version,
        )

    if production_keys_required and not state.settings.allow_test_signing_in_production:
        state.failures.append(
            "production-beta mode requires complete app signing and reviewer key inputs from the environment or protected files."
        )
        return SigningProfile(
            kind="missing",
            generated_test_keys=False,
            env=env,
            private_paths=[],
            app_key_id=app_key_id,
            reviewer_key_id=reviewer_key_id,
            review_policy_id=review_policy_id,
            review_policy_version=review_policy_version,
        )

    cli = find_crypta_app(state.settings.workspace_root)
    if cli is None or not cli.is_file():
        if state.settings.use_fixture_evidence or state.settings.skip_gradle:
            state.warnings.append("crypta-app is unavailable; fixture/test signing metadata will be used.")
            env = fixture_signing_env(env)
            return SigningProfile(
                kind="test-fixture",
                generated_test_keys=True,
                env=env,
                private_paths=[],
                app_key_id=FIXTURE_APP_SIGNING_KEY_ID,
                reviewer_key_id=FIXTURE_REVIEWER_KEY_ID,
                review_policy_id=DEFAULT_REVIEW_POLICY_ID,
                review_policy_version=DEFAULT_REVIEW_POLICY_VERSION,
            )
        state.failures.append("crypta-app launcher is required to generate dry-run signing keys.")
        return SigningProfile("missing", False, env, [], app_key_id, reviewer_key_id, review_policy_id, review_policy_version)

    key_dir.mkdir(parents=True, exist_ok=True)
    app_key_id = app_key_id or "crypta-production-beta-dry-run-app"
    reviewer_key_id = reviewer_key_id or "crypta-production-beta-dry-run-reviewer"
    app_private, app_public, _trusted = generate_key_pair(state, cli, key_dir, app_key_id, "app-signing")
    reviewer_private, reviewer_public, _review_trusted = generate_key_pair(
        state, cli, key_dir, reviewer_key_id, "reviewer-signing"
    )
    private_paths.extend([app_private, reviewer_private])
    for key in (
        "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64",
        "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64",
        "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64",
        "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64",
    ):
        env.pop(key, None)
    env.update(
        {
            "CRYPTAD_APP_SIGNING_KEY_ID": app_key_id,
            "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE": str(app_private),
            "CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE": str(app_public),
            "CRYPTAD_APP_REVIEWER_KEY_ID": reviewer_key_id,
            "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE": str(reviewer_private),
            "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE": str(reviewer_public),
            "CRYPTAD_APP_REVIEW_POLICY_ID": review_policy_id,
            "CRYPTAD_APP_REVIEW_POLICY_VERSION": review_policy_version,
        }
    )
    generated = True
    state.warnings.append("Generated ephemeral non-production signing and reviewer keys for this dry-run.")
    return SigningProfile(
        kind="test",
        generated_test_keys=generated,
        env=env,
        private_paths=private_paths,
        app_key_id=app_key_id,
        reviewer_key_id=reviewer_key_id,
        review_policy_id=review_policy_id,
        review_policy_version=review_policy_version,
    )


def app_private_key_args(profile: SigningProfile) -> list[str]:
    private_file = profile.env.get("CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE", "").strip()
    if private_file:
        return ["--private-key-file", private_file]
    return ["--private-key-env", "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64"]


def reviewer_private_key_args(profile: SigningProfile) -> list[str]:
    private_file = profile.env.get("CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE", "").strip()
    if private_file:
        return ["--reviewer-private-key-file", private_file]
    return ["--reviewer-private-key-env", "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64"]


def trusted_app_public_key_args(profile: SigningProfile) -> list[str]:
    public_file = profile.env.get("CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE", "").strip()
    if public_file:
        return ["--trusted-public-key-file", public_file]
    return [
        "--trusted-public-key-base64",
        profile.env.get("CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64", ""),
    ]


def first_tree_symlink(root: Path) -> Path | None:
    if root.is_symlink():
        return root
    for current, dir_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in sorted([*dir_names, *file_names]):
            candidate = current_path / name
            if candidate.is_symlink():
                return candidate
    return None


def reject_tree_symlinks(root: Path, label: str) -> None:
    symlink = first_tree_symlink(root)
    if symlink is None:
        return
    rel_path = relative_artifact_path(symlink, root)
    raise ReleaseArtifactError(f"{label} contains a symlink, which is not allowed in production beta artifacts: {rel_path}")


def safe_copy_tree(src: Path, dst: Path, label: str) -> None:
    reject_tree_symlinks(src, label)
    if dst.exists():
        shutil.rmtree(dst)
    ignore = shutil.ignore_patterns("._*", ".DS_Store", "__MACOSX")
    shutil.copytree(src, dst, ignore=ignore, symlinks=True)
    try:
        reject_tree_symlinks(dst, f"copied {label}")
    except ReleaseArtifactError:
        shutil.rmtree(dst)
        raise


def launcher_install_dir(settings: Settings) -> Path:
    return settings.workspace_root / "platform-devtools/build/install/crypta-app"


def copy_launcher_distribution(state: PipelineState) -> None:
    settings = state.settings
    src = launcher_install_dir(settings)
    dst = settings.out_dir / "build/crypta-app-launcher"
    if src.is_dir():
        try:
            safe_copy_tree(src, dst, "crypta-app launcher distribution")
        except ReleaseArtifactError as exc:
            state.failures.append(str(exc))
    else:
        write_text(dst / "README.txt", "crypta-app launcher was not generated in this run.\n")


def staged_app_dir(settings: Settings, app_id: str) -> Path:
    return settings.workspace_root / APP_PROJECT_DIRS[app_id] / "build/cryptad-app" / app_id


def parse_properties(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def copy_staged_apps(state: PipelineState) -> dict[str, Path]:
    settings = state.settings
    copied: dict[str, Path] = {}
    base = settings.out_dir / "build/staged-apps"
    base.mkdir(parents=True, exist_ok=True)
    for app_id in APP_IDS:
        src = staged_app_dir(settings, app_id)
        dst = base / app_id
        if src.is_dir():
            try:
                safe_copy_tree(src, dst, f"staged app {app_id}")
            except ReleaseArtifactError as exc:
                state.failures.append(str(exc))
                continue
            copied[app_id] = dst
    return copied


def public_key_base64(raw_file: Path | None, raw_value: str) -> str:
    if raw_value:
        text = raw_value.strip()
        if "BEGIN PUBLIC KEY" in text:
            return "".join(
                line.strip()
                for line in text.splitlines()
                if line.strip() and "BEGIN PUBLIC KEY" not in line and "END PUBLIC KEY" not in line
            )
        return "".join(text.split())
    if raw_file is None:
        return ""
    raw = raw_file.read_bytes()
    text = raw.decode("utf-8", errors="ignore")
    if "BEGIN PUBLIC KEY" in text:
        return "".join(
            line.strip()
            for line in text.splitlines()
            if line.strip() and "BEGIN PUBLIC KEY" not in line and "END PUBLIC KEY" not in line
        )
    try:
        decoded = base64.b64decode("".join(text.split()), validate=True)
        if decoded:
            return "".join(text.split())
    except (ValueError, base64.binascii.Error):
        pass
    return base64.b64encode(raw).decode("ascii")


def workspace_file_path(raw_file: str, workspace_root: Path) -> Path:
    path = Path(raw_file)
    if path.is_absolute():
        return path
    return workspace_root / path


def write_trusted_reviewer_keys(path: Path, profile: SigningProfile, workspace_root: Path) -> None:
    public_file = profile.env.get("CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE", "").strip()
    public_base64 = profile.env.get("CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64", "").strip()
    public_key = public_key_base64(
        workspace_file_path(public_file, workspace_root) if public_file else None,
        public_base64,
    )
    write_text(
        path,
        "\n".join(
            [
                "trusted.reviewers.version=2",
                f"reviewer.1.id={profile.reviewer_key_id}",
                "reviewer.1.algorithm=Ed25519",
                f"reviewer.1.public.key.base64={public_key}",
                "reviewer.1.display.name=Production Beta Certification Reviewer",
                f"reviewer.1.policy.id={profile.review_policy_id}",
                f"reviewer.1.policy.version={profile.review_policy_version}",
                "reviewer.1.status=active",
                "",
            ]
        ),
    )


def manifest_summary(manifest: dict[str, str], app_id: str) -> str:
    return manifest.get("app.summary") or f"First-party Crypta app bundle for {app_id}."


def permission_rationale_args(permissions: str) -> list[str]:
    args: list[str] = []
    for permission in sorted({part.strip() for part in permissions.split(",") if part.strip()}):
        args.extend(["--permission-rationale", f"{permission}=Required by the first-party app manifest."])
    return args


def first_party_maintenance_policy_file(state: PipelineState) -> Path:
    return state.settings.workspace_root / FIRST_PARTY_MAINTENANCE_POLICY_FILE


def expected_first_party_maintenance_uri(app_id: str, field: str) -> str | None:
    if field == "ownerUri":
        return FIRST_PARTY_MAINTENANCE_OWNER_URI
    if field == "supportUri":
        return f"https://example.invalid/crypta/apps/{app_id}/support"
    return None


def safe_single_line(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped or "\n" in stripped or "\r" in stripped:
        return None
    return stripped


def invalid_maintenance_policy_fields(app_id: str, app_policy: dict[str, Any]) -> list[str]:
    invalid: list[str] = []
    for field, allowed in FIRST_PARTY_POLICY_ALLOWED_VALUES.items():
        value = safe_single_line(app_policy.get(field))
        if value not in allowed:
            invalid.append(field)
    for field in ("minimumCryptaVersion", "maximumCryptaVersion"):
        value = app_policy.get(field)
        if value is not None and (
            not isinstance(value, str) or MAINTENANCE_VERSION_BOUND_RE.fullmatch(value) is None
        ):
            invalid.append(field)
    maintenance = app_policy.get("maintenance")
    if not isinstance(maintenance, dict):
        invalid.append("maintenance")
        return invalid
    owner = safe_single_line(maintenance.get("owner"))
    if owner != FIRST_PARTY_MAINTENANCE_OWNER:
        invalid.append("maintenance.owner")
    for field in ("ownerUri", "supportUri"):
        value = safe_single_line(maintenance.get(field))
        if value != expected_first_party_maintenance_uri(app_id, field):
            invalid.append(f"maintenance.{field}")
    for field, allowed in MAINTENANCE_ALLOWED_VALUES.items():
        value = safe_single_line(maintenance.get(field))
        if value not in allowed:
            invalid.append(f"maintenance.{field}")
    return invalid


def load_first_party_maintenance_policy(state: PipelineState) -> dict[str, dict[str, Any]]:
    policy_file = first_party_maintenance_policy_file(state)
    try:
        with policy_file.open("r", encoding="utf-8") as handle:
            raw_policy = json.load(handle)
    except OSError as exc:
        record_maintenance_policy_problem(
            state,
            "first-party maintenance policy could not be loaded from "
            f"{display_path(policy_file, state.settings)}: {exc.strerror or exc.__class__.__name__}",
        )
        return {}
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        record_maintenance_policy_problem(
            state,
            "first-party maintenance policy could not be parsed from "
            f"{display_path(policy_file, state.settings)}: {exc.__class__.__name__}",
        )
        return {}
    apps = raw_policy.get("apps") if isinstance(raw_policy, dict) else None
    if not isinstance(apps, dict):
        record_maintenance_policy_problem(state, "first-party maintenance policy has no apps map.")
        return {}
    normalized: dict[str, dict[str, Any]] = {}
    for app_id in APP_IDS:
        app_policy = apps.get(app_id)
        if not isinstance(app_policy, dict):
            record_maintenance_policy_problem(
                state, f"first-party maintenance policy is missing {app_id}."
            )
            continue
        maintenance = app_policy.get("maintenance")
        if not isinstance(maintenance, dict):
            record_maintenance_policy_problem(
                state, f"first-party maintenance policy for {app_id} has no maintenance block."
            )
            continue
        missing = [
            field
            for field in MAINTENANCE_REQUIRED_FIELDS
            if not isinstance(maintenance.get(field), str) or not maintenance.get(field).strip()
        ]
        if missing:
            record_maintenance_policy_problem(
                state,
                f"first-party maintenance policy for {app_id} is missing: {', '.join(missing)}.",
            )
            continue
        invalid = invalid_maintenance_policy_fields(app_id, app_policy)
        if invalid:
            record_maintenance_policy_problem(
                state,
                "first-party maintenance policy for "
                f"{app_id} has invalid or unsafe fields: {', '.join(invalid)}.",
            )
            continue
        normalized[app_id] = app_policy
    extra_apps = sorted(set(apps) - set(APP_IDS))
    if extra_apps:
        state.warnings.append(
            f"First-party maintenance policy contains {len(extra_apps)} unknown app id(s)."
        )
    return normalized


def record_maintenance_policy_problem(state: PipelineState, message: str) -> None:
    if state.settings.mode == "developer-dry-run":
        state.warnings.append(message)
    else:
        state.failures.append(message)


def policy_value(policy: dict[str, Any] | None, key: str, fallback: str) -> str:
    if not isinstance(policy, dict):
        return fallback
    value = policy.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else fallback


def maintenance_policy_args(policy: dict[str, Any]) -> list[str]:
    maintenance = policy.get("maintenance")
    if not isinstance(maintenance, dict):
        return []
    args: list[str] = []
    for field, flag in (
        ("owner", "--maintenance-owner"),
        ("ownerUri", "--maintenance-owner-uri"),
        ("supportLevel", "--maintenance-support-level"),
        ("dataSchemaPolicy", "--maintenance-data-schema-policy"),
        ("migrationPolicy", "--maintenance-migration-policy"),
        ("backupRestore", "--maintenance-backup-restore"),
        ("securityPolicy", "--maintenance-security-policy"),
        ("deprecationPolicy", "--maintenance-deprecation-policy"),
        ("supportUri", "--maintenance-support-uri"),
    ):
        value = maintenance.get(field)
        if isinstance(value, str) and value.strip():
            args.extend([flag, value.strip()])
    return args


def policy_version_bound_args(policy: dict[str, Any]) -> list[str]:
    args: list[str] = []
    for field, flag in (
        ("minimumCryptaVersion", "--minimum-crypta-version"),
        ("maximumCryptaVersion", "--maximum-crypta-version"),
    ):
        value = policy.get(field)
        if isinstance(value, str) and value.strip():
            args.extend([flag, value.strip()])
    return args


def maintenance_summary(policy: dict[str, Any]) -> dict[str, Any]:
    maintenance = policy.get("maintenance") if isinstance(policy, dict) else {}
    if not isinstance(maintenance, dict):
        maintenance = {}
    return {
        "owner": maintenance.get("owner"),
        "ownerUri": maintenance.get("ownerUri"),
        "supportLevel": maintenance.get("supportLevel"),
        "dataSchemaPolicy": maintenance.get("dataSchemaPolicy"),
        "migrationPolicy": maintenance.get("migrationPolicy"),
        "backupRestore": maintenance.get("backupRestore"),
        "securityPolicy": maintenance.get("securityPolicy"),
        "deprecationPolicy": maintenance.get("deprecationPolicy"),
        "supportUri": maintenance.get("supportUri"),
    }


def sanitized_policy_token(field: str, value: Any) -> Any:
    stripped = safe_single_line(value)
    return stripped if stripped in FIRST_PARTY_POLICY_ALLOWED_VALUES[field] else "<redacted>"


def sanitized_version_bound(value: Any) -> Any:
    if value is None:
        return None
    return (
        value
        if isinstance(value, str) and MAINTENANCE_VERSION_BOUND_RE.fullmatch(value) is not None
        else "<redacted>"
    )


def sanitized_maintenance_value(app_id: str, field: str, value: Any) -> Any:
    stripped = safe_single_line(value)
    if field == "owner":
        return stripped if stripped == FIRST_PARTY_MAINTENANCE_OWNER else "<redacted>"
    if field in ("ownerUri", "supportUri"):
        expected = expected_first_party_maintenance_uri(app_id, field)
        return stripped if stripped == expected else "<redacted>"
    if field in MAINTENANCE_ALLOWED_VALUES:
        return stripped if stripped in MAINTENANCE_ALLOWED_VALUES[field] else "<redacted>"
    return "<redacted>"


def sanitized_first_party_maintenance_policy_input(raw_policy: Any) -> dict[str, Any]:
    raw_apps = raw_policy.get("apps") if isinstance(raw_policy, dict) else None
    schema_version = (
        1
        if isinstance(raw_policy, dict) and raw_policy.get("schemaVersion") == 1
        else "<redacted>"
    )
    owner = (
        FIRST_PARTY_MAINTENANCE_OWNER
        if isinstance(raw_policy, dict)
        and raw_policy.get("owner") == FIRST_PARTY_MAINTENANCE_OWNER
        else "<redacted>"
    )
    sanitized: dict[str, Any] = {
        "schemaVersion": schema_version,
        "owner": owner,
        "apps": {},
    }
    if not isinstance(raw_apps, dict):
        return sanitized
    sanitized_apps = sanitized["apps"]
    for app_id in APP_IDS:
        app_policy = raw_apps.get(app_id)
        if not isinstance(app_policy, dict):
            continue
        maintenance = app_policy.get("maintenance")
        if not isinstance(maintenance, dict):
            maintenance = {}
        sanitized_apps[app_id] = {
            "channel": sanitized_policy_token("channel", app_policy.get("channel")),
            "supportStatus": sanitized_policy_token(
                "supportStatus", app_policy.get("supportStatus")
            ),
            "deprecationStatus": sanitized_policy_token(
                "deprecationStatus", app_policy.get("deprecationStatus")
            ),
            "minimumCryptaVersion": sanitized_version_bound(
                app_policy.get("minimumCryptaVersion")
            ),
            "maximumCryptaVersion": sanitized_version_bound(
                app_policy.get("maximumCryptaVersion")
            ),
            "maintenance": {
                field: sanitized_maintenance_value(app_id, field, maintenance.get(field))
                for field in MAINTENANCE_REQUIRED_FIELDS
            },
        }
    return sanitized


def copy_first_party_maintenance_policy_input(state: PipelineState) -> None:
    policy_file = first_party_maintenance_policy_file(state)
    if not policy_file.is_file():
        return
    try:
        with policy_file.open("r", encoding="utf-8") as handle:
            raw_policy = json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return
    target = state.settings.out_dir / "inputs/first-party-app-maintenance-policy.json"
    write_json(target, sanitized_first_party_maintenance_policy_input(raw_policy))


def package_catalog_and_reviews(
    state: PipelineState,
    profile: SigningProfile,
    copied_apps: dict[str, Path],
    work_dir: Path,
) -> None:
    cli = find_crypta_app(state.settings.workspace_root)
    if cli is None or not cli.is_file():
        state.failures.append("crypta-app launcher is missing; cannot package first-party app catalog.")
        return
    bundle_dir = state.settings.out_dir / "build/app-bundles"
    catalog_dir = state.settings.out_dir / "catalog"
    receipts_dir = state.settings.out_dir / "reviews/review-receipts"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    catalog_dir.mkdir(parents=True, exist_ok=True)
    receipts_dir.mkdir(parents=True, exist_ok=True)
    descriptor_dir = work_dir / "catalog-descriptors"
    descriptor_dir.mkdir(parents=True, exist_ok=True)
    trusted_reviewers = work_dir / "trusted-reviewers.properties"
    write_trusted_reviewer_keys(trusted_reviewers, profile, state.settings.workspace_root)
    artifact_timestamp = state.started_at

    descriptors: list[Path] = []
    receipts: list[Path] = []
    app_summaries: list[dict[str, Any]] = []
    maintenance_policies = load_first_party_maintenance_policy(state)
    for app_id, app_dir in copied_apps.items():
        manifest_path = app_dir / "cryptad-app.properties"
        if not manifest_path.is_file():
            state.failures.append(f"staged app manifest missing for {app_id}")
            continue
        manifest = parse_properties(manifest_path)
        version = manifest.get("app.version", state.version)
        app_name = manifest.get("app.name", app_id)
        zip_path = bundle_dir / f"{app_id}-{version}.zip"
        descriptor = descriptor_dir / f"{app_id}.properties"
        receipt = receipts_dir / f"{app_id}-review-receipt.properties"
        run_command(
            state,
            f"pack-{app_id}",
            [str(cli), "pack", "--bundle-dir", str(app_dir), "--output", str(zip_path), "--overwrite"],
            env=profile.env,
            timeout_seconds=300,
        )
        artifact_uri = release_artifact_uri(state.settings, zip_path)
        app_policy = maintenance_policies.get(app_id, {})
        support_status = policy_value(app_policy, "supportStatus", "supported")
        deprecation_status = policy_value(app_policy, "deprecationStatus", "none")
        entry_args = [
            str(cli),
            "catalog",
            "entry",
            "--bundle-dir",
            str(app_dir),
            "--artifact",
            str(zip_path),
            "--bundle-uri",
            artifact_uri,
            "--output",
            str(descriptor),
            "--summary",
            manifest_summary(manifest, app_id),
            "--channel",
            state.settings.catalog_channel,
            "--support-status",
            support_status,
            "--deprecation-status",
            deprecation_status,
            "--changelog-summary",
            f"Production beta candidate for {app_name}.",
            "--overwrite",
        ]
        entry_args.extend(policy_version_bound_args(app_policy))
        entry_args.extend(maintenance_policy_args(app_policy))
        permissions = manifest.get("app.permissions", "")
        entry_args.extend(permission_rationale_args(permissions))
        run_command(state, f"catalog-entry-{app_id}", entry_args, env=profile.env, timeout_seconds=300)
        run_command(
            state,
            f"review-sign-{app_id}",
            [
                str(cli),
                "review",
                "sign",
                "--catalog-entry",
                str(descriptor),
                "--receipt-file",
                str(receipt),
                "--reviewer-key-id",
                profile.reviewer_key_id,
                "--policy-id",
                profile.review_policy_id,
                "--policy-version",
                profile.review_policy_version,
                "--status",
                "reviewed",
                "--reviewed-at",
                artifact_timestamp,
                "--note",
                "First-party production beta review receipt.",
                "--overwrite",
            ]
            + reviewer_private_key_args(profile),
            env=profile.env,
            timeout_seconds=300,
        )
        run_command(
            state,
            f"review-verify-{app_id}",
            [
                str(cli),
                "review",
                "verify",
                "--catalog-entry",
                str(descriptor),
                "--receipt-file",
                str(receipt),
                "--trusted-reviewer-keys-file",
                str(trusted_reviewers),
            ],
            env=profile.env,
            timeout_seconds=300,
        )
        if descriptor.is_file():
            descriptors.append(descriptor)
        if receipt.is_file():
            receipts.append(receipt)
        if zip_path.is_file():
            app_summaries.append(
                {
                    "appId": app_id,
                    "version": version,
                    "artifact": relative_artifact_path(zip_path, state.settings.out_dir),
                    "sha256": sha256_file(zip_path),
                    "sizeBytes": zip_path.stat().st_size,
                    "channel": state.settings.catalog_channel,
                    "supportStatus": support_status,
                    "deprecationStatus": deprecation_status,
                    "maintenance": maintenance_summary(app_policy),
                    "nonProduction": profile.kind != "production",
                }
            )

    working_catalog = work_dir / "cryptad-app-catalog.properties"
    create_args = [
        str(cli),
        "catalog",
        "create",
        "--catalog-file",
        str(working_catalog),
        "--catalog-id",
        "crypta-first-party-production-beta",
        "--name",
        "Crypta First-Party Production Beta Catalog",
        "--generated-at",
        artifact_timestamp,
    ]
    for descriptor in descriptors:
        create_args.extend(["--entry", str(descriptor)])
    for receipt in receipts:
        create_args.extend(["--review-receipt", str(receipt)])
    create_args.append("--overwrite")
    run_command(state, "catalog-create-first-party", create_args, env=profile.env, timeout_seconds=300)
    run_command(
        state,
        "catalog-sign-first-party",
        [
            str(cli),
            "catalog",
            "sign",
            "--catalog-file",
            str(working_catalog),
            "--key-id",
            profile.app_key_id,
        ]
        + app_private_key_args(profile),
        env=profile.env,
        timeout_seconds=300,
    )
    run_command(
        state,
        "catalog-verify-first-party",
        [
            str(cli),
            "catalog",
            "verify",
            "--catalog-file",
            str(working_catalog),
            "--trusted-key-id",
            profile.app_key_id,
        ]
        + trusted_app_public_key_args(profile),
        env=profile.env,
        timeout_seconds=300,
    )
    signature = working_catalog.with_name(CANONICAL_CATALOG_SIGNATURE)
    if working_catalog.is_file():
        shutil.copy2(working_catalog, catalog_dir / "first-party-catalog.properties")
    if signature.is_file():
        shutil.copy2(signature, catalog_dir / CANONICAL_CATALOG_SIGNATURE)
        shutil.copy2(signature, catalog_dir / RELEASE_CATALOG_SIGNATURE_ALIAS)
    write_json(
        catalog_dir / "channel-metadata.json",
        {
            "schemaVersion": 1,
            "catalogId": "crypta-first-party-production-beta",
            "channel": state.settings.catalog_channel,
            "defaultAutomationChannel": "stable",
            "nonProduction": profile.kind != "production",
            "signingProfile": profile.kind,
            "artifactBaseUri": state.settings.artifact_base_uri,
            "firstPartyMaintenancePolicy": "inputs/first-party-app-maintenance-policy.json",
            "requiredMaintenanceApps": list(APP_IDS),
            "maintenancePolicyComplete": len(maintenance_policies) == len(APP_IDS),
            "apps": app_summaries,
        },
    )
    write_json(
        state.settings.out_dir / "reviews/review-transparency-log.json",
        {
            "schemaVersion": 1,
            "kind": "first-party-production-beta-review-transparency",
            "nonProduction": profile.kind != "production",
            "receipts": [
                {
                    "file": relative_artifact_path(receipt, state.settings.out_dir),
                    "sha256": sha256_file(receipt),
                    "sizeBytes": receipt.stat().st_size,
                }
                for receipt in receipts
                if receipt.is_file()
            ],
        },
    )


def create_fixture_artifacts(state: PipelineState) -> None:
    staged_root = state.settings.out_dir / "build/staged-apps"
    bundle_root = state.settings.out_dir / "build/app-bundles"
    catalog_root = state.settings.out_dir / "catalog"
    review_root = state.settings.out_dir / "reviews/review-receipts"
    for directory in (staged_root, bundle_root, catalog_root, review_root):
        directory.mkdir(parents=True, exist_ok=True)
    maintenance_policies = load_first_party_maintenance_policy(state)
    for app_id in APP_IDS:
        staged = staged_root / app_id
        write_text(
            staged / "cryptad-app.properties",
            "\n".join(
                [
                    f"app.id={app_id}",
                    f"app.name={app_id}",
                    "app.version=0.0.0-test",
                    "app.permissions=queue.read",
                    "app.ui.mode=static",
                    "app.ui.entry=static/index.html",
                    "signature.test-mode=true",
                    "",
                ]
            ),
        )
        write_text(staged / "static/index.html", "<!doctype html><title>fixture</title>\n")
        write_text(staged / "cryptad-app.digests", "digest.version=1\n")
        write_text(staged / "cryptad-app.signature", "signature.test-mode=true\n")
        zip_path = bundle_root / f"{app_id}-0.0.0-test.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(staged / "cryptad-app.properties", "cryptad-app.properties")
            archive.write(staged / "static/index.html", "static/index.html")
        write_text(
            review_root / f"{app_id}-review-receipt.properties",
            f"review.receipt.app.id={app_id}\nreview.receipt.status=reviewed\n",
        )
    catalog_lines = [
        "catalog.version=5",
        "catalog.id=crypta-first-party-production-beta",
        "catalog.entries=" + ",".join(APP_IDS),
    ]
    for app_id in APP_IDS:
        for key, value in maintenance_summary(maintenance_policies.get(app_id, {})).items():
            if isinstance(value, str) and value:
                catalog_lines.append(f"app.{app_id}.maintenance.{key}={value}")
    write_text(catalog_root / "first-party-catalog.properties", "\n".join(catalog_lines) + "\n")
    write_text(catalog_root / CANONICAL_CATALOG_SIGNATURE, "signature.test-mode=true\n")
    write_text(catalog_root / RELEASE_CATALOG_SIGNATURE_ALIAS, "signature.test-mode=true\n")
    write_json(
        catalog_root / "channel-metadata.json",
        {
            "schemaVersion": 1,
            "catalogId": "crypta-first-party-production-beta",
            "channel": state.settings.catalog_channel,
            "nonProduction": True,
            "signingProfile": "test-fixture",
            "firstPartyMaintenancePolicy": "inputs/first-party-app-maintenance-policy.json",
            "requiredMaintenanceApps": list(APP_IDS),
            "maintenancePolicyComplete": len(maintenance_policies) == len(APP_IDS),
            "apps": [
                {
                    "appId": app_id,
                    "supportStatus": policy_value(
                        maintenance_policies.get(app_id, {}), "supportStatus", "supported"
                    ),
                    "deprecationStatus": policy_value(
                        maintenance_policies.get(app_id, {}), "deprecationStatus", "none"
                    ),
                    "maintenance": maintenance_summary(maintenance_policies.get(app_id, {})),
                    "nonProduction": True,
                }
                for app_id in APP_IDS
            ],
        },
    )
    write_json(
        state.settings.out_dir / "reviews/review-transparency-log.json",
        {"schemaVersion": 1, "nonProduction": True, "receipts": len(APP_IDS)},
    )
    copy_launcher_distribution(state)


def release_config(state: PipelineState) -> dict[str, Any]:
    settings = state.settings
    profile = state.signing_profile
    return {
        "schemaVersion": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "generatedAt": utc_now(),
        "mode": settings.mode,
        "version": state.version,
        "catalogChannel": settings.catalog_channel,
        "artifactBaseUri": settings.artifact_base_uri,
        "requireLiveNetwork": settings.require_live_network,
        "requireSandboxProviderTests": settings.require_sandbox_provider_tests,
        "skipGradle": settings.skip_gradle,
        "skipFullBuild": settings.skip_full_build,
        "useFixtureEvidence": settings.use_fixture_evidence,
        "workspaceStatusKnown": state.workspace_status_known,
        "dirtyWorkspace": state.dirty_workspace,
        "nonRelease": release_config_non_release(settings, profile, state),
        "signingProfile": None
        if profile is None
        else {
            "kind": profile.kind,
            "generatedTestKeys": profile.generated_test_keys,
            "appKeyId": profile.app_key_id,
            "reviewerKeyId": profile.reviewer_key_id,
            "reviewPolicyId": profile.review_policy_id,
            "reviewPolicyVersion": profile.review_policy_version,
            "privateKeyMaterialIncluded": False,
        },
        "requiredEnvironment": [
            "CRYPTAD_APP_SIGNING_KEY_ID",
            "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE or CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64",
            "CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE or CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64",
            "CRYPTAD_APP_REVIEWER_KEY_ID",
            "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE or CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64",
            "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE or CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64",
            "CRYPTAD_CERT_FORM_PASSWORD and live-network fixture env when live network is required",
        ],
    }


def certification_mode(settings: Settings) -> str:
    return "pr" if settings.mode == "developer-dry-run" else "release-candidate"


def run_fixture_certification(state: PipelineState, cert_out: Path) -> None:
    fixtures = state.settings.workspace_root / "tools/release-certification/fixtures"
    cert_out.mkdir(parents=True, exist_ok=True)
    network_summary = cert_out / "network-scale-soak/summary.json"
    app_summary = cert_out / "app-platform-smoke/summary.json"
    network_summary.parent.mkdir(parents=True, exist_ok=True)
    app_summary.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(fixtures / "self-test-network-scale-soak.json", network_summary)
    shutil.copy2(fixtures / "self-test-app-platform-smoke.json", app_summary)
    args = [
        sys.executable,
        str(state.settings.workspace_root / "tools/release-certification/release_certification.py"),
        "--workspace-root",
        str(state.settings.workspace_root),
        "--out-dir",
        str(cert_out),
        "--mode",
        certification_mode(state.settings),
        "--interop-smoke-summary",
        str(fixtures / "self-test-interop-smoke.json"),
        "--perf-smoke-summary",
        str(fixtures / "self-test-perf-smoke.json"),
        "--app-platform-summary",
        str(app_summary),
        "--network-scale-soak-summary",
        str(network_summary),
        "--skip-git-metadata",
    ]
    result = run_command(state, "release-certification-fixture", args, timeout_seconds=300, allow_failure=True)
    record_certification_result(state, result)


def record_certification_result(state: PipelineState, result: CommandResult) -> None:
    state.certification_exit_code = result.exit_code
    if result.exit_code != 0:
        state.failures.append(f"{result.name} failed with exit code {result.exit_code}")


def run_release_certification(state: PipelineState, env: dict[str, str], cert_out: Path) -> None:
    if state.settings.use_fixture_evidence:
        run_fixture_certification(state, cert_out)
        return
    args = [
        str(state.settings.workspace_root / "tools/release-certification/run-release-certification.sh"),
        "--mode",
        certification_mode(state.settings),
        "--out-dir",
        str(cert_out),
    ]
    if state.settings.skip_gradle:
        args.append("--skip-gradle")
    if state.settings.require_live_network:
        args.append("--require-live-network-beta")
    if state.settings.mode != "developer-dry-run":
        args.append("--require-history")
    if state.settings.previous_summary:
        args.extend(["--previous-summary", str(state.settings.previous_summary)])
    if state.settings.waiver_file:
        args.extend(["--waiver-file", str(state.settings.waiver_file)])
    result = run_command(
        state,
        "release-certification",
        args,
        env=env,
        timeout_seconds=max(state.settings.timeout_seconds, 1800),
        allow_failure=True,
    )
    record_certification_result(state, result)


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def evidence_by_id(summary: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not summary:
        return {}
    evidence = summary.get("evidence", [])
    if not isinstance(evidence, list):
        return {}
    return {str(item.get("id")): item for item in evidence if isinstance(item, dict)}


def write_evidence_extracts(settings: Settings, cert_out: Path) -> dict[str, Any]:
    app_summary_path = cert_out / "app-platform-smoke/summary.json"
    live_summary_path = cert_out / "live-network-beta-smoke/summary.json"
    network_summary_path = cert_out / "network-scale-soak/summary.json"
    cert_summary_path = cert_out / release_certification.SUMMARY_FILE_NAME
    matrix_path = cert_out / release_certification.ECOSYSTEM_MATRIX_FILE_NAME
    app_summary = read_json(app_summary_path)
    live_summary = read_json(live_summary_path)
    network_summary = read_json(network_summary_path)
    cert_summary = read_json(cert_summary_path)
    matrix_summary = read_json(matrix_path)

    evidence_dir = settings.out_dir / "evidence"
    write_json(evidence_dir / "app-platform-smoke.json", app_summary or {"status": "missing"})
    write_json(evidence_dir / "live-network-beta-smoke.json", live_summary or {"status": "missing", "enabled": False})
    write_json(evidence_dir / "network-scale-soak.json", network_summary or {"status": "missing"})
    write_json(evidence_dir / "ecosystem-rc-certification.json", cert_summary or {"status": "missing"})
    write_json(evidence_dir / "ecosystem-certification-matrix.json", matrix_summary or {"status": "missing"})

    app_evidence = evidence_by_id(app_summary)
    write_json(evidence_dir / "api-compatibility.json", app_evidence.get("platform-api.contract", {"status": "missing"}))
    write_json(evidence_dir / "app-ui-lint.json", app_evidence.get("app-ui.lint", {"status": "missing"}))
    write_json(evidence_dir / "sandbox-provider-tests.json", app_evidence.get("apphost.sandbox-provider", {"status": "missing"}))
    return {
        "appPlatform": app_summary,
        "liveNetwork": live_summary,
        "networkScale": network_summary,
        "certification": cert_summary,
        "matrix": matrix_summary,
    }


def status_ok(status: str) -> bool:
    return status == "pass"


def evidence_details(item: dict[str, Any]) -> dict[str, Any]:
    details = item.get("details")
    return details if isinstance(details, dict) else {}


def evidence_has_unwaivable_redaction_findings(item: dict[str, Any]) -> bool:
    redaction_findings = evidence_details(item).get("redactionFindings")
    return isinstance(redaction_findings, list) and bool(redaction_findings)


def evidence_status_ok(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    status = str(item.get("status", ""))
    if evidence_has_unwaivable_redaction_findings(item):
        return False
    if status_ok(status):
        return True
    return status == "warn" and evidence_details(item).get("waived") is True


def evaluate_promotion(state: PipelineState, summaries: dict[str, Any]) -> dict[str, Any]:
    settings = state.settings
    cert_summary = summaries.get("certification") if isinstance(summaries.get("certification"), dict) else None
    app_summary = summaries.get("appPlatform") if isinstance(summaries.get("appPlatform"), dict) else None
    live_summary = summaries.get("liveNetwork") if isinstance(summaries.get("liveNetwork"), dict) else None
    matrix_summary = summaries.get("matrix") if isinstance(summaries.get("matrix"), dict) else None
    app_evidence = evidence_by_id(app_summary)
    cert_evidence = evidence_by_id(cert_summary)
    all_evidence = {**app_evidence, **cert_evidence}
    gates: list[dict[str, Any]] = []

    def add_gate(gate_id: str, ok: bool, summary: str, source: str = "pipeline") -> None:
        gates.append({"id": gate_id, "status": "pass" if ok else "fail", "summary": summary, "source": source})

    add_gate(
        "artifact.signed-first-party-bundles",
        all((settings.out_dir / "build/staged-apps" / app_id / "cryptad-app.signature").is_file() for app_id in APP_IDS),
        "Signed sidecars are present for every first-party staged app.",
    )
    add_gate(
        "artifact.signed-first-party-catalog",
        (settings.out_dir / "catalog/first-party-catalog.properties").is_file()
        and (settings.out_dir / "catalog" / CANONICAL_CATALOG_SIGNATURE).is_file(),
        "Signed first-party catalog sidecars are present.",
    )
    receipt_count = len(list((settings.out_dir / "reviews/review-receipts").glob("*-review-receipt.properties")))
    add_gate(
        "artifact.first-party-review-receipts",
        receipt_count >= len(APP_IDS),
        f"Review receipts present: {receipt_count}/{len(APP_IDS)}.",
    )
    if settings.use_fixture_evidence and settings.mode != "developer-dry-run":
        add_gate(
            "fixture-evidence.strict-mode",
            False,
            "Fixture evidence cannot certify release-candidate or production-beta runs.",
        )

    for evidence_id in CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS:
        item = all_evidence.get(evidence_id)
        ok = evidence_status_ok(item)
        add_gate(
            f"evidence.{evidence_id}",
            ok,
            str(item.get("summary", "Required evidence is missing.")) if isinstance(item, dict) else "Required evidence is missing.",
            "release-certification",
        )

    if settings.require_sandbox_provider_tests:
        item = all_evidence.get("apphost.sandbox-provider")
        add_gate(
            "evidence.required-sandbox-provider-tests",
            evidence_status_ok(item),
            str(item.get("summary", "Sandbox provider evidence is required for this run."))
            if isinstance(item, dict)
            else "Sandbox provider evidence is required for this run.",
            "release-certification",
        )

    if settings.require_live_network:
        live_evidence = evidence_by_id(live_summary)
        for evidence_id in LIVE_NETWORK_REQUIRED_IDS:
            item = live_evidence.get(evidence_id)
            add_gate(
                f"live.{evidence_id}",
                isinstance(item, dict) and item.get("status") == "pass",
                str(item.get("summary", "Required live-network beta evidence is missing."))
                if isinstance(item, dict)
                else "Required live-network beta evidence is missing.",
                "live-network-beta-smoke",
            )
    elif settings.mode == "production-beta":
        add_gate(
            "live.production-beta-skip",
            False,
            "Live-network beta evidence was skipped for a production-beta run; the candidate is not promotion-ready.",
        )

    cert_ok = isinstance(cert_summary, dict) and cert_summary.get("releaseCandidatePassed") is True
    add_gate("ecosystem.release-candidate-passed", cert_ok, "Ecosystem RC certification passed.", "release-certification")
    matrix_ok = (
        isinstance(matrix_summary, dict)
        and matrix_summary.get("status") in {"pass", "warn"}
        and int(matrix_summary.get("releaseBlockerCount", 0)) == 0
    )
    add_gate(
        "ecosystem.certification-matrix",
        matrix_ok,
        "Ecosystem certification matrix is present and has no release blockers.",
        "release-certification",
    )
    profile = state.signing_profile
    production_signing = bool(profile and profile.kind == "production" and not profile.generated_test_keys)
    if settings.mode == "production-beta":
        add_gate(
            "build.production-beta-complete",
            not production_build_skipped(settings),
            "Production beta promotion requires the Gradle build and first-party app staging/signing stages to run in this pipeline execution.",
        )
        add_gate(
            "workspace.clean-production-beta",
            state.workspace_status_known and not state.dirty_workspace,
            "Production beta promotion requires a clean git workspace.",
        )
        add_gate(
            "signing.production-keys",
            production_signing or settings.allow_test_signing_in_production,
            "Production beta uses configured production signing inputs or the explicit test-signing escape hatch.",
        )
    else:
        add_gate(
            "signing.non-production-labelled",
            bool(profile and profile.kind != "production"),
            "Dry-run or release-candidate artifacts are labelled non-production when test keys are used.",
        )

    failed = [gate for gate in gates if gate["status"] != "pass"]
    non_release = (
        settings.mode == "developer-dry-run"
        or settings.allow_test_signing_in_production
        or production_build_skipped(settings)
        or state.dirty_workspace
        or not state.workspace_status_known
        or bool(profile and profile.kind != "production")
    )
    promotion_ready = not failed and settings.mode == "production-beta" and not non_release
    return {
        "status": "pass" if not failed else "fail",
        "promotionReady": promotion_ready,
        "nonRelease": non_release,
        "failedGateCount": len(failed),
        "gates": gates,
        "knownLimitations": [
            "Legacy admin Wave 5 readiness is intentionally not implemented in PR-259 and remains a later release gate."
        ],
    }


def bad_artifact_name(rel_path: str) -> str | None:
    parts = re.split(r"[\\/]+", rel_path)
    for part in parts:
        if part.startswith("._"):
            return "AppleDouble file is not allowed"
        if part in BAD_ARTIFACT_NAMES:
            return f"{part} is not allowed"
        if part in BAD_ARTIFACT_DIRS:
            return f"{part} directory is not allowed"
        secret_reason = secret_artifact_name_reason(part)
        if secret_reason:
            return secret_reason
    return None


def secret_artifact_name_reason(name: str) -> str | None:
    leaf = name.strip()
    if not leaf:
        return None
    lower = leaf.lower()
    suffix = Path(lower).suffix
    collapsed = re.sub(r"[^a-z0-9]", "", lower)
    if suffix in FORBIDDEN_SECRET_ARTIFACT_SUFFIXES:
        return f"{suffix} key-store artifact is not allowed"
    if suffix not in CODE_LIKE_ARTIFACT_SUFFIXES and (
        SECRET_ARTIFACT_NAME_RE.search(lower) or collapsed in SECRET_ARTIFACT_COLLAPSED_NAMES
    ):
        return "secret-bearing artifact filename is not allowed"
    if suffix in SECRET_ARTIFACT_BINARY_SUFFIXES and any(
        marker in collapsed for marker in SECRET_ARTIFACT_BINARY_MARKERS
    ):
        return "binary secret/key artifact filename is not allowed"
    return None


def is_redacted_or_code_value(raw_value: str, allow_code_like: bool = True) -> bool:
    value = raw_value.strip().strip("'\"").rstrip(",;")
    if not value:
        return True
    normalized = value.lower()
    if normalized in {"==", "===", "!=", "!==", "&&", "||"}:
        return True
    if normalized in {"<redacted>", "redacted", "<masked>", "masked", "***", "null", "undefined"}:
        return True
    if (value.startswith("<") and value.endswith(">")) or normalized.startswith("<redacted") or normalized.startswith("${{"):
        return True
    if not allow_code_like:
        return False
    if "(" in value or ")" in value:
        return True
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", value) and not (
        len(value) >= 16 and any(character.isdigit() for character in value)
    ):
        return True
    if value.startswith("source.") or value.startswith("options.") or value.startswith("request."):
        return True
    return False


def is_unquoted_code_expression(match: re.Match[str]) -> bool:
    value = match.group(1).strip().rstrip(",;")
    if not value:
        return False
    value_start = match.start(1)
    if value_start > 0 and match.string[value_start - 1] in {"'", '"'}:
        return False
    return bool(re.fullmatch(r"(?:[A-Za-z_$][A-Za-z0-9_$]*\.)*[A-Za-z_$][A-Za-z0-9_$]*\([^;{}\"']*\)", value))


def add_value_findings(
    findings: list[dict[str, str]],
    text: str,
    rel_path: str,
    kind: str,
    regex: re.Pattern[str],
    allow_code_like: bool = True,
    allow_unquoted_code_expression: bool = False,
) -> None:
    for match in regex.finditer(text):
        if allow_unquoted_code_expression and is_unquoted_code_expression(match):
            continue
        value = match.group(1)
        if not is_redacted_or_code_value(value, allow_code_like=allow_code_like):
            findings.append({"path": rel_path, "kind": kind})
            return


def normalized_secret_env_value(name: str, raw_value: str) -> str | None:
    value = raw_value.strip()
    minimum_length = 1 if name == "CRYPTAD_CERT_FORM_PASSWORD" else MIN_SECRET_ENV_VALUE_LENGTH
    if len(value) < minimum_length:
        return None
    normalized = value.lower().strip("'\"")
    if normalized in {"<redacted>", "redacted", "<masked>", "masked", "***", "null", "undefined", "true", "false", "none", "unset"}:
        return None
    if (value.startswith("<") and value.endswith(">")) or normalized.startswith("<redacted") or normalized.startswith("${{"):
        return None
    return value


def protected_secret_environment_values(
    env: dict[str, str] | None = None, workspace_root: Path | None = None
) -> list[tuple[str, str]]:
    source = os.environ if env is None else env
    values: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(name: str, raw_value: str) -> None:
        value = normalized_secret_env_value(name, raw_value)
        if value is None or value in seen:
            return
        seen.add(value)
        values.append((name, value))

    def add_file_contents(name: str, raw_path: str) -> None:
        path = resolve_workspace_input_path(raw_path, workspace_root)
        if path is None:
            return
        try:
            content_bytes = path.read_bytes()
        except OSError:
            return
        if not content_bytes:
            return
        add(name, base64.b64encode(content_bytes).decode("ascii"))
        content = content_bytes.decode("utf-8", errors="ignore")
        add(name, content)
        for line in content.splitlines():
            add(name, line)

    for name, raw_value in source.items():
        if name in SECRET_ENV_INDIRECTION_NAMES:
            target_name = raw_value.strip()
            if target_name:
                add(target_name, source.get(target_name, ""))
            continue
        if name in SECRET_ENV_FILE_INDIRECTION_NAMES:
            add_file_contents(name, raw_value)
            continue
        if name.endswith(SECRET_ENV_VALUE_SKIP_SUFFIXES):
            continue
        if SECRET_ENV_VALUE_NAME_RE.search(name):
            add(name, raw_value)
    return values


def protected_secret_environment_byte_values(
    env: dict[str, str] | None = None, workspace_root: Path | None = None
) -> list[tuple[str, bytes]]:
    source = os.environ if env is None else env
    values: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()

    for name, raw_value in source.items():
        if name not in SECRET_ENV_FILE_INDIRECTION_NAMES:
            continue
        path = resolve_workspace_input_path(raw_value, workspace_root)
        if path is None:
            continue
        try:
            value = path.read_bytes()
        except OSError:
            continue
        if len(value) < MIN_SECRET_ENV_VALUE_LENGTH or value in seen:
            continue
        seen.add(value)
        values.append((name, value))
    return values


def add_protected_secret_value_findings(
    findings: list[dict[str, str]], text: str, rel_path: str, workspace_root: Path | None
) -> None:
    for name, value in protected_secret_environment_values(workspace_root=workspace_root):
        if value in text:
            findings.append(
                {
                    "path": rel_path,
                    "kind": "protected-secret-value",
                    "detail": f"{name} value appeared unredacted.",
                }
            )
            return


def add_protected_secret_byte_findings(
    findings: list[dict[str, str]],
    window: bytes,
    rel_path: str,
    protected_values: list[tuple[str, bytes]],
) -> None:
    for name, value in protected_values:
        if value in window:
            findings.append(
                {
                    "path": rel_path,
                    "kind": "protected-secret-value",
                    "detail": f"{name} value appeared unredacted.",
                }
            )
            return


def contains_path_prefix(text: str, path_text: str) -> bool:
    normalized = path_text.rstrip("/\\")
    if not normalized or normalized in {"/", "\\"}:
        return False
    pattern = re.compile(rf"(?<![A-Za-z0-9_:/.\->]){re.escape(normalized)}(?=$|[/\\])")
    return bool(pattern.search(text))


def scan_text_for_findings(text: str, rel_path: str, settings: Settings) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    checks = (
        ("private-insert-uri", PRIVATE_INSERT_URI_RE),
        ("private-key", PRIVATE_KEY_RE),
        ("private-key-header", PRIVATE_KEY_HEADER_RE),
        ("bearer-token", BEARER_RE),
        ("url-userinfo", URL_USERINFO_RE),
        ("file-uri-local-path", FILE_URI_RE),
        ("windows-local-path", WINDOWS_PATH_RE),
        ("host-local-path", HOST_PATH_RE),
    )
    workspace_text = str(settings.workspace_root.resolve())
    home_text = str(Path.home().resolve())
    temp_text = tempfile.gettempdir()
    for kind, regex in checks:
        if regex.search(text):
            findings.append({"path": rel_path, "kind": kind})
    add_value_findings(findings, text, rel_path, "authorization-header", AUTH_HEADER_RE, allow_code_like=False)
    add_value_findings(
        findings,
        text,
        rel_path,
        "app-token",
        APP_TOKEN_VALUE_RE,
        allow_code_like=False,
        allow_unquoted_code_expression=True,
    )
    add_value_findings(findings, text, rel_path, "form-password", FORM_PASSWORD_VALUE_RE, allow_code_like=False)
    add_value_findings(findings, text, rel_path, "raw-content-or-app-data", RAW_BODY_VALUE_RE, allow_code_like=False)
    add_value_findings(findings, text, rel_path, "ci-secret-value", CI_SECRET_VALUE_RE, allow_code_like=False)
    add_protected_secret_value_findings(findings, text, rel_path, settings.workspace_root)
    for kind, value in (("workspace-path", workspace_text), ("home-path", home_text), ("temp-path", temp_text)):
        if contains_path_prefix(text, value):
            findings.append({"path": rel_path, "kind": kind})
    return findings


def deduplicate_findings(findings: list[dict[str, str]]) -> list[dict[str, str]]:
    deduplicated: list[dict[str, str]] = []
    seen: set[tuple[tuple[str, str], ...]] = set()
    for finding in findings:
        key = tuple(sorted((str(name), str(value)) for name, value in finding.items()))
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(finding)
    return deduplicated


def iter_file_chunks(path: Path) -> Iterator[bytes]:
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(TEXT_SCAN_CHUNK_BYTES)
            if not chunk:
                break
            yield chunk


def iter_handle_chunks(handle: BinaryIO) -> Iterator[bytes]:
    while True:
        chunk = handle.read(TEXT_SCAN_CHUNK_BYTES)
        if not chunk:
            break
        yield chunk


def iter_prefixed_chunks(prefix: bytes, chunks: Iterable[bytes]) -> Iterator[bytes]:
    if prefix:
        yield prefix
    yield from chunks


def scan_decoded_byte_window(window: bytes, rel_path: str, settings: Settings) -> list[dict[str, str]]:
    findings = scan_text_for_findings(window.decode("utf-8", errors="ignore"), rel_path, settings)
    if b"\x00" in window:
        nul_stripped_text = window.replace(b"\x00", b"").decode("utf-8", errors="ignore")
        findings.extend(scan_text_for_findings(nul_stripped_text, rel_path, settings))
    return findings


def scan_byte_chunks(chunks: Iterable[bytes], rel_path: str, settings: Settings) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    protected_byte_values = protected_secret_environment_byte_values(workspace_root=settings.workspace_root)
    tail = b""
    for chunk in chunks:
        window = tail + chunk
        add_protected_secret_byte_findings(findings, window, rel_path, protected_byte_values)
        findings.extend(scan_decoded_byte_window(window, rel_path, settings))
        tail = window[-TEXT_SCAN_OVERLAP_BYTES:]
    return deduplicate_findings(findings)


def scan_regular_file(path: Path, rel_path: str, settings: Settings) -> list[dict[str, str]]:
    try:
        return scan_byte_chunks(iter_file_chunks(path), rel_path, settings)
    except OSError:
        return [{"path": rel_path, "kind": "unreadable"}]


def archive_kind_for_name_or_prefix(name: str, prefix: bytes = b"") -> str | None:
    lower_name = name.lower()
    if Path(lower_name).suffix in ZIP_ARCHIVE_SUFFIXES or prefix.startswith(b"PK\x03\x04"):
        return "zip"
    if lower_name.endswith(TAR_GZ_ARCHIVE_SUFFIXES):
        return "tar-gz"
    return None


def is_compiled_archive_member(name: str) -> bool:
    suffixes = Path(name.lower()).suffixes
    return any(suffix in COMPILED_ARCHIVE_MEMBER_SUFFIXES for suffix in suffixes)


def scan_embedded_archive_bytes(data: bytes, rel_path: str, settings: Settings, depth: int) -> list[dict[str, str]]:
    if depth > MAX_NESTED_ARCHIVE_DEPTH:
        return [
            {
                "path": rel_path,
                "kind": "archive-nesting-too-deep",
                "detail": "Nested archive depth exceeds the production beta redaction scanner limit.",
            }
        ]
    kind = archive_kind_for_name_or_prefix(rel_path, data[:4])
    if kind == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                return scan_zip_members(archive, rel_path, settings, depth)
        except (EOFError, OSError, RuntimeError, zipfile.BadZipFile):
            return [{"path": rel_path, "kind": "invalid-zip"}]
    if kind == "tar-gz":
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                return scan_tar_members(archive, rel_path, settings, depth)
        except (EOFError, OSError, tarfile.TarError):
            return [{"path": rel_path, "kind": "invalid-tar"}]
    return scan_byte_chunks([data], rel_path, settings)


def scan_zip_members(zip_archive: zipfile.ZipFile, rel_path: str, settings: Settings, depth: int) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for info in zip_archive.infolist():
        member_rel = f"{rel_path}!/{info.filename}"
        reason = bad_artifact_name(info.filename)
        if reason:
            findings.append({"path": member_rel, "kind": "forbidden-zip-entry", "detail": reason})
        if info.is_dir():
            continue
        try:
            with zip_archive.open(info) as member:
                prefix = member.read(4)
                archive_kind = archive_kind_for_name_or_prefix(info.filename, prefix)
                if archive_kind:
                    findings.extend(
                        scan_embedded_archive_bytes(prefix + member.read(), member_rel, settings, depth + 1)
                    )
                elif is_compiled_archive_member(info.filename):
                    continue
                else:
                    findings.extend(
                        scan_byte_chunks(iter_prefixed_chunks(prefix, iter_handle_chunks(member)), member_rel, settings)
                    )
        except (EOFError, NotImplementedError, OSError, RuntimeError, zipfile.BadZipFile):
            findings.append({"path": member_rel, "kind": "unreadable-zip-entry"})
    return findings


def scan_zip_file(path: Path, rel_path: str, settings: Settings) -> list[dict[str, str]]:
    try:
        with zipfile.ZipFile(path) as archive:
            return scan_zip_members(archive, rel_path, settings, 0)
    except (EOFError, OSError, zipfile.BadZipFile):
        return [{"path": rel_path, "kind": "invalid-zip"}]


def scan_tar_members(tar_archive: tarfile.TarFile, rel_path: str, settings: Settings, depth: int) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for member in tar_archive.getmembers():
        member_rel = member.name if not rel_path else f"{rel_path}!/{member.name}"
        reason = bad_artifact_name(member.name)
        if reason:
            findings.append({"path": member_rel, "kind": "forbidden-tar-entry", "detail": reason})
        if member.isdir():
            continue
        if not member.isfile():
            findings.append(
                {
                    "path": member_rel,
                    "kind": "forbidden-tar-entry",
                    "detail": "Only regular files and directories are allowed in production beta archives.",
                }
            )
            continue
        extracted = tar_archive.extractfile(member)
        if extracted is None:
            continue
        try:
            prefix = extracted.read(4)
            archive_kind = archive_kind_for_name_or_prefix(member.name, prefix)
            if archive_kind:
                findings.extend(scan_embedded_archive_bytes(prefix + extracted.read(), member_rel, settings, depth + 1))
            elif is_compiled_archive_member(member.name):
                continue
            else:
                findings.extend(
                    scan_byte_chunks(iter_prefixed_chunks(prefix, iter_handle_chunks(extracted)), member_rel, settings)
                )
        except (EOFError, NotImplementedError, OSError, RuntimeError, tarfile.TarError):
            findings.append({"path": member_rel, "kind": "unreadable-tar-entry"})
    return findings


def scan_tar_gz_file(path: Path, rel_path: str, settings: Settings) -> list[dict[str, str]]:
    try:
        with tarfile.open(path, "r:gz") as archive:
            return scan_tar_members(archive, rel_path, settings, 0)
    except (EOFError, OSError, tarfile.TarError):
        return [{"path": rel_path, "kind": "invalid-tar"}]


def scan_tree(root: Path, settings: Settings, include_dist: bool = False) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for path in sorted(root.rglob("*")):
        rel_path = path.relative_to(root).as_posix()
        reason = bad_artifact_name(rel_path)
        if reason:
            findings.append({"path": rel_path, "kind": "forbidden-path", "detail": reason})
        if path.is_symlink():
            findings.append(
                {
                    "path": rel_path,
                    "kind": "forbidden-symlink",
                    "detail": "Symlinks are not allowed in production beta artifacts.",
                }
            )
            continue
        if path.is_dir():
            continue
        if not include_dist and rel_path.startswith("dist/"):
            continue
        if not path.is_file():
            findings.append(
                {
                    "path": rel_path,
                    "kind": "forbidden-special-file",
                    "detail": "Only regular files and directories are allowed in production beta artifacts.",
                }
            )
            continue
        if path.suffix.lower() in ZIP_ARCHIVE_SUFFIXES:
            findings.extend(scan_zip_file(path, rel_path, settings))
        elif rel_path.lower().endswith(TAR_GZ_ARCHIVE_SUFFIXES):
            findings.extend(scan_tar_gz_file(path, rel_path, settings))
        else:
            findings.extend(scan_regular_file(path, rel_path, settings))
    return findings


def scan_tarball(path: Path, settings: Settings) -> list[dict[str, str]]:
    try:
        with tarfile.open(path, "r:gz") as archive:
            return scan_tar_members(archive, "", settings, 0)
    except (OSError, tarfile.TarError):
        return [{"path": path.name, "kind": "invalid-tar"}]


def render_markdown_summary(summary: dict[str, Any]) -> str:
    lines = [
        "# Production Beta Release Summary",
        "",
        f"- Mode: `{summary['mode']}`",
        f"- Version: `{summary['version']}`",
        f"- Status: `{summary['status']}`",
        f"- Promotion ready: `{str(summary['promotionReady']).lower()}`",
        f"- Non-release: `{str(summary['nonRelease']).lower()}`",
        f"- Dirty workspace: `{str(summary.get('dirtyWorkspace', False)).lower()}`",
        f"- Catalog channel: `{summary['catalogChannel']}`",
        f"- Signing profile: `{summary['signingProfile']['kind'] if summary.get('signingProfile') else 'missing'}`",
        f"- Redaction: `{summary['redaction']['status']}`",
        "",
        "## Artifacts",
        "",
    ]
    for name, path in summary.get("artifacts", {}).items():
        lines.append(f"- `{name}`: `{path}`")
    lines.extend(["", "## Failed Gates", ""])
    failed = [gate for gate in summary["promotion"]["gates"] if gate["status"] != "pass"]
    if not failed:
        lines.append("No failed gates.")
    else:
        for gate in failed:
            lines.append(f"- `{gate['id']}`: {gate['summary']}")
    lines.extend(["", "## Known Limitations", ""])
    for limitation in summary["promotion"].get("knownLimitations", []):
        lines.append(f"- {limitation}")
    lines.append("")
    return "\n".join(lines)


def dist_bundle_path(settings: Settings, version: str) -> Path:
    return settings.out_dir / "dist" / f"crypta-production-beta-{version}.tar.gz"


def dist_checksums_path(settings: Settings) -> Path:
    return settings.out_dir / "dist" / "checksums.txt"


def reset_output_subtree(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    path.mkdir(parents=True, exist_ok=True)


def reset_dist_dir(settings: Settings) -> None:
    reset_output_subtree(settings.out_dir / "dist")


def reset_release_output_roots(settings: Settings) -> None:
    for root_name in RELEASE_OUTPUT_ROOTS:
        reset_output_subtree(settings.out_dir / root_name)


def remove_dist_bundle(settings: Settings, archive: Path) -> None:
    for path in (archive, dist_checksums_path(settings)):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def create_dist_bundle(settings: Settings, version: str) -> Path:
    dist_dir = settings.out_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    tar_path = dist_bundle_path(settings, version)
    with tarfile.open(tar_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for root_name in RELEASE_OUTPUT_ROOTS:
            root_path = settings.out_dir / root_name
            if root_path.exists():
                archive.add(root_path, arcname=root_name, recursive=True)
    checksums = dist_checksums_path(settings)
    checksum_lines = [f"{sha256_file(tar_path)}  {tar_path.name}"]
    write_text(checksums, "\n".join(checksum_lines) + "\n")
    return tar_path


def build_final_summary(
    state: PipelineState,
    promotion: dict[str, Any],
    redaction_report: dict[str, Any],
    archive: Path | None,
) -> dict[str, Any]:
    settings = state.settings
    profile = state.signing_profile
    artifacts = {
        "releaseConfig": "inputs/release-config.json",
        "firstPartyMaintenancePolicy": "inputs/first-party-app-maintenance-policy.json",
        "catalog": "catalog/first-party-catalog.properties",
        "catalogSignature": f"catalog/{CANONICAL_CATALOG_SIGNATURE}",
        "catalogSignatureAlias": f"catalog/{RELEASE_CATALOG_SIGNATURE_ALIAS}",
        "channelMetadata": "catalog/channel-metadata.json",
        "reviewReceipts": "reviews/review-receipts/",
        "appPlatformSmoke": "evidence/app-platform-smoke.json",
        "ecosystemCertification": "evidence/ecosystem-rc-certification.json",
        "redactionReport": "reports/redaction-report.json",
    }
    if archive is not None:
        artifacts["distArchive"] = f"dist/{archive.name}"
        artifacts["checksums"] = "dist/checksums.txt"
    command_and_redaction_ok = not state.failures and redaction_report["status"] == "pass"
    if settings.mode == "developer-dry-run":
        status = "pass" if command_and_redaction_ok else "fail"
    else:
        status = "pass" if command_and_redaction_ok and promotion["status"] == "pass" else "fail"
    summary_promotion_ready = bool(command_and_redaction_ok and status == "pass" and promotion["promotionReady"])
    final_promotion = dict(promotion)
    final_promotion["promotionReady"] = summary_promotion_ready
    return {
        "schemaVersion": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "generatedAt": utc_now(),
        "startedAt": state.started_at,
        "mode": settings.mode,
        "version": state.version,
        "status": status,
        "promotionReady": summary_promotion_ready,
        "nonRelease": promotion["nonRelease"],
        "workspaceStatusKnown": state.workspace_status_known,
        "dirtyWorkspace": state.dirty_workspace,
        "catalogChannel": settings.catalog_channel,
        "signingProfile": None
        if profile is None
        else {
            "kind": profile.kind,
            "generatedTestKeys": profile.generated_test_keys,
            "appKeyId": profile.app_key_id,
            "reviewerKeyId": profile.reviewer_key_id,
            "privateKeyMaterialIncluded": False,
        },
        "certificationExitCode": state.certification_exit_code,
        "warnings": state.warnings,
        "failures": state.failures,
        "promotion": final_promotion,
        "redaction": redaction_report,
        "commands": [dataclasses.asdict(command) for command in state.commands],
        "artifacts": artifacts,
    }


def release_exit_code(settings: Settings, summary: dict[str, Any]) -> int:
    if settings.mode == "developer-dry-run":
        return 0 if summary.get("status") == "pass" else 1
    return 0 if summary.get("status") == "pass" and (settings.mode != "production-beta" or summary.get("promotionReady") is True) else 1


def run_pipeline(settings: Settings) -> tuple[dict[str, Any], int]:
    version = read_project_version(settings.workspace_root)
    state = PipelineState(settings, version, utc_now(), [], [], [])
    check_workspace_clean(state)
    ensure_safe_out_dir(settings)
    reset_release_output_roots(settings)
    reset_dist_dir(settings)
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-") as temp_name:
        temp_dir = Path(temp_name)
        key_dir = temp_dir / "keys"
        work_dir = temp_dir / "work"
        cert_out = temp_dir / "release-certification"
        validate_toolchain(state)
        if settings.use_fixture_evidence and settings.mode != "developer-dry-run":
            state.failures.append("fixture evidence is only allowed for developer-dry-run/self-test and cannot certify strict release modes.")

        if settings.use_fixture_evidence:
            state.signing_profile = prepare_signing_profile(state, key_dir)
            copy_first_party_maintenance_policy_input(state)
            create_fixture_artifacts(state)
        else:
            run_gradle(state, "gradle-install-crypta-app", [":platform-devtools:installDist"])
            state.signing_profile = prepare_signing_profile(state, key_dir)
            copy_first_party_maintenance_policy_input(state)
            write_json(settings.out_dir / "inputs/release-config.json", release_config(state))
            if not settings.skip_full_build:
                run_gradle(
                    state,
                    "gradle-release-build",
                    ["buildJar", "assembleCryptadDist"],
                    env=state.signing_profile.env if state.signing_profile else None,
                )
            elif settings.mode in {"release-candidate", "production-beta"} and not settings.emergency_skip_build:
                state.failures.append("release-candidate and production-beta modes require the build stage unless --emergency-skip-build is used.")
            run_gradle(
                state,
                "gradle-stage-sign-verify-first-party-apps",
                ["stageFirstPartyApps", "signFirstPartyApps", "verifyFirstPartyApps"],
                env=state.signing_profile.env if state.signing_profile else None,
            )
            copy_launcher_distribution(state)
            copied_apps = copy_staged_apps(state)
            package_catalog_and_reviews(state, state.signing_profile, copied_apps, work_dir)

        check_workspace_clean(state, "post-artifact-build")
        write_json(settings.out_dir / "inputs/release-config.json", release_config(state))
        profile_env = state.signing_profile.env if state.signing_profile else os.environ.copy()
        run_release_certification(state, profile_env, cert_out)
        check_workspace_clean(state, "post-certification")
        summaries = write_evidence_extracts(settings, cert_out)
        promotion = evaluate_promotion(state, summaries)
        pre_dist_findings = scan_tree(settings.out_dir, settings, include_dist=True)
        redaction_report = {
            "schemaVersion": 1,
            "status": "pass" if not pre_dist_findings else "fail",
            "scannedRoot": "<release-out>",
            "findingCount": len(pre_dist_findings),
            "findings": pre_dist_findings,
        }
        write_json(settings.out_dir / "reports/redaction-report.json", redaction_report)
        archive: Path | None = None
        summary: dict[str, Any] | None = None
        if redaction_report["status"] == "pass":
            archive = dist_bundle_path(settings, version)
            summary = build_final_summary(state, promotion, redaction_report, archive)
            write_json(settings.out_dir / "reports/production-beta-summary.json", summary)
            write_text(settings.out_dir / "reports/production-beta-summary.md", render_markdown_summary(summary))
            archive = create_dist_bundle(settings, version)
            tar_findings = scan_tarball(archive, settings)
            if tar_findings:
                redaction_report = {
                    "schemaVersion": 1,
                    "status": "fail",
                    "scannedRoot": "<release-out>",
                    "findingCount": len(tar_findings),
                    "findings": tar_findings,
                }
                write_json(settings.out_dir / "reports/redaction-report.json", redaction_report)
                remove_dist_bundle(settings, archive)
                archive = None
                summary = None
        if redaction_report["status"] != "pass":
            state.failures.append("artifact redaction scan failed")
        if summary is None:
            summary = build_final_summary(state, promotion, redaction_report, archive)
            write_json(settings.out_dir / "reports/production-beta-summary.json", summary)
            write_text(settings.out_dir / "reports/production-beta-summary.md", render_markdown_summary(summary))
        return summary, release_exit_code(settings, summary)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run Python-only production beta pipeline tests.")
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    parser.add_argument("--out-dir", type=Path, default=Path("build/production-beta-release"))
    parser.add_argument("--mode", choices=MODES, default="developer-dry-run")
    parser.add_argument("--catalog-channel", choices=CATALOG_CHANNELS, default="stable")
    parser.add_argument(
        "--artifact-base-uri",
        default="",
        help=(
            "Public base URI for app bundle artifacts. Required for release-candidate and "
            "production-beta unless CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI is set."
        ),
    )
    parser.add_argument("--require-live-network", action="store_true", help="Require live-network beta evidence.")
    parser.add_argument("--require-sandbox-provider-tests", action="store_true", help="Require sandbox evidence.")
    parser.add_argument("--skip-gradle", action="store_true", help="Skip Gradle stages. Use only for fixture/self-test dry-runs.")
    parser.add_argument("--skip-full-build", action="store_true", help="Skip buildJar and assembleCryptadDist.")
    parser.add_argument(
        "--use-fixture-evidence",
        action="store_true",
        help="Use deterministic checked-in evidence fixtures. Allowed only for developer-dry-run and internal self-tests.",
    )
    parser.add_argument("--allow-dirty-workspace", action="store_true", help="Allow dirty workspace in strict modes.")
    parser.add_argument("--emergency-skip-live-network", action="store_true", help="Production-beta emergency/test escape hatch for live evidence.")
    parser.add_argument("--emergency-skip-build", action="store_true", help="Production-beta emergency/test escape hatch for skipped Gradle stages.")
    parser.add_argument("--allow-test-signing-in-production", action="store_true", help="Explicit test escape hatch; artifacts remain non-release.")
    parser.add_argument("--previous-summary", type=Path, help="Previous release-certification summary for history comparison.")
    parser.add_argument("--waiver-file", type=Path, help="Structured release waiver JSON file.")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--no-clean-out-dir", action="store_true", help="Do not remove an existing output directory before running.")
    return parser


def settings_from_args(args: argparse.Namespace) -> Settings:
    workspace = args.workspace_root.resolve()
    out_dir = (workspace / args.out_dir).resolve() if not args.out_dir.is_absolute() else args.out_dir.resolve()
    artifact_base_uri = args.artifact_base_uri.strip() or os.environ.get(
        "CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI", ""
    ).strip()
    if not artifact_base_uri:
        if args.mode != "developer-dry-run":
            raise SystemExit(
                "--artifact-base-uri or CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI is required for "
                f"{args.mode} mode."
            )
        artifact_base_uri = f"https://downloads.crypta.invalid/production-beta/{read_project_version(workspace)}"
    validate_artifact_base_uri(args.mode, artifact_base_uri)
    if args.use_fixture_evidence and args.mode != "developer-dry-run":
        raise SystemExit("--use-fixture-evidence is only allowed with --mode developer-dry-run or internal self-tests.")
    require_live = args.require_live_network or (
        args.mode == "production-beta" and not args.emergency_skip_live_network
    )
    require_sandbox = args.require_sandbox_provider_tests or args.mode == "production-beta"
    return Settings(
        workspace_root=workspace,
        out_dir=out_dir,
        mode=args.mode,
        catalog_channel=args.catalog_channel,
        artifact_base_uri=artifact_base_uri,
        require_live_network=require_live,
        require_sandbox_provider_tests=require_sandbox,
        skip_gradle=args.skip_gradle,
        skip_full_build=args.skip_full_build,
        use_fixture_evidence=args.use_fixture_evidence,
        allow_dirty_workspace=args.allow_dirty_workspace,
        emergency_skip_live_network=args.emergency_skip_live_network,
        emergency_skip_build=args.emergency_skip_build,
        allow_test_signing_in_production=args.allow_test_signing_in_production,
        previous_summary=args.previous_summary.resolve() if args.previous_summary else None,
        waiver_file=args.waiver_file.resolve() if args.waiver_file else None,
        timeout_seconds=args.timeout_seconds,
        clean_out_dir=not args.no_clean_out_dir,
    )


def normalized_artifact_hostname(hostname: str) -> str:
    return hostname.rstrip(".").lower()


def is_numeric_dotted_host(hostname: str) -> bool:
    labels = hostname.split(".")
    return len(labels) > 1 and all(label.isdigit() for label in labels)


def artifact_hostname_is_public(hostname: str) -> bool:
    normalized_host = normalized_artifact_hostname(hostname)
    if not normalized_host or "%" in normalized_host:
        return False
    if normalized_host in LOCAL_ARTIFACT_HOSTS or normalized_host in PLACEHOLDER_ARTIFACT_HOSTS:
        return False
    if any(normalized_host.endswith(suffix) for suffix in PRIVATE_ARTIFACT_HOST_SUFFIXES):
        return False
    try:
        address = ipaddress.ip_address(normalized_host)
    except ValueError:
        if is_numeric_dotted_host(normalized_host):
            return False
        return "." in normalized_host
    return address.is_global and not address.is_multicast


def validate_artifact_base_uri(mode: str, artifact_base_uri: str) -> None:
    if mode == "developer-dry-run":
        return
    parsed = urllib.parse.urlparse(artifact_base_uri)
    hostname = parsed.hostname or ""
    if parsed.scheme != "https" or not hostname:
        raise SystemExit("release-candidate and production-beta artifact base URIs must use https.")
    if parsed.username or parsed.password:
        raise SystemExit("artifact base URI must not contain credentials.")
    if parsed.query or parsed.fragment:
        raise SystemExit("artifact base URI must not contain query strings or fragments.")
    normalized_host = normalized_artifact_hostname(hostname)
    if normalized_host in PLACEHOLDER_ARTIFACT_HOSTS or normalized_host.endswith(".invalid"):
        raise SystemExit("artifact base URI must not use the placeholder .invalid host.")
    if not artifact_hostname_is_public(hostname):
        raise SystemExit("artifact base URI must be a public HTTPS release artifact host.")


def make_self_test_workspace(root: Path) -> None:
    shutil.copytree(REPO_ROOT / "tools", root / "tools")
    shutil.copytree(REPO_ROOT / "docs", root / "docs")
    shutil.copy2(REPO_ROOT / "build.gradle.kts", root / "build.gradle.kts")
    write_text(root / "gradlew", "#!/usr/bin/env sh\nexit 0\n")
    (root / "gradlew").chmod(0o755)


def write_fake_crypta_app_cli(workspace: Path) -> Path:
    bin_dir = workspace / "platform-devtools/build/install/crypta-app/bin"
    cli = bin_dir / crypta_app_launcher_name()
    python_cli = bin_dir / "crypta-app.py"
    write_text(
        python_cli,
        textwrap.dedent(
            f"""\
            #!/usr/bin/env python3
            import pathlib
            import sys


            def value(args, flag):
                return args[args.index(flag) + 1]


            args = sys.argv[1:]
            try:
                if args[:1] == ["pack"]:
                    pathlib.Path(value(args, "--output")).write_bytes(b"fixture bundle\\n")
                elif args[:2] == ["catalog", "entry"]:
                    entry_text = (
                        "entry=ok\\n"
                        + "bundle.uri=" + value(args, "--bundle-uri") + "\\n"
                        + "artifact=" + value(args, "--artifact") + "\\n"
                    )
                    for flag, key in (
                        ("--minimum-crypta-version", "minimumCryptaVersion"),
                        ("--maximum-crypta-version", "maximumCryptaVersion"),
                        ("--maintenance-owner", "maintenance.owner"),
                        ("--maintenance-owner-uri", "maintenance.ownerUri"),
                        ("--maintenance-support-level", "maintenance.supportLevel"),
                        ("--maintenance-data-schema-policy", "maintenance.dataSchemaPolicy"),
                        ("--maintenance-migration-policy", "maintenance.migrationPolicy"),
                        ("--maintenance-backup-restore", "maintenance.backupRestore"),
                        ("--maintenance-security-policy", "maintenance.securityPolicy"),
                        ("--maintenance-deprecation-policy", "maintenance.deprecationPolicy"),
                        ("--maintenance-support-uri", "maintenance.supportUri"),
                    ):
                        if flag in args:
                            entry_text += key + "=" + value(args, flag) + "\\n"
                    pathlib.Path(value(args, "--output")).write_text(
                        entry_text,
                        encoding="utf-8",
                    )
                elif args[:2] == ["review", "sign"]:
                    pathlib.Path(value(args, "--receipt-file")).write_text(
                        "reviewedAt=" + value(args, "--reviewed-at") + "\\n", encoding="utf-8"
                    )
                elif args[:2] == ["review", "verify"]:
                    pass
                elif args[:2] == ["catalog", "create"]:
                    catalog_text = "generatedAt=" + value(args, "--generated-at") + "\\n"
                    for index, arg in enumerate(args):
                        if arg == "--entry":
                            catalog_text += pathlib.Path(args[index + 1]).read_text(encoding="utf-8")
                    pathlib.Path(value(args, "--catalog-file")).write_text(catalog_text, encoding="utf-8")
                elif args[:2] == ["catalog", "sign"]:
                    catalog = pathlib.Path(value(args, "--catalog-file"))
                    catalog.with_name("{CANONICAL_CATALOG_SIGNATURE}").write_text("signature=ok\\n", encoding="utf-8")
                elif args[:2] == ["catalog", "verify"]:
                    catalog = pathlib.Path(value(args, "--catalog-file"))
                    if not catalog.with_name("{CANONICAL_CATALOG_SIGNATURE}").is_file():
                        raise SystemExit("missing canonical signature sidecar")
                else:
                    raise SystemExit("unsupported fake crypta-app command: " + " ".join(args))
            except Exception as exc:
                sys.stderr.write(str(exc) + "\\n")
                raise SystemExit(1)
            """
        ),
    )
    if platform.system() == "Windows":
        write_text(cli, f'@echo off\r\n"{sys.executable}" "%~dp0crypta-app.py" %*\r\n')
    else:
        shutil.copy2(python_cli, cli)
        cli.chmod(0o755)
    return cli


def write_test_zip_archive(path: Path, entries: dict[str, str | bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            # These archives are generated only by the redaction self-test and may contain
            # intentionally unsafe payloads that must be detected by the scanner.
            archive.writestr(name, content)


def test_zip_archive_bytes(entries: dict[str, str | bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def test_tar_gz_archive_bytes(entries: dict[str, str | bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in entries.items():
            data = content.encode("utf-8") if isinstance(content, str) else content
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def write_test_tar_gz_archive(path: Path, entries: dict[str, str | bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # This helper is redaction-self-test-only and may persist intentionally unsafe fixtures that
    # must be rejected by the scanner.
    write_bytes(path, test_tar_gz_archive_bytes(entries))


def assert_redaction_fails(kind: str, writer: Any) -> None:
    with tempfile.TemporaryDirectory(prefix=f"cryptad-redaction-{kind}-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        out_dir = workspace / "build/redaction"
        out_dir.mkdir(parents=True)
        writer(out_dir)
        settings = Settings(
            workspace_root=workspace,
            out_dir=out_dir,
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=False,
        )
        findings = scan_tree(out_dir, settings, include_dist=True)
        assert findings, f"{kind} did not fail redaction"


def assert_redaction_allows(kind: str, writer: Any) -> None:
    with tempfile.TemporaryDirectory(prefix=f"cryptad-redaction-allow-{kind}-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        out_dir = workspace / "build/redaction"
        out_dir.mkdir(parents=True)
        writer(out_dir)
        settings = Settings(
            workspace_root=workspace,
            out_dir=out_dir,
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=False,
        )
        findings = scan_tree(out_dir, settings, include_dist=True)
        assert not findings, f"{kind} unexpectedly failed redaction: {findings}"


def assert_safe_copy_tree_rejects_symlink() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-symlink-") as temp_name:
        root = Path(temp_name)
        src = root / "src"
        dst = root / "dst"
        src.mkdir()
        write_text(src / "cryptad-app.properties", "app.id=fixture\n")
        outside = root / "outside-secret.txt"
        write_text(outside, "host-local-data\n")
        try:
            (src / "leaked-host-file").symlink_to(outside)
        except (NotImplementedError, OSError):
            return
        try:
            safe_copy_tree(src, dst, "self-test staged app")
        except ReleaseArtifactError as exc:
            assert "symlink" in str(exc), exc
            assert not (dst / "leaked-host-file").exists(), "symlink target was copied into the artifact tree"
        else:
            raise AssertionError("safe_copy_tree accepted a staged app symlink")


def assert_safe_copy_tree_rejects_symlinked_root() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-root-symlink-") as temp_name:
        root = Path(temp_name)
        target = root / "target"
        target.mkdir()
        write_text(target / "host-file.txt", "host-local-data\n")
        src = root / "src-link"
        dst = root / "dst"
        try:
            src.symlink_to(target, target_is_directory=True)
        except (NotImplementedError, OSError):
            return
        try:
            safe_copy_tree(src, dst, "self-test staged app")
        except ReleaseArtifactError as exc:
            assert "symlink" in str(exc), exc
            assert not (dst / "host-file.txt").exists(), "symlinked root target was copied into the artifact tree"
        else:
            raise AssertionError("safe_copy_tree accepted a symlinked copy root")


def assert_redaction_rejects_release_output_symlink() -> None:
    def writer(out_dir: Path) -> None:
        target = out_dir / "target.txt"
        write_text(target, "public artifact text\n")
        link = out_dir / "reports" / "target-link"
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            link.symlink_to(target)
        except (NotImplementedError, OSError):
            write_redaction_fixture_text(
                out_dir / "reports" / "fallback.txt", "CRYPTAD_APP_TOKEN=abc1234567890abcdef\n"
            )

    assert_redaction_fails("release-output-symlink", writer)


def assert_tarball_redaction_rejects_symlink_member() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-tar-symlink-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        tar_path = Path(temp_name) / "candidate.tar.gz"
        with tarfile.open(tar_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            info = tarfile.TarInfo("reports/host-workspace-link")
            info.type = tarfile.SYMTYPE
            info.linkname = str(workspace)
            archive.addfile(info)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=False,
        )
        findings = scan_tarball(tar_path, settings)
        assert any(finding["kind"] == "forbidden-tar-entry" for finding in findings), findings


def assert_blank_review_policy_env_uses_defaults() -> None:
    env_keys = (
        "CRYPTAD_APP_SIGNING_KEY_ID",
        "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE",
        "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64",
        "CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE",
        "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64",
        "CRYPTAD_APP_REVIEWER_KEY_ID",
        "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE",
        "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64",
        "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE",
        "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64",
        "CRYPTAD_APP_REVIEW_POLICY_ID",
        "CRYPTAD_APP_REVIEW_POLICY_VERSION",
    )
    saved = {key: os.environ.get(key) for key in env_keys}
    try:
        for key in env_keys:
            os.environ.pop(key, None)
        os.environ["CRYPTAD_APP_REVIEW_POLICY_ID"] = ""
        os.environ["CRYPTAD_APP_REVIEW_POLICY_VERSION"] = "  "
        with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-review-policy-") as temp_name:
            workspace = Path(temp_name) / "repo"
            make_self_test_workspace(workspace)
            settings = Settings(
                workspace_root=workspace,
                out_dir=workspace / "build/production-beta",
                mode="developer-dry-run",
                catalog_channel="stable",
                artifact_base_uri="https://downloads.crypta.invalid/self-test",
                require_live_network=False,
                require_sandbox_provider_tests=False,
                skip_gradle=True,
                skip_full_build=True,
                use_fixture_evidence=True,
                allow_dirty_workspace=True,
                emergency_skip_live_network=False,
                emergency_skip_build=False,
                allow_test_signing_in_production=False,
                previous_summary=None,
                waiver_file=None,
                timeout_seconds=60,
                clean_out_dir=True,
            )
            state = PipelineState(settings, "self-test", utc_now(), [], [], [])
            profile = prepare_signing_profile(state, workspace / "keys")
            assert profile.review_policy_id == "crypta-app-review-v1", profile
            assert profile.review_policy_version == "1", profile
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def assert_fixture_signing_profile_ignores_ambient_env() -> None:
    saved = {key: os.environ.get(key) for key in SIGNING_PROFILE_ENV_KEYS}
    try:
        os.environ.update(
            {
                "CRYPTAD_APP_SIGNING_KEY_ID": "ambient-production-app-key",
                "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64": "YW1iaWVudC1hcHAtcHJpdmF0ZQ==",
                "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64": "YW1iaWVudC1hcHAtcHVibGlj",
                "CRYPTAD_APP_REVIEWER_KEY_ID": "ambient-production-reviewer-key",
                "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64": "YW1iaWVudC1yZXZpZXdlci1wcml2YXRl",
                "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64": "YW1iaWVudC1yZXZpZXdlci1wdWJsaWM=",
                "CRYPTAD_APP_REVIEW_POLICY_ID": "ambient-review-policy",
                "CRYPTAD_APP_REVIEW_POLICY_VERSION": "99",
            }
        )
        with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-fixture-profile-") as temp_name:
            workspace = Path(temp_name) / "repo"
            make_self_test_workspace(workspace)
            settings = Settings(
                workspace_root=workspace,
                out_dir=workspace / "build/production-beta",
                mode="developer-dry-run",
                catalog_channel="stable",
                artifact_base_uri="https://downloads.crypta.invalid/self-test",
                require_live_network=False,
                require_sandbox_provider_tests=False,
                skip_gradle=True,
                skip_full_build=True,
                use_fixture_evidence=True,
                allow_dirty_workspace=True,
                emergency_skip_live_network=False,
                emergency_skip_build=False,
                allow_test_signing_in_production=False,
                previous_summary=None,
                waiver_file=None,
                timeout_seconds=60,
                clean_out_dir=True,
            )
            state = PipelineState(settings, "self-test", utc_now(), [], [], [])
            profile = prepare_signing_profile(state, workspace / "keys")
            assert profile.kind == "test-fixture", profile
            assert profile.generated_test_keys is True, profile
            assert profile.app_key_id == FIXTURE_APP_SIGNING_KEY_ID, profile
            assert profile.reviewer_key_id == FIXTURE_REVIEWER_KEY_ID, profile
            assert profile.review_policy_id == DEFAULT_REVIEW_POLICY_ID, profile
            assert profile.review_policy_version == DEFAULT_REVIEW_POLICY_VERSION, profile
            assert profile.env["CRYPTAD_APP_SIGNING_KEY_ID"] == FIXTURE_APP_SIGNING_KEY_ID, profile.env
            assert profile.env["CRYPTAD_APP_REVIEWER_KEY_ID"] == FIXTURE_REVIEWER_KEY_ID, profile.env
            assert profile.env["CRYPTAD_APP_REVIEW_POLICY_ID"] == DEFAULT_REVIEW_POLICY_ID, profile.env
            assert profile.env["CRYPTAD_APP_REVIEW_POLICY_VERSION"] == DEFAULT_REVIEW_POLICY_VERSION, profile.env
            for key in (
                "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE",
                "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64",
                "CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE",
                "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64",
                "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE",
                "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64",
                "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE",
                "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64",
            ):
                assert key not in profile.env, (key, profile.env)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def assert_dirty_production_beta_is_non_promotable() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-dirty-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="production-beta",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=False,
            allow_dirty_workspace=True,
            emergency_skip_live_network=True,
            emergency_skip_build=True,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=True,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [], dirty_workspace=True)
        state.signing_profile = SigningProfile(
            kind="production",
            generated_test_keys=False,
            env={},
            private_paths=[],
            app_key_id="app-key",
            reviewer_key_id="reviewer-key",
            review_policy_id="crypta-app-review-v1",
            review_policy_version="1",
        )
        promotion = evaluate_promotion(state, {})
        failed_ids = {gate["id"] for gate in promotion["gates"] if gate["status"] == "fail"}
        assert "workspace.clean-production-beta" in failed_ids, failed_ids
        assert promotion["nonRelease"] is True, promotion
        assert promotion["promotionReady"] is False, promotion


def write_minimal_promotion_artifacts(out_dir: Path) -> None:
    for app_id in APP_IDS:
        write_text(out_dir / "build/staged-apps" / app_id / "cryptad-app.signature", "signature=ok\n")
        write_text(out_dir / "reviews/review-receipts" / f"{app_id}-review-receipt.properties", "status=reviewed\n")
    write_text(out_dir / "catalog/first-party-catalog.properties", "catalog=ok\n")
    write_text(out_dir / "catalog" / CANONICAL_CATALOG_SIGNATURE, "signature=ok\n")


def passing_promotion_summaries() -> dict[str, Any]:
    cert_evidence = [
        {
            "id": evidence_id,
            "status": "pass",
            "summary": f"{evidence_id} passed.",
            "details": {},
        }
        for evidence_id in CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS
    ]
    live_evidence = [
        {
            "id": evidence_id,
            "status": "pass",
            "summary": f"{evidence_id} passed.",
            "details": {},
        }
        for evidence_id in LIVE_NETWORK_REQUIRED_IDS
    ]
    return {
        "certification": {"releaseCandidatePassed": True, "evidence": cert_evidence},
        "liveNetwork": {"status": "pass", "evidence": live_evidence},
        "matrix": {"status": "pass", "releaseBlockerCount": 0},
    }


def production_signing_profile() -> SigningProfile:
    return SigningProfile(
        kind="production",
        generated_test_keys=False,
        env={},
        private_paths=[],
        app_key_id="app-key",
        reviewer_key_id="reviewer-key",
        review_policy_id="crypta-app-review-v1",
        review_policy_version="1",
    )


def assert_emergency_build_skip_is_non_promotable() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-build-skip-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        out_dir = workspace / "build/production-beta"
        write_minimal_promotion_artifacts(out_dir)
        settings = Settings(
            workspace_root=workspace,
            out_dir=out_dir,
            mode="production-beta",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=True,
            require_sandbox_provider_tests=True,
            skip_gradle=False,
            skip_full_build=True,
            use_fixture_evidence=False,
            allow_dirty_workspace=False,
            emergency_skip_live_network=False,
            emergency_skip_build=True,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=True,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        state.signing_profile = production_signing_profile()
        assert release_config(state)["nonRelease"] is True
        promotion = evaluate_promotion(state, passing_promotion_summaries())
        failed_ids = {gate["id"] for gate in promotion["gates"] if gate["status"] == "fail"}
        assert "build.production-beta-complete" in failed_ids, promotion
        assert promotion["nonRelease"] is True, promotion
        assert promotion["promotionReady"] is False, promotion


def assert_allow_test_signing_env_profile_is_non_release() -> None:
    env_keys = (
        "CRYPTAD_APP_SIGNING_KEY_ID",
        "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE",
        "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64",
        "CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE",
        "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64",
        "CRYPTAD_APP_REVIEWER_KEY_ID",
        "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE",
        "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64",
        "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE",
        "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64",
        "CRYPTAD_APP_REVIEW_POLICY_ID",
        "CRYPTAD_APP_REVIEW_POLICY_VERSION",
    )
    saved = {key: os.environ.get(key) for key in env_keys}
    try:
        for key in env_keys:
            os.environ.pop(key, None)
        os.environ.update(
            {
                "CRYPTAD_APP_SIGNING_KEY_ID": "test-app-key",
                "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64": "dGVzdC1hcHAtcHJpdmF0ZS1rZXk=",
                "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64": "dGVzdC1hcHAtcHVibGljLWtleQ==",
                "CRYPTAD_APP_REVIEWER_KEY_ID": "test-reviewer-key",
                "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64": "dGVzdC1yZXZpZXdlci1wcml2YXRlLWtleQ==",
                "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64": "dGVzdC1yZXZpZXdlci1wdWJsaWMta2V5",
            }
        )
        with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-test-signing-") as temp_name:
            workspace = Path(temp_name) / "repo"
            make_self_test_workspace(workspace)
            out_dir = workspace / "build/production-beta"
            write_minimal_promotion_artifacts(out_dir)
            settings = Settings(
                workspace_root=workspace,
                out_dir=out_dir,
                mode="production-beta",
                catalog_channel="stable",
                artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
                require_live_network=True,
                require_sandbox_provider_tests=True,
                skip_gradle=False,
                skip_full_build=False,
                use_fixture_evidence=False,
                allow_dirty_workspace=False,
                emergency_skip_live_network=False,
                emergency_skip_build=False,
                allow_test_signing_in_production=True,
                previous_summary=None,
                waiver_file=None,
                timeout_seconds=60,
                clean_out_dir=True,
            )
            state = PipelineState(settings, "self-test", utc_now(), [], [], [])
            profile = prepare_signing_profile(state, workspace / "keys")
            state.signing_profile = profile
            assert profile.kind == "configured", profile
            assert profile.generated_test_keys is False, profile
            assert release_config(state)["nonRelease"] is True
            promotion = evaluate_promotion(state, passing_promotion_summaries())
            assert promotion_gate_by_id(promotion, "signing.production-keys")["status"] == "pass", promotion
            assert promotion["status"] == "pass", promotion
            assert promotion["nonRelease"] is True, promotion
            assert promotion["promotionReady"] is False, promotion
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def assert_failed_final_summary_clears_promotion_ready() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-summary-ready-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="production-beta",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=True,
            require_sandbox_provider_tests=True,
            skip_gradle=False,
            skip_full_build=False,
            use_fixture_evidence=False,
            allow_dirty_workspace=False,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=True,
        )
        promotion = {
            "status": "pass",
            "promotionReady": True,
            "nonRelease": False,
            "failedGateCount": 0,
            "gates": [],
            "knownLimitations": [],
        }
        redaction_pass = {"schemaVersion": 1, "status": "pass", "scannedRoot": "<release-out>", "findingCount": 0, "findings": []}
        redaction_fail = {
            "schemaVersion": 1,
            "status": "fail",
            "scannedRoot": "<release-out>",
            "findingCount": 1,
            "findings": [{"kind": "app-token", "path": "reports/leak.txt"}],
        }

        command_failed_state = PipelineState(
            settings,
            "self-test",
            utc_now(),
            [],
            [],
            ["gradle-stage-sign-verify-first-party-apps failed with exit code 1"],
            signing_profile=production_signing_profile(),
        )
        command_failed_summary = build_final_summary(command_failed_state, promotion, redaction_pass, None)
        assert command_failed_summary["status"] == "fail", command_failed_summary
        assert command_failed_summary["promotionReady"] is False, command_failed_summary
        assert command_failed_summary["promotion"]["promotionReady"] is False, command_failed_summary

        redaction_failed_state = PipelineState(
            settings,
            "self-test",
            utc_now(),
            [],
            [],
            [],
            signing_profile=production_signing_profile(),
        )
        redaction_failed_summary = build_final_summary(redaction_failed_state, promotion, redaction_fail, None)
        assert redaction_failed_summary["status"] == "fail", redaction_failed_summary
        assert redaction_failed_summary["promotionReady"] is False, redaction_failed_summary
        assert redaction_failed_summary["promotion"]["promotionReady"] is False, redaction_failed_summary


def promotion_gate_by_id(promotion: dict[str, Any], gate_id: str) -> dict[str, Any]:
    for gate in promotion["gates"]:
        if gate["id"] == gate_id:
            return gate
    raise AssertionError(f"missing promotion gate {gate_id}")


def assert_waived_critical_evidence_is_accepted_without_redaction_findings() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-waived-evidence-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="release-candidate",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=True,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=False,
            allow_dirty_workspace=False,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=True,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        state.signing_profile = SigningProfile(
            kind="test-fixture",
            generated_test_keys=True,
            env={},
            private_paths=[],
            app_key_id="test-app-key",
            reviewer_key_id="test-reviewer-key",
            review_policy_id="crypta-app-review-v1",
            review_policy_version="1",
        )

        def summaries_for(details: dict[str, Any]) -> dict[str, Any]:
            evidence = [
                {
                    "id": evidence_id,
                    "status": "pass",
                    "summary": f"{evidence_id} passed.",
                    "details": {},
                }
                for evidence_id in CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS
            ]
            for item in evidence:
                if item["id"] == "apphost.sandbox-provider":
                    item["status"] = "warn"
                    item["summary"] = "Sandbox provider evidence was waived."
                    item["details"] = details
            return {
                "certification": {"releaseCandidatePassed": True, "evidence": evidence},
                "matrix": {"status": "warn", "releaseBlockerCount": 0},
            }

        waived = evaluate_promotion(state, summaries_for({"waived": True, "waiverId": "sandbox-waiver"}))
        assert promotion_gate_by_id(waived, "evidence.apphost.sandbox-provider")["status"] == "pass", waived
        assert promotion_gate_by_id(waived, "evidence.required-sandbox-provider-tests")["status"] == "pass", waived

        redaction = evaluate_promotion(
            state,
            summaries_for(
                {
                    "waived": True,
                    "waiverId": "sandbox-waiver",
                    "redactionFindings": [{"kind": "raw-content-or-app-data"}],
                }
            ),
        )
        assert promotion_gate_by_id(redaction, "evidence.apphost.sandbox-provider")["status"] == "fail", redaction
        assert promotion_gate_by_id(redaction, "evidence.required-sandbox-provider-tests")["status"] == "fail", redaction


def assert_developer_dry_run_exit_code_fails_on_recorded_failures() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-dry-run-failure-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=False,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=True,
        )
        state = PipelineState(
            settings,
            "self-test",
            utc_now(),
            [],
            [],
            ["gradle-stage-sign-verify-first-party-apps failed with exit code 1"],
        )
        summary = build_final_summary(
            state,
            {"status": "pass", "promotionReady": False, "nonRelease": True, "gates": [], "knownLimitations": []},
            {"schemaVersion": 1, "status": "pass", "scannedRoot": "<release-out>", "findingCount": 0, "findings": []},
            None,
        )
        assert summary["status"] == "fail", summary
        assert release_exit_code(settings, summary) == 1, summary


def assert_certification_failure_marks_dry_run_failed() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-cert-failure-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=False,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=True,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        record_certification_result(
            state,
            CommandResult(
                name="release-certification",
                args=[],
                exit_code=17,
                duration_ms=1,
                stdout_tail="",
                stderr_tail="failed",
            ),
        )
        summary = build_final_summary(
            state,
            {"status": "fail", "promotionReady": False, "nonRelease": True, "gates": [], "knownLimitations": []},
            {"schemaVersion": 1, "status": "pass", "scannedRoot": "<release-out>", "findingCount": 0, "findings": []},
            None,
        )
        assert state.certification_exit_code == 17, state.certification_exit_code
        assert "release-certification failed with exit code 17" in state.failures, state.failures
        assert summary["status"] == "fail", summary
        assert release_exit_code(settings, summary) == 1, summary


def cleanup_test_settings(workspace: Path, out_dir: Path) -> Settings:
    return Settings(
        workspace_root=workspace,
        out_dir=out_dir,
        mode="developer-dry-run",
        catalog_channel="stable",
        artifact_base_uri="https://downloads.crypta.invalid/self-test",
        require_live_network=False,
        require_sandbox_provider_tests=False,
        skip_gradle=True,
        skip_full_build=True,
        use_fixture_evidence=False,
        allow_dirty_workspace=True,
        emergency_skip_live_network=False,
        emergency_skip_build=False,
        allow_test_signing_in_production=False,
        previous_summary=None,
        waiver_file=None,
        timeout_seconds=60,
        clean_out_dir=True,
    )


def create_git_tracked_output_target(workspace: Path) -> Path | None:
    tracked_dir = workspace / "platform-appcatalog"
    write_text(tracked_dir / "source.txt", "tracked source data\n")
    if not run_git(workspace, "init"):
        return None
    if not run_git(workspace, "add", "."):
        return None
    if not run_git(
        workspace,
        "-c",
        "user.name=Crypta Self Test",
        "-c",
        "user.email=self-test@crypta.invalid",
        "commit",
        "-m",
        "self-test workspace",
    ):
        return None
    return tracked_dir


def assert_cleanup_refuses_protected_workspace_paths() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-clean-protected-") as temp_name:
        workspace = Path(temp_name) / "repo"
        docs_dir = workspace / "docs"
        docs_dir.mkdir(parents=True)
        write_text(docs_dir / "important.md", "do not delete\n")
        settings = cleanup_test_settings(workspace, docs_dir)
        try:
            ensure_safe_out_dir(settings)
        except SystemExit as exc:
            assert "protected workspace path" in str(exc), exc
        else:
            raise AssertionError("cleanup accepted a protected workspace path")
        assert (docs_dir / "important.md").is_file(), "protected workspace path was deleted"


def assert_cleanup_refuses_arbitrary_existing_directory_without_sentinel() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-clean-arbitrary-") as temp_name:
        workspace = Path(temp_name) / "repo"
        out_dir = workspace / "release-artifacts"
        out_dir.mkdir(parents=True)
        write_text(out_dir / "important.txt", "do not delete\n")
        settings = cleanup_test_settings(workspace, out_dir)
        try:
            ensure_safe_out_dir(settings)
        except SystemExit as exc:
            assert "without a production beta sentinel" in str(exc), exc
        else:
            raise AssertionError("cleanup accepted an arbitrary existing directory without a sentinel")
        assert (out_dir / "important.txt").is_file(), "arbitrary workspace directory was deleted"


def assert_no_clean_refuses_arbitrary_existing_directory_without_sentinel() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-no-clean-arbitrary-") as temp_name:
        workspace = Path(temp_name) / "repo"
        out_dir = workspace / "release-artifacts"
        write_text(out_dir / "build/important-build-output.txt", "do not delete\n")
        write_text(out_dir / "reports/important-report.txt", "do not delete\n")
        write_text(out_dir / "dist/important-dist.txt", "do not delete\n")
        settings = dataclasses.replace(cleanup_test_settings(workspace, out_dir), clean_out_dir=False)
        try:
            ensure_safe_out_dir(settings)
        except SystemExit as exc:
            assert "without a production beta sentinel" in str(exc), exc
        else:
            raise AssertionError("no-clean output validation accepted an arbitrary existing directory without a sentinel")
        assert (out_dir / "build/important-build-output.txt").is_file(), "no-clean build subtree was deleted"
        assert (out_dir / "reports/important-report.txt").is_file(), "no-clean reports subtree was deleted"
        assert (out_dir / "dist/important-dist.txt").is_file(), "no-clean dist subtree was deleted"
        assert not cleanup_sentinel(out_dir).exists(), "sentinel was written into an untrusted no-clean output directory"


def assert_no_clean_refuses_tracked_directory_before_sentinel() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-clean-tracked-no-clean-") as temp_name:
        workspace = Path(temp_name) / "repo"
        tracked_dir = create_git_tracked_output_target(workspace)
        if tracked_dir is None:
            return
        settings = dataclasses.replace(cleanup_test_settings(workspace, tracked_dir), clean_out_dir=False)
        try:
            ensure_safe_out_dir(settings)
        except SystemExit as exc:
            assert "without a production beta sentinel" in str(exc), exc
        else:
            raise AssertionError("no-clean output validation accepted a git-tracked source directory")
        assert (tracked_dir / "source.txt").is_file(), "tracked source directory was modified"
        assert not cleanup_sentinel(tracked_dir).exists(), "sentinel was written into a tracked source directory"


def assert_cleanup_refuses_tracked_directory_even_with_sentinel() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-clean-tracked-sentinel-") as temp_name:
        workspace = Path(temp_name) / "repo"
        tracked_dir = create_git_tracked_output_target(workspace)
        if tracked_dir is None:
            return
        write_text(cleanup_sentinel(tracked_dir), "Crypta production beta release output directory.\n")
        settings = cleanup_test_settings(workspace, tracked_dir)
        try:
            ensure_safe_out_dir(settings)
        except SystemExit as exc:
            assert "contains git-tracked files" in str(exc), exc
        else:
            raise AssertionError("sentinel authorized cleanup of a git-tracked source directory")
        assert (tracked_dir / "source.txt").is_file(), "tracked source directory was deleted"
        assert cleanup_sentinel(tracked_dir).is_file(), "test sentinel unexpectedly disappeared"


def assert_cleanup_refuses_unknown_tracked_file_status() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-clean-unknown-tracked-") as temp_name:
        workspace = Path(temp_name) / "repo"
        out_dir = workspace / "build/production-beta-unknown-tracked"
        out_dir.mkdir(parents=True)
        write_text(cleanup_sentinel(out_dir), "Crypta production beta release output directory.\n")
        write_text(out_dir / "important.txt", "do not delete\n")
        settings = cleanup_test_settings(workspace, out_dir)
        original_git_tracked_files_under = globals()["git_tracked_files_under"]
        try:
            globals()["git_tracked_files_under"] = lambda _workspace, _out_dir: None
            try:
                ensure_safe_out_dir(settings)
            except SystemExit as exc:
                assert "git-tracked file status could not be verified" in str(exc), exc
            else:
                raise AssertionError("cleanup accepted an output directory with unknown git-tracked file status")
        finally:
            globals()["git_tracked_files_under"] = original_git_tracked_files_under
        assert (out_dir / "important.txt").is_file(), "output directory was deleted despite unknown tracked-file status"
        assert cleanup_sentinel(out_dir).is_file(), "test sentinel unexpectedly disappeared"


def assert_cleanup_allows_default_release_output_prefix() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-clean-default-") as temp_name:
        workspace = Path(temp_name) / "repo"
        out_dir = workspace / "build/production-beta-self-test"
        out_dir.mkdir(parents=True)
        if not run_git(workspace, "init"):
            return
        write_text(out_dir / "stale.txt", "delete me\n")
        settings = cleanup_test_settings(workspace, out_dir)
        ensure_safe_out_dir(settings)
        assert not (out_dir / "stale.txt").exists(), "default release output prefix was not cleaned"
        assert cleanup_sentinel(out_dir).is_file(), "release output sentinel was not written"


def assert_cleanup_allows_sentinel_directory() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-clean-sentinel-") as temp_name:
        workspace = Path(temp_name) / "repo"
        out_dir = workspace / "custom-output"
        out_dir.mkdir(parents=True)
        if not run_git(workspace, "init"):
            return
        write_text(cleanup_sentinel(out_dir), "Crypta production beta release output directory.\n")
        write_text(out_dir / "stale.txt", "delete me\n")
        settings = cleanup_test_settings(workspace, out_dir)
        ensure_safe_out_dir(settings)
        assert not (out_dir / "stale.txt").exists(), "sentinel output directory was not cleaned"
        assert cleanup_sentinel(out_dir).is_file(), "release output sentinel was not restored"


def assert_strict_skip_gradle_requires_emergency_build_flag() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-skip-gradle-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="release-candidate",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=False,
            allow_dirty_workspace=False,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=True,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        run_gradle(state, "gradle-self-test", ["help"])
        assert any("release-candidate mode cannot skip Gradle stage" in failure for failure in state.failures), state.failures

        emergency_settings = dataclasses.replace(settings, emergency_skip_build=True)
        emergency_state = PipelineState(emergency_settings, "self-test", utc_now(), [], [], [])
        run_gradle(emergency_state, "gradle-self-test", ["help"])
        assert not emergency_state.failures, emergency_state.failures


def assert_unknown_workspace_status_fails_strict_modes() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-unknown-workspace-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        for mode in ("release-candidate", "production-beta"):
            settings = Settings(
                workspace_root=workspace,
                out_dir=workspace / f"build/{mode}",
                mode=mode,
                catalog_channel="stable",
                artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
                require_live_network=False,
                require_sandbox_provider_tests=False,
                skip_gradle=True,
                skip_full_build=True,
                use_fixture_evidence=False,
                allow_dirty_workspace=True,
                emergency_skip_live_network=True,
                emergency_skip_build=True,
                allow_test_signing_in_production=False,
                previous_summary=None,
                waiver_file=None,
                timeout_seconds=60,
                clean_out_dir=True,
            )
            state = PipelineState(settings, "self-test", utc_now(), [], [], [])
            check_workspace_clean(state)
            assert state.workspace_status_known is False, state
            assert any("requires a readable git workspace status" in failure for failure in state.failures), state.failures


def assert_catalog_signature_and_timestamps_are_canonical() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-catalog-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        write_fake_crypta_app_cli(workspace)
        policy_file = workspace / FIRST_PARTY_MAINTENANCE_POLICY_FILE
        policy = json.loads(policy_file.read_text(encoding="utf-8"))
        policy["apps"]["queue-manager"]["minimumCryptaVersion"] = "41"
        policy["apps"]["queue-manager"]["maximumCryptaVersion"] = "43"
        write_json(policy_file, policy)
        out_dir = workspace / "build/production-beta"
        app_dir = out_dir / "build/staged-apps/queue-manager"
        write_text(
            app_dir / "cryptad-app.properties",
            "\n".join(
                [
                    "app.id=queue-manager",
                    "app.name=Queue Manager",
                    "app.version=1.2.3",
                    "app.permissions=queue.read",
                    "",
                ]
            ),
        )
        started_at = "2026-06-15T12:34:56Z"
        settings = Settings(
            workspace_root=workspace,
            out_dir=out_dir,
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=False,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=True,
        )
        state = PipelineState(settings, "self-test", started_at, [], [], [])
        profile = SigningProfile(
            kind="test",
            generated_test_keys=True,
            env={
                "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64": "AQID",
                "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64": "BAUG",
            },
            private_paths=[],
            app_key_id="app-key",
            reviewer_key_id="reviewer-key",
            review_policy_id="crypta-app-review-v1",
            review_policy_version="1",
        )
        package_catalog_and_reviews(state, profile, {"queue-manager": app_dir}, workspace / "work")
        assert not state.failures, state.failures
        canonical = out_dir / "catalog" / CANONICAL_CATALOG_SIGNATURE
        alias = out_dir / "catalog" / RELEASE_CATALOG_SIGNATURE_ALIAS
        assert canonical.is_file(), canonical
        assert alias.is_file(), alias
        assert (
            canonical.read_bytes() == alias.read_bytes()
        ), "catalog signature alias diverged from canonical sidecar"
        catalog_text = (out_dir / "catalog/first-party-catalog.properties").read_text(encoding="utf-8")
        assert f"generatedAt={started_at}" in catalog_text
        assert (
            "bundle.uri=https://downloads.crypta.invalid/self-test/build/app-bundles/queue-manager-1.2.3.zip"
            in catalog_text
        ), catalog_text
        assert "minimumCryptaVersion=41" in catalog_text, catalog_text
        assert "maximumCryptaVersion=43" in catalog_text, catalog_text
        assert "maintenance.owner=crypta-core" in catalog_text, catalog_text
        assert "maintenance.supportLevel=core" in catalog_text, catalog_text
        assert "/apps/queue-manager-1.2.3.zip" not in catalog_text, catalog_text
        channel_metadata = json.loads(
            (out_dir / "catalog/channel-metadata.json").read_text(encoding="utf-8")
        )
        assert channel_metadata["maintenancePolicyComplete"] is True, channel_metadata
        assert channel_metadata["apps"][0]["maintenance"]["owner"] == "crypta-core", (
            channel_metadata
        )
        assert f"reviewedAt={started_at}" in (
            out_dir / "reviews/review-receipts/queue-manager-review-receipt.properties"
        ).read_text(encoding="utf-8")


def assert_reviewer_public_key_file_resolves_from_workspace() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-reviewer-key-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        write_bytes(workspace / "protected/reviewer-public.der", b"\x01\x02\x03")
        profile = SigningProfile(
            kind="production",
            generated_test_keys=False,
            env={"CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE": "protected/reviewer-public.der"},
            private_paths=[],
            app_key_id="app-key",
            reviewer_key_id="reviewer-key",
            review_policy_id="crypta-app-review-v1",
            review_policy_version="1",
        )
        output = workspace / "work/trusted-reviewers.properties"
        outside = Path(temp_name) / "outside"
        outside.mkdir()
        original_cwd = Path.cwd()
        try:
            os.chdir(outside)
            write_trusted_reviewer_keys(output, profile, workspace)
        finally:
            os.chdir(original_cwd)
        trusted_text = output.read_text(encoding="utf-8")
        assert "reviewer.1.public.key.base64=AQID" in trusted_text, trusted_text


def assert_protected_secret_file_redaction_resolves_from_workspace() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-redaction-secret-file-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        secret_bytes = b"\x30\x82\x01\x00workspace-relative-private-key-material-9f4b6a"
        write_redaction_fixture_bytes(workspace / "protected/app-signing-private.der", secret_bytes)
        out_dir = workspace / "build/redaction"
        write_redaction_fixture_bytes(out_dir / "neutral.bin", b"prefix-" + secret_bytes + b"-suffix")
        write_redaction_fixture_text(
            out_dir / "neutral-base64.txt", base64.b64encode(secret_bytes).decode("ascii") + "\n"
        )
        settings = Settings(
            workspace_root=workspace,
            out_dir=out_dir,
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=False,
        )
        outside = Path(temp_name) / "outside"
        outside.mkdir()
        saved_secret_file = os.environ.get("CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE")
        original_cwd = Path.cwd()
        try:
            os.environ["CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE"] = "protected/app-signing-private.der"
            os.chdir(outside)
            findings = scan_tree(out_dir, settings, include_dist=True)
        finally:
            os.chdir(original_cwd)
            if saved_secret_file is None:
                os.environ.pop("CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE", None)
            else:
                os.environ["CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE"] = saved_secret_file
        protected_paths = {
            finding["path"]
            for finding in findings
            if finding.get("kind") == "protected-secret-value"
        }
        assert {"neutral.bin", "neutral-base64.txt"}.issubset(protected_paths), findings


def assert_no_clean_rerun_drops_stale_dist_files() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-stale-dist-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        if not run_git(workspace, "init"):
            return
        out_dir = workspace / "build/production-beta"
        write_text(cleanup_sentinel(out_dir), "Crypta production beta release output directory.\n")
        write_redaction_fixture_text(out_dir / "dist/leak.txt", "CRYPTAD_APP_TOKEN=abc1234567890abcdef\n")
        write_text(out_dir / "build/app-bundles/stale-old-version.zip", "stale bundle from an earlier run\n")
        write_text(out_dir / "reports/stale-report.txt", "stale report from an earlier run\n")
        settings = Settings(
            workspace_root=workspace,
            out_dir=out_dir,
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=120,
            clean_out_dir=False,
        )
        summary, exit_code = run_pipeline(settings)
        assert exit_code == 0, summary
        assert summary["redaction"]["status"] == "pass", summary
        assert not (out_dir / "dist/leak.txt").exists(), "stale dist leak survived the rerun"
        assert not (out_dir / "build/app-bundles/stale-old-version.zip").exists(), "stale bundle survived the rerun"
        assert not (out_dir / "reports/stale-report.txt").exists(), "stale report survived the rerun"
        checksum_text = dist_checksums_path(settings).read_text(encoding="utf-8")
        assert "leak.txt" not in checksum_text, checksum_text
        archive_path = out_dir / summary["artifacts"]["distArchive"]
        with tarfile.open(archive_path, "r:gz") as archive:
            names = set(archive.getnames())
        assert "build/app-bundles/stale-old-version.zip" not in names, names
        assert "reports/stale-report.txt" not in names, names


def run_git(workspace: Path, *args: str) -> bool:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=str(workspace),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def assert_custom_out_dir_does_not_dirty_workspace_before_check() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-custom-out-dir-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        if not run_git(workspace, "init"):
            return
        if not run_git(workspace, "add", "."):
            return
        if not run_git(
            workspace,
            "-c",
            "user.name=Crypta Self Test",
            "-c",
            "user.email=self-test@crypta.invalid",
            "commit",
            "-m",
            "self-test workspace",
        ):
            return
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "release-artifacts",
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=False,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=120,
            clean_out_dir=True,
        )
        summary, exit_code = run_pipeline(settings)
        assert exit_code == 0, summary
        assert summary["workspaceStatusKnown"] is True, summary
        assert summary["dirtyWorkspace"] is False, summary
        assert cleanup_sentinel(settings.out_dir).is_file(), "custom output sentinel was not written"


def assert_post_artifact_workspace_recheck_detects_mutation() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-post-build-dirty-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        if not run_git(workspace, "init"):
            return
        if not run_git(workspace, "add", "."):
            return
        if not run_git(
            workspace,
            "-c",
            "user.name=Crypta Self Test",
            "-c",
            "user.email=self-test@crypta.invalid",
            "commit",
            "-m",
            "self-test workspace",
        ):
            return
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "release-artifacts",
            mode="production-beta",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=True,
            require_sandbox_provider_tests=True,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=False,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=120,
            clean_out_dir=True,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        check_workspace_clean(state)
        assert state.workspace_status_known is True, state
        assert state.dirty_workspace is False, state
        assert not state.failures, state.failures

        ensure_safe_out_dir(settings)
        write_text(settings.out_dir / "reports/generated.txt", "generated release output\n")
        check_workspace_clean(state, "post-artifact-build")
        assert state.dirty_workspace is False, state
        assert not state.failures, state.failures

        build_file = workspace / "build.gradle.kts"
        write_text(build_file, build_file.read_text(encoding="utf-8") + "\n// post-build mutation\n")
        check_workspace_clean(state, "post-artifact-build")
        assert state.dirty_workspace is True, state
        assert any("after build/staging" in failure for failure in state.failures), state.failures


def assert_dirty_workspace_state_is_sticky_across_checks() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-sticky-dirty-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        if not run_git(workspace, "init"):
            return
        if not run_git(workspace, "add", "."):
            return
        if not run_git(
            workspace,
            "-c",
            "user.name=Crypta Self Test",
            "-c",
            "user.email=self-test@crypta.invalid",
            "commit",
            "-m",
            "self-test workspace",
        ):
            return
        build_file = workspace / "build.gradle.kts"
        original_build_text = build_file.read_text(encoding="utf-8")
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "release-artifacts",
            mode="production-beta",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=False,
            allow_dirty_workspace=True,
            emergency_skip_live_network=True,
            emergency_skip_build=True,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=120,
            clean_out_dir=True,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])

        write_text(build_file, original_build_text + "\n// temporary dirty state\n")
        check_workspace_clean(state)
        assert state.dirty_workspace is True, state
        assert not state.failures, state.failures

        write_text(build_file, original_build_text)
        check_workspace_clean(state, "post-artifact-build")
        assert state.dirty_workspace is True, state
        promotion = evaluate_promotion(state, {})
        assert promotion_gate_by_id(promotion, "workspace.clean-production-beta")["status"] == "fail", promotion
        assert promotion["nonRelease"] is True, promotion
        assert promotion["promotionReady"] is False, promotion


def assert_project_version_parser_accepts_release_build_numbers() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-version-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        build_file = workspace / "build.gradle.kts"

        write_text(build_file, 'version = "41"\n')
        assert read_project_version(workspace) == "41"

        write_text(build_file, "version = 42\n")
        assert read_project_version(workspace) == "42"

        write_text(build_file, "version = 43 // release build\n")
        assert read_project_version(workspace) == "43"

        write_text(build_file, "version = releaseBuild\n")
        try:
            read_project_version(workspace)
        except SystemExit as exc:
            assert "Unable to parse project version" in str(exc), exc
        else:
            raise AssertionError("read_project_version accepted an unsupported version assignment")


def assert_maintenance_policy_resolves_from_workspace() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-maintenance-workspace-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        settings = cleanup_test_settings(workspace, workspace / "build/policy-copy")
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        policy_file = first_party_maintenance_policy_file(state)
        policy = json.loads(policy_file.read_text(encoding="utf-8"))
        for app_id in APP_IDS:
            policy["apps"][app_id]["maximumCryptaVersion"] = "43"
        write_json(policy_file, policy)

        loaded = load_first_party_maintenance_policy(state)
        copy_first_party_maintenance_policy_input(state)
        copied_policy = json.loads(
            (settings.out_dir / "inputs/first-party-app-maintenance-policy.json").read_text(
                encoding="utf-8"
            )
        )

        assert not state.failures, state.failures
        assert loaded["queue-manager"]["maximumCryptaVersion"] == "43", loaded
        assert copied_policy["apps"]["queue-manager"]["maximumCryptaVersion"] == "43", (
            copied_policy
        )


def assert_missing_maintenance_policy_warns_in_dry_run_and_fails_strict_modes() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-maintenance-policy-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        original_policy = globals()["FIRST_PARTY_MAINTENANCE_POLICY_FILE"]
        try:
            globals()["FIRST_PARTY_MAINTENANCE_POLICY_FILE"] = (
                workspace / "tools/release-certification/missing-policy.json"
            )
            dry_run_settings = cleanup_test_settings(workspace, workspace / "build/dry-run")
            dry_run_state = PipelineState(dry_run_settings, "self-test", utc_now(), [], [], [])
            assert load_first_party_maintenance_policy(dry_run_state) == {}
            assert dry_run_state.warnings, dry_run_state
            assert str(workspace) not in json.dumps(dry_run_state.warnings), dry_run_state.warnings
            assert "<repo>/tools/release-certification/missing-policy.json" in dry_run_state.warnings[0], (
                dry_run_state.warnings
            )
            assert not dry_run_state.failures, dry_run_state

            strict_settings = dataclasses.replace(
                dry_run_settings,
                mode="release-candidate",
                allow_dirty_workspace=False,
                emergency_skip_build=True,
            )
            strict_state = PipelineState(strict_settings, "self-test", utc_now(), [], [], [])
            assert load_first_party_maintenance_policy(strict_state) == {}
            assert strict_state.failures, strict_state
            assert str(workspace) not in json.dumps(strict_state.failures), strict_state.failures
            assert "<repo>/tools/release-certification/missing-policy.json" in strict_state.failures[0], (
                strict_state.failures
            )
        finally:
            globals()["FIRST_PARTY_MAINTENANCE_POLICY_FILE"] = original_policy


def assert_incomplete_maintenance_policy_warns_in_dry_run_and_fails_strict_modes() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-incomplete-maintenance-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        policy_file = workspace / FIRST_PARTY_MAINTENANCE_POLICY_FILE
        policy = json.loads(policy_file.read_text(encoding="utf-8"))
        maintenance = policy["apps"]["queue-manager"]["maintenance"]
        maintenance.pop("ownerUri")
        maintenance.pop("supportUri")
        write_json(policy_file, policy)

        dry_run_settings = cleanup_test_settings(workspace, workspace / "build/dry-run")
        dry_run_state = PipelineState(dry_run_settings, "self-test", utc_now(), [], [], [])
        dry_run_policy = load_first_party_maintenance_policy(dry_run_state)
        assert "queue-manager" not in dry_run_policy, dry_run_policy
        assert dry_run_state.warnings, dry_run_state
        assert "ownerUri, supportUri" in dry_run_state.warnings[0], dry_run_state.warnings
        assert not dry_run_state.failures, dry_run_state

        strict_settings = dataclasses.replace(
            dry_run_settings,
            mode="release-candidate",
            allow_dirty_workspace=False,
            emergency_skip_build=True,
        )
        strict_state = PipelineState(strict_settings, "self-test", utc_now(), [], [], [])
        strict_policy = load_first_party_maintenance_policy(strict_state)
        assert "queue-manager" not in strict_policy, strict_policy
        assert strict_state.failures, strict_state
        assert "ownerUri, supportUri" in strict_state.failures[0], strict_state.failures


def assert_maintenance_policy_input_copy_redacts_invalid_values() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-maintenance-redaction-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        policy_file = workspace / FIRST_PARTY_MAINTENANCE_POLICY_FILE
        policy = json.loads(policy_file.read_text(encoding="utf-8"))
        unknown_app_id = str(workspace / "private-extra-app-token-secret")
        policy["apps"][unknown_app_id] = {
            "channel": "stable",
            "supportStatus": "supported",
            "deprecationStatus": "none",
            "maintenance": {},
        }
        app_policy = policy["apps"]["queue-manager"]
        app_policy["channel"] = str(workspace / "private-channel-token.txt")
        app_policy["supportStatus"] = "token=status-secret"
        app_policy["deprecationStatus"] = "USK@PRIVATE-DEPRECATION"
        app_policy["minimumCryptaVersion"] = str(workspace / "private-min-version.txt")
        app_policy["maximumCryptaVersion"] = "version-token=secret"
        maintenance = app_policy["maintenance"]
        maintenance["owner"] = "crypta-core token=owner-secret"
        maintenance["ownerUri"] = (
            "https://example.invalid/crypta/owners/core?token=owner-uri-secret"
        )
        maintenance["supportUri"] = (
            "https://example.invalid/crypta/apps/queue-manager/support?token=support-uri-secret"
        )
        maintenance["securityPolicy"] = "token=security-secret"
        write_json(policy_file, policy)

        settings = cleanup_test_settings(workspace, workspace / "build/redacted-policy-copy")
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        copy_first_party_maintenance_policy_input(state)
        copied_text = (
            settings.out_dir / "inputs/first-party-app-maintenance-policy.json"
        ).read_text(encoding="utf-8")
        loaded = load_first_party_maintenance_policy(state)
        warning_text = json.dumps(state.warnings + state.failures, sort_keys=True)

        assert "queue-manager" not in loaded, loaded
        assert state.warnings, state
        assert "invalid or unsafe fields" in warning_text, state.warnings
        assert "contains 1 unknown app id(s)" in warning_text, state.warnings
        assert "<redacted>" in copied_text, copied_text
        for forbidden in (
            "private-extra-app-token-secret",
            "private-channel-token.txt",
            "status-secret",
            "PRIVATE-DEPRECATION",
            "private-min-version.txt",
            "version-token",
            "owner-secret",
            "owner-uri-secret",
            "support-uri-secret",
            "security-secret",
            str(workspace),
        ):
            assert forbidden not in copied_text, f"maintenance input copy leaked {forbidden}"
            assert forbidden not in warning_text, f"maintenance warning leaked {forbidden}"


def run_self_test() -> None:
    assert_safe_copy_tree_rejects_symlink()
    assert_safe_copy_tree_rejects_symlinked_root()
    assert_redaction_rejects_release_output_symlink()
    assert_tarball_redaction_rejects_symlink_member()
    assert_blank_review_policy_env_uses_defaults()
    assert_fixture_signing_profile_ignores_ambient_env()
    assert_dirty_production_beta_is_non_promotable()
    assert_emergency_build_skip_is_non_promotable()
    assert_allow_test_signing_env_profile_is_non_release()
    assert_failed_final_summary_clears_promotion_ready()
    assert_waived_critical_evidence_is_accepted_without_redaction_findings()
    assert_developer_dry_run_exit_code_fails_on_recorded_failures()
    assert_certification_failure_marks_dry_run_failed()
    assert_cleanup_refuses_protected_workspace_paths()
    assert_cleanup_refuses_arbitrary_existing_directory_without_sentinel()
    assert_no_clean_refuses_arbitrary_existing_directory_without_sentinel()
    assert_no_clean_refuses_tracked_directory_before_sentinel()
    assert_cleanup_refuses_tracked_directory_even_with_sentinel()
    assert_cleanup_refuses_unknown_tracked_file_status()
    assert_cleanup_allows_default_release_output_prefix()
    assert_cleanup_allows_sentinel_directory()
    assert_strict_skip_gradle_requires_emergency_build_flag()
    assert_unknown_workspace_status_fails_strict_modes()
    assert_catalog_signature_and_timestamps_are_canonical()
    assert_reviewer_public_key_file_resolves_from_workspace()
    assert_protected_secret_file_redaction_resolves_from_workspace()
    assert_no_clean_rerun_drops_stale_dist_files()
    assert_custom_out_dir_does_not_dirty_workspace_before_check()
    assert_post_artifact_workspace_recheck_detects_mutation()
    assert_dirty_workspace_state_is_sticky_across_checks()
    assert_project_version_parser_accepts_release_build_numbers()
    assert_maintenance_policy_resolves_from_workspace()
    assert_missing_maintenance_policy_warns_in_dry_run_and_fails_strict_modes()
    assert_incomplete_maintenance_policy_warns_in_dry_run_and_fails_strict_modes()
    assert_maintenance_policy_input_copy_redacts_invalid_values()

    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-self-test-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        out_dir = workspace / "build/production-beta"
        settings = Settings(
            workspace_root=workspace,
            out_dir=out_dir,
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=120,
            clean_out_dir=True,
        )
        summary, exit_code = run_pipeline(settings)
        assert exit_code == 0, summary
        for required in (
            "inputs/release-config.json",
            "build/staged-apps/queue-manager/cryptad-app.properties",
            "build/app-bundles/queue-manager-0.0.0-test.zip",
            "catalog/first-party-catalog.properties",
            f"catalog/{CANONICAL_CATALOG_SIGNATURE}",
            f"catalog/{RELEASE_CATALOG_SIGNATURE_ALIAS}",
            "reviews/review-receipts/queue-manager-review-receipt.properties",
            "evidence/api-compatibility.json",
            "evidence/app-ui-lint.json",
            "evidence/sandbox-provider-tests.json",
            "reports/production-beta-summary.json",
            "reports/production-beta-summary.md",
            "reports/redaction-report.json",
        ):
            assert (out_dir / required).exists(), required
        assert summary["nonRelease"] is True, summary
        assert summary["signingProfile"]["kind"] == "test-fixture", summary
        assert summary["promotionReady"] is False, summary
        archive_rel = summary["artifacts"].get("distArchive")
        assert archive_rel == f"dist/crypta-production-beta-{summary['version']}.tar.gz", summary
        with tarfile.open(out_dir / archive_rel, "r:gz") as archive:
            archived_summary_file = archive.extractfile("reports/production-beta-summary.json")
            assert archived_summary_file is not None, summary
            archived_summary = json.load(archived_summary_file)
        assert archived_summary["artifacts"]["distArchive"] == archive_rel, archived_summary
        assert archived_summary["artifacts"]["checksums"] == "dist/checksums.txt", archived_summary
        assert archived_summary["redaction"]["status"] == "pass", archived_summary

    assert_redaction_fails(
        "private-insert-uri",
        lambda out_dir: write_redaction_fixture_text(out_dir / "leak.txt", "insert=USK@PRIVATE-INSERT/test\n"),
    )
    assert_redaction_fails(
        "private-insert-concrete-usk",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "leak.json",
            '{"privateInsertUri":"USK@abcdefghijklmno,qrstuvwxyz0123456789ABCDEFG/name/0"}\n',
        ),
    )
    assert_redaction_fails(
        "private-insert-concrete-ssk",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "leak.txt",
            "Insert URI: crypta:SSK@abcdefghijklmno,qrstuvwxyz0123456789ABCDEFG/name\n",
        ),
    )
    assert_redaction_allows(
        "public-usk-placeholders",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "static/index.html",
            "\n".join(
                [
                    'placeholder="crypta:USK@feed-key/feed/0/"',
                    'placeholder="USK@profile-key/profile/1/profile.json"',
                    'placeholder="USK@publisher/site/0/"',
                    'placeholder="crypta:USK@source-key/social/0/social-outbox.json"',
                    "",
                ]
            ),
        ),
    )
    assert_redaction_allows(
        "public-concrete-catalog-source",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "source.json",
            '{"catalogSource":"crypta:USK@abcdefghijklmno,qrstuvwxyz0123456789ABCDEFG/catalog/0/cryptad-app-catalog.properties"}\n',
        ),
    )
    assert_redaction_allows(
        "sdk-profile-document-code",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "static/crypta-platform.js",
            "const result = { profileDocument: profileDocumentResponse };\n",
        ),
    )
    assert_redaction_allows(
        "api-profile-document-metadata",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "evidence/api.json", '{"capability":"profile-document:experimental"}\n'
        ),
    )
    assert_redaction_fails(
        "private-key",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "key.pem",
            "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
        ),
    )
    assert_redaction_fails(
        "binary-private-der",
        lambda out_dir: write_redaction_fixture_bytes(
            out_dir / "build/staged-apps/queue-manager/app-signing-private.der",
            b"\x30\x82\x00\x01private-key-material",
        ),
    )
    assert_redaction_fails(
        "binary-private-der-zip-member",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {"keys/app-signing-private.der": b"\x30\x82\x00\x01private-key-material"},
        ),
    )
    assert_redaction_allows(
        "private-key-code-class-name",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/crypto.jar",
            {"org/example/PrivateKeyInfo.class": b"\xca\xfe\xba\xbe\x00\x00\x00\x3d"},
        ),
    )
    assert_redaction_allows(
        "compiled-class-token-constant",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {"org/example/AppTokenConstants.class": b"\xca\xfe\xba\xbe\x00CRYPTAD_APP_TOKEN=abcdefghijklmnop"},
        ),
    )
    assert_redaction_allows(
        "native-archive-member-token-bytes",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/jna.jar",
            {"native/linux-x86-64/libjnidispatch.so": b"\x7fELF\x00Authorization: Bearer abcdefghijklmnopqrstuvwxyz"},
        ),
    )
    assert_redaction_fails(
        "secret-bearing-native-archive-member-name",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/native.jar",
            {"native/app-token.so": b"\x7fELF\x00"},
        ),
    )
    assert_redaction_fails(
        "compiled-suffix-nested-archive-token",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {
                "fixtures/archive.class": test_zip_archive_bytes(
                    {"fixtures/token.txt": "CRYPTAD_APP_TOKEN=abcdefghijklmnop\n"}
                )
            },
        ),
    )
    assert_redaction_fails(
        "bearer",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "auth.txt", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n"
        ),
    )
    assert_redaction_fails(
        "app-token",
        lambda out_dir: write_redaction_fixture_text(out_dir / "token.txt", "CRYPTAD_APP_TOKEN=abc1234567890abcdef\n"),
    )
    assert_redaction_fails(
        "identifier-app-token",
        lambda out_dir: write_redaction_fixture_text(out_dir / "token.txt", "CRYPTAD_APP_TOKEN=abcdefghijklmnop\n"),
    )
    assert_redaction_allows(
        "app-token-code-expression",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "static/crypta-platform.js",
            "const browserSessionToken = sessionTokenFromBootstrap(data);\n",
        ),
    )
    assert_redaction_fails(
        "nul-bearing-app-token",
        lambda out_dir: write_redaction_fixture_bytes(
            out_dir / "resource.bin",
            "CRYPTAD_APP_TOKEN=abcdefghijklmnop\n".encode("utf-16le"),
        ),
    )
    assert_redaction_fails(
        "nul-bearing-jar-token-entry",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {"fixtures/resource.dat": "CRYPTAD_APP_TOKEN=abcdefghijklmnop\n".encode("utf-16le")},
        ),
    )
    assert_redaction_fails(
        "identifier-ci-secret",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "secret.txt", "CRYPTAD_CERT_FORM_PASSWORD=abcdefghijklmnop\n"
        ),
    )
    assert_redaction_fails(
        "form-password-field",
        lambda out_dir: write_redaction_fixture_text(out_dir / "secret.json", '{"formPassword": "hunter2-password"}\n'),
    )
    assert_redaction_fails(
        "parenthesized-form-password-field",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "secret.json", '{"formPassword": "(hunter2-password)"}\n'
        ),
    )
    assert_redaction_fails(
        "quoted-function-like-form-password-field",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "secret.json", '{"formPassword": "secret(password)"}\n'
        ),
    )
    assert_redaction_allows(
        "redacted-form-password-field",
        lambda out_dir: write_redaction_fixture_text(out_dir / "secret.json", '{"formPassword": "<redacted>"}\n'),
    )
    assert_redaction_fails(
        "parenthesized-authorization-header",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "auth.txt", "Authorization: Bearer (abcdefghijklmnopqrstuvwxyz)\n"
        ),
    )
    assert_redaction_fails(
        "json-browser-session-token",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "token.json", '{"browserSessionToken": "abc1234567890abcdef"}\n'
        ),
    )
    assert_redaction_fails(
        "json-app-process-token",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "token.json", '{"appProcessToken": "abc1234567890abcdef"}\n'
        ),
    )
    assert_redaction_fails(
        "raw-content",
        lambda out_dir: write_redaction_fixture_text(out_dir / "raw.txt", "raw fetched body: unredacted body value\n"),
    )
    assert_redaction_fails(
        "raw-app-data-value",
        lambda out_dir: write_redaction_fixture_text(out_dir / "raw.txt", "rawAppDataValue=abcdefghijklmnop\n"),
    )
    assert_redaction_fails(
        "unredacted-payload",
        lambda out_dir: write_redaction_fixture_text(out_dir / "raw.txt", "unredacted payload=abcdefghijklmnop\n"),
    )
    assert_redaction_fails(
        "appledouble",
        lambda out_dir: write_redaction_fixture_text(out_dir / "._bad", "metadata\n"),
    )
    assert_redaction_fails(
        "jar-appledouble-entry",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {"._bad": "metadata\n"},
        ),
    )
    assert_redaction_fails(
        "jar-token-entry",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {"fixtures/token.txt": "CRYPTAD_APP_TOKEN=abcdefghijklmnop\n"},
        ),
    )
    assert_redaction_fails(
        "nested-tar-gz-token-zip-member",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/app-bundles/queue-manager-0.0.0-test.zip",
            {
                "fixtures.tar.gz": test_tar_gz_archive_bytes(
                    {"fixtures/token.txt": "CRYPTAD_APP_TOKEN=abcdefghijklmnop\n"}
                )
            },
        ),
    )
    assert_redaction_fails(
        "nested-zip-token-jar-member",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {"fixtures.zip": test_zip_archive_bytes({"fixtures/token.txt": "CRYPTAD_APP_TOKEN=abcdefghijklmnop\n"})},
        ),
    )
    assert_redaction_fails(
        "direct-tar-gz-token-artifact",
        lambda out_dir: write_test_tar_gz_archive(
            out_dir / "build/app-bundles/fixtures.tar.gz",
            {"fixtures/token.txt": "CRYPTAD_APP_TOKEN=abcdefghijklmnop\n"},
        ),
    )
    assert_redaction_fails(
        "large-jar-token-entry",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {
                "static/app.js.map": (
                    "x" * (2 * 1024 * 1024 + 64) + "\nCRYPTAD_APP_TOKEN=abcdefghijklmnop\n"
                )
            },
        ),
    )
    assert_redaction_allows(
        "large-clean-jar-text-entry",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {"static/app.js.map": "x" * (2 * 1024 * 1024 + 64)},
        ),
    )
    assert_redaction_fails(
        "absolute-path",
        lambda out_dir: write_redaction_fixture_text(out_dir / "path.txt", "localPath=/home/alice/private/key.pem\n"),
    )
    assert_redaction_fails(
        "root-gradle-path",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "path.txt", "localPath=/root/.gradle/caches/modules-2/files-2.1\n"
        ),
    )
    assert_redaction_fails(
        "hostedtoolcache-path",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "path.txt", "javaHome=/opt/hostedtoolcache/Java_Temurin-Hotspot_jdk/25\n"
        ),
    )

    saved_env = {
        "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE": os.environ.get("CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE"),
        "CRYPTAD_CERT_FORM_PASSWORD": os.environ.get("CRYPTAD_CERT_FORM_PASSWORD"),
        "CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV": os.environ.get("CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV"),
        "CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE": os.environ.get("CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE"),
        "SELF_TEST_PRIVATE_INSERT_VALUE": os.environ.get("SELF_TEST_PRIVATE_INSERT_VALUE"),
    }
    try:
        os.environ["CRYPTAD_CERT_FORM_PASSWORD"] = "unit-test-live-password-9f4b6a"
        assert_redaction_fails(
            "bare-live-form-password-env-value",
            lambda out_dir: write_redaction_fixture_text(out_dir / "live.txt", "unit-test-live-password-9f4b6a\n"),
        )
        os.environ["CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV"] = "SELF_TEST_PRIVATE_INSERT_VALUE"
        os.environ["SELF_TEST_PRIVATE_INSERT_VALUE"] = "unit-test-private-insert-material-9f4b6a"
        assert_redaction_fails(
            "bare-live-private-insert-indirection-value",
            lambda out_dir: write_redaction_fixture_text(
                out_dir / "live.txt", "unit-test-private-insert-material-9f4b6a\n"
            ),
        )
        with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-private-insert-file-") as secret_temp_name:
            secret_file = Path(secret_temp_name) / "private-insert-uri.txt"
            write_redaction_fixture_text(secret_file, "unit-test-private-insert-file-material-9f4b6a\n")
            os.environ["CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE"] = str(secret_file)
            assert_redaction_fails(
                "bare-live-private-insert-file-value",
                lambda out_dir: write_redaction_fixture_text(
                    out_dir / "live.txt", "unit-test-private-insert-file-material-9f4b6a\n"
                ),
            )
        with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-private-key-file-") as secret_temp_name:
            secret_file = Path(secret_temp_name) / "app-signing-private.der"
            secret_bytes = b"\x30\x82\x01\x00unit-test-private-key-material-9f4b6a"
            write_redaction_fixture_bytes(secret_file, secret_bytes)
            os.environ["CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE"] = str(secret_file)
            secret_base64 = base64.b64encode(secret_bytes).decode("ascii")
            assert_redaction_fails(
                "private-key-file-base64-value",
                lambda out_dir: write_redaction_fixture_text(out_dir / "neutral.txt", f"{secret_base64}\n"),
            )
            assert_redaction_fails(
                "private-key-file-raw-bytes",
                lambda out_dir: write_redaction_fixture_bytes(out_dir / "neutral.bin", secret_bytes),
            )
    finally:
        for name, value in saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-artifact-uri-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        parser = build_parser()
        saved_artifact_base_uri = os.environ.pop("CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI", None)
        try:
            try:
                settings_from_args(
                    parser.parse_args(
                        [
                            "--workspace-root",
                            str(workspace),
                            "--out-dir",
                            "build/production-beta",
                            "--mode",
                            "release-candidate",
                        ]
                    )
                )
            except SystemExit as exc:
                assert "artifact-base-uri" in str(exc), exc
            else:
                raise AssertionError("release-candidate mode accepted a missing artifact base URI")
        finally:
            if saved_artifact_base_uri is None:
                os.environ.pop("CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI", None)
            else:
                os.environ["CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI"] = saved_artifact_base_uri
        try:
            settings_from_args(
                parser.parse_args(
                    [
                        "--workspace-root",
                        str(workspace),
                        "--out-dir",
                        "build/production-beta",
                        "--mode",
                        "production-beta",
                        "--artifact-base-uri",
                        "https://downloads.crypta.invalid/production-beta/self-test",
                    ]
                )
            )
        except SystemExit as exc:
            assert ".invalid" in str(exc), exc
        else:
            raise AssertionError("production-beta mode accepted a placeholder artifact base URI")
        for private_uri in (
            "https://localhost./production-beta/self-test",
            "https://127.1/production-beta/self-test",
            "https://10.1/production-beta/self-test",
            "https://10.0.0.5/production-beta/self-test",
            "https://192.168.1/production-beta/self-test",
            "https://[::ffff:127.0.0.1]/production-beta/self-test",
            "https://artifacts.localdomain/production-beta/self-test",
        ):
            try:
                settings_from_args(
                    parser.parse_args(
                        [
                            "--workspace-root",
                            str(workspace),
                            "--out-dir",
                            "build/production-beta",
                            "--mode",
                            "release-candidate",
                            "--artifact-base-uri",
                            private_uri,
                        ]
                    )
                )
            except SystemExit as exc:
                assert "public HTTPS" in str(exc), exc
            else:
                raise AssertionError(f"release-candidate mode accepted private artifact base URI {private_uri}")
        try:
            settings_from_args(
                parser.parse_args(
                    [
                        "--workspace-root",
                        str(workspace),
                        "--out-dir",
                        "build/production-beta",
                        "--mode",
                        "release-candidate",
                        "--artifact-base-uri",
                        "https://downloads.crypta.network/production-beta/self-test",
                        "--use-fixture-evidence",
                    ]
                )
            )
        except SystemExit as exc:
            assert "use-fixture-evidence" in str(exc), exc
        else:
            raise AssertionError("release-candidate mode accepted fixture evidence")

    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-rc-fixture-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="release-candidate",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=120,
            clean_out_dir=True,
        )
        summary, exit_code = run_pipeline(settings)
        assert exit_code == 1, summary
        assert summary["status"] == "fail", summary
        failed_ids = {gate["id"] for gate in summary["promotion"]["gates"] if gate["status"] == "fail"}
        assert "fixture-evidence.strict-mode" in failed_ids, failed_ids
        assert any("fixture evidence" in failure for failure in summary["failures"]), summary["failures"]

    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-prod-missing-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="production-beta",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=True,
            require_sandbox_provider_tests=True,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=True,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=120,
            clean_out_dir=True,
        )
        summary, exit_code = run_pipeline(settings)
        assert exit_code == 1, summary
        assert summary["promotionReady"] is False, summary
        failed_ids = {gate["id"] for gate in summary["promotion"]["gates"] if gate["status"] == "fail"}
        assert "live.live-network-beta.preflight" in failed_ids, failed_ids
        assert "signing.production-keys" in failed_ids, failed_ids

    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-emergency-live-skip-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="production-beta",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=True,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=True,
            emergency_skip_live_network=True,
            emergency_skip_build=True,
            allow_test_signing_in_production=True,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=120,
            clean_out_dir=True,
        )
        summary, exit_code = run_pipeline(settings)
        assert exit_code == 1, summary
        assert summary["promotionReady"] is False, summary
        failed_ids = {gate["id"] for gate in summary["promotion"]["gates"] if gate["status"] == "fail"}
        assert "live.production-beta-skip" in failed_ids, failed_ids


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        run_self_test()
        print("production beta release self-test passed")
        return 0
    settings = settings_from_args(args)
    _, exit_code = run_pipeline(settings)
    result = "pass" if exit_code == 0 else "fail"
    print(f"Production beta release {result}: <out-dir>/reports/production-beta-summary.json")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
