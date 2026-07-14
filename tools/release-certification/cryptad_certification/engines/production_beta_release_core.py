"""Implementation segment for the core portion of ``production_beta_release.py``."""

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

from cryptad_certification.engines import release_certification  # noqa: E402

from cryptad_certification.engines import app_platform_smoke  # noqa: E402

from cryptad_certification.engines import multi_node_beta_soak  # noqa: E402

from cryptad_certification.engines import network_scale_soak  # noqa: E402

from cryptad_certification.engines import security_response_runbook  # noqa: E402

from cryptad_certification.engines import stable_1_0_readiness  # noqa: E402

TOOL_NAME = "production-beta-release"

SCHEMA_VERSION = 1

MODES = ("developer-dry-run", "release-candidate", "production-beta")

CATALOG_CHANNELS = ("stable", "beta", "nightly", "deprecated")

OUT_DIR_SENTINEL = ".cryptad-production-beta-release-output"

PROTECTED_CLEAN_TOP_LEVELS = {".git", ".github", "apps", "docs", "tools"}

RELEASE_OUTPUT_ROOTS = (
    "inputs",
    "build",
    "catalog",
    "reviews",
    "evidence",
    "reports",
    "security-drills",
    "security",
)

GO_NO_GO_DASHBOARD_JSON = "reports/go-no-go-dashboard.json"

GO_NO_GO_DASHBOARD_MARKDOWN = "reports/go-no-go-dashboard.md"

GO_NO_GO_REDACTION_REPORT = "reports/go-no-go-redaction-report.json"

STABLE_READINESS_DIR = "reports/stable-1.0-readiness"

STABLE_READINESS_SUMMARY_JSON = f"{STABLE_READINESS_DIR}/stable-1.0-readiness-summary.json"

STABLE_READINESS_REPORT_MARKDOWN = f"{STABLE_READINESS_DIR}/stable-1.0-readiness-report.md"

STABLE_READINESS_LIMITATIONS_JSON = f"{STABLE_READINESS_DIR}/stable-1.0-known-limitations.json"

STABLE_READINESS_BLOCKERS_JSON = f"{STABLE_READINESS_DIR}/stable-1.0-blockers.json"

STABLE_READINESS_MULTI_NODE_SOAK_JSON = "evidence/stable-readiness-multi-node-beta-soak.json"

STABLE_READINESS_NETWORK_SCALE_SOAK_JSON = "evidence/stable-readiness-network-scale-soak.json"

ARTIFACT_REDACTION_FAILURE = "artifact redaction scan failed"

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

DNS_ARTIFACT_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

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

FIRST_PARTY_BETA_READINESS_FILE = Path(
    "tools/release-certification/first-party-app-beta-readiness.json"
)

FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID = "first-party-app.beta-quality-pass"

TRUST_SOCIAL_CONTENT_FORMAT_PROFILES_EVIDENCE_ID = (
    "app-platform.trust-social-content-format-profiles"
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

BETA_READINESS_FIELDS = (
    "status",
    "owner",
    "qualityLevel",
    "emptyState",
    "errorState",
    "retryAction",
    "recoveryAction",
    "appData",
    "backupRestore",
    "exportSupported",
    "importSupported",
    "migrationDryRun",
    "permissionRationale",
    "supportMetadata",
    "accessibility",
    "uiConsistency",
    "diagnostics",
    "schemaVersion",
    "migrationStep",
)

BETA_READINESS_ALLOWED_VALUES = {
    "ready",
    "crypta-core",
    "beta",
    "required",
    "bounded-required",
    "operator-recovery-link",
    "stateless",
    "durable",
    "durable-limited",
    "not-applicable",
    "operator-supported",
    "export-import",
    "supported",
    "additive-not-required",
    "basic-pass",
    "design-system-pass",
    "redacted-summary-only",
    "ui-state-v1-v2",
    1,
    2,
}

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

THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS = (
    "third-party-developer.beta-program",
    "third-party-developer.docs",
    "third-party-developer.template",
    "third-party-developer.sample-app-flow",
    "third-party-developer.submission-checklist",
    "third-party-developer.compatibility-window",
    "third-party-developer.feedback-workflow",
    "third-party-developer.plugin-author-migration",
    "third-party-developer.redaction",
)

THIRD_PARTY_INTAKE_EVIDENCE_IDS = (
    "third-party-intake.queue-schema",
    "third-party-intake.import",
    "third-party-intake.reviewer-assignment",
    "third-party-intake.pre-review-artifacts",
    "third-party-intake.review-decision",
    "third-party-intake.resubmission-flow",
    "third-party-intake.catalog-candidate-staging",
    "third-party-intake.beta-catalog-install-smoke",
    "third-party-intake.transparency-export",
    "third-party-intake.rejected-candidate-blocked",
    "third-party-intake.caution-warning",
    "third-party-intake.redaction",
)

PUBLIC_BETA_ONBOARDING_EVIDENCE_IDS = (
    "public-beta.docs-onboarding",
    "public-beta.user-guide",
    "public-beta.developer-quickstart",
    "public-beta.troubleshooting",
    "public-beta.security-reporting",
    "public-beta.limitations",
    "public-beta.links-redaction",
)

PUBLIC_BETA_SUPPORT_FEEDBACK_EVIDENCE_IDS = (
    "public-beta.support-feedback-loop",
    "public-beta.support-feedback-docs",
    "public-beta.issue-templates",
    "public-beta.triage-taxonomy",
    "public-beta.known-issues-tracker",
    "public-beta.feedback-to-backlog",
    "public-beta.release-notes-template",
    "public-beta.support-bundle-guidance",
    "public-beta.security-reporting-handoff",
    "public-beta.app-specific-feedback",
    "public-beta.catalog-incident-feedback",
    "public-beta.redaction-fixtures",
)

PUBLIC_BETA_DOCS_EVIDENCE_IDS = (
    *PUBLIC_BETA_ONBOARDING_EVIDENCE_IDS,
    *PUBLIC_BETA_SUPPORT_FEEDBACK_EVIDENCE_IDS,
)

CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS = (
    "app-platform.signed-bundles",
    "app-catalog.first-party-maintenance-policy",
    FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID,
    "catalog.smoke",
    "app-review.trusted-receipts",
    "app-review.first-party-catalog",
    "app-review.first-party-review-chain",
    *APP_STORE_SUBMISSION_EVIDENCE_IDS,
    *THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS,
    "platform-api.contract",
    "platform-api.stable-baseline",
    "platform-api.stable-breaking-change-check",
    "platform-api.compatibility-window",
    "platform-api.previous-contract-snapshot",
    "platform-api.deprecation-window-policy",
    "platform-api.experimental-graduation-policy",
    "platform-api.manifest-target-stability",
    "platform-api.first-party-stability-declarations",
    "platform-api.stable-reference-docs",
    "app-ui.lint",
    "apphost.sandbox-provider",
    TRUST_SOCIAL_CONTENT_FORMAT_PROFILES_EVIDENCE_ID,
    "app-platform.privacy-preserving-beta-diagnostics",
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
    "production-security.response-runbook",
    *PUBLIC_BETA_DOCS_EVIDENCE_IDS,
    "legacy-plugin.migration-finalization",
    "legacy-admin.removal-wave-5",
    "legacy-admin.final-admin-surface",
    "legacy-admin.browse-retained",
    "legacy-admin.emergency-fallback-retained",
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
    r"(?<![\w-])[\"']?Authorization[\"']?(?![\w-])"
    r"\s*(?::|(?<![=!<>])=(?!=))\s*[\"']?(?:Bearer|Basic|Digest)?\s*([^\s,'\"}]+)",
    re.IGNORECASE,
)

APP_TOKEN_VALUE_RE = re.compile(
    r"(?<![\w-])[\"']?(?:CRYPTAD_APP_TOKEN|browserSessionToken|appProcessToken|X-Crypta-App-Session|"
    r"app[-_ ]?token|browser[-_ ]?session[-_ ]?token)[\"']?(?![\w-])"
    r"\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?([^'\"\s,;&}]+)",
    re.IGNORECASE,
)

FORM_PASSWORD_VALUE_RE = re.compile(
    r"(?<![\w-])[\"']?(?:CRYPTAD_CERT_FORM_PASSWORD|formPassword|form[-_ ]?password|X-Crypta-Form-Password)[\"']?(?![\w-])"
    r"\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?([^'\"\s,;&}]+)",
    re.IGNORECASE,
)

RAW_BODY_VALUE_RE = re.compile(
    r"(?<![\w-])[\"']?(?:"
    r"raw[-_ ]*(?:(?:request|response|feed|fetched|social|message|profile|trust|app[-_ ]?data|backup|signature)[-_ ]*)?"
    r"(?:body|document|payload|content|value|values)"
    r"|"
    r"(?:request|response|feed|fetched|social|message|profile|trust|app[-_ ]?data|backup|signature)[-_ ]*raw[-_ ]*"
    r"(?:body|document|payload|content|value|values)"
    r"|"
    r"(?:private|unredacted)[-_ ]*"
    r"(?:(?:request|response|feed|fetched|social|message|profile|trust|app[-_ ]?data|backup|signature)[-_ ]*)?"
    r"(?:body|document|payload|content|value|values)"
    r"|payloadBase64|plainTextExport|queueHtml"
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

FILE_URI_RE = re.compile(
    r"(?<![\w^])file:(?://[^/\s\"'<>]*)?/"
    r"(?:private/tmp|var/folders|Users|home|work|workspace|tmp|mnt|Volumes|root|opt|runner|__w|srv|etc)"
    r"(?:/[^\s\"'<>),;]*)?(?=$|[\s\"'<>),;])",
    re.IGNORECASE,
)

WINDOWS_PATH_RE = re.compile(r"(?<![A-Za-z0-9_:/.\->])[A-Za-z]:[\\/][^:*?\"<>|\r\n]+")

HOST_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->])/"
    r"(?:Users|home|work|workspace|tmp|private/tmp|var/folders|var/lib|var/log|mnt|Volumes|root|opt|runner|__w|srv|etc)"
    r"(?:/[^\s\"'<>),;]+)+"
)

DEFAULT_REVIEW_POLICY_ID = "crypta-app-review-v1"

DEFAULT_REVIEW_POLICY_VERSION = "1"

FIXTURE_APP_SIGNING_KEY_ID = "crypta-production-beta-test-app"

FIXTURE_REVIEWER_KEY_ID = "crypta-production-beta-test-review"

NON_PRODUCTION_KEY_ID_RE = re.compile(
    r"(?:^|[._-])(?:test|fixture|dry[-_]?run|sample|example|dev|development|local)(?:$|[._-])",
    re.IGNORECASE,
)

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
    multi_node_soak_summary: Path | None = None
    run_multi_node_soak: bool = False
    multi_node_soak_config: Path | None = None
    require_multi_node_soak: bool = False
    multi_node_mode: str | None = None
    previous_release_certification_summary: Path | None = None
    third_party_intake_summary: Path | None = None
    require_third_party_intake: bool = False
    run_third_party_intake_sample_flow: bool = False
    security_drills_summary: Path | None = None
    generate_stable_readiness: bool = False
    require_stable_readiness: bool = False
    stable_readiness_policy: Path | None = None
    stable_known_limitations: Path | None = None
    stable_readiness_waivers: Path | None = None
    release_id: str | None = None
    interop_smoke_summary: Path | None = None
    interop_extended_summary: Path | None = None
    performance_smoke_summary: Path | None = None
    live_network_summary: Path | None = None
    network_scale_soak_summary: Path | None = None
    require_history: bool = False

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
    pipeline_stages: dict[str, dict[str, Any]] = dataclasses.field(default_factory=dict)

class ReleaseArtifactError(RuntimeError):
    """Raised when a staged release artifact source is unsafe to publish."""

PRODUCTION_BETA_REQUIRED_PIPELINE_STAGES = (
    "crypta-app-launcher-install",
    "gradle-full-build",
    "first-party-app-staging",
    "first-party-app-signing",
    "first-party-app-verification",
)

def production_build_skipped(settings: Settings) -> bool:
    return settings.mode == "production-beta" and (settings.skip_gradle or settings.skip_full_build)

def release_config_non_release(settings: Settings, profile: SigningProfile | None, state: PipelineState) -> bool:
    return (
        settings.mode == "developer-dry-run"
        or settings.allow_test_signing_in_production
        or production_build_skipped(settings)
        or (settings.mode == "production-beta" and not all_required_production_pipeline_stages_completed(state))
        or state.dirty_workspace
        or not state.workspace_status_known
        or bool(profile and profile.kind != "production")
    )

def pipeline_stage_completed(state: PipelineState, stage_id: str) -> bool:
    return state.pipeline_stages.get(stage_id, {}).get("status") == "pass"

def record_pipeline_stage(
    state: PipelineState,
    stage_id: str,
    status: str,
    summary: str,
    command: CommandResult | None = None,
) -> None:
    entry: dict[str, Any] = {
        "status": status,
        "summary": summary,
    }
    if command is not None:
        entry["command"] = command.name
        entry["exitCode"] = command.exit_code
        entry["durationMs"] = command.duration_ms
    state.pipeline_stages[stage_id] = entry

def record_gradle_stage(
    state: PipelineState,
    stage_id: str,
    result: CommandResult | None,
    summary: str,
) -> None:
    if result is None:
        record_pipeline_stage(state, stage_id, "skipped", summary)
        return
    record_pipeline_stage(state, stage_id, "pass" if result.ok() else "fail", summary, result)

def all_required_production_pipeline_stages_completed(state: PipelineState) -> bool:
    return all(pipeline_stage_completed(state, stage_id) for stage_id in PRODUCTION_BETA_REQUIRED_PIPELINE_STAGES)

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

def resolve_workspace_path_text(raw_path: str | None, workspace_root: Path | None) -> Path | None:
    resolved = resolve_workspace_input_path(raw_path or "", workspace_root)
    return resolved.resolve() if resolved is not None else None

def resolve_workspace_path_arg(path: Path | None, workspace_root: Path | None) -> Path | None:
    return resolve_workspace_path_text(str(path) if path is not None else None, workspace_root)

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def sha256_summary_digest(path: Path) -> str:
    return f"sha256:{sha256_file(path)}"

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

def key_id_looks_non_production(key_id: str) -> bool:
    normalized = key_id.strip()
    return bool(normalized and NON_PRODUCTION_KEY_ID_RE.search(normalized))

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
        elif state.settings.mode == "production-beta":
            non_production_key_ids = [
                key_id
                for key_id in (app_key_id, reviewer_key_id)
                if key_id_looks_non_production(key_id) or key_id in {FIXTURE_APP_SIGNING_KEY_ID, FIXTURE_REVIEWER_KEY_ID}
            ]
            if non_production_key_ids:
                kind = "configured"
                state.failures.append(
                    "production-beta signing and reviewer key IDs must be production key IDs; "
                    "test, fixture, dry-run, sample, local, or example key IDs are not release material."
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
    shutil.copytree(src, dst, ignore=ignore, symlinks=True, copy_function=shutil.copy)
    try:
        reject_tree_symlinks(dst, f"copied {label}")
    except ReleaseArtifactError:
        shutil.rmtree(dst)
        raise

def launcher_install_dir(settings: Settings) -> Path:
    return settings.workspace_root / "platform-devtools/build/install/crypta-app"

def clear_workspace_generated_release_outputs(state: PipelineState) -> None:
    if state.settings.mode != "production-beta" or state.settings.skip_gradle:
        return
    generated_paths = [
        launcher_install_dir(state.settings),
        state.settings.workspace_root / "build/cryptad-dist",
        *[
            state.settings.workspace_root / APP_PROJECT_DIRS[app_id] / "build/cryptad-app"
            for app_id in APP_IDS
        ],
    ]
    for path in generated_paths:
        try:
            if path.exists() and not path.is_symlink():
                shutil.rmtree(path)
            elif path.exists():
                path.unlink()
        except OSError as exc:
            state.failures.append(f"Could not remove stale generated release output {path}: {exc}")

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

def parse_int_field(value: Any, default: int, *, minimum: int = 0) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= minimum else default

def catalog_edition_seed(version: str) -> int:
    digits = "".join(character for character in version if character.isdigit())
    if digits:
        return max(1, int(digits[-9:]))
    digest = hashlib.sha256(version.encode("utf-8")).hexdigest()
    return (int(digest[:8], 16) % 900_000_000) + 1

def catalog_channel_editions(version: str) -> dict[str, int]:
    stable_edition = catalog_edition_seed(version)
    return {
        "stableChannelEdition": stable_edition,
        "betaChannelEdition": stable_edition + 1,
    }

def catalog_edition_field(catalog_channel: str) -> str:
    return "stableChannelEdition" if catalog_channel == "stable" else "betaChannelEdition"

def current_catalog_channel_and_edition(settings: Settings, version: str) -> tuple[str, int]:
    channel_metadata = read_json(settings.out_dir / "catalog/channel-metadata.json")
    if not isinstance(channel_metadata, dict):
        channel_metadata = {}
    editions = catalog_channel_editions(version)
    edition_field = catalog_edition_field(settings.catalog_channel)
    return (
        settings.catalog_channel,
        parse_int_field(
            channel_metadata.get(edition_field),
            editions[edition_field],
            minimum=0,
        ),
    )

def normalized_sha256_digest(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip().lower()
    if re.fullmatch(r"sha256:[0-9a-f]{64}", stripped):
        return stripped
    if re.fullmatch(r"[0-9a-f]{64}", stripped):
        return f"sha256:{stripped}"
    return None

def digest_for_existing_path(path: Path) -> str:
    if path.is_file():
        return sha256_summary_digest(path)
    return "missing"

def app_manifest_path(settings: Settings, app_id: str) -> Path:
    return settings.out_dir / "build/staged-apps" / app_id / "cryptad-app.properties"

def app_manifest(settings: Settings, app_id: str) -> dict[str, str]:
    path = app_manifest_path(settings, app_id)
    if not path.is_file():
        return {}
    try:
        return parse_properties(path)
    except OSError:
        return {}

def app_schema_version(
    app_id: str,
    manifest: dict[str, str],
    app_evidence: dict[str, dict[str, Any]],
) -> int:
    for key in (
        "app.data.schema.current",
        "app.data.schema.version",
        f"app.data.schema.namespace.{app_id}.current",
    ):
        if key in manifest:
            return parse_int_field(manifest.get(key), 1, minimum=0)
    migration = app_evidence.get("app-update.data-migration-contract", {})
    migration_details = (
        migration.get("details") if isinstance(migration.get("details"), dict) else {}
    )
    reference_apps = (
        migration_details.get("referenceApps") if isinstance(migration_details, dict) else None
    )
    app_details = reference_apps.get(app_id) if isinstance(reference_apps, dict) else None
    if isinstance(app_details, dict) and "schema" in app_details:
        return parse_int_field(app_details.get("schema"), 1, minimum=0)
    social_threading = app_evidence.get("reference-app.social-inbox-rc-threading", {})
    social_details = (
        social_threading.get("details")
        if isinstance(social_threading.get("details"), dict)
        else {}
    )
    if app_id == "social-inbox" and "schemaVersion" in social_details:
        return parse_int_field(social_details.get("schemaVersion"), 1, minimum=0)
    return 1

def app_migration_from_schema(app_id: str, manifest: dict[str, str], to_schema: int) -> int:
    migrations = [
        item.strip()
        for item in manifest.get("app.data.migrations", "").split(",")
        if item.strip()
    ]
    for migration_id in migrations:
        migration_prefix = f"app.data.migration.{migration_id}."
        migration_to = parse_int_field(manifest.get(f"{migration_prefix}to"), -1, minimum=0)
        if migration_to == to_schema:
            return parse_int_field(
                manifest.get(f"{migration_prefix}from"),
                max(0, to_schema - 1),
                minimum=0,
            )
    return to_schema

def app_bundle_digest(
    settings: Settings,
    app_id: str,
    app_summary: dict[str, Any],
    version: str,
) -> str:
    digest = normalized_sha256_digest(app_summary.get("sha256"))
    artifact = app_summary.get("artifact")
    if isinstance(artifact, str) and artifact.strip():
        artifact_path = settings.out_dir / artifact
        if artifact_path.is_file():
            return sha256_summary_digest(artifact_path)
    bundle_path = settings.out_dir / "build/app-bundles" / f"{app_id}-{version}.zip"
    if bundle_path.is_file():
        return sha256_summary_digest(bundle_path)
    if digest is not None:
        return digest
    return "missing"

def app_migration_contract_digest(settings: Settings, app_id: str, manifest: dict[str, str]) -> str:
    path = app_manifest_path(settings, app_id)
    if path.is_file():
        return sha256_summary_digest(path)
    return "missing"

def evidence_status(app_evidence: dict[str, dict[str, Any]], *evidence_ids: str) -> str:
    for evidence_id in evidence_ids:
        item = app_evidence.get(evidence_id)
        if isinstance(item, dict):
            status = str(item.get("status", "missing")).strip().lower()
            if status in {"pass", "success"}:
                return "pass"
            if status and status != "missing":
                return status
    return "missing"

def content_format_risk_summary(app_evidence: dict[str, dict[str, Any]]) -> dict[str, Any]:
    item = app_evidence.get(TRUST_SOCIAL_CONTENT_FORMAT_PROFILES_EVIDENCE_ID, {})
    details = item.get("details") if isinstance(item.get("details"), dict) else {}
    profiles_value = details.get("profiles")
    if isinstance(profiles_value, dict):
        profile_ids = sorted(str(profile_id) for profile_id in profiles_value)
    elif isinstance(profiles_value, list):
        profile_ids = sorted(str(profile_id) for profile_id in profiles_value)
    else:
        profile_ids = []
    checks = details.get("checks") if isinstance(details.get("checks"), dict) else {}
    redaction = details.get("redaction") if isinstance(details.get("redaction"), dict) else {}
    status = evidence_status(app_evidence, TRUST_SOCIAL_CONTENT_FORMAT_PROFILES_EVIDENCE_ID)
    failed_checks = [
        str(name)
        for name, passed in sorted(checks.items())
        if passed is not True
    ]
    return {
        "evidenceId": TRUST_SOCIAL_CONTENT_FORMAT_PROFILES_EVIDENCE_ID,
        "status": status,
        "severity": "info" if status == "pass" and not failed_checks else "blocker",
        "profileIds": profile_ids,
        "failedChecks": failed_checks,
        "rawContentIncluded": False,
        "rawSignaturesIncluded": False,
        "rawAppDataIncluded": False,
        "privateMaterialIncluded": False,
        "redaction": {
            "rawFetchedContentExcluded": redaction.get("rawFetchedContentExcluded") is True,
            "rawSocialMessageBodiesExcluded": (
                redaction.get("rawMessageBodiesExcluded") is True
                or redaction.get("rawSocialMessageBodiesExcluded") is True
            ),
            "rawTrustStatementBodiesExcluded": (
                redaction.get("rawTrustStatementsExcluded") is True
                or redaction.get("rawTrustStatementBodiesExcluded") is True
            ),
            "rawSignaturesExcluded": redaction.get("rawSignaturesExcluded") is True,
        },
    }

def previous_candidate_metadata_for_release(
    state: PipelineState,
    redaction_report: dict[str, Any],
) -> dict[str, Any]:
    settings = state.settings
    channel_metadata = read_json(settings.out_dir / "catalog/channel-metadata.json") or {}
    app_platform_summary = read_json(settings.out_dir / "evidence/app-platform-smoke.json") or {}
    app_evidence = evidence_by_id(app_platform_summary)
    channel_apps = {
        str(entry.get("appId")): entry
        for entry in channel_metadata.get("apps", [])
        if isinstance(entry, dict) and entry.get("appId")
    }
    editions = catalog_channel_editions(state.version)
    platform_contract = app_evidence.get("platform-api.contract", {})
    platform_details = (
        platform_contract.get("details")
        if isinstance(platform_contract.get("details"), dict)
        else {}
    )
    stable_baseline = (
        platform_details.get("stableBaseline")
        if isinstance(platform_details.get("stableBaseline"), dict)
        else {}
    )
    compatibility_window = (
        platform_details.get("compatibilityWindow")
        if isinstance(platform_details.get("compatibilityWindow"), dict)
        else {}
    )
    first_party_apps: list[dict[str, Any]] = []
    schemas: dict[str, int] = {}
    for app_id in multi_node_beta_soak.PREVIOUS_CANDIDATE_REQUIRED_APPS:
        manifest = app_manifest(settings, app_id)
        app_summary = channel_apps.get(app_id, {})
        version = str(
            app_summary.get("version")
            or manifest.get("app.version")
            or state.version
        )
        schema_version = app_schema_version(app_id, manifest, app_evidence)
        schemas[app_id] = schema_version
        app_version = app_summary.get("version") or manifest.get("app.version")
        first_party_apps.append(
            {
                "appId": app_id,
                "version": str(app_version or ""),
                "channel": str(
                    app_summary.get("channel")
                    or channel_metadata.get("channel")
                    or settings.catalog_channel
                ),
                "bundleDigest": app_bundle_digest(settings, app_id, app_summary, version),
                "dataSchemaVersion": schema_version,
                "migrationContractDigest": app_migration_contract_digest(settings, app_id, manifest),
                "backupSupported": True,
                "rollbackSupported": True,
            }
        )

    migration_status = evidence_status(app_evidence, "app-update.data-migration-contract")
    catalog_health_status = evidence_status(app_evidence, "operator-beta.catalog-health")
    backup_restore_status = evidence_status(
        app_evidence,
        "app-data.backup-restore-portability",
        "operator-beta.app-data-backup-restore",
    )
    social_status = evidence_status(
        app_evidence,
        "reference-app.social-inbox-rc-threading",
        "reference-app.social-inbox-app-data",
    )
    trust_status = evidence_status(
        app_evidence,
        "app-platform.trust-graph-durable-store",
        "reference-app.trust-graph-app-data-preview",
    )
    migration_status_by_app = {
        "feed-reader": migration_status,
        "social-inbox": social_status,
        "trust-graph": trust_status,
    }
    migration_coverage: list[dict[str, Any]] = []
    for app_id in multi_node_beta_soak.PREVIOUS_CANDIDATE_MIGRATION_APPS:
        manifest = app_manifest(settings, app_id)
        to_schema = schemas.get(app_id, app_schema_version(app_id, manifest, app_evidence))
        migration_coverage.append(
            {
                "appId": app_id,
                "fromSchema": app_migration_from_schema(app_id, manifest, to_schema),
                "toSchema": to_schema,
                "status": migration_status_by_app.get(app_id, "missing"),
                "backupBeforeUpdate": backup_restore_status == "pass",
                "rawAppDataIncluded": False,
            }
        )

    catalog = {
        "stableChannelEdition": parse_int_field(
            channel_metadata.get("stableChannelEdition"),
            editions["stableChannelEdition"],
            minimum=0,
        ),
        "betaChannelEdition": parse_int_field(
            channel_metadata.get("betaChannelEdition"),
            editions["betaChannelEdition"],
            minimum=0,
        ),
        "catalogDigest": digest_for_existing_path(
            settings.out_dir / "catalog/first-party-catalog.properties"
        ),
        "catalogSigningKeyId": str(
            channel_metadata.get("catalogSigningKeyId")
            or (state.signing_profile.app_key_id if state.signing_profile else "")
            or channel_metadata.get("signingProfile")
            or ""
        ),
        "mirrorHealthStatus": catalog_health_status,
    }
    platform_api = {
        "stableBaseline": str(stable_baseline.get("name") or "1.0"),
        "contractVersion": parse_int_field(
            platform_details.get("contractVersion"),
            1,
            minimum=1,
        ),
        "compatibilityWindow": compatibility_window,
        "snapshotDigest": digest_for_existing_path(
            settings.out_dir / "evidence/app-platform-smoke.json"
        ),
    }
    social_schema = schemas.get("social-inbox", 1)
    trust_schema = schemas.get("trust-graph", 1)
    redaction_status = str(redaction_report.get("status", "missing")).strip().lower()
    content_format_risk = content_format_risk_summary(app_evidence)
    return {
        "catalog": catalog,
        "platformApi": platform_api,
        "firstPartyApps": first_party_apps,
        "appData": {
            "backupManifestDigest": digest_for_existing_path(
                settings.out_dir / "evidence/app-platform-smoke.json"
            ),
            "restoreDrillStatus": backup_restore_status,
            "migrationCoverage": migration_coverage,
            "rawValuesIncluded": False,
        },
        "trustGraph": {
            "storeSchemaVersion": trust_schema,
            "anchorCount": 0,
            "statementCount": 0,
            "stateDigest": multi_node_beta_soak.synthetic_full_digest(
                "trust-graph-state",
                state.version,
                app_evidence.get("app-platform.trust-graph-durable-store", {}),
                app_evidence.get("reference-app.trust-graph-app-data-preview", {}),
            ),
            "rawStatementsIncluded": False,
        },
        "socialInbox": {
            "schemaVersion": social_schema,
            "threadCount": 0,
            "sourceCount": 0,
            "stateDigest": multi_node_beta_soak.synthetic_full_digest(
                "social-inbox-state",
                state.version,
                app_evidence.get("reference-app.social-inbox-rc-threading", {}),
                app_evidence.get("reference-app.social-inbox-app-data", {}),
            ),
            "rawMessageBodiesIncluded": False,
        },
        "supportBundle": {
            "formatVersion": 1,
            "redactionStatus": redaction_status,
            "digest": multi_node_beta_soak.synthetic_full_digest(
                "support-bundle-redaction",
                state.version,
                redaction_report,
            ),
        },
        "redaction": {
            "status": redaction_status,
            "findings": [],
        },
        "contentFormatProfiles": content_format_risk,
    }

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

def first_party_beta_readiness_file(state: PipelineState) -> Path:
    return state.settings.workspace_root / FIRST_PARTY_BETA_READINESS_FILE

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

def sanitized_beta_readiness_value(value: Any) -> Any:
    if isinstance(value, bool):
        return "<redacted>"
    if isinstance(value, int) and value in BETA_READINESS_ALLOWED_VALUES:
        return value
    if isinstance(value, str) and value in BETA_READINESS_ALLOWED_VALUES:
        return value
    stripped = safe_single_line(value)
    return stripped if stripped in BETA_READINESS_ALLOWED_VALUES else "<redacted>"

def sanitized_first_party_beta_readiness_input(raw_readiness: Any) -> dict[str, Any]:
    raw_apps = raw_readiness.get("apps") if isinstance(raw_readiness, dict) else None
    sanitized: dict[str, Any] = {
        "schemaVersion": (
            1
            if isinstance(raw_readiness, dict) and raw_readiness.get("schemaVersion") == 1
            else "<redacted>"
        ),
        "evidenceId": (
            FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID
            if isinstance(raw_readiness, dict)
            and raw_readiness.get("evidenceId") == FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID
            else "<redacted>"
        ),
        "apps": {},
    }
    if not isinstance(raw_apps, dict):
        return sanitized
    sanitized_apps = sanitized["apps"]
    for app_id in APP_IDS:
        app_readiness = raw_apps.get(app_id)
        beta = (
            app_readiness.get("betaReadiness")
            if isinstance(app_readiness, dict)
            else None
        )
        if not isinstance(beta, dict):
            continue
        sanitized_apps[app_id] = {
            "betaReadiness": {
                field: sanitized_beta_readiness_value(beta.get(field))
                for field in BETA_READINESS_FIELDS
                if field in beta
            }
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

def copy_first_party_beta_readiness_input(state: PipelineState) -> None:
    readiness_file = first_party_beta_readiness_file(state)
    if not readiness_file.is_file():
        return
    try:
        with readiness_file.open("r", encoding="utf-8") as handle:
            raw_readiness = json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return
    target = state.settings.out_dir / "inputs/first-party-app-beta-readiness.json"
    write_json(target, sanitized_first_party_beta_readiness_input(raw_readiness))

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
        shutil.copy(working_catalog, catalog_dir / "first-party-catalog.properties")
    if signature.is_file():
        shutil.copy(signature, catalog_dir / CANONICAL_CATALOG_SIGNATURE)
        shutil.copy(signature, catalog_dir / RELEASE_CATALOG_SIGNATURE_ALIAS)
    write_json(
        catalog_dir / "channel-metadata.json",
        {
            "schemaVersion": 1,
            "catalogId": "crypta-first-party-production-beta",
            "channel": state.settings.catalog_channel,
            "defaultAutomationChannel": "stable",
            "nonProduction": profile.kind != "production",
            "signingProfile": profile.kind,
            "catalogSigningKeyId": profile.app_key_id,
            **catalog_channel_editions(state.version),
            "artifactBaseUri": state.settings.artifact_base_uri,
            "firstPartyMaintenancePolicy": "inputs/first-party-app-maintenance-policy.json",
            "firstPartyBetaReadiness": "inputs/first-party-app-beta-readiness.json",
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
    app_summaries: list[dict[str, Any]] = []
    for app_id in APP_IDS:
        app_version = "0.0.0-test"
        schema_version = "2" if app_id in {"feed-reader", "trust-graph"} else "1"
        staged = staged_root / app_id
        write_text(
            staged / "cryptad-app.properties",
            "\n".join(
                [
                    f"app.id={app_id}",
                    f"app.name={app_id}",
                    f"app.version={app_version}",
                    "app.permissions=queue.read",
                    "app.ui.mode=static",
                    "app.ui.entry=static/index.html",
                    f"app.data.schema.current={schema_version}",
                    "signature.test-mode=true",
                    "",
                ]
            ),
        )
        write_text(staged / "static/index.html", "<!doctype html><title>fixture</title>\n")
        write_text(staged / "cryptad-app.digests", "digest.version=1\n")
        write_text(staged / "cryptad-app.signature", "signature.test-mode=true\n")
        zip_path = bundle_root / f"{app_id}-{app_version}.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(staged / "cryptad-app.properties", "cryptad-app.properties")
            archive.write(staged / "static/index.html", "static/index.html")
        write_text(
            review_root / f"{app_id}-review-receipt.properties",
            f"review.receipt.app.id={app_id}\nreview.receipt.status=reviewed\n",
        )
        app_summaries.append(
            {
                "appId": app_id,
                "version": app_version,
                "artifact": relative_artifact_path(zip_path, state.settings.out_dir),
                "sha256": sha256_file(zip_path),
                "sizeBytes": zip_path.stat().st_size,
                "channel": state.settings.catalog_channel,
                "supportStatus": policy_value(
                    maintenance_policies.get(app_id, {}), "supportStatus", "supported"
                ),
                "deprecationStatus": policy_value(
                    maintenance_policies.get(app_id, {}), "deprecationStatus", "none"
                ),
                "maintenance": maintenance_summary(maintenance_policies.get(app_id, {})),
                "nonProduction": True,
            }
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
            "catalogSigningKeyId": "test-fixture-app-key",
            **catalog_channel_editions(state.version),
            "firstPartyMaintenancePolicy": "inputs/first-party-app-maintenance-policy.json",
            "firstPartyBetaReadiness": "inputs/first-party-app-beta-readiness.json",
            "requiredMaintenanceApps": list(APP_IDS),
            "maintenancePolicyComplete": len(maintenance_policies) == len(APP_IDS),
            "apps": app_summaries,
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
        "requireMultiNodeSoak": settings.require_multi_node_soak,
        "runMultiNodeSoak": settings.run_multi_node_soak,
        "multiNodeMode": settings.multi_node_mode or "config",
        "generateStableReadiness": settings.generate_stable_readiness,
        "requireStableReadiness": settings.require_stable_readiness,
        "skipGradle": settings.skip_gradle,
        "skipFullBuild": settings.skip_full_build,
        "useFixtureEvidence": settings.use_fixture_evidence,
        "workspaceStatusKnown": state.workspace_status_known,
        "dirtyWorkspace": state.dirty_workspace,
        "nonRelease": release_config_non_release(settings, profile, state),
        "pipelineStages": state.pipeline_stages,
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
