"""Implementation segment for the core portion of ``app_platform_smoke.py``."""

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

from cryptad_certification.engines import app_platform_docs_check

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

FIRST_PARTY_MAINTENANCE_POLICY_PATH = Path(
    "tools/release-certification/first-party-app-maintenance-policy.json"
)

FIRST_PARTY_BETA_READINESS_PATH = Path(
    "tools/release-certification/first-party-app-beta-readiness.json"
)

FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID = "first-party-app.beta-quality-pass"

FIRST_PARTY_BETA_STATIC_TEXT_EXTENSIONS = {
    ".css",
    ".htm",
    ".html",
    ".js",
    ".json",
    ".mjs",
    ".svg",
    ".txt",
    ".xml",
}

FIRST_PARTY_MAINTENANCE_REQUIRED_FIELDS = (
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

FIRST_PARTY_MAINTENANCE_POLICY_METADATA_EXPECTATIONS = {
    "channel": "stable",
    "supportStatus": "supported",
    "deprecationStatus": "none",
}

FIRST_PARTY_MAINTENANCE_OWNER = "crypta-core"

FIRST_PARTY_MAINTENANCE_OWNER_URI = "https://example.invalid/crypta/owners/core"

FIRST_PARTY_MAINTENANCE_COMMON_EXPECTATIONS = {
    "securityPolicy": "catalog-advisories",
    "deprecationPolicy": "none",
}

FIRST_PARTY_MAINTENANCE_EXPECTATIONS = {
    "queue-manager": {
        "supportLevel": "core",
        "dataSchemaPolicy": "stateless",
        "migrationPolicy": "none",
        "backupRestore": "not-applicable",
        **FIRST_PARTY_MAINTENANCE_COMMON_EXPECTATIONS,
    },
    "publisher": {
        "supportLevel": "core",
        "dataSchemaPolicy": "stateless",
        "migrationPolicy": "none",
        "backupRestore": "not-applicable",
        **FIRST_PARTY_MAINTENANCE_COMMON_EXPECTATIONS,
    },
    "site-publisher": {
        "supportLevel": "maintained",
        "dataSchemaPolicy": "stateless",
        "migrationPolicy": "none",
        "backupRestore": "not-applicable",
        **FIRST_PARTY_MAINTENANCE_COMMON_EXPECTATIONS,
    },
    "profile-publisher": {
        "supportLevel": "maintained",
        "dataSchemaPolicy": "declared",
        "migrationPolicy": "declared",
        "backupRestore": "operator-supported",
        **FIRST_PARTY_MAINTENANCE_COMMON_EXPECTATIONS,
    },
    "feed-reader": {
        "supportLevel": "maintained",
        "dataSchemaPolicy": "migratable",
        "migrationPolicy": "dry-run-required",
        "backupRestore": "export-import",
        **FIRST_PARTY_MAINTENANCE_COMMON_EXPECTATIONS,
    },
    "social-inbox": {
        "supportLevel": "local-rc",
        "dataSchemaPolicy": "declared",
        "migrationPolicy": "operator-approved",
        "backupRestore": "operator-supported",
        **FIRST_PARTY_MAINTENANCE_COMMON_EXPECTATIONS,
    },
    "trust-graph": {
        "supportLevel": "local-rc",
        "dataSchemaPolicy": "migratable",
        "migrationPolicy": "dry-run-required",
        "backupRestore": "operator-supported",
        **FIRST_PARTY_MAINTENANCE_COMMON_EXPECTATIONS,
    },
}

FIRST_PARTY_BETA_EXPECTATIONS = {
    "queue-manager": {
        "appData": "stateless",
        "backupRestore": "not-applicable",
        "exportSupported": "not-applicable",
        "importSupported": "not-applicable",
        "migrationDryRun": "not-applicable",
    },
    "publisher": {
        "appData": "stateless",
        "backupRestore": "not-applicable",
        "exportSupported": "not-applicable",
        "importSupported": "not-applicable",
        "migrationDryRun": "not-applicable",
    },
    "site-publisher": {
        "appData": "stateless",
        "backupRestore": "not-applicable",
        "exportSupported": "not-applicable",
        "importSupported": "not-applicable",
        "migrationDryRun": "not-applicable",
    },
    "profile-publisher": {
        "appData": "durable-limited",
        "backupRestore": "operator-supported",
        "exportSupported": "supported",
        "importSupported": "supported",
        "migrationDryRun": "not-applicable",
        "schemaVersion": 1,
    },
    "social-inbox": {
        "appData": "durable",
        "backupRestore": "operator-supported",
        "exportSupported": "supported",
        "importSupported": "supported",
        "migrationDryRun": "additive-not-required",
        "schemaVersion": 1,
    },
    "feed-reader": {
        "appData": "durable",
        "backupRestore": "export-import",
        "exportSupported": "supported",
        "importSupported": "supported",
        "migrationDryRun": "supported",
        "schemaVersion": 2,
        "migrationStep": "ui-state-v1-v2",
    },
    "trust-graph": {
        "appData": "durable",
        "backupRestore": "operator-supported",
        "exportSupported": "supported",
        "importSupported": "supported",
        "migrationDryRun": "supported",
        "schemaVersion": 2,
        "migrationStep": "ui-state-v1-v2",
    },
}

FIRST_PARTY_BETA_COMMON_EXPECTED_VALUES = {
    "status": "ready",
    "owner": FIRST_PARTY_MAINTENANCE_OWNER,
    "qualityLevel": "beta",
    "emptyState": "required",
    "errorState": "bounded-required",
    "retryAction": "required",
    "recoveryAction": "operator-recovery-link",
    "permissionRationale": "required",
    "supportMetadata": "required",
    "accessibility": "basic-pass",
    "uiConsistency": "design-system-pass",
    "diagnostics": "redacted-summary-only",
}

FIRST_PARTY_BETA_MANIFEST_REQUIRED_VALUES = {
    "app.beta.readiness": "ready",
    "app.beta.qualityLevel": "beta",
    "app.beta.support.owner": "crypta-core",
    "app.beta.support.diagnostics": "redacted-summary-only",
    "app.beta.ui.emptyState": "true",
    "app.beta.ui.errorState": "true",
    "app.beta.ui.retryAction": "true",
    "app.beta.ui.recoveryAction": "true",
    "app.beta.accessibility": "basic-pass",
    "app.beta.uiConsistency": "design-system-pass",
    "app.beta.diagnostics": "redacted-summary-only",
}

FIRST_PARTY_BETA_UI_MARKERS = (
    "data-first-party-beta-readiness",
    "data-beta-empty-state",
    "data-beta-error-state",
    "data-beta-retry-action",
    "data-beta-recovery-action",
    "data-beta-app-data-status",
    "data-beta-support-metadata",
    "data-beta-diagnostics-redaction",
    "data-beta-permission-rationale",
    "data-beta-accessibility-status",
    "redacted-summary-only",
)

FIRST_PARTY_BETA_COMMON_LOCAL_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->])/(?:"
    r"etc|home|Users|work|tmp|var|opt|root|srv|mnt|private|Volumes"
    r")(?:/[^\s\])},;\"']+)+"
)

FIRST_PARTY_MAINTENANCE_ENUMS = {
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

CURRENT_PLATFORM_API_CONTRACT_VERSION = 23

CURRENT_PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION = 19

PLATFORM_API_MINIMUM_DEPRECATION_WINDOW_CONTRACT_VERSIONS = 2

PLATFORM_API_MINIMUM_SCHEDULED_REMOVAL_WINDOW_CONTRACT_VERSIONS = 2

PLATFORM_API_DEPRECATION_STABILITY_VALUES = {"deprecated", "scheduled-for-removal"}

FIELD_DEPRECATED_SINCE_CONTRACT_VERSION = "deprecatedSinceContractVersion"

FIELD_REMOVAL_CONTRACT_VERSION = "removalContractVersion"

FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION = CURRENT_PLATFORM_API_CONTRACT_VERSION

NETWORK_SCALE_EVIDENCE_IDS = (
    "network-scale.app-network-budget",
    "network-scale.content-fetch-budget",
    "network-scale.subscription-budget",
    "network-scale.queue-pressure-backoff",
    "network-scale.trust-graph-import-budget",
    "network-scale.social-inbox-multi-source-soak",
    "network-scale.redaction",
)

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

LEGACY_REMOVAL_WAVE_FOUR_IDS = (
    "diagnostic",
)

LEGACY_REMOVAL_WAVE_FIVE_IDS: tuple[str, ...] = ()

LEGACY_REMOVAL_WAVE_TWO_SCOPE_EXPANSION_IDS = (
    "queue-downloads",
    "queue-uploads",
    "config",
    "statistics",
)

LEGACY_FINAL_ADMIN_REMOVED_IDS = (
    "queue-downloads",
    "queue-uploads",
    "file-insert",
    "local-file-insert",
    "friends",
    "add-friend",
    "strangers",
    "connectivity",
    "alerts",
    "config",
    "security-levels",
    "core-update",
    "statistics",
    "diagnostic",
)

LEGACY_FINAL_RETAINED_BROWSE_IDS = (
    "chat",
    "fproxy-browse-root",
    "fproxy-key-content-rendering",
)

LEGACY_FINAL_RETAINED_BROWSE_SAFETY_IDS = ("content-filter",)

LEGACY_FINAL_SUPPORT_EMERGENCY_IDS = ("diagnostic",)

LEGACY_FINAL_STARTUP_RECOVERY_IDS = (
    "security-levels",
    "first-time-wizard",
    "first-time-wizard-js",
)

LEGACY_FINAL_PENDING_GAP_IDS = (
    "alerts",
    "core-update",
    "first-time-wizard",
    "first-time-wizard-js",
    "node-to-node-message",
)

LEGACY_FINAL_RETAINED_NON_ADMIN_SUPPORT_IDS = (
    "translation",
    "help",
)

LEGACY_FINAL_INFRASTRUCTURE_IDS = (
    "web-shell",
    "platform-api",
    "app-ui",
    "static-assets",
    "directory-browser",
    "symlink-resolver",
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

PLUGIN_MIGRATION_COOKBOOK_PATH = Path("docs/legacy-plugin-migration-cookbook.md")

PLUGIN_MIGRATION_TEMPLATE_PATH = Path("docs/templates/plugin-migration-plan.md")

PLUGIN_MIGRATION_EXAMPLE_PATHS = (
    Path("docs/examples/plugin-migration/wot-like-trust-graph-app.md"),
    Path("docs/examples/plugin-migration/social-inbox-migration.md"),
    Path("docs/examples/plugin-migration/future-mail-app-pattern.md"),
    Path("docs/examples/plugin-migration/content-publisher-migration.md"),
    Path("docs/examples/plugin-migration/app-service-grant-migration.md"),
    Path("docs/examples/plugin-migration/plugin-author-submission-flow.md"),
)

PLUGIN_MIGRATION_REDACTION_FIXTURE_EXPECTATIONS = {
    "tools/release-certification/fixtures/plugin-migration-redaction-private-insert-uri.json": "private insert URI",
    "tools/release-certification/fixtures/plugin-migration-redaction-private-key.json": "private key",
    "tools/release-certification/fixtures/plugin-migration-redaction-general-credentials.json": "credential-or-path marker",
    "tools/release-certification/fixtures/plugin-migration-redaction-app-token.json": "app token",
    "tools/release-certification/fixtures/plugin-migration-redaction-browser-session-token.json": "browser session token",
    "tools/release-certification/fixtures/plugin-migration-redaction-raw-social-message.json": "raw migration artifact",
    "tools/release-certification/fixtures/plugin-migration-redaction-raw-trust-statement.json": "raw migration artifact",
    "tools/release-certification/fixtures/plugin-migration-redaction-raw-profile-feed-document.json": "raw migration artifact",
    "tools/release-certification/fixtures/plugin-migration-redaction-raw-app-data-value.json": "raw migration artifact",
    "tools/release-certification/fixtures/plugin-migration-redaction-local-path.json": "local path",
    "tools/release-certification/fixtures/plugin-migration-redaction-raw-fproxy-html.json": "raw migration artifact",
    "tools/release-certification/fixtures/plugin-migration-redaction-old-plugin-export-secrets.json": "raw migration artifact",
    "tools/release-certification/fixtures/plugin-migration-redaction-raw-artifact-separators.json": "raw migration artifact",
    "tools/release-certification/fixtures/plugin-migration-redaction-partial-redaction.json": "raw migration artifact",
    "tools/release-certification/fixtures/plugin-migration-redaction-multiline-raw-payload.json": "raw migration artifact",
    "tools/release-certification/fixtures/plugin-migration-redaction-java-file-uri.json": "local path",
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
    r"|raw[-_ ]?fetched[-_ ]?content|fetched[-_ ]?content"
    r"|raw[-_ ]?public[-_ ]?key[-_ ]?byt(?:e|es)|public[-_ ]?key[-_ ]?byt(?:e|es)"
    r"|raw[-_ ]?review[-_ ]?receipt|review[-_ ]?receipt[-_ ]?content|raw[-_ ]?receipt"
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
    r"raw[-_ ]+fetched[-_ ]+content|fetched[-_ ]+content|"
    r"raw[-_ ]+public[-_ ]+key[-_ ]+byt(?:e|es)|public[-_ ]+key[-_ ]+byt(?:e|es)|"
    r"raw[-_ ]+review[-_ ]+receipt|review[-_ ]+receipt[-_ ]+content|raw[-_ ]+receipt|"
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

PUBLIC_BETA_DOCS_EVIDENCE_IDS = tuple(
    evidence_id
    for evidence_id in app_platform_docs_check.EVIDENCE_IDS
    if evidence_id.startswith("public-beta.")
)

ECOSYSTEM_SECURITY_EVIDENCE_IDS = (
    "catalog.security-advisories",
    "catalog.version-denylist",
    "app-review.receipt-revocation",
    "app-review.reviewer-key-compromise-flow",
    "app-update.security-denylist-gates",
    "web-shell.security-advisory-trust-warnings",
    "ecosystem-security.advisory-revocation-redaction",
)

PRODUCTION_SECURITY_EVIDENCE_IDS = ("production-security.response-runbook",)

PRODUCTION_SECURITY_REQUIRED_DRILLS = (
    "vulnerable-app-version",
    "app-signing-key-compromise",
    "reviewer-key-compromise",
    "catalog-signing-key-rotation",
    "malicious-catalog-entry",
    "emergency-replacement-app",
    "support-bundle-intake-redaction",
)

PRODUCTION_SECURITY_REQUIRED_DRILL_FIELDS = (
    "id",
    "severity",
    "trigger",
    "containmentActions",
    "catalogActions",
    "reviewActions",
    "operatorActions",
    "schedulerExpectations",
    "redactionRequirements",
    "verificationEvidence",
    "releaseNotesTemplate",
)

PRODUCTION_SECURITY_ARRAY_DRILL_FIELDS = (
    "containmentActions",
    "catalogActions",
    "reviewActions",
    "operatorActions",
    "schedulerExpectations",
    "redactionRequirements",
    "verificationEvidence",
)

PRODUCTION_SECURITY_SCALAR_DRILL_FIELDS = (
    "severity",
    "trigger",
    "releaseNotesTemplate",
)

PRODUCTION_SECURITY_AUTH_SCHEME_RE = re.compile(
    r"\bbearer\s+(?!(?:token|tokens)\b)[A-Za-z0-9._~+/=-]+",
    re.IGNORECASE,
)

PRODUCTION_SECURITY_RAW_APP_DATA_RE = re.compile(
    r"\braw[-_ ]?app[-_ ]?data"
    r"(?:[-_ ]?(?:value|values|payload|payloads|record|records))?\s*[:=]\s*\S",
    re.IGNORECASE,
)

PRODUCTION_SECURITY_RAW_FETCHED_CONTENT_RE = re.compile(
    r"\braw[-_ ]?fetched[-_ ]?content\s*[:=]\s*\S",
    re.IGNORECASE,
)

PRODUCTION_SECURITY_SAFE_BOOLEAN_METADATA_SUFFIXES = (
    "available",
    "configured",
    "enabled",
    "excluded",
    "excludedfromevidence",
    "present",
    "redacted",
    "required",
    "status",
)

PRODUCTION_SECURITY_SAFE_RAW_APP_DATA_BOOLEAN_METADATA_KEYS = {
    "rawappdataavailable",
    "rawappdataconfigured",
    "rawappdataenabled",
    "rawappdataexcluded",
    "rawappdataexcludedfromevidence",
    "rawappdatapresent",
    "rawappdataredacted",
    "rawappdatarequired",
}

PRODUCTION_SECURITY_SENSITIVE_JSON_KEY_NAMES = {
    "authorization",
    "authorizationheader",
    "proxyauthorization",
    "proxyauthorizationheader",
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
    "browsersession",
    "browsersessiontoken",
    "appsession",
    "appsessiontoken",
    "appprocesstoken",
    "xcryptaappsession",
    "rawappdata",
    "rawappdatavalue",
    "rawappdatavalues",
    "rawappdatapayload",
    "rawappdatapayloads",
    "rawappdatarecord",
    "rawappdatarecords",
    "rawfetchedcontent",
    "rawfetchedbody",
    "rawpublickeybytes",
    "publickeybytes",
    "rawreviewreceipt",
    "reviewreceiptcontent",
    "rawreceipt",
    "payloadbase64",
    "cisecret",
    "cisecretvalue",
}

PRODUCTION_SECURITY_SENSITIVE_JSON_KEY_FRAGMENTS = (
    "authorization",
    "credential",
    "rawappdata",
    "privatekey",
    "browsersession",
    "appsession",
    "appprocesstoken",
    "formpassword",
    "rawfetchedcontent",
    "rawfetchedbody",
    "secret",
    "token",
)

PRODUCTION_SECURITY_SENSITIVE_JSON_KEY_SUFFIXES = (
    "token",
    "password",
    "passwd",
    "secret",
    "credential",
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

PLUGIN_MIGRATION_FILE_URI_PATH_RE = re.compile(
    r"\bfile:(?://(?P<authority>[^/\s\])},;\"']*))?"
    r"(?P<path>/[^\s\])},;\"']+|[A-Za-z]:[\\/][^\s\])},;\"']+)",
    re.IGNORECASE,
)

PLUGIN_MIGRATION_PRIVATE_INSERT_URI_RE = re.compile(
    r"\b(?:crypta:|freenet:)?(?:SSK|USK)@"
    r"(?!<|\.\.\.)"
    r"(?=[A-Za-z0-9~_-]{8})"
    r"[A-Za-z0-9~_,=-]+(?:/[^\s`'\"<>)]*)?",
    re.IGNORECASE,
)

PLUGIN_MIGRATION_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 -]*PRIVATE KEY(?: BLOCK)?-----",
    re.IGNORECASE,
)

PLUGIN_MIGRATION_TOKEN_ASSIGNMENT_RE = re.compile(
    r"\b[\"']?(?:CRYPTAD_APP_TOKEN|browserSessionToken|appProcessToken)[\"']?\s*[:=]\s*"
    r"(?![\"']?(?:<[^>]+>|\.\.\.|redacted|<redacted>|<token-redacted>)[\"']?(?:$|[\s,}\]`]))"
    r"(?:[\"'][^\"'<>\r\n]{8,}[\"']|[A-Za-z0-9._~+/=-]{8,})",
    re.IGNORECASE,
)

PLUGIN_MIGRATION_BROWSER_SESSION_TOKEN_RE = re.compile(
    r"\b[\"']?browserSessionToken[\"']?\s*[:=]\s*"
    r"(?![\"']?(?:<[^>]+>|\.\.\.|redacted|<redacted>|<token-redacted>)[\"']?(?:$|[\s,}\]`]))"
    r"(?:[\"'][^\"'<>\r\n]{8,}[\"']|[A-Za-z0-9._~+/=-]{8,})",
    re.IGNORECASE,
)

PLUGIN_MIGRATION_AUTH_HEADER_RE = re.compile(
    r"(?<![\w-])[\"']?Authorization[\"']?\s*:\s*[\"']?"
    r"(?!(?:<[^>\r\n]+>|redacted|\.\.\.)(?:[\"']?\s*(?:$|[\r\n,}\]`])))"
    r"(?:[A-Za-z][A-Za-z0-9._~-]*\s+)?[A-Za-z0-9._~+/=:,-]{8,}",
    re.IGNORECASE,
)

PLUGIN_MIGRATION_RAW_ARTIFACT_RE = re.compile(
    r"(?<![\w-])[\"']?(?:"
    r"raw[-_ ]?social[-_ ]?message|raw[-_ ]?trust[-_ ]?statement|"
    r"raw[-_ ]?profile[-_ ]?document|raw[-_ ]?feed[-_ ]?document|"
    r"raw[-_ ]?feed[-_ ]?snapshot|raw[-_ ]?app[-_ ]?data[-_ ]?value|"
    r"raw[-_ ]?legacy[-_ ]?plugin[-_ ]?state|legacy[-_ ]?plugin[-_ ]?export|"
    r"old[-_ ]?plugin[-_ ]?export|plugin[-_ ]?export[-_ ]?body|"
    r"plugin[-_ ]?export[-_ ]?payload|fproxy[-_ ]?html|"
    r"raw[-_ ]?fproxy[-_ ]?html|fproxy[-_ ]?dump|raw[-_ ]?fproxy[-_ ]?dump|"
    r"raw[-_ ]?html[-_ ]?dump|queue[-_ ]?html|plain[-_ ]?text[-_ ]?export"
    r")[\"']?\s*[:=]"
    r"(?!\s*[\"']?(?:<redacted[^>\r\n]*>|redacted|\.\.\.)[\"']?\s*(?:$|[\r\n,}\]`\\]))"
    r"\s*"
    r"(?:[{\[]|[\"'][^\"'\r\n]{4,}[\"']|[^\r\n,}]{4,})",
    re.IGNORECASE,
)

PLUGIN_MIGRATION_SAFE_URI_PLACEHOLDER_RE = re.compile(
    r"\b(?:crypta:|freenet:)?(?:CHK|SSK|USK)@(?:<[^>\r\n]+>|\.\.\.)"
    r"(?:/[^\s`'\"<>)]*)?",
    re.IGNORECASE,
)

PLUGIN_MIGRATION_COMPAT_SHIM_DECLARATION_RE = re.compile(
    r"\b(?:class|interface|enum|record)\s+"
    r"(?:WebOfTrust|WoT|Freetalk|Sone|Freemail)[A-Za-z0-9_]*"
    r"(?:Compat|Compatibility|Shim|Bridge|Adapter|Handler|Plugin)\b"
    r"|"
    r"\b(?:class|interface|enum|record)\s+"
    r"(?:Plugin|LegacyPlugin)[A-Za-z0-9_]*(?:Toadlet|Admin|Manager|Runtime)\b"
)

PLUGIN_MIGRATION_PLUGIN_ROUTE_LITERAL_RE = re.compile(
    r"[\"']/plugins(?:/[^\"'\r\n]*)?[\"']"
)

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
    "appdatabackup",
    "backuppayload",
    "rawappdata",
    "rawappdatavalue",
    "rawappdatavalues",
    "rawappdatapayload",
    "rawappdatapayloads",
    "rawappdatarecord",
    "rawappdatarecords",
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
    "fetchedcontent",
    "rawfetchedcontent",
)

SENSITIVE_PATH_KEYS = {
    "catalogscratchpath",
    "stagedbundlepath",
}

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
    if normalized in SENSITIVE_PATH_KEYS:
        return True
    if normalized.endswith(NON_SECRET_METADATA_SUFFIXES):
        return False
    if normalized in {
        "authorization",
        "authorizationheader",
        "proxyauthorization",
        "proxyauthorizationheader",
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
        "rawpublickeybytes",
        "publickeybytes",
        "rawreviewreceipt",
        "reviewreceiptcontent",
        "rawreceipt",
        "payloadbase64",
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

def compact_source_text(text: str) -> str:
    return re.sub(r"\s+", "", text)

def java_string_search_text(text: str) -> str:
    return text.replace(r"\"", '"')

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
            "apiMinimumVersion": 1,
            "apiMaximumTestedVersion": FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION,
            "apiTargetStability": "stable",
            "experimentalCapabilitiesAccepted": False,
        },
        {
            "appId": "publisher",
            "name": "Publisher",
            "stagedDir": settings.workspace_root / "apps/publisher/build/cryptad-app/publisher",
            "sourceDir": settings.workspace_root / "apps/publisher/src/staged",
            "launcher": "bin/publisher.sh",
            "permissions": {"queue.read", "queue.write", "content.insert"},
            "apiMinimumVersion": 1,
            "apiMaximumTestedVersion": FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION,
            "apiTargetStability": "stable",
            "experimentalCapabilitiesAccepted": False,
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
            "apiMaximumTestedVersion": FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION,
            "apiTargetStability": "stable",
            "experimentalCapabilitiesAccepted": False,
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
            "apiMaximumTestedVersion": FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION,
            "apiTargetStability": "experimental",
            "experimentalCapabilitiesAccepted": True,
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
            "apiMaximumTestedVersion": FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION,
            "apiTargetStability": "experimental",
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
            "apiMaximumTestedVersion": FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION,
            "apiTargetStability": "stable",
            "experimentalCapabilitiesAccepted": False,
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
            "apiMinimumVersion": 22,
            "apiMaximumTestedVersion": 22,
            "apiTargetStability": "experimental",
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
        "apiTargetStability": manifest.get("api.targetStability"),
        "experimentalCapabilitiesAccepted": manifest.get("api.experimentalCapabilitiesAccepted"),
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
    if manifest.get("api.targetStability") != spec.get("apiTargetStability"):
        errors.append("api.targetStability does not match expected first-party metadata")
    expected_experimental = "true" if spec.get("experimentalCapabilitiesAccepted") else "false"
    if manifest.get("api.experimentalCapabilitiesAccepted") != expected_experimental:
        errors.append(
            "api.experimentalCapabilitiesAccepted does not match expected first-party metadata"
        )
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
        "hello-stable": "HELLO_STABLE",
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
            and "--template hello-stable" in text["docs"]
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
