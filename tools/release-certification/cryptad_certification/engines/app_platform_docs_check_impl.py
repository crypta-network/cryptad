#!/usr/bin/env python3
"""Check app-platform beta docs, links, templates, and redaction rules."""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse


SCHEMA_VERSION = 1
TOOL_NAME = "app-platform-docs-check"
EVIDENCE_IDS = (
    "app-platform.docs-portal",
    "app-platform.beta-program",
    "app-platform.beta-tutorials",
    "app-platform.docs-redaction",
    "public-beta.docs-onboarding",
    "public-beta.user-guide",
    "public-beta.developer-quickstart",
    "public-beta.troubleshooting",
    "public-beta.security-reporting",
    "public-beta.limitations",
    "public-beta.links-redaction",
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

REQUIRED_DOCS = (
    "docs/app-platform-developer-portal.md",
    "docs/app-platform-beta-tutorials.md",
    "docs/app-platform-beta-known-limitations.md",
    "docs/app-platform-beta-program.md",
    "docs/developer-beta-toolkit.md",
    "docs/third-party-developer-beta-program.md",
    "docs/third-party-app-submission-checklist.md",
    "docs/platform-api-compatibility-support-window.md",
    "docs/examples/third-party-hello-stable.md",
    "docs/app-catalogs.md",
    "docs/catalog-operations-and-mirrors.md",
    "docs/app-dev-cli.md",
    "docs/platform-api-contract.md",
    "docs/platform-api-1.0-stable-reference.md",
    "docs/platform-api-surface.md",
    "docs/app-service-discovery-and-grants.md",
    "docs/platform-sdk-js.md",
    "docs/app-permissions-and-audit.md",
    "docs/app-secret-and-identity-vault.md",
    "docs/app-review-governance.md",
    "docs/app-store-submission-and-review-workflow.md",
    "docs/user-consent-and-permission-upgrade-ux.md",
    "docs/app-update-lifecycle.md",
    "docs/app-data-backup-restore-portability.md",
    "docs/first-party-beta-catalog.md",
    "docs/first-party-app-beta-quality-pass.md",
    "docs/production-first-party-catalog-channels.md",
    "docs/production-beta-release-pipeline.md",
    "docs/multi-node-beta-soak-and-upgrade-drill.md",
    "docs/privacy-preserving-beta-diagnostics.md",
    "docs/feed-reader-reference-app.md",
    "docs/social-inbox-reference-app.md",
    "docs/trust-graph-preview.md",
    "docs/legacy-plugin-migration-guide.md",
    "docs/legacy-plugin-migration-cookbook.md",
    "docs/release-certification.md",
    "docs/SECURITY.md",
)

PLUGIN_MIGRATION_DOCS = (
    "docs/legacy-plugin-migration-cookbook.md",
    "docs/templates/plugin-migration-plan.md",
    "docs/examples/plugin-migration/wot-like-trust-graph-app.md",
    "docs/examples/plugin-migration/social-inbox-migration.md",
    "docs/examples/plugin-migration/future-mail-app-pattern.md",
    "docs/examples/plugin-migration/content-publisher-migration.md",
    "docs/examples/plugin-migration/app-service-grant-migration.md",
    "docs/examples/plugin-migration/plugin-author-submission-flow.md",
)

NEW_DOCS = (
    "docs/app-platform-developer-portal.md",
    "docs/app-platform-beta-tutorials.md",
    "docs/app-platform-beta-known-limitations.md",
    "docs/app-platform-beta-program.md",
)

ISSUE_TEMPLATES = (
    ".github/ISSUE_TEMPLATE/app-platform-beta-feedback.yml",
    ".github/ISSUE_TEMPLATE/app-specific-feedback.yml",
    ".github/ISSUE_TEMPLATE/app-update-rollback.yml",
    ".github/ISSUE_TEMPLATE/app-submission-beta.yml",
    ".github/ISSUE_TEMPLATE/developer-beta-feedback.yml",
    ".github/ISSUE_TEMPLATE/app-review-appeal.yml",
    ".github/ISSUE_TEMPLATE/catalog-incident.yml",
    ".github/ISSUE_TEMPLATE/platform-api-compatibility.yml",
    ".github/ISSUE_TEMPLATE/plugin-migration-feedback.yml",
    ".github/ISSUE_TEMPLATE/public-beta-support.yml",
    ".github/ISSUE_TEMPLATE/security-advisory-intake.yml",
    ".github/ISSUE_TEMPLATE/support-bundle-diagnostics.yml",
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

REQUIRED_PORTAL_LINKS = tuple(
    path for path in REQUIRED_DOCS if path != "docs/app-platform-developer-portal.md"
) + (
    "docs/public-beta/README.md",
    "docs/app-distribution.md",
    "docs/app-owned-ui.md",
    "docs/app-ui-design-system.md",
    "docs/apphost-runtime-hardening.md",
    "docs/legacy-http-boundary.md",
    "docs/legacy-retirement-plan.md",
)

REQUIRED_CONCEPTS = (
    "crypta-app init",
    "crypta-app dev",
    "crypta-app test",
    "crypta-app keys generate",
    "crypta-app sign",
    "crypta-app verify",
    "crypta-app pack",
    "crypta-app catalog entry",
    "crypta-app catalog create",
    "crypta-app catalog sign",
    "crypta-app catalog verify",
    "crypta-app api policy",
    "crypta-app api diff",
    "crypta-app submission create",
    "crypta-app submission verify",
    "crypta-app submission pre-review",
    "crypta-app submission decide",
    "crypta-app submission catalog-candidate",
    "crypta-app publish-usk",
    "hello-stable",
    "api.targetStability=stable",
    "api.experimentalCapabilitiesAccepted=false",
    "platform.contract.read",
    "third-party-developer.sample-app-flow",
    "content.fetch",
    "content.subscribe",
    "content.insert.app-document",
    "crypta.social.message.v1",
    "social/mail-like",
    "vault.identities.create",
    "vault.identities.use",
    "trust.read",
    "trust.write",
    "app.services.read",
    "app.services.call",
    "app-services.registry",
    "review receipt",
    "caution",
    "rejected",
    "resubmission",
    "reviewer key lifecycle",
    "transparency log",
    "background update scheduler",
    "production catalog channels",
    "network-content.subscription-scheduler",
    "rollback",
    "ecosystem certification matrix",
    "platform-api.compatibility-window",
    "platform-api.previous-contract-snapshot",
    "platform-api.deprecation-window-policy",
    "platform-api.experimental-graduation-policy",
    "FProxy browse remains retained",
)

PUBLIC_BETA_DOCS = (
    "docs/public-beta/README.md",
    "docs/public-beta/user-guide.md",
    "docs/public-beta/install-update-rollback.md",
    "docs/public-beta/catalogs-and-apps.md",
    "docs/public-beta/permissions-and-consent.md",
    "docs/public-beta/trust-social-limitations.md",
    "docs/public-beta/developer-quickstart.md",
    "docs/public-beta/app-submission-walkthrough.md",
    "docs/public-beta/troubleshooting.md",
    "docs/public-beta/security-reporting.md",
    "docs/public-beta/legacy-plugin-authors.md",
    "docs/public-beta/support-and-feedback.md",
    "docs/public-beta/triage-taxonomy.md",
    "docs/public-beta/known-issues.md",
    "docs/public-beta/feedback-to-backlog.md",
)

PUBLIC_BETA_SUPPORT_FEEDBACK_DOCS = (
    "docs/public-beta/support-and-feedback.md",
    "docs/public-beta/triage-taxonomy.md",
    "docs/public-beta/known-issues.md",
    "docs/public-beta/feedback-to-backlog.md",
    "docs/templates/beta-release-notes.md",
    "tools/release-certification/public-beta-known-issues.json",
)

PUBLIC_BETA_RELEASE_NOTES_TEMPLATE = "docs/templates/beta-release-notes.md"
PUBLIC_BETA_KNOWN_ISSUES_METADATA = (
    "tools/release-certification/public-beta-known-issues.json"
)
PUBLIC_BETA_SAFE_FEEDBACK_FIXTURE = (
    "tools/release-certification/fixtures/public-beta-feedback-safe-examples.json"
)
PUBLIC_BETA_NEGATIVE_FEEDBACK_FIXTURES = (
    "tools/release-certification/fixtures/public-beta-feedback-redaction-private-insert-uri.json",
    "tools/release-certification/fixtures/public-beta-feedback-redaction-private-key.json",
    "tools/release-certification/fixtures/public-beta-feedback-redaction-app-token.json",
    "tools/release-certification/fixtures/public-beta-feedback-redaction-browser-session-token.json",
    "tools/release-certification/fixtures/public-beta-feedback-redaction-authorization-header.json",
    "tools/release-certification/fixtures/public-beta-feedback-redaction-cookie.json",
    "tools/release-certification/fixtures/public-beta-feedback-redaction-raw-feed.json",
    "tools/release-certification/fixtures/public-beta-feedback-redaction-raw-profile.json",
    "tools/release-certification/fixtures/public-beta-feedback-redaction-raw-trust.json",
    "tools/release-certification/fixtures/public-beta-feedback-redaction-raw-social.json",
    "tools/release-certification/fixtures/public-beta-feedback-redaction-raw-app-data.json",
    "tools/release-certification/fixtures/public-beta-feedback-redaction-local-path.json",
    "tools/release-certification/fixtures/public-beta-feedback-redaction-nested-backup.json",
)

PUBLIC_BETA_SUPPORT_FEEDBACK_CONCEPTS = (
    "observe the issue",
    "collect a privacy-preserving diagnostic summary",
    "export a support bundle locally",
    "file the most specific structured issue form",
    "Maintainers run the redaction check",
    "known issue",
    "backlog candidate",
    "beta release notes template",
    "next beta candidate verifies",
    "support_bundle_digest",
    "support_bundle_schema_version",
    "diagnostic_summary_id",
    "consent_audit_event_id",
    "operator_recovery_action_id",
    "known_issue_id",
    "private insert URI",
    "private keys",
    "browser session tokens",
    "raw fetched content",
    "raw app data values",
    "absolute local paths",
)

PUBLIC_BETA_TRIAGE_LABELS = (
    "area/catalog",
    "area/app-update",
    "area/app-data",
    "area/app-service-grants",
    "area/trust-graph",
    "area/social-inbox",
    "area/feed-reader",
    "area/profile-publisher",
    "area/platform-api",
    "area/third-party-review",
    "area/security-advisory",
    "area/legacy-plugin-migration",
    "area/docs",
    "area/support-bundle",
    "severity/blocker",
    "severity/high",
    "severity/medium",
    "severity/low",
    "status/needs-redaction",
    "status/needs-repro",
    "status/known-issue",
    "status/backlog-candidate",
    "status/fixed-next-beta",
    "status/waiver-requested",
    "privacy/redaction-required",
    "privacy/redaction-passed",
)

KNOWN_ISSUE_FIELDS = (
    "knownIssueId",
    "status",
    "severity",
    "area",
    "affectedChannels",
    "affectedAppIds",
    "affectedVersions",
    "firstSeenReleaseId",
    "fixedInReleaseId",
    "workaroundSummary",
    "supportBundleEvidenceAllowed",
    "redactionNotes",
    "backlogLinkOrPlaceholder",
)

BETA_RELEASE_NOTES_SECTIONS = (
    "Release ID",
    "Catalog channels",
    "Supported upgrade path",
    "Known issues",
    "Fixed issues",
    "Security advisories",
    "App compatibility notes",
    "Platform API compatibility notes",
    "First-party app changes",
    "Third-party app intake notes",
    "Legacy plugin migration notes",
    "Support bundle and diagnostics changes",
    "Operator recovery notes",
    "Go/no-go summary",
    "Waivers",
    "Redaction confirmation",
)

COMMON_FEEDBACK_FIELD_IDS = (
    "release_id",
    "cryptad_version",
    "support_bundle_digest",
    "diagnostic_summary_id",
    "known_issue_id",
    "severity",
    "impact",
    "reproduction_steps",
    "expected_behavior",
    "actual_behavior",
    "redacted_evidence",
)

ISSUE_TEMPLATE_REQUIRED_FIELDS = {
    ".github/ISSUE_TEMPLATE/public-beta-support.yml": (
        *COMMON_FEEDBACK_FIELD_IDS,
        "platform_api_contract_version",
        "catalog_channel",
        "catalog_id",
        "app_id",
        "app_version",
        "consent_audit_event_id",
        "operator_recovery_action_id",
    ),
    ".github/ISSUE_TEMPLATE/app-specific-feedback.yml": (
        *COMMON_FEEDBACK_FIELD_IDS,
        "platform_api_contract_version",
        "catalog_channel",
        "catalog_id",
        "app_id",
        "app_version",
        "operation_being_attempted",
        "support_bundle_schema_version",
        "consent_audit_event_id",
        "operator_recovery_action_id",
        "app_data_backup_status",
        "migration_status",
        "subscription_id",
        "trust_social_document_profile_id",
    ),
    ".github/ISSUE_TEMPLATE/catalog-incident.yml": (
        "release_id",
        "cryptad_version",
        "catalog_id",
        "catalog_channel",
        "catalog_source_class",
        "mirror_id",
        "catalog_revision_edition",
        "signature_verification_status",
        "health_status",
        "rollback_attempted",
        "support_bundle_digest",
        "redacted_error_code",
        "known_issue_id",
        "severity",
        "impact",
        "reproduction_steps",
        "expected_behavior",
        "actual_behavior",
        "redacted_evidence",
    ),
    ".github/ISSUE_TEMPLATE/app-update-rollback.yml": (
        *COMMON_FEEDBACK_FIELD_IDS,
        "platform_api_contract_version",
        "app_id",
        "app_version",
        "target_app_version",
        "catalog_channel",
        "update_phase",
        "rollback_result",
        "migration_status",
        "app_data_backup_status",
        "consent_audit_event_id",
        "operator_recovery_action_id",
    ),
    ".github/ISSUE_TEMPLATE/support-bundle-diagnostics.yml": (
        "release_id",
        "cryptad_version",
        "support_bundle_digest",
        "support_bundle_schema_version",
        "diagnostic_summary_id",
        "export_preview_status",
        "redaction_concern_category",
        "known_issue_id",
        "severity",
        "impact",
        "reproduction_steps",
        "expected_behavior",
        "actual_behavior",
        "redacted_evidence",
    ),
    ".github/ISSUE_TEMPLATE/security-advisory-intake.yml": (
        "advisory_type",
        "release_id",
        "cryptad_version",
        "affected_component",
        "support_bundle_digest",
        "diagnostic_summary_id",
        "known_issue_id",
        "severity",
        "public_safe_impact",
    ),
}

PUBLIC_BETA_ONBOARDING_CONCEPTS = (
    "Public beta onboarding",
    "I am a beta user/operator",
    "I am installing or updating Cryptad",
    "I am installing first-party apps",
    "I am backing up or restoring app data",
    "I am troubleshooting a problem",
    "I am reporting a security issue",
    "I am a third-party app developer",
    "I am a former plugin author",
    "I am a reviewer/release manager",
    "install and start Cryptad",
    "open Web Shell",
    "stable catalog",
    "first-party app",
    "permissions",
    "rollback",
    "app-data backup",
    "support bundle",
    "Trust Graph Local RC",
    "not global WebOfTrust",
    "Social Inbox RC",
    "not Freemail",
    "crypta-app init",
    "submission pre-review",
    "security reporting",
    "legacy plugin migration",
    "FProxy browse remains retained",
)

PUBLIC_BETA_USER_GUIDE_CONCEPTS = (
    "Install and start Cryptad",
    "Open Web Shell",
    "check node status",
    "stable catalog",
    "catalog health",
    "install a first-party app",
    "Review permissions",
    "service grants",
    "Update or rollback an app",
    "Back up or restore app data",
    "privacy-preserving support bundle",
    "Recover from common failures",
)

PUBLIC_BETA_DEVELOPER_QUICKSTART_CONCEPTS = (
    "./gradlew :platform-devtools:installDist",
    "crypta-app init",
    "--dir build/dev-apps/hello-stable",
    "--template hello-stable",
    "crypta-app dev",
    "crypta-app test",
    "crypta-app ui lint",
    "crypta-app api snapshot",
    "crypta-app api policy",
    "crypta-app compat verify",
    "crypta-app keys generate",
    "--private-key-file build/dev-keys/dev-local-private.der",
    "--public-key-file build/dev-keys/dev-local-public.der",
    "--trusted-keys-file build/dev-keys/trusted-app-keys.properties",
    "crypta-app sign",
    "crypta-app verify",
    "crypta-app pack",
    "crypta-app submission create",
    "crypta-app submission verify",
    "crypta-app submission pre-review",
    "submission verify --json",
)

PUBLIC_BETA_TROUBLESHOOTING_CONCEPTS = (
    "Cannot open Web Shell",
    "Catalog not reachable",
    "Catalog mirror unhealthy",
    "Catalog signature verification failed",
    "App install failed",
    "App update staged but not applied",
    "App rollback needed",
    "Permission delta blocks update",
    "Grant expired or revoked",
    "Subscription stuck",
    "App-data migration failed",
    "Backup restore failed",
    "Sandbox provider unavailable",
    "Security advisory blocks update",
    "Support bundle export needed",
)

PUBLIC_BETA_SECURITY_REPORTING_CONCEPTS = (
    "Report suspected vulnerabilities",
    "What not to include",
    "Advisories and denylists",
    "Support bundle redaction expectations",
    "docs/SECURITY.md",
    "private insert URIs",
    "raw support bundles",
    "security-release-notes.md",
)

PUBLIC_BETA_LIMITATION_CONCEPTS = (
    "Trust Graph Local RC",
    "local advisory trust only",
    "not global WebOfTrust",
    "not routing policy",
    "not global moderation",
    "not a crawler",
    "not legacy WoT compatibility",
    "not a daemon-core identity-sharing system",
    "not authority for apps to import or mutate trust data",
    "trust.score",
    "operator-approved app-service grants",
    "Social Inbox RC",
    "not Freemail",
    "not Freetalk/Sone compatibility",
    "not encrypted mail transport",
    "not daemon-core social store",
    "not a background crawler",
    "not a promise that old social plugins will run unchanged",
)

REDACTION_ALLOWLIST_PATH_PREFIXES = (
    "/abs/path/",
    "/api/",
    "/app-data/",
    "/app/node/",
    "/apps/",
    "/downloads/",
    "/uploads/",
    "/insertfile/",
    "/insert-browse/",
    "/friends/",
    "/addfriend/",
    "/strangers/",
    "/connectivity/",
    "/alerts/",
    "/config/",
    "/core-update/",
    "/stats/",
    "/welcome",
    "/wizard",
    "/help",
    "/chat",
    "/content",
    "/filterfile",
    "/diagnostics",
    "/docs/",
    "/.well-known/",
    "/static/",
    "/src/",
    "/app-catalogs/",
    "/operator/",
    "/platform/",
    "/queue/",
)

REDACTION_ALLOWLIST_EXACT_PATHS = (
    "/etc/systemd/system/cryptad.service",
    "/opt/cryptad",
    "/opt/cryptad/Crypta",
    "/usr/share/applications/crypta.desktop",
    "/usr/share/wayland-sessions",
    "/usr/share/xsessions",
    "/var/lib/cryptad",
    "/app/node",
)

PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 -]*PRIVATE KEY(?: BLOCK)?-----", re.IGNORECASE
)
PRIVATE_KEY_ASSIGNMENT_NAME_RE = (
    r"(?:"
    r"(?:[A-Z0-9]+_)*PRIVATE_KEY(?:_BASE64)?"
    r"|[A-Za-z0-9]*PrivateKey(?:Base64)?"
    r")"
)
PRIVATE_KEY_ASSIGNMENT_RE = re.compile(
    r"(?<![\w-])(?:-P)?[\"']?"
    + PRIVATE_KEY_ASSIGNMENT_NAME_RE
    + r"[\"']?\s*[:=]\s*"
    r"(?![\"']?(?:<[^>]+>|redacted|\.\.\.)[\"']?(?:$|[\s,}\]`\\]))"
    r"(?:[\"'][^\"'<>\r\n]{16,}[\"']|[A-Za-z0-9._~+/=-]{16,})",
    re.IGNORECASE,
)
SEED_PHRASE_RE = re.compile(
    r"\bseed phrase\s*[:=]\s*(?!<redacted>)(?:[a-z]{3,}\s+){3,}[a-z]{3,}\b",
    re.IGNORECASE,
)
AUTHORIZATION_HEADER_RE = re.compile(
    r"(?<![\w-])[\"']?Authorization[\"']?\s*:\s*[\"']?"
    r"(?!(?:<[^>\r\n]+>|redacted|\.\.\.)(?:[\"']?\s*(?:$|[\r\n,}\]`])))"
    r"(?:"
    r"[A-Za-z][A-Za-z0-9._~-]*\s+"
    r"(?!(?:<[^>\r\n]+>|redacted|\.\.\.)(?:[\"']?\s*(?:$|[\r\n,}\]`])))"
    r"[A-Za-z0-9._~+/=:,-]{4,}"
    r"|[A-Za-z0-9._~+/=-]{8,}"
    r")",
    re.IGNORECASE,
)
COOKIE_RE = re.compile(
    r"\b(?:Cookie|Set-Cookie)\s*:\s*(?!<redacted>|<token-redacted>|$)[^\n<]{4,}",
    re.IGNORECASE,
)
APP_SESSION_RE = re.compile(
    r"\bX-Crypta-App-Session\s*:\s*(?!<redacted>|<token-redacted>)[A-Za-z0-9._~+/=-]{8,}",
    re.IGNORECASE,
)
PARTIAL_REDACTION_RE = re.compile(
    r"(?<![\w-])(?:[\"']?Authorization[\"']?\s*:\s*[\"']?(?:[A-Za-z][A-Za-z0-9._~-]*\s+)?|"
    r"(?:Cookie|Set-Cookie|X-Crypta-App-Session)\s*:|"
    r"[\"']?(?:CRYPTAD_APP_TOKEN|appToken|browserSessionToken|appProcessToken|"
    r"formPassword|CRYPTAD_CERT_FORM_PASSWORD|"
    + PRIVATE_KEY_ASSIGNMENT_NAME_RE
    + r")[\"']?\s*[:=]|"
    r"(?:-P)[\"']?"
    + PRIVATE_KEY_ASSIGNMENT_NAME_RE
    + r"[\"']?\s*[:=]|"
    r"--form-password(?:=|\s+))"
    r"\s*[\"']?(?:<[^>\r\n]+>|redacted|\.\.\.)[\"']?"
    r"(?!\s*(?:$|[\r\n,}\]`\\]))(?=[^\r\n]*[A-Za-z0-9])",
    re.IGNORECASE,
)
TOKEN_ASSIGNMENT_RE = re.compile(
    r"\b[\"']?(?:CRYPTAD_APP_TOKEN|appToken|browserSessionToken|appProcessToken)[\"']?\s*[:=]\s*"
    r"(?![\"']?(?:<[^>]+>|\.\.\.|redacted|<redacted>|<token-redacted>)[\"']?(?:$|[\s,}\]`]))"
    r"(?:[\"'][^\"'<>\r\n]{8,}[\"']|[A-Za-z0-9._~+/=-]{8,})",
    re.IGNORECASE,
)
FORM_PASSWORD_RE = re.compile(
    r"(?:\b[\"']?(?:formPassword|CRYPTAD_CERT_FORM_PASSWORD)[\"']?\s*[:=]|"
    r"(?<![\w-])--form-password(?:=|\s+))\s*"
    r"(?![\"']?(?:<[^>]+>|redacted|\.\.\.)[\"']?(?:$|[\s,}\]`\\]))"
    r"(?:[\"'][^\"'<>\r\n]{4,}[\"']|[^&,\s`'\"<>{}\[\]]{4,})",
    re.IGNORECASE,
)
PRIVATE_INSERT_URI_RE = re.compile(
    r"\b(?:crypta:|freenet:)?(?:SSK|USK)@"
    r"(?!<|\.\.\.)"
    r"(?=[A-Za-z0-9~_-]{8})"
    r"[A-Za-z0-9~_,=-]+(?:/[^\s`'\"<>)]*)?",
    re.IGNORECASE,
)
RAW_PLUGIN_MIGRATION_ARTIFACT_RE = re.compile(
    r"(?<![\w-])[\"']?(?:"
    r"raw[-_ ]?social[-_ ]?message|raw[-_ ]?trust[-_ ]?statement|"
    r"raw[-_ ]?profile[-_ ]?document|raw[-_ ]?feed[-_ ]?document|"
    r"raw[-_ ]?feed[-_ ]?snapshot|raw[-_ ]?app[-_ ]?data[-_ ]?value|"
    r"raw[-_ ]?fetched[-_ ]?content|raw[-_ ]?fetched[-_ ]?body|"
    r"raw[-_ ]?content|raw[-_ ]?content[-_ ]?body|"
    r"raw[-_ ]?legacy[-_ ]?plugin[-_ ]?state|legacy[-_ ]?plugin[-_ ]?export|"
    r"old[-_ ]?plugin[-_ ]?export|plugin[-_ ]?export[-_ ]?body|"
    r"plugin[-_ ]?export[-_ ]?payload|fproxy[-_ ]?html|"
    r"raw[-_ ]?fproxy[-_ ]?html|fproxy[-_ ]?dump|raw[-_ ]?fproxy[-_ ]?dump|"
    r"raw[-_ ]?support[-_ ]?bundle|support[-_ ]?bundle[-_ ]?payload|"
    r"raw[-_ ]?html[-_ ]?dump|queue[-_ ]?html|plain[-_ ]?text[-_ ]?export"
    r")[\"']?\s*[:=]"
    r"(?!\s*[\"']?(?:<redacted[^>\r\n]*>|redacted|\.\.\.)[\"']?\s*(?:$|[\r\n,}\]`\\]))"
    r"\s*"
    r"(?:[{\[]|[\"'][^\"'\r\n]{4,}[\"']|[^\r\n,}]{4,})",
    re.IGNORECASE,
)
LOCAL_ABSOLUTE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->])(?:"
    r"/(?!/)(?:[A-Za-z0-9._~+-]+/)+[A-Za-z0-9._~+-]+/?"
    r"|[A-Za-z]:[\\/][^\s`'\"<>)]*)"
)
UNC_ABSOLUTE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->\\])"
    r"\\\\[^\\/\s`'\"<>|:*?]+\\[^\\/\s`'\"<>|:*?]+"
    r"(?:\\[^\\\s`'\"<>|:*?]+)*"
)
FILE_URI_RE = re.compile(
    r"\bfile:(?://(?P<authority>[^/\s`'\"<>)]*))?"
    r"(?P<path>/[^\s`'\"<>)]*|[A-Za-z]:[\\/][^\s`'\"<>)]*)",
    re.IGNORECASE,
)
MARKDOWN_LINK_RE = re.compile(r"(?<!!)\[[^\]\r\n]+\]\(([^)]+)\)")
MARKDOWN_REFERENCE_LINK_RE = re.compile(r"(?<!!)\[([^\]\r\n]+)\]\[([^\]\r\n]*)\]")
MARKDOWN_REFERENCE_DEFINITION_RE = re.compile(
    r"(?m)^[ \t]{0,3}\[([^\]\r\n]+)\]:[ \t]*(.+?)\s*$"
)
MARKDOWN_LINK_DESTINATION_RE = re.compile(
    r"^(?:<(?P<angle>[^<>\r\n]*)>|(?P<bare>\S+))"
    r"(?:\s+(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|\([^)\r\n]*\)))?\s*$"
)
CRYPTA_APP_ALIAS_RE = re.compile(
    r'(?:"\$(?:CRYPTA_APP|\{CRYPTA_APP\})"|\$(?:CRYPTA_APP|\{CRYPTA_APP\}))'
)
REDACTION_CHECKS = (
    ("private-key-block", PRIVATE_KEY_BLOCK_RE),
    ("private-key-assignment", PRIVATE_KEY_ASSIGNMENT_RE),
    ("seed-phrase", SEED_PHRASE_RE),
    ("authorization-header", AUTHORIZATION_HEADER_RE),
    ("cookie", COOKIE_RE),
    ("app-session-token", APP_SESSION_RE),
    ("partial-redaction", PARTIAL_REDACTION_RE),
    ("token-assignment", TOKEN_ASSIGNMENT_RE),
    ("form-password", FORM_PASSWORD_RE),
    ("private-insert-uri", PRIVATE_INSERT_URI_RE),
    ("migration-raw-artifact", RAW_PLUGIN_MIGRATION_ARTIFACT_RE),
)
REDACTED_BROKEN_LINK_TARGET = "<redacted-sensitive-link-target>"


def display_path(path: str | Path) -> str:
    return str(path).replace("\\", "/")


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def required_file_status(workspace_root: Path, paths: tuple[str, ...]) -> dict[str, bool]:
    return {
        path: (workspace_root / path).is_file() and bool(read_text(workspace_root / path).strip())
        for path in paths
    }


def normalize_crypta_app_aliases(text: str) -> str:
    return CRYPTA_APP_ALIAS_RE.sub("crypta-app", text)


def tutorial_doc_concept_text(workspace_root: Path) -> str:
    return normalize_crypta_app_aliases(
        read_text(workspace_root / "docs/app-platform-beta-tutorials.md")
    )


def missing_concepts(text: str) -> list[str]:
    lowered = text.lower()
    return sorted(concept for concept in REQUIRED_CONCEPTS if concept.lower() not in lowered)


def missing_terms(text: str, terms: tuple[str, ...]) -> list[str]:
    lowered = normalize_crypta_app_aliases(text).lower()
    return sorted(term for term in terms if term.lower() not in lowered)


def docs_text(workspace_root: Path, paths: tuple[str, ...]) -> str:
    return "\n".join(read_text(workspace_root / path) for path in paths)


def normalize_doc_link_target(raw_target: str) -> str:
    target = raw_target.strip()
    if not target or target.startswith("#"):
        return ""
    destination = MARKDOWN_LINK_DESTINATION_RE.match(target)
    if not destination:
        return ""
    target = (destination.group("angle") or destination.group("bare") or "").strip()
    if not target or target.startswith("#"):
        return ""
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return ""
    path = unquote(parsed.path)
    if not path.endswith(".md"):
        return ""
    return path


def normalize_reference_label(label: str) -> str:
    return " ".join(label.strip().casefold().split())


def markdown_reference_definitions(text: str) -> dict[str, str]:
    definitions: dict[str, str] = {}
    for match in MARKDOWN_REFERENCE_DEFINITION_RE.finditer(text):
        label = normalize_reference_label(match.group(1))
        if not label or label in definitions:
            continue
        target = normalize_doc_link_target(match.group(2))
        if target:
            definitions[label] = target
    return definitions


def markdown_doc_link_targets(text: str) -> list[str]:
    targets: list[str] = []
    for match in MARKDOWN_LINK_RE.finditer(text):
        target = normalize_doc_link_target(match.group(1))
        if target:
            targets.append(target)
    reference_definitions = markdown_reference_definitions(text)
    for match in MARKDOWN_REFERENCE_LINK_RE.finditer(text):
        label = match.group(2) or match.group(1)
        target = reference_definitions.get(normalize_reference_label(label))
        if target:
            targets.append(target)
    return targets


def resolve_doc_link_target(workspace_root: Path, markdown_file: Path, target: str) -> Path:
    if target.startswith("/"):
        return (workspace_root / target.lstrip("/")).resolve()
    target_path = Path(target)
    if target_path.is_absolute():
        return target_path.resolve()
    return (markdown_file.parent / target_path).resolve()


def markdown_link_targets(workspace_root: Path, markdown_file: Path) -> set[str]:
    targets: set[str] = set()
    text = read_text(markdown_file)
    for target in markdown_doc_link_targets(text):
        resolved = resolve_doc_link_target(workspace_root, markdown_file, target)
        try:
            relative = resolved.relative_to(workspace_root.resolve())
        except ValueError:
            continue
        targets.add(display_path(relative))
    return targets


def markdown_files_to_check(workspace_root: Path) -> list[Path]:
    files = [workspace_root / path for path in NEW_DOCS]
    files.extend(workspace_root / path for path in (*REQUIRED_DOCS, *REQUIRED_PORTAL_LINKS))
    files.extend(workspace_root / path for path in PUBLIC_BETA_DOCS)
    files.append(workspace_root / PUBLIC_BETA_RELEASE_NOTES_TEMPLATE)
    files.extend(workspace_root / path for path in PLUGIN_MIGRATION_DOCS)
    files.append(workspace_root / "README.md")
    return sorted({path for path in files if path.is_file()})


def broken_markdown_links_for_files(
    workspace_root: Path, markdown_files: list[Path]
) -> list[dict[str, str]]:
    broken: list[dict[str, str]] = []
    for markdown_file in markdown_files:
        text = read_text(markdown_file)
        for target in markdown_doc_link_targets(text):
            resolved = resolve_doc_link_target(workspace_root, markdown_file, target)
            try:
                resolved.relative_to(workspace_root.resolve())
            except ValueError:
                broken.append(
                    {
                        "source": display_path(markdown_file.relative_to(workspace_root)),
                        "target": safe_broken_link_target(target),
                        "reason": "outside-repo",
                    }
                )
                continue
            if not resolved.is_file():
                broken.append(
                    {
                        "source": display_path(markdown_file.relative_to(workspace_root)),
                        "target": safe_broken_link_target(target),
                        "reason": "missing",
                    }
                )
    return broken


def broken_markdown_links(workspace_root: Path) -> list[dict[str, str]]:
    return broken_markdown_links_for_files(workspace_root, markdown_files_to_check(workspace_root))


def redaction_files_to_check(workspace_root: Path) -> list[Path]:
    files = [workspace_root / path for path in (*REQUIRED_DOCS, *REQUIRED_PORTAL_LINKS)]
    files.extend(workspace_root / path for path in PUBLIC_BETA_DOCS)
    files.extend(workspace_root / path for path in PUBLIC_BETA_SUPPORT_FEEDBACK_DOCS)
    files.extend(workspace_root / path for path in PLUGIN_MIGRATION_DOCS)
    files.extend(workspace_root / path for path in ISSUE_TEMPLATES)
    files.append(workspace_root / "README.md")
    return sorted({path for path in files if path.is_file()})


def allowed_absolute_path(value: str) -> bool:
    normalized = unquote(value).replace("\\", "/")
    normalized_without_trailing_slash = normalized.rstrip("/")
    return any(
        allowed_path_prefix_match(normalized, prefix)
        for prefix in REDACTION_ALLOWLIST_PATH_PREFIXES
    ) or (
        normalized_without_trailing_slash in REDACTION_ALLOWLIST_EXACT_PATHS
    )


def allowed_path_prefix_match(value: str, prefix: str) -> bool:
    if prefix.endswith("/"):
        return value.startswith(prefix)
    return value == prefix or value.startswith(f"{prefix}/")


def file_uri_path_value(raw_path: str) -> str:
    value = unquote(raw_path).replace("\\", "/")
    if re.match(r"^/[A-Za-z]:/", value):
        return value[1:]
    return value


def has_disallowed_local_path(text: str) -> bool:
    for match in FILE_URI_RE.finditer(text):
        authority = match.group("authority")
        if authority and authority.lower() != "localhost":
            return True
        value = file_uri_path_value(match.group("path"))
        if not allowed_absolute_path(value):
            return True
    for match in LOCAL_ABSOLUTE_PATH_RE.finditer(text):
        value = match.group(0)
        if not allowed_absolute_path(value):
            return True
    for match in UNC_ABSOLUTE_PATH_RE.finditer(text):
        value = match.group(0)
        if not allowed_absolute_path(value):
            return True
    return False


def has_sensitive_redaction_material(text: str) -> bool:
    return any(pattern.search(text) for _, pattern in REDACTION_CHECKS)


def safe_broken_link_target(target: str) -> str:
    if has_disallowed_local_path(target) or has_sensitive_redaction_material(target):
        return REDACTED_BROKEN_LINK_TARGET
    return target


def safe_summary_for_output(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: safe_summary_for_output(child) for key, child in value.items()}
    if isinstance(value, list):
        return [safe_summary_for_output(child) for child in value]
    if isinstance(value, str) and (
        has_disallowed_local_path(value) or has_sensitive_redaction_material(value)
    ):
        return REDACTED_BROKEN_LINK_TARGET
    return value


def redaction_findings_for_files(
    workspace_root: Path, files: list[Path]
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for path in files:
        relative = display_path(path.relative_to(workspace_root))
        text = read_text(path)
        for issue, pattern in REDACTION_CHECKS:
            if pattern.search(text):
                findings.append({"path": relative, "issue": issue})
        if has_disallowed_local_path(text):
            findings.append({"path": relative, "issue": "local-absolute-path"})
    return findings


def redaction_findings(workspace_root: Path) -> list[dict[str, str]]:
    return redaction_findings_for_files(workspace_root, redaction_files_to_check(workspace_root))


def public_beta_markdown_files_to_check(workspace_root: Path) -> list[Path]:
    return sorted(
        {
            workspace_root / path
            for path in PUBLIC_BETA_DOCS
            if (workspace_root / path).is_file()
        }
    )


def public_beta_redaction_files_to_check(workspace_root: Path) -> list[Path]:
    paths = (
        *PUBLIC_BETA_DOCS,
        *ISSUE_TEMPLATES,
        PUBLIC_BETA_RELEASE_NOTES_TEMPLATE,
        PUBLIC_BETA_KNOWN_ISSUES_METADATA,
        PUBLIC_BETA_SAFE_FEEDBACK_FIXTURE,
    )
    return sorted({workspace_root / path for path in paths if (workspace_root / path).is_file()})


def portal_link_status(workspace_root: Path) -> dict[str, bool]:
    targets = markdown_link_targets(
        workspace_root, workspace_root / "docs/app-platform-developer-portal.md"
    )
    return {path: path in targets for path in REQUIRED_PORTAL_LINKS}


def readme_links_portal(workspace_root: Path) -> bool:
    return "docs/app-platform-developer-portal.md" in markdown_link_targets(
        workspace_root, workspace_root / "README.md"
    )


ISSUE_TEMPLATE_ID_RE = re.compile(r"(?m)^\s*id:\s*([A-Za-z0-9_-]+)\s*$")


def issue_template_field_ids(text: str) -> set[str]:
    return {match.group(1) for match in ISSUE_TEMPLATE_ID_RE.finditer(text)}


def indentation_width(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def issue_template_item_blocks(text: str) -> list[list[str]]:
    blocks: list[list[str]] = []
    current: list[str] = []
    current_indent = 0
    for line in text.splitlines():
        if re.match(r"^\s*-\s*type:\s*", line):
            indent = indentation_width(line)
            if current and indent <= current_indent:
                blocks.append(current)
                current = []
            current_indent = indent
        if current or re.match(r"^\s*-\s*type:\s*", line):
            current.append(line)
    if current:
        blocks.append(current)
    return blocks


def checkbox_option_blocks(item_lines: list[str]) -> list[list[str]]:
    options_index = -1
    options_indent = 0
    for index, line in enumerate(item_lines):
        if re.match(r"^\s*options:\s*$", line):
            options_index = index
            options_indent = indentation_width(line)
            break
    if options_index < 0:
        return []

    option_blocks: list[list[str]] = []
    current: list[str] = []
    current_indent = 0
    for line in item_lines[options_index + 1 :]:
        if line.strip() and indentation_width(line) <= options_indent:
            break
        if re.match(r"^\s*-\s*label:\s*", line):
            if current:
                option_blocks.append(current)
            current = [line]
            current_indent = indentation_width(line)
            continue
        if current:
            if line.strip() and indentation_width(line) <= current_indent:
                break
            current.append(line)
    if current:
        option_blocks.append(current)
    return option_blocks


def checkbox_option_is_required(option_lines: list[str]) -> bool:
    return any(re.match(r"^\s*required:\s*true\s*$", line, re.IGNORECASE) for line in option_lines)


def has_required_redaction_confirmation(text: str) -> bool:
    for item_lines in issue_template_item_blocks(text):
        item_text = "\n".join(item_lines)
        if not re.search(r"(?im)^\s*-\s*type:\s*checkboxes\s*$", item_text):
            continue
        if not re.search(r"(?im)^\s*id:\s*redaction[-_]confirmation\s*$", item_text):
            continue
        if "redaction confirmation" not in item_text.lower():
            continue
        options = checkbox_option_blocks(item_lines)
        return bool(options) and all(checkbox_option_is_required(option) for option in options)
    return False


def line_negates_sensitive_request(line: str) -> bool:
    lowered = line.lower()
    return bool(
        re.search(
            r"\b(?:do|does|must)\s+not\b|\bnever\b|"
            r"\bnot\s+(?:include|included|request|requested|ask|asked|upload|uploaded|"
            r"attach|attached|paste|pasted|provide|provided|share|shared|disclose|"
            r"disclosed|describe|described)\b|"
            r"\bcontains?\s+no\b|"
            r"\bwith\s+no\s+(?:secrets?|private\b|private\s+uris?|"
            r"private\s+insert\s+uris?|raw\b|raw\s+support\s+bundles?|"
            r"exploit\s+details?|proof-of-concept|tokens?)\b|"
            r"\bwithout\s+(?:public\s+)?(?:exploit\s+details?|secrets?|private\s+"
            r"(?:material|content|values?|uris?|insert\s+uris?)|raw\s+"
            r"(?:content|data|support\s+bundles?))\b",
            lowered,
        )
    )


def unsafe_template_prompt_findings(path: str, text: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        lowered = line.lower()
        if "raw support bundle" in lowered and any(
            verb in lowered for verb in ("upload", "attach", "paste", "include", "request", "ask")
        ) and not line_negates_sensitive_request(line):
            findings.append(
                {
                    "path": path,
                    "issue": "raw-support-bundle-request",
                    "line": str(line_number),
                }
            )
        if "private insert uri" in lowered and not line_negates_sensitive_request(line):
            findings.append(
                {"path": path, "issue": "private-insert-uri-request", "line": str(line_number)}
            )
        if "exploit detail" in lowered and not line_negates_sensitive_request(line):
            findings.append(
                {"path": path, "issue": "public-exploit-detail-request", "line": str(line_number)}
            )
    return findings


def issue_template_validation(workspace_root: Path) -> dict[str, Any]:
    missing_fields: dict[str, list[str]] = {}
    missing_redaction_confirmation: list[str] = []
    unsafe_prompts: list[dict[str, str]] = []
    field_ids_by_template: dict[str, list[str]] = {}
    first_party_app_options = (
        "queue-manager",
        "publisher",
        "site-publisher",
        "profile-publisher",
        "feed-reader",
        "trust-graph",
        "social-inbox",
    )
    security_handoff_terms = (
        "private security report",
        "security advisory or denylist event",
        "reviewer key compromise",
        "catalog signing key compromise",
        "app signing key compromise",
        "support bundle redaction failure",
    )
    for path in ISSUE_TEMPLATES:
        text = read_text(workspace_root / path)
        field_ids = issue_template_field_ids(text)
        field_ids_by_template[path] = sorted(field_ids)
        if not has_required_redaction_confirmation(text):
            missing_redaction_confirmation.append(path)
        unsafe_prompts.extend(unsafe_template_prompt_findings(path, text))
        required_fields = ISSUE_TEMPLATE_REQUIRED_FIELDS.get(path, ())
        missing = [field for field in required_fields if field not in field_ids]
        if missing:
            missing_fields[path] = missing
    app_specific_text = read_text(
        workspace_root / ".github/ISSUE_TEMPLATE/app-specific-feedback.yml"
    )
    missing_first_party_options = [
        app_id for app_id in first_party_app_options if app_id not in app_specific_text
    ]
    security_text = read_text(
        workspace_root / ".github/ISSUE_TEMPLATE/security-advisory-intake.yml"
    )
    missing_security_handoff_terms = [
        term for term in security_handoff_terms if term not in security_text.lower()
    ]
    return {
        "fieldIdsByTemplate": field_ids_by_template,
        "missingFields": missing_fields,
        "missingRedactionConfirmation": sorted(missing_redaction_confirmation),
        "unsafePrompts": unsafe_prompts,
        "missingFirstPartyAppOptions": missing_first_party_options,
        "missingSecurityHandoffTerms": missing_security_handoff_terms,
        "passed": not missing_fields
        and not missing_redaction_confirmation
        and not unsafe_prompts
        and not missing_first_party_options
        and not missing_security_handoff_terms,
    }


def load_json_document(path: Path) -> tuple[Any | None, str]:
    try:
        return json.loads(read_text(path)), ""
    except json.JSONDecodeError as exc:
        return None, str(exc)


def known_issues_validation(workspace_root: Path) -> dict[str, Any]:
    doc_text = read_text(workspace_root / "docs/public-beta/known-issues.md")
    metadata_path = workspace_root / PUBLIC_BETA_KNOWN_ISSUES_METADATA
    metadata, error = load_json_document(metadata_path)
    missing_doc_fields = [field for field in KNOWN_ISSUE_FIELDS if field not in doc_text]
    missing_metadata_fields: dict[str, list[str]] = {}
    redaction = redaction_findings_for_files(
        workspace_root,
        [
            workspace_root / "docs/public-beta/known-issues.md",
            metadata_path,
        ],
    )
    if isinstance(metadata, dict):
        issues = metadata.get("knownIssues")
        if isinstance(issues, list):
            for index, issue in enumerate(issues):
                if isinstance(issue, dict):
                    missing = [field for field in KNOWN_ISSUE_FIELDS if field not in issue]
                else:
                    missing = list(KNOWN_ISSUE_FIELDS)
                if missing:
                    missing_metadata_fields[str(index)] = missing
        else:
            missing_metadata_fields["knownIssues"] = ["knownIssues"]
    else:
        missing_metadata_fields["json"] = ["parse"]
    return {
        "jsonParseError": error,
        "missingDocFields": missing_doc_fields,
        "missingMetadataFields": missing_metadata_fields,
        "redactionFindings": redaction,
        "passed": not error
        and not missing_doc_fields
        and not missing_metadata_fields
        and not redaction,
    }


def release_notes_template_validation(workspace_root: Path) -> dict[str, Any]:
    path = workspace_root / PUBLIC_BETA_RELEASE_NOTES_TEMPLATE
    text = read_text(path)
    missing_sections = [section for section in BETA_RELEASE_NOTES_SECTIONS if section not in text]
    redaction = redaction_findings_for_files(workspace_root, [path])
    return {
        "missingSections": missing_sections,
        "redactionFindings": redaction,
        "passed": path.is_file() and not missing_sections and not redaction,
    }


def redaction_fixture_validation(workspace_root: Path) -> dict[str, Any]:
    positive_path = workspace_root / PUBLIC_BETA_SAFE_FEEDBACK_FIXTURE
    negative_paths = [workspace_root / path for path in PUBLIC_BETA_NEGATIVE_FEEDBACK_FIXTURES]
    missing_fixtures = [
        display_path(path.relative_to(workspace_root))
        for path in [positive_path, *negative_paths]
        if not path.is_file()
    ]
    positive_findings = (
        redaction_findings_for_files(workspace_root, [positive_path])
        if positive_path.is_file()
        else []
    )
    negative_findings_by_path: dict[str, list[str]] = {}
    undetected_negative_fixtures: list[str] = []
    for path in negative_paths:
        if not path.is_file():
            continue
        relative = display_path(path.relative_to(workspace_root))
        findings = redaction_findings_for_files(workspace_root, [path])
        issues = [finding["issue"] for finding in findings if finding.get("path") == relative]
        negative_findings_by_path[relative] = issues
        if not issues:
            undetected_negative_fixtures.append(relative)
    return {
        "positiveFixture": PUBLIC_BETA_SAFE_FEEDBACK_FIXTURE,
        "negativeFixtures": list(PUBLIC_BETA_NEGATIVE_FEEDBACK_FIXTURES),
        "missingFixtures": missing_fixtures,
        "positiveFindings": positive_findings,
        "negativeFindingsByPath": negative_findings_by_path,
        "undetectedNegativeFixtures": undetected_negative_fixtures,
        "passed": not missing_fixtures
        and not positive_findings
        and not undetected_negative_fixtures,
    }


def support_bundle_guidance_validation(workspace_root: Path) -> dict[str, Any]:
    paths = (
        "docs/public-beta/support-and-feedback.md",
        "docs/privacy-preserving-beta-diagnostics.md",
        ".github/ISSUE_TEMPLATE/support-bundle-diagnostics.yml",
    )
    text = docs_text(workspace_root, paths)
    required_terms = (
        "local-only",
        "digest",
        "schema version",
        "diagnostic summary",
        "Raw app-data backups are not support bundles",
        "reviewed redacted bundle",
        "do not attach",
    )
    missing = missing_terms(text, required_terms)
    return {"missingTerms": missing, "passed": not missing}


def security_handoff_validation(workspace_root: Path) -> dict[str, Any]:
    paths = (
        "docs/public-beta/security-reporting.md",
        "docs/SECURITY.md",
        ".github/ISSUE_TEMPLATE/security-advisory-intake.yml",
    )
    text = docs_text(workspace_root, paths)
    required_terms = (
        "Public bug report",
        "Private security report",
        "Security advisory or denylist event",
        "Reviewer key compromise",
        "Catalog signing key compromise",
        "App signing key compromise",
        "Support bundle redaction failure",
        "Do not include exploit details",
    )
    missing = missing_terms(text, required_terms)
    unsafe_prompts = unsafe_template_prompt_findings(
        ".github/ISSUE_TEMPLATE/security-advisory-intake.yml",
        read_text(workspace_root / ".github/ISSUE_TEMPLATE/security-advisory-intake.yml"),
    )
    return {
        "missingTerms": missing,
        "unsafePrompts": unsafe_prompts,
        "passed": not missing and not unsafe_prompts,
    }


def evidence_item(
    evidence_id: str,
    status: str,
    summary: str,
    source: str,
    details: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": evidence_id,
        "status": status,
        "requiredForReleaseCandidate": True,
        "summary": summary,
        "source": source,
        "details": details,
    }


def run_check(workspace_root: Path) -> dict[str, Any]:
    workspace_root = workspace_root.resolve()
    required_docs = required_file_status(workspace_root, REQUIRED_DOCS)
    issue_templates = required_file_status(workspace_root, ISSUE_TEMPLATES)
    portal_links = portal_link_status(workspace_root)
    readme_portal_link = readme_links_portal(workspace_root)
    known_limitations_present = required_docs["docs/app-platform-beta-known-limitations.md"]
    tutorial_concepts_missing = missing_concepts(tutorial_doc_concept_text(workspace_root))
    broken_links = broken_markdown_links(workspace_root)
    redaction = redaction_findings(workspace_root)
    public_beta_broken_links = broken_markdown_links_for_files(
        workspace_root, public_beta_markdown_files_to_check(workspace_root)
    )
    public_beta_redaction = redaction_findings_for_files(
        workspace_root, public_beta_redaction_files_to_check(workspace_root)
    )
    public_beta_docs = required_file_status(workspace_root, PUBLIC_BETA_DOCS)
    public_beta_text = docs_text(workspace_root, PUBLIC_BETA_DOCS)
    public_beta_user_text = read_text(workspace_root / "docs/public-beta/user-guide.md")
    public_beta_developer_text = read_text(
        workspace_root / "docs/public-beta/developer-quickstart.md"
    )
    public_beta_troubleshooting_text = read_text(
        workspace_root / "docs/public-beta/troubleshooting.md"
    )
    public_beta_security_text = read_text(
        workspace_root / "docs/public-beta/security-reporting.md"
    )
    public_beta_limitations_text = read_text(
        workspace_root / "docs/public-beta/trust-social-limitations.md"
    )
    support_feedback_doc_status = required_file_status(
        workspace_root, PUBLIC_BETA_SUPPORT_FEEDBACK_DOCS
    )
    support_feedback_text = read_text(
        workspace_root / "docs/public-beta/support-and-feedback.md"
    )
    triage_taxonomy_text = read_text(
        workspace_root / "docs/public-beta/triage-taxonomy.md"
    )
    feedback_to_backlog_text = read_text(
        workspace_root / "docs/public-beta/feedback-to-backlog.md"
    )
    issue_template_checks = issue_template_validation(workspace_root)
    known_issue_checks = known_issues_validation(workspace_root)
    release_notes_checks = release_notes_template_validation(workspace_root)
    support_bundle_guidance_checks = support_bundle_guidance_validation(workspace_root)
    security_handoff_checks = security_handoff_validation(workspace_root)
    redaction_fixture_checks = redaction_fixture_validation(workspace_root)

    missing_docs = sorted(path for path, present in required_docs.items() if not present)
    missing_issue_templates = sorted(path for path, present in issue_templates.items() if not present)
    missing_portal_links = sorted(path for path, present in portal_links.items() if not present)
    missing_public_beta_docs = sorted(
        path for path, present in public_beta_docs.items() if not present
    )
    public_beta_onboarding_missing = missing_terms(
        public_beta_text, PUBLIC_BETA_ONBOARDING_CONCEPTS
    )
    public_beta_user_missing = missing_terms(
        public_beta_user_text, PUBLIC_BETA_USER_GUIDE_CONCEPTS
    )
    public_beta_developer_missing = missing_terms(
        public_beta_developer_text, PUBLIC_BETA_DEVELOPER_QUICKSTART_CONCEPTS
    )
    public_beta_troubleshooting_missing = missing_terms(
        public_beta_troubleshooting_text, PUBLIC_BETA_TROUBLESHOOTING_CONCEPTS
    )
    public_beta_security_missing = missing_terms(
        public_beta_security_text, PUBLIC_BETA_SECURITY_REPORTING_CONCEPTS
    )
    public_beta_limitations_missing = missing_terms(
        public_beta_limitations_text, PUBLIC_BETA_LIMITATION_CONCEPTS
    )
    missing_support_feedback_docs = sorted(
        path for path, present in support_feedback_doc_status.items() if not present
    )
    support_feedback_missing = missing_terms(
        support_feedback_text, PUBLIC_BETA_SUPPORT_FEEDBACK_CONCEPTS
    )
    triage_taxonomy_missing = missing_terms(
        triage_taxonomy_text, PUBLIC_BETA_TRIAGE_LABELS
    )
    feedback_to_backlog_missing = missing_terms(
        feedback_to_backlog_text,
        (
            "intake",
            "redaction check",
            "reproduction check",
            "triage category",
            "known issue matching",
            "support response",
            "security escalation",
            "developer or app-review escalation",
            "release blocker decision",
            "backlog candidate creation",
            "next beta verification",
            "release notes entry",
            "closure criteria",
            "Catalog cannot refresh",
            "App update failed",
            "Subscription stuck",
            "Trust Graph import warning",
            "Social Inbox rendering issue",
            "Third-party app compatibility report",
            "Legacy plugin author migration question",
            "Support bundle redaction concern",
            "Suspected security advisory",
        ),
    )

    docs_portal_passed = (
        not missing_docs
        and not missing_portal_links
        and readme_portal_link
        and known_limitations_present
    )
    beta_program_passed = (
        required_docs["docs/app-platform-beta-program.md"] and not missing_issue_templates
    )
    beta_tutorials_passed = (
        required_docs["docs/app-platform-beta-tutorials.md"] and not tutorial_concepts_missing
    )
    docs_redaction_passed = not broken_links and not redaction
    public_beta_links_redaction_passed = (
        not public_beta_broken_links and not public_beta_redaction
    )
    public_beta_onboarding_passed = (
        not missing_public_beta_docs
        and not public_beta_onboarding_missing
        and public_beta_links_redaction_passed
    )
    public_beta_user_passed = (
        public_beta_docs["docs/public-beta/user-guide.md"] and not public_beta_user_missing
    )
    public_beta_developer_passed = (
        public_beta_docs["docs/public-beta/developer-quickstart.md"]
        and not public_beta_developer_missing
    )
    public_beta_troubleshooting_passed = (
        public_beta_docs["docs/public-beta/troubleshooting.md"]
        and not public_beta_troubleshooting_missing
    )
    public_beta_security_passed = (
        public_beta_docs["docs/public-beta/security-reporting.md"]
        and issue_templates[".github/ISSUE_TEMPLATE/public-beta-support.yml"]
        and not public_beta_security_missing
    )
    public_beta_limitations_passed = (
        public_beta_docs["docs/public-beta/trust-social-limitations.md"]
        and not public_beta_limitations_missing
    )
    support_feedback_docs_passed = (
        not missing_support_feedback_docs and not support_feedback_missing
    )
    issue_templates_passed = (
        not missing_issue_templates and bool(issue_template_checks["passed"])
    )
    triage_taxonomy_passed = (
        support_feedback_doc_status["docs/public-beta/triage-taxonomy.md"]
        and not triage_taxonomy_missing
    )
    known_issues_passed = bool(known_issue_checks["passed"])
    feedback_to_backlog_passed = (
        support_feedback_doc_status["docs/public-beta/feedback-to-backlog.md"]
        and not feedback_to_backlog_missing
    )
    release_notes_template_passed = bool(release_notes_checks["passed"])
    support_bundle_guidance_passed = bool(support_bundle_guidance_checks["passed"])
    security_handoff_passed = bool(security_handoff_checks["passed"])
    app_specific_feedback_passed = (
        issue_templates[".github/ISSUE_TEMPLATE/app-specific-feedback.yml"]
        and not issue_template_checks["missingFields"].get(
            ".github/ISSUE_TEMPLATE/app-specific-feedback.yml"
        )
        and not issue_template_checks["missingFirstPartyAppOptions"]
    )
    catalog_incident_feedback_passed = (
        issue_templates[".github/ISSUE_TEMPLATE/catalog-incident.yml"]
        and not issue_template_checks["missingFields"].get(
            ".github/ISSUE_TEMPLATE/catalog-incident.yml"
        )
        and not any(
            finding["path"] == ".github/ISSUE_TEMPLATE/catalog-incident.yml"
            for finding in issue_template_checks["unsafePrompts"]
        )
    )
    redaction_fixtures_passed = bool(redaction_fixture_checks["passed"])
    support_feedback_loop_passed = all(
        (
            support_feedback_docs_passed,
            issue_templates_passed,
            triage_taxonomy_passed,
            known_issues_passed,
            feedback_to_backlog_passed,
            release_notes_template_passed,
            support_bundle_guidance_passed,
            security_handoff_passed,
            app_specific_feedback_passed,
            catalog_incident_feedback_passed,
            redaction_fixtures_passed,
            public_beta_links_redaction_passed,
        )
    )

    evidence = [
        evidence_item(
            "app-platform.docs-portal",
            "pass" if docs_portal_passed else "fail",
            (
                "App platform developer portal, required docs, known limitations, and README link are present."
                if docs_portal_passed
                else "App platform developer portal docs or required links are incomplete."
            ),
            "docs/app-platform-developer-portal.md",
            {
                "requiredDocsPresent": not missing_docs,
                "missingDocs": missing_docs,
                "portalLinksPresent": not missing_portal_links,
                "missingPortalLinks": missing_portal_links,
                "knownLimitationsPresent": known_limitations_present,
                "readmeLinksPortal": readme_portal_link,
            },
        ),
        evidence_item(
            "app-platform.beta-program",
            "pass" if beta_program_passed else "fail",
            (
                "Beta program doc and GitHub issue templates are present."
                if beta_program_passed
                else "Beta program doc or issue templates are missing."
            ),
            "docs/app-platform-beta-program.md",
            {
                "programDocPresent": required_docs["docs/app-platform-beta-program.md"],
                "issueTemplatesPresent": not missing_issue_templates,
                "missingIssueTemplates": missing_issue_templates,
                "issueTemplates": list(ISSUE_TEMPLATES),
            },
        ),
        evidence_item(
            "app-platform.beta-tutorials",
            "pass" if beta_tutorials_passed else "fail",
            (
                "Offline beta tutorials cover required commands and app-platform concepts."
                if beta_tutorials_passed
                else "Offline beta tutorials are missing required command or concept coverage."
            ),
            "docs/app-platform-beta-tutorials.md",
            {
                "tutorialsDocPresent": required_docs["docs/app-platform-beta-tutorials.md"],
                "requiredConceptCount": len(REQUIRED_CONCEPTS),
                "requiredConceptSource": "docs/app-platform-beta-tutorials.md",
                "launcherAliasesNormalized": True,
                "missingConcepts": tutorial_concepts_missing,
            },
        ),
        evidence_item(
            "app-platform.docs-redaction",
            "pass" if docs_redaction_passed else "fail",
            (
                "Docs and issue templates passed local Markdown link and redaction checks."
                if docs_redaction_passed
                else "Docs or issue templates failed local Markdown link or redaction checks."
            ),
            "tools/release-certification/certify.py",
            {
                "internalLinksOk": not broken_links,
                "brokenLinks": broken_links,
                "redactionOk": not redaction,
                "redactionFindings": redaction,
                "externalUrlsFetched": False,
            },
        ),
        evidence_item(
            "public-beta.docs-onboarding",
            "pass" if public_beta_onboarding_passed else "fail",
            (
                "Public beta onboarding docs are complete, cross-linked, and redaction-safe."
                if public_beta_onboarding_passed
                else "Public beta onboarding docs are incomplete or redaction-unsafe."
            ),
            "docs/public-beta/README.md",
            {
                "requiredDocsPresent": not missing_public_beta_docs,
                "missingDocs": missing_public_beta_docs,
                "requiredConceptCount": len(PUBLIC_BETA_ONBOARDING_CONCEPTS),
                "missingConcepts": public_beta_onboarding_missing,
                "linksAndRedactionOk": public_beta_links_redaction_passed,
                "supportBundleRedactionWarningRequired": True,
                "rawSecretsOrContentExamplesAllowed": False,
            },
        ),
        evidence_item(
            "public-beta.user-guide",
            "pass" if public_beta_user_passed else "fail",
            (
                "Public beta user/operator guide covers install, catalog, apps, consent, backup, support, and recovery."
                if public_beta_user_passed
                else "Public beta user/operator guide is missing required workflow coverage."
            ),
            "docs/public-beta/user-guide.md",
            {
                "docPresent": public_beta_docs["docs/public-beta/user-guide.md"],
                "requiredConceptCount": len(PUBLIC_BETA_USER_GUIDE_CONCEPTS),
                "missingConcepts": public_beta_user_missing,
            },
        ),
        evidence_item(
            "public-beta.developer-quickstart",
            "pass" if public_beta_developer_passed else "fail",
            (
                "Public beta developer quickstart covers the current crypta-app command path."
                if public_beta_developer_passed
                else "Public beta developer quickstart is missing required crypta-app command coverage."
            ),
            "docs/public-beta/developer-quickstart.md",
            {
                "docPresent": public_beta_docs["docs/public-beta/developer-quickstart.md"],
                "requiredConceptCount": len(PUBLIC_BETA_DEVELOPER_QUICKSTART_CONCEPTS),
                "missingConcepts": public_beta_developer_missing,
            },
        ),
        evidence_item(
            "public-beta.troubleshooting",
            "pass" if public_beta_troubleshooting_passed else "fail",
            (
                "Public beta troubleshooting guide covers expected user-visible failure modes."
                if public_beta_troubleshooting_passed
                else "Public beta troubleshooting guide is missing required failure-mode coverage."
            ),
            "docs/public-beta/troubleshooting.md",
            {
                "docPresent": public_beta_docs["docs/public-beta/troubleshooting.md"],
                "requiredConceptCount": len(PUBLIC_BETA_TROUBLESHOOTING_CONCEPTS),
                "missingConcepts": public_beta_troubleshooting_missing,
            },
        ),
        evidence_item(
            "public-beta.security-reporting",
            "pass" if public_beta_security_passed else "fail",
            (
                "Public beta security reporting path and redaction-safe support template are present."
                if public_beta_security_passed
                else "Public beta security reporting path or redaction-safe support template is incomplete."
            ),
            "docs/public-beta/security-reporting.md",
            {
                "docPresent": public_beta_docs["docs/public-beta/security-reporting.md"],
                "supportIssueTemplatePresent": issue_templates[
                    ".github/ISSUE_TEMPLATE/public-beta-support.yml"
                ],
                "requiredConceptCount": len(PUBLIC_BETA_SECURITY_REPORTING_CONCEPTS),
                "missingConcepts": public_beta_security_missing,
            },
        ),
        evidence_item(
            "public-beta.limitations",
            "pass" if public_beta_limitations_passed else "fail",
            (
                "Public beta Trust Graph and Social Inbox limitations are prominent and user-facing."
                if public_beta_limitations_passed
                else "Public beta Trust Graph or Social Inbox limitations are incomplete."
            ),
            "docs/public-beta/trust-social-limitations.md",
            {
                "docPresent": public_beta_docs[
                    "docs/public-beta/trust-social-limitations.md"
                ],
                "requiredConceptCount": len(PUBLIC_BETA_LIMITATION_CONCEPTS),
                "missingConcepts": public_beta_limitations_missing,
            },
        ),
        evidence_item(
            "public-beta.links-redaction",
            "pass" if public_beta_links_redaction_passed else "fail",
            (
                "Public beta onboarding docs passed local link and redaction checks."
                if public_beta_links_redaction_passed
                else "Public beta onboarding docs or support template failed local link or redaction checks."
            ),
            "tools/release-certification/certify.py",
            {
                "internalLinksOk": not public_beta_broken_links,
                "brokenLinks": public_beta_broken_links,
                "redactionOk": not public_beta_redaction,
                "redactionFindings": public_beta_redaction,
                "externalUrlsFetched": False,
                "privateInsertUrisAllowed": False,
                "rawSupportBundlesAllowed": False,
                "rawContentExamplesAllowed": False,
                "localAbsolutePathsAllowed": False,
            },
        ),
        evidence_item(
            "public-beta.support-feedback-loop",
            "pass" if support_feedback_loop_passed else "fail",
            (
                "Public beta support-feedback loop evidence is complete and redaction-safe."
                if support_feedback_loop_passed
                else "Public beta support-feedback loop evidence is incomplete or redaction-unsafe."
            ),
            "docs/public-beta/support-and-feedback.md",
            {
                "childEvidenceIds": list(PUBLIC_BETA_SUPPORT_FEEDBACK_EVIDENCE_IDS[1:]),
                "docs": support_feedback_docs_passed,
                "issueTemplates": issue_templates_passed,
                "triageTaxonomy": triage_taxonomy_passed,
                "knownIssuesTracker": known_issues_passed,
                "feedbackToBacklog": feedback_to_backlog_passed,
                "releaseNotesTemplate": release_notes_template_passed,
                "supportBundleGuidance": support_bundle_guidance_passed,
                "securityHandoff": security_handoff_passed,
                "appSpecificFeedback": app_specific_feedback_passed,
                "catalogIncidentFeedback": catalog_incident_feedback_passed,
                "redactionFixtures": redaction_fixtures_passed,
                "linksAndRedactionOk": public_beta_links_redaction_passed,
            },
        ),
        evidence_item(
            "public-beta.support-feedback-docs",
            "pass" if support_feedback_docs_passed else "fail",
            (
                "Canonical public beta support-feedback docs are present."
                if support_feedback_docs_passed
                else "Canonical public beta support-feedback docs are missing required coverage."
            ),
            "docs/public-beta/support-and-feedback.md",
            {
                "requiredDocsPresent": not missing_support_feedback_docs,
                "missingDocs": missing_support_feedback_docs,
                "requiredConceptCount": len(PUBLIC_BETA_SUPPORT_FEEDBACK_CONCEPTS),
                "missingConcepts": support_feedback_missing,
            },
        ),
        evidence_item(
            "public-beta.issue-templates",
            "pass" if issue_templates_passed else "fail",
            (
                "Public beta feedback issue templates have required fields and redaction confirmations."
                if issue_templates_passed
                else "Public beta feedback issue templates are missing required structure or contain unsafe prompts."
            ),
            ".github/ISSUE_TEMPLATE/",
            {
                "issueTemplates": list(ISSUE_TEMPLATES),
                "missingIssueTemplates": missing_issue_templates,
                "missingFields": issue_template_checks["missingFields"],
                "missingRedactionConfirmation": issue_template_checks[
                    "missingRedactionConfirmation"
                ],
                "unsafePrompts": issue_template_checks["unsafePrompts"],
            },
        ),
        evidence_item(
            "public-beta.triage-taxonomy",
            "pass" if triage_taxonomy_passed else "fail",
            (
                "Public beta triage taxonomy covers required area, severity, status, and privacy labels."
                if triage_taxonomy_passed
                else "Public beta triage taxonomy is incomplete."
            ),
            "docs/public-beta/triage-taxonomy.md",
            {
                "docPresent": support_feedback_doc_status[
                    "docs/public-beta/triage-taxonomy.md"
                ],
                "missingLabels": triage_taxonomy_missing,
            },
        ),
        evidence_item(
            "public-beta.known-issues-tracker",
            "pass" if known_issues_passed else "fail",
            (
                "Public beta known-issues tracker is deterministic and redaction-safe."
                if known_issues_passed
                else "Public beta known-issues tracker is missing fields or redaction-safe metadata."
            ),
            "docs/public-beta/known-issues.md",
            known_issue_checks,
        ),
        evidence_item(
            "public-beta.feedback-to-backlog",
            "pass" if feedback_to_backlog_passed else "fail",
            (
                "Public beta feedback-to-backlog workflow covers required triage outcomes and examples."
                if feedback_to_backlog_passed
                else "Public beta feedback-to-backlog workflow is incomplete."
            ),
            "docs/public-beta/feedback-to-backlog.md",
            {
                "docPresent": support_feedback_doc_status[
                    "docs/public-beta/feedback-to-backlog.md"
                ],
                "missingConcepts": feedback_to_backlog_missing,
            },
        ),
        evidence_item(
            "public-beta.release-notes-template",
            "pass" if release_notes_template_passed else "fail",
            (
                "Public beta release notes template is present and redaction-safe."
                if release_notes_template_passed
                else "Public beta release notes template is missing sections or has redaction findings."
            ),
            PUBLIC_BETA_RELEASE_NOTES_TEMPLATE,
            release_notes_checks,
        ),
        evidence_item(
            "public-beta.support-bundle-guidance",
            "pass" if support_bundle_guidance_passed else "fail",
            (
                "Public beta support-bundle guidance is digest-first and local-only."
                if support_bundle_guidance_passed
                else "Public beta support-bundle guidance is missing required sharing safeguards."
            ),
            "docs/public-beta/support-and-feedback.md",
            support_bundle_guidance_checks,
        ),
        evidence_item(
            "public-beta.security-reporting-handoff",
            "pass" if security_handoff_passed else "fail",
            (
                "Public beta security reporting handoff keeps public forms free of exploit details."
                if security_handoff_passed
                else "Public beta security reporting handoff is incomplete or unsafe."
            ),
            "docs/public-beta/security-reporting.md",
            security_handoff_checks,
        ),
        evidence_item(
            "public-beta.app-specific-feedback",
            "pass" if app_specific_feedback_passed else "fail",
            (
                "Public beta app-specific feedback template covers first-party app metadata."
                if app_specific_feedback_passed
                else "Public beta app-specific feedback template is incomplete."
            ),
            ".github/ISSUE_TEMPLATE/app-specific-feedback.yml",
            {
                "templatePresent": issue_templates[
                    ".github/ISSUE_TEMPLATE/app-specific-feedback.yml"
                ],
                "missingFields": issue_template_checks["missingFields"].get(
                    ".github/ISSUE_TEMPLATE/app-specific-feedback.yml", []
                ),
                "missingFirstPartyAppOptions": issue_template_checks[
                    "missingFirstPartyAppOptions"
                ],
            },
        ),
        evidence_item(
            "public-beta.catalog-incident-feedback",
            "pass" if catalog_incident_feedback_passed else "fail",
            (
                "Public beta catalog incident template captures safe catalog metadata."
                if catalog_incident_feedback_passed
                else "Public beta catalog incident template is incomplete or asks for unsafe material."
            ),
            ".github/ISSUE_TEMPLATE/catalog-incident.yml",
            {
                "templatePresent": issue_templates[
                    ".github/ISSUE_TEMPLATE/catalog-incident.yml"
                ],
                "missingFields": issue_template_checks["missingFields"].get(
                    ".github/ISSUE_TEMPLATE/catalog-incident.yml", []
                ),
                "unsafePrompts": [
                    finding
                    for finding in issue_template_checks["unsafePrompts"]
                    if finding["path"] == ".github/ISSUE_TEMPLATE/catalog-incident.yml"
                ],
            },
        ),
        evidence_item(
            "public-beta.redaction-fixtures",
            "pass" if redaction_fixtures_passed else "fail",
            (
                "Public beta feedback redaction fixtures detect unsafe examples and accept safe examples."
                if redaction_fixtures_passed
                else "Public beta feedback redaction fixtures are missing or unsafe examples were accepted."
            ),
            "tools/release-certification/fixtures/",
            redaction_fixture_checks,
        ),
    ]
    status = "pass" if all(item["status"] == "pass" for item in evidence) else "fail"
    return {
        "schemaVersion": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "status": status,
        "evidence": evidence,
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_self_test(repo_root: Path) -> None:
    summary = run_check(repo_root)
    assert summary["status"] == "pass", summary
    with tempfile.TemporaryDirectory(prefix="cryptad-docs-check-self-test-") as temp_name:
        temp_root = Path(temp_name)
        for path in sorted(
            {
                *REQUIRED_DOCS,
                *REQUIRED_PORTAL_LINKS,
                *PUBLIC_BETA_DOCS,
                *PUBLIC_BETA_SUPPORT_FEEDBACK_DOCS,
                *PLUGIN_MIGRATION_DOCS,
                PUBLIC_BETA_SAFE_FEEDBACK_FIXTURE,
                *PUBLIC_BETA_NEGATIVE_FEEDBACK_FIXTURES,
            }
        ):
            source = repo_root / path
            target = temp_root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(read_text(source), encoding="utf-8")
        for path in ISSUE_TEMPLATES:
            source = repo_root / path
            target = temp_root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(read_text(source), encoding="utf-8")
        (temp_root / "README.md").write_text(read_text(repo_root / "README.md"), encoding="utf-8")
        missing_doc = temp_root / "docs/app-platform-beta-tutorials.md"
        missing_doc.unlink()
        failed = run_check(temp_root)
        assert failed["status"] == "fail", failed
        stale_doc = temp_root / "docs/app-platform-beta-tutorials.md"
        stale_doc.write_text("# Stale beta tutorials\n\ncrypta-app dev\n", encoding="utf-8")
        stale = run_check(temp_root)
        stale_evidence = evidence_by_id(stale)
        assert stale["status"] == "fail", stale
        assert stale_evidence["app-platform.beta-tutorials"]["status"] == "fail", stale
        assert "crypta-app init" in stale_evidence["app-platform.beta-tutorials"]["details"][
            "missingConcepts"
        ], stale
        stale_doc.write_text(
            read_text(repo_root / "docs/app-platform-beta-tutorials.md"), encoding="utf-8"
        )
        portal_doc = temp_root / "docs/app-platform-developer-portal.md"
        portal_doc.write_text(
            read_text(repo_root / "docs/app-platform-developer-portal.md").replace(
                "(app-catalogs.md)", '(app-catalogs.md "catalog docs")'
            ),
            encoding="utf-8",
        )
        titled_portal = run_check(temp_root)
        titled_portal_evidence = evidence_by_id(titled_portal)["app-platform.docs-portal"]
        assert "docs/app-catalogs.md" not in titled_portal_evidence["details"][
            "missingPortalLinks"
        ], titled_portal
        portal_doc.write_text(
            read_text(repo_root / "docs/app-platform-developer-portal.md").replace(
                "[app-catalogs.md](app-catalogs.md)",
                "[app-catalogs.md][catalog-docs]",
            )
            + '\n[catalog-docs]: app-catalogs.md "catalog docs"\n',
            encoding="utf-8",
        )
        reference_portal = run_check(temp_root)
        reference_portal_evidence = evidence_by_id(reference_portal)[
            "app-platform.docs-portal"
        ]
        assert "docs/app-catalogs.md" not in reference_portal_evidence["details"][
            "missingPortalLinks"
        ], reference_portal
        portal_doc.write_text(
            read_text(repo_root / "docs/app-platform-developer-portal.md").replace(
                "(app-catalogs.md)", "(app-catalogs.md.bak)"
            ),
            encoding="utf-8",
        )
        filename_mention_portal = run_check(temp_root)
        portal_evidence = evidence_by_id(filename_mention_portal)["app-platform.docs-portal"]
        assert portal_evidence["status"] == "fail", filename_mention_portal
        assert "docs/app-catalogs.md" in portal_evidence["details"][
            "missingPortalLinks"
        ], filename_mention_portal
        portal_doc.write_text(
            read_text(repo_root / "docs/app-platform-developer-portal.md"), encoding="utf-8"
        )
        readme = temp_root / "README.md"
        readme.write_text(
            "This prose mentions docs/app-platform-developer-portal.md but does not link it.\n",
            encoding="utf-8",
        )
        filename_mention_readme = run_check(temp_root)
        readme_evidence = evidence_by_id(filename_mention_readme)["app-platform.docs-portal"]
        assert readme_evidence["status"] == "fail", filename_mention_readme
        assert readme_evidence["details"]["readmeLinksPortal"] is False, filename_mention_readme
        readme.write_text(
            "[App Platform Beta](/docs/app-platform-developer-portal.md)\n",
            encoding="utf-8",
        )
        root_relative_readme = run_check(temp_root)
        root_relative_evidence = evidence_by_id(root_relative_readme)
        assert root_relative_evidence["app-platform.docs-portal"]["details"][
            "readmeLinksPortal"
        ] is True, root_relative_readme
        assert not any(
            broken["source"] == "README.md"
            and broken["target"] == "/docs/app-platform-developer-portal.md"
            for broken in root_relative_evidence["app-platform.docs-redaction"]["details"][
                "brokenLinks"
            ]
        ), root_relative_readme
        readme.write_text(
            '[App Platform Beta][portal-doc]\n\n'
            '[portal-doc]: /docs/app-platform-developer-portal.md "portal docs"\n',
            encoding="utf-8",
        )
        reference_readme = run_check(temp_root)
        reference_readme_evidence = evidence_by_id(reference_readme)
        assert reference_readme_evidence["app-platform.docs-portal"]["details"][
            "readmeLinksPortal"
        ] is True, reference_readme
        assert not any(
            broken["source"] == "README.md"
            and broken["target"] == "/docs/app-platform-developer-portal.md"
            for broken in reference_readme_evidence["app-platform.docs-redaction"]["details"][
                "brokenLinks"
            ]
        ), reference_readme
        readme.write_text(read_text(repo_root / "README.md"), encoding="utf-8")
        portal_linked_doc = temp_root / "docs/app-owned-ui.md"
        portal_linked_doc.write_text(
            read_text(repo_root / "docs/app-owned-ui.md")
            + "\nAuthorization: Bearer concrete-token-value\n"
            + "Insert URI: USK@abcdefghijklmno,qrstuvwxyz0123456789ABCDEFG/name/0\n"
            + "Private key path: /root/.crypta-dev/keys/dev-local-bundle-private.der\n",
            encoding="utf-8",
        )
        leaked_portal_doc = run_check(temp_root)
        redaction_evidence = evidence_by_id(leaked_portal_doc)["app-platform.docs-redaction"]
        assert redaction_evidence["status"] == "fail", leaked_portal_doc
        assert {
            "path": "docs/app-owned-ui.md",
            "issue": "authorization-header",
        } in redaction_evidence["details"]["redactionFindings"], leaked_portal_doc
        assert {
            "path": "docs/app-owned-ui.md",
            "issue": "private-insert-uri",
        } in redaction_evidence["details"]["redactionFindings"], leaked_portal_doc
        assert {
            "path": "docs/app-owned-ui.md",
            "issue": "local-absolute-path",
        } in redaction_evidence["details"]["redactionFindings"], leaked_portal_doc
        portal_linked_doc.write_text(
            read_text(repo_root / "docs/app-owned-ui.md")
            + '\n[Broken portal-linked doc link](missing-beta-link.md "missing beta link")\n',
            encoding="utf-8",
        )
        broken_portal_link = run_check(temp_root)
        broken_link_evidence = evidence_by_id(broken_portal_link)["app-platform.docs-redaction"]
        assert broken_link_evidence["status"] == "fail", broken_portal_link
        assert {
            "source": "docs/app-owned-ui.md",
            "target": "missing-beta-link.md",
            "reason": "missing",
        } in broken_link_evidence["details"]["brokenLinks"], broken_portal_link
        portal_linked_doc.write_text(
            read_text(repo_root / "docs/app-owned-ui.md")
            + '\n[Broken portal-linked doc link][missing-beta]\n'
            + '\n[missing-beta]: missing-beta-link.md "missing beta link"\n',
            encoding="utf-8",
        )
        broken_reference_link = run_check(temp_root)
        broken_reference_evidence = evidence_by_id(broken_reference_link)[
            "app-platform.docs-redaction"
        ]
        assert broken_reference_evidence["status"] == "fail", broken_reference_link
        assert {
            "source": "docs/app-owned-ui.md",
            "target": "missing-beta-link.md",
            "reason": "missing",
        } in broken_reference_evidence["details"]["brokenLinks"], broken_reference_link
        portal_linked_doc.write_text(
            read_text(repo_root / "docs/app-owned-ui.md")
            + "\n[Unsafe local link](/home/alice/private.md)\n",
            encoding="utf-8",
        )
        unsafe_link = run_check(temp_root)
        unsafe_link_evidence = evidence_by_id(unsafe_link)["app-platform.docs-redaction"]
        assert {
            "source": "docs/app-owned-ui.md",
            "target": REDACTED_BROKEN_LINK_TARGET,
            "reason": "missing",
        } in unsafe_link_evidence["details"]["brokenLinks"], unsafe_link
        assert "/home/alice/private.md" not in json.dumps(unsafe_link, sort_keys=True)
        assert {
            "path": "docs/app-owned-ui.md",
            "issue": "local-absolute-path",
        } in unsafe_link_evidence["details"]["redactionFindings"], unsafe_link
        sensitive_uri_target = "USK@abcdefghijklmno,qrstuvwxyz0123456789ABCDEFG/private/doc.md"
        portal_linked_doc.write_text(
            read_text(repo_root / "docs/app-owned-ui.md")
            + f"\n[Sensitive URI link]({sensitive_uri_target})\n",
            encoding="utf-8",
        )
        sensitive_links = run_check(temp_root)
        sensitive_link_evidence = evidence_by_id(sensitive_links)["app-platform.docs-redaction"]
        assert {
            "source": "docs/app-owned-ui.md",
            "target": REDACTED_BROKEN_LINK_TARGET,
            "reason": "missing",
        } in sensitive_link_evidence["details"]["brokenLinks"], sensitive_links
        sensitive_links_encoded = json.dumps(sensitive_links, sort_keys=True)
        assert sensitive_uri_target not in sensitive_links_encoded, sensitive_links
        assert {
            "path": "docs/app-owned-ui.md",
            "issue": "private-insert-uri",
        } in sensitive_link_evidence["details"]["redactionFindings"], sensitive_links
        security_reporting_doc = temp_root / "docs/public-beta/security-reporting.md"
        security_reporting_doc.unlink()
        missing_security = run_check(temp_root)
        missing_security_evidence = evidence_by_id(missing_security)
        assert missing_security_evidence["public-beta.security-reporting"]["status"] == "fail", (
            missing_security
        )
        assert missing_security_evidence["public-beta.docs-onboarding"]["status"] == "fail", (
            missing_security
        )
        security_reporting_doc.write_text(
            read_text(repo_root / "docs/public-beta/security-reporting.md"), encoding="utf-8"
        )
        limitations_doc = temp_root / "docs/public-beta/trust-social-limitations.md"
        limitations_doc.write_text(
            "# Public beta limits\n\nSocial Inbox RC is not Freemail.\n", encoding="utf-8"
        )
        missing_limitations = run_check(temp_root)
        limitations_evidence = evidence_by_id(missing_limitations)["public-beta.limitations"]
        assert limitations_evidence["status"] == "fail", missing_limitations
        assert "Trust Graph Local RC" in limitations_evidence["details"][
            "missingConcepts"
        ], missing_limitations
        assert "not a crawler" in limitations_evidence["details"][
            "missingConcepts"
        ], missing_limitations
        assert "not routing policy" in limitations_evidence["details"][
            "missingConcepts"
        ], missing_limitations
        limitations_doc.write_text(
            read_text(repo_root / "docs/public-beta/trust-social-limitations.md"),
            encoding="utf-8",
        )
        public_beta_readme = temp_root / "docs/public-beta/README.md"
        public_beta_readme.write_text(
            read_text(repo_root / "docs/public-beta/README.md")
            + "\n[Missing public beta doc](missing-public-beta-doc.md)\n",
            encoding="utf-8",
        )
        missing_public_beta_link = run_check(temp_root)
        public_beta_link_evidence = evidence_by_id(missing_public_beta_link)[
            "public-beta.links-redaction"
        ]
        assert public_beta_link_evidence["status"] == "fail", missing_public_beta_link
        assert {
            "source": "docs/public-beta/README.md",
            "target": "missing-public-beta-doc.md",
            "reason": "missing",
        } in public_beta_link_evidence["details"]["brokenLinks"], missing_public_beta_link
        public_beta_readme.write_text(
            read_text(repo_root / "docs/public-beta/README.md")
            + "\nrawSupportBundle: private diagnostic body\n",
            encoding="utf-8",
        )
        raw_support_bundle = run_check(temp_root)
        public_beta_redaction = evidence_by_id(raw_support_bundle)["public-beta.links-redaction"]
        assert public_beta_redaction["status"] == "fail", raw_support_bundle
        assert {
            "path": "docs/public-beta/README.md",
            "issue": "migration-raw-artifact",
        } in public_beta_redaction["details"]["redactionFindings"], raw_support_bundle
        public_beta_readme.write_text(
            read_text(repo_root / "docs/public-beta/README.md"), encoding="utf-8"
        )
        support_template = temp_root / ".github/ISSUE_TEMPLATE/public-beta-support.yml"
        support_template_original = read_text(support_template)
        support_template.write_text(
            support_template_original.replace(
                "id: redaction-confirmation", "id: missing-redaction-confirmation"
            ),
            encoding="utf-8",
        )
        missing_redaction_confirmation = run_check(temp_root)
        issue_template_evidence = evidence_by_id(missing_redaction_confirmation)[
            "public-beta.issue-templates"
        ]
        assert issue_template_evidence["status"] == "fail", missing_redaction_confirmation
        assert ".github/ISSUE_TEMPLATE/public-beta-support.yml" in issue_template_evidence[
            "details"
        ]["missingRedactionConfirmation"], missing_redaction_confirmation
        support_template.write_text(support_template_original, encoding="utf-8")
        optional_checkbox_template = re.sub(
            r"(id: redaction-confirmation[\s\S]*?options:\n\s+- label:[^\n]*\n\s+)required: true",
            r"\1required: false",
            support_template_original,
            count=1,
        )
        assert optional_checkbox_template != support_template_original
        support_template.write_text(optional_checkbox_template, encoding="utf-8")
        optional_redaction_confirmation = run_check(temp_root)
        optional_redaction_evidence = evidence_by_id(optional_redaction_confirmation)[
            "public-beta.issue-templates"
        ]
        assert optional_redaction_evidence["status"] == "fail", optional_redaction_confirmation
        assert ".github/ISSUE_TEMPLATE/public-beta-support.yml" in optional_redaction_evidence[
            "details"
        ]["missingRedactionConfirmation"], optional_redaction_confirmation
        support_template.write_text(support_template_original, encoding="utf-8")
        support_template.write_text(
            support_template_original
            + "\n  - type: textarea\n"
            + "    id: raw_bundle_upload\n"
            + "    attributes:\n"
            + "      label: Please upload a raw support bundle\n",
            encoding="utf-8",
        )
        raw_bundle_upload = run_check(temp_root)
        assert evidence_by_id(raw_bundle_upload)["public-beta.issue-templates"][
            "status"
        ] == "fail", raw_bundle_upload
        support_template.write_text(support_template_original, encoding="utf-8")
        catalog_template = temp_root / ".github/ISSUE_TEMPLATE/catalog-incident.yml"
        catalog_template_original = read_text(catalog_template)
        catalog_template.write_text(
            catalog_template_original
            + "\n  - type: input\n"
            + "    id: unsafe_private_insert_uri\n"
            + "    attributes:\n"
            + "      label: Private insert URI\n",
            encoding="utf-8",
        )
        catalog_private_uri = run_check(temp_root)
        assert evidence_by_id(catalog_private_uri)["public-beta.catalog-incident-feedback"][
            "status"
        ] == "fail", catalog_private_uri
        catalog_template.write_text(catalog_template_original, encoding="utf-8")
        known_issues_doc = temp_root / "docs/public-beta/known-issues.md"
        known_issues_doc_original = read_text(known_issues_doc)
        known_issues_doc.write_text(
            known_issues_doc_original + '\nrawAppDataValue: "private app value"\n',
            encoding="utf-8",
        )
        known_raw_app_data = run_check(temp_root)
        assert evidence_by_id(known_raw_app_data)["public-beta.known-issues-tracker"][
            "status"
        ] == "fail", known_raw_app_data
        known_issues_doc.write_text(
            known_issues_doc_original
            + "\nInsert URI: USK@abcdefghijklmno,qrstuvwxyz0123456789ABCDEFG/name/0\n",
            encoding="utf-8",
        )
        known_private_uri = run_check(temp_root)
        assert evidence_by_id(known_private_uri)["public-beta.known-issues-tracker"][
            "status"
        ] == "fail", known_private_uri
        known_issues_doc.write_text(known_issues_doc_original, encoding="utf-8")
        release_notes_template = temp_root / PUBLIC_BETA_RELEASE_NOTES_TEMPLATE
        release_notes_template_original = read_text(release_notes_template)
        release_notes_template.write_text(
            release_notes_template_original + '\nrawFetchedContent: "private fetched body"\n',
            encoding="utf-8",
        )
        release_notes_raw_content = run_check(temp_root)
        assert evidence_by_id(release_notes_raw_content)[
            "public-beta.release-notes-template"
        ]["status"] == "fail", release_notes_raw_content
        release_notes_template.write_text(release_notes_template_original, encoding="utf-8")
        safe_fixture = temp_root / PUBLIC_BETA_SAFE_FEEDBACK_FIXTURE
        safe_fixture_original = read_text(safe_fixture)
        safe_fixture.write_text(
            safe_fixture_original
            + '\n{"feedbackToBacklogRecord":{"privateKey":"-----BEGIN PRIVATE KEY-----"}}\n',
            encoding="utf-8",
        )
        feedback_private_key = run_check(temp_root)
        assert evidence_by_id(feedback_private_key)["public-beta.redaction-fixtures"][
            "status"
        ] == "fail", feedback_private_key
        safe_fixture.write_text(safe_fixture_original, encoding="utf-8")
        security_template = temp_root / ".github/ISSUE_TEMPLATE/security-advisory-intake.yml"
        security_template_original = read_text(security_template)
        security_template.write_text(
            security_template_original + "\nPlease include exploit details publicly.\n",
            encoding="utf-8",
        )
        security_public_exploit = run_check(temp_root)
        assert evidence_by_id(security_public_exploit)[
            "public-beta.security-reporting-handoff"
        ]["status"] == "fail", security_public_exploit
        security_template.write_text(security_template_original, encoding="utf-8")
        assert unsafe_template_prompt_findings(
            "unsafe.yml", "Please include exploit details without redaction."
        ) == [
            {
                "path": "unsafe.yml",
                "issue": "public-exploit-detail-request",
                "line": "1",
            }
        ]
        assert unsafe_template_prompt_findings(
            "unsafe.yml", "Please paste a raw support bundle with no redaction."
        ) == [
            {
                "path": "unsafe.yml",
                "issue": "raw-support-bundle-request",
                "line": "1",
            }
        ]
        assert not unsafe_template_prompt_findings(
            "safe.yml", "Do not include exploit details here."
        )
        assert not unsafe_template_prompt_findings(
            "safe.yml",
            "Classify a suspected public-beta security issue without public exploit details.",
        )
        assert not unsafe_template_prompt_findings(
            "safe.yml", "Do not upload a raw support bundle in this public issue."
        )
    assert redaction_findings_for_text("Authorization: Bearer concrete-token-value") == [
        "authorization-header"
    ]
    assert "authorization-header" in redaction_findings_for_text(
        "Authorization: Basic dXNlcjpwYXNz"
    )
    assert "authorization-header" in redaction_findings_for_text(
        '"Authorization": "Bearer real-token"'
    )
    assert "authorization-header" in redaction_findings_for_text(
        "'Authorization': 'Basic dXNlcjpwYXNz'"
    )
    assert "authorization-header" in redaction_findings_for_text(
        'Authorization: "Bearer real-token"'
    )
    assert "authorization-header" not in redaction_findings_for_text(
        "Authorization: Bearer <token>"
    )
    assert "authorization-header" not in redaction_findings_for_text(
        '"Authorization": "Bearer <token>"'
    )
    assert "partial-redaction" in redaction_findings_for_text(
        "Authorization: Bearer <redacted> abc123"
    )
    assert "partial-redaction" in redaction_findings_for_text(
        '"Authorization": "Bearer <redacted> abc123"'
    )
    assert "partial-redaction" in redaction_findings_for_text(
        "Authorization: Basic <redacted> dXNlcjpwYXNz"
    )
    assert "partial-redaction" in redaction_findings_for_text(
        "Cookie: <redacted>; sid=abcdef012345"
    )
    assert "partial-redaction" in redaction_findings_for_text(
        "appToken: <redacted> abcdef0123456789"
    )
    assert "partial-redaction" not in redaction_findings_for_text(
        "Authorization: Bearer <redacted>"
    )
    assert "partial-redaction" not in redaction_findings_for_text("Cookie: <redacted>")
    assert "private-key-block" in redaction_findings_for_text(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----"
    )
    assert "private-key-assignment" in redaction_findings_for_text(
        "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64=MC4CAQAwBQYDK2VwBCIEIAabcdefghijklmnop"
    )
    assert "private-key-assignment" in redaction_findings_for_text(
        '"reviewerPrivateKey": "MC4CAQAwBQYDK2VwBCIEIAabcdefghijklmnop"'
    )
    assert "private-key-assignment" in redaction_findings_for_text(
        "-PcryptadAppSigningPrivateKeyBase64=MC4CAQAwBQYDK2VwBCIEIAabcdefghijklmnop"
    )
    assert "private-key-assignment" not in redaction_findings_for_text(
        "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64=..."
    )
    assert "private-key-assignment" not in redaction_findings_for_text(
        '"reviewerPrivateKey": "<redacted>"'
    )
    assert "private-key-assignment" not in redaction_findings_for_text(
        "-PcryptadAppSigningPrivateKeyBase64=..."
    )
    assert "private-key-assignment" not in redaction_findings_for_text(
        "-PcryptadAppSigningPrivateKeyFile=/abs/path/to/dev-app-signing-private.pem"
    )
    assert "partial-redaction" in redaction_findings_for_text(
        "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64=<redacted> MC4CAQAwBQYDK2Vw"
    )
    assert "partial-redaction" in redaction_findings_for_text(
        "-PcryptadAppSigningPrivateKeyBase64=<redacted> MC4CAQAwBQYDK2Vw"
    )
    assert "form-password" in redaction_findings_for_text("formPassword=hunter2")
    assert "form-password" in redaction_findings_for_text("formPassword: hunter2")
    assert "form-password" in redaction_findings_for_text('"formPassword": "hunter2"')
    assert "form-password" in redaction_findings_for_text(
        "CRYPTAD_CERT_FORM_PASSWORD=hunter2"
    )
    assert "form-password" in redaction_findings_for_text("--form-password hunter2")
    assert "form-password" in redaction_findings_for_text("--form-password=hunter2")
    assert "form-password" not in redaction_findings_for_text("formPassword=<redacted>")
    assert "form-password" not in redaction_findings_for_text('"formPassword": "<redacted>"')
    assert "form-password" not in redaction_findings_for_text(
        "CRYPTAD_CERT_FORM_PASSWORD=<redacted> \\"
    )
    assert "form-password" not in redaction_findings_for_text("--form-password <redacted>")
    assert "partial-redaction" in redaction_findings_for_text(
        "CRYPTAD_CERT_FORM_PASSWORD=<redacted> hunter2"
    )
    assert "partial-redaction" in redaction_findings_for_text(
        "--form-password <redacted> hunter2"
    )
    assert "token-assignment" in redaction_findings_for_text(
        "CRYPTAD_APP_TOKEN=abcdef0123456789"
    )
    assert "token-assignment" in redaction_findings_for_text(
        '"browserSessionToken": "abcdef0123456789"'
    )
    assert "token-assignment" in redaction_findings_for_text(
        "appProcessToken: abcdef0123456789"
    )
    assert "token-assignment" in redaction_findings_for_text("appToken: abcdef0123456789")
    assert "token-assignment" not in redaction_findings_for_text("CRYPTAD_APP_TOKEN=...")
    assert "token-assignment" not in redaction_findings_for_text(
        '"browserSessionToken": "<opaque-browser-session-token>"'
    )
    assert "private-insert-uri" in redaction_findings_for_text(
        "Insert URI: USK@abcdefghijklmno,qrstuvwxyz0123456789ABCDEFG/name/0"
    )
    assert "private-insert-uri" in redaction_findings_for_text(
        "Insert URI: crypta:SSK@abcdefghijklmno,qrstuvwxyz0123456789ABCDEFG/name"
    )
    assert "private-insert-uri" not in redaction_findings_for_text(
        "Placeholder: crypta:USK@<catalog-key>/cryptad-app-catalog.properties"
    )
    assert "private-insert-uri" not in redaction_findings_for_text(
        "Placeholder: crypta:USK@<example-public-read-key>/profile/0"
    )
    assert "private-insert-uri" not in redaction_findings_for_text(
        "Placeholder: USK@.../profile.json"
    )
    assert "migration-raw-artifact" in redaction_findings_for_text(
        '"rawSocialMessage": "private-message-body"'
    )
    assert "migration-raw-artifact" in redaction_findings_for_text(
        '"raw_social_message": "private-message-body"'
    )
    assert "migration-raw-artifact" in redaction_findings_for_text(
        "rawTrustStatement: trust-statement-json"
    )
    assert "migration-raw-artifact" in redaction_findings_for_text(
        "raw-trust-statement: trust-statement-json"
    )
    assert "migration-raw-artifact" in redaction_findings_for_text(
        "oldPluginExport=serialized-state-with-secrets"
    )
    assert "migration-raw-artifact" in redaction_findings_for_text(
        '"old_plugin_export": "serialized-state-with-secrets"'
    )
    assert "migration-raw-artifact" in redaction_findings_for_text(
        '"raw profile document": "private-profile-document"'
    )
    assert "migration-raw-artifact" in redaction_findings_for_text(
        "rawFproxyHtml: <html><body>private</body></html>"
    )
    assert "migration-raw-artifact" in redaction_findings_for_text(
        '"rawSocialMessage": {\n  "body": "private-message-body"\n}'
    )
    assert "migration-raw-artifact" in redaction_findings_for_text(
        '"rawTrustStatement": [\n  {"issuer": "private-issuer"}\n]'
    )
    assert "migration-raw-artifact" in redaction_findings_for_text(
        "rawSocialMessage: <redacted> private-message-body"
    )
    assert "migration-raw-artifact" in redaction_findings_for_text(
        "rawSupportBundle: private diagnostic body"
    )
    assert "migration-raw-artifact" in redaction_findings_for_text(
        "rawFetchedContent: private fetched body"
    )
    assert "migration-raw-artifact" in redaction_findings_for_text(
        '"rawSocialMessage": "<redacted> private-message-body"'
    )
    assert "migration-raw-artifact" not in redaction_findings_for_text(
        "rawSocialMessage: <redacted>"
    )
    assert "migration-raw-artifact" not in redaction_findings_for_text(
        '"rawSocialMessage": "<redacted>",'
    )
    assert "migration-raw-artifact" not in redaction_findings_for_text(
        "rawSocialMessage: <redacted>\nnextField: summary-only"
    )
    assert "migration-raw-artifact" not in redaction_findings_for_text(
        "The migration guide says raw social messages must never appear in support bundles."
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        "/root/.crypta-dev/keys/dev-local-bundle-private.der"
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        "C:/Users/Alice/.crypta-dev/keys/dev-local-bundle-private.der"
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        "file:///home/alice/.crypta-dev/keys/dev-local-bundle-private.der"
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        "file:///C:/Users/Alice/.crypta-dev/keys/dev-local-bundle-private.der"
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        "/etc/cryptad/form-password"
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        "/var/lib/cryptad/apphost"
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        "/opt/cryptad/config.yml"
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        "file://localhost/home/alice/key.pem"
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        "file:/home/alice/key.pem"
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        "file:/C:/Users/Alice/key.pem"
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        r"\\server\share\crypta\keys\dev-private.der"
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        "file://server/share/crypta/key.pem"
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        "/tmp/crypta-release/keys/private.pem"
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        "file:///tmp/crypta-app-catalog/staged-bundle.zip"
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        "/app/secrets/private.pem"
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        "file:///app/secrets/private.pem"
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        "/content-secret/dev-private.pem"
    )
    assert "local-absolute-path" in redaction_findings_for_text(
        "file:///content-secret/dev-private.pem"
    )
    assert "local-absolute-path" in redaction_findings_for_text("/welcome-back/key.pem")
    assert "local-absolute-path" not in redaction_findings_for_text("/app/node")
    assert "local-absolute-path" not in redaction_findings_for_text("/app/node/")
    assert "local-absolute-path" not in redaction_findings_for_text("file:///app/node")
    assert "local-absolute-path" not in redaction_findings_for_text("file:///app/node/")
    assert "local-absolute-path" not in redaction_findings_for_text("/content")
    assert "local-absolute-path" not in redaction_findings_for_text("/content/")
    assert "local-absolute-path" not in redaction_findings_for_text("/content/fetch")
    assert "local-absolute-path" not in redaction_findings_for_text("/welcome")
    assert "local-absolute-path" not in redaction_findings_for_text("/welcome/")
    assert "local-absolute-path" not in redaction_findings_for_text(
        "/abs/path/outside/repo/dev-private.der"
    )
    assert "local-absolute-path" not in redaction_findings_for_text(
        "file:///abs/path/outside/repo/dev-private.der"
    )
    assert "local-absolute-path" not in redaction_findings_for_text(
        "file:/abs/path/outside/repo/dev-private.der"
    )
    assert "local-absolute-path" not in redaction_findings_for_text("/var/lib/cryptad")


def evidence_by_id(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in summary["evidence"]}


def redaction_findings_for_text(text: str) -> list[str]:
    issues = []
    for issue, pattern in REDACTION_CHECKS:
        if pattern.search(text):
            issues.append(issue)
    if has_disallowed_local_path(text):
        issues.append("local-absolute-path")
    return issues


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    workspace_root = args.workspace_root.resolve()
    if args.self_test:
        run_self_test(workspace_root)
        print("app-platform docs check self-test passed")
        return 0
    summary = run_check(workspace_root)
    output_summary = safe_summary_for_output(summary)
    if args.output:
        write_json(args.output, output_summary)
    else:
        status_text = "passed" if summary["status"] == "pass" else "failed"
        print(f"app-platform docs check {status_text}; use --output for redacted JSON details")
    return 0 if summary["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
