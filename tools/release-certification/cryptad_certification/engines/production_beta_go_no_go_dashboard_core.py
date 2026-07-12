"""Implementation segment for the core portion of ``production_beta_go_no_go_dashboard.py``."""

from __future__ import annotations

import argparse

import base64

import copy

import dataclasses

import datetime as dt

import io

import json

import os

import re

import sys

import tarfile

import tempfile

import zipfile

from pathlib import Path

from typing import Any, Iterable, Iterator

sys.dont_write_bytecode = True

from cryptad_certification.engines import multi_node_beta_soak

from cryptad_certification.engines import security_response_runbook

TOOL_NAME = "production-beta-go-no-go-dashboard"

SCHEMA_VERSION = 1

MODES = ("developer-dry-run", "release-candidate", "production-beta")

DECISIONS = ("go", "no-go", "go-with-waivers")

SEVERITIES = ("info", "warning", "blocker", "critical")

SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITIES)}

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

DEFAULT_GENERATED_AT = "1970-01-01T00:00:00Z"

OUTPUT_JSON = "go-no-go-dashboard.json"

OUTPUT_MARKDOWN = "go-no-go-dashboard.md"

OUTPUT_REDACTION = "go-no-go-redaction-report.json"

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

PLATFORM_API_STABLE_FREEZE_EVIDENCE_IDS = (
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
)

LIVE_NETWORK_REQUIRED_EVIDENCE_IDS = (
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

NETWORK_SCALE_EVIDENCE_IDS = (
    "network-scale.app-network-budget",
    "network-scale.content-fetch-budget",
    "network-scale.subscription-budget",
    "network-scale.queue-pressure-backoff",
    "network-scale.trust-graph-import-budget",
    "network-scale.social-inbox-multi-source-soak",
    "network-scale.redaction",
    "network-scale.rc-soak-summary",
)

MULTI_NODE_BETA_EVIDENCE_IDS = (
    "multi-node-beta.soak",
    "multi-node-beta.upgrade-drill",
    "multi-node-beta.catalog-channel-update",
    "multi-node-beta.app-install-update-rollback",
    "multi-node-beta.app-data-migration",
    "multi-node-beta.backup-restore",
    "multi-node-beta.subscription-pressure",
    "multi-node-beta.trust-graph-import",
    "multi-node-beta.social-inbox-multi-source",
    "multi-node-beta.support-bundle-drill",
    "multi-node-beta.redaction",
)

TRUST_SOCIAL_HARDENING_EVIDENCE_IDS = (
    "app-platform.trust-social-beta-hardening",
    "app-platform.trust-social-content-format-profiles",
    "reference-app.trust-graph",
    "reference-app.trust-graph-durable-exchange",
    "reference-app.trust-graph-app-data-preview",
    "reference-app.social-inbox",
    "reference-app.social-inbox-signed-message",
    "reference-app.social-inbox-subscriptions",
    "reference-app.social-inbox-app-data",
    "reference-app.social-inbox-trust-annotations",
    "reference-app.social-inbox-rc-threading",
)

LEGACY_ADMIN_EVIDENCE_IDS = (
    "legacy-admin.removal-wave-5",
    "legacy-admin.final-admin-surface",
    "legacy-admin.browse-retained",
    "legacy-admin.emergency-fallback-retained",
)

LEGACY_PLUGIN_MIGRATION_EVIDENCE_IDS = ("legacy-plugin.migration-finalization",)

CATALOG_AND_SIGNING_EVIDENCE_IDS = (
    "app-platform.signed-bundles",
    "catalog.smoke",
    "catalog.production-channels",
    "app-review.trusted-receipts",
    "app-review.first-party-catalog",
    "app-review.first-party-review-chain",
)

CONSENT_EVIDENCE_IDS = ("app-platform.user-consent-flow",)

SECURITY_RESPONSE_EVIDENCE_IDS = ("production-security.response-runbook",)

FIRST_PARTY_MAINTENANCE_EVIDENCE_IDS = ("app-catalog.first-party-maintenance-policy",)

FIRST_PARTY_BETA_QUALITY_EVIDENCE_IDS = ("first-party-app.beta-quality-pass",)

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
    "first-party-app.beta-quality-pass",
    "catalog.smoke",
    "app-review.trusted-receipts",
    "app-review.first-party-catalog",
    "app-review.first-party-review-chain",
    *APP_STORE_SUBMISSION_EVIDENCE_IDS,
    *THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS,
    *PLATFORM_API_STABLE_FREEZE_EVIDENCE_IDS,
    "app-platform.trust-social-content-format-profiles",
    "app-platform.privacy-preserving-beta-diagnostics",
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
    "production-security.response-runbook",
    *PUBLIC_BETA_DOCS_EVIDENCE_IDS,
    *LEGACY_PLUGIN_MIGRATION_EVIDENCE_IDS,
    *LEGACY_ADMIN_EVIDENCE_IDS,
)

DASHBOARD_EVIDENCE_IDS = (
    "production-beta.go-no-go-dashboard",
    "production-beta.go-no-go-decision",
    "production-beta.waiver-validation",
    "production-beta.dashboard-redaction",
    "production-beta.launch-artifact-hygiene",
)

STABLE_1_0_READINESS_EVIDENCE_IDS = (
    "stable-1.0.readiness-gate",
    "stable-1.0.production-beta-state",
    "stable-1.0.release-certification",
    "stable-1.0.platform-api-compatibility",
    "stable-1.0.app-ecosystem-maturity",
    "stable-1.0.third-party-intake",
    "stable-1.0.security-drills",
    "stable-1.0.live-multi-node-soak",
    "stable-1.0.legacy-plugin-migration",
    "stable-1.0.support-feedback-readiness",
    "stable-1.0.known-limitations",
    "stable-1.0.redaction",
)

STABLE_1_0_READINESS_DOMAIN_IDS = (
    "readiness-policy",
    "production-beta-state",
    "release-certification-summary",
    "ecosystem-certification-matrix",
    "platform-api-1.0",
    "app-ecosystem-maturity",
    "third-party-intake",
    "security-drills",
    "live-multi-node-soak",
    "legacy-plugin-migration",
    "support-feedback-readiness",
    "known-limitations",
    "redaction",
)

DOMAIN_SPECS = (
    {
        "id": "production-beta-release-pipeline",
        "title": "Production beta release pipeline",
        "evidenceIds": ("production-beta.summary",),
        "artifactInputs": ("productionBetaSummary",),
    },
    {
        "id": "release-certification",
        "title": "Release certification",
        "evidenceIds": ("release-certification.ecosystem-rc-gate",),
        "artifactInputs": ("releaseCertificationSummary",),
    },
    {
        "id": "ecosystem-rc-certification-matrix",
        "title": "Ecosystem RC certification matrix",
        "evidenceIds": ("release-certification.ecosystem-matrix",),
        "artifactInputs": ("ecosystemMatrix",),
    },
    {
        "id": "catalog-and-app-signing",
        "title": "Catalog and app signing",
        "evidenceIds": CATALOG_AND_SIGNING_EVIDENCE_IDS,
        "artifactInputs": ("appPlatformSummary",),
    },
    {
        "id": "first-party-app-maintenance-policy",
        "title": "First-party app maintenance policy",
        "evidenceIds": FIRST_PARTY_MAINTENANCE_EVIDENCE_IDS,
        "artifactInputs": ("appPlatformSummary",),
    },
    {
        "id": "first-party-app-beta-quality",
        "title": "First-party app beta quality",
        "evidenceIds": FIRST_PARTY_BETA_QUALITY_EVIDENCE_IDS,
        "artifactInputs": ("appPlatformSummary",),
    },
    {
        "id": "platform-api-stable-freeze",
        "title": "Platform API 1.0 stable freeze",
        "evidenceIds": PLATFORM_API_STABLE_FREEZE_EVIDENCE_IDS,
        "artifactInputs": ("appPlatformSummary",),
    },
    {
        "id": "stable-1-0-readiness",
        "title": "Stable 1.0 readiness",
        "evidenceIds": STABLE_1_0_READINESS_EVIDENCE_IDS,
        "artifactInputs": ("stableReadinessSummary",),
    },
    {
        "id": "app-submission-review-workflow",
        "title": "App submission and review workflow",
        "evidenceIds": (*APP_STORE_SUBMISSION_EVIDENCE_IDS, *THIRD_PARTY_INTAKE_EVIDENCE_IDS),
        "artifactInputs": ("appPlatformSummary",),
    },
    {
        "id": "user-consent-permission-upgrade",
        "title": "User consent and permission upgrade UX",
        "evidenceIds": CONSENT_EVIDENCE_IDS,
        "artifactInputs": ("appPlatformSummary",),
    },
    {
        "id": "trust-graph-social-inbox-hardening",
        "title": "Trust Graph and Social Inbox beta hardening",
        "evidenceIds": TRUST_SOCIAL_HARDENING_EVIDENCE_IDS,
        "artifactInputs": ("appPlatformSummary",),
    },
    {
        "id": "trust-social-content-format-risk",
        "title": "Trust/social content-format risk",
        "evidenceIds": ("app-platform.trust-social-content-format-profiles",),
        "artifactInputs": ("appPlatformSummary",),
    },
    {
        "id": "privacy-preserving-diagnostics-risk",
        "title": "Privacy-preserving diagnostics risk",
        "evidenceIds": (
            "app-platform.privacy-preserving-beta-diagnostics",
            "operator-beta.support-bundle-redaction",
            "operator-rc.support-bundle-wizard",
            "multi-node-beta.support-bundle-drill",
        ),
        "artifactInputs": ("appPlatformSummary", "multiNodeBetaSoakSummary"),
    },
    {
        "id": "legacy-admin-final-surface",
        "title": "Legacy admin Wave 5 final surface",
        "evidenceIds": LEGACY_ADMIN_EVIDENCE_IDS,
        "artifactInputs": ("appPlatformSummary",),
    },
    {
        "id": "legacy-plugin-migration-finalization",
        "title": "Legacy plugin migration finalization",
        "evidenceIds": LEGACY_PLUGIN_MIGRATION_EVIDENCE_IDS,
        "artifactInputs": ("appPlatformSummary",),
    },
    {
        "id": "production-security-response",
        "title": "Production security response drills",
        "evidenceIds": SECURITY_RESPONSE_EVIDENCE_IDS,
        "artifactInputs": ("securityDrillsSummary", "securityResponseSummary", "appPlatformSummary"),
    },
    {
        "id": "live-network-beta-smoke",
        "title": "Live-network beta smoke",
        "evidenceIds": LIVE_NETWORK_REQUIRED_EVIDENCE_IDS,
        "artifactInputs": ("liveNetworkSummary",),
    },
    {
        "id": "network-scale-soak",
        "title": "Network-scale soak",
        "evidenceIds": NETWORK_SCALE_EVIDENCE_IDS,
        "artifactInputs": ("networkScaleSoakSummary",),
    },
    {
        "id": "multi-node-beta-soak",
        "title": "Multi-node beta soak and upgrade drill",
        "evidenceIds": MULTI_NODE_BETA_EVIDENCE_IDS,
        "artifactInputs": ("multiNodeBetaSoakSummary",),
    },
    {
        "id": "third-party-developer-beta",
        "title": "Third-party developer beta program",
        "evidenceIds": THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS,
        "artifactInputs": ("appPlatformSummary",),
    },
    {
        "id": "public-beta-docs-onboarding",
        "title": "Public beta docs and onboarding",
        "evidenceIds": PUBLIC_BETA_ONBOARDING_EVIDENCE_IDS,
        "artifactInputs": (
            "releaseCertificationSummary",
            "appPlatformSummary",
            "ecosystemMatrix",
        ),
    },
    {
        "id": "public-beta-support-feedback-loop",
        "title": "Public beta support feedback loop",
        "evidenceIds": PUBLIC_BETA_SUPPORT_FEEDBACK_EVIDENCE_IDS,
        "artifactInputs": (
            "productionBetaSummary",
            "releaseCertificationSummary",
            "appPlatformSummary",
            "ecosystemMatrix",
        ),
    },
    {
        "id": "redaction-artifact-hygiene",
        "title": "Redaction and artifact hygiene",
        "evidenceIds": ("production-beta.dashboard-redaction", "production-beta.launch-artifact-hygiene"),
        "artifactInputs": (),
    },
)

CRITICAL_INPUTS_BY_MODE = {
    "developer-dry-run": (),
    "release-candidate": (
        "productionBetaSummary",
        "releaseCertificationSummary",
        "ecosystemMatrix",
        "appPlatformSummary",
        "securityDrillsSummary",
        "networkScaleSoakSummary",
        "multiNodeBetaSoakSummary",
    ),
    "production-beta": (
        "productionBetaSummary",
        "releaseCertificationSummary",
        "ecosystemMatrix",
        "appPlatformSummary",
        "securityDrillsSummary",
        "liveNetworkSummary",
        "networkScaleSoakSummary",
        "multiNodeBetaSoakSummary",
    ),
}

NON_WAIVABLE_EVIDENCE_IDS = {
    "production-beta.dashboard-redaction",
    "production-beta.launch-artifact-hygiene",
    "production-beta.waiver-validation",
    "production-beta.non-release",
    "redaction.status",
}

PRODUCTION_BETA_NON_WAIVABLE_EVIDENCE_IDS = {
    "production-beta.production-signing",
    "production-beta.test-signing",
    "production-beta.build-complete",
    "production-beta.workspace-clean",
    "production-beta.fixture-evidence",
    "signing.production-keys",
    "apphost.sandbox-provider",
    "evidence.required-sandbox-provider-tests",
    "evidence.apphost.sandbox-provider",
    "build.production-beta-complete",
    "build.crypta-app-launcher-install",
    "build.gradle-full-build",
    "build.first-party-app-staging",
    "build.first-party-app-signing",
    "build.first-party-app-verification",
    "workspace.clean-production-beta",
    "fixture-evidence.strict-mode",
    "live.production-beta-skip",
    "live-network-beta.preflight",
    "live-network-beta.catalog-usk-fetch",
    "live-network-beta.app-install-update-rollback",
    "live-network-beta.content-fetch",
    "live-network-beta.feed-subscription",
    "live-network-beta.profile-publish",
    "live-network-beta.trust-statement-publish-import",
    "live-network-beta.interop-perf-budget",
    "live-network-beta.redaction",
    "live.live-network-beta.preflight",
    "live.live-network-beta.catalog-usk-fetch",
    "live.live-network-beta.app-install-update-rollback",
    "live.live-network-beta.content-fetch",
    "live.live-network-beta.feed-subscription",
    "live.live-network-beta.profile-publish",
    "live.live-network-beta.trust-statement-publish-import",
    "live.live-network-beta.interop-perf-budget",
    "live.live-network-beta.redaction",
    "multi-node-beta.soak",
    "multi-node-beta.redaction",
    "multi-node-beta.previous-candidate-summary",
    "multi-node-beta.previous-candidate-summary-validation",
    "multi-node-beta.previous-candidate-upgrade-binding",
    "multi-node-beta.production-evidence-mode",
    "multi-node-beta.upgrade-drill",
    "multi-node-beta.catalog-channel-update",
    "multi-node-beta.app-install-update-rollback",
    "multi-node-beta.app-data-migration",
    "multi-node-beta.backup-restore",
    "multi-node-beta.subscription-pressure",
    "multi-node-beta.trust-graph-import",
    "multi-node-beta.social-inbox-multi-source",
    "multi-node-beta.support-bundle-drill",
    "release-certification.ecosystem-rc-gate",
    "ecosystem.release-candidate-passed",
    "ecosystem.certification-matrix",
    "legacy-plugin.migration-finalization",
    "evidence.legacy-plugin.migration-finalization",
}

PRODUCTION_ARTIFACT_GATE_IDS = {
    "artifact.signed-first-party-bundles",
    "artifact.signed-first-party-catalog",
    "artifact.first-party-review-receipts",
}

def evidence_ids_with_gate_aliases(evidence_ids: Iterable[str]) -> set[str]:
    ids: set[str] = set()
    for evidence_id in evidence_ids:
        ids.add(evidence_id)
        ids.add(f"evidence.{evidence_id}")
    return ids

def non_waivable_evidence_ids_for_mode(mode: str) -> set[str]:
    ids = set(NON_WAIVABLE_EVIDENCE_IDS)
    if mode == "production-beta":
        ids.update(PRODUCTION_BETA_NON_WAIVABLE_EVIDENCE_IDS)
        ids.update(evidence_ids_with_gate_aliases(CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS))
        ids.update(PRODUCTION_ARTIFACT_GATE_IDS)
    return ids

def evidence_id_is_non_waivable_in_mode(evidence_id: str, mode: str) -> bool:
    return evidence_id in non_waivable_evidence_ids_for_mode(mode)

REDACTION_FINDING_KINDS = {
    "private-insert-uri",
    "private-key",
    "private-key-header",
    "openssh-private-key",
    "bearer-token",
    "authorization-header",
    "cookie-header",
    "url-userinfo",
    "app-token",
    "browser-session-token",
    "form-password",
    "raw-content-or-app-data",
    "ci-secret-value",
    "protected-secret-value",
    "sensitive-field-value",
    "file-uri-local-path",
    "windows-local-path",
    "host-local-path",
    "workspace-path",
    "home-path",
    "temp-path",
    "forbidden-path",
    "forbidden-zip-entry",
    "forbidden-tar-entry",
    "unreadable",
}

BAD_ARTIFACT_NAMES = {".DS_Store"}

BAD_ARTIFACT_DIRS = {"__MACOSX"}

ZIP_ARCHIVE_SUFFIXES = {".zip", ".jar"}

TAR_GZ_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz")

MAX_NESTED_ARCHIVE_DEPTH = 4

TEXT_SCAN_CHUNK_BYTES = 1024 * 1024

TEXT_SCAN_OVERLAP_BYTES = 64 * 1024

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

OPENSSH_PRIVATE_KEY_RE = re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----", re.IGNORECASE)

BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE)

AUTH_HEADER_RE = re.compile(
    r"(?<![\w-])[\"']?Authorization[\"']?(?![\w-])"
    r"\s*(?::|(?<![=!<>])=(?!=))\s*[\"']?(?:Bearer|Basic|Digest)?\s*([^\s,'\"}]+)",
    re.IGNORECASE,
)

COOKIE_HEADER_RE = re.compile(
    r"(?<![\w-])[\"']?(?:Cookie|Set-Cookie)[\"']?(?![\w-])"
    r"\s*(?::|(?<![=!<>])=(?!=))\s*[\"']?([^'\"\r\n}]+)",
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

SENSITIVE_FIELD_VALUE_RE = re.compile(
    r"(?P<key>\"(?:\\.|[^\"\\])*\"|[A-Za-z_][A-Za-z0-9_-]*)"
    r"\s*:\s*"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|[^\s,}\]]+)",
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

SENSITIVE_NORMALIZED_KEYS = frozenset(
    {
        "privatekey",
        "privatekeybase64",
        "privatekeyfile",
        "privateinserturi",
        "token",
        "password",
        "formpassword",
        "browsersessiontoken",
        "appprocesstoken",
        "authorization",
        "cookie",
        "rawappdatavalue",
        "rawfetchedcontent",
    }
)

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
    r"(?:Users|home|work|workspace|tmp|private/tmp|var/folders|mnt|Volumes|root|opt|runner|__w|srv|etc)"
    r"(?:/[^\s\"'<>),;]+)+"
)

SECRET_ARTIFACT_NAME_RE = re.compile(
    r"(?:^|[._-])(?:"
    r"private[._-]*key|signing[._-]*private(?:[._-]*key)?|reviewer[._-]*private(?:[._-]*key)?|"
    r"private[._-]*insert[._-]*uri|insert[._-]*uri|app[._-]*token|browser[._-]*session[._-]*token|"
    r"form[._-]*password|bearer[._-]*token|id[._-]*(?:rsa|dsa|ecdsa|ed25519)"
    r")(?:$|[._-])",
    re.IGNORECASE,
)

FORBIDDEN_SECRET_ARTIFACT_SUFFIXES = {".p12", ".pfx", ".jks", ".keystore", ".p8", ".pkcs8"}

SECRET_ARTIFACT_BINARY_SUFFIXES = {".der", ".key", ".pem", ".bin"}

SECRET_ARTIFACT_BINARY_MARKERS = ("private", "secret", "password", "token", "inserturi")

@dataclasses.dataclass(frozen=True)
class Issue:
    id: str
    evidence_id: str
    domain_id: str
    severity: str
    title: str
    summary: str
    source: str
    waivable: bool
    category: str
    waived_by: str = ""

    def to_json(self) -> dict[str, Any]:
        value = {
            "id": self.id,
            "evidenceId": self.evidence_id,
            "domainId": self.domain_id,
            "severity": self.severity,
            "title": self.title,
            "summary": self.summary,
            "source": self.source,
            "waivable": self.waivable,
            "category": self.category,
        }
        if self.waived_by:
            value["waivedBy"] = self.waived_by
        return value

@dataclasses.dataclass(frozen=True)
class Waiver:
    id: str
    evidence_id: str
    severity: str
    scope: str
    rationale: str
    approved_by: str
    owner: str
    created_at: str
    expires_at: str
    references: tuple[str, ...]
    source: str
    active: bool
    applies_to_mode: bool
    external_risk_accepted: bool
    validation_errors: tuple[str, ...]
    used_by: tuple[str, ...] = ()

    def matches(self, issue: Issue) -> bool:
        candidates = expand_waiver_target_aliases(
            issue.id,
            issue.evidence_id,
            issue.domain_id,
            f"evidence.{issue.evidence_id}",
        )
        targets = expand_waiver_target_aliases(self.id, self.evidence_id)
        return bool(candidates & targets)

    def with_usage(self, issue_ids: Iterable[str]) -> "Waiver":
        return dataclasses.replace(self, used_by=tuple(sorted(set(issue_ids))))

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "evidenceId": self.evidence_id,
            "severity": self.severity,
            "scope": self.scope,
            "rationale": self.rationale,
            "approvedBy": self.approved_by,
            "owner": self.owner,
            "createdAt": self.created_at,
            "expiresAt": self.expires_at,
            "references": list(self.references),
            "source": self.source,
            "active": self.active,
            "appliesToMode": self.applies_to_mode,
            "externalRiskAccepted": self.external_risk_accepted,
            "validationErrors": list(self.validation_errors),
            "usedBy": list(self.used_by),
        }

def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

def live_network_target_aliases(value: str) -> set[str]:
    aliases = {value}
    if value.startswith("live."):
        aliases.add(value.removeprefix("live."))
    elif value.startswith("live-network-beta."):
        aliases.add(f"live.{value}")
    if value.startswith("evidence.live."):
        aliases.add(f"evidence.{value.removeprefix('evidence.live.')}")
    elif value.startswith("evidence.live-network-beta."):
        aliases.add(f"evidence.live.{value.removeprefix('evidence.')}")
    return aliases

def evidence_prefix_target_aliases(value: str) -> set[str]:
    aliases = {value}
    if value.startswith("evidence."):
        aliases.add(value.removeprefix("evidence."))
    elif "." in value:
        aliases.add(f"evidence.{value}")
    return aliases

def canonical_evidence_id(value: str) -> str:
    return value.removeprefix("evidence.")

def expand_waiver_target_aliases(*values: str) -> set[str]:
    aliases: set[str] = set()
    for value in values:
        if not value:
            continue
        for alias in evidence_prefix_target_aliases(value):
            aliases.update(live_network_target_aliases(alias))
    return aliases

def format_time(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def parse_time(value: str) -> dt.datetime | None:
    raw = value.strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)

def parse_generated_at(value: str | None) -> tuple[str, dt.datetime]:
    if value:
        parsed = parse_time(value)
        if parsed is None:
            raise SystemExit("--generated-at must be an ISO-8601 timestamp")
        return format_time(parsed), parsed
    now = utc_now()
    return format_time(now), now

def read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None

def read_json_object_with_error(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"Waiver file could not be read: {exc.strerror or exc.__class__.__name__}."
    except UnicodeDecodeError:
        return None, "Waiver file must be UTF-8 encoded JSON."
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"Waiver file is malformed JSON at line {exc.lineno}, column {exc.colno}."
    if not isinstance(value, dict):
        return None, f"Waiver file must contain a JSON object, found {type(value).__name__}."
    return value, None

def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")

def display_path(path: Path, workspace_root: Path) -> str:
    try:
        return path.resolve().relative_to(workspace_root.resolve()).as_posix()
    except (OSError, ValueError):
        return f"<workdir>/{path.name}"

def display_unresolved_path(path: Path, workspace_root: Path) -> str:
    try:
        absolute_path = Path(os.path.abspath(path))
        absolute_root = Path(os.path.abspath(workspace_root))
        return absolute_path.relative_to(absolute_root).as_posix()
    except (OSError, ValueError):
        return f"<workdir>/{path.name}"

def resolve_workspace_input_path(raw_path: str, workspace_root: Path | None) -> Path | None:
    value = raw_path.strip()
    if not value:
        return None
    path = Path(value).expanduser()
    if not path.is_absolute() and workspace_root is not None:
        path = workspace_root / path
    try:
        return path.resolve()
    except OSError:
        return None

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
    env: dict[str, str] | None = None,
    workspace_root: Path | None = None,
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

def redact_protected_secret_values(text: str, workspace_root: Path | None) -> str:
    result = text
    for _name, value in sorted(
        protected_secret_environment_values(workspace_root=workspace_root),
        key=lambda item: (-len(item[1]), item[0], item[1]),
    ):
        result = result.replace(value, "<redacted-protected-secret>")
    return result

def redact_captured_value(text: str, regex: re.Pattern[str], replacement: str) -> str:
    def replace(match: re.Match[str]) -> str:
        start, end = match.span(1)
        relative_start = start - match.start()
        relative_end = end - match.start()
        return f"{match.group(0)[:relative_start]}{replacement}{match.group(0)[relative_end:]}"

    return regex.sub(replace, text)

def scrub_text(value: str, workspace_root: Path, out_dir: Path) -> str:
    text = value
    replacements = (
        (str(workspace_root.resolve()), "<repo>"),
        (str(out_dir.resolve()), "<dashboard-out>"),
        (str(Path.home().resolve()), "<home>"),
        (tempfile.gettempdir(), "<workdir>"),
    )
    for needle, replacement in replacements:
        if needle:
            text = text.replace(needle, replacement)
            text = text.replace(needle.replace("\\", "/"), replacement)
    text = PRIVATE_KEY_RE.sub("<redacted-private-key>", text)
    text = PRIVATE_KEY_HEADER_RE.sub("<redacted-private-key>", text)
    text = OPENSSH_PRIVATE_KEY_RE.sub("<redacted-private-key>", text)
    text = PRIVATE_INSERT_URI_RE.sub("<redacted-private-insert-uri>", text)
    text = URL_USERINFO_RE.sub("<redacted-url-userinfo>@", text)
    text = FILE_URI_RE.sub("<redacted-file-uri>", text)
    text = redact_captured_value(text, AUTH_HEADER_RE, "<redacted-authorization>")
    text = redact_captured_value(text, COOKIE_HEADER_RE, "<redacted-cookie>")
    text = redact_captured_value(text, APP_TOKEN_VALUE_RE, "<redacted-token>")
    text = redact_captured_value(text, FORM_PASSWORD_VALUE_RE, "<redacted-password>")
    text = redact_captured_value(text, RAW_BODY_VALUE_RE, "<redacted-raw-payload>")
    text = redact_captured_value(text, CI_SECRET_VALUE_RE, "<redacted-ci-secret>")
    text = BEARER_RE.sub("Bearer <redacted-token>", text)
    text = HOST_PATH_RE.sub("<redacted-absolute-path>", text)
    text = WINDOWS_PATH_RE.sub("<redacted-absolute-path>", text)
    text = redact_protected_secret_values(text, workspace_root)
    return text

def sanitize_value(value: Any, workspace_root: Path, out_dir: Path) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in sorted(value.items(), key=lambda item: str(item[0])):
            key_text = str(key)
            normalized = re.sub(r"[^a-z0-9]", "", key_text.lower())
            if normalized in SENSITIVE_NORMALIZED_KEYS:
                result[key_text] = "<redacted>"
            else:
                result[key_text] = sanitize_value(child, workspace_root, out_dir)
        return result
    if isinstance(value, list):
        return [sanitize_value(child, workspace_root, out_dir) for child in value]
    if isinstance(value, str):
        return scrub_text(value, workspace_root, out_dir)
    return value

def normalize_status(value: Any) -> str:
    status = str(value or "missing").strip().lower()
    return {
        "success": "pass",
        "ok": "pass",
        "passed": "pass",
        "failure": "fail",
        "failed": "fail",
        "warning": "warn",
        "warnings": "warn",
        "not-run": "skip",
    }.get(status, status if status in {"pass", "warn", "fail", "skip", "missing"} else "missing")

def entry_has_redaction_findings(entry: dict[str, Any] | None) -> bool:
    return recursive_redaction_field_failure(entry)

def redaction_proof_key(key: Any) -> bool:
    lowered = str(key).lower()
    return lowered.endswith(
        ("excluded", "excludedfromevidence", "redacted", "sanitized", "stored")
    ) or (
        lowered.startswith("raw")
        and lowered.endswith(("included", "persisted", "inevidence"))
    ) or (
        "redaction" in lowered
        and lowered.endswith(("clean", "ok", "passed", "checkspass"))
    ) or (
        "redaction" in lowered and lowered.endswith("status")
    )

def redaction_proof_failure(key: Any, value: Any) -> bool:
    lowered = str(key).lower()
    if "redaction" in lowered and lowered.endswith("status"):
        return not isinstance(value, str) or value.strip().lower() != "pass"
    if "redaction" in lowered and lowered.endswith(
        ("clean", "ok", "passed", "checkspass")
    ):
        return value is not True
    if lowered.endswith(("excluded", "excludedfromevidence", "redacted", "sanitized")):
        return value is not True
    if lowered.endswith("stored"):
        return value is not False
    return (
        lowered.startswith("raw")
        and lowered.endswith(("included", "persisted", "inevidence"))
        and value is not False
    )

def recursive_redaction_failure(value: Any, *, include_summary_fields: bool = True) -> bool:
    if isinstance(value, dict):
        if "redaction" in value and recursive_redaction_failure(value["redaction"]):
            return True
        if include_summary_fields:
            redaction_findings = value.get("redactionFindings")
            if "redactionFindings" in value and not isinstance(redaction_findings, list):
                return True
            if isinstance(redaction_findings, list) and bool(redaction_findings):
                return True
            findings = value.get("findings")
            if "findings" in value and not isinstance(findings, list):
                return True
            if isinstance(findings, list) and bool(findings):
                return True
            for count_key in ("findingCount", "criticalFindingCount"):
                finding_count, malformed_finding_count = parse_release_blocker_count(
                    value.get(count_key, 0)
                )
                if malformed_finding_count or finding_count > 0:
                    return True
            status = value.get("status")
            if "status" in value and (
                not isinstance(status, str) or status.strip().lower() != "pass"
            ):
                return True
        for key, child in value.items():
            if key == "redaction":
                continue
            if redaction_proof_failure(key, child):
                return True
            if recursive_redaction_failure(child, include_summary_fields=include_summary_fields):
                return True
    elif isinstance(value, list):
        return any(
            recursive_redaction_failure(child, include_summary_fields=include_summary_fields)
            for child in value
        )
    return False

def recursive_redaction_field_failure(value: Any) -> bool:
    if isinstance(value, dict):
        redaction_payload = {
            key: child
            for key, child in value.items()
            if redaction_signal_key(key)
        }
        if redaction_payload and recursive_redaction_failure(redaction_payload):
            return True
        return any(
            recursive_redaction_field_failure(child)
            for child in value.values()
            if isinstance(child, (dict, list))
        )
    if isinstance(value, list):
        return any(recursive_redaction_field_failure(child) for child in value)
    return False

def redaction_signal_key(key: Any) -> bool:
    lowered = str(key).lower()
    return (
        "redaction" in lowered
        or lowered in {"findings", "findingcount", "criticalfindingcount"}
        or redaction_proof_key(key)
    )

def entry_waiver_id(entry: dict[str, Any] | None) -> str:
    if not isinstance(entry, dict):
        return ""
    details = entry.get("details", {})
    if not isinstance(details, dict) or details.get("waived") is not True:
        return ""
    return str(details.get("waiverId", "")).strip()

def status_ok(entry: dict[str, Any] | None) -> bool:
    if not isinstance(entry, dict):
        return False
    if entry_has_redaction_findings(entry):
        return False
    return normalize_status(entry.get("status")) == "pass"

def status_warn(entry: dict[str, Any] | None) -> bool:
    return isinstance(entry, dict) and normalize_status(entry.get("status")) == "warn"

def evidence_entries(summary: dict[str, Any] | None, evidence_id: str) -> list[dict[str, Any]]:
    if not isinstance(summary, dict):
        return []
    entries = summary.get("evidence", [])
    if not isinstance(entries, list):
        return []
    return [
        entry
        for entry in entries
        if isinstance(entry, dict) and str(entry.get("id", "")) == evidence_id
    ]

def evidence_details(entry: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    details = entry.get("details")
    return details if isinstance(details, dict) else {}

def security_response_app_component(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    candidates: list[dict[str, Any]] = []
    for entry in entries:
        details = evidence_details(entry)
        component = details.get("appPlatformRunbook")
        if isinstance(component, dict):
            candidates.append(component)
        elif not isinstance(details.get("securityDrills"), dict):
            candidates.append(entry)
    return worst_status_entry(candidates or entries)

def worst_status_entry(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not entries:
        return None
    rank = {"fail": 0, "missing": 1, "skip": 2, "warn": 3, "pass": 4}
    return sorted(
        entries,
        key=lambda entry: rank.get(normalize_status(entry.get("status")), -1),
    )[0]

def combined_security_response_status(entries: list[dict[str, Any]]) -> str:
    statuses = [normalize_status(entry.get("status")) for entry in entries if isinstance(entry, dict)]
    for status in ("fail", "missing", "skip", "warn"):
        if status in statuses:
            return status
    return "pass"

def security_response_redaction_findings(entries: list[dict[str, Any]]) -> list[Any]:
    findings: list[Any] = []
    for entry in entries:
        details = evidence_details(entry)
        item_findings = details.get("redactionFindings")
        if isinstance(item_findings, list):
            findings.extend(item_findings)
    return findings

def combine_security_response_evidence(
    existing_entries: list[dict[str, Any]],
    drill_entry: dict[str, Any],
) -> dict[str, Any]:
    app_entry = security_response_app_component(existing_entries)
    if app_entry is None:
        app_entry = {
            "id": "production-security.response-runbook",
            "requiredForReleaseCandidate": True,
            "source": "app-platform-smoke",
            "status": "missing",
            "summary": "App-platform security response runbook evidence is missing.",
            "details": {},
        }
    components = [app_entry, drill_entry]
    status = combined_security_response_status(components)
    if status == "pass":
        summary = "Production security response runbook and operational drills passed."
    else:
        summary = (
            "Production security response is not promotion-ready: "
            f"appPlatformRunbook={normalize_status(app_entry.get('status'))}, "
            f"securityDrills={normalize_status(drill_entry.get('status'))}."
        )
    details: dict[str, Any] = {
        "appPlatformRunbook": app_entry,
        "securityDrills": drill_entry,
        "componentStatuses": {
            "appPlatformRunbook": normalize_status(app_entry.get("status")),
            "securityDrills": normalize_status(drill_entry.get("status")),
        },
    }
    redaction_findings = security_response_redaction_findings([*existing_entries, drill_entry])
    if redaction_findings:
        details["redactionFindings"] = redaction_findings
    return {
        "id": "production-security.response-runbook",
        "requiredForReleaseCandidate": True,
        "source": "; ".join(
            str(entry.get("source", "production-security.response-runbook"))
            for entry in components
        ),
        "status": status,
        "summary": summary,
        "details": details,
    }

def evidence_map(*summaries: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for summary in summaries:
        if not isinstance(summary, dict):
            continue
        entries = summary.get("evidence", [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict) and entry.get("id"):
                result[str(entry["id"])] = entry
    return result

def multi_node_scenario_evidence(summary: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(summary, dict):
        return {}
    scenario_statuses = summary.get("scenarioStatuses")
    if not isinstance(scenario_statuses, dict):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for scenario_id, scenario_status in scenario_statuses.items():
        evidence_id = multi_node_beta_soak.SCENARIO_EVIDENCE_IDS.get(
            str(scenario_id),
            f"multi-node-beta.{scenario_id}",
        )
        status = normalize_status(scenario_status)
        result[evidence_id] = {
            "id": evidence_id,
            "status": status,
            "summary": f"Multi-node beta scenario {scenario_id} status is {status}.",
            "source": "multi-node-beta-soak-summary",
        }
    return result

def security_response_evidence(
    summary: dict[str, Any] | None,
    source: str = "security-response-summary",
    production: bool = False,
    strict: bool = False,
    now: dt.datetime | None = None,
    expected_release_id: str | None = None,
    expected_mode: str | None = None,
    summary_path: Path | None = None,
) -> dict[str, Any] | None:
    if not isinstance(summary, dict):
        if source == "security-drills-summary":
            return {
                "id": "production-security.response-runbook",
                "requiredForReleaseCandidate": True,
                "source": source,
                "status": "fail",
                "summary": "Security response drills summary must be an aggregate JSON object.",
                "details": {
                    "summaryRequired": True,
                    "promotionReady": False,
                    "validationErrors": ["securityDrillsSummary must be an object"],
                    "redactionClean": False,
                },
            }
        return None
    if source == "security-drills-summary" and summary.get("kind") != "cryptad-security-response-drills-summary":
        return {
            "id": "production-security.response-runbook",
            "requiredForReleaseCandidate": True,
            "source": source,
            "status": "fail",
            "summary": "Security response drills summary must use the aggregate drill-summary envelope.",
            "details": {
                "summaryRequired": True,
                "summaryStatus": summary.get("status", "missing"),
                "promotionReady": False,
                "kind": summary.get("kind", "missing"),
                "validationErrors": ["kind must be cryptad-security-response-drills-summary"],
                "redactionClean": False,
            },
        }
    if summary.get("kind") == "cryptad-security-response-drills-summary":
        validation = security_response_runbook.validate_drills_summary(
            summary,
            production=production,
            strict=strict,
            now=now,
            expected_mode=expected_mode,
        )
        validation_errors = list(validation.get("errors", [])) if isinstance(validation.get("errors"), list) else []
        artifact_validation: dict[str, Any] | None = None
        artifact_redaction_findings: list[Any] = []
        if summary_path is not None:
            artifact_validation = security_response_runbook.validate_drill_artifact_files(
                summary,
                summary_path,
                model_path=Path(__file__).resolve().parent
                / "production-security-response-runbook.json",
                strict=strict,
                now=now,
            )
            artifact_errors = artifact_validation.get("errors")
            if isinstance(artifact_errors, list):
                validation_errors.extend(str(error) for error in artifact_errors)
            artifact_findings = artifact_validation.get("redactionFindings")
            if isinstance(artifact_findings, list):
                artifact_redaction_findings.extend(artifact_findings)
        release_id = summary.get("releaseId")
        release_id_matches = not (
            strict
            and expected_release_id
            and release_id != expected_release_id
        )
        if not release_id_matches:
            validation_errors.append(
                f"releaseId must match dashboard candidate {expected_release_id}"
            )
        counts = summary.get("counts") if isinstance(summary.get("counts"), dict) else {}
        redaction = summary.get("redaction") if isinstance(summary.get("redaction"), dict) else {}
        declared_redaction_findings = (
            redaction.get("findings") if isinstance(redaction.get("findings"), list) else []
        )
        validator_redaction_findings = (
            validation.get("redactionFindings")
            if isinstance(validation.get("redactionFindings"), list)
            else []
        )
        redaction_findings = security_response_runbook.safe_redaction_findings(
            [
                *declared_redaction_findings,
                *validator_redaction_findings,
                *artifact_redaction_findings,
            ]
        )
        required_scenarios = (
            summary.get("requiredScenarios") if isinstance(summary.get("requiredScenarios"), list) else []
        )
        passed_scenarios = (
            summary.get("passedScenarios") if isinstance(summary.get("passedScenarios"), list) else []
        )
        failed_scenarios = (
            summary.get("failedScenarios") if isinstance(summary.get("failedScenarios"), list) else []
        )
        missing_scenarios = (
            summary.get("missingScenarios") if isinstance(summary.get("missingScenarios"), list) else []
        )
        stale_scenarios = (
            summary.get("staleScenarios") if isinstance(summary.get("staleScenarios"), list) else []
        )
        malformed_scenarios = (
            summary.get("malformedScenarios") if isinstance(summary.get("malformedScenarios"), list) else []
        )
        artifacts_valid = (
            artifact_validation is None
            or artifact_validation.get("status") == "pass"
        )
        status = (
            "pass"
            if validation.get("status") == "pass" and release_id_matches and artifacts_valid
            else "fail"
        )
        required = safe_int_count(counts.get("required"), len(security_response_runbook.REQUIRED_DRILLS))
        passed = safe_int_count(counts.get("passed"), len(passed_scenarios))
        if status == "pass":
            summary_text = f"Security response drills passed for {passed}/{required} required scenarios."
        else:
            summary_text = (
                "Security response drills are missing, failed, stale, malformed, fixture-only, "
                "or redaction-unsafe."
            )
        return {
            "id": "production-security.response-runbook",
            "requiredForReleaseCandidate": True,
            "source": source,
            "status": status,
            "summary": summary_text,
            "details": {
                "summaryStatus": summary.get("status", "missing"),
                "promotionReady": bool(summary.get("promotionReady")),
                "nonRelease": bool(summary.get("nonRelease")),
                "fixtureOnly": bool(summary.get("fixtureOnly")),
                "mode": summary.get("mode", "missing"),
                "evidenceMode": summary.get("evidenceMode", "missing"),
                "releaseId": release_id if isinstance(release_id, str) else "missing",
                "expectedReleaseId": expected_release_id or "not-required",
                "releaseIdMatchesDashboard": release_id_matches,
                "generatedAt": summary.get("generatedAt", "missing"),
                "counts": counts,
                "requiredScenarios": required_scenarios,
                "passedScenarios": passed_scenarios,
                "failedScenarios": failed_scenarios,
                "missingScenarios": missing_scenarios,
                "staleScenarios": stale_scenarios,
                "malformedScenarios": malformed_scenarios,
                "redaction": redaction,
                "redactionFindings": redaction_findings,
                "releaseNotes": summary.get("releaseNotes", {}),
                "advisoryTemplate": summary.get("advisoryTemplate", {}),
                "artifacts": summary.get("artifacts", []),
                "artifactValidation": artifact_validation or {},
                "validationErrors": validation_errors,
                "redactionClean": (
                    validation.get("redactionClean", False)
                    and not artifact_redaction_findings
                ),
            },
        }
    status = normalize_status(summary.get("status"))
    if status == "missing":
        return None
    summary_text = (
        "Production security response runbook passed."
        if status == "pass"
        else f"Production security response runbook status is {status}."
    )
    return {
        "id": "production-security.response-runbook",
        "requiredForReleaseCandidate": True,
        "source": source,
        "status": status,
        "summary": summary_text,
    }

def evidence_summary(entry: dict[str, Any] | None) -> str:
    if not isinstance(entry, dict):
        return "Required evidence is missing."
    return str(entry.get("summary") or f"Evidence status is {normalize_status(entry.get('status'))}.")

def issue_id(domain_id: str, evidence_id: str, suffix: str = "status") -> str:
    raw = f"{domain_id}.{evidence_id}.{suffix}".lower()
    return re.sub(r"[^a-z0-9_.-]+", "-", raw).strip("-")

def is_redaction_evidence(evidence_id: str, domain_id: str = "") -> bool:
    lowered = f"{domain_id} {evidence_id}".lower()
    return "redaction" in lowered or "hygiene" in lowered or evidence_id in {
        "production-beta.dashboard-redaction",
        "production-beta.launch-artifact-hygiene",
    }

def issue_for_evidence(domain_id: str, evidence_id: str, entry: dict[str, Any] | None, mode: str) -> Issue | None:
    if status_ok(entry):
        return None
    if evidence_id.startswith("third-party-intake.") and not isinstance(entry, dict):
        return Issue(
            id=issue_id(domain_id, evidence_id, "optional-missing"),
            evidence_id=evidence_id,
            domain_id=domain_id,
            severity="warning",
            title=f"{evidence_id} is not attached",
            summary="Third-party intake evidence is not required for this dashboard unless the release wrapper requires it.",
            source=domain_id,
            waivable=True,
            category="optional-evidence",
        )
    waiver_id = "" if entry_has_redaction_findings(entry) else entry_waiver_id(entry)
    if waiver_id and status_warn(entry):
        return Issue(
            id=issue_id(domain_id, evidence_id, "waived"),
            evidence_id=evidence_id,
            domain_id=domain_id,
            severity="blocker",
            title=f"{evidence_id} is waived",
            summary=evidence_summary(entry),
            source=str(entry.get("source", domain_id)) if isinstance(entry, dict) else domain_id,
            waivable=True,
            category="evidence-waiver",
            waived_by=waiver_id,
        )
    if entry_has_redaction_findings(entry):
        details = entry.get("details", {}) if isinstance(entry, dict) else {}
        findings = details.get("redactionFindings") if isinstance(details, dict) else []
        finding_count = len(findings) if isinstance(findings, list) else 1
        return Issue(
            id=issue_id(domain_id, evidence_id, "redaction"),
            evidence_id=evidence_id,
            domain_id=domain_id,
            severity="critical",
            title=f"{evidence_id} has redaction findings",
            summary=f"{evidence_summary(entry)} Redaction findings reported: {finding_count}.",
            source=str(entry.get("source", domain_id)) if isinstance(entry, dict) else domain_id,
            waivable=False,
            category="redaction",
        )
    if status_warn(entry):
        return Issue(
            id=issue_id(domain_id, evidence_id, "warning"),
            evidence_id=evidence_id,
            domain_id=domain_id,
            severity="warning",
            title=f"{evidence_id} is warning",
            summary=evidence_summary(entry),
            source=str(entry.get("source", domain_id)) if isinstance(entry, dict) else domain_id,
            waivable=True,
            category="evidence",
        )
    severity = "critical" if is_redaction_evidence(evidence_id, domain_id) else "blocker"
    return Issue(
        id=issue_id(domain_id, evidence_id),
        evidence_id=evidence_id,
        domain_id=domain_id,
        severity=severity,
        title=f"{evidence_id} is not passing",
        summary=evidence_summary(entry),
        source=str(entry.get("source", domain_id)) if isinstance(entry, dict) else domain_id,
        waivable=severity != "critical" and not evidence_id_is_non_waivable_in_mode(evidence_id, mode),
        category="evidence",
    )

def domain_status(issues: list[Issue]) -> str:
    if any(issue.severity in {"critical", "blocker"} and not issue.waived_by for issue in issues):
        return "fail"
    if any(issue.waived_by for issue in issues):
        return "waived"
    if any(issue.severity == "warning" for issue in issues):
        return "warn"
    return "pass"

def scan_safe_value(raw_value: str, allow_code_like: bool = True) -> bool:
    value = raw_value.strip().strip("'\"").rstrip(",;")
    if not value:
        return True
    normalized = value.lower()
    if normalized in {"<redacted>", "redacted", "[redacted]", "<masked>", "masked", "[masked]", "***", "null", "undefined", "unset", "true", "false", "none"}:
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
    return False

def decode_json_like_token(raw_value: str) -> str:
    value = raw_value.strip()
    if value.startswith('"') and value.endswith('"'):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return value.strip('"')
        return decoded if isinstance(decoded, str) else str(decoded)
    return value

def add_sensitive_field_value_findings(findings: list[dict[str, str]], text: str, rel_path: str) -> None:
    for match in SENSITIVE_FIELD_VALUE_RE.finditer(text):
        key = decode_json_like_token(match.group("key"))
        normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
        if normalized_key not in SENSITIVE_NORMALIZED_KEYS:
            continue
        value = decode_json_like_token(match.group("value"))
        if not scan_safe_value(value, allow_code_like=False):
            findings.append(
                {
                    "path": rel_path,
                    "kind": "sensitive-field-value",
                    "detail": f"{key} field appeared unredacted.",
                }
            )
            return

def add_value_findings(
    findings: list[dict[str, str]],
    text: str,
    rel_path: str,
    kind: str,
    regex: re.Pattern[str],
    allow_code_like: bool = True,
) -> None:
    for match in regex.finditer(text):
        value = match.group(1)
        if not scan_safe_value(value, allow_code_like=allow_code_like):
            findings.append({"path": rel_path, "kind": kind})
            return

def add_protected_secret_value_findings(
    findings: list[dict[str, str]],
    text: str,
    rel_path: str,
    workspace_root: Path | None,
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

def bad_artifact_name(rel_path: str) -> str | None:
    parts = re.split(r"[\\/]+", rel_path)
    for part in parts:
        if not part:
            continue
        if part.startswith("._"):
            return "AppleDouble file is not allowed"
        if part in BAD_ARTIFACT_NAMES:
            return f"{part} is not allowed"
        if part in BAD_ARTIFACT_DIRS:
            return f"{part} directory is not allowed"
        lower = part.lower()
        suffix = Path(lower).suffix
        collapsed = re.sub(r"[^a-z0-9]", "", lower)
        if suffix in FORBIDDEN_SECRET_ARTIFACT_SUFFIXES:
            return f"{suffix} key-store artifact is not allowed"
        if SECRET_ARTIFACT_NAME_RE.search(lower):
            return "secret-bearing artifact filename is not allowed"
        if suffix in SECRET_ARTIFACT_BINARY_SUFFIXES and any(
            marker in collapsed for marker in SECRET_ARTIFACT_BINARY_MARKERS
        ):
            return "binary secret/key artifact filename is not allowed"
    return None

def scan_text_for_findings(text: str, rel_path: str, workspace_root: Path, out_dir: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    checks = (
        ("private-insert-uri", PRIVATE_INSERT_URI_RE),
        ("private-key", PRIVATE_KEY_RE),
        ("private-key-header", PRIVATE_KEY_HEADER_RE),
        ("openssh-private-key", OPENSSH_PRIVATE_KEY_RE),
        ("bearer-token", BEARER_RE),
        ("url-userinfo", URL_USERINFO_RE),
        ("file-uri-local-path", FILE_URI_RE),
        ("windows-local-path", WINDOWS_PATH_RE),
        ("host-local-path", HOST_PATH_RE),
    )
    for kind, regex in checks:
        if regex.search(text):
            findings.append({"path": rel_path, "kind": kind})
    add_value_findings(findings, text, rel_path, "authorization-header", AUTH_HEADER_RE, allow_code_like=False)
    add_value_findings(findings, text, rel_path, "cookie-header", COOKIE_HEADER_RE, allow_code_like=False)
    add_value_findings(findings, text, rel_path, "app-token", APP_TOKEN_VALUE_RE, allow_code_like=False)
    add_value_findings(findings, text, rel_path, "form-password", FORM_PASSWORD_VALUE_RE, allow_code_like=False)
    add_value_findings(findings, text, rel_path, "raw-content-or-app-data", RAW_BODY_VALUE_RE, allow_code_like=False)
    add_value_findings(findings, text, rel_path, "ci-secret-value", CI_SECRET_VALUE_RE, allow_code_like=False)
    add_sensitive_field_value_findings(findings, text, rel_path)
    add_protected_secret_value_findings(findings, text, rel_path, workspace_root)
    for kind, raw_path in (
        ("workspace-path", str(workspace_root.resolve())),
        ("home-path", str(Path.home().resolve())),
        ("temp-path", tempfile.gettempdir()),
    ):
        if raw_path and raw_path not in {"/", "\\"}:
            pattern = re.compile(rf"(?<![A-Za-z0-9_:/.\->]){re.escape(raw_path.rstrip('/\\'))}(?=$|[/\\])")
            if pattern.search(text):
                findings.append({"path": rel_path, "kind": kind})
    return deduplicate_findings(findings)

def deduplicate_findings(findings: list[dict[str, str]]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    seen: set[tuple[tuple[str, str], ...]] = set()
    for finding in findings:
        key = tuple(sorted((str(name), str(value)) for name, value in finding.items()))
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result

def iter_file_chunks(path: Path) -> Iterator[bytes]:
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(TEXT_SCAN_CHUNK_BYTES)
            if not chunk:
                break
            yield chunk

def iter_handle_chunks(handle: Any) -> Iterator[bytes]:
    while True:
        chunk = handle.read(TEXT_SCAN_CHUNK_BYTES)
        if not chunk:
            break
        yield chunk

def scan_byte_chunks(chunks: Iterable[bytes], rel_path: str, workspace_root: Path, out_dir: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    tail = b""
    for chunk in chunks:
        window = tail + chunk
        findings.extend(scan_text_for_findings(window.decode("utf-8", errors="ignore"), rel_path, workspace_root, out_dir))
        if b"\x00" in window:
            findings.extend(
                scan_text_for_findings(window.replace(b"\x00", b"").decode("utf-8", errors="ignore"), rel_path, workspace_root, out_dir)
            )
        tail = window[-TEXT_SCAN_OVERLAP_BYTES:]
    return deduplicate_findings(findings)

def archive_kind_for_name_or_prefix(name: str, prefix: bytes = b"") -> str | None:
    lower = name.lower()
    if Path(lower).suffix in ZIP_ARCHIVE_SUFFIXES or prefix.startswith(b"PK\x03\x04"):
        return "zip"
    if lower.endswith(TAR_GZ_ARCHIVE_SUFFIXES):
        return "tar-gz"
    return None

def scan_embedded_archive(data: bytes, rel_path: str, workspace_root: Path, out_dir: Path, depth: int) -> list[dict[str, str]]:
    if depth > MAX_NESTED_ARCHIVE_DEPTH:
        return [{"path": rel_path, "kind": "archive-nesting-too-deep"}]
    kind = archive_kind_for_name_or_prefix(rel_path, data[:4])
    if kind == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                return scan_zip_members(archive, rel_path, workspace_root, out_dir, depth)
        except (OSError, RuntimeError, zipfile.BadZipFile):
            return [{"path": rel_path, "kind": "invalid-zip"}]
    if kind == "tar-gz":
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                return scan_tar_members(archive, rel_path, workspace_root, out_dir, depth)
        except (OSError, tarfile.TarError):
            return [{"path": rel_path, "kind": "invalid-tar"}]
    return scan_byte_chunks([data], rel_path, workspace_root, out_dir)

def scan_zip_members(zip_archive: zipfile.ZipFile, rel_path: str, workspace_root: Path, out_dir: Path, depth: int) -> list[dict[str, str]]:
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
                    findings.extend(scan_embedded_archive(prefix + member.read(), member_rel, workspace_root, out_dir, depth + 1))
                else:
                    findings.extend(
                        scan_byte_chunks(_iter_prefixed(prefix, iter_handle_chunks(member)), member_rel, workspace_root, out_dir)
                    )
        except (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
            findings.append({"path": member_rel, "kind": "unreadable-zip-entry"})
    return deduplicate_findings(findings)

def scan_tar_members(tar_archive: tarfile.TarFile, rel_path: str, workspace_root: Path, out_dir: Path, depth: int) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for member in tar_archive.getmembers():
        member_rel = f"{rel_path}!/{member.name}" if rel_path else member.name
        reason = bad_artifact_name(member.name)
        if reason:
            findings.append({"path": member_rel, "kind": "forbidden-tar-entry", "detail": reason})
        if member.isdir():
            continue
        if not member.isfile():
            findings.append({"path": member_rel, "kind": "forbidden-tar-entry", "detail": "Only regular files and directories are allowed."})
            continue
        extracted = tar_archive.extractfile(member)
        if extracted is None:
            continue
        try:
            prefix = extracted.read(4)
            archive_kind = archive_kind_for_name_or_prefix(member.name, prefix)
            if archive_kind:
                findings.extend(scan_embedded_archive(prefix + extracted.read(), member_rel, workspace_root, out_dir, depth + 1))
            else:
                findings.extend(
                    scan_byte_chunks(_iter_prefixed(prefix, iter_handle_chunks(extracted)), member_rel, workspace_root, out_dir)
                )
        except (OSError, RuntimeError, tarfile.TarError):
            findings.append({"path": member_rel, "kind": "unreadable-tar-entry"})
    return deduplicate_findings(findings)

def _iter_prefixed(prefix: bytes, chunks: Iterable[bytes]) -> Iterator[bytes]:
    if prefix:
        yield prefix
    yield from chunks

def scan_file(path: Path, rel_path: str, workspace_root: Path, out_dir: Path) -> list[dict[str, str]]:
    reason = bad_artifact_name(rel_path)
    findings: list[dict[str, str]] = []
    if reason:
        findings.append({"path": rel_path, "kind": "forbidden-path", "detail": reason})
    if path.is_symlink():
        findings.append({"path": rel_path, "kind": "forbidden-symlink"})
        return findings
    if not path.is_file():
        findings.append({"path": rel_path, "kind": "forbidden-special-file"})
        return findings
    kind = archive_kind_for_name_or_prefix(rel_path)
    try:
        if kind == "zip":
            with zipfile.ZipFile(path) as archive:
                findings.extend(scan_zip_members(archive, rel_path, workspace_root, out_dir, 0))
        elif kind == "tar-gz":
            with tarfile.open(path, "r:gz") as archive:
                findings.extend(scan_tar_members(archive, rel_path, workspace_root, out_dir, 0))
        else:
            findings.extend(scan_byte_chunks(iter_file_chunks(path), rel_path, workspace_root, out_dir))
    except (OSError, RuntimeError, tarfile.TarError, zipfile.BadZipFile):
        findings.append({"path": rel_path, "kind": "unreadable"})
    return deduplicate_findings(findings)

def scan_paths(paths: Iterable[Path], workspace_root: Path, out_dir: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    seen: set[Path] = set()
    for candidate in sorted(paths, key=lambda item: str(item)):
        if not candidate.exists() and not candidate.is_symlink():
            continue
        rel_path = display_unresolved_path(candidate, workspace_root)
        reason = bad_artifact_name(rel_path)
        if candidate.is_symlink():
            if reason:
                findings.append({"path": rel_path, "kind": "forbidden-path", "detail": reason})
            findings.append({"path": rel_path, "kind": "forbidden-symlink"})
            continue
        path = candidate.resolve()
        if path in seen:
            continue
        seen.add(path)
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_symlink():
                    findings.extend(
                        scan_file(child, display_unresolved_path(child, workspace_root), workspace_root, out_dir)
                    )
                    continue
                if child.is_dir():
                    reason = bad_artifact_name(display_path(child, workspace_root))
                    if reason:
                        findings.append(
                            {
                                "path": display_path(child, workspace_root),
                                "kind": "forbidden-path",
                                "detail": reason,
                            }
                        )
                    continue
                findings.extend(scan_file(child, display_path(child, workspace_root), workspace_root, out_dir))
        else:
            findings.extend(scan_file(path, display_path(path, workspace_root), workspace_root, out_dir))
    return deduplicate_findings(findings)

def redaction_report(findings: list[dict[str, str]]) -> dict[str, Any]:
    critical = [finding for finding in findings if finding.get("kind") in REDACTION_FINDING_KINDS]
    return {
        "schemaVersion": SCHEMA_VERSION,
        "status": "pass" if not findings else "fail",
        "findingCount": len(findings),
        "criticalFindingCount": len(critical),
        "checks": {
            "failOnPrivateInsertUri": True,
            "failOnPrivateKeys": True,
            "failOnTokens": True,
            "failOnRawPayloads": True,
            "failOnAbsoluteLocalPaths": True,
            "failOnArchiveSidecars": True,
            "failOnProtectedSecretValues": True,
            "failOnSensitiveFieldValues": True,
        },
        "findings": sorted(findings, key=lambda item: (item.get("path", ""), item.get("kind", ""), item.get("detail", ""))),
    }

def load_inputs_from_paths(args: argparse.Namespace, workspace_root: Path) -> tuple[dict[str, Any], dict[str, Path], list[Path], dict[str, Any] | None, str]:
    path_by_name = {
        "productionBetaSummary": args.production_beta_summary,
        "releaseCertificationSummary": args.release_certification_summary,
        "ecosystemMatrix": args.ecosystem_matrix,
        "appPlatformSummary": args.app_platform_summary,
        "liveNetworkSummary": args.live_network_summary,
        "networkScaleSoakSummary": args.network_scale_soak_summary,
        "multiNodeBetaSoakSummary": args.multi_node_beta_soak_summary,
        "securityDrillsSummary": args.security_drills_summary,
        "securityResponseSummary": args.security_response_summary,
        "stableReadinessSummary": args.stable_readiness_summary,
    }
    inputs: dict[str, Any] = {}
    paths: dict[str, Path] = {}
    scan_targets: list[Path] = []
    for name, raw_path in path_by_name.items():
        if raw_path is None:
            continue
        path = raw_path if raw_path.is_absolute() else workspace_root / raw_path
        paths[name] = path
        scan_targets.append(path)
        value = read_json(path)
        if value is not None:
            inputs[name] = value
    waiver_value = None
    if args.waivers is not None:
        waiver_path = args.waivers if args.waivers.is_absolute() else workspace_root / args.waivers
        paths["waivers"] = waiver_path
        scan_targets.append(waiver_path)
        waiver_value, waiver_error = read_json_object_with_error(waiver_path)
        if waiver_error is not None:
            waiver_value = {"__loadError": waiver_error}
    release_id = args.release_id or infer_release_id(inputs)
    return inputs, paths, scan_targets, waiver_value, release_id
