#!/usr/bin/env python3
"""Build a redacted production beta go/no-go dashboard.

The dashboard is a final release-manager view over existing production beta and
release-certification summaries. It does not collect live evidence, sign
artifacts, or replace release certification. It fails closed for missing
production-critical inputs, unsafe redaction findings, invalid waivers, and
non-release production-beta runs.
"""

from __future__ import annotations

import argparse
import base64
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
import multi_node_beta_soak
import security_response_runbook

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
PUBLIC_BETA_DOCS_EVIDENCE_IDS = (
    "public-beta.docs-onboarding",
    "public-beta.user-guide",
    "public-beta.developer-quickstart",
    "public-beta.troubleshooting",
    "public-beta.security-reporting",
    "public-beta.limitations",
    "public-beta.links-redaction",
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
        "evidenceIds": PUBLIC_BETA_DOCS_EVIDENCE_IDS,
        "artifactInputs": (
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
    if not isinstance(entry, dict):
        return False
    details = entry.get("details", {})
    return isinstance(details, dict) and bool(details.get("redactionFindings"))


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


def load_inputs_from_fixture(args: argparse.Namespace, workspace_root: Path) -> tuple[dict[str, Any], dict[str, Path], list[Path], dict[str, Any] | None, str, str, str]:
    fixture_path = args.fixtures if args.fixtures.is_absolute() else workspace_root / args.fixtures
    fixture = load_fixture(fixture_path)
    inputs = fixture.get("inputs")
    if not isinstance(inputs, dict):
        raise SystemExit(f"Fixture {fixture_path} must contain an inputs object.")
    waiver_value = fixture.get("waivers") if isinstance(fixture.get("waivers"), dict) else None
    mode = args.mode or str(fixture.get("mode", "release-candidate"))
    generated_at = args.generated_at or str(fixture.get("generatedAt", DEFAULT_GENERATED_AT))
    release_id = args.release_id or str(fixture.get("releaseId", fixture_path.stem))
    inputs = rebind_inherited_fixture_security_drills_summary(
        inputs,
        fixture_path,
        release_id,
        mode,
        generated_at,
    )
    return inputs, {}, [fixture_path], waiver_value, release_id, mode, generated_at


def rebind_inherited_fixture_security_drills_summary(
    inputs: dict[str, Any],
    fixture_path: Path,
    release_id: str,
    mode: str,
    generated_at: str,
) -> dict[str, Any]:
    """Keep inherited pass-fixture drill summaries bound to the child fixture candidate."""
    raw_fixture = read_json(fixture_path)
    raw_inputs = raw_fixture.get("inputs") if isinstance(raw_fixture, dict) else None
    if isinstance(raw_inputs, dict) and "securityDrillsSummary" in raw_inputs:
        return inputs
    summary = inputs.get("securityDrillsSummary")
    if not isinstance(summary, dict):
        return inputs
    if summary.get("kind") != "cryptad-security-response-drills-summary":
        return inputs
    rebound = json.loads(json.dumps(inputs))
    rebound_summary = rebound.get("securityDrillsSummary")
    if isinstance(rebound_summary, dict):
        rebound_summary["releaseId"] = release_id
        rebound_summary["generatedAt"] = generated_at
        if mode in security_response_runbook.RELEASE_DRILL_MODES:
            rebound_summary["mode"] = mode
    return rebound


def load_fixture(fixture_path: Path, seen: set[Path] | None = None) -> dict[str, Any]:
    resolved = fixture_path.resolve()
    active = set() if seen is None else seen
    if resolved in active:
        raise SystemExit(f"Fixture inheritance cycle includes {resolved}.")
    active.add(resolved)
    fixture = read_json(resolved)
    if fixture is None:
        raise SystemExit(f"Fixture {resolved} is missing or malformed.")
    extends = fixture.get("extends")
    if isinstance(extends, str) and extends.strip():
        base_path = (resolved.parent / extends).resolve()
        base = load_fixture(base_path, active)
        fixture = deep_merge(base, fixture)
        fixture.pop("extends", None)
    active.remove(resolved)
    return fixture


def deep_merge(base: Any, override: Any) -> Any:
    if isinstance(base, dict) and isinstance(override, dict):
        result = dict(base)
        for key, value in override.items():
            if key == "extends":
                continue
            result[key] = deep_merge(result.get(key), value)
        return result
    return override


def infer_release_id(inputs: dict[str, Any]) -> str:
    prod = inputs.get("productionBetaSummary")
    if isinstance(prod, dict):
        release_id = prod.get("releaseId")
        if isinstance(release_id, str) and release_id.strip():
            return release_id
        version = prod.get("version")
        if version:
            return f"crypta-production-beta-{version}"
    cert = inputs.get("releaseCertificationSummary")
    if isinstance(cert, dict):
        metadata = cert.get("metadata") if isinstance(cert.get("metadata"), dict) else {}
        release_id = metadata.get("releaseId")
        if isinstance(release_id, str) and release_id.strip():
            return release_id
        release_version = metadata.get("releaseVersion") or metadata.get("version")
        if release_version:
            return f"crypta-production-beta-{release_version}"
    return "crypta-production-beta-candidate"


def input_missing_issue(name: str, mode: str) -> Issue:
    required = name in CRITICAL_INPUTS_BY_MODE.get(mode, ())
    severity = "blocker" if required else "warning"
    return Issue(
        id=f"input.{name}.missing",
        evidence_id=f"input.{name}",
        domain_id="production-beta-release-pipeline",
        severity=severity,
        title=f"{name} input is missing",
        summary=f"{name} was not provided or could not be parsed.",
        source=name,
        waivable=not required,
        category="missing-input",
    )


def production_summary_issues(summary: dict[str, Any] | None, mode: str) -> list[Issue]:
    if not isinstance(summary, dict):
        return []
    issues: list[Issue] = []
    status = normalize_status(summary.get("status"))
    promotion = summary.get("promotion") if isinstance(summary.get("promotion"), dict) else {}
    gates = promotion.get("gates") if isinstance(promotion.get("gates"), list) else []
    has_failed_promotion_gate = any(
        isinstance(gate, dict) and normalize_status(gate.get("status")) != "pass" for gate in gates
    )
    failures = summary.get("failures") if isinstance(summary.get("failures"), list) else []
    redaction = summary.get("redaction") if isinstance(summary.get("redaction"), dict) else {}
    redaction_status = normalize_status(redaction.get("status") if isinstance(redaction, dict) else "missing")
    if redaction_status != "pass":
        issues.append(
            Issue(
                id="production-beta.redaction.status",
                evidence_id="redaction.status",
                domain_id="redaction-artifact-hygiene",
                severity="critical",
                title="Production beta redaction failed",
                summary=f"Production beta artifact redaction status is {redaction_status}.",
                source="production-beta-summary",
                waivable=False,
                category="redaction",
            )
        )
    unexplained_failure = status == "fail" and (failures or not has_failed_promotion_gate)
    malformed_or_nonready_status = status not in {"pass", "fail"}
    if mode == "production-beta" and (malformed_or_nonready_status or unexplained_failure):
        detail = ""
        if failures:
            detail = f" First failure: {failures[0]}."
        issues.append(
            Issue(
                id="production-beta.summary.status",
                evidence_id="production-beta.summary",
                domain_id="production-beta-release-pipeline",
                severity="blocker",
                title="Production beta summary is not passing",
                summary=f"Production beta summary status is {status}.{detail}",
                source="production-beta-summary",
                waivable=False,
                category="pipeline",
            )
        )
    elif unexplained_failure:
        detail = ""
        if failures:
            detail = f" First failure: {failures[0]}."
        issues.append(
            Issue(
                id="production-beta.summary.status",
                evidence_id="production-beta.summary",
                domain_id="production-beta-release-pipeline",
                severity="blocker",
                title="Production beta summary failed",
                summary=f"Production beta summary status is fail.{detail}",
                source="production-beta-summary",
                waivable=False,
                category="pipeline",
            )
        )
    if mode == "production-beta" and summary.get("promotionReady") is not True and not has_failed_promotion_gate:
        issues.append(
            Issue(
                id="production-beta.summary.promotion-ready",
                evidence_id="production-beta.promotion-ready",
                domain_id="production-beta-release-pipeline",
                severity="blocker",
                title="Production beta summary is not promotion-ready",
                summary=f"Production beta summary promotionReady is {summary.get('promotionReady')}.",
                source="production-beta-summary",
                waivable=False,
                category="pipeline",
            )
        )
    profile = summary.get("signingProfile") if isinstance(summary.get("signingProfile"), dict) else {}
    if summary.get("nonRelease") is not False:
        issues.append(
            Issue(
                id="production-beta.non-release",
                evidence_id="production-beta.non-release",
                domain_id="production-beta-release-pipeline",
                severity="critical",
                title="Candidate is not a release artifact",
                summary="Launchable dashboard decisions require productionBetaSummary.nonRelease to be false.",
                source="production-beta-summary",
                waivable=False,
                category="pipeline",
            )
        )
    if mode == "production-beta" and (profile.get("kind") != "production" or profile.get("generatedTestKeys") is True):
        issues.append(
            Issue(
                id="production-beta.test-signing",
                evidence_id="production-beta.test-signing",
                domain_id="catalog-and-app-signing",
                severity="critical",
                title="Production beta candidate is not using production signing",
                summary="Production beta mode cannot use test-only or generated signing material.",
                source="production-beta-summary",
                waivable=False,
                category="signing",
            )
        )
    for gate in gates:
        if not isinstance(gate, dict) or normalize_status(gate.get("status")) == "pass":
            continue
        gate_id = str(gate.get("id", "promotion-gate"))
        evidence_id = canonical_evidence_id(gate_id)
        source = str(gate.get("source", "promotion"))
        mode_non_waivable_ids = non_waivable_evidence_ids_for_mode(mode)
        nonwaivable = (
            gate_id in mode_non_waivable_ids
            or evidence_id in mode_non_waivable_ids
            or is_redaction_evidence(gate_id)
            or is_redaction_evidence(evidence_id)
        )
        if mode == "production-beta" and (gate_id == "signing.production-keys" or "test-signing" in gate_id):
            nonwaivable = True
        if mode == "production-beta" and gate_id in {
            "build.production-beta-complete",
            "workspace.clean-production-beta",
            "fixture-evidence.strict-mode",
        }:
            nonwaivable = True
        issues.append(
            Issue(
                id=f"promotion.{gate_id}",
                evidence_id=evidence_id,
                domain_id=domain_for_gate(evidence_id, source),
                severity="critical" if nonwaivable else "blocker",
                title=f"{gate_id} failed",
                summary=str(gate.get("summary", "Promotion gate failed.")),
                source=source,
                waivable=not nonwaivable,
                category="promotion-gate",
            )
        )
    return issues


def domain_for_gate(gate_id: str, source: str) -> str:
    if gate_id.startswith("live.") or source == "live-network-beta-smoke":
        return "live-network-beta-smoke"
    if gate_id.startswith("multi-node-beta") or source == "multi-node-beta-soak":
        return "multi-node-beta-soak"
    if "signing" in gate_id or "catalog" in gate_id or "review" in gate_id:
        return "catalog-and-app-signing"
    if gate_id.startswith("ecosystem."):
        return "release-certification"
    if "workspace" in gate_id or "build" in gate_id or "fixture" in gate_id:
        return "production-beta-release-pipeline"
    return "production-beta-release-pipeline"


def release_certification_issues(summary: dict[str, Any] | None, mode: str) -> list[Issue]:
    if not isinstance(summary, dict):
        return []
    issues: list[Issue] = []
    evidence_entries = summary.get("evidence") if isinstance(summary.get("evidence"), list) else []
    for entry in evidence_entries:
        if not isinstance(entry, dict):
            continue
        evidence_id = str(entry.get("id", ""))
        if evidence_id != "release-certification.ecosystem-rc-gate":
            continue
        issue = issue_for_evidence("release-certification", evidence_id, entry, mode)
        if issue is not None:
            issues.append(issue)
    if summary.get("releaseCandidatePassed") is not True:
        issues.append(
            Issue(
                id="release-certification.release-candidate-passed",
                evidence_id="release-certification.ecosystem-rc-gate",
                domain_id="release-certification",
                severity="blocker",
                title="Release certification did not pass",
                summary=f"Release certification decision is {summary.get('promotionDecision', 'FAIL')}.",
                source="release-certification-summary",
                waivable=True,
                category="release-certification",
            )
        )
    gates = summary.get("ecosystemGates") if isinstance(summary.get("ecosystemGates"), list) else []
    for gate in gates:
        if not isinstance(gate, dict):
            continue
        if normalize_status(gate.get("status")) == "pass":
            continue
        gate_id = str(gate.get("id", "ecosystem-gate"))
        details = gate.get("details") if isinstance(gate.get("details"), dict) else {}
        unwaivable = bool(details.get("unwaivableFailureEvidenceIds")) or is_redaction_evidence(gate_id)
        issues.append(
            Issue(
                id=f"release-certification.{gate_id}",
                evidence_id=gate_id,
                domain_id="release-certification",
                severity="critical" if unwaivable else ("blocker" if gate.get("releaseBlocker") else "warning"),
                title=f"{gate_id} is not passing",
                summary=str(gate.get("summary", "Ecosystem gate is not passing.")),
                source="release-certification-summary",
                waivable=not unwaivable and bool(gate.get("releaseBlocker", True)),
                category="release-certification",
            )
        )
    return issues


def parse_release_blocker_count(value: Any) -> tuple[int, bool]:
    if value is None or value == "":
        return 0, False
    if isinstance(value, bool):
        return 0, True
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0, True
    if parsed < 0:
        return 0, True
    return parsed, False


def ecosystem_matrix_issues(matrix: dict[str, Any] | None) -> list[Issue]:
    if not isinstance(matrix, dict):
        return []
    issues: list[Issue] = []
    status = normalize_status(matrix.get("status"))
    release_blocker_count, malformed_release_blocker_count = parse_release_blocker_count(
        matrix.get("releaseBlockerCount", 0)
    )
    if status not in {"pass", "warn"} or malformed_release_blocker_count or release_blocker_count > 0:
        details: list[str] = []
        if status not in {"pass", "warn"}:
            details.append(f"status is {status}")
        if malformed_release_blocker_count:
            details.append("releaseBlockerCount is not a non-negative integer")
        elif release_blocker_count > 0:
            details.append(f"releaseBlockerCount is {release_blocker_count}")
        detail = "; ".join(details) if details else "contains release blockers"
        issues.append(
            Issue(
                id="ecosystem-matrix.release-blockers",
                evidence_id="release-certification.ecosystem-matrix",
                domain_id="ecosystem-rc-certification-matrix",
                severity="blocker",
                title="Ecosystem matrix has release blockers",
                summary=f"Ecosystem certification matrix {detail}.",
                source="ecosystem-certification-matrix",
                waivable=not malformed_release_blocker_count,
                category="ecosystem-matrix",
            )
        )
    coverage = matrix.get("coverage") if isinstance(matrix.get("coverage"), dict) else {}
    if coverage.get("redactionPassed") is False:
        issues.append(
            Issue(
                id="ecosystem-matrix.redaction",
                evidence_id="production-beta.dashboard-redaction",
                domain_id="redaction-artifact-hygiene",
                severity="critical",
                title="Ecosystem matrix redaction failed",
                summary="Ecosystem matrix coverage reports redactionPassed=false.",
                source="ecosystem-certification-matrix",
                waivable=False,
                category="redaction",
            )
        )
    rows = matrix.get("rows") if isinstance(matrix.get("rows"), list) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        status = normalize_status(row.get("status"))
        if status in {"pass", "warn"} and row.get("releaseBlocker") is not True:
            continue
        row_id = str(row.get("id", "matrix-row"))
        redaction_row = row_id == "redaction-and-private-artifacts" or is_redaction_evidence(row_id)
        issues.append(
            Issue(
                id=f"ecosystem-matrix.{row_id}",
                evidence_id=row_id,
                domain_id="ecosystem-rc-certification-matrix",
                severity="critical" if redaction_row else ("blocker" if row.get("releaseBlocker") else "warning"),
                title=f"{row_id} matrix row is not passing",
                summary=str(row.get("recommendation") or row.get("title") or "Matrix row is not passing."),
                source="ecosystem-certification-matrix",
                waivable=not redaction_row and bool(row.get("releaseBlocker", True)),
                category="ecosystem-matrix",
            )
        )
    return issues


def network_scale_issues(summary: dict[str, Any] | None, mode: str) -> list[Issue]:
    if not isinstance(summary, dict):
        return []
    issues: list[Issue] = []
    status = normalize_status(summary.get("status"))
    if status != "pass":
        issues.append(
            Issue(
                id="network-scale-soak.status",
                evidence_id="network-scale.rc-soak-summary",
                domain_id="network-scale-soak",
                severity="blocker" if mode != "developer-dry-run" else "warning",
                title="Network-scale soak is not passing",
                summary=f"Network-scale soak status is {status}.",
                source="network-scale-soak-summary",
                waivable=mode != "production-beta",
                category="network-scale",
            )
        )
    findings = []
    for section, keys in (
        ("redaction", ("rawFetchedContentExcluded", "privateInsertUrisExcluded", "tokensExcluded", "absolutePathsExcluded", "queueHtmlExcluded")),
        ("budgets", ("globalFetchBudgetEnforced", "perAppFetchBudgetEnforced", "concurrencyLeasesReleased")),
    ):
        value = summary.get(section)
        if not isinstance(value, dict) or any(value.get(key) is not True for key in keys):
            findings.append(section)
    if findings:
        issues.append(
            Issue(
                id="network-scale-soak.redaction-or-budget",
                evidence_id="network-scale.redaction",
                domain_id="network-scale-soak",
                severity="critical",
                title="Network-scale soak redaction or budget checks failed",
                summary=f"Network-scale soak sections failed: {', '.join(sorted(findings))}.",
                source="network-scale-soak-summary",
                waivable=False,
                category="redaction",
            )
        )
    return issues


def non_bool_int(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def compact_text(value: Any) -> str:
    return str(value).strip() if value is not None and not isinstance(value, bool) else ""


def catalog_edition_field(catalog_channel: str) -> str:
    return "stableChannelEdition" if catalog_channel == "stable" else "betaChannelEdition"


def previous_candidate_upgrade_current_binding_failures(
    upgrade: dict[str, Any],
    production_summary: dict[str, Any] | None,
) -> list[str]:
    if not isinstance(production_summary, dict):
        return ["productionBetaSummary"]
    failures: list[str] = []
    expected_version = compact_text(production_summary.get("version"))
    if not expected_version:
        failures.append("productionBetaSummary.version")
    elif compact_text(upgrade.get("currentVersion")) != expected_version:
        failures.append("currentVersion")

    expected_channel = compact_text(production_summary.get("catalogChannel"))
    if not expected_channel:
        failures.append("productionBetaSummary.catalogChannel")
        return failures
    if expected_channel not in {"stable", "beta"}:
        failures.append("productionBetaSummary.catalogChannel")
        return failures
    if compact_text(upgrade.get("currentCatalogChannel")) != expected_channel:
        failures.append("currentCatalogChannel")

    metadata = production_summary.get("previousCandidateMetadata")
    catalog = metadata.get("catalog") if isinstance(metadata, dict) else None
    edition_field = catalog_edition_field(expected_channel)
    expected_edition = non_bool_int(catalog.get(edition_field)) if isinstance(catalog, dict) else None
    if expected_edition is None:
        failures.append(f"productionBetaSummary.previousCandidateMetadata.catalog.{edition_field}")
        return failures
    if non_bool_int(upgrade.get("currentCatalogEdition")) != expected_edition:
        failures.append("currentCatalogEdition")
    return failures


def multi_node_issues(
    summary: dict[str, Any] | None,
    mode: str,
    production_summary: dict[str, Any] | None = None,
) -> list[Issue]:
    if not isinstance(summary, dict):
        return []
    issues: list[Issue] = []
    status = normalize_status(summary.get("status"))
    if status != "pass" or summary.get("promotionReady") is not True:
        issues.append(
            Issue(
                id="multi-node-beta-soak.status",
                evidence_id="multi-node-beta.soak",
                domain_id="multi-node-beta-soak",
                severity="blocker" if mode != "developer-dry-run" else "warning",
                title="Multi-node beta soak is not promotion-ready",
                summary=f"Multi-node beta soak status is {status}; promotionReady={summary.get('promotionReady')}.",
                source="multi-node-beta-soak-summary",
                waivable=mode != "production-beta",
                category="multi-node",
            )
        )
    redaction = summary.get("redaction") if isinstance(summary.get("redaction"), dict) else {}
    if normalize_status(redaction.get("status")) != "pass":
        issues.append(
            Issue(
                id="multi-node-beta-soak.redaction",
                evidence_id="multi-node-beta.redaction",
                domain_id="multi-node-beta-soak",
                severity="critical",
                title="Multi-node beta soak redaction failed",
                summary=f"Multi-node beta redaction status is {normalize_status(redaction.get('status'))}.",
                source="multi-node-beta-soak-summary",
                waivable=False,
                category="redaction",
            )
        )
    scenario_statuses = summary.get("scenarioStatuses")
    if isinstance(scenario_statuses, dict):
        for scenario_id, scenario_status in sorted(scenario_statuses.items()):
            if normalize_status(scenario_status) != "pass":
                evidence_id = multi_node_beta_soak.SCENARIO_EVIDENCE_IDS.get(
                    scenario_id,
                    f"multi-node-beta.{scenario_id}",
                )
                issues.append(
                    Issue(
                        id=f"multi-node-beta-soak.{scenario_id}",
                        evidence_id=evidence_id,
                        domain_id="multi-node-beta-soak",
                        severity="blocker",
                        title=f"{scenario_id} scenario is not passing",
                        summary=f"{scenario_id} status is {scenario_status}.",
                        source="multi-node-beta-soak-summary",
                        waivable=mode != "production-beta",
                        category="multi-node",
                    )
                )
    upgrade = summary.get("previousCandidateUpgrade")
    if mode == "production-beta":
        if not isinstance(upgrade, dict):
            issues.append(
                Issue(
                    id="multi-node-beta-soak.previous-candidate-summary",
                    evidence_id="multi-node-beta.previous-candidate-summary",
                    domain_id="multi-node-beta-soak",
                    severity="blocker",
                    title="Previous beta candidate upgrade evidence is missing",
                    summary="Production beta requires compact previous-candidate upgrade evidence in the multi-node summary.",
                    source="multi-node-beta-soak-summary",
                    waivable=False,
                    category="multi-node",
                )
            )
        else:
            expected = {
                "status": "pass",
                "previousSummaryConfigured": True,
                "previousSummaryProvided": True,
                "previousSummaryValid": True,
                "currentUpgradePathRepresented": True,
                "firstPartyAppMigrationStatus": "pass",
                "backupBeforeUpdateStatus": "pass",
                "restoreIntoCleanNodeStatus": "pass",
                "socialInboxMigrationStatus": "pass",
                "trustGraphMigrationStatus": "pass",
                "supportBundleRedactionStatus": "pass",
                "rollbackStatus": "pass",
                "rawDataIncluded": False,
            }
            failed_fields = [
                field
                for field, expected_value in expected.items()
                if upgrade.get(field) != expected_value
            ]
            validation_errors = upgrade.get("previousSummaryValidationErrors")
            if not isinstance(validation_errors, list):
                validation_errors = ["previousSummaryValidationErrors missing"]
            if failed_fields or validation_errors:
                issues.append(
                    Issue(
                        id="multi-node-beta-soak.previous-candidate-summary",
                        evidence_id="multi-node-beta.previous-candidate-summary",
                        domain_id="multi-node-beta-soak",
                        severity="blocker",
                        title="Previous beta candidate upgrade evidence is not production-ready",
                        summary=(
                            "Previous-candidate upgrade evidence has failing fields: "
                            + ", ".join(failed_fields or ["validation"])
                        ),
                        source="multi-node-beta-soak-summary",
                        waivable=False,
                        category="multi-node",
                    )
                )
            binding_failures = previous_candidate_upgrade_current_binding_failures(
                upgrade,
                production_summary,
            )
            if binding_failures:
                issues.append(
                    Issue(
                        id="multi-node-beta-soak.previous-candidate-current-binding",
                        evidence_id="multi-node-beta.previous-candidate-upgrade-binding",
                        domain_id="multi-node-beta-soak",
                        severity="blocker",
                        title="Previous beta candidate upgrade evidence is bound to a different current candidate",
                        summary=(
                            "Previous-candidate upgrade evidence does not match the production summary fields: "
                            + ", ".join(binding_failures)
                        ),
                        source="multi-node-beta-soak-summary",
                        waivable=False,
                        category="multi-node",
                    )
                )
    return issues


def security_response_issues(summary: dict[str, Any] | None) -> list[Issue]:
    if not isinstance(summary, dict):
        return []
    if normalize_status(summary.get("status")) == "pass":
        return []
    return [
        Issue(
            id="security-response-runbook.status",
            evidence_id="production-security.response-runbook",
            domain_id="production-security-response",
            severity="blocker",
            title="Production security response runbook is not passing",
            summary=f"Security response summary status is {normalize_status(summary.get('status'))}.",
            source="security-response-summary",
            waivable=True,
            category="security-response",
        )
    ]


def build_domain_rows(
    inputs: dict[str, Any],
    paths: dict[str, Path],
    workspace_root: Path,
    out_dir: Path,
    all_issues: list[Issue],
    all_evidence: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    issues_by_domain: dict[str, list[Issue]] = {}
    for issue in all_issues:
        issues_by_domain.setdefault(issue.domain_id, []).append(issue)
    for spec in DOMAIN_SPECS:
        domain_id = str(spec["id"])
        evidence_ids = list(spec["evidenceIds"])
        artifact_refs: list[str] = []
        for input_name in spec.get("artifactInputs", ()):
            path = paths.get(str(input_name))
            if path is not None:
                artifact_refs.append(display_path(path, workspace_root))
        source_issues = issues_by_domain.get(domain_id, [])
        status = domain_status(source_issues)
        rows.append(
            {
                "id": domain_id,
                "title": spec["title"],
                "status": status,
                "severity": "required",
                "evidenceIds": evidence_ids,
                "artifactRefs": sorted(dict.fromkeys(artifact_refs)),
                "summary": domain_summary(domain_id, status, source_issues, evidence_ids, all_evidence),
            }
        )
    return rows


def domain_summary(
    domain_id: str,
    status: str,
    issues: list[Issue],
    evidence_ids: list[str],
    all_evidence: dict[str, dict[str, Any]],
) -> str:
    if status == "pass":
        reported = [evidence_id for evidence_id in evidence_ids if evidence_id in all_evidence]
        if reported:
            return f"{len(reported)} evidence item(s) reported and passing."
        if domain_id == "redaction-artifact-hygiene":
            return "Dashboard input and output redaction scan passed."
        return "Domain passed."
    if status == "waived":
        return "Blocking findings are covered by explicit valid waivers."
    if issues:
        first = sorted(issues, key=lambda issue: (issue.severity != "critical", issue.id))[0]
        return first.summary
    return "Domain is not passing."


def compact_security_drills(
    summary: dict[str, Any] | None,
    production: bool = False,
    strict: bool = False,
    now: dt.datetime | None = None,
    expected_release_id: str | None = None,
    expected_mode: str | None = None,
    artifact_validation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {
            "status": "missing",
            "promotionReady": False,
            "expectedReleaseId": expected_release_id or "not-required",
            "requiredScenarioCount": len(security_response_runbook.REQUIRED_DRILLS),
            "passedScenarioCount": 0,
            "failedScenarioCount": 0,
            "missingScenarioCount": len(security_response_runbook.REQUIRED_DRILLS),
            "staleScenarioCount": 0,
            "malformedScenarioCount": 0,
            "redactionStatus": "missing",
            "releaseNotesTemplateStatus": "missing",
            "advisoryTemplateStatus": "missing",
            "supportBundleIntakeRedactionStatus": "missing",
        }
    if summary.get("kind") != "cryptad-security-response-drills-summary":
        return {
            "status": "fail",
            "promotionReady": False,
            "requiredScenarios": list(security_response_runbook.REQUIRED_DRILLS),
            "passedScenarios": [],
            "failedScenarios": [],
            "missingScenarios": list(security_response_runbook.REQUIRED_DRILLS),
            "staleScenarios": [],
            "malformedScenarios": [str(summary.get("scenario", summary.get("kind", "unknown")))],
            "requiredScenarioCount": len(security_response_runbook.REQUIRED_DRILLS),
            "passedScenarioCount": 0,
            "failedScenarioCount": 0,
            "missingScenarioCount": len(security_response_runbook.REQUIRED_DRILLS),
            "staleScenarioCount": 0,
            "malformedScenarioCount": 1,
            "redactionStatus": "fail",
            "releaseNotesTemplateStatus": "missing",
            "advisoryTemplateStatus": "missing",
            "supportBundleIntakeRedactionStatus": "missing",
            "fixtureOnly": bool(summary.get("fixtureOnly")),
            "nonRelease": bool(summary.get("nonRelease")),
            "releaseId": summary.get("releaseId", "missing"),
            "expectedReleaseId": expected_release_id or "not-required",
            "releaseIdMatchesDashboard": False,
        }
    counts = summary.get("counts") if isinstance(summary.get("counts"), dict) else {}
    redaction = summary.get("redaction") if isinstance(summary.get("redaction"), dict) else {}
    release_notes = summary.get("releaseNotes") if isinstance(summary.get("releaseNotes"), dict) else {}
    advisory_template = (
        summary.get("advisoryTemplate") if isinstance(summary.get("advisoryTemplate"), dict) else {}
    )
    validation = security_response_runbook.validate_drills_summary(
        summary,
        production=production,
        strict=strict,
        now=now,
        expected_mode=expected_mode,
    )
    validation_errors = list(validation.get("errors", [])) if isinstance(validation.get("errors"), list) else []
    release_id = summary.get("releaseId")
    release_id_matches = not (
        strict
        and expected_release_id
        and release_id != expected_release_id
    )
    if not release_id_matches:
        validation_errors.append(f"releaseId must match dashboard candidate {expected_release_id}")
    artifact_errors = (
        artifact_validation.get("errors")
        if isinstance(artifact_validation, dict)
        and isinstance(artifact_validation.get("errors"), list)
        else []
    )
    validation_errors.extend(str(error) for error in artifact_errors)
    computed_status = normalize_status(summary.get("status"))
    artifacts_valid = (
        artifact_validation is None
        or artifact_validation.get("status") == "pass"
    )
    if validation.get("status") != "pass" or not release_id_matches or not artifacts_valid:
        computed_status = "fail"
    passed_scenarios = summary.get("passedScenarios") if isinstance(summary.get("passedScenarios"), list) else []
    failed_scenarios = summary.get("failedScenarios") if isinstance(summary.get("failedScenarios"), list) else []
    missing_scenarios = summary.get("missingScenarios") if isinstance(summary.get("missingScenarios"), list) else []
    stale_scenarios = summary.get("staleScenarios") if isinstance(summary.get("staleScenarios"), list) else []
    malformed_scenarios = summary.get("malformedScenarios") if isinstance(summary.get("malformedScenarios"), list) else []
    support_status = "pass" if "support-bundle-intake-redaction" in passed_scenarios else "missing"
    if "support-bundle-intake-redaction" in failed_scenarios:
        support_status = "fail"
    elif "support-bundle-intake-redaction" in stale_scenarios:
        support_status = "stale"
    elif "support-bundle-intake-redaction" in malformed_scenarios:
        support_status = "fail"
    return {
        "status": computed_status,
        "promotionReady": (
            bool(summary.get("promotionReady"))
            and validation.get("status") == "pass"
            and release_id_matches
            and artifacts_valid
        ),
        "releaseId": release_id if isinstance(release_id, str) else "missing",
        "expectedReleaseId": expected_release_id or "not-required",
        "releaseIdMatchesDashboard": release_id_matches,
        "requiredScenarios": summary.get("requiredScenarios", []),
        "passedScenarios": passed_scenarios,
        "failedScenarios": failed_scenarios,
        "missingScenarios": missing_scenarios,
        "staleScenarios": stale_scenarios,
        "malformedScenarios": malformed_scenarios,
        "requiredScenarioCount": safe_int_count(
            counts.get("required"),
            len(security_response_runbook.REQUIRED_DRILLS),
        ),
        "passedScenarioCount": safe_int_count(counts.get("passed"), len(passed_scenarios)),
        "failedScenarioCount": safe_int_count(counts.get("failed"), len(failed_scenarios)),
        "missingScenarioCount": safe_int_count(counts.get("missing"), len(missing_scenarios)),
        "staleScenarioCount": safe_int_count(counts.get("stale"), len(stale_scenarios)),
        "malformedScenarioCount": safe_int_count(
            counts.get("malformed"),
            len(malformed_scenarios),
        ),
        "redactionStatus": normalize_status(redaction.get("status")),
        "criticalBlockers": len(failed_scenarios) + len(missing_scenarios) + len(stale_scenarios) + len(malformed_scenarios),
        "releaseNotesTemplateStatus": normalize_status(release_notes.get("templateStatus")),
        "advisoryTemplateStatus": normalize_status(advisory_template.get("templateStatus")),
        "supportBundleIntakeRedactionStatus": support_status,
        "fixtureOnly": bool(summary.get("fixtureOnly")),
        "nonRelease": bool(summary.get("nonRelease")),
        "artifactValidation": artifact_validation or {},
        "validationErrors": validation_errors,
    }


def safe_int_count(value: Any, fallback: int) -> int:
    if isinstance(value, bool):
        return fallback
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def scope_applies(scope: str, mode: str) -> bool:
    normalized = scope.strip().lower()
    if normalized in {"all", "all-modes", "any"}:
        return True
    if normalized in {mode, f"{mode}-only"}:
        return True
    if normalized == "release-candidate-and-production-beta" and mode in {"release-candidate", "production-beta"}:
        return True
    if normalized == "release-candidate-only" and mode == "release-candidate":
        return True
    if normalized == "production-beta-only" and mode == "production-beta":
        return True
    return False


def release_certification_scope(entry: dict[str, Any]) -> str:
    scope = str(entry.get("scope", "")).strip()
    if scope:
        return scope
    allow_release_candidate = entry.get("allowReleaseCandidate")
    if isinstance(allow_release_candidate, bool):
        return "release-candidate" if allow_release_candidate else "developer-dry-run"
    return ""


def release_certification_owner(entry: dict[str, Any]) -> str:
    owner = str(entry.get("owner", "")).strip()
    if owner:
        return owner
    if "reason" in entry or "allowReleaseCandidate" in entry:
        return str(entry.get("approvedBy", "")).strip() or "release-certification"
    return ""


def release_certification_record_scope(record: dict[str, Any]) -> str:
    scope = str(record.get("scope", "")).strip()
    if scope:
        return scope
    if record.get("allowReleaseCandidate") is True or record.get("appliesToReleaseCandidate") is True:
        return "release-candidate"
    return "developer-dry-run"


def release_certification_record_applies(record: dict[str, Any], mode: str) -> bool:
    if mode == "production-beta":
        return release_certification_record_scope(record).strip().lower() in {
            "production-beta",
            "production-beta-only",
            "release-candidate-and-production-beta",
            "all",
            "all-modes",
            "any",
        }
    if mode == "release-candidate":
        return record.get("allowReleaseCandidate") is True or record.get("appliesToReleaseCandidate") is True
    return True


def release_certification_waiver_records(
    summary: dict[str, Any] | None,
    mode: str,
    now: dt.datetime,
    workspace_root: Path,
    out_dir: Path,
) -> list[Waiver]:
    if not isinstance(summary, dict):
        return []
    records = summary.get("waiverRecords")
    if not isinstance(records, list):
        return []
    waivers: list[Waiver] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        waiver_id = str(record.get("id", "")).strip()
        evidence_id = str(record.get("evidenceId", waiver_id)).strip()
        if not waiver_id and not evidence_id:
            continue
        status = str(record.get("status", "approved")).strip().lower()
        expired = record.get("expired") is True
        applies = release_certification_record_applies(record, mode)
        expires_at = str(record.get("expiresAt", "")).strip()
        expiry = parse_time(expires_at)
        validation_error = str(record.get("validationError", "")).strip()
        validation_errors: list[str] = []
        if validation_error:
            validation_errors.append(validation_error)
        if not expires_at:
            validation_errors.append("expiresAt is required")
        elif expiry is None:
            validation_errors.append("expiresAt must be an ISO-8601 timestamp")
        elif expiry <= now:
            validation_errors.append("waiver is expired")
        active = (
            record.get("active") is True
            and status == "approved"
            and not expired
            and applies
            and not validation_errors
        )
        safe_errors = tuple(scrub_text(error, workspace_root, out_dir) for error in validation_errors)
        waivers.append(
            Waiver(
                id=scrub_text(waiver_id or evidence_id or f"release-certification-waiver-{index}", workspace_root, out_dir),
                evidence_id=scrub_text(evidence_id or waiver_id or f"release-certification-waiver-{index}", workspace_root, out_dir),
                severity="blocker",
                scope=scrub_text(release_certification_record_scope(record), workspace_root, out_dir),
                rationale=scrub_text(str(record.get("reason", record.get("rationale", ""))).strip(), workspace_root, out_dir),
                approved_by=scrub_text(str(record.get("approvedBy", "")).strip(), workspace_root, out_dir),
                owner=scrub_text(str(record.get("owner", "release-certification")).strip() or "release-certification", workspace_root, out_dir),
                created_at=scrub_text(str(record.get("createdAt", "")).strip(), workspace_root, out_dir),
                expires_at=scrub_text(expires_at, workspace_root, out_dir),
                references=(),
                source=scrub_text(str(record.get("source", "release-certification")).strip() or "release-certification", workspace_root, out_dir),
                active=active,
                applies_to_mode=applies,
                external_risk_accepted=False,
                validation_errors=safe_errors,
            )
        )
    return waivers


def severity_covers(waiver: Waiver, issue: Issue) -> bool:
    return SEVERITY_RANK.get(waiver.severity, -1) >= SEVERITY_RANK.get(issue.severity, 99)


def issue_is_non_waivable_in_mode(issue: Issue, mode: str) -> bool:
    if issue.severity == "critical":
        return True
    mode_non_waivable_ids = non_waivable_evidence_ids_for_mode(mode)
    return issue.id in mode_non_waivable_ids or issue.evidence_id in mode_non_waivable_ids


def load_waivers(
    value: dict[str, Any] | None,
    source: str,
    mode: str,
    now: dt.datetime,
    known_ids: set[str],
    workspace_root: Path,
    out_dir: Path,
) -> tuple[list[Waiver], list[Issue]]:
    if value is None:
        return [], []
    errors: list[Issue] = []
    if value.get("__loadError"):
        return [], [
            Issue(
                id="waiver.file.invalid",
                evidence_id="production-beta.waiver-validation",
                domain_id="redaction-artifact-hygiene",
                severity="blocker",
                title="Waiver file is invalid",
                summary=scrub_text(str(value["__loadError"]), workspace_root, out_dir),
                source=source,
                waivable=False,
                category="waiver-validation",
            )
        ]
    records_value = value.get("waivers")
    schema_version = value.get("schemaVersion", value.get("version"))
    if schema_version != 1 or not isinstance(records_value, list):
        return [], [
            Issue(
                id="waiver.schema.invalid",
                evidence_id="production-beta.waiver-validation",
                domain_id="redaction-artifact-hygiene",
                severity="blocker",
                title="Waiver file is invalid",
                summary="Waiver file must use schemaVersion/version 1 and a waivers array.",
                source=source,
                waivable=False,
                category="waiver-validation",
            )
        ]
    waivers: list[Waiver] = []
    for index, entry in enumerate(records_value):
        validation_errors: list[str] = []
        if not isinstance(entry, dict):
            validation_errors.append("entry must be an object")
            entry = {}
        waiver_id = str(entry.get("id", "")).strip()
        evidence_id = str(entry.get("evidenceId", waiver_id)).strip()
        severity = str(entry.get("severity", "blocker")).strip().lower()
        scope = release_certification_scope(entry)
        rationale = str(entry.get("rationale", entry.get("reason", ""))).strip()
        approved_by = str(entry.get("approvedBy", "")).strip()
        owner = release_certification_owner(entry)
        created_at = str(entry.get("createdAt", "")).strip()
        expires_at = str(entry.get("expiresAt", "")).strip()
        references_value = entry.get("references", [])
        references = tuple(str(item) for item in references_value) if isinstance(references_value, list) else ()
        external_risk_accepted = entry.get("externalRiskAccepted") is True
        status = str(entry.get("status", "approved")).strip().lower()
        applies = scope_applies(scope, mode) if scope else False
        expiry = parse_time(expires_at)
        if not waiver_id:
            validation_errors.append("id is required")
        if not evidence_id:
            validation_errors.append("evidenceId is required")
        if severity not in SEVERITIES:
            validation_errors.append("severity must be info, warning, blocker, or critical")
        if not scope:
            validation_errors.append("scope is required")
        if not rationale:
            validation_errors.append("rationale is required")
        if not approved_by:
            validation_errors.append("approvedBy is required")
        if not owner:
            validation_errors.append("owner is required")
        if status != "approved":
            validation_errors.append("status must be approved")
        if not isinstance(references_value, list):
            validation_errors.append("references must be an array when provided")
        if not expires_at:
            validation_errors.append("expiresAt is required")
        elif expiry is None:
            validation_errors.append("expiresAt must be an ISO-8601 timestamp")
        elif expiry <= now:
            validation_errors.append("waiver is expired")
        if not applies:
            validation_errors.append(f"scope does not apply to {mode}")
        if evidence_id and evidence_id not in known_ids and not external_risk_accepted:
            validation_errors.append("evidenceId is unknown and externalRiskAccepted is not true")
        if mode == "production-beta" and evidence_id_is_non_waivable_in_mode(evidence_id, mode):
            validation_errors.append("target is non-waivable in production-beta mode")
        active = not validation_errors
        safe_errors = tuple(scrub_text(error, workspace_root, out_dir) for error in validation_errors)
        waiver = Waiver(
            id=scrub_text(waiver_id or f"{source}#{index}", workspace_root, out_dir),
            evidence_id=scrub_text(evidence_id or waiver_id or f"{source}#{index}", workspace_root, out_dir),
            severity=severity if severity in SEVERITIES else "blocker",
            scope=scrub_text(scope, workspace_root, out_dir),
            rationale=scrub_text(rationale, workspace_root, out_dir),
            approved_by=scrub_text(approved_by, workspace_root, out_dir),
            owner=scrub_text(owner, workspace_root, out_dir),
            created_at=scrub_text(created_at, workspace_root, out_dir),
            expires_at=scrub_text(expires_at if expiry is not None else expires_at, workspace_root, out_dir),
            references=tuple(scrub_text(reference, workspace_root, out_dir) for reference in references),
            source=source,
            active=active,
            applies_to_mode=applies,
            external_risk_accepted=external_risk_accepted,
            validation_errors=safe_errors,
        )
        waivers.append(waiver)
        if validation_errors:
            errors.append(
                Issue(
                    id=f"waiver.{waiver.id}.invalid",
                    evidence_id="production-beta.waiver-validation",
                    domain_id="redaction-artifact-hygiene",
                    severity="blocker",
                    title=f"Waiver {waiver.id} is invalid",
                    summary="; ".join(safe_errors),
                    source=source,
                    waivable=False,
                    category="waiver-validation",
                )
            )
    return waivers, errors


def apply_waivers(issues: list[Issue], waivers: list[Waiver], mode: str) -> tuple[list[Issue], list[Waiver], list[Issue]]:
    applied: list[Issue] = []
    usage: dict[str, list[str]] = {waiver.id: [] for waiver in waivers}
    validation_issues: list[Issue] = []
    for issue in issues:
        if issue.waived_by:
            matching = next(
                (
                    waiver
                    for waiver in waivers
                    if waiver.active
                    and waiver.id == issue.waived_by
                    and waiver.matches(issue)
                    and severity_covers(waiver, issue)
                ),
                None,
            )
            if matching is None or issue_is_non_waivable_in_mode(issue, mode):
                validation_issues.append(
                    Issue(
                        id=f"waiver.{issue.waived_by}.missing-or-invalid",
                        evidence_id="production-beta.waiver-validation",
                        domain_id="redaction-artifact-hygiene",
                        severity="blocker",
                        title="Applied waiver is missing or invalid",
                        summary=f"Evidence {issue.evidence_id} references waiver {issue.waived_by}, but no matching active waiver record is valid.",
                        source=issue.source,
                        waivable=False,
                        category="waiver-validation",
                    )
                )
                applied.append(dataclasses.replace(issue, waived_by=""))
                continue
            usage.setdefault(matching.id, []).append(issue.id)
            applied.append(dataclasses.replace(issue, waived_by=matching.id))
            continue
        if issue.severity not in {"blocker", "critical"} or not issue.waivable:
            applied.append(issue)
            continue
        matching = None
        under_severity = None
        for waiver in reversed(waivers):
            if not waiver.active or not waiver.matches(issue):
                continue
            if not severity_covers(waiver, issue):
                under_severity = waiver
                continue
            matching = waiver
            break
        if matching is None:
            if under_severity is not None:
                validation_issues.append(
                    Issue(
                        id=f"waiver.{under_severity.id}.severity-too-low",
                        evidence_id="production-beta.waiver-validation",
                        domain_id="redaction-artifact-hygiene",
                        severity="blocker",
                        title="Waiver severity is lower than finding severity",
                        summary=(
                            f"Waiver {under_severity.id} is approved for {under_severity.severity} "
                            f"but {issue.evidence_id} is {issue.severity}."
                        ),
                        source=under_severity.source,
                        waivable=False,
                        category="waiver-validation",
                    )
                )
            applied.append(issue)
            continue
        if issue_is_non_waivable_in_mode(issue, mode):
            validation_issues.append(
                Issue(
                    id=f"waiver.{matching.id}.non-waivable-target",
                    evidence_id="production-beta.waiver-validation",
                    domain_id="redaction-artifact-hygiene",
                    severity="blocker",
                    title="Waiver targets a non-waivable finding",
                    summary=f"Waiver {matching.id} cannot waive {issue.evidence_id}.",
                    source=matching.source,
                    waivable=False,
                    category="waiver-validation",
                )
            )
            applied.append(issue)
            continue
        usage[matching.id].append(issue.id)
        applied.append(dataclasses.replace(issue, waived_by=matching.id))
    used_waivers = [waiver.with_usage(usage.get(waiver.id, [])) for waiver in waivers]
    return [*applied, *validation_issues], used_waivers, validation_issues


def live_evidence_required(inputs: dict[str, Any], mode: str) -> bool:
    if mode == "production-beta":
        return True
    summary = inputs.get("liveNetworkSummary")
    if not isinstance(summary, dict):
        return False
    return summary.get("enabled") is True or summary.get("required") is True


def collect_issues(
    inputs: dict[str, Any],
    mode: str,
    input_paths: dict[str, Path],
    now: dt.datetime,
    release_id: str,
) -> tuple[list[Issue], dict[str, dict[str, Any]]]:
    all_evidence = evidence_map(
        inputs.get("releaseCertificationSummary"),
        inputs.get("appPlatformSummary"),
        inputs.get("liveNetworkSummary"),
        inputs.get("securityResponseSummary"),
    )
    for evidence_id, entry in multi_node_scenario_evidence(
        inputs.get("multiNodeBetaSoakSummary")
    ).items():
        all_evidence.setdefault(evidence_id, entry)
    if "securityDrillsSummary" in inputs:
        security_drills_evidence = security_response_evidence(
            inputs.get("securityDrillsSummary"),
            "security-drills-summary",
            production=mode == "production-beta",
            strict=mode in {"release-candidate", "production-beta"},
            now=now,
            expected_release_id=release_id,
            expected_mode=mode if mode in {"release-candidate", "production-beta"} else None,
            summary_path=input_paths.get("securityDrillsSummary"),
        )
        if security_drills_evidence is not None:
            existing_security_entries = [
                *evidence_entries(
                    inputs.get("releaseCertificationSummary"),
                    "production-security.response-runbook",
                ),
                *evidence_entries(
                    inputs.get("appPlatformSummary"),
                    "production-security.response-runbook",
                ),
                *evidence_entries(
                    inputs.get("securityResponseSummary"),
                    "production-security.response-runbook",
                ),
            ]
            if not existing_security_entries and "production-security.response-runbook" in all_evidence:
                existing_security_entries = [all_evidence["production-security.response-runbook"]]
            all_evidence["production-security.response-runbook"] = combine_security_response_evidence(
                existing_security_entries,
                security_drills_evidence,
            )
        else:
            all_evidence.pop("production-security.response-runbook", None)
    else:
        standalone_security_evidence = security_response_evidence(inputs.get("securityResponseSummary"))
        if standalone_security_evidence is not None:
            all_evidence.setdefault("production-security.response-runbook", standalone_security_evidence)
    issues: list[Issue] = []
    for name in CRITICAL_INPUTS_BY_MODE.get(mode, ()):
        if name not in inputs:
            issues.append(input_missing_issue(name, mode))
    for name, path in input_paths.items():
        if name != "waivers" and name not in inputs and name in {spec_name for spec in DOMAIN_SPECS for spec_name in spec.get("artifactInputs", ())}:
            issues.append(input_missing_issue(name, mode))
    issues.extend(production_summary_issues(inputs.get("productionBetaSummary"), mode))
    issues.extend(release_certification_issues(inputs.get("releaseCertificationSummary"), mode))
    issues.extend(ecosystem_matrix_issues(inputs.get("ecosystemMatrix")))
    issues.extend(network_scale_issues(inputs.get("networkScaleSoakSummary"), mode))
    issues.extend(
        multi_node_issues(
            inputs.get("multiNodeBetaSoakSummary"),
            mode,
            inputs.get("productionBetaSummary") if isinstance(inputs.get("productionBetaSummary"), dict) else None,
        )
    )
    for spec in DOMAIN_SPECS:
        domain_id = str(spec["id"])
        if domain_id in {
            "production-beta-release-pipeline",
            "release-certification",
            "ecosystem-rc-certification-matrix",
            "network-scale-soak",
            "multi-node-beta-soak",
            "redaction-artifact-hygiene",
        }:
            continue
        if domain_id == "live-network-beta-smoke" and not live_evidence_required(inputs, mode):
            continue
        for evidence_id in spec["evidenceIds"]:
            issue = issue_for_evidence(domain_id, str(evidence_id), all_evidence.get(str(evidence_id)), mode)
            if issue is not None:
                issues.append(issue)
    return dedupe_issues(issues), all_evidence


def dedupe_issues(issues: list[Issue]) -> list[Issue]:
    result: list[Issue] = []
    seen: set[str] = set()
    for issue in sorted(issues, key=lambda item: (item.id, item.evidence_id, item.summary)):
        if issue.id in seen:
            continue
        seen.add(issue.id)
        result.append(issue)
    return result


def known_ids(all_evidence: dict[str, dict[str, Any]], issues: list[Issue]) -> set[str]:
    ids = set(all_evidence)
    for spec in DOMAIN_SPECS:
        ids.add(str(spec["id"]))
        ids.update(str(evidence_id) for evidence_id in spec["evidenceIds"])
    ids.update(DASHBOARD_EVIDENCE_IDS)
    for issue in issues:
        ids.update({issue.id, issue.evidence_id, issue.domain_id, f"evidence.{issue.evidence_id}"})
    ids.update(NON_WAIVABLE_EVIDENCE_IDS)
    ids.update(PRODUCTION_BETA_NON_WAIVABLE_EVIDENCE_IDS)
    ids.update(PRODUCTION_ARTIFACT_GATE_IDS)
    return expand_waiver_target_aliases(*ids)


def decision_from_issues(issues: list[Issue]) -> str:
    unwaived = [issue for issue in issues if issue.severity in {"critical", "blocker"} and not issue.waived_by]
    if unwaived:
        return "no-go"
    if any(issue.waived_by for issue in issues if issue.severity in {"critical", "blocker"}):
        return "go-with-waivers"
    return "go"


def recommendation_for(decision: str, blockers: list[Issue], warnings: list[Issue]) -> str:
    if decision == "go":
        return "Launch candidate is ready for production beta promotion."
    if decision == "go-with-waivers":
        return "Launch candidate is promotable only with the listed approved waivers preserved in the release record."
    if blockers:
        return f"Do not launch. Resolve or replace the top blocker: {blockers[0].title}."
    if warnings:
        return "Do not launch until dashboard warnings are reviewed and the decision is regenerated."
    return "Do not launch until the dashboard can be regenerated from complete evidence."


def build_dashboard(
    inputs: dict[str, Any],
    input_paths: dict[str, Path],
    scan_targets: list[Path],
    waiver_value: dict[str, Any] | None,
    workspace_root: Path,
    out_dir: Path,
    mode: str,
    release_id: str,
    generated_at: str,
    now: dt.datetime,
) -> dict[str, Any]:
    if mode not in MODES:
        raise SystemExit(f"--mode must be one of {', '.join(MODES)}")
    issues, all_evidence = collect_issues(inputs, mode, input_paths, now, release_id)
    imported_waivers = release_certification_waiver_records(
        inputs.get("releaseCertificationSummary") if isinstance(inputs.get("releaseCertificationSummary"), dict) else None,
        mode,
        now,
        workspace_root,
        out_dir,
    )
    waivers, waiver_issues = load_waivers(
        waiver_value,
        display_path(input_paths.get("waivers", Path("waivers.json")), workspace_root) if input_paths.get("waivers") else "fixture-waivers",
        mode,
        now,
        known_ids(all_evidence, issues),
        workspace_root,
        out_dir,
    )
    waivers = [*imported_waivers, *waivers]
    issues = dedupe_issues([*issues, *waiver_issues])
    issues, waivers, _validation_issues = apply_waivers(issues, waivers, mode)
    domains = build_domain_rows(inputs, input_paths, workspace_root, out_dir, issues, all_evidence)
    redaction = redaction_report(scan_paths(scan_targets, workspace_root, out_dir))
    if redaction["status"] != "pass":
        redaction_issue = Issue(
            id="dashboard.redaction.scan",
            evidence_id="production-beta.dashboard-redaction",
            domain_id="redaction-artifact-hygiene",
            severity="critical",
            title="Dashboard input redaction scan failed",
            summary=f"Dashboard redaction scanner found {redaction['findingCount']} finding(s).",
            source="dashboard-redaction",
            waivable=False,
            category="redaction",
        )
        issues = dedupe_issues([*issues, redaction_issue])
        domains = build_domain_rows(inputs, input_paths, workspace_root, out_dir, issues, all_evidence)
    blockers = [issue for issue in issues if issue.severity in {"critical", "blocker"} and not issue.waived_by]
    warnings = [issue for issue in issues if issue.severity == "warning" or issue.waived_by]
    decision = decision_from_issues(issues)
    production_summary = inputs.get("productionBetaSummary") if isinstance(inputs.get("productionBetaSummary"), dict) else {}
    multi_node_summary = (
        inputs.get("multiNodeBetaSoakSummary")
        if isinstance(inputs.get("multiNodeBetaSoakSummary"), dict)
        else {}
    )
    previous_upgrade = (
        multi_node_summary.get("previousCandidateUpgrade")
        if isinstance(multi_node_summary.get("previousCandidateUpgrade"), dict)
        else {"status": "missing"}
    )
    security_response_item = all_evidence.get("production-security.response-runbook")
    security_response_details = evidence_details(security_response_item)
    security_drills_component = security_response_details.get("securityDrills")
    security_drills_details = (
        evidence_details(security_drills_component)
        if isinstance(security_drills_component, dict)
        else {}
    )
    artifact_validation = security_drills_details.get("artifactValidation")
    security_drills = compact_security_drills(
        inputs.get("securityDrillsSummary") if isinstance(inputs.get("securityDrillsSummary"), dict) else None,
        production=mode == "production-beta",
        strict=mode in {"release-candidate", "production-beta"},
        now=now,
        expected_release_id=release_id,
        expected_mode=mode if mode in {"release-candidate", "production-beta"} else None,
        artifact_validation=(
            artifact_validation
            if isinstance(artifact_validation, dict) and "status" in artifact_validation
            else None
        ),
    )
    artifact_refs = {
        "dashboardJson": OUTPUT_JSON,
        "dashboardMarkdown": OUTPUT_MARKDOWN,
        "dashboardRedactionReport": OUTPUT_REDACTION,
    }
    artifacts = production_summary.get("artifacts") if isinstance(production_summary.get("artifacts"), dict) else {}
    for key in ("redactionReport", "distArchive", "checksums", "ecosystemCertification", "multiNodeBetaSoak"):
        if key in artifacts:
            artifact_refs[key] = str(artifacts[key])
    dashboard = {
        "schemaVersion": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "generatedAt": generated_at,
        "mode": mode,
        "releaseId": scrub_text(release_id, workspace_root, out_dir),
        "decision": decision,
        "promotionReady": decision in {"go", "go-with-waivers"},
        "summary": {
            "blockers": len(blockers),
            "warnings": len(warnings),
            "waiversUsed": sum(1 for waiver in waivers if waiver.used_by),
            "criticalRedactionFindings": int(redaction.get("criticalFindingCount", 0)),
            "criticalFindings": sum(1 for issue in issues if issue.severity == "critical" and not issue.waived_by),
        },
        "domains": domains,
        "blockers": [issue.to_json() for issue in blockers],
        "warnings": [issue.to_json() for issue in warnings],
        "waivers": [waiver.to_json() for waiver in waivers],
        "previousCandidateUpgrade": previous_upgrade,
        "securityDrills": security_drills,
        "redaction": redaction,
        "recommendation": recommendation_for(decision, blockers, warnings),
        "artifactRefs": artifact_refs,
    }
    return sanitize_value(dashboard, workspace_root, out_dir)


def render_markdown(dashboard: dict[str, Any]) -> str:
    decision_label = {
        "go": "GO",
        "no-go": "NO-GO",
        "go-with-waivers": "GO WITH WAIVERS",
    }.get(str(dashboard.get("decision")), "NO-GO")
    lines = [
        "# Production Beta Go/No-Go Dashboard",
        "",
        f"- Release ID: `{dashboard.get('releaseId', '')}`",
        f"- Mode: `{dashboard.get('mode', '')}`",
        f"- Decision: **{decision_label}**",
        f"- Promotion ready: `{str(dashboard.get('promotionReady', False)).lower()}`",
        f"- Generated: `{dashboard.get('generatedAt', '')}`",
        f"- Recommendation: {dashboard.get('recommendation', '')}",
        "",
        "## Security Drills",
        "",
    ]
    security_drills = dashboard.get("securityDrills") if isinstance(dashboard.get("securityDrills"), dict) else {}
    lines.extend(
        [
            f"- Status: `{security_drills.get('status', 'missing')}`",
            f"- Promotion ready: `{str(security_drills.get('promotionReady', False)).lower()}`",
            f"- Required scenarios: `{security_drills.get('requiredScenarioCount', 0)}`",
            f"- Passed scenarios: `{security_drills.get('passedScenarioCount', 0)}`",
            f"- Failed scenarios: `{security_drills.get('failedScenarioCount', 0)}`",
            f"- Missing scenarios: `{security_drills.get('missingScenarioCount', 0)}`",
            f"- Stale scenarios: `{security_drills.get('staleScenarioCount', 0)}`",
            f"- Redaction: `{security_drills.get('redactionStatus', 'missing')}`",
            f"- Release notes template: `{security_drills.get('releaseNotesTemplateStatus', 'missing')}`",
            f"- Advisory template: `{security_drills.get('advisoryTemplateStatus', 'missing')}`",
            f"- Support-bundle intake redaction: `{security_drills.get('supportBundleIntakeRedactionStatus', 'missing')}`",
            "",
        ]
    )
    if security_drills.get("failedScenarios"):
        lines.append(f"- Failed: {markdown_code_list(security_drills.get('failedScenarios', []))}")
    if security_drills.get("missingScenarios"):
        lines.append(f"- Missing: {markdown_code_list(security_drills.get('missingScenarios', []))}")
    if security_drills.get("staleScenarios"):
        lines.append(f"- Stale: {markdown_code_list(security_drills.get('staleScenarios', []))}")
    lines.extend(
        [
            "",
            "## Top Blockers",
            "",
        ]
    )
    blockers = dashboard.get("blockers", [])
    if not blockers:
        lines.append("No unwaived blockers.")
    else:
        for issue in blockers[:10]:
            if isinstance(issue, dict):
                lines.append(f"- `{issue.get('evidenceId', '')}`: {issue.get('summary', '')}")
    lines.extend(["", "## Top Warnings", ""])
    warnings = dashboard.get("warnings", [])
    if not warnings:
        lines.append("No warnings.")
    else:
        for issue in warnings[:10]:
            if isinstance(issue, dict):
                waived = f" Waiver: `{issue.get('waivedBy')}`." if issue.get("waivedBy") else ""
                lines.append(f"- `{issue.get('evidenceId', '')}`: {issue.get('summary', '')}{waived}")
    upgrade = dashboard.get("previousCandidateUpgrade")
    if isinstance(upgrade, dict) and upgrade:
        lines.extend(
            [
                "",
                "## Previous Candidate Upgrade",
                "",
                f"- Previous release: `{upgrade.get('previousReleaseId', 'missing')}`",
                f"- Previous version: `{upgrade.get('previousVersion', 'missing')}`",
                f"- Current version: `{upgrade.get('currentVersion', 'missing')}`",
                f"- Previous summary: `{upgrade.get('previousSummaryStatus', 'missing')}`",
                f"- Upgrade drill: `{upgrade.get('status', 'missing')}`",
                f"- App migrations: `{upgrade.get('firstPartyAppMigrationStatus', 'missing')}`",
                f"- Backup before update: `{upgrade.get('backupBeforeUpdateStatus', 'missing')}`",
                f"- Restore into clean node: `{upgrade.get('restoreIntoCleanNodeStatus', 'missing')}`",
                f"- Social Inbox migration: `{upgrade.get('socialInboxMigrationStatus', 'missing')}`",
                f"- Trust Graph migration: `{upgrade.get('trustGraphMigrationStatus', 'missing')}`",
                f"- Support bundle redaction: `{upgrade.get('supportBundleRedactionStatus', 'missing')}`",
            ]
        )
    lines.extend(["", "## Waivers Used", ""])
    waivers = [waiver for waiver in dashboard.get("waivers", []) if isinstance(waiver, dict) and waiver.get("usedBy")]
    if not waivers:
        lines.append("No waivers were used.")
    else:
        lines.extend(["| Waiver | Evidence | Scope | Expires | Used by |", "| --- | --- | --- | --- | --- |"])
        for waiver in waivers:
            lines.append(
                "| `{}` | `{}` | `{}` | `{}` | {} |".format(
                    waiver.get("id", ""),
                    waiver.get("evidenceId", ""),
                    waiver.get("scope", ""),
                    waiver.get("expiresAt", ""),
                    markdown_code_list(waiver.get("usedBy", [])),
                )
            )
    lines.extend(["", "## Domain Table", ""])
    lines.extend(["| Domain | Status | Required | Evidence | Artifacts |", "| --- | --- | --- | --- | --- |"])
    for domain in dashboard.get("domains", []):
        if not isinstance(domain, dict):
            continue
        lines.append(
            "| {} | `{}` | `{}` | {} | {} |".format(
                markdown_cell(domain.get("title", domain.get("id", ""))),
                domain.get("status", ""),
                domain.get("severity", "required"),
                markdown_code_list(domain.get("evidenceIds", [])),
                markdown_code_list(domain.get("artifactRefs", [])),
            )
        )
    redaction = dashboard.get("redaction") if isinstance(dashboard.get("redaction"), dict) else {}
    lines.extend(
        [
            "",
            "## Redaction Status",
            "",
            f"- Status: `{redaction.get('status', 'missing')}`",
            f"- Findings: `{redaction.get('findingCount', 0)}`",
            f"- Critical findings: `{redaction.get('criticalFindingCount', 0)}`",
        ]
    )
    for finding in redaction.get("findings", [])[:10] if isinstance(redaction.get("findings"), list) else []:
        if isinstance(finding, dict):
            detail = f": {finding.get('detail')}" if finding.get("detail") else ""
            lines.append(f"- `{finding.get('kind', '')}` at `{finding.get('path', '')}`{detail}")
    lines.extend(["", "## Required Follow-Ups", ""])
    if blockers:
        lines.append("- Resolve all unwaived blockers and regenerate the dashboard.")
    if redaction.get("status") != "pass":
        lines.append("- Remove unsafe input/output content and regenerate the redaction report.")
    invalid_waivers = [
        waiver
        for waiver in dashboard.get("waivers", [])
        if isinstance(waiver, dict) and waiver.get("validationErrors")
    ]
    if invalid_waivers:
        lines.append("- Fix invalid or expired waiver records before promotion.")
    if not blockers and redaction.get("status") == "pass" and not invalid_waivers:
        lines.append("- Preserve this dashboard and the listed redacted artifacts with the release candidate.")
    lines.extend(["", "## Redacted Artifacts", ""])
    artifact_refs = dashboard.get("artifactRefs", {}) if isinstance(dashboard.get("artifactRefs"), dict) else {}
    for name in sorted(artifact_refs):
        lines.append(f"- `{name}`: `{artifact_refs[name]}`")
    lines.append("")
    return "\n".join(lines)


def markdown_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def markdown_code_list(values: Any) -> str:
    if not isinstance(values, list):
        return ""
    return ", ".join(f"`{markdown_cell(value)}`" for value in values)


def write_dashboard_artifacts(dashboard: dict[str, Any], out_dir: Path, workspace_root: Path) -> dict[str, Any]:
    write_json(out_dir / OUTPUT_JSON, dashboard)
    write_text(out_dir / OUTPUT_MARKDOWN, render_markdown(dashboard))
    output_findings = scan_paths([out_dir / OUTPUT_JSON, out_dir / OUTPUT_MARKDOWN], workspace_root, out_dir)
    combined_findings = [
        *dashboard.get("redaction", {}).get("findings", []),
        *output_findings,
    ]
    final_redaction = redaction_report([finding for finding in combined_findings if isinstance(finding, dict)])
    dashboard["redaction"] = final_redaction
    if final_redaction["status"] != "pass" and dashboard.get("decision") != "no-go":
        issue = {
            "id": "dashboard.output-redaction.scan",
            "evidenceId": "production-beta.dashboard-redaction",
            "domainId": "redaction-artifact-hygiene",
            "severity": "critical",
            "title": "Dashboard output redaction scan failed",
            "summary": f"Dashboard output redaction scanner found {final_redaction['findingCount']} finding(s).",
            "source": "dashboard-redaction",
            "waivable": False,
            "category": "redaction",
        }
        dashboard["decision"] = "no-go"
        dashboard["promotionReady"] = False
        dashboard.setdefault("blockers", []).append(issue)
        summary = dashboard.setdefault("summary", {})
        summary["blockers"] = int(summary.get("blockers", 0)) + 1
        summary["criticalRedactionFindings"] = int(final_redaction.get("criticalFindingCount", 0))
        dashboard["recommendation"] = "Do not launch. Resolve dashboard output redaction findings and regenerate."
    write_json(out_dir / OUTPUT_JSON, dashboard)
    write_text(out_dir / OUTPUT_MARKDOWN, render_markdown(dashboard))
    write_json(out_dir / OUTPUT_REDACTION, final_redaction)
    return dashboard


def build_command(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    workspace_root = args.workspace_root.resolve()
    out_dir = args.out_dir if args.out_dir.is_absolute() else workspace_root / args.out_dir
    out_dir = out_dir.resolve()
    if args.fixtures is not None:
        inputs, paths, scan_targets, waiver_value, release_id, fixture_mode, fixture_generated_at = load_inputs_from_fixture(args, workspace_root)
        mode = args.mode or fixture_mode
        generated_at, now = parse_generated_at(args.generated_at or fixture_generated_at)
    else:
        inputs, paths, scan_targets, waiver_value, release_id = load_inputs_from_paths(args, workspace_root)
        mode = args.mode or "developer-dry-run"
        generated_at, now = parse_generated_at(args.generated_at)
    dashboard = build_dashboard(
        inputs,
        paths,
        scan_targets,
        waiver_value,
        workspace_root,
        out_dir,
        mode,
        release_id,
        generated_at,
        now,
    )
    dashboard = write_dashboard_artifacts(dashboard, out_dir, workspace_root)
    return dashboard, 0 if dashboard["decision"] in {"go", "go-with-waivers"} else 1


def run_self_test(quiet: bool = False) -> None:
    content_format_evidence_id = "app-platform.trust-social-content-format-profiles"
    privacy_diagnostics_evidence_id = "app-platform.privacy-preserving-beta-diagnostics"
    plugin_migration_evidence_id = "legacy-plugin.migration-finalization"
    if content_format_evidence_id not in CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS:
        raise AssertionError("content-format profile evidence must be production-critical")
    if privacy_diagnostics_evidence_id not in CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS:
        raise AssertionError("privacy-preserving diagnostics evidence must be production-critical")
    if plugin_migration_evidence_id not in CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS:
        raise AssertionError("legacy plugin migration finalization evidence must be production-critical")
    if not evidence_id_is_non_waivable_in_mode(content_format_evidence_id, "production-beta"):
        raise AssertionError(
            "content-format profile evidence must be non-waivable in production-beta"
        )
    if not evidence_id_is_non_waivable_in_mode(
        f"evidence.{content_format_evidence_id}",
        "production-beta",
    ):
        raise AssertionError(
            "content-format profile promotion gate must be non-waivable in production-beta"
        )
    if not evidence_id_is_non_waivable_in_mode(
        privacy_diagnostics_evidence_id,
        "production-beta",
    ):
        raise AssertionError("privacy-preserving diagnostics evidence must be non-waivable")
    if not evidence_id_is_non_waivable_in_mode(
        f"evidence.{privacy_diagnostics_evidence_id}",
        "production-beta",
    ):
        raise AssertionError(
            "privacy-preserving diagnostics promotion gate must be non-waivable"
        )
    if not evidence_id_is_non_waivable_in_mode(
        plugin_migration_evidence_id,
        "production-beta",
    ):
        raise AssertionError("legacy plugin migration finalization must be non-waivable")
    if not evidence_id_is_non_waivable_in_mode(
        f"evidence.{plugin_migration_evidence_id}",
        "production-beta",
    ):
        raise AssertionError(
            "legacy plugin migration finalization gate must be non-waivable"
        )
    for evidence_id in CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS:
        if not evidence_id_is_non_waivable_in_mode(evidence_id, "production-beta"):
            raise AssertionError(f"production critical evidence is waivable in production-beta: {evidence_id}")
        gate_id = f"evidence.{evidence_id}"
        if not evidence_id_is_non_waivable_in_mode(gate_id, "production-beta"):
            raise AssertionError(f"production critical evidence gate is waivable in production-beta: {gate_id}")
    if evidence_id_is_non_waivable_in_mode("app-store.submission-cli", "release-candidate"):
        raise AssertionError("release-candidate app-store evidence should remain waiverable")
    if not evidence_id_is_non_waivable_in_mode(
        "multi-node-beta.previous-candidate-upgrade-binding",
        "production-beta",
    ):
        raise AssertionError("previous-candidate binding failures must be non-waivable in production-beta")

    fixture_expectations = {
        "go-no-go-pass.json": "go",
        "go-no-go-no-go.json": "no-go",
        "go-no-go-with-waivers.json": "no-go",
        "go-no-go-expired-waiver.json": "no-go",
        "go-no-go-waiver-valid-at-generated-at.json": "no-go",
        "go-no-go-critical-redaction.json": "no-go",
        "go-no-go-test-signing-production.json": "no-go",
        "go-no-go-summary-failure-with-gates.json": "no-go",
        "go-no-go-production-summary-not-ready.json": "no-go",
        "go-no-go-production-summary-skipped.json": "no-go",
        "go-no-go-missing-ecosystem-matrix-status.json": "no-go",
        "go-no-go-warning-ecosystem-matrix.json": "go",
        "go-no-go-malformed-ecosystem-matrix-count.json": "no-go",
        "go-no-go-release-cert-schema-waiver.json": "go-with-waivers",
        "go-no-go-release-cert-applied-waiver.json": "go-with-waivers",
        "go-no-go-release-cert-applied-waiver-expired.json": "no-go",
        "go-no-go-release-cert-applied-waiver-missing-record.json": "no-go",
        "go-no-go-artifact-gate-waiver.json": "no-go",
        "go-no-go-warning-redaction-findings.json": "no-go",
        "go-no-go-multi-node-upgrade-waiver.json": "go-with-waivers",
        "go-no-go-network-scale-redaction-waiver.json": "no-go",
        "go-no-go-previous-candidate-warning.json": "no-go",
        "go-no-go-previous-candidate-binding-waiver.json": "no-go",
        "go-no-go-secret-value-redaction.json": "no-go",
        "go-no-go-underseverity-waiver.json": "no-go",
        "go-no-go-live-evidence-waiver-alias.json": "no-go",
        "go-no-go-live-network-skip-waiver.json": "no-go",
        "go-no-go-production-critical-evidence-waiver.json": "no-go",
        "go-no-go-release-candidate-live-waiver.json": "go-with-waivers",
        "go-no-go-release-candidate-live-disabled.json": "no-go",
        "go-no-go-malformed-non-release-status.json": "no-go",
        "go-no-go-security-drills-missing-summary.json": "no-go",
        "go-no-go-security-drills-missing-scenario.json": "no-go",
        "go-no-go-security-drills-failed-scenario.json": "no-go",
        "go-no-go-security-drills-stale-scenario.json": "no-go",
        "go-no-go-security-drills-redaction-unsafe.json": "no-go",
        "go-no-go-security-drills-fixture-only.json": "no-go",
        "go-no-go-security-drills-developer-dry-run.json": "no-go",
        "go-no-go-security-drills-malformed-envelope.json": "no-go",
        "go-no-go-security-drills-single-artifact-pass.json": "no-go",
        "go-no-go-security-drills-malformed-count.json": "no-go",
        "go-no-go-security-drills-expired-waiver.json": "no-go",
        "go-no-go-security-drills-underseverity-redaction-waiver.json": "no-go",
    }
    with tempfile.TemporaryDirectory(prefix="cryptad-go-no-go-dashboard-") as temp_name:
        root = Path(temp_name)
        outputs: dict[str, str] = {}
        for fixture_name, expected in fixture_expectations.items():
            out_dir = root / fixture_name.removesuffix(".json")
            fixture = FIXTURE_DIR / fixture_name
            args = build_parser().parse_args(
                [
                    "build",
                    "--workspace-root",
                    str(Path(__file__).resolve().parents[2]),
                    "--out-dir",
                    str(out_dir),
                    "--fixtures",
                    str(fixture),
                ]
            )
            dashboard, _exit_code = build_command(args)
            if dashboard["decision"] != expected:
                raise AssertionError(f"{fixture_name} expected {expected}, got {dashboard['decision']}: {dashboard}")
            blocker_ids = {
                str(blocker.get("evidenceId"))
                for blocker in dashboard.get("blockers", [])
                if isinstance(blocker, dict)
            }
            if fixture_name == "go-no-go-underseverity-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("under-severity waiver was incorrectly used")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("under-severity waiver did not produce a waiver-validation blocker")
            if fixture_name == "go-no-go-expired-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("expired waiver was incorrectly used")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("expired waiver did not produce a waiver-validation blocker")
                if dashboard.get("generatedAt") != "2026-06-24T00:00:00Z":
                    raise AssertionError("expired waiver fixture did not use its recorded generatedAt")
            if fixture_name.startswith("go-no-go-security-drills-"):
                if "production-security.response-runbook" not in blocker_ids:
                    raise AssertionError(
                        f"{fixture_name} did not block on production security response evidence"
                    )
                security_drills = dashboard.get("securityDrills")
                if not isinstance(security_drills, dict) or security_drills.get("promotionReady") is True:
                    raise AssertionError(f"{fixture_name} left security drills promotion-ready")
            if fixture_name == "go-no-go-security-drills-redaction-unsafe.json":
                critical_security_blockers = [
                    blocker
                    for blocker in dashboard.get("blockers", [])
                    if isinstance(blocker, dict)
                    and blocker.get("evidenceId") == "production-security.response-runbook"
                    and blocker.get("severity") == "critical"
                ]
                if not critical_security_blockers:
                    raise AssertionError("redaction-unsafe drill fixture did not create a critical blocker")
            if fixture_name in {
                "go-no-go-security-drills-expired-waiver.json",
                "go-no-go-security-drills-underseverity-redaction-waiver.json",
            }:
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("security drill waiver fixture was incorrectly used")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("security drill waiver fixture did not fail waiver validation")
            if fixture_name == "go-no-go-waiver-valid-at-generated-at.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("non-waivable live evidence waiver was incorrectly used")
                if dashboard.get("generatedAt") != "1999-06-24T00:00:00Z":
                    raise AssertionError("historical waiver fixture did not use its recorded generatedAt")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("historical non-waivable live evidence waiver did not fail validation")
            if fixture_name == "go-no-go-production-summary-not-ready.json":
                if "production-beta.promotion-ready" not in blocker_ids:
                    raise AssertionError("non-ready production summary did not block production beta")
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("promotionReady=false hard blocker was incorrectly waived")
            if fixture_name == "go-no-go-production-summary-skipped.json":
                if "production-beta.summary" not in blocker_ids:
                    raise AssertionError("skipped production summary did not block production beta")
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("non-passing production summary hard blocker was incorrectly waived")
            if fixture_name == "go-no-go-previous-candidate-binding-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("previous-candidate binding waiver was incorrectly used")
                if "multi-node-beta.previous-candidate-upgrade-binding" not in blocker_ids:
                    raise AssertionError("previous-candidate binding failure did not remain blocked")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("previous-candidate binding waiver did not fail waiver validation")
            if fixture_name == "go-no-go-live-evidence-waiver-alias.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("live evidence alias waiver was incorrectly used")
                if "live-network-beta.content-fetch" not in blocker_ids:
                    raise AssertionError("live evidence waiver attempt did not leave live-network evidence blocked")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("live evidence waiver attempt did not fail waiver validation")
            if fixture_name == "go-no-go-release-candidate-live-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 1:
                    raise AssertionError("release-candidate live evidence waiver was not used")
                waived_evidence_ids = {
                    str(warning.get("evidenceId"))
                    for warning in dashboard.get("warnings", [])
                    if isinstance(warning, dict) and warning.get("waivedBy")
                }
                if "live-network-beta.content-fetch" not in waived_evidence_ids:
                    raise AssertionError("release-candidate live evidence waiver did not waive content-fetch evidence")
            if fixture_name == "go-no-go-production-critical-evidence-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("production-critical evidence waiver was incorrectly used")
                if "app-store.submission-cli" not in blocker_ids:
                    raise AssertionError("production-critical app-store evidence did not remain blocked")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("production-critical evidence waiver attempt did not fail validation")
            if fixture_name == "go-no-go-release-cert-schema-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 1:
                    raise AssertionError("release-certification schema waiver was not used by dashboard")
                waived_evidence_ids = {
                    str(warning.get("evidenceId"))
                    for warning in dashboard.get("warnings", [])
                    if isinstance(warning, dict) and warning.get("waivedBy")
                }
                if "app-store.submission-cli" not in waived_evidence_ids:
                    raise AssertionError("canonical app-store evidence id did not waive evidence-prefixed gate")
                if any(
                    str(warning.get("evidenceId")).startswith("evidence.")
                    for warning in dashboard.get("warnings", [])
                    if isinstance(warning, dict)
                ):
                    raise AssertionError("dashboard exposed evidence-prefixed promotion evidence id")
            if fixture_name == "go-no-go-release-cert-applied-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 1:
                    raise AssertionError("already-applied release-certification waiver was not preserved")
                waived_evidence_ids = {
                    str(warning.get("evidenceId"))
                    for warning in dashboard.get("warnings", [])
                    if isinstance(warning, dict) and warning.get("waivedBy")
                }
                if "release-certification.ecosystem-rc-gate" not in waived_evidence_ids:
                    raise AssertionError("already-applied release-certification waiver did not remain visible")
            if fixture_name == "go-no-go-release-cert-applied-waiver-expired.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("expired release-certification waiver record was incorrectly counted")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("expired release-certification waiver record did not block the dashboard")
            if fixture_name == "go-no-go-release-cert-applied-waiver-missing-record.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("missing release-certification waiver record was incorrectly counted")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("missing release-certification waiver record did not block the dashboard")
            if fixture_name == "go-no-go-artifact-gate-waiver.json":
                if "artifact.signed-first-party-bundles" not in blocker_ids:
                    raise AssertionError("artifact-presence gate waiver incorrectly removed the blocker")
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("artifact-presence gate waiver was incorrectly used")
            if fixture_name == "go-no-go-warning-redaction-findings.json":
                if "release-certification.ecosystem-rc-gate" not in blocker_ids:
                    raise AssertionError("warning evidence with redaction findings did not block launch")
                critical_ids = {
                    str(blocker.get("evidenceId"))
                    for blocker in dashboard.get("blockers", [])
                    if isinstance(blocker, dict) and blocker.get("severity") == "critical"
                }
                if "release-certification.ecosystem-rc-gate" not in critical_ids:
                    raise AssertionError("warning evidence redaction findings were not critical")
            if fixture_name == "go-no-go-multi-node-upgrade-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 1:
                    raise AssertionError("canonical multi-node upgrade-drill waiver was not used")
                waived_evidence_ids = {
                    str(warning.get("evidenceId"))
                    for warning in dashboard.get("warnings", [])
                    if isinstance(warning, dict) and warning.get("waivedBy")
                }
                if "multi-node-beta.upgrade-drill" not in waived_evidence_ids:
                    raise AssertionError("multi-node upgrade scenario did not use canonical evidence id")
            if fixture_name == "go-no-go-live-network-skip-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("live-network production-beta skip hard blocker was incorrectly waived")
                if "live.production-beta-skip" not in blocker_ids:
                    raise AssertionError("live-network production-beta skip did not block launch")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("live-network production-beta skip waiver did not fail validation")
            if fixture_name == "go-no-go-release-candidate-live-disabled.json":
                if any(blocker_id.startswith("live-network-beta.") for blocker_id in blocker_ids):
                    raise AssertionError("disabled live-network evidence blocked release-candidate mode")
                if "production-beta.non-release" not in blocker_ids:
                    raise AssertionError("release-candidate non-release artifact did not block publication")
            if fixture_name == "go-no-go-malformed-non-release-status.json":
                if "production-beta.non-release" not in blocker_ids:
                    raise AssertionError("malformed nonRelease value did not block launchable decision")
            if fixture_name == "go-no-go-malformed-ecosystem-matrix-count.json":
                if "release-certification.ecosystem-matrix" not in blocker_ids:
                    raise AssertionError("malformed ecosystem matrix releaseBlockerCount did not block launch")
            if fixture_name == "go-no-go-network-scale-redaction-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 1:
                    raise AssertionError("network-scale status waiver was not recorded")
                if "network-scale.redaction" not in blocker_ids:
                    raise AssertionError("network-scale redaction failure was incorrectly waived")
                waived_evidence_ids = {
                    str(warning.get("evidenceId"))
                    for warning in dashboard.get("warnings", [])
                    if isinstance(warning, dict) and warning.get("waivedBy")
                }
                if "network-scale.rc-soak-summary" not in waived_evidence_ids:
                    raise AssertionError("network-scale status waiver did not apply to the generic status issue")
            for artifact_name in (OUTPUT_JSON, OUTPUT_MARKDOWN, OUTPUT_REDACTION):
                if not (out_dir / artifact_name).is_file():
                    raise AssertionError(f"{fixture_name} did not write {artifact_name}")
            markdown = (out_dir / OUTPUT_MARKDOWN).read_text(encoding="utf-8")
            for required in ("Production Beta Go/No-Go Dashboard", "Domain Table", "Redaction Status"):
                if required not in markdown:
                    raise AssertionError(f"{fixture_name} markdown missing {required}")
            encoded = json.dumps(dashboard, sort_keys=True) + markdown
            for forbidden in (
                "Bearer abcdefghijklmnop",
                "-----BEGIN PRIVATE KEY-----",
                "USK@PRIVATE-INSERT",
                "/home/alice",
                "/work/cryptad",
                "hunter2",
                "session=abc1234567890",
                "app-token-123456789",
                "rawpayload123456789",
                "github-token-123456789",
            ):
                if forbidden in encoded:
                    raise AssertionError(f"{fixture_name} leaked {forbidden}")
            outputs[fixture_name] = (out_dir / OUTPUT_JSON).read_text(encoding="utf-8")
        repeat_dir = root / "repeat"
        repeat_args = build_parser().parse_args(
            [
                "build",
                "--workspace-root",
                str(Path(__file__).resolve().parents[2]),
                "--out-dir",
                str(repeat_dir),
                "--fixtures",
                str(FIXTURE_DIR / "go-no-go-pass.json"),
                "--generated-at",
                DEFAULT_GENERATED_AT,
            ]
        )
        build_command(repeat_args)
        repeat_text = (repeat_dir / OUTPUT_JSON).read_text(encoding="utf-8")
        if repeat_text != outputs["go-no-go-pass.json"]:
            raise AssertionError("go/no-go dashboard JSON is not deterministic for fixed fixture inputs")
        assert_supplied_waiver_file_errors_block_launch(root)
        assert_protected_secret_values_are_scanned_and_redacted(root)
        assert_symlink_inputs_are_rejected(root)
        assert_legacy_security_response_summary_fallback_is_honored(root)
        assert_standalone_security_response_summary_is_honored(root)
        assert_security_drills_preserve_failing_runbook_evidence(root)
        assert_security_drills_require_app_platform_runbook_evidence(root)
        assert_security_drill_summary_evidence_is_not_generic_release_evidence(root)
        assert_security_drill_summary_path_requires_sibling_artifacts(root)
        assert_security_drills_release_id_matches_dashboard_candidate(root)
        assert_validator_security_drill_redaction_findings_are_non_waivable(root)
        assert_inherited_security_drill_summary_timestamp_rebinds(root)
        assert_previous_candidate_upgrade_current_binding_is_enforced(root)
        assert_multi_node_release_evidence_is_not_overwritten(root)
    if not quiet:
        print("production beta go/no-go dashboard self-test passed")


def assert_multi_node_release_evidence_is_not_overwritten(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    inputs = json.loads(json.dumps(pass_fixture["inputs"]))
    release_certification = inputs["releaseCertificationSummary"]
    release_certification.setdefault("evidence", []).append(
        {
            "id": "multi-node-beta.support-bundle-drill",
            "status": "fail",
            "summary": "Release certification found support-bundle redaction findings.",
            "source": "release-certification-summary",
            "details": {"redactionFindings": ["support bundle leaked unsafe material"]},
        }
    )
    generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
    dashboard = build_dashboard(
        inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "multi-node-release-evidence-preserved",
        "production-beta",
        "crypta-production-beta-270",
        generated_at,
        now,
    )
    if dashboard.get("decision") != "no-go":
        raise AssertionError(
            "failing release-certification multi-node evidence was overwritten: "
            f"{dashboard}"
        )
    blocker_ids = {
        str(blocker.get("evidenceId"))
        for blocker in dashboard.get("blockers", [])
        if isinstance(blocker, dict)
    }
    if "multi-node-beta.support-bundle-drill" not in blocker_ids:
        raise AssertionError(
            "failing release-certification support-bundle drill evidence did not block: "
            f"{dashboard}"
        )


def assert_inherited_security_drill_summary_timestamp_rebinds(root: Path) -> None:
    args = build_parser().parse_args(
        [
            "build",
            "--workspace-root",
            str(Path(__file__).resolve().parents[2]),
            "--out-dir",
            str(root / "inherited-security-drills-timestamp-rebind"),
            "--fixtures",
            str(FIXTURE_DIR / "go-no-go-expired-waiver.json"),
        ]
    )
    inputs, _paths, _scan_targets, _waiver_value, _release_id, mode, generated_at = (
        load_inputs_from_fixture(args, Path(__file__).resolve().parents[2])
    )
    summary = inputs.get("securityDrillsSummary")
    if not isinstance(summary, dict):
        raise AssertionError("expired-waiver fixture did not inherit a security drills summary")
    if summary.get("generatedAt") != generated_at:
        raise AssertionError(
            "inherited security drills summary did not rebind generatedAt: "
            f"{summary.get('generatedAt')} != {generated_at}"
        )
    _timestamp, now = parse_generated_at(generated_at)
    validation = security_response_runbook.validate_drills_summary(
        summary,
        production=mode == "production-beta",
        strict=mode in {"release-candidate", "production-beta"},
        now=now,
        expected_mode=mode if mode in {"release-candidate", "production-beta"} else None,
    )
    if "drills summary is stale" in validation.get("errors", []):
        raise AssertionError(
            "inherited security drills summary kept the parent fixture timestamp: "
            f"{validation}"
        )


def assert_previous_candidate_upgrade_current_binding_is_enforced(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    mutations = (
        ("current-version", "currentVersion", "269"),
        ("current-catalog-channel", "currentCatalogChannel", "beta"),
        ("current-catalog-edition", "currentCatalogEdition", 123),
    )
    for label, field, value in mutations:
        inputs = json.loads(json.dumps(pass_fixture["inputs"]))
        upgrade = inputs["multiNodeBetaSoakSummary"]["previousCandidateUpgrade"]
        upgrade[field] = value
        generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
        dashboard = build_dashboard(
            inputs,
            {},
            [FIXTURE_DIR / "go-no-go-pass.json"],
            None,
            Path(__file__).resolve().parents[2],
            root / f"previous-candidate-current-binding-{label}",
            "production-beta",
            "crypta-production-beta-270",
            generated_at,
            now,
        )
        if dashboard.get("decision") != "no-go":
            raise AssertionError(f"mismatched previous-candidate upgrade {field} did not block: {dashboard}")
        blocker_ids = {
            str(blocker.get("evidenceId"))
            for blocker in dashboard.get("blockers", [])
            if isinstance(blocker, dict)
        }
        if "multi-node-beta.previous-candidate-upgrade-binding" not in blocker_ids:
            raise AssertionError(f"mismatched previous-candidate upgrade {field} used wrong blocker: {dashboard}")


def assert_security_drills_preserve_failing_runbook_evidence(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    inputs = json.loads(json.dumps(pass_fixture["inputs"]))
    inputs["releaseCertificationSummary"].setdefault("evidence", []).append(
        {
            "id": "production-security.response-runbook",
            "status": "pass",
            "summary": "Combined release-certification security response evidence passed.",
            "source": "release-certification-summary",
            "details": {
                "appPlatformRunbook": {
                    "id": "production-security.response-runbook",
                    "status": "pass",
                    "summary": "App-platform runbook evidence passed.",
                    "source": "app-platform-smoke",
                },
                "securityDrills": {
                    "id": "production-security.response-runbook",
                    "status": "pass",
                    "summary": "Security response drills passed.",
                    "source": "security-drills-summary",
                },
                "componentStatuses": {
                    "appPlatformRunbook": "pass",
                    "securityDrills": "pass",
                },
            },
        }
    )
    for entry in inputs["appPlatformSummary"]["evidence"]:
        if isinstance(entry, dict) and entry.get("id") == "production-security.response-runbook":
            entry["status"] = "fail"
            entry["summary"] = "App-platform security response runbook integration failed."
            entry["details"] = {"checks": {"runbookDocExists": False}}
            break
    else:
        raise AssertionError("app-platform production-security.response-runbook evidence is missing")
    generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
    dashboard = build_dashboard(
        inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "security-drills-preserve-failing-runbook",
        "production-beta",
        "crypta-production-beta-270",
        generated_at,
        now,
    )
    if dashboard.get("decision") != "no-go":
        raise AssertionError(
            "passing security drills overwrote failing runbook evidence: "
            f"{dashboard}"
        )
    blocker_ids = {
        str(blocker.get("evidenceId"))
        for blocker in dashboard.get("blockers", [])
        if isinstance(blocker, dict)
    }
    if "production-security.response-runbook" not in blocker_ids:
        raise AssertionError(f"failing runbook evidence did not block: {dashboard}")
    security_domain = next(
        (domain for domain in dashboard.get("domains", []) if domain.get("id") == "production-security-response"),
        {},
    )
    if security_domain.get("status") != "fail":
        raise AssertionError(f"security response domain did not fail: {security_domain}")


def assert_security_drills_require_app_platform_runbook_evidence(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    inputs = json.loads(json.dumps(pass_fixture["inputs"]))
    for summary_name in ("releaseCertificationSummary", "appPlatformSummary"):
        summary = inputs.get(summary_name)
        if not isinstance(summary, dict) or not isinstance(summary.get("evidence"), list):
            continue
        summary["evidence"] = [
            entry
            for entry in summary["evidence"]
            if not (isinstance(entry, dict) and entry.get("id") == "production-security.response-runbook")
        ]
    generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
    dashboard = build_dashboard(
        inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "security-drills-require-app-platform-runbook",
        "production-beta",
        "crypta-production-beta-270",
        generated_at,
        now,
    )
    if dashboard.get("decision") != "no-go":
        raise AssertionError(
            "passing security drills masked missing app-platform runbook evidence: "
            f"{dashboard}"
        )
    blocker_ids = {
        str(blocker.get("evidenceId"))
        for blocker in dashboard.get("blockers", [])
        if isinstance(blocker, dict)
    }
    if "production-security.response-runbook" not in blocker_ids:
        raise AssertionError(f"missing app-platform runbook evidence did not block: {dashboard}")
    security_evidence = dashboard.get("securityDrills")
    if not isinstance(security_evidence, dict) or security_evidence.get("promotionReady") is not True:
        raise AssertionError(f"passing drill summary should remain visible separately: {dashboard}")


def assert_security_drill_summary_evidence_is_not_generic_release_evidence(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    inputs = json.loads(json.dumps(pass_fixture["inputs"]))
    for entry in inputs["appPlatformSummary"]["evidence"]:
        if isinstance(entry, dict) and entry.get("id") == "first-party-app.beta-quality-pass":
            entry["status"] = "fail"
            entry["summary"] = "First-party beta-quality readiness failed."
            break
    else:
        raise AssertionError("first-party beta-quality evidence is missing from app-platform fixture")
    security_drills = inputs.get("securityDrillsSummary")
    if not isinstance(security_drills, dict):
        raise AssertionError("go-no-go-pass fixture is missing securityDrillsSummary")
    security_drills.setdefault("evidence", []).append(
        {
            "id": "first-party-app.beta-quality-pass",
            "status": "pass",
            "summary": "Forged generic evidence inside the security drills summary.",
            "source": "security-drills-summary",
        }
    )
    generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
    dashboard = build_dashboard(
        inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "security-drills-evidence-not-generic",
        "production-beta",
        "crypta-production-beta-270",
        generated_at,
        now,
    )
    if dashboard.get("decision") != "no-go":
        raise AssertionError(
            "generic evidence embedded in securityDrillsSummary overrode authoritative evidence: "
            f"{dashboard}"
        )
    blocker_ids = {
        str(blocker.get("evidenceId"))
        for blocker in dashboard.get("blockers", [])
        if isinstance(blocker, dict)
    }
    if "first-party-app.beta-quality-pass" not in blocker_ids:
        raise AssertionError(f"failed first-party beta-quality evidence did not block: {dashboard}")
    security_drills_compact = dashboard.get("securityDrills")
    if (
        not isinstance(security_drills_compact, dict)
        or security_drills_compact.get("promotionReady") is not True
    ):
        raise AssertionError(f"passing drill summary should remain visible separately: {dashboard}")


def assert_security_drill_summary_path_requires_sibling_artifacts(root: Path) -> None:
    input_args, input_paths = path_input_args_from_pass_fixture(
        root,
        "security-drill-summary-path-missing-artifacts",
    )
    pass_fixture = read_json(FIXTURE_DIR / "go-no-go-pass.json")
    if not isinstance(pass_fixture, dict) or not isinstance(pass_fixture.get("inputs"), dict):
        raise AssertionError("go-no-go-pass.json must contain security drill path-test inputs")
    security_drills = pass_fixture["inputs"].get("securityDrillsSummary")
    if not isinstance(security_drills, dict):
        raise AssertionError("go-no-go-pass fixture is missing securityDrillsSummary")
    security_drills_path = (
        root
        / "security-drill-summary-path-missing-artifacts"
        / "security-drills-summary.json"
    )
    write_json(security_drills_path, security_drills)
    args_list = [
        "build",
        "--workspace-root",
        str(Path(__file__).resolve().parents[2]),
        "--out-dir",
        str(root / "security-drill-summary-path-missing-artifacts-output"),
        "--mode",
        "production-beta",
        "--release-id",
        "crypta-production-beta-270",
        "--generated-at",
        DEFAULT_GENERATED_AT,
        "--security-drills-summary",
        str(security_drills_path),
    ]
    for flag, input_name in input_args:
        args_list.extend([flag, str(input_paths[input_name])])
    dashboard, _exit_code = build_command(build_parser().parse_args(args_list))
    if dashboard.get("decision") != "no-go":
        raise AssertionError(
            "file-backed securityDrillsSummary without sibling artifacts produced GO: "
            f"{dashboard}"
        )
    blocker_ids = {
        str(blocker.get("evidenceId"))
        for blocker in dashboard.get("blockers", [])
        if isinstance(blocker, dict)
    }
    if "production-security.response-runbook" not in blocker_ids:
        raise AssertionError(f"missing drill artifacts did not block security response: {dashboard}")
    security_drills_compact = dashboard.get("securityDrills")
    if (
        not isinstance(security_drills_compact, dict)
        or security_drills_compact.get("status") != "fail"
        or security_drills_compact.get("promotionReady") is True
    ):
        raise AssertionError(f"missing drill artifacts did not fail compact drill status: {dashboard}")
    artifact_validation = security_drills_compact.get("artifactValidation")
    artifact_errors = (
        artifact_validation.get("errors")
        if isinstance(artifact_validation, dict)
        and isinstance(artifact_validation.get("errors"), list)
        else []
    )
    if "security drill artifact for reviewer-key-compromise is missing" not in artifact_errors:
        raise AssertionError(
            "missing sibling drill artifacts were not reported in compact validation: "
            f"{dashboard}"
        )


def assert_security_drills_release_id_matches_dashboard_candidate(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    inputs = json.loads(json.dumps(pass_fixture["inputs"]))
    security_drills = inputs.get("securityDrillsSummary")
    if not isinstance(security_drills, dict):
        raise AssertionError("go-no-go-pass fixture is missing securityDrillsSummary")
    security_drills["releaseId"] = "cryptad-beta-other-candidate"
    generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
    dashboard = build_dashboard(
        inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "security-drills-release-id-mismatch",
        "production-beta",
        "crypta-production-beta-270",
        generated_at,
        now,
    )
    if dashboard.get("decision") != "no-go":
        raise AssertionError(
            "security drills from another release id did not block: "
            f"{dashboard}"
        )
    blockers = [
        blocker
        for blocker in dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("evidenceId") == "production-security.response-runbook"
    ]
    if not blockers:
        raise AssertionError(f"release-id mismatch did not block production security response: {dashboard}")
    security_evidence = next(
        (
            domain
            for domain in dashboard.get("domains", [])
            if isinstance(domain, dict) and domain.get("id") == "production-security-response"
        ),
        {},
    )
    if security_evidence.get("status") != "fail":
        raise AssertionError(f"release-id mismatch did not fail security response domain: {dashboard}")
    security_drills = dashboard.get("securityDrills")
    if not isinstance(security_drills, dict) or security_drills.get("status") != "fail":
        raise AssertionError(f"release-id mismatch did not fail compact security drill status: {dashboard}")
    if security_drills.get("promotionReady") is True:
        raise AssertionError(f"release-id mismatch left security drills promotion-ready: {dashboard}")


def assert_validator_security_drill_redaction_findings_are_non_waivable(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    inputs = json.loads(json.dumps(pass_fixture["inputs"]))
    security_drills = inputs.get("securityDrillsSummary")
    if not isinstance(security_drills, dict):
        raise AssertionError("go-no-go-pass fixture is missing securityDrillsSummary")
    security_drills["mode"] = "release-candidate"
    security_drills["rawSupportBundleBody"] = "fixture-payload"
    redaction = security_drills.get("redaction")
    if not isinstance(redaction, dict):
        raise AssertionError("go-no-go-pass fixture securityDrillsSummary is missing redaction")
    redaction["status"] = "pass"
    redaction["findings"] = []
    redaction["rawSensitiveMaterialExcluded"] = True
    waiver_value = {
        "schemaVersion": 1,
        "waivers": [
            {
                "id": "waive-validator-security-drill-redaction",
                "evidenceId": "production-security.response-runbook",
                "severity": "blocker",
                "scope": "release-candidate",
                "rationale": "Regression fixture: validator redaction findings are non-waivable.",
                "approvedBy": "release-manager",
                "owner": "release",
                "createdAt": "1970-01-01T00:00:00Z",
                "expiresAt": "2099-01-01T00:00:00Z",
                "references": ["validator-security-drill-redaction"],
            }
        ],
    }
    generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
    dashboard = build_dashboard(
        inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        waiver_value,
        Path(__file__).resolve().parents[2],
        root / "validator-security-drill-redaction",
        "release-candidate",
        "crypta-production-beta-270",
        generated_at,
        now,
    )
    if dashboard.get("decision") != "no-go":
        raise AssertionError(
            "validator-detected security drill redaction was waived: "
            f"{dashboard}"
        )
    if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
        raise AssertionError("validator-detected security drill redaction waiver was incorrectly used")
    critical_redaction_blockers = [
        blocker
        for blocker in dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("evidenceId") == "production-security.response-runbook"
        and blocker.get("category") == "redaction"
        and blocker.get("severity") == "critical"
        and blocker.get("waivable") is False
    ]
    if not critical_redaction_blockers:
        raise AssertionError(
            "validator-detected security drill redaction did not create a critical non-waivable blocker: "
            f"{dashboard}"
        )


def assert_standalone_security_response_summary_is_honored(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    inputs = json.loads(json.dumps(pass_fixture["inputs"]))
    inputs.pop("securityDrillsSummary", None)
    inputs["securityResponseSummary"] = {
        "status": "pass",
        "summary": "Standalone production security response summary passed.",
    }
    app_summary = inputs["appPlatformSummary"]
    evidence = app_summary["evidence"]
    app_summary["evidence"] = [
        entry
        for entry in evidence
        if not (isinstance(entry, dict) and entry.get("id") == "production-security.response-runbook")
    ]
    if len(app_summary["evidence"]) == len(evidence):
        raise AssertionError("standalone security response self-test did not remove duplicated app-platform evidence")
    generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
    dashboard = build_dashboard(
        inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "standalone-security-response",
        "developer-dry-run",
        "crypta-production-beta-270-standalone-security-response",
        generated_at,
        now,
    )
    if dashboard.get("decision") != "go":
        raise AssertionError(f"standalone security-response summary produced {dashboard.get('decision')}: {dashboard}")
    security_domain = next(
        (domain for domain in dashboard.get("domains", []) if domain.get("id") == "production-security-response"),
        {},
    )
    if security_domain.get("status") != "pass":
        raise AssertionError(f"standalone security-response domain did not pass: {security_domain}")


def assert_legacy_security_response_summary_fallback_is_honored(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    inputs = json.loads(json.dumps(pass_fixture["inputs"]))
    inputs.pop("securityDrillsSummary", None)
    inputs["securityResponseSummary"] = {
        "status": "pass",
        "summary": "Legacy production security response summary passed.",
    }
    for summary_name in ("appPlatformSummary", "releaseCertificationSummary"):
        summary = inputs.get(summary_name)
        if not isinstance(summary, dict) or not isinstance(summary.get("evidence"), list):
            continue
        summary["evidence"] = [
            entry
            for entry in summary["evidence"]
            if not (isinstance(entry, dict) and entry.get("id") == "production-security.response-runbook")
        ]
    generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
    dashboard = build_dashboard(
        inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "legacy-security-response-fallback",
        "developer-dry-run",
        "crypta-production-beta-270-legacy-security-response-fallback",
        generated_at,
        now,
    )
    if dashboard.get("decision") != "go":
        raise AssertionError(f"legacy security-response fallback produced {dashboard.get('decision')}: {dashboard}")
    security_domain = next(
        (domain for domain in dashboard.get("domains", []) if domain.get("id") == "production-security-response"),
        {},
    )
    if security_domain.get("status") != "pass":
        raise AssertionError(f"legacy security-response fallback domain did not pass: {security_domain}")


def path_input_args_from_pass_fixture(root: Path, input_dir_name: str) -> tuple[tuple[tuple[str, str], ...], dict[str, Path]]:
    pass_fixture = read_json(FIXTURE_DIR / "go-no-go-pass.json")
    if not isinstance(pass_fixture, dict) or not isinstance(pass_fixture.get("inputs"), dict):
        raise AssertionError("go-no-go-pass.json must contain path-test inputs")
    inputs = pass_fixture["inputs"]
    input_args = (
        ("--production-beta-summary", "productionBetaSummary"),
        ("--release-certification-summary", "releaseCertificationSummary"),
        ("--ecosystem-matrix", "ecosystemMatrix"),
        ("--app-platform-summary", "appPlatformSummary"),
        ("--live-network-summary", "liveNetworkSummary"),
        ("--network-scale-soak-summary", "networkScaleSoakSummary"),
        ("--multi-node-beta-soak-summary", "multiNodeBetaSoakSummary"),
        ("--security-response-summary", "securityResponseSummary"),
    )
    input_dir = root / input_dir_name
    input_paths: dict[str, Path] = {}
    for _flag, input_name in input_args:
        value = inputs.get(input_name)
        if not isinstance(value, dict):
            raise AssertionError(f"go-no-go-pass.json missing {input_name}")
        path = input_dir / f"{input_name}.json"
        write_json(path, value)
        input_paths[input_name] = path
    return input_args, input_paths


def assert_symlink_inputs_are_rejected(root: Path) -> None:
    input_args, input_paths = path_input_args_from_pass_fixture(root, "symlink-inputs")
    link_dir = root / "symlink-links"
    link_dir.mkdir(parents=True)
    summary_link = link_dir / "productionBetaSummary.json"
    summary_link.symlink_to(input_paths["productionBetaSummary"])
    out_dir = root / "symlink-output"
    args_list = [
        "build",
        "--workspace-root",
        str(Path(__file__).resolve().parents[2]),
        "--out-dir",
        str(out_dir),
        "--mode",
        "production-beta",
    ]
    for flag, input_name in input_args:
        value = summary_link if input_name == "productionBetaSummary" else input_paths[input_name]
        args_list.extend([flag, str(value)])
    dashboard, _exit_code = build_command(build_parser().parse_args(args_list))
    if dashboard.get("decision") != "no-go":
        raise AssertionError("symlinked dashboard input did not force no-go")
    redaction = read_json(out_dir / OUTPUT_REDACTION)
    findings = redaction.get("findings") if isinstance(redaction, dict) else []
    if not any(
        isinstance(finding, dict) and finding.get("kind") == "forbidden-symlink" for finding in findings
    ):
        raise AssertionError("symlinked dashboard input did not produce a forbidden-symlink finding")


def assert_protected_secret_values_are_scanned_and_redacted(root: Path) -> None:
    secret_name = "CRYPTAD_DASHBOARD_TEST_TOKEN"
    secret_value = "dashboard-protected-secret-12345"
    short_secret_name = "CRYPTAD_DASHBOARD_TEST_SHORT_TOKEN"
    long_secret_name = "CRYPTAD_DASHBOARD_TEST_LONG_TOKEN"
    file_secret_name = "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE"
    short_secret_value = "dashboard-overlap-secret"
    long_secret_suffix = "TAILLEAK12345"
    long_secret_value = f"{short_secret_value}-{long_secret_suffix}"
    generic_token = "generic-dashboard-token-12345"
    generic_password = "generic-dashboard-password-12345"
    generic_private_key_base64 = "Z2VuZXJpYy1kYXNoYm9hcmQtcHJpdmF0ZS1rZXktMTIzNDU="
    previous = os.environ.get(secret_name)
    previous_short = os.environ.get(short_secret_name)
    previous_long = os.environ.get(long_secret_name)
    previous_file = os.environ.get(file_secret_name)
    os.environ[secret_name] = secret_value
    os.environ[short_secret_name] = short_secret_value
    os.environ[long_secret_name] = long_secret_value
    try:
        input_args, input_paths = path_input_args_from_pass_fixture(root, "protected-secret-inputs")
        protected_dir = root / "protected"
        protected_dir.mkdir(parents=True)
        file_secret_bytes = b"\x01cryptad-dashboard-file-backed-private-key\x02\xff"
        file_secret_path = protected_dir / "app-signing-private.der"
        file_secret_path.write_bytes(file_secret_bytes)
        file_secret_base64 = base64.b64encode(file_secret_bytes).decode("ascii")
        os.environ[file_secret_name] = str(file_secret_path.relative_to(root))
        production_summary = read_json(input_paths["productionBetaSummary"])
        if not isinstance(production_summary, dict):
            raise AssertionError("productionBetaSummary path input is missing")
        production_summary["status"] = "fail"
        production_summary["promotionReady"] = False
        production_summary["failures"] = [
            f"dashboard input leaked {secret_value} without an environment variable name",
            f"dashboard input leaked overlapping protected value {long_secret_value}",
            f"dashboard input leaked file-backed signing material {file_secret_base64}",
        ]
        production_summary["token"] = generic_token
        production_summary["password"] = generic_password
        production_summary["privateKeyBase64"] = generic_private_key_base64
        write_json(input_paths["productionBetaSummary"], production_summary)
        out_dir = root / "protected-secret-output"
        args_list = [
            "build",
            "--workspace-root",
            str(root),
            "--out-dir",
            str(out_dir),
            "--mode",
            "production-beta",
            "--generated-at",
            DEFAULT_GENERATED_AT,
        ]
        for flag, input_name in input_args:
            args_list.extend([flag, str(input_paths[input_name])])
        dashboard, _exit_code = build_command(build_parser().parse_args(args_list))
        finding_kinds = {
            str(finding.get("kind"))
            for finding in dashboard.get("redaction", {}).get("findings", [])
            if isinstance(finding, dict)
        }
        if dashboard["decision"] != "no-go" or "protected-secret-value" not in finding_kinds:
            raise AssertionError(f"protected secret value did not block dashboard: {dashboard}")
        if "sensitive-field-value" not in finding_kinds:
            raise AssertionError(f"generic sensitive fields did not block dashboard: {dashboard}")
        generated_text = (out_dir / OUTPUT_JSON).read_text(encoding="utf-8") + (
            out_dir / OUTPUT_MARKDOWN
        ).read_text(encoding="utf-8")
        if secret_value in generated_text:
            raise AssertionError("dashboard artifacts leaked a protected secret value")
        for forbidden in (
            short_secret_value,
            long_secret_value,
            long_secret_suffix,
            file_secret_base64,
            generic_token,
            generic_password,
            generic_private_key_base64,
        ):
            if forbidden in generated_text:
                raise AssertionError(f"dashboard artifacts leaked overlapping protected secret content: {forbidden}")
    finally:
        if previous is None:
            os.environ.pop(secret_name, None)
        else:
            os.environ[secret_name] = previous
        if previous_short is None:
            os.environ.pop(short_secret_name, None)
        else:
            os.environ[short_secret_name] = previous_short
        if previous_long is None:
            os.environ.pop(long_secret_name, None)
        else:
            os.environ[long_secret_name] = previous_long
        if previous_file is None:
            os.environ.pop(file_secret_name, None)
        else:
            os.environ[file_secret_name] = previous_file


def assert_supplied_waiver_file_errors_block_launch(root: Path) -> None:
    input_args, input_paths = path_input_args_from_pass_fixture(root, "path-inputs")
    valid_waiver = {
        "id": "waiver-malformed-references",
        "evidenceId": "app-store.submission-cli",
        "severity": "blocker",
        "scope": "production-beta-only",
        "rationale": "Self-test malformed references record.",
        "approvedBy": "release-manager@example.invalid",
        "owner": "release-engineering",
        "createdAt": "2026-06-24T00:00:00Z",
        "expiresAt": "2099-06-30T00:00:00Z",
    }

    def waiver_with_references(references: Any) -> str:
        waiver = dict(valid_waiver)
        waiver["references"] = references
        return json.dumps({"schemaVersion": 1, "waivers": [waiver]}, sort_keys=True)

    waiver_cases = {
        "missing": None,
        "malformed": "{",
        "non-object": "[]",
        "references-null": waiver_with_references(None),
        "references-number": waiver_with_references(123),
    }
    for case_name, content in waiver_cases.items():
        waiver_path = root / f"{case_name}-waivers.json"
        if content is not None:
            write_text(waiver_path, content)
        args_list = [
            "build",
            "--workspace-root",
            str(root),
            "--out-dir",
            str(root / f"{case_name}-waiver-output"),
            "--mode",
            "production-beta",
            "--generated-at",
            DEFAULT_GENERATED_AT,
            "--waivers",
            str(waiver_path),
        ]
        for flag, input_name in input_args:
            args_list.extend([flag, str(input_paths[input_name])])
        dashboard, _exit_code = build_command(build_parser().parse_args(args_list))
        if dashboard["decision"] != "no-go":
            raise AssertionError(f"{case_name} waiver file expected no-go, got {dashboard['decision']}")
        blocker_ids = {
            str(blocker.get("evidenceId"))
            for blocker in dashboard.get("blockers", [])
            if isinstance(blocker, dict)
        }
        if "production-beta.waiver-validation" not in blocker_ids:
            raise AssertionError(f"{case_name} waiver file did not produce a waiver-validation blocker: {dashboard}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run offline dashboard fixture tests.")
    subparsers = parser.add_subparsers(dest="command")
    build = subparsers.add_parser("build", help="Build dashboard artifacts.")
    build.add_argument("--workspace-root", type=Path, default=Path.cwd())
    build.add_argument("--out-dir", type=Path, required=True)
    build.add_argument("--mode", choices=MODES, default=None)
    build.add_argument("--release-id", default="")
    build.add_argument("--generated-at", default="")
    build.add_argument("--production-beta-summary", type=Path)
    build.add_argument("--release-certification-summary", type=Path)
    build.add_argument("--ecosystem-matrix", type=Path)
    build.add_argument("--app-platform-summary", type=Path)
    build.add_argument("--live-network-summary", type=Path)
    build.add_argument("--network-scale-soak-summary", type=Path)
    build.add_argument("--multi-node-beta-soak-summary", type=Path)
    build.add_argument("--security-drills-summary", type=Path)
    build.add_argument("--security-response-summary", type=Path)
    build.add_argument("--waivers", type=Path)
    build.add_argument("--fixtures", type=Path, help="Build from a checked-in dashboard fixture bundle.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        run_self_test()
        return 0
    if args.command == "build":
        dashboard, exit_code = build_command(args)
        print(f"Production beta go/no-go dashboard {dashboard['decision']}: {args.out_dir / OUTPUT_JSON}")
        return exit_code
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
