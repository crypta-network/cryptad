"""Implementation segment for the core portion of ``release_certification.py``."""

from __future__ import annotations

import argparse

import base64

import binascii

import dataclasses

import datetime as dt

import hashlib

import hmac

import json

import os

import re

import shutil

import stat

import subprocess

import sys

import tempfile

from pathlib import Path

from typing import Any

sys.dont_write_bytecode = True

from cryptad_certification.engines import app_platform_docs_check

from cryptad_certification.engines import multi_node_beta_soak

from cryptad_certification.engines import production_beta_go_no_go_dashboard

from cryptad_certification.engines import security_response_runbook

from cryptad_certification.io import read_json as read_strict_json

from cryptad_certification.schema_validation import validate_schema

from cryptad_certification.stable_dependency_vulnerability_handoff import (
    STABLE_DEPENDENCY_VULNERABILITY_CERTIFICATION_CLOCK_ENV,
    STABLE_DEPENDENCY_VULNERABILITY_CURRENT_TIP_LEDGER_DIGEST_ENV,
    STABLE_DEPENDENCY_VULNERABILITY_CURRENT_TIP_LEDGER_EDITION_ENV,
    STABLE_DEPENDENCY_VULNERABILITY_EVALUATION_WORKFLOW,
    STABLE_DEPENDENCY_VULNERABILITY_HANDOFF_AUTHENTICATION_ALGORITHM,
    STABLE_DEPENDENCY_VULNERABILITY_HANDOFF_FIELDS,
    STABLE_DEPENDENCY_VULNERABILITY_HANDOFF_FILE,
    STABLE_DEPENDENCY_VULNERABILITY_HANDOFF_KEY_DOMAIN,
    STABLE_DEPENDENCY_VULNERABILITY_HANDOFF_KEY_ENV,
    STABLE_DEPENDENCY_VULNERABILITY_HANDOFF_MAC_DOMAIN,
    STABLE_DEPENDENCY_VULNERABILITY_WORKFLOW,
    stable_dependency_vulnerability_evaluation_handoff_errors,
    stable_dependency_vulnerability_current_tip_errors,
    stable_dependency_vulnerability_handoff_authentication_tag,
    stable_dependency_vulnerability_handoff_errors,
)

from cryptad_certification.stable_vulnerability_handoff import (
    current_tip_errors as shared_stable_vulnerability_current_tip_errors,
    handoff_paths as shared_stable_vulnerability_handoff_paths,
    provenance_errors as shared_stable_vulnerability_provenance_errors,
    sealed_handoff_errors as shared_stable_vulnerability_sealed_handoff_errors,
    source_digest as shared_stable_vulnerability_source_digest,
    summary_errors as shared_stable_vulnerability_summary_errors,
)

TOOL_NAME = "release-certification"

SCHEMA_VERSION = 1

DEFAULT_OUT_DIR = Path("build/release-certification")

DEFAULT_HISTORY_DIR = Path("build/release-certification-history")

SUMMARY_FILE_NAME = "release-certification-summary.json"

REPORT_FILE_NAME = "release-certification-report.md"

HISTORY_COMPARISON_FILE_NAME = "history-comparison.json"

HISTORY_COMPARISON_REPORT_FILE_NAME = "history-comparison.md"

ECOSYSTEM_MATRIX_FILE_NAME = "ecosystem-certification-matrix.json"

ECOSYSTEM_MATRIX_REPORT_FILE_NAME = "ecosystem-certification-matrix.md"

ECOSYSTEM_MATRIX_SCHEMA_VERSION = 1

CERT_STATUSES = ("pass", "warn", "fail", "skip", "missing")

MODES = ("pr", "nightly", "release-candidate")

PRIVATE_ARTIFACT_NAMES = ("private-insert-uris.json",)

PRODUCTION_BETA_GO_NO_GO_SELF_TEST_RESULT: tuple[bool, str] | None = None

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
    app_platform_docs_check.PUBLIC_BETA_SUPPORT_FEEDBACK_EVIDENCE_IDS
)

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

OPERATOR_RC_EVIDENCE_IDS = (
    "operator-rc.dashboard",
    "operator-rc.recovery-plan-execute",
    "operator-rc.catalog-repair",
    "operator-rc.app-reinstall-rollback",
    "operator-rc.export-before-uninstall",
    "operator-rc.subscription-recovery",
    "operator-rc.app-service-grant-recovery",
    "operator-rc.trust-graph-recovery",
    "operator-rc.network-budget-visibility",
    "operator-rc.support-bundle-wizard",
    "operator-rc.redaction",
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

LIVE_NETWORK_BETA_EVIDENCE_IDS = (
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

LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS = tuple(
    evidence_id
    for evidence_id in LIVE_NETWORK_BETA_EVIDENCE_IDS
    if evidence_id != "live-network-beta.app-service-score"
)

NETWORK_SCALE_EVIDENCE_IDS = (
    "network-scale.app-network-budget",
    "network-scale.content-fetch-budget",
    "network-scale.subscription-budget",
    "network-scale.queue-pressure-backoff",
    "network-scale.trust-graph-import-budget",
    "network-scale.social-inbox-multi-source-soak",
    "network-scale.redaction",
)

NETWORK_SCALE_SOAK_EVIDENCE_ID = "network-scale.rc-soak-summary"

NETWORK_SCALE_SOAK_APP_IDS = ("social-inbox", "feed-reader")

NETWORK_SCALE_SOAK_APP_COUNT_KEYS = (
    "subscriptions",
    "pollAttempts",
    "budgetSkips",
    "queuePressureSkips",
    "updatesObserved",
)

NETWORK_SCALE_SOAK_TRUST_GRAPH_COUNT_KEYS = ("importsAttempted", "budgetSkips")

NETWORK_SCALE_SOAK_BUDGET_KEYS = (
    "globalFetchBudgetEnforced",
    "perAppFetchBudgetEnforced",
    "concurrencyLeasesReleased",
)

NETWORK_SCALE_SOAK_REDACTION_KEYS = (
    "rawFetchedContentExcluded",
    "privateInsertUrisExcluded",
    "tokensExcluded",
    "absolutePathsExcluded",
    "queueHtmlExcluded",
)

MULTI_NODE_BETA_EVIDENCE_IDS = multi_node_beta_soak.EVIDENCE_IDS

MULTI_NODE_BETA_SCENARIO_EVIDENCE_IDS = multi_node_beta_soak.SCENARIO_EVIDENCE_IDS

ECOSYSTEM_RC_GATE_ID = "ecosystem.rc-certification"

ECOSYSTEM_RC_EVIDENCE_ID = "release-certification.ecosystem-rc-gate"

ECOSYSTEM_RC_MATRIX_ROW_ID = "ecosystem-rc-certification-gate"

PRODUCTION_BETA_GO_NO_GO_EVIDENCE_IDS = production_beta_go_no_go_dashboard.DASHBOARD_EVIDENCE_IDS

STABLE_1_0_READINESS_EVIDENCE_IDS = production_beta_go_no_go_dashboard.STABLE_1_0_READINESS_EVIDENCE_IDS

STABLE_1_0_READINESS_DOMAIN_IDS = production_beta_go_no_go_dashboard.STABLE_1_0_READINESS_DOMAIN_IDS

STABLE_1_0_READINESS_MATRIX_ROW_ID = "stable-1-0-readiness"

STABLE_VULNERABILITY_EVIDENCE_ID = "stable-vulnerability.release-promotion"

STABLE_VULNERABILITY_GATE_ID = "ecosystem.stable-vulnerability"

STABLE_SUPPLY_CHAIN_EVIDENCE_ID = "stable-supply-chain.release-promotion"

STABLE_SUPPLY_CHAIN_GATE_ID = "ecosystem.stable-supply-chain"

STABLE_DEPENDENCY_VULNERABILITY_EVIDENCE_ID = (
    "stable-dependency-vulnerability.release-promotion"
)

STABLE_DEPENDENCY_VULNERABILITY_GATE_ID = (
    "ecosystem.stable-dependency-vulnerability"
)

STABLE_DEPENDENCY_VULNERABILITY_SUMMARY_SCHEMA = (
    "stable-1.0-dependency-vulnerability-promotion-summary-v1.schema.json"
)

STABLE_DEPENDENCY_VULNERABILITY_REQUIRED_EVIDENCE_IDS = (
    "stable-dependency-vulnerability.policy",
    "stable-dependency-vulnerability.intelligence-authenticity",
    "stable-dependency-vulnerability.snapshot-freshness",
    "stable-dependency-vulnerability.alias-integrity",
    "stable-dependency-vulnerability.component-matching",
    "stable-dependency-vulnerability.disposition-governance",
    "stable-dependency-vulnerability.open-findings",
    "stable-dependency-vulnerability.remediation-binding",
    "stable-dependency-vulnerability.case-binding",
    "stable-dependency-vulnerability.publication",
    "stable-dependency-vulnerability.redaction",
    "stable-dependency-vulnerability.release-promotion",
    "stable-dependency-vulnerability.phase-11-closeout",
)

STABLE_SUPPLY_CHAIN_SUMMARY_SCHEMA = (
    "stable-1.0-supply-chain-promotion-summary-v1.schema.json"
)

STABLE_SUPPLY_CHAIN_REQUIRED_EVIDENCE_IDS = (
    "stable-supply-chain.policy",
    "stable-supply-chain.dependency-resolution",
    "stable-supply-chain.component-coverage",
    "stable-supply-chain.subject-binding",
    "stable-supply-chain.post-build-subject-binding",
    "stable-supply-chain.license-policy",
    "stable-supply-chain.build-materials",
    "stable-supply-chain.builder-independence",
    "stable-supply-chain.byte-reproducibility",
    "stable-supply-chain.normalized-payload-reproducibility",
    "stable-supply-chain.sbom-binding",
    "stable-supply-chain.vulnerability-index",
    "stable-supply-chain.redaction",
    "stable-supply-chain.release-promotion",
)

STABLE_SUPPLY_CHAIN_PUBLICATION_EVIDENCE_ID = "stable-supply-chain.publication"

STABLE_SUPPLY_CHAIN_HANDOFF_FILE = (
    "stable-1.0-supply-chain-summary-provenance.json"
)

STABLE_SUPPLY_CHAIN_HANDOFF_KEY_ENV = (
    "CRYPTAD_STABLE_SUPPLY_CHAIN_HANDOFF_KEY_BASE64"
)

STABLE_SUPPLY_CHAIN_HANDOFF_AUTHENTICATION_ALGORITHM = "hmac-sha256"

STABLE_SUPPLY_CHAIN_HANDOFF_KEY_DOMAIN = (
    b"cryptad-stable-supply-chain-promotion-handoff-key-v1"
)

STABLE_SUPPLY_CHAIN_HANDOFF_MAC_DOMAIN = (
    b"cryptad-stable-supply-chain-promotion-handoff-v1\0"
)

STABLE_SUPPLY_CHAIN_WORKFLOW = (
    "crypta-network/cryptad/.github/workflows/stable-1.0-supply-chain.yml"
)

STABLE_SUPPLY_CHAIN_HANDOFF_FIELDS = frozenset(
    {
        "schemaVersion",
        "kind",
        "repository",
        "workflow",
        "workflowCommit",
        "runId",
        "runAttempt",
        "operation",
        "releaseId",
        "buildVersion",
        "sourceCommit",
        "artifactName",
        "producerArtifactDigest",
        "summaryFileName",
        "summaryByteDigest",
        "attestationSubjectDigest",
        "attestationVerified",
        "denySelfHostedRunners",
        "authenticationStatus",
        "authenticationAlgorithm",
        "authenticationTag",
    }
)

NONWAIVABLE_EVIDENCE_IDS = frozenset(
    {
        STABLE_VULNERABILITY_EVIDENCE_ID,
        STABLE_SUPPLY_CHAIN_EVIDENCE_ID,
        STABLE_DEPENDENCY_VULNERABILITY_EVIDENCE_ID,
    }
)

STABLE_VULNERABILITY_SUMMARY_SCHEMA = (
    "stable-1.0-vulnerability-summary-v1.schema.json"
)

STABLE_VULNERABILITY_SUCCESSOR_BINDING_SCHEMA = (
    "stable-1.0-vulnerability-successor-binding-v1.schema.json"
)

STABLE_VULNERABILITY_SUMMARY_PROVENANCE_SCHEMA = (
    "stable-1.0-vulnerability-summary-provenance-v1.schema.json"
)

STABLE_VULNERABILITY_POLICY_PATH = Path(
    "tools/release-certification/stable-1.0-vulnerability-disclosure-policy.json"
)

STABLE_VULNERABILITY_SUMMARY_ROOT_ENV = (
    "CRYPTAD_STABLE_VULNERABILITY_SUMMARY_ROOT"
)
STABLE_VULNERABILITY_HANDOFF_KEY_ENV = (
    "CRYPTAD_STABLE_VULNERABILITY_HANDOFF_KEY_BASE64"
)

STABLE_VULNERABILITY_SUMMARY_FILE = "stable-1.0-vulnerability-summary.json"

STABLE_VULNERABILITY_SUCCESSOR_BINDING_FILE = (
    "stable-1.0-vulnerability-successor-binding.json"
)

STABLE_VULNERABILITY_SUMMARY_PROVENANCE_FILE = (
    "stable-1.0-vulnerability-summary-provenance.json"
)
STABLE_VULNERABILITY_SEALED_HANDOFF_DIRECTORY = "sealed-successor"
STABLE_VULNERABILITY_SEALED_HANDOFF_FILES = {
    "stable-1.0-protected-handoff.enc",
    "stable-1.0-protected-handoff.json",
}

MAX_STABLE_VULNERABILITY_SUMMARY_BYTES = 4 * 1024 * 1024

MAX_STABLE_VULNERABILITY_PROVENANCE_BYTES = 64 * 1024

APP_SERVICE_DEPENDENCY_AND_GRANT_BUNDLE_EVIDENCE_IDS = (
    "app-services.dependency-graph",
    "app-services.grant-bundles",
    "app-services.grant-expiry-renewal",
    "app-services.provider-revalidation",
    "reference-app.social-inbox-service-dependency",
    "app-services.dependency-redaction",
)

APP_SERVICE_DISCOVERY_AND_GRANT_EVIDENCE_IDS = (
    "app-services.registry",
    "app-services.grants",
    *APP_SERVICE_DEPENDENCY_AND_GRANT_BUNDLE_EVIDENCE_IDS,
    "app-services.trust-score-provider",
    "reference-app.social-inbox-service-grant",
    "app-services.web-shell",
    "app-services.redaction",
)

PLATFORM_API_STABLE_FREEZE_EVIDENCE_IDS = (
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

ECOSYSTEM_RC_REQUIRED_GATE_IDS = (
    "ecosystem.required-evidence-regressions",
    "ecosystem.platform-api-compatibility",
    "ecosystem.first-party-apps",
    "ecosystem.app-ui-quality",
    "ecosystem.app-review-trust",
    "ecosystem.app-update-rollback",
    "ecosystem.operator-rc-recovery",
    "ecosystem.security-advisory-revocation",
    "ecosystem.app-vault",
    "ecosystem.sandbox-provider",
    "ecosystem.reference-content-apps",
    "ecosystem.multi-node-beta",
    "ecosystem.legacy-retirement",
)

ECOSYSTEM_RC_REQUIRED_EVIDENCE_IDS = (
    "interop.smoke",
    "performance.smoke",
    "release-certification.ecosystem-matrix",
    *PRODUCTION_BETA_GO_NO_GO_EVIDENCE_IDS,
    "platform-api.contract",
    *PLATFORM_API_STABLE_FREEZE_EVIDENCE_IDS,
    "app-platform.first-party",
    "first-party-app.beta-quality-pass",
    "app-platform.devtools-cli",
    "app-platform.developer-beta-toolkit",
    *app_platform_docs_check.EVIDENCE_IDS,
    "catalog.smoke",
    "catalog.live-usk-publication",
    "catalog.live-usk-source-verification",
    "app-catalog.first-party-beta",
    "app-platform.signed-bundles",
    "catalog.production-channels",
    "app-catalog.first-party-maintenance-policy",
    *ECOSYSTEM_SECURITY_EVIDENCE_IDS,
    *PRODUCTION_SECURITY_EVIDENCE_IDS,
    "app-review.trusted-receipts",
    "app-review.policy",
    "app-review.governance",
    "app-review.reviewer-key-lifecycle",
    "app-review.transparency-log",
    "app-review.review-history-api",
    "app-review.first-party-catalog",
    "app-review.first-party-review-chain",
    *APP_STORE_SUBMISSION_EVIDENCE_IDS,
    *THIRD_PARTY_INTAKE_EVIDENCE_IDS,
    *THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS,
    "app-platform.user-consent-flow",
    "app-update.lifecycle",
    "app-update.scheduler",
    "app-update.live-catalog-refresh",
    "app-update.rollback",
    "app-update.data-migration-contract",
    "app-platform.durable-app-data-store",
    "app-data.backup-restore-portability",
    "operator-beta.app-data-backup-restore",
    "app-vault.capabilities",
    "app-platform.identity-profile-publish",
    "app-platform.generated-document-insert",
    "app-platform.content-fetch",
    "app-platform.content-subscriptions",
    "network-content.subscription-scheduler",
    "app-platform.trust-graph-preview",
    "app-platform.trust-graph-rc-scope-and-safety",
    "app-platform.trust-graph-durable-store",
    "app-platform.trust-graph-exchange",
    "app-platform.trust-social-beta-hardening",
    "app-platform.trust-social-content-format-profiles",
    "app-platform.privacy-preserving-beta-diagnostics",
    "app-platform.trust-statement-signing",
    "reference-app.trust-graph",
    "reference-app.trust-graph-durable-exchange",
    "reference-app.trust-graph-app-data-preview",
    "app-platform.social-message-signing",
    "reference-app.social-inbox",
    "reference-app.social-inbox-signed-message",
    "reference-app.social-inbox-subscriptions",
    "reference-app.social-inbox-app-data",
    "reference-app.social-inbox-trust-annotations",
    "reference-app.social-inbox-rc-threading",
    "reference-app.social-inbox-service-grant",
    "reference-app.social-inbox-service-dependency",
    "migration.social-mail-preview",
    *APP_SERVICE_DISCOVERY_AND_GRANT_EVIDENCE_IDS,
    *NETWORK_SCALE_EVIDENCE_IDS,
    NETWORK_SCALE_SOAK_EVIDENCE_ID,
    *MULTI_NODE_BETA_EVIDENCE_IDS,
    *OPERATOR_RC_EVIDENCE_IDS,
    "legacy.retirement",
    "legacy-admin.removal-wave-1",
    "legacy-admin.removal-wave-2",
    "legacy-admin.removal-wave-3",
    "legacy-admin.removal-wave-4",
    "legacy-admin.removal-wave-5",
    "legacy-admin.final-admin-surface",
    "legacy-admin.browse-retained",
    "legacy-admin.emergency-fallback-retained",
    "legacy-plugin.freeze-policy",
    "legacy-plugin.migration-guide",
    "legacy-plugin.social-inbox-spike",
    "legacy-plugin.migration-finalization",
    "app-ui.design-system",
    "app-ui.lint",
    "app-ui.first-party-adoption",
    "app-ui.smoke",
    "apphost.sandbox-provider",
    *PUBLIC_BETA_SECURITY_EVIDENCE_IDS,
    "reference-apps.content",
    "reference-app.profile-publisher",
    "reference-app.profile-publisher-app-data",
    "reference-app.feed-reader",
    "reference-app.feed-reader-subscriptions",
    "reference-app.feed-reader-app-data",
)

ECOSYSTEM_RC_REDACTION_EVIDENCE_IDS = (
    "app-platform.docs-redaction",
    "public-beta.links-redaction",
    "ecosystem-security.advisory-revocation-redaction",
    "live-network-beta.redaction",
    "network-scale.redaction",
    "multi-node-beta.redaction",
    "app-services.redaction",
    "app-services.dependency-redaction",
    "legacy-plugin.migration-finalization",
    "app-platform.privacy-preserving-beta-diagnostics",
    "operator-beta.support-bundle-redaction",
    "operator-rc.redaction",
    "public-beta-security.audit-redaction-fuzz",
    "public-beta.redaction-fixtures",
    "production-security.response-runbook",
    "third-party-developer.redaction",
)

SENSITIVE_KEY_PATTERN = (
    r"token|password|passwd|secret|credential|authorization|cookie|set-cookie|"
    r"private[-_ ]?key|formPassword|browserSessionToken|CRYPTAD_APP_TOKEN|X-Crypta-App-Session|"
    r"identity[-_ ]?seed|recovery[-_ ]?phrase|mnemonic|"
    r"raw[-_ ]?request[-_ ]?bod(?:y|ies)|request[-_ ]?bod(?:y|ies)|"
    r"raw[-_ ]?feed[-_ ]?bod(?:y|ies)|feed[-_ ]?bod(?:y|ies)|"
    r"raw[-_ ]?trust[-_ ]?statement[-_ ]?bod(?:y|ies)|trust[-_ ]?statement[-_ ]?bod(?:y|ies)"
    r"|raw[-_ ]?message[-_ ]?bod(?:y|ies)|message[-_ ]?bod(?:y|ies)"
    r"|raw[-_ ]?fetched[-_ ]?bod(?:y|ies)|fetched[-_ ]?bod(?:y|ies)"
    r"|raw[-_ ]?public[-_ ]?key[-_ ]?byt(?:e|es)|public[-_ ]?key[-_ ]?byt(?:e|es)"
    r"|raw[-_ ]?review[-_ ]?receipt|review[-_ ]?receipt[-_ ]?content|raw[-_ ]?receipt"
    r"|raw[-_ ]?signature[-_ ]?valu(?:e|es)|signature[-_ ]?valu(?:e|es)"
    r"|app[-_ ]?data[-_ ]?backup|backup[-_ ]?payload|payloadBase64|"
    r"raw[-_ ]?app[-_ ]?data[-_ ]?valu(?:e|es)|record[-_ ]?valu(?:e|es)"
)

SENSITIVE_KEY_RE = re.compile(
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

URI_KEY_RE = re.compile(r"\b(?:CHK|SSK|USK)@[^\s\])},;\"']+")

URL_USERINFO_RE = re.compile(r"(\b[a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@", re.IGNORECASE)

# A colon must not exempt a local path: hosted tools commonly report values such as
# ``-javaagent:/home/runner/...`` or ``workspace:/home/runner/...``. URL authority separators
# remain excluded because the first slash is followed by another slash and later URL-path slashes
# are preceded by an authority character.
ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9_/.\->])/(?:[A-Za-z0-9._ -]+/)+[A-Za-z0-9._ -]+")

WINDOWS_DRIVE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->])(?:[A-Za-z]:[\\/](?:[^\\/:*?\"<>|\r\n]+[\\/])*[^\\/:*?\"<>|\r\n]+[\\/]?)"
)

WINDOWS_UNC_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->])(?:\\\\[^\\/:*?\"<>|\r\n]+\\[^\\/:*?\"<>|\r\n]+(?:\\[^\\/:*?\"<>|\r\n]+)*\\?)"
)

FILE_URI_PATH_RE = re.compile(r"\bfile://(?P<path>[^\s\])},;\"']+)")

ROUTE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->])/(?:api/v1|apps|app/node|operator|\.well-known)(?:/[^\s\])},;\"'?]*)?"
)

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
class EvidenceItem:
    """Stable evidence record written into the certification summary."""

    id: str
    status: str
    required_for_release_candidate: bool
    summary: str
    source: str
    details: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "requiredForReleaseCandidate": self.required_for_release_candidate,
            "summary": self.summary,
            "source": self.source,
            "details": self.details,
        }

@dataclasses.dataclass(frozen=True)
class WaiverRecord:
    """Approved release-manager waiver loaded from the CLI or a structured file."""

    id: str
    evidence_id: str
    reason: str
    source: str
    status: str = "approved"
    approved_by: str = ""
    expires_at: str = ""
    allow_release_candidate: bool = False
    active: bool = True
    expired: bool = False
    applies_to_release_candidate: bool = True
    validation_error: str = ""

    def matches(self, target_id: str, issue_ids: list[str] | None = None) -> bool:
        candidates = {target_id}
        if issue_ids:
            candidates.update(issue_ids)
        return self.id in candidates or self.evidence_id in candidates

    def to_json(self) -> dict[str, Any]:
        value = {
            "id": self.id,
            "evidenceId": self.evidence_id,
            "status": self.status,
            "approvedBy": self.approved_by,
            "reason": self.reason,
            "source": self.source,
            "active": self.active,
            "expired": self.expired,
            "allowReleaseCandidate": self.allow_release_candidate,
            "appliesToReleaseCandidate": self.applies_to_release_candidate,
        }
        if self.expires_at:
            value["expiresAt"] = self.expires_at
        if self.validation_error:
            value["validationError"] = self.validation_error
        return value

@dataclasses.dataclass(frozen=True)
class WaiverContext:
    """Resolved waiver state used by evidence and ecosystem gate evaluation."""

    records: list[WaiverRecord] = dataclasses.field(default_factory=list)
    errors: list[str] = dataclasses.field(default_factory=list)

    def active_records(self, mode: str) -> list[WaiverRecord]:
        return [
            record
            for record in self.records
            if record.active
            and not record.expired
            and record.status == "approved"
            and (mode != "release-candidate" or record.allow_release_candidate)
        ]

@dataclasses.dataclass(frozen=True)
class GateResult:
    """Deterministic ecosystem release gate result."""

    id: str
    status: str
    release_blocker: bool
    summary: str
    details: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "releaseBlocker": self.release_blocker,
            "summary": self.summary,
            "details": self.details,
        }

@dataclasses.dataclass(frozen=True)
class MatrixRowSpec:
    """Stable release-manager-facing ecosystem certification row."""

    id: str
    category: str
    title: str
    required_evidence_ids: tuple[str, ...] = ()
    optional_evidence_ids: tuple[str, ...] = ()
    gate_ids: tuple[str, ...] = ()
    optional_gate_ids: tuple[str, ...] = ()
    docs: tuple[str, ...] = ()
    owner: str = "release"
    phase: str = "phase-7"
    required_for_release_candidate: bool = True
    first_party_apps: tuple[str, ...] = ()
    synthetic: str = ""

    def evidence_ids(self) -> tuple[str, ...]:
        return self.required_evidence_ids + self.optional_evidence_ids

    def all_gate_ids(self) -> tuple[str, ...]:
        return self.gate_ids + self.optional_gate_ids

@dataclasses.dataclass(frozen=True)
class Settings:
    workspace_root: Path
    out_dir: Path
    mode: str
    interop_smoke_summary: Path
    interop_extended_summary: Path
    perf_smoke_summary: Path
    app_platform_summary: Path
    live_network_summary: Path
    network_scale_soak_summary: Path
    live_network_beta_enabled: bool
    live_network_beta_required: bool
    waivers: dict[str, str]
    metadata: dict[str, str]
    skip_git_metadata: bool
    previous_summary: Path | None = None
    require_history: bool = False
    history_dir: Path = DEFAULT_HISTORY_DIR
    write_history: bool = False
    history_label: str = ""
    waiver_files: tuple[Path, ...] = ()
    multi_node_soak_summary: Path = DEFAULT_OUT_DIR / "multi-node-beta-soak" / "summary.json"
    multi_node_soak_required: bool = False
    security_drills_summary: Path | None = None
    stable_readiness_summary: Path | None = None
    stable_readiness_required: bool = False
    stable_vulnerability_summary: Path | None = None
    stable_vulnerability_required: bool = False
    stable_vulnerability_candidate_release_id: str = ""
    stable_vulnerability_candidate_build_version: str = ""
    stable_supply_chain_summary: Path | None = None
    stable_supply_chain_required: bool = False
    stable_supply_chain_candidate_release_id: str = ""
    stable_supply_chain_candidate_build_version: str = ""
    stable_supply_chain_candidate_source_commit: str = ""
    stable_supply_chain_candidate_source_ref: str = ""
    stable_dependency_vulnerability_summary: Path | None = None
    stable_dependency_vulnerability_required: bool = False
    stable_dependency_vulnerability_candidate_release_id: str = ""
    stable_dependency_vulnerability_candidate_build_version: str = ""
    stable_dependency_vulnerability_candidate_source_commit: str = ""
    stable_dependency_vulnerability_candidate_source_ref: str = ""
    stable_dependency_vulnerability_evidence_phase: str = "final-publication"

def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    return value

def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")

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
    if raw == "":
        return ""
    path_value = Path(raw)
    if not path_value.is_absolute():
        return scrub_text(raw.replace("\\", "/"), workspace_root, out_dir)
    resolved = path_value
    try:
        relative = resolved.resolve().relative_to(workspace_root.resolve())
        return f"<repo>/{relative.as_posix()}"
    except ValueError:
        pass
    if out_dir is not None:
        try:
            relative = resolved.resolve().relative_to(out_dir.resolve())
            out_dir_display = display_path(out_dir, workspace_root)
            if not relative.parts:
                return out_dir_display
            return f"{out_dir_display}/{relative.as_posix()}"
        except ValueError:
            pass
    try:
        relative = resolved.resolve().relative_to(Path(tempfile.gettempdir()).resolve())
        return f"<workdir>/{relative.as_posix()}"
    except ValueError:
        return "<path>/" + resolved.name

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

def protect_route_paths(text: str) -> tuple[str, list[tuple[str, str]]]:
    routes: list[tuple[str, str]] = []

    def replace_route(match: re.Match[str]) -> str:
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

def scrub_text(text: str, workspace_root: Path, out_dir: Path | None = None) -> str:
    redacted = URL_USERINFO_RE.sub(r"\1<redacted>@", text)
    redacted = SENSITIVE_HEADER_RE.sub(lambda match: match.group("prefix") + "<redacted>", redacted)
    redacted = SENSITIVE_TEXT_LABEL_RE.sub(lambda match: match.group("prefix") + "<redacted>", redacted)
    redacted = PRIVATE_KEY_BLOCK_RE.sub("<redacted-private-key>", redacted)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(scrub_sensitive_assignment_match, redacted)
    redacted = URI_KEY_RE.sub("<redacted-uri>", redacted)
    redacted = FILE_URI_PATH_RE.sub(scrub_file_uri_match, redacted)
    redacted, protected_routes = protect_route_paths(redacted)
    for artifact_name in PRIVATE_ARTIFACT_NAMES:
        redacted = redacted.replace(artifact_name, "<redacted-private-artifact>")
    for root_text in path_prefix_variants(workspace_root):
        redacted = replace_absolute_path_prefix(redacted, root_text, "<repo>")
    if out_dir is not None:
        out_display = display_path(out_dir, workspace_root)
        for out_text in path_prefix_variants(out_dir):
            redacted = replace_absolute_path_prefix(redacted, out_text, out_display)
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
        "identityseed",
        "recoveryphrase",
        "mnemonic",
        "seed",
        "token",
        "password",
        "passwd",
        "browsersessiontoken",
        "xcryptaappsession",
        "rawpublickeybytes",
        "publickeybytes",
        "rawreviewreceipt",
        "reviewreceiptcontent",
        "rawreceipt",
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

def sanitize_value(value: Any, workspace_root: Path, out_dir: Path | None = None, key_hint: str = "") -> Any:
    if should_redact_key_name(key_hint, value):
        return "<redacted>"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            result[key_text] = sanitize_value(child, workspace_root, out_dir, key_text)
        return result
    if isinstance(value, list):
        sanitized = [sanitize_value(child, workspace_root, out_dir, key_hint) for child in value]
        return [
            child
            for child in sanitized
            if not (isinstance(child, str) and "<redacted-private-artifact>" in child)
        ]
    if isinstance(value, str):
        return scrub_text(value, workspace_root, out_dir)
    return value

def normalize_evidence_status(status: str) -> str:
    normalized = status.strip().lower()
    if normalized in CERT_STATUSES:
        return normalized
    if normalized in {"success", "passed", "ok", "collected"}:
        return "pass"
    if normalized in {"warning", "warn"}:
        return "warn"
    if normalized in {"failure", "failed", "error"}:
        return "fail"
    if normalized in {"skipped"}:
        return "skip"
    return "missing"

def sanitize_evidence_item(item: EvidenceItem, workspace_root: Path, out_dir: Path) -> EvidenceItem:
    return EvidenceItem(
        id=item.id,
        status=item.status,
        required_for_release_candidate=item.required_for_release_candidate,
        summary=scrub_text(item.summary, workspace_root, out_dir),
        source=scrub_text(item.source, workspace_root, out_dir),
        details=dict(sanitize_value(item.details, workspace_root, out_dir)),
    )

def parse_expiry(value: str) -> dt.datetime | None:
    if not value:
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)

def waiver_scope_allows_release_candidate(scope: str) -> bool:
    normalized = scope.strip().lower()
    return normalized in {
        "all",
        "all-modes",
        "any",
        "release-candidate",
        "release-candidate-only",
        "release-candidate-and-production-beta",
    }

def load_structured_waiver_file(path: Path, settings: Settings, now: dt.datetime) -> tuple[list[WaiverRecord], list[str]]:
    source = display_path(path, settings.workspace_root, settings.out_dir)
    value = read_json(path)
    if value is None:
        return [], [f"Waiver file {source} is missing or malformed."]
    records = value.get("waivers", [])
    schema_version = value.get("version", value.get("schemaVersion"))
    if schema_version != 1 or not isinstance(records, list):
        return [], [f"Waiver file {source} must use version/schemaVersion 1 and a waivers array."]
    loaded: list[WaiverRecord] = []
    errors: list[str] = []
    for index, entry in enumerate(records):
        if not isinstance(entry, dict):
            errors.append(f"Waiver file {source} entry {index} is not an object.")
            continue
        waiver_id = str(entry.get("id", "")).strip()
        evidence_id = str(entry.get("evidenceId", waiver_id)).strip()
        reason = str(entry.get("reason", entry.get("rationale", ""))).strip()
        dashboard_style = "rationale" in entry or "scope" in entry or "owner" in entry or "severity" in entry
        raw_status = str(entry.get("status", "approved" if dashboard_style else "")).strip().lower()
        status = raw_status if raw_status == "approved" else ("pending" if not raw_status else "invalid")
        approved_by = str(entry.get("approvedBy", "")).strip()
        raw_expires_at = str(entry.get("expiresAt", "")).strip()
        allow_release_candidate_present = "allowReleaseCandidate" in entry
        allow_release_candidate_value = entry.get("allowReleaseCandidate", False)
        scope = str(entry.get("scope", "")).strip()
        allow_release_candidate = (
            allow_release_candidate_value
            if allow_release_candidate_present and isinstance(allow_release_candidate_value, bool)
            else waiver_scope_allows_release_candidate(scope)
        )
        validation_errors: list[str] = []
        if not waiver_id:
            validation_errors.append("id is required")
        if not evidence_id:
            validation_errors.append("evidenceId is required")
        if not reason:
            validation_errors.append("reason is required")
        if status != "approved":
            validation_errors.append("status must be approved")
        if allow_release_candidate_present and not isinstance(allow_release_candidate_value, bool):
            validation_errors.append("allowReleaseCandidate must be a boolean")
        expiry = parse_expiry(raw_expires_at)
        if raw_expires_at and expiry is None:
            validation_errors.append("expiresAt must be an ISO-8601 timestamp")
        expired = bool(expiry and expiry <= now)
        if expired:
            validation_errors.append("waiver is expired")
        safe_reason = scrub_text(reason, settings.workspace_root, settings.out_dir)
        safe_waiver_id = scrub_text(waiver_id, settings.workspace_root, settings.out_dir)
        safe_evidence_id = scrub_text(evidence_id, settings.workspace_root, settings.out_dir)
        safe_approved_by = scrub_text(approved_by, settings.workspace_root, settings.out_dir)
        safe_expires_at = (
            scrub_text(raw_expires_at, settings.workspace_root, settings.out_dir)
            if expiry is not None
            else ("<invalid>" if raw_expires_at else "")
        )
        safe_error = "; ".join(validation_errors)
        if validation_errors:
            errors.append(f"Waiver {safe_waiver_id or index} in {source}: {safe_error}.")
        loaded.append(
            WaiverRecord(
                id=safe_waiver_id or f"{source}#{index}",
                evidence_id=safe_evidence_id or safe_waiver_id or f"{source}#{index}",
                reason=safe_reason,
                source=source,
                status=status,
                approved_by=safe_approved_by,
                expires_at=safe_expires_at,
                allow_release_candidate=allow_release_candidate,
                active=not validation_errors,
                expired=expired,
                applies_to_release_candidate=allow_release_candidate,
                validation_error=safe_error,
            )
        )
    return loaded, errors

def load_waiver_context(settings: Settings, now: dt.datetime) -> WaiverContext:
    records: list[WaiverRecord] = []
    errors: list[str] = []
    for waiver_file in settings.waiver_files:
        loaded, file_errors = load_structured_waiver_file(waiver_file, settings, now)
        records.extend(loaded)
        errors.extend(file_errors)
    for waiver_id, reason in settings.waivers.items():
        safe_reason = scrub_text(reason, settings.workspace_root, settings.out_dir)
        safe_waiver_id = scrub_text(waiver_id, settings.workspace_root, settings.out_dir)
        records.append(
            WaiverRecord(
                id=safe_waiver_id,
                evidence_id=safe_waiver_id,
                reason=safe_reason,
                source="cli",
                status="approved",
                approved_by="cli",
                allow_release_candidate=True,
                active=True,
                applies_to_release_candidate=True,
            )
        )
    return WaiverContext(records=records, errors=errors)

def active_waiver_for(
    context: WaiverContext, target_id: str, issue_ids: list[str] | None, mode: str
) -> WaiverRecord | None:
    for record in reversed(context.active_records(mode)):
        if record.matches(target_id, issue_ids):
            return record
    return None

def unique_non_empty_strings(values: Any) -> list[str]:
    if not isinstance(values, (list, tuple)):
        return []
    result: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in result:
            result.append(text)
    return result

def redaction_signal_has_unwaivable_findings(
    value: Any,
    *,
    include_summary_fields: bool = True,
) -> bool:
    if isinstance(value, dict):
        if "redaction" in value and redaction_signal_has_unwaivable_findings(value["redaction"]):
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
                if count_key in value:
                    finding_count, malformed_finding_count = parse_stable_readiness_count(
                        value.get(count_key)
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
            if production_beta_go_no_go_dashboard.redaction_proof_failure(key, child):
                return True
            if redaction_signal_has_unwaivable_findings(
                child,
                include_summary_fields=include_summary_fields,
            ):
                return True
    elif isinstance(value, list):
        return any(
            redaction_signal_has_unwaivable_findings(
                child,
                include_summary_fields=include_summary_fields,
            )
            for child in value
        )
    return False

def has_unwaivable_redaction_findings(_evidence_id: str, details: dict[str, Any]) -> bool:
    redaction_findings = details.get("redactionFindings")
    if "redactionFindings" in details and not isinstance(redaction_findings, list):
        return True
    if isinstance(redaction_findings, list) and bool(redaction_findings):
        return True
    return redaction_signal_has_unwaivable_findings(details, include_summary_fields=False)

def evidence_item_has_unwaivable_redaction_findings(item: EvidenceItem) -> bool:
    return has_unwaivable_redaction_findings(item.id, item.details)

def evidence_entry_has_unwaivable_redaction_findings(entry: dict[str, Any] | None) -> bool:
    return recursive_redaction_field_has_unwaivable_findings(entry)

def recursive_redaction_field_has_unwaivable_findings(value: Any) -> bool:
    if isinstance(value, dict):
        redaction_payload = {
            key: child
            for key, child in value.items()
            if redaction_signal_key(key)
        }
        if redaction_payload and redaction_signal_has_unwaivable_findings(redaction_payload):
            return True
        return any(
            recursive_redaction_field_has_unwaivable_findings(child)
            for child in value.values()
            if isinstance(child, (dict, list))
        )
    if isinstance(value, list):
        return any(recursive_redaction_field_has_unwaivable_findings(child) for child in value)
    return False

def redaction_signal_key(key: Any) -> bool:
    lowered = str(key).lower()
    return (
        "redaction" in lowered
        or lowered in {"findings", "findingcount", "criticalfindingcount"}
        or production_beta_go_no_go_dashboard.redaction_proof_key(key)
    )

def active_waivers_for_all(
    context: WaiverContext, target_ids: list[str], mode: str
) -> list[WaiverRecord]:
    records: list[WaiverRecord] = []
    for target_id in target_ids:
        waiver = active_waiver_for(context, target_id, None, mode)
        if waiver is None:
            return []
        records.append(waiver)
    return records

def active_waivers_for_all_ecosystem_rc_evidence(
    context: WaiverContext, evidence_ids: list[str], mode: str
) -> list[WaiverRecord]:
    records: list[WaiverRecord] = []
    for evidence_id in evidence_ids:
        waiver = active_waiver_for_ecosystem_rc_evidence(context, evidence_id, mode)
        if waiver is None:
            return []
        records.append(waiver)
    return records

def with_waiver_record(item: EvidenceItem, waiver: WaiverRecord | None) -> EvidenceItem:
    if waiver is None or item.status == "pass":
        return item
    details = dict(item.details)
    details["waived"] = True
    details["waiverId"] = waiver.id
    details["waiverReason"] = waiver.reason
    details["waiverSource"] = waiver.source
    return EvidenceItem(
        id=item.id,
        status="warn",
        required_for_release_candidate=item.required_for_release_candidate,
        summary=f"{item.summary} Waiver recorded: {waiver.reason}",
        source=item.source,
        details=details,
    )

def active_waiver_for_evidence_item(
    context: WaiverContext, item: EvidenceItem, mode: str
) -> WaiverRecord | None:
    if (
        item.id in NONWAIVABLE_EVIDENCE_IDS
        or evidence_item_has_unwaivable_redaction_findings(item)
    ):
        return None
    return active_waiver_for(context, item.id, [f"evidence.{item.id}"], mode)

def apply_waiver_to_gate(gate: GateResult, context: WaiverContext, mode: str) -> GateResult:
    if gate.id == "ecosystem.waivers":
        return gate
    issue_ids = [str(value) for value in gate.details.get("issueIds", []) if value]
    unwaivable_failure_evidence_ids = set(
        unique_non_empty_strings(gate.details.get("unwaivableFailureEvidenceIds", []))
    )
    waiver = (
        None
        if unwaivable_failure_evidence_ids
        else active_waiver_for(context, gate.id, issue_ids, mode)
    )
    waived_evidence_ids: list[str] = []
    if waiver is None and gate.status == "fail":
        failure_evidence_ids = unique_non_empty_strings(gate.details.get("failureEvidenceIds", []))
        evidence_waivers = (
            []
            if unwaivable_failure_evidence_ids.intersection(failure_evidence_ids)
            else active_waivers_for_all_ecosystem_rc_evidence(context, failure_evidence_ids, mode)
        )
        if evidence_waivers:
            waiver = evidence_waivers[-1]
            waived_evidence_ids = failure_evidence_ids
    if waiver is None or gate.status == "pass":
        return gate
    details = dict(gate.details)
    details["waived"] = True
    details["waiverId"] = waiver.id
    details["waiverReason"] = waiver.reason
    details["waiverSource"] = waiver.source
    if waived_evidence_ids:
        details["waivedEvidenceIds"] = waived_evidence_ids
    return GateResult(
        id=gate.id,
        status="warn",
        release_blocker=False,
        summary=f"{gate.summary} Waiver recorded: {waiver.reason}",
        details=details,
    )


def stable_vulnerability_source_digest(raw: bytes) -> str:
    """Return the digest of exact attached protected-summary bytes."""

    return shared_stable_vulnerability_source_digest(raw)


def _stable_vulnerability_handoff_paths(
    path: Path,
    workspace_root: Path,
    out_dir: Path,
) -> tuple[Path | None, Path | None, Path | None, list[str]]:
    """Resolve one authenticated external summary handoff without reading unsafe paths."""

    return shared_stable_vulnerability_handoff_paths(
        path, workspace_root, out_dir
    )


def _stable_vulnerability_provenance_errors(
    summary: dict[str, Any],
    summary_raw: bytes,
    binding_path: Path,
    provenance_path: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, list[str]]:
    """Authenticate the exact producer binding and protected materialization receipt."""

    return shared_stable_vulnerability_provenance_errors(
        summary, summary_raw, binding_path, provenance_path
    )


def _stable_vulnerability_sealed_handoff_errors(
    summary_raw: bytes,
    binding_path: Path,
    workspace_root: Path,
) -> list[str]:
    """Cryptographically re-open and compare the protected producer handoff."""

    return shared_stable_vulnerability_sealed_handoff_errors(
        summary_raw, binding_path, workspace_root
    )


def stable_vulnerability_summary_errors(
    value: dict[str, Any],
    raw: bytes,
    workspace_root: Path,
    evaluation_clock: dt.datetime,
    expected_release_id: str,
    expected_build_version: str,
) -> list[str]:
    """Authenticate one bounded protected Stable vulnerability summary."""

    return shared_stable_vulnerability_summary_errors(
        value,
        raw,
        workspace_root,
        evaluation_clock,
        expected_release_id,
        expected_build_version,
    )


def stable_vulnerability_evidence(
    path: Path | None,
    workspace_root: Path,
    out_dir: Path,
    expected_release_id: str,
    expected_build_version: str,
    *,
    required: bool = False,
) -> EvidenceItem | None:
    """Load a protected PR-288 summary as non-waivable aggregate evidence."""

    if path is None:
        if not required:
            return None
        return EvidenceItem(
            STABLE_VULNERABILITY_EVIDENCE_ID,
            "missing",
            True,
            (
                "Authenticated Stable vulnerability governance evidence is "
                "required but no summary was configured."
            ),
            "stable-vulnerability-summary",
            {
                "configured": False,
                "authenticated": False,
                "blockingStablePromotion": False,
                "nonWaivable": True,
                "validationErrors": [
                    "required Stable vulnerability summary is missing"
                ],
            },
        )
    source = display_path(path, workspace_root, out_dir)
    raw = b""
    value: dict[str, Any] | None = None
    binding: dict[str, Any] | None = None
    provenance: dict[str, Any] | None = None
    (
        authenticated_path,
        binding_path,
        provenance_path,
        errors,
    ) = _stable_vulnerability_handoff_paths(path, workspace_root, out_dir)
    if authenticated_path is not None:
        try:
            raw = authenticated_path.read_bytes()
        except OSError:
            errors.append("configured summary is missing or unreadable")
    if raw and len(raw) > MAX_STABLE_VULNERABILITY_SUMMARY_BYTES:
        errors.append("configured summary exceeds the bounded size limit")
    elif raw:
        try:
            loaded = read_strict_json(authenticated_path)
        except (OSError, UnicodeDecodeError, ValueError):
            errors.append("configured summary is malformed")
        else:
            if isinstance(loaded, dict):
                value = loaded
                errors.extend(
                    stable_vulnerability_summary_errors(
                        loaded,
                        raw,
                        workspace_root,
                        dt.datetime.now(dt.timezone.utc),
                        expected_release_id,
                        expected_build_version,
                    )
                )
                assert binding_path is not None and provenance_path is not None
                (
                    binding,
                    provenance,
                    provenance_errors,
                ) = _stable_vulnerability_provenance_errors(
                    loaded,
                    raw,
                    binding_path,
                    provenance_path,
                )
                errors.extend(provenance_errors)
                errors.extend(
                    _stable_vulnerability_sealed_handoff_errors(
                        raw,
                        binding_path,
                        workspace_root,
                    )
                )
                errors.extend(
                    shared_stable_vulnerability_current_tip_errors(
                        loaded, binding, provenance
                    )
                )
            else:
                errors.append("configured summary is not a JSON object")

    details: dict[str, Any] = {
        "configured": True,
        "nonWaivable": True,
        "releaseId": value.get("releaseId") if value is not None else None,
        "buildVersion": value.get("buildVersion") if value is not None else None,
        "authenticated": value is not None and not errors,
        "blockingStablePromotion": (
            value.get("blockingStablePromotion") is True
            if value is not None
            else False
        ),
        "validationErrors": errors,
    }
    blocked = details["blockingStablePromotion"] is True
    status = "fail" if errors or blocked else "pass"
    if errors:
        summary = (
            "The bounded Stable vulnerability summary failed authentication or "
            "schema, consistency, or redaction validation."
        )
    elif blocked:
        summary = (
            "The authenticated Stable vulnerability summary blocks this promotion."
        )
    else:
        summary = (
            "The authenticated Stable vulnerability summary permits this promotion."
        )
    return EvidenceItem(
        STABLE_VULNERABILITY_EVIDENCE_ID,
        status,
        True,
        summary,
        source,
        details,
    )


def stable_supply_chain_handoff_authentication_tag(
    value: dict[str, Any], key: bytes
) -> str:
    """Return the domain-separated MAC for one canonical producer handoff."""

    document = {
        field: child
        for field, child in value.items()
        if field != "authenticationTag"
    }
    canonical = json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    mac_key = hmac.new(
        key,
        STABLE_SUPPLY_CHAIN_HANDOFF_KEY_DOMAIN,
        hashlib.sha256,
    ).digest()
    tag = hmac.new(
        mac_key,
        STABLE_SUPPLY_CHAIN_HANDOFF_MAC_DOMAIN + canonical,
        hashlib.sha256,
    ).hexdigest()
    return f"sha256:{tag}"


def _stable_supply_chain_handoff_key() -> tuple[bytes | None, str | None]:
    encoded = os.environ.get(STABLE_SUPPLY_CHAIN_HANDOFF_KEY_ENV, "")
    try:
        key = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return None, "configured supply-chain handoff authentication key is invalid"
    if (
        len(key) != 32
        or base64.b64encode(key).decode("ascii") != encoded
    ):
        return None, "configured supply-chain handoff authentication key is invalid"
    return key, None


def stable_supply_chain_handoff_authentication_errors(
    value: dict[str, Any],
    *,
    label: str = "configured supply-chain producer handoff",
) -> list[str]:
    """Authenticate one closed producer handoff with the protected MAC key."""

    errors: list[str] = []
    authentication_tag = str(value.get("authenticationTag", ""))
    if re.fullmatch(r"sha256:[0-9a-f]{64}", authentication_tag) is None:
        errors.append(f"{label} authentication tag is invalid")
    key, key_error = _stable_supply_chain_handoff_key()
    if key_error is not None:
        errors.append(key_error)
    elif key is not None and not hmac.compare_digest(
        authentication_tag,
        stable_supply_chain_handoff_authentication_tag(value, key),
    ):
        errors.append(f"{label} authentication failed")
    return errors


def stable_supply_chain_handoff_errors(
    summary_path: Path,
    summary: dict[str, Any],
    summary_byte_digest: str,
    expected_release_id: str,
    expected_build_version: str,
    expected_source_commit: str,
) -> tuple[list[str], dict[str, Any] | None]:
    """Authenticate the exact protected workflow handoff for a PR-289 summary."""

    path = summary_path.with_name(STABLE_SUPPLY_CHAIN_HANDOFF_FILE)
    errors: list[str] = []
    value: dict[str, Any] | None = None
    try:
        metadata = path.stat(follow_symlinks=False)
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            errors.append("configured supply-chain producer handoff is not a regular file")
        elif metadata.st_size > 64 * 1024:
            errors.append("configured supply-chain producer handoff exceeds its size bound")
        else:
            raw = path.read_bytes()
            loaded = read_strict_json(path)
            if not isinstance(loaded, dict):
                errors.append("configured supply-chain producer handoff is not a JSON object")
            else:
                value = loaded
                canonical = (
                    json.dumps(loaded, ensure_ascii=False, indent=2, sort_keys=True).encode(
                        "utf-8"
                    )
                    + b"\n"
                )
                if raw != canonical:
                    errors.append(
                        "configured supply-chain producer handoff bytes are not canonical"
                    )
    except (OSError, UnicodeDecodeError, ValueError):
        errors.append(
            "configured supply-chain producer handoff is missing, unreadable, or malformed"
        )

    if value is None:
        return errors, None
    if set(value) != STABLE_SUPPLY_CHAIN_HANDOFF_FIELDS:
        errors.append("configured supply-chain producer handoff fields are not closed")
    expected = {
        "schemaVersion": 1,
        "kind": "stable-1.0-supply-chain-promotion-handoff",
        "repository": "crypta-network/cryptad",
        "workflow": f"{STABLE_SUPPLY_CHAIN_WORKFLOW}@{expected_source_commit}",
        "workflowCommit": expected_source_commit,
        "operation": "compare-evaluate",
        "releaseId": expected_release_id,
        "buildVersion": expected_build_version,
        "sourceCommit": expected_source_commit,
        "artifactName": (
            f"stable-1.0-supply-chain-{expected_release_id}-comparison"
        ),
        "summaryFileName": "stable-1.0-supply-chain-summary.json",
        "summaryByteDigest": summary_byte_digest,
        "attestationSubjectDigest": summary_byte_digest,
        "attestationVerified": True,
        "denySelfHostedRunners": True,
        "authenticationStatus": "pass",
        "authenticationAlgorithm": (
            STABLE_SUPPLY_CHAIN_HANDOFF_AUTHENTICATION_ALGORITHM
        ),
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            errors.append(f"configured supply-chain producer handoff {field} differs")
    if re.fullmatch(r"[1-9][0-9]*", str(value.get("runId", ""))) is None:
        errors.append("configured supply-chain producer handoff runId is invalid")
    if re.fullmatch(r"[1-9][0-9]*", str(value.get("runAttempt", ""))) is None:
        errors.append("configured supply-chain producer handoff runAttempt is invalid")
    if (
        re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(value.get("producerArtifactDigest", ""))
        )
        is None
    ):
        errors.append(
            "configured supply-chain producer handoff artifact digest is invalid"
        )
    errors.extend(stable_supply_chain_handoff_authentication_errors(value))
    return errors, value


def stable_supply_chain_evidence(
    path: Path | None,
    workspace_root: Path,
    out_dir: Path,
    expected_release_id: str,
    expected_build_version: str,
    expected_source_commit: str,
    expected_source_ref: str,
    observed_source_commit: str,
    *,
    required: bool = False,
) -> EvidenceItem | None:
    """Authenticate one public-safe PR-289 promotion summary as non-waivable evidence."""

    if path is None:
        if not required:
            return None
        return EvidenceItem(
            STABLE_SUPPLY_CHAIN_EVIDENCE_ID,
            "missing",
            True,
            "Authenticated Stable supply-chain evidence is required but no summary was configured.",
            "stable-supply-chain-summary",
            {
                "configured": False,
                "authenticated": False,
                "promotionReady": False,
                "nonWaivable": True,
                "validationErrors": ["required Stable supply-chain summary is missing"],
            },
        )

    errors: list[str] = []
    value: dict[str, Any] | None = None
    handoff: dict[str, Any] | None = None
    handoff_errors: list[str] = []
    raw = b""
    try:
        metadata = path.stat(follow_symlinks=False)
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            errors.append("configured supply-chain summary is not a regular file")
        elif metadata.st_size > 4 * 1024 * 1024:
            errors.append("configured supply-chain summary exceeds the bounded size limit")
        else:
            raw = path.read_bytes()
            loaded = read_strict_json(path)
            if not isinstance(loaded, dict):
                errors.append("configured supply-chain summary is not a JSON object")
            else:
                value = loaded
    except (OSError, UnicodeDecodeError, ValueError):
        errors.append("configured supply-chain summary is missing, unreadable, or malformed")

    if re.fullmatch(r"[0-9a-f]{40}", expected_source_commit) is None:
        errors.append(
            "expected Stable supply-chain candidate source commit is missing or malformed"
        )
    if expected_source_ref != f"commit:{expected_source_commit}":
        errors.append(
            "expected Stable supply-chain candidate source ref is not the immutable commit identity"
        )
    if observed_source_commit != expected_source_commit:
        errors.append(
            "current checkout source commit differs from the expected Stable supply-chain candidate"
        )

    if value is not None:
        errors.extend(validate_schema(value, STABLE_SUPPLY_CHAIN_SUMMARY_SCHEMA))
        canonical = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if raw != canonical:
            errors.append("configured supply-chain summary JSON bytes are not canonical")
        digest_payload = {
            key: child for key, child in value.items() if key != "summaryDigest"
        }
        expected_digest = "sha256:" + hashlib.sha256(
            json.dumps(
                digest_payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        if value.get("summaryDigest") != expected_digest:
            errors.append("configured supply-chain summary digest is invalid")
        summary_byte_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        handoff_errors, handoff = stable_supply_chain_handoff_errors(
            path,
            value,
            summary_byte_digest,
            expected_release_id,
            expected_build_version,
            expected_source_commit,
        )
        errors.extend(handoff_errors)
        if value.get("releaseId") != expected_release_id:
            errors.append("configured supply-chain summary release identity differs")
        build_version = value.get("buildVersion")
        if str(build_version) != expected_build_version:
            errors.append("configured supply-chain summary build identity differs")
        if value.get("sourceCommit") != expected_source_commit:
            errors.append("configured supply-chain summary source commit differs")
        if value.get("sourceRef") != expected_source_ref:
            errors.append("configured supply-chain summary source ref differs")
        if (
            value.get("mode") != "evaluate-promotion"
            or value.get("status") != "pass"
            or value.get("promotionReady") is not True
        ):
            errors.append("configured supply-chain summary does not authorize promotion")
        if value.get("blockers") != [] or value.get("waivers") != []:
            errors.append("configured supply-chain summary contains blockers or waivers")
        evidence = value.get("evidence")
        evidence = evidence if isinstance(evidence, list) else []
        evidence_by_id = {
            row.get("evidenceId"): row for row in evidence if isinstance(row, dict)
        }
        if len(evidence_by_id) != len(evidence):
            errors.append("configured supply-chain summary contains duplicate evidence ids")
        allowed_evidence_ids = set(STABLE_SUPPLY_CHAIN_REQUIRED_EVIDENCE_IDS) | {
            STABLE_SUPPLY_CHAIN_PUBLICATION_EVIDENCE_ID
        }
        if set(evidence_by_id) - allowed_evidence_ids:
            errors.append("configured supply-chain summary contains an unknown evidence id")
        for evidence_id in STABLE_SUPPLY_CHAIN_REQUIRED_EVIDENCE_IDS:
            row = evidence_by_id.get(evidence_id)
            if (
                not isinstance(row, dict)
                or row.get("status") != "pass"
                or row.get("nonWaivable") is not True
            ):
                errors.append(f"required supply-chain evidence is not passing: {evidence_id}")
        publication_row = evidence_by_id.get(
            STABLE_SUPPLY_CHAIN_PUBLICATION_EVIDENCE_ID
        )
        if (
            isinstance(publication_row, dict)
            and publication_row.get("status") == "pass"
        ):
            errors.append(
                "promotion summary falsely claims Stable supply-chain publication passed"
            )
        redaction = value.get("redaction")
        if (
            not isinstance(redaction, dict)
            or redaction.get("status") != "pass"
            or redaction.get("privatePathsExcluded") is not True
            or redaction.get("credentialsExcluded") is not True
            or redaction.get("privateUrisExcluded") is not True
            or redaction.get("embargoedVulnerabilityDataExcluded") is not True
            or redaction.get("sideEffectsPerformed") is not False
        ):
            errors.append("configured supply-chain summary failed public redaction")

    details: dict[str, Any] = {
        "configured": True,
        "authenticated": value is not None and not errors,
        "promotionReady": value.get("promotionReady") is True if value else False,
        "releaseId": value.get("releaseId") if value else None,
        "buildVersion": value.get("buildVersion") if value else None,
        "sourceCommit": value.get("sourceCommit") if value else None,
        "sourceRef": value.get("sourceRef") if value else None,
        "policyDigest": value.get("policyDigest") if value else None,
        "summaryDigest": value.get("summaryDigest") if value else None,
        "componentReverseIndexDigest": (
            value.get("vulnerabilityReverseIndexDigest") if value else None
        ),
        "protectedProducerAuthenticated": (
            handoff is not None and not handoff_errors if value is not None else False
        ),
        "producerWorkflow": handoff.get("workflow") if value and handoff else None,
        "producerRunId": handoff.get("runId") if value and handoff else None,
        "producerArtifactName": (
            handoff.get("artifactName") if value and handoff else None
        ),
        "producerArtifactDigest": (
            handoff.get("producerArtifactDigest") if value and handoff else None
        ),
        "nonWaivable": True,
        "validationErrors": errors,
    }
    return EvidenceItem(
        STABLE_SUPPLY_CHAIN_EVIDENCE_ID,
        "fail" if errors else "pass",
        True,
        (
            "The authenticated Stable supply-chain summary permits this promotion."
            if not errors
            else "The Stable supply-chain summary failed exact identity, schema, digest, evidence, or redaction authentication."
        ),
        display_path(path, workspace_root, out_dir),
        details,
    )


def stable_dependency_vulnerability_phase_errors(
    value: dict[str, Any],
    evidence_phase: str,
) -> list[str]:
    """Validate the closed PR-290 evidence set for one release phase."""

    errors: list[str] = []
    if evidence_phase not in {
        "prepublication-evaluation",
        "final-publication",
    }:
        return [
            "configured dependency-vulnerability evidence phase is unsupported"
        ]
    expected_mode = (
        "evaluate-promotion"
        if evidence_phase == "prepublication-evaluation"
        else "verify-publication"
    )
    if (
        value.get("mode") != expected_mode
        or value.get("status") != "pass"
        or value.get("promotionReady") is not True
        or value.get("activationStatus") != "active-post-activation"
    ):
        errors.append(
            "configured dependency-vulnerability summary does not match the required authenticated evidence phase"
        )
    if value.get("blockers") != [] or value.get("waivers") != []:
        errors.append(
            "configured dependency-vulnerability summary contains blockers or waivers"
        )
    evidence = value.get("evidence")
    evidence = evidence if isinstance(evidence, list) else []
    evidence_by_id = {
        row.get("evidenceId"): row for row in evidence if isinstance(row, dict)
    }
    if len(evidence_by_id) != len(evidence):
        errors.append(
            "configured dependency-vulnerability summary contains duplicate evidence ids"
        )
    required_evidence_ids = set(
        STABLE_DEPENDENCY_VULNERABILITY_REQUIRED_EVIDENCE_IDS
    )
    if evidence_phase == "prepublication-evaluation":
        required_evidence_ids.remove(
            "stable-dependency-vulnerability.publication"
        )
    if set(evidence_by_id) != required_evidence_ids:
        errors.append(
            "configured dependency-vulnerability summary evidence ids are not the closed required set"
        )
    for evidence_id in sorted(required_evidence_ids):
        row = evidence_by_id.get(evidence_id)
        if (
            not isinstance(row, dict)
            or row.get("status") != "pass"
            or row.get("nonWaivable") is not True
        ):
            errors.append(
                "required dependency-vulnerability evidence is not passing: "
                f"{evidence_id}"
            )
    publication_fields = (
        "publicationPlanDigest",
        "publicationReceiptDigest",
        "publicObservationDigest",
    )
    for field in publication_fields:
        field_value = value.get(field)
        if evidence_phase == "prepublication-evaluation":
            if field_value is not None:
                errors.append(
                    "configured prepublication dependency-vulnerability summary "
                    f"unexpectedly contains {field}"
                )
        elif re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(field_value or "")
        ) is None:
            errors.append(
                "configured dependency-vulnerability summary lacks final "
                f"{field}"
            )
    return errors


def stable_dependency_vulnerability_evidence(
    path: Path | None,
    workspace_root: Path,
    out_dir: Path,
    expected_release_id: str,
    expected_build_version: str,
    expected_source_commit: str,
    expected_source_ref: str,
    observed_source_commit: str,
    supply_chain_item: EvidenceItem | None,
    vulnerability_item: EvidenceItem | None,
    expected_vulnerability_summary_digest: str | None,
    *,
    required: bool = False,
    certification_clock: str | None = None,
    evidence_phase: str = "final-publication",
) -> EvidenceItem | None:
    """Authenticate one public-safe PR-290 companion promotion summary."""

    if path is None:
        if not required:
            return None
        return EvidenceItem(
            STABLE_DEPENDENCY_VULNERABILITY_EVIDENCE_ID,
            "missing",
            True,
            (
                "Authenticated Stable dependency-vulnerability evidence is required "
                "but no summary was configured."
            ),
            "stable-dependency-vulnerability-summary",
            {
                "configured": False,
                "authenticated": False,
                "promotionReady": False,
                "nonWaivable": True,
                "validationErrors": [
                    "required Stable dependency-vulnerability summary is missing"
                ],
            },
        )

    errors: list[str] = []
    value: dict[str, Any] | None = None
    handoff: dict[str, Any] | None = None
    handoff_errors: list[str] = []
    current_tip_errors: list[str] = []
    raw = b""
    try:
        metadata = path.stat(follow_symlinks=False)
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            errors.append(
                "configured dependency-vulnerability summary is not a regular file"
            )
        elif metadata.st_size > 4 * 1024 * 1024:
            errors.append(
                "configured dependency-vulnerability summary exceeds its size bound"
            )
        else:
            raw = path.read_bytes()
            loaded = read_strict_json(path)
            if not isinstance(loaded, dict):
                errors.append(
                    "configured dependency-vulnerability summary is not a JSON object"
                )
            else:
                value = loaded
    except (OSError, UnicodeDecodeError, ValueError):
        errors.append(
            "configured dependency-vulnerability summary is missing, unreadable, or malformed"
        )

    if re.fullmatch(r"[0-9a-f]{40}", expected_source_commit) is None:
        errors.append(
            "expected dependency-vulnerability candidate source commit is missing or malformed"
        )
    if expected_source_ref != f"commit:{expected_source_commit}":
        errors.append(
            "expected dependency-vulnerability source ref is not the immutable commit identity"
        )
    if observed_source_commit != expected_source_commit:
        errors.append(
            "current checkout source commit differs from the expected dependency-vulnerability candidate"
        )

    if value is not None:
        errors.extend(
            validate_schema(
                value, STABLE_DEPENDENCY_VULNERABILITY_SUMMARY_SCHEMA
            )
        )
        canonical = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        if raw != canonical:
            errors.append(
                "configured dependency-vulnerability summary JSON bytes are not canonical"
            )
        digest_payload = {
            key: child for key, child in value.items() if key != "summaryDigest"
        }
        expected_digest = "sha256:" + hashlib.sha256(
            json.dumps(
                digest_payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        if value.get("summaryDigest") != expected_digest:
            errors.append(
                "configured dependency-vulnerability summary digest is invalid"
            )
        summary_byte_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        handoff_validator = (
            stable_dependency_vulnerability_evaluation_handoff_errors
            if evidence_phase == "prepublication-evaluation"
            else stable_dependency_vulnerability_handoff_errors
        )
        handoff_errors, handoff = handoff_validator(
            path,
            summary_byte_digest,
            expected_release_id,
            expected_build_version,
            expected_source_commit,
        )
        errors.extend(handoff_errors)
        current_tip_errors = stable_dependency_vulnerability_current_tip_errors(
            value,
            certification_clock=certification_clock,
        )
        errors.extend(current_tip_errors)
        if value.get("releaseId") != expected_release_id:
            errors.append(
                "configured dependency-vulnerability summary release identity differs"
            )
        if str(value.get("buildVersion")) != expected_build_version:
            errors.append(
                "configured dependency-vulnerability summary build identity differs"
            )
        if value.get("candidateSourceCommit") != expected_source_commit:
            errors.append(
                "configured dependency-vulnerability summary source commit differs"
            )
        errors.extend(
            stable_dependency_vulnerability_phase_errors(
                value,
                evidence_phase,
            )
        )
        redaction = value.get("redaction")
        if (
            not isinstance(redaction, dict)
            or redaction.get("status") != "pass"
            or redaction.get("privateCaseMaterialExcluded") is not True
            or redaction.get("reporterIdentityExcluded") is not True
            or redaction.get("embargoedDetailsExcluded") is not True
            or redaction.get("credentialsExcluded") is not True
            or redaction.get("privateUrisExcluded") is not True
            or redaction.get("absolutePathsExcluded") is not True
            or redaction.get("rawFeedsExcluded") is not True
            or redaction.get("sideEffectsPerformed") is not False
        ):
            errors.append(
                "configured dependency-vulnerability summary failed public redaction"
            )

        supply_details = supply_chain_item.details if supply_chain_item else {}
        if supply_chain_item is None or supply_chain_item.status != "pass":
            errors.append(
                "dependency-vulnerability promotion requires passing PR-289 supply-chain evidence"
            )
        else:
            expected_supply_bindings = {
                "supplyChainPolicyDigest": supply_details.get("policyDigest"),
                "supplyChainPromotionSummaryDigest": supply_details.get(
                    "summaryDigest"
                ),
                "componentReverseIndexDigest": supply_details.get(
                    "componentReverseIndexDigest"
                ),
            }
            for field, expected_value in expected_supply_bindings.items():
                if not isinstance(expected_value, str) or value.get(field) != expected_value:
                    errors.append(
                        "configured dependency-vulnerability summary "
                        f"{field} does not bind the authenticated PR-289 evidence"
                    )
        if vulnerability_item is None or vulnerability_item.status != "pass":
            errors.append(
                "dependency-vulnerability promotion requires passing PR-288 vulnerability evidence"
            )
        elif (
            not isinstance(expected_vulnerability_summary_digest, str)
            or value.get("vulnerabilityPromotionSummaryDigest")
            != expected_vulnerability_summary_digest
        ):
            errors.append(
                "configured dependency-vulnerability summary does not bind the authenticated PR-288 summary"
            )

    details: dict[str, Any] = {
        "configured": True,
        "authenticated": value is not None and not errors,
        "promotionReady": value.get("promotionReady") is True if value else False,
        "evidencePhase": evidence_phase,
        "releaseId": value.get("releaseId") if value else None,
        "buildVersion": value.get("buildVersion") if value else None,
        "candidateSourceCommit": (
            value.get("candidateSourceCommit") if value else None
        ),
        "policyDigest": value.get("policyDigest") if value else None,
        "intelligenceSnapshotDigest": (
            value.get("intelligenceSnapshotDigest") if value else None
        ),
        "componentReverseIndexDigest": (
            value.get("componentReverseIndexDigest") if value else None
        ),
        "summaryDigest": value.get("summaryDigest") if value else None,
        "ledgerEdition": value.get("ledgerEdition") if value else None,
        "ledgerDigest": value.get("ledgerDigest") if value else None,
        "validUntil": value.get("validUntil") if value else None,
        "currentTipAuthenticated": value is not None and not current_tip_errors,
        "protectedProducerAuthenticated": (
            handoff is not None and not handoff_errors if value is not None else False
        ),
        "publicationVerified": (
            value.get("mode") == "verify-publication" and not errors
            if value
            else False
        ),
        "producerWorkflow": handoff.get("workflow") if value and handoff else None,
        "producerRunId": handoff.get("runId") if value and handoff else None,
        "producerRunAttempt": (
            handoff.get("runAttempt") if value and handoff else None
        ),
        "producerArtifactName": (
            handoff.get("artifactName") if value and handoff else None
        ),
        "producerArtifactDigest": (
            handoff.get("producerArtifactDigest") if value and handoff else None
        ),
        "nonWaivable": True,
        "validationErrors": errors,
    }
    return EvidenceItem(
        STABLE_DEPENDENCY_VULNERABILITY_EVIDENCE_ID,
        "fail" if errors else "pass",
        True,
        (
            "The authenticated Stable dependency-vulnerability companion summary permits this promotion."
            if not errors
            else "The Stable dependency-vulnerability summary failed exact identity, binding, authentication, evidence, or redaction validation."
        ),
        display_path(path, workspace_root, out_dir),
        details,
    )


def has_required_flow(summary: dict[str, Any], flow_name: str) -> bool:
    flows = summary.get("flows", {})
    if not isinstance(flows, dict):
        return False
    flow = flows.get(flow_name, {})
    return isinstance(flow, dict) and flow.get("status") == "passed"

def flow_status(summary: dict[str, Any], flow_name: str) -> str:
    flows = summary.get("flows", {})
    if not isinstance(flows, dict):
        return "missing"
    flow = flows.get(flow_name, {})
    if isinstance(flow, dict):
        return str(flow.get("status", "missing"))
    return str(flow)

def sanitized_artifact_refs(summary: dict[str, Any], workspace_root: Path, out_dir: Path) -> list[str]:
    artifacts = summary.get("artifacts", [])
    if not isinstance(artifacts, list):
        return []
    refs: list[str] = []
    for artifact in artifacts:
        artifact_text = str(artifact)
        if any(name in artifact_text for name in PRIVATE_ARTIFACT_NAMES):
            continue
        refs.append(str(sanitize_value(artifact_text, workspace_root, out_dir)))
    return sorted(dict.fromkeys(refs))

def interop_evidence(
    evidence_id: str,
    path: Path,
    required: bool,
    expected_mode: str,
    workspace_root: Path,
    out_dir: Path,
) -> EvidenceItem:
    source = display_path(path, workspace_root, out_dir)
    summary = read_json(path)
    if summary is None:
        missing_status = "missing"
        return EvidenceItem(
            evidence_id,
            missing_status,
            required,
            f"{expected_mode} interop summary is missing",
            source,
            {},
        )

    sanitized = sanitize_value(summary, workspace_root, out_dir)
    common_required_flows = [
        "handshake",
        "peer_exchange",
        "chk_cross_fetch",
        "ssk_cross_fetch",
        "usk_smoke",
        "restart_recovery",
    ]
    extended_required_flows = ["usk_subscribe_soak", "persistent_request_replay"]
    required_flows = common_required_flows + (
        extended_required_flows if expected_mode == "extended" else []
    )
    coverage = {flow: flow_status(summary, flow) for flow in required_flows}
    missing_flows = [flow for flow in required_flows if not has_required_flow(summary, flow)]
    summary_status = str(summary.get("status", "missing"))
    summary_mode = str(summary.get("mode", "missing"))
    mode_matches = summary_mode == expected_mode
    if summary_status == "success" and not mode_matches:
        status = "fail" if required else "warn"
        headline = f"{expected_mode} Hyphanet interop summary has wrong mode"
    elif summary_status == "success" and not missing_flows:
        status = "pass"
        headline = f"{expected_mode} Hyphanet interop passed"
    elif summary_status == "success":
        status = "warn" if not required else "fail"
        headline = f"{expected_mode} Hyphanet interop completed with incomplete required coverage"
    elif summary_status == "failure":
        status = "fail"
        headline = f"{expected_mode} Hyphanet interop failed"
    else:
        status = "missing"
        headline = f"{expected_mode} Hyphanet interop status is unavailable"

    details = {
        "expectedMode": expected_mode,
        "mode": sanitized.get("mode"),
        "modeMatches": mode_matches,
        "status": sanitized.get("status"),
        "coverage": coverage,
        "missingRequiredFlows": missing_flows,
        "restartRecoveryLevel": sanitized.get("restart_recovery_level"),
        "restartRecoveryChecks": sanitized.get("restart_recovery_checks", []),
        "restartRecoveryDeferredChecks": sanitized.get(
            "restart_recovery_deferred_checks", []
        ),
        "baseline": sanitized.get("baseline", sanitized.get("hyphanet", {})),
        "artifacts": sanitized_artifact_refs(summary, workspace_root, out_dir),
    }
    if expected_mode == "extended":
        details["extendedCoverage"] = {
            "uskSubscribeSoak": flow_status(summary, "usk_subscribe_soak"),
            "persistentRequestReplay": flow_status(summary, "persistent_request_replay"),
            "opennetOptional": flow_status(summary, "opennet_optional"),
        }
    return EvidenceItem(evidence_id, status, required, headline, source, details)

def perf_evidence(path: Path, required: bool, workspace_root: Path, out_dir: Path) -> EvidenceItem:
    source = display_path(path, workspace_root, out_dir)
    summary = read_json(path)
    if summary is None:
        return EvidenceItem(
            "performance.smoke",
            "missing",
            required,
            "Performance smoke summary is missing",
            source,
            {},
        )
    sanitized = sanitize_value(summary, workspace_root, out_dir)
    raw_status = str(summary.get("status", "missing"))
    summary_mode = str(summary.get("mode", "missing"))
    expected_mode = "smoke"
    mode_matches = summary_mode == expected_mode
    status = (
        {"success": "pass", "warning": "warn", "failure": "fail"}.get(raw_status, "missing")
        if mode_matches
        else ("fail" if required else "warn")
    )
    comparison = summary.get("comparison", {})
    if not isinstance(comparison, dict):
        comparison = {}
    details = {
        "expectedMode": expected_mode,
        "mode": sanitized.get("mode"),
        "modeMatches": mode_matches,
        "status": sanitized.get("status"),
        "comparison": sanitize_value(comparison, workspace_root, out_dir),
        "failedMetrics": failed_perf_metrics(summary),
        "warningMetrics": warning_perf_metrics(summary),
        "perfReport": display_path(path.parent / "artifacts" / "perf-report.md", workspace_root, out_dir),
    }
    if not mode_matches:
        return EvidenceItem(
            "performance.smoke",
            status,
            required,
            "Performance smoke summary has wrong mode",
            source,
            details,
        )
    return EvidenceItem(
        "performance.smoke",
        status,
        required,
        f"Performance smoke status is {raw_status}",
        source,
        details,
    )

def failed_perf_metrics(summary: dict[str, Any]) -> list[str]:
    metrics = summary.get("metrics", {})
    if not isinstance(metrics, dict):
        return []
    return sorted(name for name, metric in metrics.items() if isinstance(metric, dict) and metric.get("status") == "failed")

def warning_perf_metrics(summary: dict[str, Any]) -> list[str]:
    comparison = summary.get("comparison", {})
    if not isinstance(comparison, dict):
        return []
    names: list[str] = []
    for group in ("regressions", "warnings"):
        entries = comparison.get(group, [])
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict) and entry.get("metric"):
                    names.append(str(entry["metric"]))
    return sorted(dict.fromkeys(names))

def app_platform_evidence(
    path: Path, workspace_root: Path, out_dir: Path, expected_mode: str
) -> list[EvidenceItem]:
    source = display_path(path, workspace_root, out_dir)
    summary = read_json(path)
    expected_ids = [
        "app-platform.first-party",
        "first-party-app.beta-quality-pass",
        "app-platform.devtools-cli",
        "app-platform.developer-beta-toolkit",
        "platform-api.contract",
        *PLATFORM_API_STABLE_FREEZE_EVIDENCE_IDS,
        "app-vault.capabilities",
        "app-platform.identity-profile-publish",
        "app-platform.generated-document-insert",
        "app-platform.content-fetch",
        "app-platform.content-subscriptions",
        "network-content.subscription-scheduler",
        *NETWORK_SCALE_EVIDENCE_IDS,
        "app-platform.durable-app-data-store",
        "app-data.backup-restore-portability",
        "app-platform.trust-graph-preview",
        "app-platform.trust-graph-rc-scope-and-safety",
        "app-platform.trust-graph-durable-store",
        "app-platform.trust-graph-exchange",
        "app-platform.trust-social-beta-hardening",
        "app-platform.trust-social-content-format-profiles",
        "app-platform.privacy-preserving-beta-diagnostics",
        "app-platform.trust-statement-signing",
        "app-platform.social-message-signing",
        *APP_SERVICE_DISCOVERY_AND_GRANT_EVIDENCE_IDS,
        "app-platform.signed-bundles",
        "catalog.smoke",
        "catalog.live-usk-publication",
        "catalog.live-usk-source-verification",
        "app-catalog.first-party-beta",
        "catalog.production-channels",
        "catalog.operations-and-mirrors",
        "app-catalog.first-party-maintenance-policy",
        "app-review.trusted-receipts",
        "app-review.policy",
        "app-review.governance",
        "app-review.reviewer-key-lifecycle",
        "app-review.transparency-log",
        "app-review.review-history-api",
        "app-review.first-party-catalog",
        "app-review.first-party-review-chain",
        *APP_STORE_SUBMISSION_EVIDENCE_IDS,
        *THIRD_PARTY_INTAKE_EVIDENCE_IDS,
        *THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS,
        "app-platform.user-consent-flow",
        "app-ui.design-system",
        "app-ui.lint",
        "app-ui.first-party-adoption",
        "app-ui.smoke",
        "reference-apps.content",
        "reference-app.profile-publisher",
        "reference-app.profile-publisher-app-data",
        "reference-app.feed-reader",
        "reference-app.feed-reader-subscriptions",
        "reference-app.feed-reader-app-data",
        "reference-app.trust-graph",
        "reference-app.trust-graph-durable-exchange",
        "reference-app.trust-graph-app-data-preview",
        "reference-app.social-inbox",
        "reference-app.social-inbox-signed-message",
        "reference-app.social-inbox-subscriptions",
        "reference-app.social-inbox-app-data",
        "reference-app.social-inbox-trust-annotations",
        "reference-app.social-inbox-rc-threading",
        "migration.social-mail-preview",
        "legacy-plugin.freeze-policy",
        "legacy-plugin.migration-guide",
        "legacy-plugin.social-inbox-spike",
        "legacy-plugin.migration-finalization",
        "legacy.retirement",
        "legacy-admin.removal-wave-1",
        "legacy-admin.removal-wave-2",
        "legacy-admin.removal-wave-3",
        "legacy-admin.removal-wave-4",
        "legacy-admin.removal-wave-5",
        "legacy-admin.final-admin-surface",
        "legacy-admin.browse-retained",
        "legacy-admin.emergency-fallback-retained",
        "apphost.sandbox-provider",
        *PUBLIC_BETA_SECURITY_EVIDENCE_IDS,
        *ECOSYSTEM_SECURITY_EVIDENCE_IDS,
        "app-update.lifecycle",
        "app-update.scheduler",
        "app-update.live-catalog-refresh",
        "app-update.rollback",
        "app-update.data-migration-contract",
        *OPERATOR_BETA_EVIDENCE_IDS,
        *OPERATOR_RC_EVIDENCE_IDS,
        "apphost.live",
    ]
    if summary is None:
        return [
            EvidenceItem(
                evidence_id,
                "missing" if evidence_id != "apphost.live" else "skip",
                evidence_id != "apphost.live",
                "App-platform smoke summary is missing",
                source,
                {},
            )
            for evidence_id in expected_ids
        ]
    summary_mode = str(summary.get("mode", "missing"))
    mode_matches = summary_mode == expected_mode
    if expected_mode == "release-candidate" and not mode_matches:
        return [
            EvidenceItem(
                evidence_id,
                "fail" if evidence_id != "apphost.live" else "skip",
                evidence_id != "apphost.live",
                "App-platform smoke summary has wrong mode",
                source,
                {
                    "expectedMode": expected_mode,
                    "mode": sanitize_value(summary_mode, workspace_root, out_dir),
                    "modeMatches": False,
                    "summaryStatus": sanitize_value(summary.get("status"), workspace_root, out_dir),
                },
            )
            for evidence_id in expected_ids
        ]
    evidence = summary.get("evidence", [])
    if not isinstance(evidence, list):
        return [
            EvidenceItem(
                "app-platform.smoke",
                "fail",
                True,
                "App-platform summary has no evidence list",
                source,
                {"summaryStatus": sanitize_value(summary.get("status"), workspace_root, out_dir)},
            )
        ]
    items: list[EvidenceItem] = []
    seen: set[str] = set()
    for value in evidence:
        if not isinstance(value, dict):
            continue
        evidence_id = str(value.get("id", "app-platform.unknown"))
        seen.add(evidence_id)
        items.append(
            EvidenceItem(
                id=evidence_id,
                status=normalize_evidence_status(str(value.get("status", "missing"))),
                required_for_release_candidate=bool(value.get("requiredForReleaseCandidate", True)),
                summary=str(
                    sanitize_value(value.get("summary", "No summary provided"), workspace_root, out_dir)
                ),
                source=str(sanitize_value(value.get("source", source), workspace_root, out_dir)),
                details=dict(
                    sanitize_value(value.get("details", {}), workspace_root, out_dir)
                    if isinstance(value.get("details", {}), dict)
                    else {}
                ),
            )
        )
    for evidence_id in expected_ids:
        if evidence_id not in seen:
            items.append(
                EvidenceItem(
                    evidence_id,
                    "missing" if evidence_id != "apphost.live" else "skip",
                    evidence_id != "apphost.live",
                    f"{evidence_id} was not reported by app-platform smoke",
                    source,
                    {},
                )
            )
    return items

def security_drill_artifact_file_validation(
    summary: dict[str, Any],
    summary_path: Path,
    workspace_root: Path,
    out_dir: Path,
    strict: bool,
) -> dict[str, Any]:
    model_path = workspace_root / "tools/release-certification/production-security-response-runbook.json"
    if not model_path.is_file():
        model_path = Path(__file__).resolve().parent / "production-security-response-runbook.json"
    return security_response_runbook.validate_drill_artifact_files(
        summary,
        summary_path,
        model_path=model_path,
        strict=strict,
        display_path_fn=lambda path: display_path(path, workspace_root, out_dir),
    )

def security_drills_evidence(
    path: Path | None,
    workspace_root: Path,
    out_dir: Path,
    mode: str,
) -> EvidenceItem:
    source_path = path or workspace_root / "build/security-drills/security-drills-summary.json"
    source = display_path(source_path, workspace_root, out_dir)
    summary = read_json(source_path)
    if summary is None:
        return EvidenceItem(
            "production-security.response-runbook",
            "missing",
            True,
            "Security response drills summary is missing.",
            source,
            {
                "summaryRequired": True,
                "requiredScenarios": list(security_response_runbook.REQUIRED_DRILLS),
                "missingScenarios": list(security_response_runbook.REQUIRED_DRILLS),
                "promotionReady": False,
            },
        )
    validation = security_response_runbook.validate_drills_summary(
        summary,
        strict=mode == "release-candidate",
    )
    artifact_validation = security_drill_artifact_file_validation(
        summary,
        source_path,
        workspace_root,
        out_dir,
        strict=mode == "release-candidate",
    )
    counts = summary.get("counts") if isinstance(summary.get("counts"), dict) else {}
    redaction = summary.get("redaction") if isinstance(summary.get("redaction"), dict) else {}
    validation_redaction_findings = validation.get("redactionFindings")
    if not isinstance(validation_redaction_findings, list):
        validation_redaction_findings = []
    summary_redaction_findings = redaction.get("findings")
    if not isinstance(summary_redaction_findings, list):
        summary_redaction_findings = []
    artifact_redaction_findings = artifact_validation.get("redactionFindings")
    if not isinstance(artifact_redaction_findings, list):
        artifact_redaction_findings = []
    redaction_findings = [
        *validation_redaction_findings,
        *summary_redaction_findings,
        *artifact_redaction_findings,
    ]
    if redaction.get("status") != "pass" and not redaction_findings:
        redaction_findings.append("security response drills summary redaction status is not pass")
    validation_errors = list(validation.get("errors", [])) if isinstance(validation.get("errors"), list) else []
    artifact_errors = (
        artifact_validation.get("errors") if isinstance(artifact_validation.get("errors"), list) else []
    )
    details = {
        "summaryRequired": True,
        "summaryStatus": summary.get("status", "missing"),
        "promotionReady": bool(summary.get("promotionReady")),
        "nonRelease": bool(summary.get("nonRelease")),
        "fixtureOnly": bool(summary.get("fixtureOnly")),
        "mode": summary.get("mode", "missing"),
        "evidenceMode": summary.get("evidenceMode", "missing"),
        "releaseId": summary.get("releaseId", "missing"),
        "generatedAt": summary.get("generatedAt", "missing"),
        "counts": counts,
        "requiredScenarios": summary.get("requiredScenarios", []),
        "passedScenarios": summary.get("passedScenarios", []),
        "failedScenarios": summary.get("failedScenarios", []),
        "missingScenarios": summary.get("missingScenarios", []),
        "staleScenarios": summary.get("staleScenarios", []),
        "malformedScenarios": summary.get("malformedScenarios", []),
        "redaction": redaction,
        "releaseNotes": summary.get("releaseNotes", {}),
        "advisoryTemplate": summary.get("advisoryTemplate", {}),
        "artifacts": summary.get("artifacts", []),
        "artifactValidation": artifact_validation,
        "validationErrors": [*validation_errors, *artifact_errors],
        "redactionClean": validation.get("redactionClean", False) and not artifact_redaction_findings,
        "redactionFindings": redaction_findings,
    }
    details = dict(sanitize_value(details, workspace_root, out_dir))
    if validation["status"] == "pass" and artifact_validation.get("status") == "pass":
        passed = counts.get("passed", len(summary.get("passedScenarios", [])))
        required = counts.get("required", len(security_response_runbook.REQUIRED_DRILLS))
        headline = f"Security response drills passed for {passed}/{required} required scenarios."
        status = "pass"
    else:
        headline = (
            "Security response drills are missing, stale, failed, malformed, "
            "artifact-incomplete, or redaction-unsafe."
        )
        status = "fail"
    return EvidenceItem(
        "production-security.response-runbook",
        status,
        True,
        headline,
        source,
        details,
    )

def combined_security_response_status(items: list[EvidenceItem]) -> str:
    statuses = [normalize_evidence_status(item.status) for item in items]
    for status in ("fail", "missing", "skip", "warn"):
        if status in statuses:
            return status
    return "pass"

def security_response_redaction_findings(items: list[EvidenceItem]) -> list[Any]:
    findings: list[Any] = []
    for item in items:
        item_findings = item.details.get("redactionFindings")
        if isinstance(item_findings, list):
            findings.extend(item_findings)
    return findings

def combine_security_response_evidence(
    app_platform_items: list[EvidenceItem],
    drill_item: EvidenceItem,
) -> EvidenceItem:
    app_item = (
        app_platform_items[0]
        if app_platform_items
        else EvidenceItem(
            id="production-security.response-runbook",
            status="missing",
            required_for_release_candidate=True,
            summary="App-platform security response runbook evidence is missing.",
            source="app-platform-smoke",
            details={},
        )
    )
    components = [app_item, drill_item]
    status = combined_security_response_status(components)
    if status == "pass":
        summary = "Production security response runbook and operational drills passed."
    else:
        summary = (
            "Production security response is not promotion-ready: "
            f"appPlatformRunbook={app_item.status}, securityDrills={drill_item.status}."
        )
    details: dict[str, Any] = {
        "appPlatformRunbook": app_item.to_json(),
        "securityDrills": drill_item.to_json(),
        "componentStatuses": {
            "appPlatformRunbook": app_item.status,
            "securityDrills": drill_item.status,
        },
    }
    if len(app_platform_items) > 1:
        details["duplicateAppPlatformRunbookEvidence"] = [
            item.to_json() for item in app_platform_items[1:]
        ]
    redaction_findings = security_response_redaction_findings(components)
    if redaction_findings:
        details["redactionFindings"] = redaction_findings
    return EvidenceItem(
        id="production-security.response-runbook",
        status=status,
        required_for_release_candidate=(
            app_item.required_for_release_candidate or drill_item.required_for_release_candidate
        ),
        summary=summary,
        source=f"{app_item.source}; {drill_item.source}",
        details=details,
    )

def live_network_beta_evidence(
    path: Path,
    workspace_root: Path,
    out_dir: Path,
    expected_mode: str,
    enabled: bool,
    required: bool,
) -> list[EvidenceItem]:
    source = display_path(path, workspace_root, out_dir)
    default_status = "missing" if enabled or required else "skip"
    default_required = required
    default_details = {"enabled": enabled, "required": required}
    if not enabled and not required:
        return [
            EvidenceItem(
                evidence_id,
                default_status,
                False,
                "Live-network beta certification was not requested.",
                source,
                default_details,
            )
            for evidence_id in LIVE_NETWORK_BETA_EVIDENCE_IDS
        ]

    summary = read_json(path)
    if summary is None:
        default_summary = (
            "Live-network beta certification summary is missing."
            if enabled or required
            else "Live-network beta certification was not requested."
        )
        return [
            EvidenceItem(
                evidence_id,
                default_status,
                default_required and evidence_id in LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS,
                default_summary,
                source,
                default_details,
            )
            for evidence_id in LIVE_NETWORK_BETA_EVIDENCE_IDS
        ]

    sanitized_summary = dict(sanitize_value(summary, workspace_root, out_dir))
    summary_mode = str(sanitized_summary.get("mode", "missing"))
    summary_enabled = bool(sanitized_summary.get("enabled", enabled))
    summary_required = bool(sanitized_summary.get("required", required)) or required
    mode_matches = summary_mode == expected_mode
    kind_matches = sanitized_summary.get("kind") == "live-network-beta-smoke"
    summary_status = normalize_evidence_status(str(sanitized_summary.get("status", "missing")))
    summary_details = {
        "enabled": summary_enabled,
        "required": summary_required,
        "summaryStatus": summary_status,
        "mode": summary_mode,
        "modeMatches": mode_matches,
        "kind": sanitized_summary.get("kind"),
        "node": sanitized_summary.get("node", {}),
        "redaction": sanitized_summary.get("redaction", {}),
    }
    if not kind_matches:
        status = "fail" if summary_required else "warn"
        return [
            EvidenceItem(
                evidence_id,
                status,
                summary_required and evidence_id in LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS,
                "Live-network beta summary has the wrong kind.",
                source,
                summary_details,
            )
            for evidence_id in LIVE_NETWORK_BETA_EVIDENCE_IDS
        ]
    if expected_mode == "release-candidate" and not mode_matches:
        status = "fail" if summary_required else "warn"
        return [
            EvidenceItem(
                evidence_id,
                status,
                summary_required and evidence_id in LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS,
                "Live-network beta summary has wrong mode.",
                source,
                summary_details,
            )
            for evidence_id in LIVE_NETWORK_BETA_EVIDENCE_IDS
        ]

    raw_evidence = sanitized_summary.get("evidence", [])
    if not isinstance(raw_evidence, list):
        status = "fail" if summary_required else "warn"
        return [
            EvidenceItem(
                evidence_id,
                status,
                summary_required and evidence_id in LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS,
                "Live-network beta summary has no evidence list.",
                source,
                summary_details,
            )
            for evidence_id in LIVE_NETWORK_BETA_EVIDENCE_IDS
        ]

    items: list[EvidenceItem] = []
    seen: set[str] = set()
    for value in raw_evidence:
        if not isinstance(value, dict):
            continue
        evidence_id = str(value.get("id", "live-network-beta.unknown"))
        seen.add(evidence_id)
        item_required = bool(value.get("requiredForReleaseCandidate", False))
        if summary_required and evidence_id in LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS:
            item_required = True
        details = value.get("details", {})
        safe_details = details if isinstance(details, dict) else {}
        safe_details = {
            **summary_details,
            **dict(sanitize_value(safe_details, workspace_root, out_dir)),
        }
        items.append(
            EvidenceItem(
                id=evidence_id,
                status=normalize_evidence_status(str(value.get("status", "missing"))),
                required_for_release_candidate=item_required,
                summary=str(
                    sanitize_value(value.get("summary", "No summary provided"), workspace_root, out_dir)
                ),
                source=str(sanitize_value(value.get("source", source), workspace_root, out_dir)),
                details=safe_details,
            )
        )

    missing_status = "missing" if summary_enabled or summary_required else "skip"
    for evidence_id in LIVE_NETWORK_BETA_EVIDENCE_IDS:
        if evidence_id in seen:
            continue
        item_required = summary_required and evidence_id in LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS
        items.append(
            EvidenceItem(
                evidence_id,
                missing_status,
                item_required,
                f"{evidence_id} was not reported by live-network beta smoke.",
                source,
                summary_details,
            )
        )
    return items

def add_network_scale_unexpected_field_error(
    value: dict[str, Any],
    allowed_keys: set[str],
    errors: list[str],
    context: str,
) -> None:
    if any(str(key) not in allowed_keys for key in value):
        errors.append(f"{context} contains unsupported fields")

def network_scale_safe_enum(
    value: Any,
    allowed_values: set[str],
    errors: list[str],
    field_name: str,
) -> str:
    if isinstance(value, str) and value in allowed_values:
        return value
    errors.append(f"{field_name} must be one of the supported values")
    return "invalid"

def network_scale_safe_int(
    value: Any,
    errors: list[str],
    field_name: str,
    *,
    minimum: int = 0,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        errors.append(f"{field_name} must be an integer")
        return 0
    parsed = value
    if parsed < minimum:
        errors.append(f"{field_name} must be at least {minimum}")
    return parsed

def network_scale_safe_bool(
    value: Any,
    errors: list[str],
    field_name: str,
    *,
    expected: bool,
) -> bool | None:
    if value is expected:
        return value
    expected_text = "true" if expected else "false"
    errors.append(f"{field_name} must be {expected_text}")
    return None

def network_scale_safe_release_id(value: Any, errors: list[str]) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        errors.append("releaseId must be a string")
        return ""
    release_id = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", release_id):
        errors.append("releaseId must be a non-empty candidate identifier")
        return ""
    return release_id

def allowlisted_network_scale_app_summary(
    app_id: str,
    value: Any,
    errors: list[str],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{app_id} app summary is missing")
        return {}
    allowed_keys = {*NETWORK_SCALE_SOAK_APP_COUNT_KEYS, "rawContentPersisted"}
    add_network_scale_unexpected_field_error(value, allowed_keys, errors, f"apps.{app_id}")
    summary = {
        key: network_scale_safe_int(value.get(key), errors, f"apps.{app_id}.{key}")
        for key in NETWORK_SCALE_SOAK_APP_COUNT_KEYS
    }
    summary["rawContentPersisted"] = network_scale_safe_bool(
        value.get("rawContentPersisted"),
        errors,
        f"apps.{app_id}.rawContentPersisted",
        expected=False,
    )
    return summary

def allowlisted_network_scale_bool_section(
    summary: dict[str, Any],
    section_name: str,
    required_keys: tuple[str, ...],
    errors: list[str],
) -> dict[str, Any]:
    value = summary.get(section_name, {})
    if not isinstance(value, dict):
        errors.append(f"{section_name} must be an object")
        value = {}
    else:
        add_network_scale_unexpected_field_error(value, set(required_keys), errors, section_name)
    return {
        key: network_scale_safe_bool(
            value.get(key),
            errors,
            f"{section_name}.{key}",
            expected=True,
        )
        for key in required_keys
    }

def allowlisted_network_scale_redaction_section(
    summary: dict[str, Any],
    errors: list[str],
) -> dict[str, Any]:
    value = summary.get("redaction", {})
    if not isinstance(value, dict):
        errors.append("redaction must be an object")
        value = {}
    else:
        add_network_scale_unexpected_field_error(
            value,
            {*NETWORK_SCALE_SOAK_REDACTION_KEYS, "status"},
            errors,
            "redaction",
        )
    safe_redaction = {
        key: network_scale_safe_bool(
            value.get(key),
            errors,
            f"redaction.{key}",
            expected=True,
        )
        for key in NETWORK_SCALE_SOAK_REDACTION_KEYS
    }
    safe_redaction["status"] = network_scale_safe_enum(
        value.get("status"),
        {"pass"},
        errors,
        "redaction.status",
    )
    return safe_redaction

def allowlisted_network_scale_soak_summary(
    summary: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Return a redaction-safe network-scale soak summary and schema errors."""

    errors: list[str] = []
    add_network_scale_unexpected_field_error(
        summary,
        {
            "mode",
            "status",
            "durationHoursSimulated",
            "apps",
            "trustGraph",
            "budgets",
            "redaction",
            "releaseId",
        },
        errors,
        "summary",
    )
    duration = network_scale_safe_int(
        summary.get("durationHoursSimulated"),
        errors,
        "durationHoursSimulated",
        minimum=24,
    )
    apps_value = summary.get("apps", {})
    if not isinstance(apps_value, dict):
        errors.append("apps must be an object")
        apps_value = {}
    else:
        add_network_scale_unexpected_field_error(
            apps_value,
            set(NETWORK_SCALE_SOAK_APP_IDS),
            errors,
            "apps",
        )
    safe_apps = {
        app_id: allowlisted_network_scale_app_summary(app_id, apps_value.get(app_id), errors)
        for app_id in NETWORK_SCALE_SOAK_APP_IDS
    }
    trust_graph_value = summary.get("trustGraph", {})
    if not isinstance(trust_graph_value, dict):
        errors.append("trustGraph must be an object")
        trust_graph_value = {}
    else:
        add_network_scale_unexpected_field_error(
            trust_graph_value,
            {*NETWORK_SCALE_SOAK_TRUST_GRAPH_COUNT_KEYS, "rawStatementsInEvidence"},
            errors,
            "trustGraph",
        )
    safe_trust_graph = {
        key: network_scale_safe_int(trust_graph_value.get(key), errors, f"trustGraph.{key}")
        for key in NETWORK_SCALE_SOAK_TRUST_GRAPH_COUNT_KEYS
    }
    safe_trust_graph["rawStatementsInEvidence"] = network_scale_safe_bool(
        trust_graph_value.get("rawStatementsInEvidence"),
        errors,
        "trustGraph.rawStatementsInEvidence",
        expected=False,
    )
    safe_summary = {
        "mode": network_scale_safe_enum(
            summary.get("mode"),
            {"simulated-rc-soak", "live-rc-soak"},
            errors,
            "mode",
        ),
        "status": network_scale_safe_enum(summary.get("status"), {"success"}, errors, "status"),
        "durationHoursSimulated": duration,
        "apps": safe_apps,
        "trustGraph": safe_trust_graph,
        "budgets": allowlisted_network_scale_bool_section(
            summary,
            "budgets",
            NETWORK_SCALE_SOAK_BUDGET_KEYS,
            errors,
        ),
        "redaction": allowlisted_network_scale_redaction_section(summary, errors),
    }
    release_id = network_scale_safe_release_id(summary.get("releaseId"), errors)
    if release_id:
        safe_summary["releaseId"] = release_id
    return safe_summary, errors

def network_scale_soak_evidence(
    path: Path, workspace_root: Path, out_dir: Path, mode: str
) -> EvidenceItem:
    source = display_path(path, workspace_root, out_dir)
    summary = read_json(path)
    required = mode == "release-candidate"
    if summary is None:
        return EvidenceItem(
            NETWORK_SCALE_SOAK_EVIDENCE_ID,
            "missing" if required else "skip",
            required,
            "Network-scale RC soak summary is missing.",
            source,
            {"requiredInMode": required},
        )
    safe_summary, errors = allowlisted_network_scale_soak_summary(summary)
    details = {
        "mode": safe_summary["mode"],
        "durationHoursSimulated": safe_summary["durationHoursSimulated"],
        "summary": safe_summary,
    }
    if errors:
        return EvidenceItem(
            NETWORK_SCALE_SOAK_EVIDENCE_ID,
            "fail" if required else "warn",
            required,
            "Network-scale RC soak summary failed validation.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        NETWORK_SCALE_SOAK_EVIDENCE_ID,
        "pass",
        required,
        "Network-scale RC soak summary passed redacted budget and pressure checks.",
        source,
        details,
    )

def multi_node_validation_redaction_findings(validation_errors: list[str]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for error in validation_errors:
        match = re.match(r"^redaction leak detected: (?P<kind>[^ ]+) at (?P<location>.+)$", error)
        if not match:
            match = re.match(r"^redaction safety violation: (?P<kind>[^ ]+) at (?P<location>.+)$", error)
        if match:
            findings.append(
                {
                    "kind": match.group("kind"),
                    "location": match.group("location"),
                    "source": "validation",
                }
            )
    return findings

def multi_node_beta_soak_evidence(
    path: Path,
    workspace_root: Path,
    out_dir: Path,
    mode: str,
    required: bool,
) -> list[EvidenceItem]:
    source = display_path(path, workspace_root, out_dir)
    summary = read_json(path)
    required_for_rc = required or mode == "release-candidate"
    if summary is None:
        status = "missing" if required_for_rc else "skip"
        return [
            EvidenceItem(
                evidence_id,
                status,
                required_for_rc,
                "Multi-node beta soak summary is missing.",
                source,
                {"requiredInMode": required_for_rc},
            )
            for evidence_id in MULTI_NODE_BETA_EVIDENCE_IDS
        ]

    validation_errors = multi_node_beta_soak.validate_summary(summary, strict=False)
    required_disabled_scenarios: set[str] = set()
    if required_for_rc:
        for scenario_id, entry in multi_node_beta_soak.scenario_map(summary).items():
            if scenario_id not in MULTI_NODE_BETA_SCENARIO_EVIDENCE_IDS:
                continue
            evidence = entry.get("evidence") if isinstance(entry, dict) else None
            if isinstance(evidence, dict) and evidence.get("configured") is False:
                required_disabled_scenarios.add(scenario_id)
        validation_errors = [
            *validation_errors,
            *[
                f"scenario {scenario_id} is disabled but required in {mode}"
                for scenario_id in sorted(required_disabled_scenarios)
            ],
        ]
    compact = multi_node_beta_soak.compact_for_release(summary)
    compact = dict(sanitize_value(compact, workspace_root, out_dir))
    summary_status = normalize_evidence_status(str(compact.get("status", "missing")))
    scenario_statuses = compact.get("scenarioStatuses", {})
    if not isinstance(scenario_statuses, dict):
        scenario_statuses = {}
    else:
        scenario_statuses = dict(scenario_statuses)
    for scenario_id in required_disabled_scenarios:
        scenario_statuses[scenario_id] = "fail"
    redaction = compact.get("redaction", {})
    if not isinstance(redaction, dict):
        redaction = {}
    redaction_findings = redaction.get("findings", [])
    if not isinstance(redaction_findings, list):
        redaction_findings = []
    redaction_findings = [
        *redaction_findings,
        *multi_node_validation_redaction_findings(validation_errors),
    ]
    promotion_ready = compact.get("promotionReady") is True
    common_details = {
        "requiredInMode": required_for_rc,
        "summaryStatus": summary_status,
        "mode": compact.get("mode", "missing"),
        "durationProfile": compact.get("durationProfile", "missing"),
        "promotionReady": promotion_ready,
        "scenarioStatuses": scenario_statuses,
        "previousCandidateUpgrade": compact.get("previousCandidateUpgrade", {}),
        "blockers": compact.get("blockers", []),
        "warnings": compact.get("warnings", []),
        "validationErrors": validation_errors,
    }
    if required_disabled_scenarios:
        common_details["disabledRequiredScenarios"] = sorted(required_disabled_scenarios)
    if redaction_findings:
        common_details["redactionFindings"] = sanitize_value(redaction_findings, workspace_root, out_dir)

    umbrella_status = summary_status
    if validation_errors or not promotion_ready:
        umbrella_status = "fail" if required_for_rc else ("fail" if summary_status == "fail" else "warn")
    items = [
        EvidenceItem(
            "multi-node-beta.soak",
            umbrella_status,
            required_for_rc,
            (
                "Multi-node beta soak and upgrade drill evidence is promotion-ready."
                if umbrella_status == "pass"
                else "Multi-node beta soak and upgrade drill evidence has warnings or failures."
            ),
            source,
            common_details,
        )
    ]

    scenario_by_evidence_id = {
        evidence_id: scenario_id for scenario_id, evidence_id in MULTI_NODE_BETA_SCENARIO_EVIDENCE_IDS.items()
    }
    for evidence_id in MULTI_NODE_BETA_EVIDENCE_IDS:
        if evidence_id in {"multi-node-beta.soak", "multi-node-beta.redaction"}:
            continue
        scenario_id = scenario_by_evidence_id.get(evidence_id, "")
        scenario_status = normalize_evidence_status(str(scenario_statuses.get(scenario_id, "missing")))
        if scenario_status == "missing" and required_for_rc:
            scenario_summary = f"{scenario_id or evidence_id} was not reported by multi-node beta soak."
        else:
            scenario_summary = f"{scenario_id or evidence_id} status is {scenario_status}."
        items.append(
            EvidenceItem(
                evidence_id,
                scenario_status,
                required_for_rc,
                scenario_summary,
                source,
                {**common_details, "scenarioId": scenario_id, "scenarioStatus": scenario_status},
            )
        )

    redaction_status = normalize_evidence_status(str(redaction.get("status", "missing")))
    if redaction_findings:
        redaction_status = "fail"
    items.append(
        EvidenceItem(
            "multi-node-beta.redaction",
            redaction_status,
            required_for_rc,
            (
                "Multi-node beta soak artifacts passed redaction checks."
                if redaction_status == "pass"
                else "Multi-node beta soak artifacts failed or missed redaction checks."
            ),
            source,
            {
                **common_details,
                "redactionStatus": redaction_status,
                "redactionFindings": sanitize_value(redaction_findings, workspace_root, out_dir),
            },
        )
    )
    return items

def app_platform_docs_evidence(workspace_root: Path, out_dir: Path) -> list[EvidenceItem]:
    source = display_path(
        workspace_root / "tools/release-certification/certify.py",
        workspace_root,
        out_dir,
    )
    try:
        summary = app_platform_docs_check.run_check(workspace_root)
    except Exception as exception:  # noqa: BLE001 - release evidence must degrade to redacted failure.
        return [
            EvidenceItem(
                evidence_id,
                "fail",
                True,
                "App-platform docs check failed to run",
                source,
                {"error": scrub_text(str(exception), workspace_root, out_dir)},
            )
            for evidence_id in app_platform_docs_check.EVIDENCE_IDS
        ]
    evidence = summary.get("evidence", [])
    if not isinstance(evidence, list):
        return [
            EvidenceItem(
                evidence_id,
                "fail",
                True,
                "App-platform docs check produced no evidence list",
                source,
                {"summaryStatus": sanitize_value(summary.get("status"), workspace_root, out_dir)},
            )
            for evidence_id in app_platform_docs_check.EVIDENCE_IDS
        ]
    items: list[EvidenceItem] = []
    seen: set[str] = set()
    for value in evidence:
        if not isinstance(value, dict):
            continue
        evidence_id = str(value.get("id", "app-platform.docs-unknown"))
        seen.add(evidence_id)
        items.append(
            EvidenceItem(
                id=evidence_id,
                status=normalize_evidence_status(str(value.get("status", "missing"))),
                required_for_release_candidate=bool(value.get("requiredForReleaseCandidate", True)),
                summary=str(
                    sanitize_value(value.get("summary", "No summary provided"), workspace_root, out_dir)
                ),
                source=str(sanitize_value(value.get("source", source), workspace_root, out_dir)),
                details=dict(
                    sanitize_value(value.get("details", {}), workspace_root, out_dir)
                    if isinstance(value.get("details", {}), dict)
                    else {}
                ),
            )
        )
    for evidence_id in app_platform_docs_check.EVIDENCE_IDS:
        if evidence_id not in seen:
            items.append(
                EvidenceItem(
                    evidence_id,
                    "missing",
                    True,
                    f"{evidence_id} was not reported by app-platform docs check",
                    source,
                    {},
                )
            )
    return items

def production_beta_go_no_go_evidence(workspace_root: Path, out_dir: Path) -> list[EvidenceItem]:
    global PRODUCTION_BETA_GO_NO_GO_SELF_TEST_RESULT
    generator_path = Path(
        getattr(
            production_beta_go_no_go_dashboard,
            "__engine_loader__",
            production_beta_go_no_go_dashboard.__file__,
        )
    ).resolve()
    fixture_dir = Path(production_beta_go_no_go_dashboard.FIXTURE_DIR).resolve()
    source = display_path(generator_path, workspace_root, out_dir)
    fixture_names = (
        "go-no-go-pass.json",
        "go-no-go-no-go.json",
        "go-no-go-with-waivers.json",
        "go-no-go-expired-waiver.json",
        "go-no-go-critical-redaction.json",
        "go-no-go-test-signing-production.json",
    )
    fixture_paths = [fixture_dir / fixture_name for fixture_name in fixture_names]
    generator_exists = generator_path.is_file()
    fixtures_present = all(path.is_file() for path in fixture_paths)
    self_test_passed = False
    error = ""
    if generator_exists and fixtures_present:
        if PRODUCTION_BETA_GO_NO_GO_SELF_TEST_RESULT is None:
            try:
                production_beta_go_no_go_dashboard.run_self_test(quiet=True)
                PRODUCTION_BETA_GO_NO_GO_SELF_TEST_RESULT = (True, "")
            except SystemExit as exception:
                code = exception.code if exception.code is not None else "unknown"
                PRODUCTION_BETA_GO_NO_GO_SELF_TEST_RESULT = (
                    False,
                    f"dashboard self-test exited with {code}",
                )
            except Exception as exception:  # noqa: BLE001 - release evidence must degrade to redacted failure.
                PRODUCTION_BETA_GO_NO_GO_SELF_TEST_RESULT = (False, str(exception))
        self_test_passed, raw_error = PRODUCTION_BETA_GO_NO_GO_SELF_TEST_RESULT
        error = scrub_text(raw_error, workspace_root, out_dir) if raw_error else ""
    checks = {
        "generatorExists": generator_exists,
        "fixturesPresent": fixtures_present,
        "selfTestPasses": self_test_passed,
        "jsonMarkdownArtifactsCovered": self_test_passed,
        "waiverValidationCovered": self_test_passed,
        "redactionScanningCovered": self_test_passed,
        "noGoCriticalFailuresCovered": self_test_passed,
        "goWithWaiversCovered": self_test_passed,
        "goCovered": self_test_passed,
    }
    status = "pass" if all(checks.values()) else "fail"
    details: dict[str, Any] = {
        "checks": checks,
        "fixtureCount": len(fixture_names),
        "outputFiles": [
            production_beta_go_no_go_dashboard.OUTPUT_JSON,
            production_beta_go_no_go_dashboard.OUTPUT_MARKDOWN,
            production_beta_go_no_go_dashboard.OUTPUT_REDACTION,
        ],
        "decisions": list(production_beta_go_no_go_dashboard.DECISIONS),
    }
    if error:
        details["error"] = error

    summaries = {
        "production-beta.go-no-go-dashboard": "Go/no-go dashboard generator and fixture self-test passed.",
        "production-beta.go-no-go-decision": "Go, no-go, and go-with-waivers decision fixtures passed.",
        "production-beta.waiver-validation": "Waiver validation fixtures passed.",
        "production-beta.dashboard-redaction": "Dashboard redaction negative fixture passed.",
        "production-beta.launch-artifact-hygiene": "Launch artifact hygiene fixture coverage passed.",
    }
    return [
        EvidenceItem(
            evidence_id,
            status,
            True,
            summaries[evidence_id] if status == "pass" else "Go/no-go dashboard self-test failed.",
            source,
            details,
        )
        for evidence_id in PRODUCTION_BETA_GO_NO_GO_EVIDENCE_IDS
    ]

def parse_stable_readiness_count(value: Any) -> tuple[int, bool]:
    if value is None or value == "":
        return 0, False
    if isinstance(value, bool):
        return 0, True
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text or not text.isdigit():
            return 0, True
        parsed = int(text)
    else:
        return 0, True
    if parsed < 0:
        return 0, True
    return parsed, False

def stable_readiness_record_errors(
    summary: dict[str, Any],
    field_name: str,
    count_field_name: str,
    parsed_count: int,
    malformed_count: bool,
) -> tuple[int, list[str]]:
    value = summary.get(field_name)
    if not isinstance(value, list):
        return 0, [f"{field_name} must be a list"]
    errors: list[str] = []
    record_count = len(value)
    if record_count:
        errors.append(f"{field_name} contains {record_count} record(s)")
    if not malformed_count and parsed_count != record_count:
        errors.append(f"{count_field_name} is {parsed_count} but {field_name} contains {record_count}")
    return record_count, errors

def stable_readiness_warning_record_errors(
    summary: dict[str, Any],
    parsed_count: int,
    malformed_count: bool,
) -> tuple[int, int, list[str]]:
    warnings = summary.get("warnings")
    if not isinstance(warnings, list):
        return 0, 0, ["warnings must be a list"]
    errors = [
        f"warnings[{index}] must be an object"
        for index, warning in enumerate(warnings)
        if not isinstance(warning, dict)
    ]
    warning_record_count = len(warnings)
    domain_warning_record_count = 0
    domains = summary.get("domains")
    if isinstance(domains, list):
        domain_warning_record_count = sum(
            len(domain.get("warnings", []))
            for domain in domains
            if isinstance(domain, dict) and isinstance(domain.get("warnings", []), list)
        )
        errors.extend(
            f"domains[{domain_index}].warnings[{warning_index}] must be an object"
            for domain_index, domain in enumerate(domains)
            if isinstance(domain, dict) and isinstance(domain.get("warnings", []), list)
            for warning_index, warning in enumerate(domain.get("warnings", []))
            if not isinstance(warning, dict)
        )
    if not malformed_count and parsed_count != warning_record_count:
        errors.append(
            f"warningCount is {parsed_count} but warnings contains {warning_record_count} record(s)"
        )
    if not malformed_count and parsed_count != domain_warning_record_count:
        errors.append(
            "warningCount is "
            f"{parsed_count} but domains contain {domain_warning_record_count} warning record(s)"
        )
    return warning_record_count, domain_warning_record_count, errors

def stable_readiness_allowed_limitation_metadata_errors(record: Any, label: str) -> list[str]:
    if not isinstance(record, dict):
        return [f"{label} must be an object"]
    errors: list[str] = []
    for field in ("id", "title", "category", "classification", "status", "summary", "boundedBy"):
        if not isinstance(record.get(field), str) or not str(record.get(field)).strip():
            errors.append(f"{label}.{field} must be a non-empty string")
    classification = str(record.get("classification", "")).strip().lower()
    if classification and classification != "allowed-for-stable-1.0":
        errors.append(f"{label}.classification must be allowed-for-stable-1.0")
    evidence_ids = record.get("evidenceIds")
    if not isinstance(evidence_ids, list) or not evidence_ids:
        errors.append(f"{label}.evidenceIds must be a non-empty list")
    elif any(not isinstance(item, str) or not item.strip() for item in evidence_ids):
        errors.append(f"{label}.evidenceIds must contain only non-empty strings")
    return errors

def stable_readiness_allowed_record_errors(
    summary: dict[str, Any],
    parsed_count: int,
    malformed_count: bool,
) -> tuple[int, list[str]]:
    value = summary.get("allowedLimitations")
    if not isinstance(value, list):
        return 0, ["allowedLimitations must be a list"]
    record_count = len(value)
    errors: list[str] = []
    for index, limitation in enumerate(value):
        errors.extend(
            stable_readiness_allowed_limitation_metadata_errors(
                limitation,
                f"allowedLimitations[{index}]",
            )
        )
    if not malformed_count and parsed_count != record_count:
        errors.append(
            f"allowedLimitationCount is {parsed_count} but allowedLimitations contains {record_count}"
        )
    return record_count, errors

def stable_readiness_domain_errors(summary: dict[str, Any]) -> list[str]:
    domains = summary.get("domains")
    if not isinstance(domains, list):
        return ["domains must be a non-empty list"]
    if not domains:
        return ["domains must not be empty"]
    errors = production_beta_go_no_go_dashboard.stable_summary_domain_id_errors(summary)
    for index, domain in enumerate(domains):
        if not isinstance(domain, dict):
            errors.append(f"domains[{index}] must be an object")
            continue
        domain_id = str(domain.get("id") or f"domains[{index}]")
        status = normalize_evidence_status(str(domain.get("status", "missing")))
        if status in {"fail", "missing", "skip"}:
            errors.append(f"domain {domain_id} status is {status}")
        blockers = domain.get("blockers")
        if blockers is not None and not isinstance(blockers, list):
            errors.append(f"domain {domain_id} blockers must be a list")
        elif isinstance(blockers, list) and blockers:
            errors.append(f"domain {domain_id} contains {len(blockers)} blocker(s)")
        for field_name in ("warnings", "allowedLimitations"):
            if field_name in domain and not isinstance(domain.get(field_name), list):
                errors.append(f"domain {domain_id} {field_name} must be a list")
        warnings = domain.get("warnings")
        allowed_limitations = domain.get("allowedLimitations")
        if (
            status == "warn"
            and not (isinstance(warnings, list) and warnings)
            and not (isinstance(allowed_limitations, list) and allowed_limitations)
        ):
            errors.append(
                f"domain {domain_id} status is warn but contains no warnings or allowed limitations"
            )
        if isinstance(allowed_limitations, list):
            for allowed_index, limitation in enumerate(allowed_limitations):
                errors.extend(
                    stable_readiness_allowed_limitation_metadata_errors(
                        limitation,
                        f"domain {domain_id} allowedLimitations[{allowed_index}]",
                    )
                )
    errors.extend(
        production_beta_go_no_go_dashboard.stable_summary_domain_allowed_limitation_consistency_errors(
            summary
        )
    )
    return errors

def stable_readiness_evidence_rows(summary: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    rows = {evidence_id: [] for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS}
    evidence = summary.get("evidence")
    if not isinstance(evidence, list):
        return rows
    for entry in evidence:
        if not isinstance(entry, dict):
            continue
        evidence_id = str(entry.get("id", ""))
        if evidence_id in rows:
            rows[evidence_id].append(entry)
    return rows

def stable_readiness_evidence_redaction_ids(summary: dict[str, Any]) -> list[str]:
    evidence = summary.get("evidence")
    if not isinstance(evidence, list):
        return []
    return [
        str(entry.get("id") or entry.get("evidenceId") or f"evidence[{index}]")
        for index, entry in enumerate(evidence, start=1)
        if isinstance(entry, dict) and evidence_entry_has_unwaivable_redaction_findings(entry)
    ]

def stable_readiness_row_status(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "missing"
    if len(rows) > 1:
        return "fail"
    if any(evidence_entry_has_unwaivable_redaction_findings(row) for row in rows):
        return "fail"
    statuses = [normalize_evidence_status(str(row.get("status", "missing"))) for row in rows]
    if any(status == "fail" for status in statuses):
        return "fail"
    if any(status == "missing" for status in statuses):
        return "missing"
    if any(status == "skip" for status in statuses):
        return "skip"
    if any(status == "warn" for status in statuses):
        return "warn"
    return "pass"

def stable_readiness_release_id_from_mapping(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    for key in ("releaseId", "release_id", "candidateReleaseId", "candidate_release_id"):
        release_id = value.get(key)
        if isinstance(release_id, str) and release_id.strip() and release_id != "missing":
            return release_id.strip()
    return ""

def stable_readiness_expected_release_id(
    settings: Settings,
    _evidence: list[EvidenceItem],
) -> str:
    return stable_readiness_release_id_from_mapping(settings.metadata)

def stable_readiness_evidence(
    summary_path: Path | None,
    required: bool,
    workspace_root: Path,
    out_dir: Path,
    expected_release_id: str | None = None,
) -> list[EvidenceItem]:
    if summary_path is None:
        if not required:
            return []
        return [
            EvidenceItem(
                evidence_id,
                "missing",
                False,
                "Stable 1.0 readiness is required but no summary path was provided.",
                "stable-readiness-summary",
                {"required": True},
            )
            for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
        ]

    source = display_path(summary_path, workspace_root, out_dir)
    summary = read_json(summary_path)
    if not isinstance(summary, dict):
        return [
            EvidenceItem(
                "stable-1.0.readiness-gate",
                "fail",
                False,
                "Stable 1.0 readiness summary is missing or malformed.",
                source,
                {"required": required},
            )
        ]

    summary_kind = str(summary.get("kind", ""))
    summary_tool_value = summary.get("tool")
    summary_tool = summary_tool_value if isinstance(summary_tool_value, str) else ""
    release_id_requirement_active = expected_release_id is not None
    expected_release_id = (expected_release_id or "").strip()
    summary_release_id_value = summary.get("releaseId")
    summary_release_id = (
        summary_release_id_value.strip()
        if isinstance(summary_release_id_value, str)
        else ""
    )
    summary_schema_version = summary.get("schemaVersion")
    summary_schema_version_valid = (
        isinstance(summary_schema_version, int)
        and not isinstance(summary_schema_version, bool)
        and summary_schema_version == 1
    )
    summary_validation_errors: list[str] = []
    if not summary_schema_version_valid:
        summary_validation_errors.append(
            "schemaVersion is not integer 1"
            if summary_schema_version is not None
            else "schemaVersion is missing"
        )
    if required and summary_tool != "stable-1.0-readiness":
        summary_validation_errors.append(
            "tool must be stable-1.0-readiness"
            if summary_tool
            else "tool is missing; expected stable-1.0-readiness"
        )
    if required and release_id_requirement_active and not expected_release_id:
        summary_validation_errors.append(
            "candidate releaseId metadata is required when Stable readiness is required"
        )
    elif expected_release_id:
        if not summary_release_id:
            summary_validation_errors.append(
                f"releaseId is missing; expected {expected_release_id}"
            )
        elif summary_release_id != expected_release_id:
            summary_validation_errors.append(
                f"releaseId must match candidate {expected_release_id}; "
                f"summary releaseId is {summary_release_id}"
            )
    redaction = summary.get("redaction") if isinstance(summary.get("redaction"), dict) else {}
    redaction_status = normalize_evidence_status(str(redaction.get("status", "missing")))
    redaction_findings_value = redaction.get("findings")
    redaction_findings_malformed = (
        "findings" in redaction and not isinstance(redaction_findings_value, list)
    )
    redaction_findings = redaction_findings_value if isinstance(redaction_findings_value, list) else []
    redaction_finding_count, malformed_redaction_finding_count = parse_stable_readiness_count(
        redaction.get("findingCount", len(redaction_findings))
    )
    (
        redaction_critical_finding_count,
        malformed_redaction_critical_finding_count,
    ) = parse_stable_readiness_count(redaction.get("criticalFindingCount", 0))
    redaction_validation_errors: list[str] = []
    if redaction_findings_malformed:
        redaction_validation_errors.append("findings is not a list")
    if malformed_redaction_finding_count:
        redaction_validation_errors.append("findingCount is not a non-negative integer")
    elif redaction_finding_count > 0:
        redaction_validation_errors.append(f"findingCount is {redaction_finding_count}")
    if malformed_redaction_critical_finding_count:
        redaction_validation_errors.append("criticalFindingCount is not a non-negative integer")
    elif redaction_critical_finding_count > 0:
        redaction_validation_errors.append(
            f"criticalFindingCount is {redaction_critical_finding_count}"
        )
    redaction_payload_unsafe = redaction_signal_has_unwaivable_findings(redaction)
    if redaction_payload_unsafe and not (
        redaction_status != "pass"
        or redaction_findings
        or redaction_validation_errors
    ):
        redaction_validation_errors.append(
            "redaction payload contains unsafe raw or unwaivable findings"
        )
    decision = str(summary.get("decision", "not-ready"))
    valid_decisions = {"ready", "ready-with-allowed-limitations", "not-ready"}
    decision_validation_errors: list[str] = []
    if decision not in valid_decisions:
        decision_validation_errors.append(
            "decision must be ready, ready-with-allowed-limitations, or not-ready"
        )
    stable_ready = summary.get("stableReady") is True
    main_status = normalize_evidence_status(str(summary.get("status", "missing")))
    blocker_count, malformed_blocker_count = parse_stable_readiness_count(summary.get("blockerCount", 0))
    warning_count, malformed_warning_count = parse_stable_readiness_count(summary.get("warningCount", 0))
    allowed_count, malformed_allowed_count = parse_stable_readiness_count(
        summary.get("allowedLimitationCount", 0)
    )
    disallowed_count, malformed_disallowed_count = parse_stable_readiness_count(
        summary.get("disallowedLimitationCount", 0)
    )
    blocker_record_count, blocker_record_errors = stable_readiness_record_errors(
        summary,
        "blockers",
        "blockerCount",
        blocker_count,
        malformed_blocker_count,
    )
    (
        warning_record_count,
        domain_warning_record_count,
        warning_record_errors,
    ) = stable_readiness_warning_record_errors(
        summary,
        warning_count,
        malformed_warning_count,
    )
    disallowed_record_count, disallowed_record_errors = stable_readiness_record_errors(
        summary,
        "disallowedLimitations",
        "disallowedLimitationCount",
        disallowed_count,
        malformed_disallowed_count,
    )
    allowed_record_count, allowed_record_errors = stable_readiness_allowed_record_errors(
        summary,
        allowed_count,
        malformed_allowed_count,
    )
    count_validation_errors: list[str] = []
    if malformed_blocker_count:
        count_validation_errors.append("blockerCount is not a non-negative integer")
    elif blocker_count > 0:
        count_validation_errors.append(f"blockerCount is {blocker_count}")
    if malformed_disallowed_count:
        count_validation_errors.append("disallowedLimitationCount is not a non-negative integer")
    elif disallowed_count > 0:
        count_validation_errors.append(f"disallowedLimitationCount is {disallowed_count}")
    count_validation_errors.extend(blocker_record_errors)
    count_validation_errors.extend(disallowed_record_errors)
    warning_validation_errors: list[str] = []
    if malformed_warning_count:
        warning_validation_errors.append("warningCount is not a non-negative integer")
    warning_validation_errors.extend(warning_record_errors)
    warning_remaining_count = max(
        warning_count if not malformed_warning_count else 0,
        warning_record_count,
        domain_warning_record_count,
    )
    allowed_validation_errors: list[str] = []
    if malformed_allowed_count:
        allowed_validation_errors.append("allowedLimitationCount is not a non-negative integer")
    allowed_validation_errors.extend(allowed_record_errors)
    allowed_remaining_count = max(allowed_count if not malformed_allowed_count else 0, allowed_record_count)
    status_validation_errors: list[str] = []
    if main_status == "warn" and warning_remaining_count == 0 and allowed_remaining_count == 0:
        status_validation_errors.append(
            "status is warn but no warnings or allowed limitations are reported"
        )
    domain_validation_errors = stable_readiness_domain_errors(summary)
    evidence_rows = stable_readiness_evidence_rows(summary)
    missing_evidence_ids = [
        evidence_id
        for evidence_id, rows in evidence_rows.items()
        if not rows
    ]
    duplicate_evidence_ids = [
        evidence_id
        for evidence_id, rows in evidence_rows.items()
        if len(rows) > 1
    ]
    evidence_validation_errors: list[str] = []
    if missing_evidence_ids:
        evidence_validation_errors.append(
            "evidence is missing required IDs: " + ", ".join(missing_evidence_ids)
        )
    if duplicate_evidence_ids:
        evidence_validation_errors.append(
            "evidence contains duplicate required IDs: " + ", ".join(duplicate_evidence_ids)
        )
    evidence_redaction_ids = stable_readiness_evidence_redaction_ids(summary)
    if evidence_redaction_ids:
        redaction_validation_errors.append(
            "evidence rows contain redaction findings: " + ", ".join(evidence_redaction_ids)
        )
    if (
        summary_kind != "stable-1.0-readiness"
        or summary_validation_errors
        or redaction_status != "pass"
        or redaction_findings
        or redaction_validation_errors
        or decision_validation_errors
        or count_validation_errors
        or warning_validation_errors
        or allowed_validation_errors
        or status_validation_errors
        or domain_validation_errors
        or evidence_validation_errors
    ):
        main_status = "fail"
    elif (
        decision == "ready-with-allowed-limitations"
        or allowed_remaining_count > 0
    ) and main_status == "pass":
        main_status = "warn"
    elif warning_remaining_count > 0 and main_status == "pass":
        main_status = "warn"
    elif not stable_ready or decision == "not-ready":
        main_status = "fail"

    redaction_finding_count_value = (
        redaction_finding_count
        if not malformed_redaction_finding_count
        else redaction.get("findingCount", len(redaction_findings))
    )
    redaction_critical_finding_count_value = (
        redaction_critical_finding_count
        if not malformed_redaction_critical_finding_count
        else redaction.get("criticalFindingCount", 0)
    )
    redaction_signal_details = dict(redaction)
    redaction_signal_details["reportedStatus"] = redaction_status
    redaction_signal_details["status"] = (
        "fail"
        if redaction_status != "pass" or redaction_findings or redaction_validation_errors
        else "pass"
    )
    redaction_signal_details["findingCount"] = redaction_finding_count_value
    redaction_signal_details["criticalFindingCount"] = redaction_critical_finding_count_value
    if redaction_findings:
        redaction_signal_details["findings"] = redaction_findings
    redaction_details: dict[str, Any] = {
        "status": redaction_status,
        "findingCount": redaction_finding_count_value,
        "criticalFindingCount": redaction_critical_finding_count_value,
        "redaction": redaction_signal_details,
    }
    if redaction_validation_errors:
        redaction_details["validationErrors"] = redaction_validation_errors
    if redaction_findings:
        redaction_details["redactionFindings"] = redaction_findings
    main_summary = f"Stable 1.0 readiness decision is {decision}."
    main_validation_errors = [
        *summary_validation_errors,
        *decision_validation_errors,
        *count_validation_errors,
        *warning_validation_errors,
        *allowed_validation_errors,
        *status_validation_errors,
        *domain_validation_errors,
        *evidence_validation_errors,
    ]
    if summary_validation_errors:
        main_summary = "Stable 1.0 readiness summary schema is malformed."
    elif status_validation_errors:
        main_summary = "Stable 1.0 readiness summary status is inconsistent."
    elif count_validation_errors:
        main_summary = "Stable 1.0 readiness summary reports remaining blockers or forbidden limitations."
    elif warning_validation_errors:
        main_summary = "Stable 1.0 readiness summary warning metadata is malformed."
    elif allowed_validation_errors:
        main_summary = "Stable 1.0 readiness summary allowed limitations are malformed."
    elif domain_validation_errors:
        main_summary = "Stable 1.0 readiness summary domains are not passing."
    elif evidence_validation_errors:
        main_summary = "Stable 1.0 readiness summary evidence rows are malformed."
    elif allowed_remaining_count > 0:
        main_summary = "Stable 1.0 readiness has bounded allowed limitations."
    synthetic_entries: dict[str, dict[str, Any]] = {
        "stable-1.0.readiness-gate": {
            "id": "stable-1.0.readiness-gate",
            "status": main_status,
            "summary": main_summary,
            "details": {
                "required": required,
                "summaryKind": summary_kind,
                "summaryTool": summary_tool or "missing",
                "schemaVersion": summary_schema_version if summary_schema_version is not None else "missing",
                "releaseId": summary_release_id or "missing",
                "expectedReleaseId": expected_release_id or "not-available",
                "decision": decision,
                "stableReady": stable_ready,
                "blockerCount": blocker_count
                if not malformed_blocker_count
                else summary.get("blockerCount", 0),
                "warningCount": warning_count
                if not malformed_warning_count
                else summary.get("warningCount", 0),
                "warningRecordCount": warning_record_count,
                "domainWarningRecordCount": domain_warning_record_count,
                "allowedLimitationCount": allowed_count
                if not malformed_allowed_count
                else summary.get("allowedLimitationCount", 0),
                "disallowedLimitationCount": disallowed_count
                if not malformed_disallowed_count
                else summary.get("disallowedLimitationCount", 0),
                "blockerRecordCount": blocker_record_count,
                "allowedLimitationRecordCount": allowed_record_count,
                "allowedLimitationOpenCount": allowed_remaining_count,
                "disallowedLimitationRecordCount": disallowed_record_count,
                "domainValidationErrorCount": len(domain_validation_errors),
                "validationErrors": main_validation_errors,
                "summaryPath": source,
                "artifactRefs": summary.get("artifactRefs", {})
                if isinstance(summary.get("artifactRefs"), dict)
                else {},
            },
        },
        "stable-1.0.redaction": {
            "id": "stable-1.0.redaction",
            "status": "fail"
            if redaction_status != "pass" or redaction_findings or redaction_validation_errors
            else "pass",
            "summary": (
                "Stable 1.0 readiness redaction checks passed."
                if redaction_status == "pass"
                and not redaction_findings
                and not redaction_validation_errors
                else "Stable 1.0 readiness redaction checks failed."
            ),
            "details": redaction_details,
        },
    }
    items: list[EvidenceItem] = []
    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS:
        rows = evidence_rows.get(evidence_id, [])
        if not rows:
            if evidence_id not in synthetic_entries or (
                evidence_id == "stable-1.0.redaction"
                and redaction_status == "pass"
                and not redaction_findings
                and not redaction_validation_errors
            ):
                items.append(
                    EvidenceItem(
                        evidence_id,
                        "missing",
                        False,
                        f"{evidence_id} was not reported by the Stable 1.0 readiness summary.",
                        source,
                        {
                            "required": required,
                            "validationErrors": [
                                f"{evidence_id} is missing from stable readiness evidence"
                            ],
                        },
                    )
                )
                continue
        synthetic_entry = synthetic_entries.get(evidence_id)
        entry = synthetic_entry or rows[0]
        if not isinstance(entry, dict):
            items.append(
                EvidenceItem(
                    evidence_id,
                    "missing",
                    False,
                    f"{evidence_id} was not reported by the Stable 1.0 readiness summary.",
                    source,
                    {"required": required},
                )
            )
            continue
        details = entry.get("details", {}) if isinstance(entry.get("details"), dict) else {}
        if not rows:
            details = dict(details)
            validation_errors = (
                details.get("validationErrors")
                if isinstance(details.get("validationErrors"), list)
                else []
            )
            details["validationErrors"] = [
                *validation_errors,
                f"{evidence_id} is missing from stable readiness evidence",
            ]
        status = normalize_evidence_status(str(entry.get("status", "missing")))
        row_status = stable_readiness_row_status(rows) if rows else "missing"
        if synthetic_entry is None:
            status = stable_readiness_row_status(rows)
            if len(rows) > 1:
                details = dict(details)
                details["duplicateStableReadinessEvidenceRows"] = len(rows)
                details["validationErrors"] = [
                    f"{evidence_id} appears {len(rows)} times in stable readiness evidence"
                ]
        elif rows and row_status != "pass":
            if status_severity(row_status) >= status_severity(status):
                status = row_status
            details = dict(details)
            validation_errors = (
                details.get("validationErrors")
                if isinstance(details.get("validationErrors"), list)
                else []
            )
            row_validation_errors = [
                f"{evidence_id} reported evidence row status is {row_status}"
            ]
            if len(rows) > 1:
                details["duplicateStableReadinessEvidenceRows"] = len(rows)
                row_validation_errors.append(
                    f"{evidence_id} appears {len(rows)} times in stable readiness evidence"
                )
            details["reportedStableReadinessEvidenceStatus"] = row_status
            details["validationErrors"] = [*validation_errors, *row_validation_errors]
        elif evidence_entry_has_unwaivable_redaction_findings(entry):
            status = "fail"
        elif evidence_id == "stable-1.0.redaction" and (
            redaction_status != "pass" or redaction_findings or redaction_validation_errors
        ):
            status = "fail"
        items.append(
            EvidenceItem(
                evidence_id,
                status,
                False,
                str(entry.get("summary", f"{evidence_id} status is {status}.")),
                source,
                dict(details),
            )
        )
    return items

def command_output(args: list[str], cwd: Path) -> str:
    try:
        completed = subprocess.run(
            args,
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()

def collect_git_metadata(settings: Settings) -> dict[str, str]:
    if settings.skip_git_metadata:
        return {}
    metadata: dict[str, str] = {}
    sha = command_output(["git", "rev-parse", "HEAD"], settings.workspace_root)
    branch = command_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], settings.workspace_root)
    dirty = command_output(["git", "status", "--short"], settings.workspace_root)
    if sha:
        metadata["gitCommit"] = sha
    if branch:
        metadata["gitBranch"] = branch
    if dirty:
        metadata["gitDirty"] = "true"
    elif sha or branch:
        metadata["gitDirty"] = "false"
    return metadata

def collect_ci_metadata(env: dict[str, str]) -> dict[str, str]:
    mappings = {
        "GITHUB_ACTIONS": "githubActions",
        "GITHUB_WORKFLOW": "githubWorkflow",
        "GITHUB_RUN_ID": "githubRunId",
        "GITHUB_RUN_ATTEMPT": "githubRunAttempt",
        "GITHUB_REF": "githubRef",
        "GITHUB_SHA": "githubSha",
        "RUNNER_OS": "runnerOs",
    }
    metadata: dict[str, str] = {}
    for env_name, key in mappings.items():
        value = env.get(env_name)
        if value:
            metadata[key] = value
    return metadata

def evidence_item_has_active_rc_waiver(
    item: EvidenceItem, waiver_context: WaiverContext, mode: str
) -> bool:
    if item.id in NONWAIVABLE_EVIDENCE_IDS:
        return False
    if item.details.get("waived"):
        return True
    if evidence_item_has_unwaivable_redaction_findings(item):
        return False
    return (
        active_waiver_for_ecosystem_rc_evidence(waiver_context, item.id, mode) is not None
    )

def determine_overall_status(
    mode: str, evidence: list[EvidenceItem], waiver_context: WaiverContext
) -> tuple[str, bool]:
    required_bad = [
        item
        for item in evidence
        if item.required_for_release_candidate and item.status in {"fail", "missing", "skip"}
        and not evidence_item_has_active_rc_waiver(item, waiver_context, mode)
    ]
    required_warn = [
        item
        for item in evidence
        if item.required_for_release_candidate and item.status == "warn" and not item.details.get("waived")
    ]
    any_warnish = any(
        item.status in {"warn", "missing", "fail"} or (item.required_for_release_candidate and item.status == "skip")
        for item in evidence
    )
    if mode == "release-candidate":
        if required_bad:
            return "fail", False
        if required_warn or any_warnish:
            return "warn", True
        return "pass", True
    if mode == "nightly":
        required_fail = [
            item
            for item in evidence
            if item.required_for_release_candidate and item.status == "fail"
            and not evidence_item_has_active_rc_waiver(item, waiver_context, mode)
        ]
        if required_fail:
            return "fail", False
        if required_bad:
            return "warn", False
        if required_warn or any_warnish:
            return "warn", True
        return "pass", True
    if any_warnish:
        return "warn", not required_bad
    return "pass", True

def evidence_counts(evidence: list[EvidenceItem]) -> dict[str, int]:
    counts = {status: 0 for status in CERT_STATUSES}
    for item in evidence:
        counts[item.status] = counts.get(item.status, 0) + 1
    return counts

STATUS_SEVERITY = {"pass": 0, "warn": 1, "skip": 2, "missing": 2, "fail": 3}

EXPECTED_FIRST_PARTY_APPS = (
    "queue-manager",
    "publisher",
    "site-publisher",
    "profile-publisher",
    "feed-reader",
    "social-inbox",
    "trust-graph",
)

FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID = "first-party-app.beta-quality-pass"

EXPECTED_VAULT_CAPABILITIES = (
    "vault.secrets.read",
    "vault.secrets.write",
    "vault.identities.read",
    "vault.identities.create",
    "vault.identities.use",
    "vault.identities.manage",
)

def evidence_map_from_items(evidence: list[EvidenceItem]) -> dict[str, dict[str, Any]]:
    return {item.id: item.to_json() for item in evidence}

def evidence_map_from_summary(summary: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(summary, dict):
        return {}
    evidence = summary.get("evidence", [])
    if not isinstance(evidence, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for entry in evidence:
        if isinstance(entry, dict) and entry.get("id"):
            result[str(entry["id"])] = entry
    return result

def evidence_status(entry: dict[str, Any] | None) -> str:
    if not isinstance(entry, dict):
        return "missing"
    return normalize_evidence_status(str(entry.get("status", "missing")))

def evidence_required(entry: dict[str, Any] | None) -> bool:
    return isinstance(entry, dict) and bool(entry.get("requiredForReleaseCandidate", False))

def evidence_details(entry: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    details = entry.get("details", {})
    return details if isinstance(details, dict) else {}

def status_severity(status: str) -> int:
    return STATUS_SEVERITY.get(normalize_evidence_status(status), 2)

def sorted_strings(value: Any) -> list[str]:
    if isinstance(value, list):
        return sorted(dict.fromkeys(str(item) for item in value))
    if isinstance(value, tuple):
        return sorted(dict.fromkeys(str(item) for item in value))
    return []

def app_ids_from_details(details: dict[str, Any], key: str = "apps") -> set[str]:
    value = details.get(key)
    if isinstance(value, dict):
        return {str(app_id) for app_id in value.keys()}
    return set(sorted_strings(value))

def nested_dict(value: dict[str, Any], key: str) -> dict[str, Any]:
    child = value.get(key, {})
    return child if isinstance(child, dict) else {}

def int_value(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None

def detail_int(details: dict[str, Any], key: str) -> int | None:
    return int_value(details.get(key))

def stable_descriptor_count(details: dict[str, Any]) -> int | None:
    explicit = detail_int(details, "stableDescriptorCount")
    if explicit is not None:
        return explicit
    stability_counts = nested_dict(details, "stabilityCounts")
    return int_value(stability_counts.get("stable"))

def total_ui_warnings(details: dict[str, Any]) -> int | None:
    apps = details.get("apps")
    if not isinstance(apps, dict):
        return None
    total = 0
    found = False
    for app in apps.values():
        if not isinstance(app, dict):
            continue
        summary = app.get("summary")
        if not isinstance(summary, dict):
            summary = app.get("report", {}).get("summary") if isinstance(app.get("report"), dict) else {}
        warning_count = int_value(summary.get("warnings") if isinstance(summary, dict) else None)
        if warning_count is not None:
            total += warning_count
            found = True
    return total if found else None

def all_boolean_checks_pass(details: dict[str, Any]) -> bool | None:
    checks = details.get("checks")
    if not isinstance(checks, dict):
        return None
    boolean_values = [value for value in checks.values() if isinstance(value, bool)]
    if not boolean_values:
        return None
    return all(boolean_values)

def set_from_detail(details: dict[str, Any], *keys: str) -> set[str]:
    for key in keys:
        value = details.get(key)
        if isinstance(value, list):
            return {str(item) for item in value}
        if isinstance(value, dict):
            return {str(item) for item in value.keys()}
    return set()

def reported_set_from_detail(details: dict[str, Any], key: str) -> tuple[bool, set[str]]:
    value = details.get(key)
    if isinstance(value, list):
        return True, {str(item) for item in value}
    if isinstance(value, dict):
        return True, {str(item) for item in value.keys()}
    return False, set()

def stable_named_set(details: dict[str, Any], list_key: str, fallback_key: str) -> set[str]:
    direct = set_from_detail(details, list_key)
    if direct:
        return direct
    values = details.get(fallback_key)
    result: set[str] = set()
    if isinstance(values, list):
        for value in values:
            if isinstance(value, dict):
                stability = str(value.get("stability", value.get("lifecycle", ""))).lower()
                if stability and stability != "stable":
                    continue
                route_template = value.get("routeTemplate")
                if route_template:
                    method = str(value.get("method", "")).strip().upper()
                    name = f"{method} {route_template}" if method else route_template
                else:
                    name = value.get("id") or value.get("name") or value.get("path") or value.get("route")
                if name:
                    result.add(str(name))
            elif isinstance(value, str):
                result.add(value)
    if isinstance(values, dict):
        for key, value in values.items():
            if isinstance(value, dict):
                stability = str(value.get("stability", value.get("lifecycle", ""))).lower()
                if stability and stability != "stable":
                    continue
            result.add(str(key))
    return result

def stable_named_set_reported(details: dict[str, Any], list_key: str, fallback_key: str) -> bool:
    for key in (list_key, fallback_key):
        value = details.get(key)
        if isinstance(value, (dict, list)):
            return True
    return False

def stable_baseline_details(details: dict[str, Any]) -> dict[str, Any]:
    value = details.get("stableBaseline")
    return value if isinstance(value, dict) else {}

def stable_baseline_reported(details: dict[str, Any]) -> bool:
    if isinstance(details.get("stableBaseline"), dict):
        return True
    for key in (
        "stableBaselineCapabilities",
        "stableBaselineEndpoints",
        "stableBaselineCapabilityCount",
        "stableBaselineEndpointCount",
    ):
        value = details.get(key)
        if isinstance(value, (dict, list)):
            return True
        if int_value(value) is not None:
            return True
    return False

def stable_baseline_named_set(
    details: dict[str, Any],
    baseline_list_key: str,
    explicit_key: str,
    legacy_key: str,
    legacy_fallback_key: str,
) -> set[str]:
    reported, direct = reported_set_from_detail(details, explicit_key)
    if reported:
        return direct
    baseline = stable_baseline_details(details)
    reported, direct = reported_set_from_detail(baseline, baseline_list_key)
    if reported:
        return direct
    return stable_named_set(details, legacy_key, legacy_fallback_key)

def stable_baseline_named_set_reported(
    details: dict[str, Any], baseline_list_key: str, explicit_key: str
) -> bool:
    if isinstance(details.get(explicit_key), (dict, list)):
        return True
    baseline = stable_baseline_details(details)
    return isinstance(baseline.get(baseline_list_key), (dict, list))

def stable_baseline_count(
    details: dict[str, Any],
    baseline_count_key: str,
    explicit_count_key: str,
    baseline_list_key: str,
    explicit_list_key: str,
) -> int | None:
    direct = detail_int(details, explicit_count_key)
    if direct is not None:
        return direct
    baseline = stable_baseline_details(details)
    direct = detail_int(baseline, baseline_count_key)
    if direct is not None:
        return direct
    values = stable_baseline_named_set(
        details,
        baseline_list_key,
        explicit_list_key,
        "stableCapabilities" if baseline_list_key == "capabilities" else "stableEndpoints",
        "capabilities" if baseline_list_key == "capabilities" else "endpoints",
    )
    return len(values) if values else None

def normalized_string_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    result: set[str] = set()
    for item in value:
        text = str(item).strip()
        if text:
            result.add(text)
    return tuple(sorted(result))

def endpoint_identity_from_detail(value: dict[str, Any]) -> str:
    route_template = value.get("routeTemplate")
    if route_template:
        method = str(value.get("method", "")).strip().upper()
        return f"{method} {route_template}" if method else str(route_template)
    return str(value.get("id") or value.get("name") or value.get("path") or value.get("route") or "")

def concrete_endpoint_identity(value: Any) -> str:
    text = str(value).strip()
    if not text or "<" in text or ">" in text:
        return ""
    if text.startswith("/"):
        return text
    _method, separator, route = text.partition(" ")
    return text if separator and route.startswith("/") else ""

def stable_endpoint_capability_map(details: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    direct = details.get("stableEndpointRequiredCapabilities")
    if isinstance(direct, dict):
        return {
            str(endpoint): normalized_string_tuple(capabilities)
            for endpoint, capabilities in direct.items()
            if str(endpoint)
        }
    result: dict[str, tuple[str, ...]] = {}
    endpoints = details.get("endpoints")
    if not isinstance(endpoints, list):
        return result
    for value in endpoints:
        if not isinstance(value, dict):
            continue
        stability = str(value.get("stability", value.get("lifecycle", ""))).lower()
        if stability and stability != "stable":
            continue
        identity = endpoint_identity_from_detail(value)
        if identity:
            result[identity] = normalized_string_tuple(value.get("requiredCapabilities"))
    return result

def stable_endpoint_capability_map_reported(details: dict[str, Any]) -> bool:
    if isinstance(details.get("stableEndpointRequiredCapabilities"), dict):
        return True
    endpoints = details.get("endpoints")
    if not isinstance(endpoints, list):
        return False
    return any(isinstance(value, dict) and "requiredCapabilities" in value for value in endpoints)

def stable_endpoint_action_label_map(details: dict[str, Any]) -> dict[str, str]:
    direct = details.get("stableEndpointActionLabels")
    if isinstance(direct, dict):
        return {
            str(endpoint): str(label).strip()
            for endpoint, label in direct.items()
            if str(endpoint) and str(label).strip()
        }
    result: dict[str, str] = {}
    endpoints = details.get("endpoints")
    if not isinstance(endpoints, list):
        return result
    for value in endpoints:
        if not isinstance(value, dict):
            continue
        stability = str(value.get("stability", value.get("lifecycle", ""))).lower()
        if stability and stability != "stable":
            continue
        identity = endpoint_identity_from_detail(value)
        label = str(value.get("actionLabel") or "").strip()
        if identity and label:
            result[identity] = label
    return result

def stable_endpoint_action_label_map_reported(details: dict[str, Any]) -> bool:
    if isinstance(details.get("stableEndpointActionLabels"), dict):
        return bool(stable_endpoint_action_label_map(details))
    endpoints = details.get("endpoints")
    if not isinstance(endpoints, list):
        return False
    stable_endpoints = []
    for value in endpoints:
        if not isinstance(value, dict):
            continue
        stability = str(value.get("stability", value.get("lifecycle", ""))).lower()
        if stability and stability != "stable":
            continue
        stable_endpoints.append(value)
    if not stable_endpoints:
        return False
    return all("actionLabel" in value for value in stable_endpoints)

def endpoint_access_tuple(value: Any) -> tuple[bool, bool]:
    if not isinstance(value, dict):
        return (False, False)
    return (
        value.get("appProcessPrincipalsAllowed") is True,
        value.get("appBrowserPrincipalsAllowed") is True,
    )

def endpoint_access_detail(value: tuple[bool, bool]) -> dict[str, bool]:
    return {
        "appProcessPrincipalsAllowed": value[0],
        "appBrowserPrincipalsAllowed": value[1],
    }

def stable_endpoint_access_map(details: dict[str, Any]) -> dict[str, tuple[bool, bool]]:
    direct = details.get("stableEndpointAppAccess")
    if isinstance(direct, dict):
        return {
            str(endpoint): endpoint_access_tuple(access)
            for endpoint, access in direct.items()
            if str(endpoint)
        }
    result: dict[str, tuple[bool, bool]] = {}
    endpoints = details.get("endpoints")
    if not isinstance(endpoints, list):
        return result
    for value in endpoints:
        if not isinstance(value, dict):
            continue
        stability = str(value.get("stability", value.get("lifecycle", ""))).lower()
        if stability and stability != "stable":
            continue
        identity = endpoint_identity_from_detail(value)
        if identity:
            result[identity] = endpoint_access_tuple(value)
    return result

def stable_endpoint_access_map_reported(details: dict[str, Any]) -> bool:
    direct = details.get("stableEndpointAppAccess")
    if isinstance(direct, dict):
        return bool(direct)
    endpoints = details.get("endpoints")
    if not isinstance(endpoints, list):
        return False
    stable_endpoints = []
    for value in endpoints:
        if not isinstance(value, dict):
            continue
        stability = str(value.get("stability", value.get("lifecycle", ""))).lower()
        if stability and stability != "stable":
            continue
        stable_endpoints.append(value)
    if not stable_endpoints:
        return False
    return all(
        "appProcessPrincipalsAllowed" in value and "appBrowserPrincipalsAllowed" in value
        for value in stable_endpoints
    )

def stable_endpoint_metadata_keys(details: dict[str, Any]) -> set[str]:
    result: set[str] = {
        identity
        for endpoint in stable_baseline_named_set(
            details,
            "endpoints",
            "stableBaselineEndpoints",
            "stableEndpoints",
            "endpoints",
        )
        if (identity := concrete_endpoint_identity(endpoint))
    }
    endpoints = details.get("endpoints")
    if isinstance(endpoints, list):
        for value in endpoints:
            if not isinstance(value, dict):
                continue
            stability = str(value.get("stability", value.get("lifecycle", ""))).lower()
            if stability and stability != "stable":
                continue
            identity = endpoint_identity_from_detail(value)
            if identity:
                result.add(identity)
    result.update(stable_endpoint_capability_map(details))
    result.update(stable_endpoint_access_map(details))
    result.update(stable_endpoint_action_label_map(details))
    return result

def stable_endpoint_expected_count(details: dict[str, Any]) -> int | None:
    count = stable_baseline_count(
        details,
        "endpointCount",
        "stableBaselineEndpointCount",
        "endpoints",
        "stableBaselineEndpoints",
    )
    if count is not None:
        return count
    return detail_int(details, "stableEndpointCount")

def stable_endpoint_metadata_count_gap(
    details: dict[str, Any], metadata: dict[str, Any]
) -> dict[str, int]:
    expected = stable_endpoint_expected_count(details)
    actual = len(metadata)
    if expected is not None and actual < expected:
        return {"expected": expected, "actual": actual}
    return {}

MATRIX_CATEGORY_TITLES = {
    "release-operations": "Release operations",
    "network-compatibility": "Network compatibility",
    "performance": "Performance",
    "app-platform": "App platform",
    "app-distribution": "App distribution",
    "review-governance": "Review governance",
    "first-party-apps": "First-party apps",
    "reference-apps": "Reference apps",
    "legacy-retirement": "Legacy retirement",
    "security-redaction": "Security and redaction",
}
