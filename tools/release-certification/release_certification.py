#!/usr/bin/env python3
"""Aggregate release-candidate evidence into a redacted certification report.

The tool intentionally depends only on the Python standard library.  It consumes
the existing interop, performance, and app-platform smoke summaries and emits a
single Markdown report plus a stable JSON companion for release-candidate
evidence.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# Local release-certification helpers must not create __pycache__ before git metadata is collected.
sys.dont_write_bytecode = True
import app_platform_docs_check
import multi_node_beta_soak
import production_beta_go_no_go_dashboard
import security_response_runbook


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
ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9_:/.\->])/(?:[A-Za-z0-9._ -]+/)+[A-Za-z0-9._ -]+")
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
            if normalize_evidence_status(str(status)) == "fail":
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
    if not isinstance(entry, dict):
        return False
    return has_unwaivable_redaction_findings(str(entry.get("id", "")), evidence_details(entry))


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
    if evidence_item_has_unwaivable_redaction_findings(item):
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
        workspace_root / "tools/release-certification/app_platform_docs_check.py",
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
    generator_path = Path(production_beta_go_no_go_dashboard.__file__).resolve()
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
        allowed_limitations = domain.get("allowedLimitations")
        if isinstance(allowed_limitations, list):
            for allowed_index, limitation in enumerate(allowed_limitations):
                errors.extend(
                    stable_readiness_allowed_limitation_metadata_errors(
                        limitation,
                        f"domain {domain_id} allowedLimitations[{allowed_index}]",
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
    allowed_validation_errors: list[str] = []
    if malformed_allowed_count:
        allowed_validation_errors.append("allowedLimitationCount is not a non-negative integer")
    allowed_validation_errors.extend(allowed_record_errors)
    allowed_remaining_count = max(allowed_count if not malformed_allowed_count else 0, allowed_record_count)
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
        or allowed_validation_errors
        or domain_validation_errors
        or evidence_validation_errors
    ):
        main_status = "fail"
    elif (
        decision == "ready-with-allowed-limitations"
        or allowed_remaining_count > 0
    ) and main_status == "pass":
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
        *allowed_validation_errors,
        *domain_validation_errors,
        *evidence_validation_errors,
    ]
    if summary_validation_errors:
        main_summary = "Stable 1.0 readiness summary schema is malformed."
    elif count_validation_errors:
        main_summary = "Stable 1.0 readiness summary reports remaining blockers or forbidden limitations."
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
                "schemaVersion": summary_schema_version if summary_schema_version is not None else "missing",
                "releaseId": summary_release_id or "missing",
                "expectedReleaseId": expected_release_id or "not-available",
                "decision": decision,
                "stableReady": stable_ready,
                "blockerCount": blocker_count
                if not malformed_blocker_count
                else summary.get("blockerCount", 0),
                "warningCount": summary.get("warningCount", 0),
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


def ecosystem_matrix_row_specs() -> list[MatrixRowSpec]:
    """Return the deterministic ecosystem certification row registry."""

    return [
        MatrixRowSpec(
            id="release-history-and-waivers",
            category="release-operations",
            title="Release history comparison and waiver visibility",
            gate_ids=("ecosystem.required-evidence-regressions",),
            optional_gate_ids=("ecosystem.waivers",),
            docs=(
                "docs/release-certification.md",
                "tools/release-certification/README.md",
                "docs/cryptad-release-workflow-and-runbook.md",
            ),
            synthetic="history",
        ),
        MatrixRowSpec(
            id="ecosystem-certification-matrix",
            category="release-operations",
            title="Ecosystem certification matrix completeness",
            required_evidence_ids=("release-certification.ecosystem-matrix",),
            docs=(
                "docs/release-certification.md",
                "tools/release-certification/README.md",
                "docs/cryptad-release-workflow-and-runbook.md",
            ),
        ),
        MatrixRowSpec(
            id=ECOSYSTEM_RC_MATRIX_ROW_ID,
            category="release-operations",
            title="Ecosystem RC certification gate",
            required_evidence_ids=(ECOSYSTEM_RC_EVIDENCE_ID,),
            gate_ids=(ECOSYSTEM_RC_GATE_ID,),
            docs=(
                "docs/release-certification.md",
                "docs/ecosystem-rc-certification-gate.md",
                "docs/cryptad-release-workflow-and-runbook.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-9",
        ),
        MatrixRowSpec(
            id="production-beta-go-no-go-dashboard",
            category="release-operations",
            title="Production beta go/no-go dashboard",
            required_evidence_ids=PRODUCTION_BETA_GO_NO_GO_EVIDENCE_IDS,
            docs=(
                "docs/production-beta-go-no-go-dashboard.md",
                "docs/production-beta-release-pipeline.md",
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-10",
        ),
        MatrixRowSpec(
            id="stable-1-0-readiness",
            category="release-operations",
            title="Stable 1.0 readiness gate",
            optional_evidence_ids=STABLE_1_0_READINESS_EVIDENCE_IDS,
            docs=(
                "docs/stable-1.0-readiness-gate.md",
                "docs/stable-1.0-known-limitations.md",
                "docs/production-beta-go-no-go-dashboard.md",
                "docs/release-certification.md",
            ),
            phase="phase-11",
            required_for_release_candidate=False,
            synthetic="stable-readiness",
        ),
        MatrixRowSpec(
            id="interop-smoke",
            category="network-compatibility",
            title="Hyphanet interop smoke certification",
            required_evidence_ids=("interop.smoke",),
            optional_evidence_ids=("interop.extended",),
            docs=("docs/release-certification.md", "tools/interop/README.md"),
        ),
        MatrixRowSpec(
            id="performance-smoke",
            category="performance",
            title="Performance regression smoke certification",
            required_evidence_ids=("performance.smoke",),
            docs=("docs/release-certification.md", "tools/perf/README.md"),
        ),
        MatrixRowSpec(
            id="live-network-beta-certification",
            category="network-compatibility",
            title="Live-network beta certification",
            optional_evidence_ids=LIVE_NETWORK_BETA_EVIDENCE_IDS,
            gate_ids=("ecosystem.live-network-beta",),
            docs=(
                "docs/release-certification.md",
                "tools/release-certification/README.md",
                "docs/cryptad-release-workflow-and-runbook.md",
                "docs/app-platform-beta-program.md",
                "docs/app-platform-beta-known-limitations.md",
            ),
            phase="phase-8",
        ),
        MatrixRowSpec(
            id="platform-api-contract",
            category="app-platform",
            title="Platform API contract compatibility",
            required_evidence_ids=(
                "platform-api.contract",
                *PLATFORM_API_STABLE_FREEZE_EVIDENCE_IDS,
            ),
            gate_ids=("ecosystem.platform-api-compatibility",),
            docs=(
                "docs/platform-api-contract.md",
                "docs/platform-api-1.0-stable-reference.md",
                "docs/platform-api-compatibility-support-window.md",
                "docs/platform-api-surface.md",
            ),
        ),
        MatrixRowSpec(
            id="developer-beta-toolkit",
            category="app-platform",
            title="Developer beta toolkit and CLI readiness",
            required_evidence_ids=(
                "app-platform.devtools-cli",
                "app-platform.developer-beta-toolkit",
            ),
            docs=("docs/app-dev-cli.md", "docs/developer-beta-toolkit.md"),
        ),
        MatrixRowSpec(
            id="app-platform-beta-docs-and-program",
            category="app-platform",
            title="App platform beta docs and program readiness",
            required_evidence_ids=(
                "app-platform.docs-portal",
                "app-platform.beta-program",
                "app-platform.beta-tutorials",
                "app-platform.docs-redaction",
            ),
            docs=(
                "docs/app-platform-developer-portal.md",
                "docs/app-platform-beta-tutorials.md",
                "docs/app-platform-beta-known-limitations.md",
                "docs/app-platform-beta-program.md",
                "docs/release-certification.md",
            ),
        ),
        MatrixRowSpec(
            id="public-beta-docs-onboarding",
            category="app-platform",
            title="Public beta docs and onboarding readiness",
            required_evidence_ids=PUBLIC_BETA_ONBOARDING_EVIDENCE_IDS,
            docs=(
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
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-10",
        ),
        MatrixRowSpec(
            id="public-beta-support-feedback-loop",
            category="app-platform",
            title="Public beta support and feedback loop",
            required_evidence_ids=PUBLIC_BETA_SUPPORT_FEEDBACK_EVIDENCE_IDS,
            docs=(
                "docs/public-beta/support-and-feedback.md",
                "docs/public-beta/triage-taxonomy.md",
                "docs/public-beta/known-issues.md",
                "docs/public-beta/feedback-to-backlog.md",
                "docs/templates/beta-release-notes.md",
                "docs/privacy-preserving-beta-diagnostics.md",
                "docs/public-beta/security-reporting.md",
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-10",
        ),
        MatrixRowSpec(
            id="app-vault-and-generated-documents",
            category="app-platform",
            title="App vault, identity profile publishing, and generated documents",
            required_evidence_ids=(
                "app-vault.capabilities",
                "app-platform.identity-profile-publish",
                "app-platform.generated-document-insert",
            ),
            gate_ids=("ecosystem.app-vault",),
            docs=(
                "docs/app-secret-and-identity-vault.md",
                "docs/platform-api-contract.md",
                "docs/release-certification.md",
            ),
        ),
        MatrixRowSpec(
            id="content-fetch-and-networked-content",
            category="app-platform",
            title="Content fetch, subscriptions, and networked content surfaces",
            required_evidence_ids=(
                "app-platform.content-fetch",
                "app-platform.content-subscriptions",
                "network-content.subscription-scheduler",
                "app-platform.durable-app-data-store",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=(
                "docs/platform-api-contract.md",
                "docs/feed-reader-reference-app.md",
                "docs/app-data-store.md",
            ),
        ),
        MatrixRowSpec(
            id="network-scale-soak-and-subscription-budget",
            category="app-platform",
            title="Network-scale soak and subscription budget",
            required_evidence_ids=(
                *NETWORK_SCALE_EVIDENCE_IDS,
                NETWORK_SCALE_SOAK_EVIDENCE_ID,
            ),
            docs=(
                "docs/network-scale-soak-and-subscription-budget.md",
                "docs/release-certification.md",
                "docs/social-inbox-reference-app.md",
                "docs/feed-reader-reference-app.md",
                "docs/trust-graph-preview.md",
            ),
            phase="phase-9",
            first_party_apps=("social-inbox", "feed-reader", "trust-graph"),
        ),
        MatrixRowSpec(
            id="multi-node-beta-soak-and-upgrade-drill",
            category="release-operations",
            title="Multi-node beta soak and upgrade drill",
            required_evidence_ids=MULTI_NODE_BETA_EVIDENCE_IDS,
            gate_ids=("ecosystem.multi-node-beta",),
            docs=(
                "docs/multi-node-beta-soak-and-upgrade-drill.md",
                "docs/release-certification.md",
                "docs/production-beta-release-pipeline.md",
                "tools/release-certification/README.md",
                "docs/operator-rc-recovery-and-support-workflow.md",
            ),
            phase="phase-10",
            first_party_apps=("feed-reader", "social-inbox", "trust-graph", "profile-publisher"),
        ),
        MatrixRowSpec(
            id="previous-candidate-upgrade-path",
            category="release-operations",
            title="Previous beta candidate upgrade path",
            required_evidence_ids=(
                "multi-node-beta.upgrade-drill",
                "multi-node-beta.app-install-update-rollback",
                "multi-node-beta.app-data-migration",
                "multi-node-beta.backup-restore",
                "multi-node-beta.social-inbox-multi-source",
                "multi-node-beta.trust-graph-import",
                "multi-node-beta.support-bundle-drill",
                "multi-node-beta.redaction",
            ),
            gate_ids=("ecosystem.multi-node-beta",),
            docs=(
                "docs/multi-node-beta-soak-and-upgrade-drill.md",
                "docs/production-beta-release-pipeline.md",
                "docs/production-beta-go-no-go-dashboard.md",
                "docs/app-upgrade-data-migrations.md",
                "docs/app-data-backup-restore-portability.md",
                "docs/operator-rc-recovery-and-support-workflow.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-10",
            first_party_apps=("feed-reader", "social-inbox", "trust-graph", "profile-publisher"),
        ),
        MatrixRowSpec(
            id="app-data-backup-restore-portability",
            category="app-platform",
            title="App-data backup, restore, and portability",
            required_evidence_ids=(
                "app-platform.durable-app-data-store",
                "app-data.backup-restore-portability",
                "operator-beta.app-data-backup-restore",
            ),
            docs=(
                "docs/app-data-backup-restore-portability.md",
                "docs/app-data-store.md",
                "docs/operator-beta-dashboard.md",
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-9",
        ),
        MatrixRowSpec(
            id="trust-graph-preview-platform",
            category="app-platform",
            title="Trust Graph Local RC platform routes and signing",
            required_evidence_ids=(
                "app-platform.trust-graph-preview",
                "app-platform.trust-graph-rc-scope-and-safety",
                "app-platform.trust-graph-durable-store",
                "app-platform.trust-graph-exchange",
                "app-platform.trust-social-beta-hardening",
                "app-platform.trust-statement-signing",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=("docs/trust-graph-preview.md", "docs/platform-api-contract.md"),
        ),
        MatrixRowSpec(
            id="app-service-discovery-and-grants",
            category="app-platform",
            title="App-service discovery, grants, dependency graph, and grant bundles",
            required_evidence_ids=APP_SERVICE_DISCOVERY_AND_GRANT_EVIDENCE_IDS,
            gate_ids=("ecosystem.reference-content-apps",),
            docs=(
                "docs/app-service-discovery-and-grants.md",
                "docs/platform-api-contract.md",
                "docs/social-inbox-reference-app.md",
                "docs/trust-graph-preview.md",
            ),
        ),
        MatrixRowSpec(
            id="apphost-sandbox-provider",
            category="app-platform",
            title="AppHost sandbox-provider enforcement",
            required_evidence_ids=("apphost.sandbox-provider",),
            optional_evidence_ids=("apphost.live",),
            gate_ids=("ecosystem.sandbox-provider",),
            docs=("docs/apphost-runtime-hardening.md", "docs/release-certification.md"),
        ),
        MatrixRowSpec(
            id="public-beta-security-hardening",
            category="security-redaction",
            title="Public beta security hardening",
            required_evidence_ids=PUBLIC_BETA_SECURITY_EVIDENCE_IDS,
            gate_ids=(
                "ecosystem.app-ui-quality",
                "ecosystem.reference-content-apps",
                "ecosystem.sandbox-provider",
                "ecosystem.app-review-trust",
            ),
            docs=(
                "docs/SECURITY.md",
                "docs/app-owned-ui.md",
                "docs/feed-reader-reference-app.md",
                "docs/social-inbox-reference-app.md",
                "docs/trust-graph-preview.md",
                "docs/apphost-runtime-hardening.md",
                "docs/release-certification.md",
            ),
            phase="phase-8",
        ),
        MatrixRowSpec(
            id="app-platform-user-consent-flow",
            category="app-platform",
            title="User consent and permission-upgrade flow",
            required_evidence_ids=("app-platform.user-consent-flow",),
            docs=(
                "docs/user-consent-and-permission-upgrade-ux.md",
                "docs/app-update-lifecycle.md",
                "docs/app-catalogs.md",
                "docs/app-service-discovery-and-grants.md",
                "docs/app-data-store.md",
                "docs/app-upgrade-data-migrations.md",
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
        ),
        MatrixRowSpec(
            id="app-update",
            category="app-platform",
            title="App update lifecycle, scheduler, and rollback",
            required_evidence_ids=(
                "app-update.lifecycle",
                "app-update.scheduler",
                "app-update.live-catalog-refresh",
                "app-update.rollback",
                "app-update.data-migration-contract",
            ),
            gate_ids=("ecosystem.app-update-rollback",),
            docs=(
                "docs/app-update-lifecycle.md",
                "docs/app-upgrade-data-migrations.md",
                "docs/release-certification.md",
            ),
        ),
        MatrixRowSpec(
            id="privacy-preserving-diagnostics-risk",
            category="security-redaction",
            title="Privacy-preserving beta diagnostics",
            required_evidence_ids=(
                "app-platform.privacy-preserving-beta-diagnostics",
                "operator-beta.support-bundle-redaction",
                "operator-rc.support-bundle-wizard",
                "multi-node-beta.support-bundle-drill",
            ),
            gate_ids=("ecosystem.operator-rc-recovery", "ecosystem.multi-node-beta"),
            docs=(
                "docs/privacy-preserving-beta-diagnostics.md",
                "docs/operator-beta-dashboard.md",
                "docs/operator-rc-recovery-and-support-workflow.md",
                "docs/production-beta-go-no-go-dashboard.md",
                "docs/production-beta-release-pipeline.md",
                "docs/production-security-response-runbook.md",
                "docs/SECURITY.md",
            ),
            phase="phase-10",
        ),
        MatrixRowSpec(
            id="operator-beta-ux-and-recovery",
            category="app-platform",
            title="Operator beta dashboard, recovery, and support bundle",
            required_evidence_ids=OPERATOR_BETA_EVIDENCE_IDS,
            docs=(
                "docs/operator-beta-dashboard.md",
                "docs/platform-api-surface.md",
                "docs/app-platform-beta-program.md",
                "docs/app-platform-beta-known-limitations.md",
                "docs/release-certification.md",
            ),
            phase="phase-8",
        ),
        MatrixRowSpec(
            id="operator-rc-recovery-and-support-workflow",
            category="app-platform",
            title="Operator RC recovery and support workflow",
            required_evidence_ids=OPERATOR_RC_EVIDENCE_IDS,
            gate_ids=("ecosystem.operator-rc-recovery",),
            docs=(
                "docs/operator-rc-recovery-and-support-workflow.md",
                "docs/operator-beta-dashboard.md",
                "docs/platform-api-surface.md",
                "docs/app-platform-beta-known-limitations.md",
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-9",
        ),
        MatrixRowSpec(
            id="first-party-beta-catalog",
            category="app-distribution",
            title="First-party beta catalog and signed bundles",
            required_evidence_ids=(
                "catalog.smoke",
                "catalog.live-usk-publication",
                "catalog.live-usk-source-verification",
                "app-catalog.first-party-beta",
                "app-platform.signed-bundles",
            ),
            docs=("docs/first-party-beta-catalog.md", "docs/app-catalogs.md"),
        ),
        MatrixRowSpec(
            id="production-catalog-channels",
            category="app-distribution",
            title="Production first-party catalog channels",
            required_evidence_ids=("catalog.production-channels",),
            docs=(
                "docs/production-first-party-catalog-channels.md",
                "docs/app-catalogs.md",
                "docs/app-update-lifecycle.md",
                "docs/platform-api-surface.md",
            ),
            phase="phase-9",
        ),
        MatrixRowSpec(
            id="catalog-operations-and-mirrors",
            category="app-distribution",
            title="Catalog operations and mirrors",
            required_evidence_ids=("catalog.operations-and-mirrors",),
            docs=(
                "docs/catalog-operations-and-mirrors.md",
                "docs/app-catalogs.md",
                "docs/production-security-response-runbook.md",
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-10",
        ),
        MatrixRowSpec(
            id="first-party-app-maintenance-policy",
            category="app-distribution",
            title="First-party app maintenance policy",
            required_evidence_ids=("app-catalog.first-party-maintenance-policy",),
            docs=(
                "docs/first-party-app-maintenance-policy.md",
                "docs/app-catalogs.md",
                "docs/production-first-party-catalog-channels.md",
                "docs/production-beta-release-pipeline.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-10",
            first_party_apps=(
                "queue-manager",
                "publisher",
                "site-publisher",
                "profile-publisher",
                "feed-reader",
                "social-inbox",
                "trust-graph",
            ),
        ),
        MatrixRowSpec(
            id="ecosystem-security-advisory-and-revocation",
            category="security-redaction",
            title="Ecosystem security advisory and revocation response",
            required_evidence_ids=ECOSYSTEM_SECURITY_EVIDENCE_IDS,
            gate_ids=("ecosystem.security-advisory-revocation",),
            docs=(
                "docs/ecosystem-security-advisories.md",
                "docs/app-catalogs.md",
                "docs/production-first-party-catalog-channels.md",
                "docs/app-review-governance.md",
                "docs/app-update-lifecycle.md",
                "docs/SECURITY.md",
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-9",
        ),
        MatrixRowSpec(
            id="production-security-response-runbook",
            category="security-redaction",
            title="Production security response runbook",
            required_evidence_ids=PRODUCTION_SECURITY_EVIDENCE_IDS,
            gate_ids=("ecosystem.security-advisory-revocation", "ecosystem.operator-rc-recovery"),
            docs=(
                "docs/production-security-response-runbook.md",
                "docs/templates/security-release-notes.md",
                "docs/SECURITY.md",
                "docs/ecosystem-security-advisories.md",
                "docs/app-catalogs.md",
                "docs/app-review-governance.md",
                "docs/operator-rc-recovery-and-support-workflow.md",
                "docs/production-beta-release-pipeline.md",
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-10",
        ),
        MatrixRowSpec(
            id="review-trusted-receipts",
            category="review-governance",
            title="Trusted app-review receipts and policy",
            required_evidence_ids=(
                "app-review.trusted-receipts",
                "app-review.policy",
                "app-review.first-party-catalog",
            ),
            gate_ids=("ecosystem.app-review-trust",),
            docs=("docs/app-review-governance.md", "docs/app-catalogs.md"),
        ),
        MatrixRowSpec(
            id="review-governance-transparency",
            category="review-governance",
            title="Review governance, transparency log, and review history",
            required_evidence_ids=(
                "app-review.governance",
                "app-review.reviewer-key-lifecycle",
                "app-review.transparency-log",
                "app-review.review-history-api",
                "app-review.first-party-review-chain",
            ),
            gate_ids=("ecosystem.app-review-trust",),
            docs=("docs/app-review-governance.md",),
        ),
        MatrixRowSpec(
            id="app-store-submission-and-review",
            category="review-governance",
            title="Third-party app submission and review workflow",
            required_evidence_ids=(
                *APP_STORE_SUBMISSION_EVIDENCE_IDS,
                *THIRD_PARTY_INTAKE_EVIDENCE_IDS,
            ),
            gate_ids=("ecosystem.app-review-trust",),
            docs=(
                "docs/app-store-submission-and-review-workflow.md",
                "docs/app-dev-cli.md",
                "docs/app-review-governance.md",
                "docs/app-catalogs.md",
                "docs/production-beta-release-pipeline.md",
            ),
        ),
        MatrixRowSpec(
            id="third-party-developer-beta-program",
            category="review-governance",
            title="Third-party developer beta program",
            required_evidence_ids=THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS,
            gate_ids=("ecosystem.app-review-trust",),
            docs=(
                "docs/third-party-developer-beta-program.md",
                "docs/third-party-app-submission-checklist.md",
                "docs/platform-api-compatibility-support-window.md",
                "docs/examples/third-party-hello-stable.md",
                "docs/app-store-submission-and-review-workflow.md",
                "docs/app-catalogs.md",
                "docs/legacy-plugin-migration-guide.md",
                "docs/release-certification.md",
            ),
        ),
        MatrixRowSpec(
            id="ui-design-system",
            category="first-party-apps",
            title="App UI design-system adoption and lint",
            required_evidence_ids=(
                "app-ui.design-system",
                "app-ui.lint",
                "app-ui.first-party-adoption",
                "app-ui.smoke",
            ),
            gate_ids=("ecosystem.app-ui-quality",),
            docs=("docs/app-ui-design-system.md", "docs/app-owned-ui.md"),
        ),
        MatrixRowSpec(
            id="first-party-app-bundles",
            category="first-party-apps",
            title="First-party app bundle set and beta quality",
            required_evidence_ids=(
                "app-platform.first-party",
                FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID,
            ),
            gate_ids=("ecosystem.first-party-apps",),
            docs=(
                "docs/first-party-beta-catalog.md",
                "docs/first-party-app-beta-quality-pass.md",
                "docs/app-distribution.md",
            ),
            first_party_apps=EXPECTED_FIRST_PARTY_APPS,
        ),
        MatrixRowSpec(
            id="reference-content-apps",
            category="reference-apps",
            title="Site Publisher reference content app",
            required_evidence_ids=("reference-apps.content",),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=("docs/first-party-beta-catalog.md", "docs/app-distribution.md"),
            first_party_apps=("site-publisher",),
        ),
        MatrixRowSpec(
            id="profile-publisher",
            category="reference-apps",
            title="Profile Publisher reference app",
            required_evidence_ids=(
                "reference-app.profile-publisher",
                "reference-app.profile-publisher-app-data",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=("docs/first-party-beta-catalog.md",),
            first_party_apps=("profile-publisher",),
        ),
        MatrixRowSpec(
            id="feed-reader",
            category="reference-apps",
            title="Feed Reader reference app",
            required_evidence_ids=(
                "reference-app.feed-reader",
                "reference-app.feed-reader-subscriptions",
                "reference-app.feed-reader-app-data",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=("docs/feed-reader-reference-app.md",),
            first_party_apps=("feed-reader",),
        ),
        MatrixRowSpec(
            id="trust-graph-app",
            category="reference-apps",
            title="Trust Graph Local RC reference app",
            required_evidence_ids=(
                "reference-app.trust-graph",
                "reference-app.trust-graph-durable-exchange",
                "reference-app.trust-graph-app-data-preview",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=("docs/trust-graph-preview.md",),
            first_party_apps=("trust-graph",),
        ),
        MatrixRowSpec(
            id="social-inbox-preview",
            category="reference-apps",
            title="Social Inbox RC message-threading reference app",
            required_evidence_ids=(
                "app-platform.social-message-signing",
                "reference-app.social-inbox",
                "reference-app.social-inbox-signed-message",
                "reference-app.social-inbox-subscriptions",
                "reference-app.social-inbox-app-data",
                "reference-app.social-inbox-trust-annotations",
                "reference-app.social-inbox-rc-threading",
                "app-platform.trust-social-beta-hardening",
                "app-platform.trust-social-content-format-profiles",
                "reference-app.social-inbox-service-grant",
                "reference-app.social-inbox-service-dependency",
                "migration.social-mail-preview",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=(
                "docs/social-inbox-reference-app.md",
                "docs/platform-api-contract.md",
                "docs/app-secret-and-identity-vault.md",
                "docs/app-service-discovery-and-grants.md",
            ),
            first_party_apps=("social-inbox",),
        ),
        MatrixRowSpec(
            id="legacy-plugin-migration",
            category="legacy-retirement",
            title="Legacy plugin-to-app migration guidance",
            required_evidence_ids=(
                "legacy-plugin.freeze-policy",
                "legacy-plugin.migration-guide",
                "legacy-plugin.social-inbox-spike",
                "legacy-plugin.migration-finalization",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=(
                "docs/legacy-plugin-freeze-policy.md",
                "docs/legacy-plugin-migration-guide.md",
                "docs/legacy-plugin-migration-cookbook.md",
                "docs/templates/plugin-migration-plan.md",
                "docs/plugin-system.md",
                "docs/social-inbox-reference-app.md",
                "docs/app-service-discovery-and-grants.md",
            ),
            first_party_apps=("social-inbox", "trust-graph"),
            phase="phase-9",
        ),
        MatrixRowSpec(
            id="legacy-retirement",
            category="legacy-retirement",
            title="Legacy admin retirement and removal waves",
            required_evidence_ids=(
                "legacy.retirement",
                "legacy-admin.removal-wave-1",
                "legacy-admin.removal-wave-2",
                "legacy-admin.removal-wave-3",
                "legacy-admin.removal-wave-4",
                "legacy-admin.removal-wave-5",
                "legacy-admin.final-admin-surface",
                "legacy-admin.browse-retained",
                "legacy-admin.emergency-fallback-retained",
            ),
            gate_ids=("ecosystem.legacy-retirement",),
            docs=("docs/legacy-retirement-plan.md", "docs/release-certification.md"),
            phase="phase-10",
        ),
        MatrixRowSpec(
            id="redaction-and-private-artifacts",
            category="security-redaction",
            title="Redaction and private artifact exclusions",
            docs=(
                "docs/release-certification.md",
                "tools/release-certification/README.md",
                "docs/cryptad-release-workflow-and-runbook.md",
            ),
            synthetic="redaction",
        ),
    ]


def required_stable_readiness_blocking(settings: Settings, rows: Any) -> bool:
    if not settings.stable_readiness_required:
        return False
    if not isinstance(rows, list):
        return True
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("id") == STABLE_1_0_READINESS_MATRIX_ROW_ID:
            return bool(row.get("releaseBlocker"))
    return True


def matrix_status_from_counts(mode: str, counts: dict[str, int], coverage: dict[str, Any]) -> str:
    release_blockers = counts.get("releaseBlockers", 0)
    warnish_rows = sum(counts.get(status, 0) for status in ("warn", "missing", "skip"))
    redaction_failed = coverage.get("redactionPassed") is False
    unwaived_coverage_issue_ids = [
        str(issue_id) for issue_id in coverage.get("unwaivedIssueIds", coverage.get("issueIds", [])) if issue_id
    ]
    coverage_warn = bool(coverage.get("issueIds")) or not all(
        bool(coverage.get(key))
        for key in ("requiredEvidenceCovered", "ecosystemGatesCovered", "firstPartyAppsCovered", "docsCovered")
    )
    if mode == "pr":
        if redaction_failed:
            return "fail"
        return "warn" if release_blockers or warnish_rows or coverage_warn else "pass"
    if mode == "release-candidate" and (release_blockers or redaction_failed or unwaived_coverage_issue_ids):
        return "fail"
    if redaction_failed:
        return "fail"
    if release_blockers or warnish_rows or coverage_warn:
        return "warn"
    return "pass"


def previous_matrix_row_statuses(previous_summary: dict[str, Any] | None) -> dict[str, str]:
    if not isinstance(previous_summary, dict):
        return {}
    compact = previous_summary.get("ecosystemMatrix")
    if not isinstance(compact, dict):
        return {}
    statuses = compact.get("rowStatuses")
    if isinstance(statuses, dict):
        return {
            str(row_id): normalize_evidence_status(str(status))
            for row_id, status in statuses.items()
        }
    rows = compact.get("rows")
    if isinstance(rows, list):
        return {
            str(row.get("id")): normalize_evidence_status(str(row.get("status", "missing")))
            for row in rows
            if isinstance(row, dict) and row.get("id")
        }
    return {}


def regression_status_for_row(
    spec: MatrixRowSpec,
    status: str,
    release_blocker: bool,
    previous_summary_present: bool,
    previous_matrix_present: bool,
    previous_row_statuses: dict[str, str],
) -> tuple[str, str]:
    if not previous_summary_present:
        return "missing", "not-comparable"
    if not previous_matrix_present:
        return "missing", "previous-missing"
    previous_status = previous_row_statuses.get(spec.id)
    if previous_status is None:
        return "missing", "new-row"
    previous_severity = status_severity(previous_status)
    current_severity = status_severity(status)
    if current_severity > previous_severity:
        return previous_status, "regressed-blocker" if release_blocker or status == "fail" else "regressed-warning"
    if current_severity < previous_severity:
        return previous_status, "improved"
    return previous_status, "unchanged"


def gate_status(entry: dict[str, Any] | None) -> str:
    if not isinstance(entry, dict):
        return "missing"
    return normalize_evidence_status(str(entry.get("status", "missing")))


def aggregate_status_values(values: list[str], *, missing_if_empty: bool = False) -> str:
    normalized = [normalize_evidence_status(value) for value in values]
    if not normalized:
        return "missing" if missing_if_empty else "pass"
    if any(value == "fail" for value in normalized):
        return "fail"
    if any(value == "warn" for value in normalized):
        return "warn"
    if any(value == "missing" for value in normalized):
        return "missing"
    if any(value == "skip" for value in normalized):
        return "skip"
    return "pass"


def unwaivable_matrix_issue_ids(
    unwaivable_evidence_ids: set[str],
    extra_unwaivable_issue_ids: set[str] | None = None,
) -> set[str]:
    unwaivable_issue_ids = set(unwaivable_evidence_ids)
    unwaivable_issue_ids.update(
        f"evidence.{evidence_id}" for evidence_id in unwaivable_evidence_ids
    )
    if extra_unwaivable_issue_ids:
        unwaivable_issue_ids.update(extra_unwaivable_issue_ids)
    return unwaivable_issue_ids


def waivable_matrix_issue_ids(
    issue_ids: list[str],
    unwaivable_evidence_ids: set[str],
    extra_unwaivable_issue_ids: set[str] | None = None,
) -> list[str]:
    unwaivable_issue_ids = unwaivable_matrix_issue_ids(
        unwaivable_evidence_ids,
        extra_unwaivable_issue_ids,
    )
    return [issue_id for issue_id in issue_ids if issue_id not in unwaivable_issue_ids]


def row_waivers(
    spec: MatrixRowSpec,
    evidence_entries: dict[str, dict[str, Any]],
    gate_entries: dict[str, dict[str, Any]],
    context: WaiverContext,
    mode: str,
    issue_ids: list[str],
    unwaivable_evidence_ids: set[str],
    extra_unwaivable_issue_ids: set[str] | None = None,
) -> tuple[list[WaiverRecord], list[str]]:
    records: dict[str, WaiverRecord] = {}
    unwaivable_issue_ids = unwaivable_matrix_issue_ids(
        unwaivable_evidence_ids,
        extra_unwaivable_issue_ids,
    )
    waivable_issue_ids = waivable_matrix_issue_ids(
        issue_ids,
        unwaivable_evidence_ids,
        extra_unwaivable_issue_ids,
    )
    targets = [spec.id, *spec.evidence_ids(), *spec.all_gate_ids()]
    if unwaivable_evidence_ids or extra_unwaivable_issue_ids:
        targets = [
            target_id
            for target_id in targets
            if target_id != spec.id and target_id not in unwaivable_evidence_ids
        ]
    for target_id in targets:
        waiver = active_waiver_for(context, target_id, waivable_issue_ids, mode)
        if waiver is not None:
            records[waiver.id] = waiver
    for evidence_id in spec.evidence_ids():
        if evidence_id in unwaivable_evidence_ids:
            continue
        for waiver_id in detail_waiver_ids(evidence_details(evidence_entries.get(evidence_id))):
            waiver = active_waiver_for(context, str(waiver_id), waivable_issue_ids, mode)
            if waiver is not None:
                records[waiver.id] = waiver
    for gate_id in spec.all_gate_ids():
        gate = gate_entries.get(gate_id)
        details = gate.get("details", {}) if isinstance(gate, dict) else {}
        if isinstance(details, dict):
            for waiver_id in detail_waiver_ids(details):
                if str(waiver_id) in unwaivable_issue_ids:
                    continue
                waiver = active_waiver_for(context, str(waiver_id), waivable_issue_ids, mode)
                if waiver is not None:
                    records[waiver.id] = waiver
    waiver_ids = sorted(records)
    return [records[waiver_id] for waiver_id in waiver_ids], waiver_ids


def row_release_blocker_waiver(
    spec: MatrixRowSpec,
    context: WaiverContext,
    mode: str,
    issue_ids: list[str],
    blocker_targets: list[str],
    unwaivable_evidence_ids: set[str],
    extra_unwaivable_issue_ids: set[str] | None = None,
) -> WaiverRecord | None:
    if unwaivable_evidence_ids.intersection(blocker_targets):
        return None
    if extra_unwaivable_issue_ids and extra_unwaivable_issue_ids.intersection(issue_ids):
        return None
    waivable_issue_ids = waivable_matrix_issue_ids(
        issue_ids,
        unwaivable_evidence_ids,
        extra_unwaivable_issue_ids,
    )
    return active_waiver_for(
        context,
        spec.id,
        sorted(dict.fromkeys(waivable_issue_ids + blocker_targets)),
        mode,
    )


def row_recommendation(
    status: str,
    release_blocker: bool,
    waiver_ids: list[str],
    missing_required: list[str],
    gate_blockers: list[str],
    previous_matrix_missing_warning: bool,
) -> str:
    if status == "pass":
        return "No release action required."
    if previous_matrix_missing_warning:
        return "Record the previous-summary matrix gap in the release log."
    if waiver_ids:
        return "Review waived evidence before release-candidate promotion."
    if release_blocker and missing_required:
        return "Restore missing required evidence before release-candidate promotion."
    if release_blocker and gate_blockers:
        return "Resolve release-blocking ecosystem gate or record an approved waiver."
    if release_blocker:
        return "Review failing evidence and rerun release certification."
    if status == "missing":
        return "Restore missing required evidence before release-candidate promotion."
    if status == "skip":
        return "Review skipped evidence before release-candidate promotion."
    return "Review warning evidence or record an approved waiver."


def safe_waiver_summaries(records: list[WaiverRecord]) -> dict[str, str]:
    return {record.id: record.reason for record in records}


def evaluate_matrix_row(
    spec: MatrixRowSpec,
    settings: Settings,
    evidence_entries: dict[str, dict[str, Any]],
    previous_evidence_entries: dict[str, dict[str, Any]],
    gate_entries: dict[str, dict[str, Any]],
    history_comparison: dict[str, Any],
    previous_summary_present: bool,
    previous_matrix_present: bool,
    previous_row_statuses: dict[str, str],
    waiver_context: WaiverContext,
    redaction: dict[str, bool],
) -> dict[str, Any]:
    required_statuses = {
        evidence_id: evidence_status(evidence_entries.get(evidence_id))
        for evidence_id in spec.required_evidence_ids
    }
    optional_statuses = {
        evidence_id: evidence_status(evidence_entries.get(evidence_id))
        for evidence_id in spec.optional_evidence_ids
    }
    unwaivable_redaction_evidence_ids = {
        evidence_id
        for evidence_id in spec.evidence_ids()
        if evidence_entry_has_unwaivable_redaction_findings(evidence_entries.get(evidence_id))
    }
    previous_statuses = {
        evidence_id: evidence_status(previous_evidence_entries.get(evidence_id))
        for evidence_id in spec.evidence_ids()
    }
    gate_statuses = {
        gate_id: gate_status(gate_entries.get(gate_id))
        for gate_id in spec.gate_ids
    }
    optional_gate_statuses = {
        gate_id: gate_status(gate_entries.get(gate_id))
        for gate_id in spec.optional_gate_ids
        if gate_id in gate_entries
    }
    stable_not_requested = False
    issue_ids: list[str] = []
    extra_unwaivable_issue_ids: set[str] = set()
    gate_blockers: list[str] = []
    gate_warnings: list[str] = []
    for gate_id in spec.all_gate_ids():
        gate = gate_entries.get(gate_id)
        if not isinstance(gate, dict):
            if gate_id in spec.gate_ids:
                issue_ids.append(f"matrix.gate-missing.{gate_id}")
            continue
        details = gate.get("details", {})
        if isinstance(details, dict):
            issue_ids.extend(str(value) for value in details.get("issueIds", []) if value)
        status = gate_status(gate)
        if status == "fail" and gate.get("releaseBlocker"):
            gate_blockers.append(gate_id)
        elif status in {"warn", "fail", "missing"}:
            gate_warnings.append(gate_id)

    missing_required = [
        evidence_id for evidence_id, status in required_statuses.items() if status == "missing"
    ]
    skipped_required = [
        evidence_id for evidence_id, status in required_statuses.items() if status == "skip"
    ]
    skipped_required_non_rc = skipped_required if settings.mode != "release-candidate" else []
    required_skip_only = (
        bool(spec.required_evidence_ids)
        and settings.mode != "release-candidate"
        and all(status == "skip" for status in required_statuses.values())
    )
    required_bad = [
        evidence_id
        for evidence_id, status in required_statuses.items()
        if status in {"fail", "missing"} or (status == "skip" and settings.mode == "release-candidate")
    ]
    required_warn = [
        evidence_id for evidence_id, status in required_statuses.items() if status == "warn"
    ]
    optional_warn: list[str] = []
    for evidence_id, status in optional_statuses.items():
        if (
            evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
            and status == "missing"
            and not settings.stable_readiness_required
        ):
            continue
        if status in {"fail", "warn", "missing"}:
            optional_warn.append(evidence_id)
        elif status == "skip":
            evidence_details_value = evidence_details(evidence_entries.get(evidence_id))
            live_beta_disabled_skip = (
                evidence_id in LIVE_NETWORK_BETA_EVIDENCE_IDS
                and not settings.live_network_beta_enabled
                and not settings.live_network_beta_required
                and not bool(evidence_details_value.get("enabled"))
            )
            if live_beta_disabled_skip:
                continue
            if evidence_id == "apphost.live":
                continue
            if evidence_id == "live-network-beta.app-service-score" and not bool(
                evidence_details_value.get("enabled")
            ):
                continue
            optional_warn.append(evidence_id)
    if required_bad:
        issue_ids.extend(f"evidence.{evidence_id}" for evidence_id in required_bad)
    if required_warn:
        issue_ids.extend(f"evidence.{evidence_id}" for evidence_id in required_warn)
    if skipped_required_non_rc:
        issue_ids.extend(f"evidence.{evidence_id}" for evidence_id in skipped_required_non_rc)
    if optional_warn:
        issue_ids.extend(f"evidence.{evidence_id}" for evidence_id in optional_warn)
    blocker_targets = sorted(dict.fromkeys(required_bad + gate_blockers))

    previous_matrix_missing_warning = (
        spec.synthetic == "history"
        and previous_summary_present
        and not previous_matrix_present
        and settings.mode in {"nightly", "release-candidate"}
    )
    history_status = normalize_evidence_status(str(history_comparison.get("status", "missing")))
    if spec.synthetic == "history":
        if history_status == "fail" or gate_blockers:
            status = "fail"
            release_blocker = True
        elif history_status in {"warn", "missing"} or gate_warnings or previous_matrix_missing_warning:
            status = "warn"
            release_blocker = False
        else:
            status = "pass"
            release_blocker = False
        if waiver_context.records:
            status = "warn" if status == "pass" else status
        if waiver_context.errors and settings.mode == "release-candidate":
            status = "fail"
            release_blocker = True
        summary = "History comparison and waiver validation are visible in the release record."
    elif spec.synthetic == "redaction":
        release_blocker = not all(redaction.values())
        status = "fail" if release_blocker else "pass"
        summary = "Certification summaries and copied artifacts exclude private material."
        if release_blocker:
            issue_ids.append("matrix.redaction.failed")
    elif spec.synthetic == "stable-readiness":
        attached = any(evidence_id in evidence_entries for evidence_id in spec.evidence_ids())
        main_entry = evidence_entries.get("stable-1.0.readiness-gate")
        redaction_entry = evidence_entries.get("stable-1.0.redaction")
        main_status = evidence_status(main_entry)
        redaction_status = evidence_status(redaction_entry)
        main_details = evidence_details(main_entry)
        decision = str(main_details.get("decision", "not-attached"))
        stable_ready = main_details.get("stableReady") is True
        redaction_failed = (
            redaction_status != "pass"
            or bool(unwaivable_redaction_evidence_ids)
            or evidence_entry_has_unwaivable_redaction_findings(main_entry)
            or evidence_entry_has_unwaivable_redaction_findings(redaction_entry)
        )
        stable_evidence_bad = [
            evidence_id
            for evidence_id in spec.evidence_ids()
            if evidence_status(evidence_entries.get(evidence_id)) in {"fail", "missing", "skip"}
        ]
        stable_evidence_warn = [
            evidence_id
            for evidence_id in spec.evidence_ids()
            if evidence_status(evidence_entries.get(evidence_id)) == "warn"
        ]
        if not attached and not settings.stable_readiness_required:
            status = "pass"
            release_blocker = False
            stable_not_requested = True
            summary = "Stable 1.0 readiness was not requested for this certification run."
            issue_ids = [
                issue_id
                for issue_id in issue_ids
                if not issue_id.startswith("evidence.stable-1.0.")
            ]
        elif not attached:
            status = "fail"
            release_blocker = True
            summary = "Stable 1.0 readiness is required but no summary was attached."
            issue_ids.append("matrix.stable-readiness.required-missing")
            extra_unwaivable_issue_ids.add("matrix.stable-readiness.required-missing")
        elif redaction_failed:
            status = "fail"
            release_blocker = True
            summary = "Stable 1.0 readiness redaction findings are non-waivable."
            if redaction_status == "fail" or not unwaivable_redaction_evidence_ids:
                unwaivable_redaction_evidence_ids.add("stable-1.0.redaction")
            extra_unwaivable_issue_ids.add("matrix.stable-readiness.redaction-failed")
            blocker_targets.extend(sorted(unwaivable_redaction_evidence_ids))
            issue_ids.append("matrix.stable-readiness.redaction-failed")
        elif stable_evidence_bad:
            release_blocker = settings.stable_readiness_required
            status = "fail" if release_blocker else "warn"
            summary = (
                "Stable 1.0 readiness is required but expected evidence is missing or failing."
                if release_blocker
                else "Stable 1.0 readiness advisory evidence is missing or failing."
            )
            issue_ids.append("matrix.stable-readiness.evidence-not-passing")
            if release_blocker:
                extra_unwaivable_issue_ids.add(
                    "matrix.stable-readiness.evidence-not-passing"
                )
                blocker_targets.extend(stable_evidence_bad)
        elif main_status == "fail" or not stable_ready or decision == "not-ready":
            release_blocker = settings.stable_readiness_required
            status = "fail" if release_blocker else "warn"
            summary = (
                "Stable 1.0 readiness is required and not passing."
                if release_blocker
                else "Stable 1.0 readiness is attached as advisory evidence and is not ready."
            )
            if release_blocker:
                issue_ids.append("matrix.stable-readiness.not-ready")
                extra_unwaivable_issue_ids.add("matrix.stable-readiness.not-ready")
                blocker_targets.append("stable-1.0.readiness-gate")
        elif main_status == "warn" or decision == "ready-with-allowed-limitations":
            status = "warn"
            release_blocker = False
            summary = "Stable 1.0 readiness is ready with bounded allowed limitations."
        elif stable_evidence_warn:
            status = "warn"
            release_blocker = False
            summary = "Stable 1.0 readiness evidence has warnings."
        else:
            status = "pass"
            release_blocker = False
            summary = "Stable 1.0 readiness evidence passed."
    elif not spec.evidence_ids() and not spec.all_gate_ids():
        status = "missing"
        release_blocker = False
        summary = "Matrix row has no evidence or gate inputs."
        issue_ids.append("matrix.row-inputs-missing")
    elif required_bad or gate_blockers:
        status = "fail"
        release_blocker = True
        summary = "Required evidence or an ecosystem gate is release-blocking."
    elif (
        required_skip_only
        and not required_warn
        and not optional_warn
        and not gate_warnings
    ):
        status = "skip"
        release_blocker = False
        summary = "Required evidence was intentionally skipped outside release-candidate mode."
    elif (
        required_warn
        or skipped_required_non_rc
        or optional_warn
        or gate_warnings
        or any(
            previous_statuses.get(evidence_id) == "pass" and status_value == "warn"
            for evidence_id, status_value in required_statuses.items()
        )
    ):
        status = "warn"
        release_blocker = False
        summary = "Required or optional evidence needs release-manager review."
    else:
        status = "pass"
        release_blocker = False
        summary = "Required evidence and referenced ecosystem gates passed."

    waiver_for_blocker = row_release_blocker_waiver(
        spec,
        waiver_context,
        settings.mode,
        issue_ids,
        blocker_targets,
        unwaivable_redaction_evidence_ids,
        extra_unwaivable_issue_ids,
    )
    if release_blocker and waiver_for_blocker is not None:
        status = "warn"
        release_blocker = False
        summary = f"{summary} Waiver recorded: {waiver_for_blocker.reason}"
    waiver_records, waiver_ids = row_waivers(
        spec,
        evidence_entries,
        gate_entries,
        waiver_context,
        settings.mode,
        issue_ids,
        unwaivable_redaction_evidence_ids,
        extra_unwaivable_issue_ids,
    )
    if waiver_for_blocker is not None and waiver_for_blocker.id not in waiver_ids:
        waiver_records = sorted([*waiver_records, waiver_for_blocker], key=lambda record: record.id)
        waiver_ids = sorted([*waiver_ids, waiver_for_blocker.id])
    if waiver_ids and status == "pass":
        status = "warn"
        summary = "Active waiver is recorded for this row."

    previous_status, regression_status = regression_status_for_row(
        spec,
        status,
        release_blocker,
        previous_summary_present,
        previous_matrix_present,
        previous_row_statuses,
    )
    if stable_not_requested:
        previous_status = "pass"
        regression_status = "unchanged"
    if regression_status in {"regressed-warning", "regressed-blocker"} and status == "pass":
        status = "warn"
    gate_status_value = aggregate_status_values(
        list(gate_statuses.values()) + list(optional_gate_statuses.values()),
        missing_if_empty=bool(spec.gate_ids),
    )
    details: dict[str, Any] = {
        "currentEvidenceStatuses": required_statuses | optional_statuses,
        "previousEvidenceStatuses": previous_statuses,
        "gateStatuses": gate_statuses | optional_gate_statuses,
    }
    if spec.first_party_apps:
        details["firstPartyApps"] = list(spec.first_party_apps)
    if waiver_records:
        details["waiverReasons"] = safe_waiver_summaries(waiver_records)
    if spec.synthetic == "history":
        details["historyStatus"] = history_status
        details["previousMatrixPresent"] = previous_matrix_present
    if spec.synthetic == "redaction":
        details["redaction"] = redaction
    if stable_not_requested:
        details["notRequested"] = True
        details["required"] = False
    if unwaivable_redaction_evidence_ids:
        details["unwaivableRedactionEvidenceIds"] = sorted(unwaivable_redaction_evidence_ids)
    if extra_unwaivable_issue_ids:
        details["unwaivableIssueIds"] = sorted(extra_unwaivable_issue_ids)

    return {
        "id": spec.id,
        "category": spec.category,
        "title": spec.title,
        "requiredForReleaseCandidate": spec.required_for_release_candidate,
        "status": status,
        "previousStatus": previous_status,
        "regressionStatus": regression_status,
        "releaseBlocker": release_blocker,
        "summary": summary,
        "evidenceIds": list(spec.evidence_ids()),
        "requiredEvidenceIds": list(spec.required_evidence_ids),
        "optionalEvidenceIds": list(spec.optional_evidence_ids),
        "gateIds": list(spec.all_gate_ids()),
        "gateStatus": gate_status_value,
        "waiverIds": waiver_ids,
        "issueIds": sorted(dict.fromkeys(issue_ids)),
        "docs": list(spec.docs),
        "owner": spec.owner,
        "phase": spec.phase,
        "recommendation": row_recommendation(
            status,
            release_blocker,
            waiver_ids,
            missing_required,
            gate_blockers,
            previous_matrix_missing_warning,
        ),
        "details": details,
    }


def validate_matrix_coverage(
    settings: Settings,
    specs: list[MatrixRowSpec],
    evidence_entries: dict[str, dict[str, Any]],
    gate_entries: dict[str, dict[str, Any]],
    redaction: dict[str, bool],
) -> dict[str, Any]:
    mapped_required_evidence = {
        evidence_id for spec in specs for evidence_id in spec.required_evidence_ids
    }
    mapped_evidence = {evidence_id for spec in specs for evidence_id in spec.evidence_ids()}
    required_evidence = {
        evidence_id
        for evidence_id, entry in evidence_entries.items()
        if evidence_required(entry)
    }
    mapped_gates = {gate_id for spec in specs for gate_id in spec.all_gate_ids()}
    gate_ids = set(gate_entries)
    non_synthetic_specs = [spec for spec in specs if not spec.synthetic]
    rows_without_docs = [spec.id for spec in non_synthetic_specs if not spec.docs]
    rows_without_owners = [spec.id for spec in specs if not spec.owner]
    missing_doc_paths = sorted(
        {
            doc_path
            for spec in non_synthetic_specs
            for doc_path in spec.docs
            if not (settings.workspace_root / doc_path).is_file()
        }
    )
    first_party_apps = sorted(
        {
            app_id
            for spec in specs
            for app_id in spec.first_party_apps
        }
    )
    missing_first_party_apps = sorted(set(EXPECTED_FIRST_PARTY_APPS) - set(first_party_apps))
    missing_required_evidence_ids = sorted(mapped_required_evidence - set(evidence_entries))
    unmapped_required_evidence_ids = sorted(required_evidence - mapped_evidence)
    unmapped_gate_ids = sorted(gate_ids - mapped_gates)
    coverage_issue_ids: list[str] = []
    if missing_required_evidence_ids:
        coverage_issue_ids.append("matrix.required-evidence-missing")
    if unmapped_required_evidence_ids:
        coverage_issue_ids.append("matrix.required-evidence-unmapped")
    if unmapped_gate_ids:
        coverage_issue_ids.append("matrix.ecosystem-gates-unmapped")
    if missing_first_party_apps:
        coverage_issue_ids.append("matrix.first-party-apps-uncovered")
    if rows_without_docs or missing_doc_paths:
        coverage_issue_ids.append("matrix.docs-uncovered")
    if not all(redaction.values()):
        coverage_issue_ids.append("matrix.redaction-failed")
    return {
        "requiredEvidenceCovered": not missing_required_evidence_ids and not unmapped_required_evidence_ids,
        "ecosystemGatesCovered": not unmapped_gate_ids,
        "firstPartyAppsCovered": not missing_first_party_apps,
        "docsCovered": not rows_without_docs and not missing_doc_paths,
        "redactionPassed": all(redaction.values()),
        "missingRequiredEvidenceIds": missing_required_evidence_ids,
        "unmappedRequiredEvidenceIds": unmapped_required_evidence_ids,
        "unmappedGateIds": unmapped_gate_ids,
        "rowsWithoutDocs": rows_without_docs,
        "rowsWithoutOwners": rows_without_owners,
        "missingDocPaths": missing_doc_paths,
        "coveredFirstPartyApps": first_party_apps,
        "missingFirstPartyApps": missing_first_party_apps,
        "issueIds": coverage_issue_ids,
    }


def matrix_coverage_waiver_state(
    coverage: dict[str, Any], context: WaiverContext, mode: str
) -> tuple[list[WaiverRecord], list[str], list[str]]:
    issue_ids = [str(issue_id) for issue_id in coverage.get("issueIds", []) if issue_id]
    waivable_issue_ids = [issue_id for issue_id in issue_ids if issue_id != "matrix.redaction-failed"]
    records_by_id: dict[str, WaiverRecord] = {}
    waived_issue_ids: list[str] = []
    row_waiver = active_waiver_for(
        context,
        "ecosystem-certification-matrix",
        ["release-certification.ecosystem-matrix"],
        mode,
    )
    for issue_id in waivable_issue_ids:
        waiver = row_waiver or active_waiver_for(
            context, "ecosystem-certification-matrix", [issue_id], mode
        )
        if waiver is None:
            waiver = active_waiver_for(context, issue_id, None, mode)
        if waiver is None:
            continue
        records_by_id[waiver.id] = waiver
        waived_issue_ids.append(issue_id)
    waived_issue_ids = sorted(dict.fromkeys(waived_issue_ids))
    unwaived_issue_ids = sorted(issue_id for issue_id in issue_ids if issue_id not in waived_issue_ids)
    return [records_by_id[waiver_id] for waiver_id in sorted(records_by_id)], waived_issue_ids, unwaived_issue_ids


def matrix_redaction_summary(summary_redaction: dict[str, Any] | None = None) -> dict[str, bool]:
    source = summary_redaction if isinstance(summary_redaction, dict) else {}
    return {
        "secretMaterialRedacted": bool(source.get("secretMaterialRedacted", True)),
        "formPasswordsRedacted": bool(source.get("formPasswordsRedacted", True)),
        "appProcessTokensRedacted": bool(source.get("appProcessTokensRedacted", True)),
        "browserSessionTokensRedacted": bool(source.get("browserSessionTokensRedacted", True)),
        "rawRequestBodiesExcluded": bool(source.get("rawRequestBodiesExcluded", True)),
        "rawFeedBodiesExcluded": bool(source.get("rawFeedBodiesExcluded", True)),
        "privateInsertUrisExcluded": bool(source.get("privateInsertUrisExcluded", True)),
        "signatureValuesRedacted": bool(source.get("signatureValuesRedacted", True)),
        "absolutePathsSanitized": bool(source.get("absolutePathsSanitized", True)),
    }


def matrix_categories(specs: list[MatrixRowSpec], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    row_counts = {category: 0 for category in MATRIX_CATEGORY_TITLES}
    for row in rows:
        category = str(row.get("category", ""))
        row_counts[category] = row_counts.get(category, 0) + 1
    categories: list[dict[str, Any]] = []
    for spec in specs:
        if any(category.get("id") == spec.category for category in categories):
            continue
        categories.append(
            {
                "id": spec.category,
                "title": MATRIX_CATEGORY_TITLES.get(spec.category, spec.category),
                "rowCount": row_counts.get(spec.category, 0),
            }
        )
    return categories


def build_ecosystem_matrix(
    settings: Settings,
    evidence: list[EvidenceItem],
    previous_summary: dict[str, Any] | None,
    history_comparison: dict[str, Any],
    ecosystem_gates: list[GateResult],
    waiver_context: WaiverContext,
    generated_at: str,
    summary_redaction: dict[str, Any] | None = None,
) -> dict[str, Any]:
    specs = ecosystem_matrix_row_specs()
    evidence_entries = evidence_map_from_items(evidence)
    previous_evidence_entries = evidence_map_from_summary(previous_summary)
    gate_entries = {gate.id: gate.to_json() for gate in ecosystem_gates}
    previous_summary_present = previous_summary is not None
    previous_matrix_present = bool(
        isinstance(previous_summary, dict) and isinstance(previous_summary.get("ecosystemMatrix"), dict)
    )
    previous_row_statuses = previous_matrix_row_statuses(previous_summary)
    redaction = matrix_redaction_summary(summary_redaction)
    rows = [
        evaluate_matrix_row(
            spec,
            settings,
            evidence_entries,
            previous_evidence_entries,
            gate_entries,
            history_comparison,
            previous_summary_present,
            previous_matrix_present,
            previous_row_statuses,
            waiver_context,
            redaction,
        )
        for spec in specs
        ]
    coverage = validate_matrix_coverage(settings, specs, evidence_entries, gate_entries, redaction)
    coverage_waiver_records, waived_coverage_issue_ids, unwaived_coverage_issue_ids = matrix_coverage_waiver_state(
        coverage, waiver_context, settings.mode
    )
    coverage["waivedIssueIds"] = waived_coverage_issue_ids
    coverage["unwaivedIssueIds"] = unwaived_coverage_issue_ids
    coverage["coverageWaiverIds"] = [record.id for record in coverage_waiver_records]
    if coverage_waiver_records:
        coverage["waiverReasons"] = safe_waiver_summaries(coverage_waiver_records)
    for row in rows:
        if row["id"] == "ecosystem-certification-matrix" and coverage.get("issueIds"):
            row["issueIds"] = sorted(dict.fromkeys(row["issueIds"] + coverage["issueIds"]))
            row["details"]["coverageIssueIds"] = coverage["issueIds"]
            if waived_coverage_issue_ids:
                row["details"]["waivedCoverageIssueIds"] = waived_coverage_issue_ids
                row["details"]["waiverReasons"] = {
                    **(
                        row["details"].get("waiverReasons", {})
                        if isinstance(row["details"].get("waiverReasons"), dict)
                        else {}
                    ),
                    **safe_waiver_summaries(coverage_waiver_records),
                }
                row["waiverIds"] = sorted(
                    dict.fromkeys([*row.get("waiverIds", []), *coverage["coverageWaiverIds"]])
                )
            if unwaived_coverage_issue_ids and (
                settings.mode == "release-candidate" or coverage.get("redactionPassed") is False
            ):
                row["status"] = "fail"
                row["releaseBlocker"] = True
                row["summary"] = "Matrix coverage or redaction validation failed."
                row["recommendation"] = "Review failing evidence and rerun release certification."
            elif waived_coverage_issue_ids:
                row["status"] = "warn"
                row["releaseBlocker"] = False
                row["summary"] = "Matrix coverage validation produced waived warnings."
                row["recommendation"] = "Review waived evidence before release-candidate promotion."
            elif row["status"] == "pass":
                row["status"] = "warn"
                row["summary"] = "Matrix coverage validation produced warnings."
                row["recommendation"] = "Review warning evidence or record an approved waiver."
    counts = {status: 0 for status in CERT_STATUSES}
    release_blockers = 0
    waived_rows = 0
    for row in rows:
        if row["status"] == "skip" and row.get("requiredForReleaseCandidate") is False:
            counts["optionalSkips"] = counts.get("optionalSkips", 0) + 1
        else:
            counts[row["status"]] = counts.get(row["status"], 0) + 1
        if row.get("releaseBlocker"):
            release_blockers += 1
        if row.get("waiverIds"):
            waived_rows += 1
    counts["rows"] = len(rows)
    counts["releaseBlockers"] = release_blockers
    counts["waivedRows"] = waived_rows
    stable_required_blocking = required_stable_readiness_blocking(settings, rows)
    status = (
        "fail"
        if stable_required_blocking
        else matrix_status_from_counts(settings.mode, counts, coverage)
    )
    release_candidate_passed = status != "fail" and release_blockers == 0
    matrix_diffs = [
        {
            "rowId": row["id"],
            "previousStatus": row["previousStatus"],
            "currentStatus": row["status"],
            "regressionStatus": row["regressionStatus"],
        }
        for row in rows
        if row["regressionStatus"] in {"regressed-warning", "regressed-blocker", "new-row", "previous-missing"}
    ]
    matrix = {
        "schemaVersion": ECOSYSTEM_MATRIX_SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "kind": "ecosystem-certification-matrix",
        "mode": settings.mode,
        "status": status,
        "generatedAt": generated_at,
        "promotionDecision": (
            "block"
            if not release_candidate_passed
            else ("promote-with-warnings" if status == "warn" else "promote")
        ),
        "releaseCandidatePassed": release_candidate_passed,
        "workspaceRoot": "<repo>",
        "summaryPath": display_path(settings.out_dir / SUMMARY_FILE_NAME, settings.workspace_root, settings.out_dir),
        "reportPath": display_path(settings.out_dir / REPORT_FILE_NAME, settings.workspace_root, settings.out_dir),
        "matrixPath": display_path(
            settings.out_dir / ECOSYSTEM_MATRIX_FILE_NAME,
            settings.workspace_root,
            settings.out_dir,
        ),
        "matrixReportPath": display_path(
            settings.out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME,
            settings.workspace_root,
            settings.out_dir,
        ),
        "historyComparisonPath": display_path(
            settings.out_dir / HISTORY_COMPARISON_FILE_NAME,
            settings.workspace_root,
            settings.out_dir,
        ),
        "previousSummaryPresent": previous_summary_present,
        "previousMatrixPresent": previous_matrix_present,
        "counts": counts,
        "coverage": coverage,
        "categories": matrix_categories(specs, rows),
        "rows": rows,
        "matrixDiffs": matrix_diffs,
        "redaction": redaction,
    }
    return dict(sanitize_value(matrix, settings.workspace_root, settings.out_dir))


def matrix_compact_summary(matrix: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(matrix, dict):
        return {
            "schemaVersion": ECOSYSTEM_MATRIX_SCHEMA_VERSION,
            "status": "missing",
            "rowCount": 0,
            "releaseBlockerCount": 0,
            "coverage": {},
            "rowStatuses": {},
            "matrixDiffs": [],
        }
    rows = matrix.get("rows", [])
    row_statuses = {
        str(row.get("id")): str(row.get("status", "missing"))
        for row in rows
        if isinstance(row, dict) and row.get("id")
    } if isinstance(rows, list) else {}
    counts = matrix.get("counts", {}) if isinstance(matrix.get("counts"), dict) else {}
    return {
        "schemaVersion": matrix.get("schemaVersion", ECOSYSTEM_MATRIX_SCHEMA_VERSION),
        "status": matrix.get("status", "missing"),
        "rowCount": counts.get("rows", len(row_statuses)),
        "releaseBlockerCount": counts.get("releaseBlockers", 0),
        "coverage": matrix.get("coverage", {}) if isinstance(matrix.get("coverage"), dict) else {},
        "rowStatuses": row_statuses,
        "matrixDiffs": matrix.get("matrixDiffs", []) if isinstance(matrix.get("matrixDiffs"), list) else [],
    }


def stable_readiness_compact_summary(
    evidence: list[EvidenceItem],
    required: bool,
) -> dict[str, Any]:
    entries = evidence_map_from_items(evidence)
    main = entries.get("stable-1.0.readiness-gate")
    redaction = entries.get("stable-1.0.redaction")
    if not isinstance(main, dict):
        return {
            "status": "missing" if required else "skip",
            "decision": "not-attached",
            "stableReady": False,
            "required": required,
            "summary": (
                "Stable 1.0 readiness is required but not attached."
                if required
                else "Stable 1.0 readiness was not requested for this certification run."
            ),
        }
    details = evidence_details(main)
    redaction_details = evidence_details(redaction)
    return {
        "status": evidence_status(main),
        "decision": str(details.get("decision", "not-ready")),
        "stableReady": details.get("stableReady") is True,
        "required": required,
        "source": str(main.get("source", "")),
        "summary": str(main.get("summary", "")),
        "blockerCount": details.get("blockerCount", 0),
        "warningCount": details.get("warningCount", 0),
        "allowedLimitationCount": details.get("allowedLimitationCount", 0),
        "disallowedLimitationCount": details.get("disallowedLimitationCount", 0),
        "redactionStatus": evidence_status(redaction),
        "redactionFindingCount": redaction_details.get("findingCount", 0),
        "artifactRefs": details.get("artifactRefs", {}) if isinstance(details.get("artifactRefs"), dict) else {},
    }


def ecosystem_matrix_evidence(
    matrix: dict[str, Any],
    workspace_root: Path,
    out_dir: Path,
) -> EvidenceItem:
    status = normalize_evidence_status(str(matrix.get("status", "missing")))
    counts = matrix.get("counts", {}) if isinstance(matrix.get("counts"), dict) else {}
    coverage = matrix.get("coverage", {}) if isinstance(matrix.get("coverage"), dict) else {}
    return sanitize_evidence_item(
        EvidenceItem(
            "release-certification.ecosystem-matrix",
            status,
            True,
            f"Ecosystem certification matrix status is {status}.",
            display_path(out_dir / ECOSYSTEM_MATRIX_FILE_NAME, workspace_root, out_dir),
            {
                "matrixPath": display_path(out_dir / ECOSYSTEM_MATRIX_FILE_NAME, workspace_root, out_dir),
                "matrixReportPath": display_path(
                    out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME,
                    workspace_root,
                    out_dir,
                ),
                "schemaVersion": ECOSYSTEM_MATRIX_SCHEMA_VERSION,
                "rowCount": counts.get("rows", 0),
                "coverage": coverage,
                "redactionPassed": bool(coverage.get("redactionPassed", False)),
            },
        ),
        workspace_root,
        out_dir,
    )


def placeholder_ecosystem_matrix_evidence(workspace_root: Path, out_dir: Path) -> EvidenceItem:
    return sanitize_evidence_item(
        EvidenceItem(
            "release-certification.ecosystem-matrix",
            "pass",
            True,
            "Ecosystem certification matrix generation is pending.",
            display_path(out_dir / ECOSYSTEM_MATRIX_FILE_NAME, workspace_root, out_dir),
            {
                "matrixPath": display_path(out_dir / ECOSYSTEM_MATRIX_FILE_NAME, workspace_root, out_dir),
                "matrixReportPath": display_path(
                    out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME,
                    workspace_root,
                    out_dir,
                ),
                "schemaVersion": ECOSYSTEM_MATRIX_SCHEMA_VERSION,
            },
        ),
        workspace_root,
        out_dir,
    )


def ecosystem_rc_gate_evidence(
    gate: GateResult | None,
    workspace_root: Path,
    out_dir: Path,
) -> EvidenceItem:
    if gate is None:
        return placeholder_ecosystem_rc_gate_evidence(workspace_root, out_dir)
    waiver_ids = gate_waiver_ids(gate)
    compact_details = {
        key: gate.details.get(key)
        for key in (
            "phase",
            "requiredEvidenceIds",
            "requiredGateIds",
            "failedEvidenceIds",
            "warningEvidenceIds",
            "missingEvidenceIds",
            "skippedEvidenceIds",
            "blockingGateIds",
            "warningGateIds",
            "waivedEvidenceIds",
            "waivedGateIds",
            "historyComparisonStatus",
            "liveNetworkRequired",
            "liveNetworkSatisfied",
            "networkScaleSoakSatisfied",
            "redactionPassed",
            "redactionFailureEvidenceIds",
            "firstPartyAppsCovered",
            "promotionReady",
        )
        if key in gate.details
    }
    if waiver_ids:
        compact_details["waiverIds"] = waiver_ids
    details = {
        "gateId": gate.id,
        "releaseBlocker": gate.release_blocker,
        "promotionReady": bool(gate.details.get("promotionReady", not gate.release_blocker)),
        "failedEvidenceCount": len(gate.details.get("failedEvidenceIds", [])),
        "missingEvidenceCount": len(gate.details.get("missingEvidenceIds", [])),
        "warningEvidenceCount": len(gate.details.get("warningEvidenceIds", [])),
        "blockingGateCount": len(gate.details.get("blockingGateIds", [])),
        "warningGateCount": len(gate.details.get("warningGateIds", [])),
        "waiverCount": len(waiver_ids),
        "details": compact_details,
    }
    return sanitize_evidence_item(
        EvidenceItem(
            ECOSYSTEM_RC_EVIDENCE_ID,
            gate.status,
            True,
            gate.summary,
            display_path(out_dir / SUMMARY_FILE_NAME, workspace_root, out_dir),
            details,
        ),
        workspace_root,
        out_dir,
    )


def placeholder_ecosystem_rc_gate_evidence(workspace_root: Path, out_dir: Path) -> EvidenceItem:
    return sanitize_evidence_item(
        EvidenceItem(
            ECOSYSTEM_RC_EVIDENCE_ID,
            "pass",
            True,
            "Ecosystem RC certification gate evaluation is pending.",
            display_path(out_dir / SUMMARY_FILE_NAME, workspace_root, out_dir),
            {
                "gateId": ECOSYSTEM_RC_GATE_ID,
                "phase": "phase-9",
                "promotionReady": False,
            },
        ),
        workspace_root,
        out_dir,
    )


def release_metadata_note_present(metadata: dict[str, Any], *keys: str) -> bool:
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return True
        if isinstance(value, bool) and value:
            return True
    return False


def summary_identity(
    summary: dict[str, Any] | None,
    workspace_root: Path,
    out_dir: Path,
    source: str = "",
) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {"source": source} if source else {}
    metadata = summary.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    git_sha = (
        metadata.get("gitCommit")
        or metadata.get("githubSha")
        or summary.get("gitSha")
        or summary.get("commit")
        or ""
    )
    release_version = (
        metadata.get("releaseVersion")
        or metadata.get("version")
        or summary.get("releaseVersion")
        or summary.get("version")
        or ""
    )
    identity = {
        "source": source,
        "generatedAt": summary.get("generatedAt", ""),
        "gitSha": git_sha,
        "releaseVersion": release_version,
    }
    return {key: sanitize_value(value, workspace_root, out_dir) for key, value in identity.items()}


def current_identity(generated_at: str, metadata: dict[str, Any]) -> dict[str, Any]:
    git_sha = metadata.get("gitCommit") or metadata.get("githubSha") or ""
    release_version = metadata.get("releaseVersion") or metadata.get("version") or ""
    return {
        "generatedAt": generated_at,
        "gitSha": git_sha,
        "releaseVersion": release_version,
    }


def classify_evidence_diff(
    evidence_id: str,
    previous: dict[str, Any] | None,
    current: dict[str, Any] | None,
    waiver_context: WaiverContext,
    mode: str,
) -> dict[str, Any]:
    previous_status = evidence_status(previous)
    current_status = evidence_status(current)
    previous_present = previous is not None
    current_present = current is not None
    current_required = evidence_required(current)
    previous_required = evidence_required(previous)
    if not previous_present and current_present:
        classification = "new"
    elif previous_present and not current_present:
        classification = "removed"
    elif status_severity(current_status) > status_severity(previous_status):
        classification = "regression"
    elif status_severity(current_status) < status_severity(previous_status):
        classification = "improvement"
    else:
        classification = "unchanged"

    issue_ids = [
        f"history.{classification}.{evidence_id}",
        f"history.evidence.{evidence_id}",
        f"evidence.{evidence_id}",
        *ecosystem_matrix_row_ids_for_evidence(evidence_id),
    ]
    waived = bool(current and evidence_details(current).get("waived"))
    unwaivable_redaction_findings = evidence_entry_has_unwaivable_redaction_findings(current)
    waiver = (
        None
        if unwaivable_redaction_findings
        else active_waiver_for(waiver_context, evidence_id, issue_ids, mode)
    )
    release_blocker = False
    reason = "Evidence status is unchanged."
    if classification == "new":
        reason = "New evidence item is present in the current certification."
        if current_required and current_status in {"fail", "missing", "skip"}:
            release_blocker = True
            reason = "New required evidence is not passing."
        elif current_required and current_status == "warn":
            reason = "New required evidence is warning."
    elif classification == "removed":
        reason = "Evidence item was present in the previous certification but is absent now."
        release_blocker = previous_required
    elif classification == "regression":
        reason = f"Evidence regressed from {previous_status} to {current_status}."
        if (previous_required or current_required) and previous_status == "pass" and current_status in {
            "fail",
            "missing",
            "skip",
        }:
            release_blocker = True
        elif previous_required or current_required:
            reason = f"Required evidence regressed from {previous_status} to {current_status}."
    elif classification == "improvement":
        reason = f"Evidence improved from {previous_status} to {current_status}."

    if waiver is not None or waived:
        release_blocker = False
        if waiver is not None:
            reason = f"{reason} Waiver recorded: {waiver.reason}"

    return {
        "id": evidence_id,
        "previousStatus": previous_status if previous_present else "missing",
        "currentStatus": current_status if current_present else "missing",
        "classification": classification,
        "requiredForReleaseCandidate": bool(current_required or previous_required),
        "releaseBlocker": release_blocker,
        "reason": reason,
        "unwaivableRedactionFindings": unwaivable_redaction_findings,
    }


def load_previous_summary(settings: Settings) -> tuple[dict[str, Any] | None, str, str]:
    history_dir = resolve_path(settings.workspace_root, settings.history_dir)
    path: Path | None = settings.previous_summary
    if path is None:
        candidate = history_dir / "latest-summary.json"
        if candidate.is_file():
            path = candidate
    if path is None:
        return None, "", ""
    source = display_path(path, settings.workspace_root, settings.out_dir)
    value = read_json(path)
    if value is None:
        if path.is_file():
            return None, source, f"Previous summary {source} is malformed."
        return None, source, f"Previous summary {source} is missing."
    contract_error = previous_summary_contract_error(value)
    if contract_error:
        return None, source, f"Previous summary {source} is invalid: {contract_error}"
    sanitized = sanitize_value(value, settings.workspace_root, settings.out_dir)
    return sanitized if isinstance(sanitized, dict) else None, source, ""


def previous_summary_contract_error(value: dict[str, Any]) -> str:
    if value.get("kind") == multi_node_beta_soak.PREVIOUS_CANDIDATE_SUMMARY_KIND:
        return "previous beta candidate summaries are upgrade evidence, not release-certification history baselines"
    if value.get("tool") != TOOL_NAME:
        return "not a release-certification summary"
    if value.get("schemaVersion") != SCHEMA_VERSION:
        return "unsupported schema version"
    evidence = value.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return "missing evidence list"
    if not any(isinstance(entry, dict) and entry.get("id") for entry in evidence):
        return "evidence list has no evidence ids"
    return ""


def compare_history(
    settings: Settings,
    previous_summary: dict[str, Any] | None,
    previous_source: str,
    previous_error: str,
    current_evidence: list[EvidenceItem],
    generated_at: str,
    metadata: dict[str, Any],
    waiver_context: WaiverContext,
) -> dict[str, Any]:
    previous_identity = summary_identity(
        previous_summary, settings.workspace_root, settings.out_dir, previous_source
    )
    current = current_identity(generated_at, metadata)
    if previous_summary is None:
        if previous_error:
            status = "fail" if settings.mode == "release-candidate" or settings.require_history else "warn"
            summary = previous_error
        elif settings.require_history:
            status = "fail"
            summary = "Previous certified baseline is required but was not provided."
        elif settings.mode == "pr":
            status = "skip"
            summary = "Previous certified baseline was not provided."
        else:
            status = "warn"
            summary = "Previous certified baseline was not provided; historical regression context is unavailable."
        return {
            "version": 1,
            "status": status,
            "summary": summary,
            "previous": previous_identity,
            "current": current,
            "evidenceDiffs": [],
            "ecosystemGates": [],
            "waivers": [record.to_json() for record in waiver_context.records],
        }

    previous_evidence = evidence_map_from_summary(previous_summary)
    current_evidence_map = evidence_map_from_items(current_evidence)
    all_ids = sorted(set(previous_evidence) | set(current_evidence_map))
    diffs = [
        classify_evidence_diff(
            evidence_id,
            previous_evidence.get(evidence_id),
            current_evidence_map.get(evidence_id),
            waiver_context,
            settings.mode,
        )
        for evidence_id in all_ids
    ]
    has_blocker = any(diff["releaseBlocker"] for diff in diffs)
    has_warning = any(
        diff["classification"] in {"regression", "new", "removed"} and diff["currentStatus"] != "pass"
        for diff in diffs
    )
    status = "fail" if has_blocker else ("warn" if has_warning else "pass")
    return {
        "version": 1,
        "status": status,
        "summary": "Historical comparison completed." if status == "pass" else "Historical comparison found release-relevant changes.",
        "previous": previous_identity,
        "current": current,
        "evidenceDiffs": diffs,
        "ecosystemGates": [],
        "waivers": [record.to_json() for record in waiver_context.records],
    }


def gate_from_issues(gate_id: str, summary: str, failures: list[str], warnings: list[str], details: dict[str, Any]) -> GateResult:
    if failures:
        status = "fail"
        release_blocker = True
        message = f"{summary} Blockers: {'; '.join(failures)}"
    elif warnings:
        status = "warn"
        release_blocker = False
        message = f"{summary} Warnings: {'; '.join(warnings)}"
    else:
        status = "pass"
        release_blocker = False
        message = summary
    if failures:
        details["failures"] = failures
    if warnings:
        details["warnings"] = warnings
    issue_ids = [f"{gate_id}.{slugify_issue(issue)}" for issue in failures + warnings]
    if issue_ids:
        details["issueIds"] = issue_ids
    return GateResult(gate_id, status, release_blocker, message, details)


def add_evidence_issue(details: dict[str, Any], key: str, evidence_id: str) -> None:
    values = details.setdefault(key, [])
    if isinstance(values, list) and evidence_id not in values:
        values.append(evidence_id)


def slugify_issue(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:80] or "issue"


def evaluate_required_evidence_regressions(diffs: list[dict[str, Any]]) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details = {"regressions": [], "newRequiredEvidence": [], "removedEvidence": []}
    for diff in diffs:
        classification = diff["classification"]
        required = bool(diff.get("requiredForReleaseCandidate"))
        current_status = diff["currentStatus"]
        if classification == "regression" and required:
            details["regressions"].append(diff)
            if diff.get("releaseBlocker"):
                failures.append(f"{diff['id']} regressed from {diff['previousStatus']} to {current_status}")
                add_evidence_issue(details, "failureEvidenceIds", str(diff["id"]))
                if diff.get("unwaivableRedactionFindings"):
                    add_evidence_issue(details, "unwaivableFailureEvidenceIds", str(diff["id"]))
            else:
                warnings.append(f"{diff['id']} regressed from {diff['previousStatus']} to {current_status}")
                add_evidence_issue(details, "warningEvidenceIds", str(diff["id"]))
        elif classification == "regression":
            details["regressions"].append(diff)
            warnings.append(f"Optional evidence {diff['id']} regressed")
            add_evidence_issue(details, "warningEvidenceIds", str(diff["id"]))
        elif classification == "new" and required:
            details["newRequiredEvidence"].append(diff)
            if current_status in {"fail", "missing", "skip"}:
                failures.append(f"New required evidence {diff['id']} is {current_status}")
                add_evidence_issue(details, "failureEvidenceIds", str(diff["id"]))
                if diff.get("unwaivableRedactionFindings"):
                    add_evidence_issue(details, "unwaivableFailureEvidenceIds", str(diff["id"]))
            elif current_status == "warn":
                warnings.append(f"New required evidence {diff['id']} is warning")
                add_evidence_issue(details, "warningEvidenceIds", str(diff["id"]))
        elif classification == "removed":
            details["removedEvidence"].append(diff)
            if required and diff.get("releaseBlocker"):
                failures.append(f"Required evidence {diff['id']} was removed")
                add_evidence_issue(details, "failureEvidenceIds", str(diff["id"]))
            elif required:
                warnings.append(f"Required evidence {diff['id']} was removed")
                add_evidence_issue(details, "warningEvidenceIds", str(diff["id"]))
            else:
                warnings.append(f"Optional evidence {diff['id']} was removed")
                add_evidence_issue(details, "warningEvidenceIds", str(diff["id"]))
    return gate_from_issues(
        "ecosystem.required-evidence-regressions",
        "Required release-candidate evidence did not regress.",
        failures,
        warnings,
        details,
    )


def evaluate_platform_api_gate(
    current: dict[str, dict[str, Any]],
    previous: dict[str, dict[str, Any]],
    mode: str,
    require_history: bool,
) -> GateResult:
    current_item = current.get("platform-api.contract")
    previous_item = previous.get("platform-api.contract")
    current_status = evidence_status(current_item)
    details = {"currentStatus": current_status}
    failures: list[str] = []
    warnings: list[str] = []
    if current_status in {"fail", "missing", "skip"}:
        failures.append("Platform API contract evidence is not passing")
    elif current_status == "warn":
        warnings.append("Platform API contract evidence is warning")
    for evidence_id in PLATFORM_API_STABLE_FREEZE_EVIDENCE_IDS:
        evidence = current.get(evidence_id)
        status = evidence_status(evidence)
        details.setdefault("stableFreezeEvidence", {})[evidence_id] = status
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            if mode == "release-candidate" and require_history:
                failures.append(f"{evidence_id} evidence is warning in release-candidate mode")
                add_evidence_issue(details, "failureEvidenceIds", evidence_id)
            else:
                warnings.append(f"{evidence_id} evidence is warning")
                add_evidence_issue(details, "warningEvidenceIds", evidence_id)
    current_details = evidence_details(current_item)
    previous_details = evidence_details(previous_item)
    current_baseline_reported = stable_baseline_reported(current_details)
    previous_baseline_reported = stable_baseline_reported(previous_details)
    current_window = current_details.get("compatibilityWindow")
    previous_window = previous_details.get("compatibilityWindow")
    if not isinstance(current_window, dict):
        failures.append("Current Platform API compatibility-window metadata is unavailable")
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.compatibility-window")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.compatibility-window"
        )
        current_window = {}
    if current_window.get("criticalStableRemovalWaiverAllowed") is not False:
        failures.append("Critical stable API removal waiver policy is not explicitly rejected")
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.deprecation-window-policy")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.deprecation-window-policy"
        )
    if previous_details and not isinstance(previous_window, dict):
        message = "Previous Platform API compatibility-window metadata is unavailable"
        if mode == "release-candidate" and require_history:
            failures.append(message)
            add_evidence_issue(
                details, "failureEvidenceIds", "platform-api.previous-contract-snapshot"
            )
            add_evidence_issue(
                details,
                "unwaivableFailureEvidenceIds",
                "platform-api.previous-contract-snapshot",
            )
        else:
            warnings.append(message)
            add_evidence_issue(
                details, "warningEvidenceIds", "platform-api.previous-contract-snapshot"
            )
    elif isinstance(previous_window, dict):
        previous_baseline_name = previous_window.get("baselineName")
        current_baseline_name = current_window.get("baselineName")
        previous_baseline_contract = previous_window.get("baselineContractVersion")
        current_baseline_contract = current_window.get("baselineContractVersion")
        if (
            previous_baseline_name != current_baseline_name
            or previous_baseline_contract != current_baseline_contract
        ):
            failures.append("Platform API compatibility-window baseline identity changed")
            add_evidence_issue(
                details, "failureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
            add_evidence_issue(
                details,
                "unwaivableFailureEvidenceIds",
                "platform-api.stable-breaking-change-check",
            )
    details["current"] = {
        "contractVersion": current_details.get("contractVersion"),
        "endpointCount": current_details.get("endpointCount"),
        "capabilityCount": current_details.get("capabilityCount"),
        "compatibilityWindow": current_window,
        "stableDescriptorCount": stable_descriptor_count(current_details),
        "stableBaselineCapabilityCount": stable_baseline_count(
            current_details,
            "capabilityCount",
            "stableBaselineCapabilityCount",
            "capabilities",
            "stableBaselineCapabilities",
        ),
        "stableBaselineEndpointCount": stable_baseline_count(
            current_details,
            "endpointCount",
            "stableBaselineEndpointCount",
            "endpoints",
            "stableBaselineEndpoints",
        ),
        "stableEndpointCapabilitySetCount": len(stable_endpoint_capability_map(current_details)),
        "stableEndpointActionLabelSetCount": len(stable_endpoint_action_label_map(current_details)),
        "stableEndpointAppAccessSetCount": len(stable_endpoint_access_map(current_details)),
        "flaggedStability": current_details.get("flaggedStability", []),
    }
    if previous_details:
        details["previous"] = {
            "contractVersion": previous_details.get("contractVersion"),
            "endpointCount": previous_details.get("endpointCount"),
            "capabilityCount": previous_details.get("capabilityCount"),
            "compatibilityWindow": previous_window if isinstance(previous_window, dict) else None,
            "stableDescriptorCount": stable_descriptor_count(previous_details),
            "stableBaselineCapabilityCount": stable_baseline_count(
                previous_details,
                "capabilityCount",
                "stableBaselineCapabilityCount",
                "capabilities",
                "stableBaselineCapabilities",
            ),
            "stableBaselineEndpointCount": stable_baseline_count(
                previous_details,
                "endpointCount",
                "stableBaselineEndpointCount",
                "endpoints",
                "stableBaselineEndpoints",
            ),
            "stableEndpointCapabilitySetCount": len(stable_endpoint_capability_map(previous_details)),
            "stableEndpointActionLabelSetCount": len(
                stable_endpoint_action_label_map(previous_details)
            ),
            "stableEndpointAppAccessSetCount": len(stable_endpoint_access_map(previous_details)),
        }
    previous_version = detail_int(previous_details, "contractVersion")
    current_version = detail_int(current_details, "contractVersion")
    if previous_version is not None and current_version is not None and current_version < previous_version:
        failures.append(f"Contract version moved backward from {previous_version} to {current_version}")
    if current_baseline_reported and previous_details and not previous_baseline_reported:
        if mode == "release-candidate" and require_history:
            failures.append(
                "Previous Platform API stable baseline metadata is unavailable; "
                "stable baseline comparison is required"
            )
            add_evidence_issue(
                details, "failureEvidenceIds", "platform-api.previous-contract-snapshot"
            )
            add_evidence_issue(
                details, "failureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
            add_evidence_issue(
                details,
                "unwaivableFailureEvidenceIds",
                "platform-api.previous-contract-snapshot",
            )
            add_evidence_issue(
                details,
                "unwaivableFailureEvidenceIds",
                "platform-api.stable-breaking-change-check",
            )
        else:
            warnings.append(
                "Previous Platform API stable baseline metadata is unavailable; "
                "stable baseline comparison is status-limited"
            )
            add_evidence_issue(
                details, "warningEvidenceIds", "platform-api.stable-breaking-change-check"
            )
    compared_stable_baseline_counts = False
    if current_baseline_reported and previous_baseline_reported:
        for baseline_count_key, explicit_count_key, label in (
            ("endpointCount", "stableBaselineEndpointCount", "endpoint"),
            ("capabilityCount", "stableBaselineCapabilityCount", "capability"),
        ):
            previous_count = stable_baseline_count(
                previous_details,
                baseline_count_key,
                explicit_count_key,
                "endpoints" if label == "endpoint" else "capabilities",
                "stableBaselineEndpoints" if label == "endpoint" else "stableBaselineCapabilities",
            )
            current_count = stable_baseline_count(
                current_details,
                baseline_count_key,
                explicit_count_key,
                "endpoints" if label == "endpoint" else "capabilities",
                "stableBaselineEndpoints" if label == "endpoint" else "stableBaselineCapabilities",
            )
            if previous_count is None or current_count is None:
                continue
            compared_stable_baseline_counts = True
            if current_count < previous_count:
                failures.append(
                    f"Stable baseline {label} count decreased from {previous_count} to {current_count}"
                )
                add_evidence_issue(
                    details, "failureEvidenceIds", "platform-api.stable-breaking-change-check"
                )
                add_evidence_issue(
                    details,
                    "unwaivableFailureEvidenceIds",
                    "platform-api.stable-breaking-change-check",
                )
    if (
        not compared_stable_baseline_counts
        and not current_baseline_reported
        and not previous_baseline_reported
    ):
        previous_stable_count = stable_descriptor_count(previous_details)
        current_stable_count = stable_descriptor_count(current_details)
        if (
            previous_stable_count is not None
            and current_stable_count is not None
            and current_stable_count < previous_stable_count
        ):
            failures.append(
                "Stable Platform API descriptor count decreased from "
                f"{previous_stable_count} to {current_stable_count}"
            )
    if current_baseline_reported or previous_baseline_reported:
        previous_endpoints = stable_baseline_named_set(
            previous_details,
            "endpoints",
            "stableBaselineEndpoints",
            "stableEndpoints",
            "endpoints",
        )
        current_endpoints = stable_baseline_named_set(
            current_details,
            "endpoints",
            "stableBaselineEndpoints",
            "stableEndpoints",
            "endpoints",
        )
        current_endpoints_reported = stable_baseline_named_set_reported(
            current_details, "endpoints", "stableBaselineEndpoints"
        )
    else:
        previous_endpoints = stable_named_set(previous_details, "stableEndpoints", "endpoints")
        current_endpoints = stable_named_set(current_details, "stableEndpoints", "endpoints")
        current_endpoints_reported = stable_named_set_reported(
            current_details, "stableEndpoints", "endpoints"
        )
    removed_endpoints = (
        sorted(previous_endpoints - current_endpoints)
        if previous_endpoints
        and current_endpoints_reported
        and (previous_baseline_reported or not current_baseline_reported)
        else []
    )
    if removed_endpoints:
        failures.append(f"Stable endpoints were removed: {', '.join(removed_endpoints)}")
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
        )
    previous_endpoint_metadata_keys = stable_endpoint_metadata_keys(previous_details)
    current_endpoint_metadata_keys = stable_endpoint_metadata_keys(current_details)
    previous_endpoint_capabilities = stable_endpoint_capability_map(previous_details)
    current_endpoint_capabilities = stable_endpoint_capability_map(current_details)
    previous_endpoint_capabilities_reported = stable_endpoint_capability_map_reported(previous_details)
    current_endpoint_capabilities_reported = stable_endpoint_capability_map_reported(current_details)
    missing_current_endpoint_capabilities = sorted(
        current_endpoint_metadata_keys - set(current_endpoint_capabilities)
    )
    missing_previous_endpoint_capabilities = sorted(
        previous_endpoint_metadata_keys - set(previous_endpoint_capabilities)
    )
    current_endpoint_capability_count_gap = stable_endpoint_metadata_count_gap(
        current_details, current_endpoint_capabilities
    )
    previous_endpoint_capability_count_gap = stable_endpoint_metadata_count_gap(
        previous_details, previous_endpoint_capabilities
    )
    if current_endpoints and not current_endpoint_capabilities_reported:
        failures.append("Current stable endpoint required-capability metadata is unavailable")
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
        )
    elif missing_current_endpoint_capabilities or current_endpoint_capability_count_gap:
        if missing_current_endpoint_capabilities:
            failures.append(
                "Current stable endpoint required-capability metadata is incomplete: "
                + ", ".join(missing_current_endpoint_capabilities)
            )
            details["stableEndpointRequiredCapabilitiesMissing"] = (
                missing_current_endpoint_capabilities
            )
        else:
            failures.append(
                "Current stable endpoint required-capability metadata is incomplete: "
                f"expected {current_endpoint_capability_count_gap['expected']} entries, "
                f"found {current_endpoint_capability_count_gap['actual']}"
            )
            details["stableEndpointRequiredCapabilitiesExpectedCount"] = (
                current_endpoint_capability_count_gap["expected"]
            )
            details["stableEndpointRequiredCapabilitiesSetCount"] = (
                current_endpoint_capability_count_gap["actual"]
            )
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
        )
    elif previous_endpoints and previous_baseline_reported and (
        not previous_endpoint_capabilities_reported
        or missing_previous_endpoint_capabilities
        or previous_endpoint_capability_count_gap
    ):
        if previous_endpoint_capabilities_reported:
            if missing_previous_endpoint_capabilities:
                message = (
                    "Previous stable endpoint required-capability metadata is incomplete: "
                    + ", ".join(missing_previous_endpoint_capabilities)
                )
                details["previousStableEndpointRequiredCapabilitiesMissing"] = (
                    missing_previous_endpoint_capabilities
                )
            else:
                message = (
                    "Previous stable endpoint required-capability metadata is incomplete: "
                    f"expected {previous_endpoint_capability_count_gap['expected']} entries, "
                    f"found {previous_endpoint_capability_count_gap['actual']}"
                )
                details["previousStableEndpointRequiredCapabilitiesExpectedCount"] = (
                    previous_endpoint_capability_count_gap["expected"]
                )
                details["previousStableEndpointRequiredCapabilitiesSetCount"] = (
                    previous_endpoint_capability_count_gap["actual"]
                )
        else:
            message = "Previous stable endpoint required-capability metadata is unavailable"
        if mode == "release-candidate" and require_history:
            failures.append(message)
            add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
            add_evidence_issue(
                details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
        else:
            warnings.append(message)
            add_evidence_issue(details, "warningEvidenceIds", "platform-api.stable-breaking-change-check")
    elif (
        previous_endpoint_capabilities
        and current_endpoint_capabilities_reported
        and (previous_baseline_reported or not current_baseline_reported)
    ):
        changed_endpoint_capabilities = []
        for endpoint in sorted(set(previous_endpoint_capabilities) & set(current_endpoint_capabilities)):
            previous_caps = previous_endpoint_capabilities[endpoint]
            current_caps = current_endpoint_capabilities[endpoint]
            if previous_caps != current_caps:
                changed_endpoint_capabilities.append(
                    {
                        "endpoint": endpoint,
                        "previous": list(previous_caps),
                        "current": list(current_caps),
                    }
                )
        if changed_endpoint_capabilities:
            failures.append(
                "Stable endpoint required capabilities changed: "
                + ", ".join(change["endpoint"] for change in changed_endpoint_capabilities)
            )
            add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
            add_evidence_issue(
                details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
            details["stableEndpointCapabilityChanges"] = changed_endpoint_capabilities
    previous_endpoint_access = stable_endpoint_access_map(previous_details)
    current_endpoint_access = stable_endpoint_access_map(current_details)
    previous_endpoint_access_reported = stable_endpoint_access_map_reported(previous_details)
    current_endpoint_access_reported = stable_endpoint_access_map_reported(current_details)
    missing_current_endpoint_access = sorted(current_endpoint_metadata_keys - set(current_endpoint_access))
    missing_previous_endpoint_access = sorted(previous_endpoint_metadata_keys - set(previous_endpoint_access))
    current_endpoint_access_count_gap = stable_endpoint_metadata_count_gap(
        current_details, current_endpoint_access
    )
    previous_endpoint_access_count_gap = stable_endpoint_metadata_count_gap(
        previous_details, previous_endpoint_access
    )
    if current_endpoints and not current_endpoint_access_reported:
        failures.append("Current stable endpoint app-principal access metadata is unavailable")
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
        )
    elif missing_current_endpoint_access or current_endpoint_access_count_gap:
        if missing_current_endpoint_access:
            failures.append(
                "Current stable endpoint app-principal access metadata is incomplete: "
                + ", ".join(missing_current_endpoint_access)
            )
            details["stableEndpointAppAccessMissing"] = missing_current_endpoint_access
        else:
            failures.append(
                "Current stable endpoint app-principal access metadata is incomplete: "
                f"expected {current_endpoint_access_count_gap['expected']} entries, "
                f"found {current_endpoint_access_count_gap['actual']}"
            )
            details["stableEndpointAppAccessExpectedCount"] = (
                current_endpoint_access_count_gap["expected"]
            )
            details["stableEndpointAppAccessSetCount"] = current_endpoint_access_count_gap[
                "actual"
            ]
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
        )
    elif previous_endpoints and previous_baseline_reported and (
        not previous_endpoint_access_reported
        or missing_previous_endpoint_access
        or previous_endpoint_access_count_gap
    ):
        if previous_endpoint_access_reported:
            if missing_previous_endpoint_access:
                message = (
                    "Previous stable endpoint app-principal access metadata is incomplete: "
                    + ", ".join(missing_previous_endpoint_access)
                )
                details["previousStableEndpointAppAccessMissing"] = missing_previous_endpoint_access
            else:
                message = (
                    "Previous stable endpoint app-principal access metadata is incomplete: "
                    f"expected {previous_endpoint_access_count_gap['expected']} entries, "
                    f"found {previous_endpoint_access_count_gap['actual']}"
                )
                details["previousStableEndpointAppAccessExpectedCount"] = (
                    previous_endpoint_access_count_gap["expected"]
                )
                details["previousStableEndpointAppAccessSetCount"] = (
                    previous_endpoint_access_count_gap["actual"]
                )
        else:
            message = "Previous stable endpoint app-principal access metadata is unavailable"
        if mode == "release-candidate" and require_history:
            failures.append(message)
            add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
            add_evidence_issue(
                details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
        else:
            warnings.append(message)
            add_evidence_issue(details, "warningEvidenceIds", "platform-api.stable-breaking-change-check")
    elif (
        previous_endpoint_access
        and current_endpoint_access_reported
        and (previous_baseline_reported or not current_baseline_reported)
    ):
        changed_endpoint_access = []
        for endpoint in sorted(set(previous_endpoint_access) & set(current_endpoint_access)):
            previous_access = previous_endpoint_access[endpoint]
            current_access = current_endpoint_access[endpoint]
            if previous_access != current_access:
                changed_endpoint_access.append(
                    {
                        "endpoint": endpoint,
                        "previous": endpoint_access_detail(previous_access),
                        "current": endpoint_access_detail(current_access),
                    }
                )
        if changed_endpoint_access:
            failures.append(
                "Stable endpoint app-principal access changed: "
                + ", ".join(change["endpoint"] for change in changed_endpoint_access)
            )
            add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
            add_evidence_issue(
                details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
            details["stableEndpointAccessChanges"] = changed_endpoint_access
    previous_endpoint_action_labels = stable_endpoint_action_label_map(previous_details)
    current_endpoint_action_labels = stable_endpoint_action_label_map(current_details)
    previous_endpoint_action_labels_reported = stable_endpoint_action_label_map_reported(
        previous_details
    )
    current_endpoint_action_labels_reported = stable_endpoint_action_label_map_reported(
        current_details
    )
    missing_current_endpoint_action_labels = sorted(
        current_endpoint_metadata_keys - set(current_endpoint_action_labels)
    )
    missing_previous_endpoint_action_labels = sorted(
        previous_endpoint_metadata_keys - set(previous_endpoint_action_labels)
    )
    current_endpoint_action_label_count_gap = stable_endpoint_metadata_count_gap(
        current_details, current_endpoint_action_labels
    )
    previous_endpoint_action_label_count_gap = stable_endpoint_metadata_count_gap(
        previous_details, previous_endpoint_action_labels
    )
    if current_endpoints and not current_endpoint_action_labels_reported:
        failures.append("Current stable endpoint action-label metadata is unavailable")
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
        )
    elif missing_current_endpoint_action_labels or current_endpoint_action_label_count_gap:
        if missing_current_endpoint_action_labels:
            failures.append(
                "Current stable endpoint action-label metadata is incomplete: "
                + ", ".join(missing_current_endpoint_action_labels)
            )
            details["stableEndpointActionLabelsMissing"] = (
                missing_current_endpoint_action_labels
            )
        else:
            failures.append(
                "Current stable endpoint action-label metadata is incomplete: "
                f"expected {current_endpoint_action_label_count_gap['expected']} entries, "
                f"found {current_endpoint_action_label_count_gap['actual']}"
            )
            details["stableEndpointActionLabelsExpectedCount"] = (
                current_endpoint_action_label_count_gap["expected"]
            )
            details["stableEndpointActionLabelsSetCount"] = (
                current_endpoint_action_label_count_gap["actual"]
            )
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
        )
    elif previous_endpoints and previous_baseline_reported and (
        not previous_endpoint_action_labels_reported
        or missing_previous_endpoint_action_labels
        or previous_endpoint_action_label_count_gap
    ):
        if previous_endpoint_action_labels_reported:
            if missing_previous_endpoint_action_labels:
                message = (
                    "Previous stable endpoint action-label metadata is incomplete: "
                    + ", ".join(missing_previous_endpoint_action_labels)
                )
                details["previousStableEndpointActionLabelsMissing"] = (
                    missing_previous_endpoint_action_labels
                )
            else:
                message = (
                    "Previous stable endpoint action-label metadata is incomplete: "
                    f"expected {previous_endpoint_action_label_count_gap['expected']} entries, "
                    f"found {previous_endpoint_action_label_count_gap['actual']}"
                )
                details["previousStableEndpointActionLabelsExpectedCount"] = (
                    previous_endpoint_action_label_count_gap["expected"]
                )
                details["previousStableEndpointActionLabelsSetCount"] = (
                    previous_endpoint_action_label_count_gap["actual"]
                )
        else:
            message = "Previous stable endpoint action-label metadata is unavailable"
        if mode == "release-candidate" and require_history:
            failures.append(message)
            add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
            add_evidence_issue(
                details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
        else:
            warnings.append(message)
            add_evidence_issue(details, "warningEvidenceIds", "platform-api.stable-breaking-change-check")
    elif (
        previous_endpoint_action_labels
        and current_endpoint_action_labels_reported
        and (previous_baseline_reported or not current_baseline_reported)
    ):
        missing_endpoint_action_labels = sorted(
            set(previous_endpoint_action_labels) - set(current_endpoint_action_labels)
        )
        if missing_endpoint_action_labels:
            failures.append(
                "Current stable endpoint action-label metadata is incomplete: "
                + ", ".join(missing_endpoint_action_labels)
            )
            add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
            add_evidence_issue(
                details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
            details["stableEndpointActionLabelsMissing"] = missing_endpoint_action_labels
        changed_endpoint_action_labels = []
        for endpoint in sorted(
            set(previous_endpoint_action_labels) & set(current_endpoint_action_labels)
        ):
            previous_label = previous_endpoint_action_labels[endpoint]
            current_label = current_endpoint_action_labels[endpoint]
            if previous_label != current_label:
                changed_endpoint_action_labels.append(
                    {
                        "endpoint": endpoint,
                        "previous": previous_label,
                        "current": current_label,
                    }
                )
        if changed_endpoint_action_labels:
            failures.append(
                "Stable endpoint action labels changed: "
                + ", ".join(change["endpoint"] for change in changed_endpoint_action_labels)
            )
            add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
            add_evidence_issue(
                details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
            details["stableEndpointActionLabelChanges"] = changed_endpoint_action_labels
    if current_baseline_reported or previous_baseline_reported:
        previous_capabilities = stable_baseline_named_set(
            previous_details,
            "capabilities",
            "stableBaselineCapabilities",
            "stableCapabilities",
            "capabilities",
        )
        current_capabilities = stable_baseline_named_set(
            current_details,
            "capabilities",
            "stableBaselineCapabilities",
            "stableCapabilities",
            "capabilities",
        )
        current_capabilities_reported = stable_baseline_named_set_reported(
            current_details, "capabilities", "stableBaselineCapabilities"
        )
    else:
        previous_capabilities = stable_named_set(previous_details, "stableCapabilities", "capabilities")
        current_capabilities = stable_named_set(current_details, "stableCapabilities", "capabilities")
        current_capabilities_reported = stable_named_set_reported(
            current_details, "stableCapabilities", "capabilities"
        )
    removed_capabilities = (
        sorted(previous_capabilities - current_capabilities)
        if previous_capabilities
        and current_capabilities_reported
        and (previous_baseline_reported or not current_baseline_reported)
        else []
    )
    if removed_capabilities:
        failures.append(f"Stable capabilities were removed: {', '.join(removed_capabilities)}")
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
        )
    if current_details.get("flaggedStability"):
        warnings.append("Contract evidence contains stability warnings")
    if not previous_details:
        if mode == "release-candidate" and require_history:
            failures.append("Previous Platform API contract details were unavailable; stable baseline comparison is required")
            add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
            add_evidence_issue(
                details,
                "unwaivableFailureEvidenceIds",
                "platform-api.stable-breaking-change-check",
            )
        else:
            warnings.append("Previous Platform API contract details were unavailable; comparison is status-limited")
            add_evidence_issue(details, "warningEvidenceIds", "platform-api.stable-breaking-change-check")
    if failures:
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.contract")
    if warnings:
        add_evidence_issue(details, "warningEvidenceIds", "platform-api.contract")
    return gate_from_issues(
        "ecosystem.platform-api-compatibility",
        "Platform API compatibility evidence is stable.",
        failures,
        warnings,
        details,
    )


def evaluate_first_party_apps_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    current_item = current.get("app-platform.first-party")
    previous_item = previous.get("app-platform.first-party")
    beta_quality_item = current.get(FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID)
    beta_quality_details = evidence_details(beta_quality_item)
    current_details = evidence_details(current_item)
    previous_details = evidence_details(previous_item)
    current_apps = app_ids_from_details(current_details)
    previous_apps = app_ids_from_details(previous_details)
    required_apps = set(EXPECTED_FIRST_PARTY_APPS)
    failures: list[str] = []
    warnings: list[str] = []
    status = evidence_status(current_item)
    if status in {"fail", "missing", "skip"}:
        failures.append("First-party app evidence is not passing")
    elif status == "warn":
        warnings.append("First-party app evidence is warning")
    beta_quality_status = evidence_status(beta_quality_item)
    if beta_quality_status in {"fail", "missing", "skip"}:
        failures.append("First-party beta-quality evidence is not passing")
    elif beta_quality_status == "warn":
        warnings.append("First-party beta-quality evidence is warning")
    missing_required = sorted(required_apps - current_apps)
    if missing_required:
        failures.append(f"Required first-party apps are absent: {', '.join(missing_required)}")
    disappeared = sorted(previous_apps - current_apps) if previous_apps else []
    if disappeared:
        failures.append(f"Previously certified first-party apps disappeared: {', '.join(disappeared)}")
    gate_details = {
        "currentApps": sorted(current_apps),
        "previousApps": sorted(previous_apps),
        "requiredApps": sorted(required_apps),
        "betaQualityStatus": beta_quality_status,
    }
    if status in {"fail", "missing", "skip"} or missing_required or disappeared:
        add_evidence_issue(gate_details, "failureEvidenceIds", "app-platform.first-party")
    if beta_quality_status in {"fail", "missing", "skip"}:
        add_evidence_issue(
            gate_details, "failureEvidenceIds", FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID
        )
    if status == "warn":
        add_evidence_issue(gate_details, "warningEvidenceIds", "app-platform.first-party")
    if beta_quality_status == "warn":
        add_evidence_issue(
            gate_details, "warningEvidenceIds", FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID
        )
    if beta_quality_details.get("redactionFindings"):
        add_evidence_issue(
            gate_details, "unwaivableFailureEvidenceIds", FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID
        )
    return gate_from_issues(
        "ecosystem.first-party-apps",
        "First-party app evidence covers required apps.",
        failures,
        warnings,
        gate_details,
    )


def evaluate_app_ui_quality_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}
    for evidence_id in ("app-ui.lint", "app-ui.design-system", "app-ui.first-party-adoption"):
        status = evidence_status(current.get(evidence_id))
        previous_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {"currentStatus": status, "previousStatus": previous_status}
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_status == "pass" and status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    current_warnings = total_ui_warnings(evidence_details(current.get("app-ui.lint")))
    previous_warnings = total_ui_warnings(evidence_details(previous.get("app-ui.lint")))
    details["lintWarnings"] = {"current": current_warnings, "previous": previous_warnings}
    if current_warnings is not None and previous_warnings is not None and current_warnings > previous_warnings:
        warnings.append(f"UI lint warnings increased from {previous_warnings} to {current_warnings}")
        add_evidence_issue(details, "warningEvidenceIds", "app-ui.lint")
    return gate_from_issues(
        "ecosystem.app-ui-quality",
        "First-party app UI lint and design-system evidence passed.",
        failures,
        warnings,
        details,
    )


def evaluate_app_review_trust_gate(
    current: dict[str, dict[str, Any]],
    previous: dict[str, dict[str, Any]],
    metadata: dict[str, Any],
    mode: str,
) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}
    for evidence_id in (
        "app-review.trusted-receipts",
        "app-review.policy",
        "app-review.governance",
        "app-review.reviewer-key-lifecycle",
        "app-review.transparency-log",
        "app-review.review-history-api",
        "app-review.first-party-catalog",
        "app-review.first-party-review-chain",
    ):
        status = evidence_status(current.get(evidence_id))
        previous_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {"currentStatus": status, "previousStatus": previous_status}
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_status == "pass" and status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    catalog_details = evidence_details(current.get("app-review.first-party-catalog"))
    coverage = nested_dict(catalog_details, "coverage")
    first_party_apps = sorted_strings(catalog_details.get("firstPartyApps"))
    trusted_positive = int_value(coverage.get("trustedPositiveReceipts"))
    missing_receipts = int_value(coverage.get("missingReceipts"))
    details["firstPartyReceiptCoverage"] = {
        "firstPartyApps": first_party_apps,
        "trustedPositiveReceipts": trusted_positive,
        "missingReceipts": missing_receipts,
    }
    if mode == "release-candidate":
        if trusted_positive is None or trusted_positive < len(first_party_apps):
            failures.append("First-party catalog lacks trusted positive review receipts for every app")
            add_evidence_issue(details, "failureEvidenceIds", "app-review.first-party-catalog")
        if missing_receipts and missing_receipts > 0:
            failures.append("First-party catalog has missing trusted review receipts")
            add_evidence_issue(details, "failureEvidenceIds", "app-review.first-party-catalog")
    policy_details = evidence_details(current.get("app-review.policy"))
    previous_policy_details = evidence_details(previous.get("app-review.policy"))
    policy_marker = policy_details.get("policyId") or policy_details.get("policyVersion") or policy_details.get("mode")
    previous_policy_marker = (
        previous_policy_details.get("policyId")
        or previous_policy_details.get("policyVersion")
        or previous_policy_details.get("mode")
    )
    if previous_policy_marker and policy_marker and previous_policy_marker != policy_marker:
        if not release_metadata_note_present(metadata, "releaseNotes", "reviewPolicyChange", "reviewPolicyVersion"):
            warnings.append("Review policy marker changed without release-note metadata")
            add_evidence_issue(details, "warningEvidenceIds", "app-review.policy")
    return gate_from_issues(
        "ecosystem.app-review-trust",
        "Trusted app-review receipt and policy evidence passed.",
        failures,
        warnings,
        details,
    )


def evaluate_app_update_rollback_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}
    for evidence_id in (
        "app-update.lifecycle",
        "app-update.scheduler",
        "app-update.live-catalog-refresh",
        "app-update.rollback",
        "app-update.data-migration-contract",
    ):
        status = evidence_status(current.get(evidence_id))
        previous_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {"currentStatus": status, "previousStatus": previous_status}
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_status == "pass" and status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    rollback_details = evidence_details(current.get("app-update.rollback"))
    details["rollbackScope"] = rollback_details.get("rollbackScope")
    details["preservesDataCacheRun"] = rollback_details.get("preservesDataCacheRun")
    if rollback_details.get("rollbackScope") != "installed-bundle-only":
        warnings.append("Rollback evidence does not prove installed-bundle-only scope")
        add_evidence_issue(details, "warningEvidenceIds", "app-update.rollback")
    if rollback_details.get("preservesDataCacheRun") is not True:
        warnings.append("Rollback evidence does not prove data/cache/run preservation")
        add_evidence_issue(details, "warningEvidenceIds", "app-update.rollback")
    return gate_from_issues(
        "ecosystem.app-update-rollback",
        "App-update lifecycle, scheduler, and rollback evidence passed.",
        failures,
        warnings,
        details,
    )


def evaluate_operator_rc_recovery_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {"evidenceIds": list(OPERATOR_RC_EVIDENCE_IDS)}
    for evidence_id in OPERATOR_RC_EVIDENCE_IDS:
        status = evidence_status(current.get(evidence_id))
        previous_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {"currentStatus": status, "previousStatus": previous_status}
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_status == "pass" and status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    redaction_details = evidence_details(current.get("operator-rc.redaction"))
    checks = redaction_details.get("checks") if isinstance(redaction_details, dict) else None
    if isinstance(checks, dict) and checks.get("redactorTest") is not True:
        failures.append("Operator RC redaction evidence did not prove support-bundle redaction")
        add_evidence_issue(details, "failureEvidenceIds", "operator-rc.redaction")
    details["planBeforeExecute"] = evidence_status(current.get("operator-rc.recovery-plan-execute"))
    details["supportBundleWizard"] = evidence_status(current.get("operator-rc.support-bundle-wizard"))
    return gate_from_issues(
        "ecosystem.operator-rc-recovery",
        "Operator RC recovery and support workflow evidence passed.",
        failures,
        warnings,
        details,
    )


def evaluate_ecosystem_security_advisory_revocation_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}
    for evidence_id in ECOSYSTEM_SECURITY_EVIDENCE_IDS:
        status = evidence_status(current.get(evidence_id))
        previous_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {"currentStatus": status, "previousStatus": previous_status}
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_status == "pass" and status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    redaction_details = evidence_details(
        current.get("ecosystem-security.advisory-revocation-redaction")
    )
    redaction = nested_dict(redaction_details, "redaction")
    if redaction and redaction.get("leaks"):
        failures.append("Ecosystem security redaction evidence contains forbidden payload leaks")
        add_evidence_issue(
            details, "failureEvidenceIds", "ecosystem-security.advisory-revocation-redaction"
        )
    details["evidenceIds"] = list(ECOSYSTEM_SECURITY_EVIDENCE_IDS)
    return gate_from_issues(
        "ecosystem.security-advisory-revocation",
        "Ecosystem security advisory, denylist, and review revocation evidence passed.",
        failures,
        warnings,
        details,
    )


def evaluate_live_network_beta_gate(
    current: dict[str, dict[str, Any]],
    settings: Settings,
) -> GateResult:
    entries = {
        evidence_id: current.get(evidence_id)
        for evidence_id in LIVE_NETWORK_BETA_EVIDENCE_IDS
    }
    details_by_id = {
        evidence_id: evidence_details(entry)
        for evidence_id, entry in entries.items()
    }
    enabled = settings.live_network_beta_enabled or any(
        bool(details.get("enabled")) for details in details_by_id.values()
    )
    required = settings.live_network_beta_required
    statuses = {
        evidence_id: evidence_status(entry)
        for evidence_id, entry in entries.items()
    }
    required_ids = [
        evidence_id
        for evidence_id in LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS
        if required or evidence_required(entries.get(evidence_id))
    ]
    failures: list[str] = []
    warnings: list[str] = []
    failure_evidence_ids: list[str] = []
    warning_evidence_ids: list[str] = []
    if not enabled and not required:
        return GateResult(
            "ecosystem.live-network-beta",
            "pass",
            False,
            "Live-network beta certification was not requested.",
            {
                "enabled": False,
                "required": False,
                "statuses": statuses,
                "requiredEvidenceIds": [],
                "optionalEvidenceIds": ["live-network-beta.app-service-score"],
                "node": {},
                "redaction": {},
                "stepCounts": {},
                "artifactPaths": [],
            },
        )
    for evidence_id in required_ids:
        status = statuses[evidence_id]
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is {status}")
            add_evidence_issue(details_by_id.setdefault(evidence_id, {}), "failureEvidenceIds", evidence_id)
            failure_evidence_ids.append(evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details_by_id.setdefault(evidence_id, {}), "warningEvidenceIds", evidence_id)
            warning_evidence_ids.append(evidence_id)
    if enabled and not required:
        for evidence_id, status in statuses.items():
            if status in {"fail", "missing", "warn"}:
                warnings.append(f"{evidence_id} evidence is {status}")
                add_evidence_issue(details_by_id.setdefault(evidence_id, {}), "warningEvidenceIds", evidence_id)
                warning_evidence_ids.append(evidence_id)
    optional_service_status = statuses.get("live-network-beta.app-service-score", "missing")
    optional_service_details = details_by_id.get("live-network-beta.app-service-score", {})
    optional_service_requested = bool(optional_service_details.get("enabled"))
    if enabled and optional_service_status in {"fail", "missing", "warn"}:
        warnings.append(
            f"live-network-beta.app-service-score evidence is {optional_service_status}; app-service score invocation remains optional"
        )
        warning_evidence_ids.append("live-network-beta.app-service-score")
    elif enabled and optional_service_status == "skip" and optional_service_requested:
        warnings.append(
            "live-network-beta.app-service-score evidence is skip after score invocation was requested; app-service score invocation remains optional"
        )
        warning_evidence_ids.append("live-network-beta.app-service-score")
    redaction_status = statuses.get("live-network-beta.redaction", "missing")
    if redaction_status in {"fail", "missing", "skip"} and required:
        add_evidence_issue(details_by_id.setdefault("live-network-beta.redaction", {}), "failureEvidenceIds", "live-network-beta.redaction")
        failure_evidence_ids.append("live-network-beta.redaction")

    representative_details = next(
        (details for details in details_by_id.values() if details),
        {},
    )
    failures = sorted(dict.fromkeys(failures))
    warnings = sorted(dict.fromkeys(warnings))
    compact_details: dict[str, Any] = {
        "enabled": enabled,
        "required": required,
        "statuses": statuses,
        "requiredEvidenceIds": required_ids,
        "optionalEvidenceIds": ["live-network-beta.app-service-score"],
        "node": representative_details.get("node", {}),
        "redaction": representative_details.get("redaction", {}),
        "stepCounts": representative_details.get("stepCounts", {}),
        "artifactPaths": representative_details.get("artifactPaths", []),
    }
    if failures:
        compact_details["failureEvidenceIds"] = sorted(dict.fromkeys(failure_evidence_ids))
    if warnings:
        compact_details["warningEvidenceIds"] = sorted(dict.fromkeys(warning_evidence_ids))
    return gate_from_issues(
        "ecosystem.live-network-beta",
        "Live-network beta certification evidence is complete.",
        failures,
        warnings,
        compact_details,
    )


def evaluate_multi_node_beta_gate(
    current: dict[str, dict[str, Any]],
    settings: Settings,
) -> GateResult:
    entries = {evidence_id: current.get(evidence_id) for evidence_id in MULTI_NODE_BETA_EVIDENCE_IDS}
    statuses = {evidence_id: evidence_status(entry) for evidence_id, entry in entries.items()}
    details_by_id = {evidence_id: evidence_details(entry) for evidence_id, entry in entries.items()}
    required = settings.multi_node_soak_required or settings.mode == "release-candidate"
    failures: list[str] = []
    warnings: list[str] = []
    failure_evidence_ids: list[str] = []
    warning_evidence_ids: list[str] = []
    for evidence_id, status in statuses.items():
        if status in {"fail", "missing", "skip"}:
            message = f"{evidence_id} evidence is {status}"
            if required:
                failures.append(message)
                failure_evidence_ids.append(evidence_id)
            else:
                warnings.append(message)
                warning_evidence_ids.append(evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            warning_evidence_ids.append(evidence_id)
    redaction_details = details_by_id.get("multi-node-beta.redaction", {})
    redaction_findings = redaction_details.get("redactionFindings")
    if isinstance(redaction_findings, list) and redaction_findings:
        failures.append("multi-node-beta.redaction has unwaivable redaction findings")
        failure_evidence_ids.append("multi-node-beta.redaction")
    representative_details = details_by_id.get("multi-node-beta.soak", {})
    compact_details = {
        "required": required,
        "statuses": statuses,
        "mode": representative_details.get("mode", "missing"),
        "durationProfile": representative_details.get("durationProfile", "missing"),
        "promotionReady": bool(representative_details.get("promotionReady", False)),
        "scenarioStatuses": representative_details.get("scenarioStatuses", {}),
        "blockers": representative_details.get("blockers", []),
        "warnings": representative_details.get("warnings", []),
    }
    if failure_evidence_ids:
        compact_details["failureEvidenceIds"] = sorted(dict.fromkeys(failure_evidence_ids))
    if warning_evidence_ids:
        compact_details["warningEvidenceIds"] = sorted(dict.fromkeys(warning_evidence_ids))
    return gate_from_issues(
        "ecosystem.multi-node-beta",
        "Multi-node beta soak and upgrade drill evidence is complete.",
        sorted(dict.fromkeys(failures)),
        sorted(dict.fromkeys(warnings)),
        compact_details,
    )


def evaluate_app_vault_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    item = current.get("app-vault.capabilities")
    previous_item = previous.get("app-vault.capabilities")
    status = evidence_status(item)
    previous_status = evidence_status(previous_item)
    vault_details = evidence_details(item)
    details: dict[str, Any] = {}
    failures: list[str] = []
    warnings: list[str] = []
    if status in {"fail", "missing", "skip"}:
        failures.append("Vault capability evidence is not passing")
        add_evidence_issue(details, "failureEvidenceIds", "app-vault.capabilities")
    elif status == "warn":
        warnings.append("Vault capability evidence is warning")
        add_evidence_issue(details, "warningEvidenceIds", "app-vault.capabilities")
    if previous_status == "pass" and status in {"fail", "missing", "skip"}:
        failures.append(f"Vault capability evidence regressed from pass to {status}")
        add_evidence_issue(details, "failureEvidenceIds", "app-vault.capabilities")
    capabilities = set(sorted_strings(vault_details.get("capabilities")))
    missing_capabilities = sorted(set(EXPECTED_VAULT_CAPABILITIES) - capabilities)
    if missing_capabilities:
        failures.append(f"Vault capability evidence is missing capabilities: {', '.join(missing_capabilities)}")
        add_evidence_issue(details, "failureEvidenceIds", "app-vault.capabilities")
    checks_pass = all_boolean_checks_pass(vault_details)
    if checks_pass is False:
        failures.append("Vault capability checks are not all passing")
        add_evidence_issue(details, "failureEvidenceIds", "app-vault.capabilities")
    redaction = nested_dict(vault_details, "redaction")
    for key in ("secretValuesRedacted", "identityPrivateMaterialRedacted"):
        if redaction.get(key) is not True:
            failures.append(f"Vault redaction check {key} failed or missing")
            add_evidence_issue(details, "failureEvidenceIds", "app-vault.capabilities")
    for evidence_id in ("app-platform.identity-profile-publish",):
        route_status = evidence_status(current.get(evidence_id))
        previous_route_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {
            "currentStatus": route_status,
            "previousStatus": previous_route_status,
        }
        if route_status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif route_status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_route_status == "pass" and route_status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {route_status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    details.update(
        {"currentStatus": status, "previousStatus": previous_status, "capabilities": sorted(capabilities)}
    )
    return gate_from_issues(
        "ecosystem.app-vault",
        "App-vault capability and redaction evidence passed.",
        failures,
        warnings,
        details,
    )


def evaluate_sandbox_provider_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]], mode: str, metadata: dict[str, Any]
) -> GateResult:
    item = current.get("apphost.sandbox-provider")
    previous_item = previous.get("apphost.sandbox-provider")
    sandbox_details = evidence_details(item)
    previous_details = evidence_details(previous_item)
    status = evidence_status(item)
    previous_status = evidence_status(previous_item)
    support_level = str(sandbox_details.get("supportLevel", "")).lower()
    previous_support_level = str(previous_details.get("supportLevel", "")).lower()
    enforcement_required = mode == "release-candidate" or str(metadata.get("sandboxEnforcementRequired", "")).lower() == "true"
    issue_details: dict[str, Any] = {}
    failures: list[str] = []
    warnings: list[str] = []
    if status in {"fail", "missing", "skip"}:
        if enforcement_required:
            failures.append("Sandbox-provider evidence is not passing")
            add_evidence_issue(issue_details, "failureEvidenceIds", "apphost.sandbox-provider")
        else:
            warnings.append("Sandbox-provider evidence is not passing")
            add_evidence_issue(issue_details, "warningEvidenceIds", "apphost.sandbox-provider")
    elif status == "warn":
        warnings.append("Sandbox-provider evidence is warning")
        add_evidence_issue(issue_details, "warningEvidenceIds", "apphost.sandbox-provider")
    if previous_status == "pass" and status in {"fail", "missing", "skip"} and enforcement_required:
        failures.append(f"Sandbox-provider evidence regressed from pass to {status}")
        add_evidence_issue(issue_details, "failureEvidenceIds", "apphost.sandbox-provider")
    if previous_support_level == "enforced" and support_level and support_level != "enforced":
        if enforcement_required:
            failures.append(f"Sandbox support regressed from enforced to {support_level}")
            add_evidence_issue(issue_details, "failureEvidenceIds", "apphost.sandbox-provider")
        else:
            warnings.append(f"Sandbox support regressed from enforced to {support_level}")
            add_evidence_issue(issue_details, "warningEvidenceIds", "apphost.sandbox-provider")
    if enforcement_required and support_level != "enforced":
        failures.append("Enforced sandbox-provider evidence is required but not present")
        add_evidence_issue(issue_details, "failureEvidenceIds", "apphost.sandbox-provider")
    return gate_from_issues(
        "ecosystem.sandbox-provider",
        "Sandbox-provider evidence remains enforced where required.",
        failures,
        warnings,
        {
            "currentStatus": status,
            "previousStatus": previous_status,
            "supportLevel": support_level,
            "previousSupportLevel": previous_support_level,
            "enforcementRequired": enforcement_required,
            "failureEvidenceIds": issue_details.get("failureEvidenceIds", []),
            "warningEvidenceIds": issue_details.get("warningEvidenceIds", []),
        },
    )


def evaluate_reference_content_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    item = current.get("reference-apps.content")
    previous_item = previous.get("reference-apps.content")
    profile_item = current.get("reference-app.profile-publisher")
    previous_profile_item = previous.get("reference-app.profile-publisher")
    profile_app_data_item = current.get("reference-app.profile-publisher-app-data")
    previous_profile_app_data_item = previous.get("reference-app.profile-publisher-app-data")
    feed_reader_item = current.get("reference-app.feed-reader")
    previous_feed_reader_item = previous.get("reference-app.feed-reader")
    feed_reader_subscription_item = current.get("reference-app.feed-reader-subscriptions")
    previous_feed_reader_subscription_item = previous.get("reference-app.feed-reader-subscriptions")
    feed_reader_app_data_item = current.get("reference-app.feed-reader-app-data")
    previous_feed_reader_app_data_item = previous.get("reference-app.feed-reader-app-data")
    trust_graph_item = current.get("reference-app.trust-graph")
    previous_trust_graph_item = previous.get("reference-app.trust-graph")
    trust_graph_durable_exchange_item = current.get("reference-app.trust-graph-durable-exchange")
    previous_trust_graph_durable_exchange_item = previous.get(
        "reference-app.trust-graph-durable-exchange"
    )
    trust_graph_app_data_item = current.get("reference-app.trust-graph-app-data-preview")
    previous_trust_graph_app_data_item = previous.get(
        "reference-app.trust-graph-app-data-preview"
    )
    social_message_signing_item = current.get("app-platform.social-message-signing")
    previous_social_message_signing_item = previous.get("app-platform.social-message-signing")
    social_inbox_item = current.get("reference-app.social-inbox")
    previous_social_inbox_item = previous.get("reference-app.social-inbox")
    social_inbox_signed_message_item = current.get("reference-app.social-inbox-signed-message")
    previous_social_inbox_signed_message_item = previous.get(
        "reference-app.social-inbox-signed-message"
    )
    social_inbox_subscription_item = current.get("reference-app.social-inbox-subscriptions")
    previous_social_inbox_subscription_item = previous.get(
        "reference-app.social-inbox-subscriptions"
    )
    social_inbox_app_data_item = current.get("reference-app.social-inbox-app-data")
    previous_social_inbox_app_data_item = previous.get("reference-app.social-inbox-app-data")
    social_inbox_trust_item = current.get("reference-app.social-inbox-trust-annotations")
    previous_social_inbox_trust_item = previous.get(
        "reference-app.social-inbox-trust-annotations"
    )
    social_inbox_rc_threading_item = current.get("reference-app.social-inbox-rc-threading")
    previous_social_inbox_rc_threading_item = previous.get(
        "reference-app.social-inbox-rc-threading"
    )
    trust_social_beta_hardening_item = current.get("app-platform.trust-social-beta-hardening")
    previous_trust_social_beta_hardening_item = previous.get(
        "app-platform.trust-social-beta-hardening"
    )
    trust_social_content_format_profiles_item = current.get(
        "app-platform.trust-social-content-format-profiles"
    )
    previous_trust_social_content_format_profiles_item = previous.get(
        "app-platform.trust-social-content-format-profiles"
    )
    social_mail_migration_item = current.get("migration.social-mail-preview")
    previous_social_mail_migration_item = previous.get("migration.social-mail-preview")
    generated_document_item = current.get("app-platform.generated-document-insert")
    previous_generated_document_item = previous.get("app-platform.generated-document-insert")
    content_fetch_item = current.get("app-platform.content-fetch")
    previous_content_fetch_item = previous.get("app-platform.content-fetch")
    content_subscription_item = current.get("app-platform.content-subscriptions")
    previous_content_subscription_item = previous.get("app-platform.content-subscriptions")
    content_subscription_scheduler_item = current.get("network-content.subscription-scheduler")
    previous_content_subscription_scheduler_item = previous.get(
        "network-content.subscription-scheduler"
    )
    app_data_store_item = current.get("app-platform.durable-app-data-store")
    previous_app_data_store_item = previous.get("app-platform.durable-app-data-store")
    trust_graph_preview_item = current.get("app-platform.trust-graph-preview")
    previous_trust_graph_preview_item = previous.get("app-platform.trust-graph-preview")
    trust_graph_durable_store_item = current.get("app-platform.trust-graph-durable-store")
    previous_trust_graph_durable_store_item = previous.get(
        "app-platform.trust-graph-durable-store"
    )
    trust_graph_exchange_item = current.get("app-platform.trust-graph-exchange")
    previous_trust_graph_exchange_item = previous.get("app-platform.trust-graph-exchange")
    trust_statement_signing_item = current.get("app-platform.trust-statement-signing")
    previous_trust_statement_signing_item = previous.get("app-platform.trust-statement-signing")
    app_services_registry_item = current.get("app-services.registry")
    previous_app_services_registry_item = previous.get("app-services.registry")
    app_services_grants_item = current.get("app-services.grants")
    previous_app_services_grants_item = previous.get("app-services.grants")
    app_services_dependency_graph_item = current.get("app-services.dependency-graph")
    previous_app_services_dependency_graph_item = previous.get("app-services.dependency-graph")
    app_services_grant_bundles_item = current.get("app-services.grant-bundles")
    previous_app_services_grant_bundles_item = previous.get("app-services.grant-bundles")
    app_services_grant_expiry_item = current.get("app-services.grant-expiry-renewal")
    previous_app_services_grant_expiry_item = previous.get("app-services.grant-expiry-renewal")
    app_services_provider_revalidation_item = current.get("app-services.provider-revalidation")
    previous_app_services_provider_revalidation_item = previous.get("app-services.provider-revalidation")
    app_services_provider_item = current.get("app-services.trust-score-provider")
    previous_app_services_provider_item = previous.get("app-services.trust-score-provider")
    social_inbox_service_grant_item = current.get("reference-app.social-inbox-service-grant")
    previous_social_inbox_service_grant_item = previous.get(
        "reference-app.social-inbox-service-grant"
    )
    social_inbox_service_dependency_item = current.get(
        "reference-app.social-inbox-service-dependency"
    )
    previous_social_inbox_service_dependency_item = previous.get(
        "reference-app.social-inbox-service-dependency"
    )
    app_services_web_shell_item = current.get("app-services.web-shell")
    previous_app_services_web_shell_item = previous.get("app-services.web-shell")
    app_services_redaction_item = current.get("app-services.redaction")
    previous_app_services_redaction_item = previous.get("app-services.redaction")
    app_services_dependency_redaction_item = current.get("app-services.dependency-redaction")
    previous_app_services_dependency_redaction_item = previous.get(
        "app-services.dependency-redaction"
    )
    details = evidence_details(item)
    profile_details = evidence_details(profile_item)
    profile_app_data_details = evidence_details(profile_app_data_item)
    feed_reader_details = evidence_details(feed_reader_item)
    feed_reader_subscription_details = evidence_details(feed_reader_subscription_item)
    feed_reader_app_data_details = evidence_details(feed_reader_app_data_item)
    trust_graph_details = evidence_details(trust_graph_item)
    trust_graph_durable_exchange_details = evidence_details(trust_graph_durable_exchange_item)
    trust_graph_app_data_details = evidence_details(trust_graph_app_data_item)
    social_message_signing_details = evidence_details(social_message_signing_item)
    social_inbox_details = evidence_details(social_inbox_item)
    social_inbox_signed_message_details = evidence_details(social_inbox_signed_message_item)
    social_inbox_subscription_details = evidence_details(social_inbox_subscription_item)
    social_inbox_app_data_details = evidence_details(social_inbox_app_data_item)
    social_inbox_trust_details = evidence_details(social_inbox_trust_item)
    social_inbox_rc_threading_details = evidence_details(social_inbox_rc_threading_item)
    social_mail_migration_details = evidence_details(social_mail_migration_item)
    generated_document_details = evidence_details(generated_document_item)
    content_fetch_details = evidence_details(content_fetch_item)
    content_subscription_details = evidence_details(content_subscription_item)
    content_subscription_scheduler_details = evidence_details(
        content_subscription_scheduler_item
    )
    app_data_store_details = evidence_details(app_data_store_item)
    trust_graph_preview_details = evidence_details(trust_graph_preview_item)
    trust_graph_durable_store_details = evidence_details(trust_graph_durable_store_item)
    trust_graph_exchange_details = evidence_details(trust_graph_exchange_item)
    trust_statement_signing_details = evidence_details(trust_statement_signing_item)
    app_services_registry_details = evidence_details(app_services_registry_item)
    app_services_grants_details = evidence_details(app_services_grants_item)
    app_services_dependency_graph_details = evidence_details(app_services_dependency_graph_item)
    app_services_grant_bundles_details = evidence_details(app_services_grant_bundles_item)
    app_services_grant_expiry_details = evidence_details(app_services_grant_expiry_item)
    app_services_provider_revalidation_details = evidence_details(
        app_services_provider_revalidation_item
    )
    app_services_provider_details = evidence_details(app_services_provider_item)
    social_inbox_service_grant_details = evidence_details(social_inbox_service_grant_item)
    social_inbox_service_dependency_details = evidence_details(
        social_inbox_service_dependency_item
    )
    app_services_web_shell_details = evidence_details(app_services_web_shell_item)
    app_services_redaction_details = evidence_details(app_services_redaction_item)
    app_services_dependency_redaction_details = evidence_details(
        app_services_dependency_redaction_item
    )
    checks = nested_dict(details, "checks")
    profile_checks = nested_dict(profile_details, "checks")
    profile_app_data_checks = nested_dict(profile_app_data_details, "checks")
    feed_reader_checks = nested_dict(feed_reader_details, "checks")
    feed_reader_app_data_checks = nested_dict(feed_reader_app_data_details, "checks")
    trust_graph_checks = nested_dict(trust_graph_details, "checks")
    trust_graph_durable_exchange_checks = nested_dict(
        trust_graph_durable_exchange_details, "checks"
    )
    trust_graph_app_data_checks = nested_dict(trust_graph_app_data_details, "checks")
    social_message_signing_checks = nested_dict(social_message_signing_details, "checks")
    social_inbox_checks = nested_dict(social_inbox_details, "checks")
    social_inbox_signed_message_checks = nested_dict(
        social_inbox_signed_message_details, "checks"
    )
    social_inbox_subscription_checks = nested_dict(social_inbox_subscription_details, "checks")
    social_inbox_app_data_checks = nested_dict(social_inbox_app_data_details, "checks")
    social_inbox_trust_checks = nested_dict(social_inbox_trust_details, "checks")
    social_inbox_rc_threading_checks = nested_dict(social_inbox_rc_threading_details, "checks")
    social_inbox_service_grant_checks = nested_dict(social_inbox_service_grant_details, "checks")
    social_mail_migration_checks = nested_dict(social_mail_migration_details, "checks")
    app_services_registry_checks = nested_dict(app_services_registry_details, "checks")
    app_services_grants_checks = nested_dict(app_services_grants_details, "checks")
    app_services_dependency_graph_checks = nested_dict(app_services_dependency_graph_details, "checks")
    app_services_grant_bundles_checks = nested_dict(app_services_grant_bundles_details, "checks")
    app_services_grant_expiry_checks = nested_dict(app_services_grant_expiry_details, "checks")
    app_services_provider_revalidation_checks = nested_dict(
        app_services_provider_revalidation_details, "checks"
    )
    app_services_provider_checks = nested_dict(app_services_provider_details, "checks")
    app_services_web_shell_checks = nested_dict(app_services_web_shell_details, "checks")
    app_services_redaction_checks = nested_dict(app_services_redaction_details, "checks")
    social_inbox_service_dependency_checks = nested_dict(
        social_inbox_service_dependency_details, "checks"
    )
    app_services_dependency_redaction_checks = nested_dict(
        app_services_dependency_redaction_details, "checks"
    )
    status = evidence_status(item)
    previous_status = evidence_status(previous_item)
    profile_status = evidence_status(profile_item)
    previous_profile_status = evidence_status(previous_profile_item)
    profile_app_data_status = evidence_status(profile_app_data_item)
    previous_profile_app_data_status = evidence_status(previous_profile_app_data_item)
    feed_reader_status = evidence_status(feed_reader_item)
    previous_feed_reader_status = evidence_status(previous_feed_reader_item)
    feed_reader_subscription_status = evidence_status(feed_reader_subscription_item)
    previous_feed_reader_subscription_status = evidence_status(
        previous_feed_reader_subscription_item
    )
    feed_reader_app_data_status = evidence_status(feed_reader_app_data_item)
    previous_feed_reader_app_data_status = evidence_status(previous_feed_reader_app_data_item)
    trust_graph_status = evidence_status(trust_graph_item)
    previous_trust_graph_status = evidence_status(previous_trust_graph_item)
    trust_graph_durable_exchange_status = evidence_status(trust_graph_durable_exchange_item)
    previous_trust_graph_durable_exchange_status = evidence_status(
        previous_trust_graph_durable_exchange_item
    )
    trust_graph_app_data_status = evidence_status(trust_graph_app_data_item)
    previous_trust_graph_app_data_status = evidence_status(previous_trust_graph_app_data_item)
    social_message_signing_status = evidence_status(social_message_signing_item)
    previous_social_message_signing_status = evidence_status(
        previous_social_message_signing_item
    )
    social_inbox_status = evidence_status(social_inbox_item)
    previous_social_inbox_status = evidence_status(previous_social_inbox_item)
    social_inbox_signed_message_status = evidence_status(social_inbox_signed_message_item)
    previous_social_inbox_signed_message_status = evidence_status(
        previous_social_inbox_signed_message_item
    )
    social_inbox_subscription_status = evidence_status(social_inbox_subscription_item)
    previous_social_inbox_subscription_status = evidence_status(
        previous_social_inbox_subscription_item
    )
    social_inbox_app_data_status = evidence_status(social_inbox_app_data_item)
    previous_social_inbox_app_data_status = evidence_status(previous_social_inbox_app_data_item)
    social_inbox_trust_status = evidence_status(social_inbox_trust_item)
    previous_social_inbox_trust_status = evidence_status(previous_social_inbox_trust_item)
    social_inbox_rc_threading_status = evidence_status(social_inbox_rc_threading_item)
    previous_social_inbox_rc_threading_status = evidence_status(
        previous_social_inbox_rc_threading_item
    )
    trust_social_beta_hardening_status = evidence_status(trust_social_beta_hardening_item)
    previous_trust_social_beta_hardening_status = evidence_status(
        previous_trust_social_beta_hardening_item
    )
    trust_social_content_format_profiles_status = evidence_status(
        trust_social_content_format_profiles_item
    )
    previous_trust_social_content_format_profiles_status = evidence_status(
        previous_trust_social_content_format_profiles_item
    )
    social_mail_migration_status = evidence_status(social_mail_migration_item)
    previous_social_mail_migration_status = evidence_status(previous_social_mail_migration_item)
    generated_document_status = evidence_status(generated_document_item)
    previous_generated_document_status = evidence_status(previous_generated_document_item)
    content_fetch_status = evidence_status(content_fetch_item)
    previous_content_fetch_status = evidence_status(previous_content_fetch_item)
    content_subscription_status = evidence_status(content_subscription_item)
    previous_content_subscription_status = evidence_status(previous_content_subscription_item)
    content_subscription_scheduler_status = evidence_status(content_subscription_scheduler_item)
    previous_content_subscription_scheduler_status = evidence_status(
        previous_content_subscription_scheduler_item
    )
    app_data_store_status = evidence_status(app_data_store_item)
    previous_app_data_store_status = evidence_status(previous_app_data_store_item)
    trust_graph_preview_status = evidence_status(trust_graph_preview_item)
    previous_trust_graph_preview_status = evidence_status(previous_trust_graph_preview_item)
    trust_graph_durable_store_status = evidence_status(trust_graph_durable_store_item)
    previous_trust_graph_durable_store_status = evidence_status(
        previous_trust_graph_durable_store_item
    )
    trust_graph_exchange_status = evidence_status(trust_graph_exchange_item)
    previous_trust_graph_exchange_status = evidence_status(previous_trust_graph_exchange_item)
    trust_statement_signing_status = evidence_status(trust_statement_signing_item)
    previous_trust_statement_signing_status = evidence_status(
        previous_trust_statement_signing_item
    )
    app_services_registry_status = evidence_status(app_services_registry_item)
    previous_app_services_registry_status = evidence_status(previous_app_services_registry_item)
    app_services_grants_status = evidence_status(app_services_grants_item)
    previous_app_services_grants_status = evidence_status(previous_app_services_grants_item)
    app_services_dependency_graph_status = evidence_status(app_services_dependency_graph_item)
    previous_app_services_dependency_graph_status = evidence_status(
        previous_app_services_dependency_graph_item
    )
    app_services_grant_bundles_status = evidence_status(app_services_grant_bundles_item)
    previous_app_services_grant_bundles_status = evidence_status(
        previous_app_services_grant_bundles_item
    )
    app_services_grant_expiry_status = evidence_status(app_services_grant_expiry_item)
    previous_app_services_grant_expiry_status = evidence_status(
        previous_app_services_grant_expiry_item
    )
    app_services_provider_revalidation_status = evidence_status(
        app_services_provider_revalidation_item
    )
    previous_app_services_provider_revalidation_status = evidence_status(
        previous_app_services_provider_revalidation_item
    )
    app_services_provider_status = evidence_status(app_services_provider_item)
    previous_app_services_provider_status = evidence_status(previous_app_services_provider_item)
    social_inbox_service_grant_status = evidence_status(social_inbox_service_grant_item)
    previous_social_inbox_service_grant_status = evidence_status(
        previous_social_inbox_service_grant_item
    )
    social_inbox_service_dependency_status = evidence_status(social_inbox_service_dependency_item)
    previous_social_inbox_service_dependency_status = evidence_status(
        previous_social_inbox_service_dependency_item
    )
    app_services_web_shell_status = evidence_status(app_services_web_shell_item)
    previous_app_services_web_shell_status = evidence_status(previous_app_services_web_shell_item)
    app_services_redaction_status = evidence_status(app_services_redaction_item)
    previous_app_services_redaction_status = evidence_status(previous_app_services_redaction_item)
    app_services_dependency_redaction_status = evidence_status(
        app_services_dependency_redaction_item
    )
    previous_app_services_dependency_redaction_status = evidence_status(
        previous_app_services_dependency_redaction_item
    )
    gate_details: dict[str, Any] = {}
    failures: list[str] = []
    warnings: list[str] = []
    if status in {"fail", "missing", "skip"}:
        failures.append("Site Publisher reference-content evidence is not passing")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-apps.content")
    elif status == "warn":
        warnings.append("Site Publisher reference-content evidence is warning")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-apps.content")
    if previous_status == "pass" and status in {"fail", "missing", "skip"}:
        failures.append(f"Site Publisher evidence regressed from pass to {status}")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-apps.content")
    if details.get("appId") not in {"site-publisher", None}:
        failures.append("Reference content app evidence is not for site-publisher")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-apps.content")
    if checks:
        for key in ("usesContentInsertDirectory", "usesContentInsertFile", "usesSdkBootstrap"):
            if checks.get(key) is not True:
                failures.append(f"Reference content app check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "reference-apps.content")
    elif status == "pass":
        warnings.append("Reference content app coverage lacks detailed staged app checks")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-apps.content")
    for evidence_id, current_status, previous_status_value in (
        ("reference-app.profile-publisher", profile_status, previous_profile_status),
        (
            "reference-app.profile-publisher-app-data",
            profile_app_data_status,
            previous_profile_app_data_status,
        ),
        ("reference-app.feed-reader", feed_reader_status, previous_feed_reader_status),
        (
            "reference-app.feed-reader-subscriptions",
            feed_reader_subscription_status,
            previous_feed_reader_subscription_status,
        ),
        (
            "reference-app.feed-reader-app-data",
            feed_reader_app_data_status,
            previous_feed_reader_app_data_status,
        ),
        ("reference-app.trust-graph", trust_graph_status, previous_trust_graph_status),
        (
            "reference-app.trust-graph-durable-exchange",
            trust_graph_durable_exchange_status,
            previous_trust_graph_durable_exchange_status,
        ),
        (
            "reference-app.trust-graph-app-data-preview",
            trust_graph_app_data_status,
            previous_trust_graph_app_data_status,
        ),
        (
            "app-platform.social-message-signing",
            social_message_signing_status,
            previous_social_message_signing_status,
        ),
        ("reference-app.social-inbox", social_inbox_status, previous_social_inbox_status),
        (
            "reference-app.social-inbox-signed-message",
            social_inbox_signed_message_status,
            previous_social_inbox_signed_message_status,
        ),
        (
            "reference-app.social-inbox-subscriptions",
            social_inbox_subscription_status,
            previous_social_inbox_subscription_status,
        ),
        (
            "reference-app.social-inbox-app-data",
            social_inbox_app_data_status,
            previous_social_inbox_app_data_status,
        ),
        (
            "reference-app.social-inbox-trust-annotations",
            social_inbox_trust_status,
            previous_social_inbox_trust_status,
        ),
        (
            "reference-app.social-inbox-rc-threading",
            social_inbox_rc_threading_status,
            previous_social_inbox_rc_threading_status,
        ),
        (
            "app-platform.trust-social-beta-hardening",
            trust_social_beta_hardening_status,
            previous_trust_social_beta_hardening_status,
        ),
        (
            "app-platform.trust-social-content-format-profiles",
            trust_social_content_format_profiles_status,
            previous_trust_social_content_format_profiles_status,
        ),
        (
            "migration.social-mail-preview",
            social_mail_migration_status,
            previous_social_mail_migration_status,
        ),
        (
            "app-platform.generated-document-insert",
            generated_document_status,
            previous_generated_document_status,
        ),
        ("app-platform.content-fetch", content_fetch_status, previous_content_fetch_status),
        (
            "app-platform.content-subscriptions",
            content_subscription_status,
            previous_content_subscription_status,
        ),
        (
            "network-content.subscription-scheduler",
            content_subscription_scheduler_status,
            previous_content_subscription_scheduler_status,
        ),
        (
            "app-platform.durable-app-data-store",
            app_data_store_status,
            previous_app_data_store_status,
        ),
        (
            "app-platform.trust-graph-preview",
            trust_graph_preview_status,
            previous_trust_graph_preview_status,
        ),
        (
            "app-platform.trust-graph-durable-store",
            trust_graph_durable_store_status,
            previous_trust_graph_durable_store_status,
        ),
        (
            "app-platform.trust-graph-exchange",
            trust_graph_exchange_status,
            previous_trust_graph_exchange_status,
        ),
        (
            "app-platform.trust-statement-signing",
            trust_statement_signing_status,
            previous_trust_statement_signing_status,
        ),
        ("app-services.registry", app_services_registry_status, previous_app_services_registry_status),
        ("app-services.grants", app_services_grants_status, previous_app_services_grants_status),
        (
            "app-services.dependency-graph",
            app_services_dependency_graph_status,
            previous_app_services_dependency_graph_status,
        ),
        (
            "app-services.grant-bundles",
            app_services_grant_bundles_status,
            previous_app_services_grant_bundles_status,
        ),
        (
            "app-services.grant-expiry-renewal",
            app_services_grant_expiry_status,
            previous_app_services_grant_expiry_status,
        ),
        (
            "app-services.provider-revalidation",
            app_services_provider_revalidation_status,
            previous_app_services_provider_revalidation_status,
        ),
        (
            "app-services.trust-score-provider",
            app_services_provider_status,
            previous_app_services_provider_status,
        ),
        (
            "reference-app.social-inbox-service-grant",
            social_inbox_service_grant_status,
            previous_social_inbox_service_grant_status,
        ),
        (
            "reference-app.social-inbox-service-dependency",
            social_inbox_service_dependency_status,
            previous_social_inbox_service_dependency_status,
        ),
        (
            "app-services.web-shell",
            app_services_web_shell_status,
            previous_app_services_web_shell_status,
        ),
        (
            "app-services.redaction",
            app_services_redaction_status,
            previous_app_services_redaction_status,
        ),
        (
            "app-services.dependency-redaction",
            app_services_dependency_redaction_status,
            previous_app_services_dependency_redaction_status,
        ),
    ):
        if current_status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(gate_details, "failureEvidenceIds", evidence_id)
        elif current_status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(gate_details, "warningEvidenceIds", evidence_id)
        if previous_status_value == "pass" and current_status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {current_status}")
            add_evidence_issue(gate_details, "failureEvidenceIds", evidence_id)
    if profile_details.get("appId") not in {"profile-publisher", None}:
        failures.append("Profile Publisher evidence is not for profile-publisher")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.profile-publisher")
    if profile_checks:
        for key in (
            "usesBrowserSafeIdentityCreation",
            "usesProfileDocumentRoute",
            "usesGeneratedDocumentInsertRoute",
            "usesSdkBootstrap",
        ):
            if profile_checks.get(key) is not True:
                failures.append(f"Profile Publisher reference app check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.profile-publisher")
    elif profile_status == "pass":
        warnings.append("Profile Publisher coverage lacks detailed staged app checks")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-app.profile-publisher")
    if profile_app_data_checks:
        for key in (
            "manifestUsesAppDataContract",
            "usesSdkJsonRecordHelpers",
            "persistsBoundedDraftState",
            "docsAndEvidenceMentionDurableAppData",
        ):
            if profile_app_data_checks.get(key) is not True:
                failures.append(f"Profile Publisher app-data check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.profile-publisher-app-data",
                )
    elif profile_app_data_status == "pass":
        warnings.append("Profile Publisher app-data coverage lacks detailed checks")
        add_evidence_issue(
            gate_details, "warningEvidenceIds", "reference-app.profile-publisher-app-data"
        )
    if feed_reader_details.get("appId") not in {"feed-reader", None}:
        failures.append("Feed Reader evidence is not for feed-reader")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.feed-reader")
    if feed_reader_checks:
        for key in (
            "usesContentFetchRouteOrHelper",
            "usesContentSubscriptionHelpers",
            "usesGeneratedDocumentInsertRoute",
            "usesSdkBootstrap",
        ):
            if feed_reader_checks.get(key) is not True:
                failures.append(f"Feed Reader reference app check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.feed-reader")
    elif feed_reader_status == "pass":
        warnings.append("Feed Reader coverage lacks detailed staged app checks")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-app.feed-reader")
    feed_reader_subscription_checks = nested_dict(feed_reader_subscription_details, "checks")
    if feed_reader_subscription_checks:
        for key in (
            "manifestDeclaresSubscribeAndV9",
            "appUsesPlatformSubscriptionWorkflow",
            "noTabLocalFollowLoop",
            "sdkHelpersAvailable",
            "docsDescribeSubscriptionFlow",
        ):
            if feed_reader_subscription_checks.get(key) is not True:
                failures.append(f"Feed Reader subscription check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.feed-reader-subscriptions",
                )
    elif feed_reader_subscription_status == "pass":
        warnings.append("Feed Reader subscription coverage lacks detailed staged app checks")
        add_evidence_issue(
            gate_details, "warningEvidenceIds", "reference-app.feed-reader-subscriptions"
        )
    if feed_reader_app_data_checks:
        for key in (
            "manifestUsesAppDataContract",
            "usesSdkJsonRecordHelpers",
            "persistsBoundedReaderState",
            "docsAndEvidenceMentionDurableAppData",
        ):
            if feed_reader_app_data_checks.get(key) is not True:
                failures.append(f"Feed Reader app-data check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.feed-reader-app-data",
                )
    elif feed_reader_app_data_status == "pass":
        warnings.append("Feed Reader app-data coverage lacks detailed checks")
        add_evidence_issue(
            gate_details, "warningEvidenceIds", "reference-app.feed-reader-app-data"
        )
    if trust_graph_details.get("appId") not in {"trust-graph", None}:
        failures.append("Trust Graph Local RC evidence is not for trust-graph")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.trust-graph")
    if trust_graph_checks:
        for key in (
            "manifestDeclaresTrustGraph",
            "manifestDeclaresTrustPermissions",
            "manifestUsesContractV22",
            "usesTrustHelpers",
            "usesBoundedTrustSigningHelper",
            "usesTrustExchangeAndQueuePreview",
            "docsDescribePreviewLimits",
            "docsDescribeTrustScoreService",
            "manifestAdvertisesTrustScoreService",
        ):
            if trust_graph_checks.get(key) is not True:
                failures.append(f"Trust Graph Local RC reference app check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.trust-graph")
    elif trust_graph_status == "pass":
        warnings.append("Trust Graph Local RC coverage lacks detailed staged app checks")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-app.trust-graph")
    if trust_graph_app_data_checks:
        for key in (
            "manifestUsesAppDataContract",
            "usesSdkJsonRecordHelpers",
            "persistsOnlyUiLocalPreviewState",
            "docsSeparateAppDataAndTrustBackend",
        ):
            if trust_graph_app_data_checks.get(key) is not True:
                failures.append(f"Trust Graph app-data preview check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.trust-graph-app-data-preview",
                )
    elif trust_graph_app_data_status == "pass":
        warnings.append("Trust Graph app-data preview coverage lacks detailed checks")
        add_evidence_issue(
            gate_details, "warningEvidenceIds", "reference-app.trust-graph-app-data-preview"
        )
    if social_message_signing_checks:
        for key in (
            "routeInContract",
            "contractVersionV11",
            "capabilitiesInContract",
            "handlerUsesFixedDomainAppVaultSigning",
            "requestRejectsGenericSigningInputs",
            "sdkHelperUsesBoundedRoute",
            "docsDescribeBoundedSigningBoundary",
        ):
            if social_message_signing_checks.get(key) is not True:
                failures.append(f"Social message signing check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "app-platform.social-message-signing",
                )
    if social_inbox_details.get("appId") not in {"social-inbox", None}:
        failures.append("Social Inbox evidence is not for social-inbox")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.social-inbox")
    if social_inbox_checks:
        for key in (
            "manifestDeclaresSocialInbox",
            "manifestDeclaresSocialPermissions",
            "manifestUsesContractV12",
            "manifestDeclaresTrustScoreServiceRequest",
            "usesAppVaultIdentityFlow",
            "usesProfileMetadataFlow",
            "usesGeneratedOutboxInsert",
            "usesSubscriptionAndFetchFlow",
            "usesDurableAppData",
            "usesTrustAnnotations",
            "previewAndNonGoalCopyPresent",
            "noRawAdminOrBrowserStorage",
        ):
            if social_inbox_checks.get(key) is not True:
                failures.append(f"Social Inbox reference app check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.social-inbox")
    elif social_inbox_status == "pass":
        warnings.append("Social Inbox coverage lacks detailed staged app checks")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-app.social-inbox")
    if social_inbox_signed_message_checks:
        for key in (
            "manifestAllowsBoundedSigning",
            "usesSdkBoundedSigner",
            "verifiesImportedMessageSignatures",
            "documentShapeIsBounded",
            "docsDescribeSignedMessageFormat",
        ):
            if social_inbox_signed_message_checks.get(key) is not True:
                failures.append(f"Social Inbox signed-message check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-signed-message",
                )
    if social_inbox_subscription_checks:
        for key in (
            "manifestDeclaresSubscriptionPermissions",
            "uiDisclosesSubscriptionWorkflow",
            "appUsesPlatformSubscriptionLifecycle",
            "manualFetchUsesBoundedContentFetch",
            "docsDescribeDurableUskSources",
        ):
            if social_inbox_subscription_checks.get(key) is not True:
                failures.append(f"Social Inbox subscription check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-subscriptions",
                )
    if social_inbox_app_data_checks:
        for key in (
            "manifestDeclaresAppDataPermissions",
            "usesSdkJsonRecordHelpers",
            "persistsNamedBoundedRecords",
            "signingDoesNotOverwritePublishSummary",
            "storesSafeSummariesOnly",
            "permissionDisclosureMentionsAppData",
            "docsDescribePrivacyRules",
            "noBrowserStorageOrRawAdminPath",
        ):
            if social_inbox_app_data_checks.get(key) is not True:
                failures.append(f"Social Inbox app-data check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-app-data",
                )
    if social_inbox_trust_checks:
        for key in (
            "manifestDeclaresAppServiceCapabilities",
            "manifestDeclaresTrustScoreRequest",
            "appQueriesAuthorScores",
            "uiShowsNeutralAndScoredStates",
            "unknownScoresRemainUnscored",
            "docsFrameScoresAsAnnotations",
        ):
            if social_inbox_trust_checks.get(key) is not True:
                failures.append(f"Social Inbox trust annotation check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-trust-annotations",
                )
    if social_inbox_rc_threading_checks:
        for key in (
            "threadBuildingLogic",
            "threadRenderingIsBoundedAndDomSafe",
            "replyActionUsesExistingReplyTo",
            "channelFilteringIsLocal",
            "boundedLocalSearch",
            "threadActionsPersistSafeState",
            "authorProfileDisplayIsSafe",
            "dedupePreservesSafeSourceSummaries",
            "subscriptionRefreshUxIsExplicit",
            "trustGraphMediatedOnly",
            "noUnsafeBrowserPersistenceOrExecution",
            "manifestUsesAdditiveBetaSchemaContract",
            "appWritesExistingSchemaVersion",
            "docsFrameRcReferenceAndNonGoals",
            "evidenceIdDocumented",
        ):
            if social_inbox_rc_threading_checks.get(key) is not True:
                failures.append(f"Social Inbox RC threading check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-rc-threading",
                )
    if social_inbox_service_grant_checks:
        for key in (
            "socialManifestRequestsServiceGrant",
            "socialManifestUsesAppServiceCapabilities",
            "socialUsesSdkServicesNamespace",
            "socialUiShowsGrantStates",
            "socialDocsDescribeRevocation",
        ):
            if social_inbox_service_grant_checks.get(key) is not True:
                failures.append(f"Social Inbox service-grant check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-service-grant",
                )
    if social_inbox_service_dependency_checks:
        for key in (
            "socialManifestDeclaresOptionalDependency",
            "socialDegradesSafely",
            "socialDependencyDocsPresent",
        ):
            if social_inbox_service_dependency_checks.get(key) is not True:
                failures.append(f"Social Inbox service-dependency check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-service-dependency",
                )
    if app_services_registry_checks:
        for key in (
            "contractV12AndCapabilitiesPresent",
            "routeFamilyPresent",
            "descriptorParserPresent",
            "runtimeWiresSharedCoordinator",
            "sdkHelpersPresent",
            "testsCoverManifestAndRouter",
        ):
            if app_services_registry_checks.get(key) is not True:
                failures.append(f"App-service registry check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "app-services.registry")
    if app_services_grants_checks:
        for key in (
            "grantModelHasRequiredFields",
            "grantStatusesPresent",
            "storesAreFileBackedAndInMemory",
            "coordinatorEnforcesApprovalRevocation",
            "testsCoverGrantLifecycle",
        ):
            if app_services_grants_checks.get(key) is not True:
                failures.append(f"App-service grant check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "app-services.grants")
    if app_services_dependency_graph_checks:
        for key in (
            "dependencyModelsPresent",
            "dependencyParserStrictFieldsPresent",
            "dependencyRoutesPresent",
            "dependencyTestsPresent",
        ):
            if app_services_dependency_graph_checks.get(key) is not True:
                failures.append(f"App-service dependency graph check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-services.dependency-graph"
                )
    if app_services_grant_bundles_checks:
        for key in (
            "bundleModelsAndStorePresent",
            "bundleRoutesPresent",
            "bundleCoordinatorHostOnly",
            "bundleTestsPresent",
        ):
            if app_services_grant_bundles_checks.get(key) is not True:
                failures.append(f"App-service grant-bundle check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-services.grant-bundles"
                )
    if app_services_grant_expiry_checks:
        for key in (
            "grantExpiryFieldsPresent",
            "expiredGrantsFailClosed",
            "renewalRevalidates",
        ):
            if app_services_grant_expiry_checks.get(key) is not True:
                failures.append(f"App-service grant expiry check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-services.grant-expiry-renewal"
                )
    if app_services_provider_revalidation_checks:
        for key in (
            "compatibilityFingerprintPresent",
            "descriptorDriftNonAuthorizing",
            "descriptorMatchingChecksVersionScopeContextKindAdapter",
        ):
            if app_services_provider_revalidation_checks.get(key) is not True:
                failures.append(f"App-service provider revalidation check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-services.provider-revalidation"
                )
    if app_services_provider_checks:
        for key in (
            "trustGraphManifestAdvertisesService",
            "adapterIsBoundedNotProxy",
            "providerDocsAndUiDescribePreviewGrantBoundary",
            "adapterTestsCoverRedaction",
        ):
            if app_services_provider_checks.get(key) is not True:
                failures.append(f"Trust-score provider check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-services.trust-score-provider"
                )
    if app_services_web_shell_checks:
        for key in (
            "webShellLoadsAppServiceData",
            "webShellRendersGrantActions",
            "webShellOmitsPrivateMaterial",
            "webShellTestsPresent",
        ):
            if app_services_web_shell_checks.get(key) is not True:
                failures.append(f"App-service Web Shell check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "app-services.web-shell")
    if app_services_redaction_checks:
        for key in (
            "auditModelIsRedacted",
            "invocationReturnsHashNotRawSubject",
            "grantJsonContainsOnlyFingerprint",
            "docsStateNoGenericProxyOrLocalhostTrust",
            "evidenceIdsDocumented",
        ):
            if app_services_redaction_checks.get(key) is not True:
                failures.append(f"App-service redaction check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "app-services.redaction")
    if app_services_dependency_redaction_checks:
        for key in (
            "dependencyJsonPathFreeByConstruction",
            "bundlePublicJsonFieldsSafe",
            "uiAndEvidenceAvoidRawSensitiveValues",
        ):
            if app_services_dependency_redaction_checks.get(key) is not True:
                failures.append(f"App-service dependency-redaction check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-services.dependency-redaction"
                )
    if social_mail_migration_checks:
        for key in (
            "migrationFramingPresent",
            "nonGoalsDocumented",
            "appComposesExpectedPlatformSurfaces",
            "uiStatesPreviewBoundary",
            "evidenceIdsDocumented",
        ):
            if social_mail_migration_checks.get(key) is not True:
                failures.append(f"Social/mail migration preview check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "migration.social-mail-preview",
                )
    generated_checks = nested_dict(generated_document_details, "checks")
    if generated_checks and generated_checks.get("routeDocumented") is not True:
        failures.append("Generated document insert route documentation check failed")
        add_evidence_issue(gate_details, "failureEvidenceIds", "app-platform.generated-document-insert")
    content_fetch_checks = nested_dict(content_fetch_details, "checks")
    if content_fetch_checks and content_fetch_checks.get("routeDocumented") is not True:
        failures.append("Content fetch route documentation check failed")
        add_evidence_issue(gate_details, "failureEvidenceIds", "app-platform.content-fetch")
    content_subscription_checks = nested_dict(content_subscription_details, "checks")
    if content_subscription_checks:
        for key in ("currentContractVersionV9", "routesPresent", "capabilityGatesPresent"):
            if content_subscription_checks.get(key) is not True:
                failures.append(f"Content subscription API check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.content-subscriptions"
                )
    app_data_store_checks = nested_dict(app_data_store_details, "checks")
    if app_data_store_checks:
        for key in (
            "contractV9AndCapabilities",
            "routesRequireAppPrincipalAndCapabilities",
            "fileBackedStoreIsPathSafeAndAtomic",
            "serviceBoundsQuotaAndImportExport",
            "docsCoverLimitsAndRedaction",
        ):
            if app_data_store_checks.get(key) is not True:
                failures.append(f"Durable app-data store check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.durable-app-data-store"
                )
    content_subscription_scheduler_checks = nested_dict(
        content_subscription_scheduler_details, "checks"
    )
    if content_subscription_scheduler_checks:
        for key in (
            "deterministicTickAndNoOverlap",
            "conservativeLimits",
            "dedupeAndMetadataOnly",
            "pressureGateStableSignals",
            "durablePathFreeStore",
        ):
            if content_subscription_scheduler_checks.get(key) is not True:
                failures.append(f"Content subscription scheduler check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "network-content.subscription-scheduler",
                )
    trust_preview_checks = nested_dict(trust_graph_preview_details, "checks")
    if trust_preview_checks:
        for key in ("contractVersionV7", "routesPresent", "capabilityGatesPresent"):
            if trust_preview_checks.get(key) is not True:
                failures.append(f"Trust graph preview API check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.trust-graph-preview"
                )
    trust_durable_store_checks = nested_dict(trust_graph_durable_store_details, "checks")
    if trust_durable_store_checks:
        for key in ("fileBackedStorePresent", "runtimeInjectsDurableStore", "durabilityTestsPresent"):
            if trust_durable_store_checks.get(key) is not True:
                failures.append(f"Trust graph durable store check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.trust-graph-durable-store"
                )
    trust_exchange_checks = nested_dict(trust_graph_exchange_details, "checks")
    if trust_exchange_checks:
        for key in ("contractVersionV10", "contractDescriptorsPresent", "sdkExchangeHelpersPresent"):
            if trust_exchange_checks.get(key) is not True:
                failures.append(f"Trust graph exchange check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.trust-graph-exchange"
                )
    if trust_graph_durable_exchange_checks:
        for key in (
            "manifestUsesContractV22",
            "usesSdkExchangeHelpers",
            "noRawApiOrManualFetch",
        ):
            if trust_graph_durable_exchange_checks.get(key) is not True:
                failures.append(f"Trust Graph Local RC durable exchange app check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.trust-graph-durable-exchange",
                )
    trust_signing_checks = nested_dict(trust_statement_signing_details, "checks")
    if trust_signing_checks:
        for key in ("routeInContract", "capabilitiesInContract", "handlerSignsCanonicalPayload"):
            if trust_signing_checks.get(key) is not True:
                failures.append(f"Trust statement signing check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.trust-statement-signing"
                )
    gate_details.update(
        {
            "currentStatus": status,
            "previousStatus": previous_status,
            "appId": details.get("appId"),
            "profilePublisherStatus": profile_status,
            "previousProfilePublisherStatus": previous_profile_status,
            "profilePublisherAppDataStatus": profile_app_data_status,
            "previousProfilePublisherAppDataStatus": previous_profile_app_data_status,
            "feedReaderStatus": feed_reader_status,
            "previousFeedReaderStatus": previous_feed_reader_status,
            "feedReaderAppDataStatus": feed_reader_app_data_status,
            "previousFeedReaderAppDataStatus": previous_feed_reader_app_data_status,
            "trustGraphStatus": trust_graph_status,
            "previousTrustGraphStatus": previous_trust_graph_status,
            "trustGraphAppDataPreviewStatus": trust_graph_app_data_status,
            "previousTrustGraphAppDataPreviewStatus": previous_trust_graph_app_data_status,
            "socialMessageSigningStatus": social_message_signing_status,
            "previousSocialMessageSigningStatus": previous_social_message_signing_status,
            "socialInboxStatus": social_inbox_status,
            "previousSocialInboxStatus": previous_social_inbox_status,
            "socialInboxSignedMessageStatus": social_inbox_signed_message_status,
            "previousSocialInboxSignedMessageStatus": previous_social_inbox_signed_message_status,
            "socialInboxSubscriptionStatus": social_inbox_subscription_status,
            "previousSocialInboxSubscriptionStatus": previous_social_inbox_subscription_status,
            "socialInboxAppDataStatus": social_inbox_app_data_status,
            "previousSocialInboxAppDataStatus": previous_social_inbox_app_data_status,
            "socialInboxTrustAnnotationStatus": social_inbox_trust_status,
            "previousSocialInboxTrustAnnotationStatus": previous_social_inbox_trust_status,
            "socialInboxRcThreadingStatus": social_inbox_rc_threading_status,
            "previousSocialInboxRcThreadingStatus": previous_social_inbox_rc_threading_status,
            "trustSocialBetaHardeningStatus": trust_social_beta_hardening_status,
            "previousTrustSocialBetaHardeningStatus": previous_trust_social_beta_hardening_status,
            "trustSocialContentFormatProfilesStatus": (
                trust_social_content_format_profiles_status
            ),
            "previousTrustSocialContentFormatProfilesStatus": (
                previous_trust_social_content_format_profiles_status
            ),
            "socialMailMigrationStatus": social_mail_migration_status,
            "previousSocialMailMigrationStatus": previous_social_mail_migration_status,
            "generatedDocumentInsertStatus": generated_document_status,
            "previousGeneratedDocumentInsertStatus": previous_generated_document_status,
            "contentFetchStatus": content_fetch_status,
            "previousContentFetchStatus": previous_content_fetch_status,
            "appDataStoreStatus": app_data_store_status,
            "previousAppDataStoreStatus": previous_app_data_store_status,
            "trustGraphPreviewStatus": trust_graph_preview_status,
            "previousTrustGraphPreviewStatus": previous_trust_graph_preview_status,
            "trustStatementSigningStatus": trust_statement_signing_status,
            "previousTrustStatementSigningStatus": previous_trust_statement_signing_status,
            "appServicesDependencyGraphStatus": app_services_dependency_graph_status,
            "previousAppServicesDependencyGraphStatus": previous_app_services_dependency_graph_status,
            "appServicesGrantBundlesStatus": app_services_grant_bundles_status,
            "previousAppServicesGrantBundlesStatus": previous_app_services_grant_bundles_status,
            "appServicesGrantExpiryStatus": app_services_grant_expiry_status,
            "previousAppServicesGrantExpiryStatus": previous_app_services_grant_expiry_status,
            "appServicesProviderRevalidationStatus": app_services_provider_revalidation_status,
            "previousAppServicesProviderRevalidationStatus": (
                previous_app_services_provider_revalidation_status
            ),
            "socialInboxServiceDependencyStatus": social_inbox_service_dependency_status,
            "previousSocialInboxServiceDependencyStatus": (
                previous_social_inbox_service_dependency_status
            ),
            "appServicesDependencyRedactionStatus": app_services_dependency_redaction_status,
            "previousAppServicesDependencyRedactionStatus": (
                previous_app_services_dependency_redaction_status
            ),
            "profilePublisherAppId": profile_details.get("appId"),
            "feedReaderAppId": feed_reader_details.get("appId"),
            "trustGraphAppId": trust_graph_details.get("appId"),
            "socialInboxAppId": social_inbox_details.get("appId"),
        }
    )
    return gate_from_issues(
        "ecosystem.reference-content-apps",
        "Reference content, profile, feed, trust, and social inbox app evidence passed.",
        failures,
        warnings,
        gate_details,
    )


def evaluate_legacy_retirement_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}
    for evidence_id in (
        "legacy.retirement",
        "legacy-admin.removal-wave-1",
        "legacy-admin.removal-wave-2",
        "legacy-admin.removal-wave-3",
        "legacy-admin.removal-wave-4",
        "legacy-admin.removal-wave-5",
        "legacy-admin.final-admin-surface",
        "legacy-admin.browse-retained",
        "legacy-admin.emergency-fallback-retained",
    ):
        status = evidence_status(current.get(evidence_id))
        previous_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {"currentStatus": status, "previousStatus": previous_status}
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_status == "pass" and status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    for evidence_id in (
        "legacy-admin.removal-wave-1",
        "legacy-admin.removal-wave-2",
        "legacy-admin.removal-wave-3",
        "legacy-admin.removal-wave-4",
        "legacy-admin.removal-wave-5",
    ):
        current_wave = evidence_details(current.get(evidence_id))
        previous_wave = evidence_details(previous.get(evidence_id))
        current_routes = set(sorted_strings(current_wave.get("removedByDefaultRouteIds")))
        previous_routes = set(sorted_strings(previous_wave.get("removedByDefaultRouteIds")))
        details[f"{evidence_id}.removedByDefaultRouteCounts"] = {
            "current": len(current_routes),
            "previous": len(previous_routes),
        }
        if previous_routes and current_routes != previous_routes:
            if current_wave.get("docsDescribeWave") or current_wave.get("updateNote"):
                warnings.append(f"{evidence_id} route set changed with documentation evidence")
                add_evidence_issue(details, "warningEvidenceIds", evidence_id)
            else:
                warnings.append(f"{evidence_id} route set changed without doc/update note metadata")
                add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        safety = current_wave.get("retainedBrowseSafety") or current_wave.get("retainedScope")
        if isinstance(safety, dict) and any(value is False for value in safety.values()):
            failures.append(f"{evidence_id} retained browse safety evidence failed")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    return gate_from_issues(
        "ecosystem.legacy-retirement",
        "Legacy retirement and removal-wave evidence passed.",
        failures,
        warnings,
        details,
    )


def evaluate_waiver_validation_gate(context: WaiverContext, mode: str) -> GateResult | None:
    if not context.errors:
        return None
    status = "fail" if mode == "release-candidate" else "warn"
    return GateResult(
        "ecosystem.waivers",
        status,
        status == "fail",
        "Structured waiver files contain validation errors.",
        {"errors": context.errors, "issueIds": ["ecosystem.waivers.validation"]},
    )


def unique_ids(values: Any) -> list[str]:
    return sorted(dict.fromkeys(str(value) for value in values if str(value).strip()))


def detail_waiver_ids(details: dict[str, Any]) -> list[str]:
    waiver_ids: list[Any] = []
    existing_ids = details.get("waiverIds", [])
    if isinstance(existing_ids, list):
        waiver_ids.extend(existing_ids)
    elif existing_ids:
        waiver_ids.append(existing_ids)
    direct_waiver_id = details.get("waiverId")
    if direct_waiver_id:
        waiver_ids.append(direct_waiver_id)
    return unique_ids(waiver_ids)


def evidence_detail_waiver_id(entry: dict[str, Any] | None) -> str:
    details = evidence_details(entry)
    waiver_id = details.get("waiverId")
    return str(waiver_id) if waiver_id else ""


def gate_detail_waiver_id(gate: GateResult | None) -> str:
    if gate is None:
        return ""
    waiver_id = gate.details.get("waiverId")
    return str(waiver_id) if waiver_id else ""


def gate_waiver_ids(gate: GateResult | None) -> list[str]:
    if gate is None:
        return []
    return detail_waiver_ids(gate.details)


def ecosystem_matrix_row_ids_for_evidence(evidence_id: str) -> list[str]:
    return unique_ids(
        spec.id for spec in ecosystem_matrix_row_specs() if evidence_id in spec.evidence_ids()
    )


def active_waiver_for_ecosystem_rc_evidence(
    context: WaiverContext, evidence_id: str, mode: str
) -> WaiverRecord | None:
    issue_ids = [
        f"evidence.{evidence_id}",
        *ecosystem_matrix_row_ids_for_evidence(evidence_id),
    ]
    return active_waiver_for(context, evidence_id, issue_ids, mode)


def ecosystem_rc_evidence_waiver_id(
    entry: dict[str, Any] | None,
    context: WaiverContext,
    evidence_id: str,
    mode: str,
) -> str:
    if evidence_entry_has_unwaivable_redaction_findings(entry):
        return ""
    waiver_id = evidence_detail_waiver_id(entry)
    if waiver_id:
        return waiver_id
    waiver = active_waiver_for_ecosystem_rc_evidence(context, evidence_id, mode)
    return waiver.id if waiver is not None else ""


def ecosystem_rc_evidence_satisfied(
    entries: dict[str, dict[str, Any]],
    context: WaiverContext,
    evidence_id: str,
    mode: str,
) -> bool:
    entry = entries.get(evidence_id)
    status = evidence_status(entry)
    if status not in {"fail", "missing", "skip"}:
        return True
    return bool(ecosystem_rc_evidence_waiver_id(entry, context, evidence_id, mode))


def conditional_ecosystem_rc_required_evidence_ids(settings: Settings) -> list[str]:
    evidence_ids = list(ECOSYSTEM_RC_REQUIRED_EVIDENCE_IDS)
    if settings.live_network_beta_required:
        evidence_ids.extend(LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS)
    return unique_ids(evidence_ids)


def conditional_ecosystem_rc_required_gate_ids(
    settings: Settings, gate_entries: dict[str, GateResult]
) -> list[str]:
    gate_ids = list(ECOSYSTEM_RC_REQUIRED_GATE_IDS)
    if settings.live_network_beta_required:
        gate_ids.append("ecosystem.live-network-beta")
    if "ecosystem.waivers" in gate_entries:
        gate_ids.append("ecosystem.waivers")
    return unique_ids(gate_ids)


def evaluate_ecosystem_rc_certification_gate(
    settings: Settings,
    current_evidence: list[EvidenceItem],
    child_gates: list[GateResult],
    history_comparison: dict[str, Any],
    waiver_context: WaiverContext,
) -> GateResult:
    current = evidence_map_from_items(current_evidence)
    gate_entries = {gate.id: gate for gate in child_gates}
    required_evidence_ids = conditional_ecosystem_rc_required_evidence_ids(settings)
    required_gate_ids = conditional_ecosystem_rc_required_gate_ids(settings, gate_entries)
    optional_gate_ids = [] if settings.live_network_beta_required else ["ecosystem.live-network-beta"]
    failed_evidence_ids: list[str] = []
    warning_evidence_ids: list[str] = []
    missing_evidence_ids: list[str] = []
    skipped_evidence_ids: list[str] = []
    waived_evidence_ids: list[str] = []
    waived_gate_ids: list[str] = []
    waiver_ids: list[str] = []
    redaction_failure_ids: list[str] = []

    for evidence_id in required_evidence_ids:
        entry = current.get(evidence_id)
        status = evidence_status(entry)
        if evidence_entry_has_unwaivable_redaction_findings(entry):
            redaction_failure_ids.append(evidence_id)
            failed_evidence_ids.append(evidence_id)
            continue
        waiver_id = (
            ecosystem_rc_evidence_waiver_id(entry, waiver_context, evidence_id, settings.mode)
            if status in {"fail", "missing", "skip", "warn"}
            else evidence_detail_waiver_id(entry)
        )
        if waiver_id:
            waived_evidence_ids.append(evidence_id)
            waiver_ids.append(waiver_id)
        if status == "fail":
            if waiver_id:
                warning_evidence_ids.append(evidence_id)
            else:
                failed_evidence_ids.append(evidence_id)
        elif status == "missing":
            if waiver_id:
                warning_evidence_ids.append(evidence_id)
            else:
                missing_evidence_ids.append(evidence_id)
        elif status == "skip":
            if waiver_id:
                warning_evidence_ids.append(evidence_id)
            elif settings.mode == "release-candidate":
                skipped_evidence_ids.append(evidence_id)
            else:
                warning_evidence_ids.append(evidence_id)
        elif status == "warn":
            warning_evidence_ids.append(evidence_id)

    blocking_gate_ids: list[str] = []
    warning_gate_ids: list[str] = []
    for gate_id in required_gate_ids:
        gate = gate_entries.get(gate_id)
        if gate is None:
            blocking_gate_ids.append(gate_id)
            continue
        waiver_id = gate_detail_waiver_id(gate)
        if waiver_id:
            waived_gate_ids.append(gate_id)
            waiver_ids.append(waiver_id)
        if gate.status == "fail" and gate.release_blocker:
            blocking_gate_ids.append(gate_id)
        elif gate.status in {"warn", "fail", "missing"}:
            warning_gate_ids.append(gate_id)
    for gate_id in optional_gate_ids:
        gate = gate_entries.get(gate_id)
        if gate is not None and gate.status in {"warn", "fail", "missing"}:
            warning_gate_ids.append(gate_id)

    history_status = normalize_evidence_status(str(history_comparison.get("status", "missing")))
    if history_status == "fail":
        blocking_gate_ids.append("history-comparison")
    elif history_status in {"warn", "missing"}:
        warning_gate_ids.append("history-comparison")

    matrix_entry = current.get("release-certification.ecosystem-matrix")
    matrix_coverage = evidence_details(matrix_entry).get("coverage", {})
    matrix_redaction_passed = (
        bool(matrix_coverage.get("redactionPassed", True))
        if isinstance(matrix_coverage, dict)
        else True
    )
    redaction_evidence_passed = True
    for evidence_id in ECOSYSTEM_RC_REDACTION_EVIDENCE_IDS:
        entry = current.get(evidence_id)
        status = evidence_status(entry)
        has_redaction_findings = evidence_entry_has_unwaivable_redaction_findings(entry)
        if (
            evidence_id == "live-network-beta.redaction"
            and not settings.live_network_beta_required
            and status in {"missing", "skip"}
            and not has_redaction_findings
        ):
            continue
        if has_redaction_findings:
            redaction_evidence_passed = False
            if evidence_id not in redaction_failure_ids:
                redaction_failure_ids.append(evidence_id)
    redaction_passed = matrix_redaction_passed and redaction_evidence_passed

    live_required = settings.live_network_beta_required
    live_network_satisfied = (not live_required) or all(
        ecosystem_rc_evidence_satisfied(
            current,
            waiver_context,
            evidence_id,
            settings.mode,
        )
        for evidence_id in LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS
    )
    network_scale_soak_satisfied = ecosystem_rc_evidence_satisfied(
        current,
        waiver_context,
        NETWORK_SCALE_SOAK_EVIDENCE_ID,
        settings.mode,
    )
    multi_node_beta_satisfied = all(
        ecosystem_rc_evidence_satisfied(
            current,
            waiver_context,
            evidence_id,
            settings.mode,
        )
        for evidence_id in MULTI_NODE_BETA_EVIDENCE_IDS
    )
    first_party_gate = gate_entries.get("ecosystem.first-party-apps")
    first_party_apps_covered = first_party_gate is not None and first_party_gate.status in {"pass", "warn"}

    failed_evidence_ids = unique_ids(failed_evidence_ids)
    warning_evidence_ids = unique_ids(warning_evidence_ids)
    missing_evidence_ids = unique_ids(missing_evidence_ids)
    skipped_evidence_ids = unique_ids(skipped_evidence_ids)
    blocking_gate_ids = unique_ids(blocking_gate_ids)
    warning_gate_ids = unique_ids(warning_gate_ids)
    waived_evidence_ids = unique_ids(waived_evidence_ids)
    waived_gate_ids = unique_ids(waived_gate_ids)
    waiver_ids = unique_ids(waiver_ids)
    redaction_failure_ids = unique_ids(redaction_failure_ids)

    has_blockers = bool(
        failed_evidence_ids
        or missing_evidence_ids
        or (settings.mode == "release-candidate" and skipped_evidence_ids)
        or blocking_gate_ids
        or not redaction_passed
        or not network_scale_soak_satisfied
        or not multi_node_beta_satisfied
        or not live_network_satisfied
    )
    has_warnings = bool(
        warning_evidence_ids
        or skipped_evidence_ids
        or warning_gate_ids
        or waiver_ids
        or history_status in {"warn", "missing"}
    )
    release_blocker = has_blockers and (settings.mode == "release-candidate" or not redaction_passed)
    status = "fail" if release_blocker else ("warn" if has_blockers or has_warnings else "pass")
    promotion_ready = not release_blocker
    details = {
        "phase": "phase-9",
        "requiredEvidenceIds": required_evidence_ids,
        "requiredGateIds": required_gate_ids,
        "optionalGateIds": optional_gate_ids,
        "failedEvidenceIds": failed_evidence_ids,
        "warningEvidenceIds": warning_evidence_ids,
        "missingEvidenceIds": missing_evidence_ids,
        "skippedEvidenceIds": skipped_evidence_ids,
        "blockingGateIds": blocking_gate_ids,
        "warningGateIds": warning_gate_ids,
        "waiverIds": waiver_ids,
        "waivedEvidenceIds": waived_evidence_ids,
        "waivedGateIds": waived_gate_ids,
        "historyComparisonStatus": history_status,
        "liveNetworkRequired": live_required,
        "liveNetworkSatisfied": live_network_satisfied,
        "networkScaleSoakSatisfied": network_scale_soak_satisfied,
        "multiNodeBetaSatisfied": multi_node_beta_satisfied,
        "redactionPassed": redaction_passed,
        "redactionFailureEvidenceIds": redaction_failure_ids,
        "firstPartyAppsCovered": first_party_apps_covered,
        "promotionReady": promotion_ready,
    }
    if failed_evidence_ids or missing_evidence_ids or skipped_evidence_ids:
        details["failureEvidenceIds"] = unique_ids(
            failed_evidence_ids + missing_evidence_ids + skipped_evidence_ids
        )
    if redaction_failure_ids:
        details["unwaivableFailureEvidenceIds"] = redaction_failure_ids
    if warning_evidence_ids:
        details["warningEvidenceIds"] = warning_evidence_ids
    summary = (
        "Ecosystem RC certification is ready for promotion."
        if status == "pass"
        else (
            "Ecosystem RC certification has warnings or waived blockers."
            if status == "warn"
            else "Ecosystem RC certification has release-blocking failures."
        )
    )
    return GateResult(ECOSYSTEM_RC_GATE_ID, status, release_blocker, summary, details)


def evaluate_ecosystem_gates(
    settings: Settings,
    current_evidence: list[EvidenceItem],
    previous_summary: dict[str, Any] | None,
    history_comparison: dict[str, Any],
    metadata: dict[str, Any],
    waiver_context: WaiverContext,
) -> list[GateResult]:
    current = evidence_map_from_items(current_evidence)
    previous = evidence_map_from_summary(previous_summary)
    diffs = history_comparison.get("evidenceDiffs", [])
    if not isinstance(diffs, list):
        diffs = []
    child_gates = [
        evaluate_required_evidence_regressions([diff for diff in diffs if isinstance(diff, dict)]),
        evaluate_platform_api_gate(current, previous, settings.mode, settings.require_history),
        evaluate_first_party_apps_gate(current, previous),
        evaluate_app_ui_quality_gate(current, previous),
        evaluate_app_review_trust_gate(current, previous, metadata, settings.mode),
        evaluate_app_update_rollback_gate(current, previous),
        evaluate_operator_rc_recovery_gate(current, previous),
        evaluate_ecosystem_security_advisory_revocation_gate(current, previous),
        evaluate_live_network_beta_gate(current, settings),
        evaluate_multi_node_beta_gate(current, settings),
        evaluate_app_vault_gate(current, previous),
        evaluate_sandbox_provider_gate(current, previous, settings.mode, metadata),
        evaluate_reference_content_gate(current, previous),
        evaluate_legacy_retirement_gate(current, previous),
    ]
    waiver_gate = evaluate_waiver_validation_gate(waiver_context, settings.mode)
    if waiver_gate is not None:
        child_gates.append(waiver_gate)
    waived_child_gates = [
        apply_waiver_to_gate(gate, waiver_context, settings.mode) for gate in child_gates
    ]
    final_gate = evaluate_ecosystem_rc_certification_gate(
        settings,
        current_evidence,
        waived_child_gates,
        history_comparison,
        waiver_context,
    )
    return [
        *waived_child_gates,
        apply_waiver_to_gate(final_gate, waiver_context, settings.mode),
    ]


def history_status_affects_decision(status: str) -> bool:
    return status in {"warn", "fail", "missing"}


def determine_certification_status(
    mode: str,
    evidence: list[EvidenceItem],
    history_comparison: dict[str, Any],
    ecosystem_gates: list[GateResult],
    waiver_context: WaiverContext,
) -> tuple[str, bool]:
    evidence_status_value, evidence_release_passed = determine_overall_status(
        mode, evidence, waiver_context
    )
    history_status = normalize_evidence_status(str(history_comparison.get("status", "missing")))
    gate_failures = [gate for gate in ecosystem_gates if gate.status == "fail" and gate.release_blocker]
    gate_warnings = [gate for gate in ecosystem_gates if gate.status in {"warn", "fail", "missing"}]
    history_warning = history_status_affects_decision(history_status)
    release_candidate_passed = evidence_release_passed and not gate_failures and history_status != "fail"
    if mode == "release-candidate":
        if evidence_status_value == "fail" or gate_failures or history_status == "fail":
            return "fail", False
        if evidence_status_value == "warn" or gate_warnings or history_warning:
            return "warn", release_candidate_passed
        return "pass", True
    if mode == "nightly":
        if evidence_status_value == "fail" or gate_failures:
            return "fail", False
        if evidence_status_value == "warn" or gate_warnings or history_warning:
            return "warn", release_candidate_passed
        return "pass", True
    if evidence_status_value == "warn" or gate_warnings or history_warning:
        return "warn", release_candidate_passed
    return "pass", release_candidate_passed


def promotion_decision(status: str, release_candidate_passed: bool = True) -> str:
    if not release_candidate_passed:
        return "FAIL"
    if status == "pass":
        return "PASS"
    if status == "warn":
        return "PASS WITH WARNINGS"
    return "FAIL"


def report_status_label(status: Any) -> str:
    normalized = normalize_evidence_status(str(status))
    if normalized in {"skip", "missing"}:
        return "NOT AVAILABLE"
    return normalized.upper()


def aggregate_gate_status(gates: list[GateResult]) -> str:
    if any(gate.status == "fail" for gate in gates):
        return "fail"
    if any(gate.status == "warn" for gate in gates):
        return "warn"
    return "pass"


def ecosystem_rc_gate_summary(gates: list[GateResult]) -> dict[str, Any]:
    gate = next((candidate for candidate in gates if candidate.id == ECOSYSTEM_RC_GATE_ID), None)
    if gate is None:
        return {
            "id": ECOSYSTEM_RC_GATE_ID,
            "status": "missing",
            "releaseBlocker": True,
            "promotionReady": False,
            "failedEvidenceCount": 0,
            "missingEvidenceCount": 0,
            "blockingGateCount": 1,
            "waiverCount": 0,
        }
    details = gate.details
    waiver_ids = gate_waiver_ids(gate)
    return {
        "id": gate.id,
        "status": gate.status,
        "releaseBlocker": gate.release_blocker,
        "promotionReady": bool(details.get("promotionReady", not gate.release_blocker)),
        "failedEvidenceCount": len(details.get("failedEvidenceIds", [])),
        "missingEvidenceCount": len(details.get("missingEvidenceIds", [])),
        "warningEvidenceCount": len(details.get("warningEvidenceIds", [])),
        "blockingGateCount": len(details.get("blockingGateIds", [])),
        "warningGateCount": len(details.get("warningGateIds", [])),
        "waiverCount": len(waiver_ids),
    }


def ecosystem_rc_decision(compact_gate: dict[str, Any]) -> str:
    if compact_gate.get("releaseBlocker") or compact_gate.get("status") in {"fail", "missing"}:
        return "FAIL"
    if compact_gate.get("status") == "warn":
        return "PASS_WITH_WARNINGS"
    return "PASS"


def safe_multi_node_report_text(source_path: Path, settings: Settings, out_dir: Path) -> str | None:
    try:
        report_text = source_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    findings = multi_node_beta_soak.scan_redaction_payload({}, report_text)
    if not findings:
        return scrub_text(report_text, settings.workspace_root, out_dir)
    finding_kinds = sorted({str(finding.get("kind", "redaction-finding")) for finding in findings})
    return (
        "# Multi-node Beta Soak Report Redacted\n\n"
        "The attached multi-node report was not copied because the multi-node redaction "
        "scanner found prohibited content. Use the compact JSON summary for release evidence.\n\n"
        f"- findingCount: {len(findings)}\n"
        f"- findingKinds: {', '.join(finding_kinds)}\n"
    )


def collect_source_artifacts(settings: Settings, out_dir: Path) -> list[str]:
    artifacts_dir = out_dir / "artifacts"
    if artifacts_dir.exists():
        shutil.rmtree(artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    source_map = {
        "interop-smoke-summary.json": settings.interop_smoke_summary,
        "interop-extended-summary.json": settings.interop_extended_summary,
        "performance-smoke-summary.json": settings.perf_smoke_summary,
        "app-platform-smoke-summary.json": settings.app_platform_summary,
        "security-drills-summary.json": settings.security_drills_summary
        or settings.workspace_root / "build/security-drills/security-drills-summary.json",
        "interop-smoke-report.md": settings.interop_smoke_summary.parent / "artifacts" / "interop-report.md",
        "interop-extended-report.md": settings.interop_extended_summary.parent / "artifacts" / "interop-report.md",
        "performance-smoke-report.md": settings.perf_smoke_summary.parent / "artifacts" / "perf-report.md",
        "app-platform-smoke-report.md": settings.app_platform_summary.parent / "app-platform-smoke-report.md",
        "network-scale-soak-summary.json": settings.network_scale_soak_summary,
        "multi-node-beta-soak-summary.json": settings.multi_node_soak_summary,
        "multi-node-beta-soak-report.md": settings.multi_node_soak_summary.parent
        / multi_node_beta_soak.REPORT_FILE_NAME,
    }
    if settings.live_network_beta_enabled or settings.live_network_beta_required:
        source_map.update(
            {
                "live-network-beta-smoke-summary.json": settings.live_network_summary,
                "live-network-beta-smoke-report.md": settings.live_network_summary.parent
                / "live-network-beta-smoke-report.md",
            }
        )
    copied: list[str] = []
    for target_name, source_path in source_map.items():
        if not source_path.is_file():
            continue
        if any(name in str(source_path) for name in PRIVATE_ARTIFACT_NAMES):
            continue
        target_path = artifacts_dir / target_name
        if target_name.endswith(".json"):
            value = read_json(source_path)
            if value is None:
                continue
            if target_name == "network-scale-soak-summary.json":
                safe_value, _ = allowlisted_network_scale_soak_summary(value)
            elif target_name == "multi-node-beta-soak-summary.json":
                safe_value = sanitize_compact_multi_node_summary(value, settings.workspace_root, out_dir)
            else:
                safe_value = sanitize_value(value, settings.workspace_root, out_dir)
            write_json(target_path, safe_value)
        elif target_name == "multi-node-beta-soak-report.md":
            safe_text = safe_multi_node_report_text(source_path, settings, out_dir)
            if safe_text is None:
                continue
            target_path.write_text(safe_text, encoding="utf-8")
        else:
            target_path.write_text(
                scrub_text(source_path.read_text(encoding="utf-8"), settings.workspace_root, out_dir),
                encoding="utf-8",
            )
        copied.append(display_path(target_path, settings.workspace_root, out_dir))
    return copied


def sanitize_compact_multi_node_summary(
    value: dict[str, Any],
    workspace_root: Path,
    out_dir: Path,
) -> dict[str, Any]:
    compact = multi_node_beta_soak.compact_for_release(value)
    safe_value = sanitize_value(compact, workspace_root, out_dir)
    if not isinstance(safe_value, dict):
        return {}
    safe_redaction = safe_value.get("redaction")
    compact_redaction = compact.get("redaction")
    if not isinstance(safe_redaction, dict) or not isinstance(compact_redaction, dict):
        return safe_value
    safe_checks = safe_redaction.get("checks")
    compact_checks = compact_redaction.get("checks")
    if not isinstance(safe_checks, dict) or not isinstance(compact_checks, dict):
        return safe_value
    for key in multi_node_beta_soak.REDACTION_KEYS:
        value = compact_checks.get(key)
        if isinstance(value, bool):
            safe_checks[key] = value
    return safe_value


def collect_metadata(settings: Settings) -> dict[str, Any]:
    metadata = {}
    metadata.update(collect_git_metadata(settings))
    metadata.update(collect_ci_metadata(os.environ))
    metadata.update(settings.metadata)
    return dict(sanitize_value(metadata, settings.workspace_root, settings.out_dir))


def sanitized_cli_waivers(settings: Settings) -> dict[str, str]:
    return {
        scrub_text(str(waiver_id), settings.workspace_root, settings.out_dir): scrub_text(
            reason, settings.workspace_root, settings.out_dir
        )
        for waiver_id, reason in settings.waivers.items()
    }


def build_summary(
    settings: Settings,
    evidence: list[EvidenceItem],
    copied_artifacts: list[str],
    generated_at: str,
    metadata: dict[str, Any],
    history_comparison: dict[str, Any],
    ecosystem_gates: list[GateResult],
    waiver_context: WaiverContext,
    ecosystem_matrix: dict[str, Any] | None = None,
) -> dict[str, Any]:
    status, release_candidate_passed = determine_certification_status(
        settings.mode, evidence, history_comparison, ecosystem_gates, waiver_context
    )
    ecosystem_status = aggregate_gate_status(ecosystem_gates)
    cli_waivers = sanitized_cli_waivers(settings)
    compact_matrix = matrix_compact_summary(ecosystem_matrix)
    compact_stable_readiness = stable_readiness_compact_summary(
        evidence,
        settings.stable_readiness_required,
    )
    matrix_rows = (
        ecosystem_matrix.get("rows")
        if isinstance(ecosystem_matrix, dict)
        else None
    )
    if required_stable_readiness_blocking(settings, matrix_rows):
        status = "fail"
        release_candidate_passed = False
    compact_rc_gate = ecosystem_rc_gate_summary(ecosystem_gates)
    compact_rc_gate_decision = ecosystem_rc_decision(compact_rc_gate)
    compact_rc_decision = compact_rc_gate_decision if release_candidate_passed else "FAIL"
    ecosystem_rc_passed = (
        compact_rc_decision != "FAIL"
        and bool(compact_rc_gate.get("promotionReady", False))
    )
    return {
        "schemaVersion": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "mode": settings.mode,
        "status": status,
        "promotionDecision": promotion_decision(status, release_candidate_passed),
        "releaseCandidatePassed": release_candidate_passed,
        "generatedAt": generated_at,
        "workspaceRoot": "<repo>",
        "summaryPath": display_path(settings.out_dir / SUMMARY_FILE_NAME, settings.workspace_root, settings.out_dir),
        "reportPath": display_path(settings.out_dir / REPORT_FILE_NAME, settings.workspace_root, settings.out_dir),
        "ecosystemMatrixStatus": compact_matrix.get("status", "missing"),
        "ecosystemMatrixPath": display_path(
            settings.out_dir / ECOSYSTEM_MATRIX_FILE_NAME, settings.workspace_root, settings.out_dir
        ),
        "ecosystemMatrixReportPath": display_path(
            settings.out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME, settings.workspace_root, settings.out_dir
        ),
        "historyComparisonPath": display_path(
            settings.out_dir / HISTORY_COMPARISON_FILE_NAME, settings.workspace_root, settings.out_dir
        ),
        "historyComparisonReportPath": display_path(
            settings.out_dir / HISTORY_COMPARISON_REPORT_FILE_NAME, settings.workspace_root, settings.out_dir
        ),
        "artifactsDir": display_path(settings.out_dir / "artifacts", settings.workspace_root, settings.out_dir),
        "metadata": metadata,
        "waivers": cli_waivers,
        "cliWaivers": cli_waivers,
        "waiverRecords": [record.to_json() for record in waiver_context.records],
        "counts": evidence_counts(evidence),
        "evidence": [item.to_json() for item in evidence],
        "historyComparison": history_comparison,
        "ecosystemGateStatus": ecosystem_status,
        "ecosystemGates": [gate.to_json() for gate in ecosystem_gates],
        "ecosystemRcGate": compact_rc_gate,
        "ecosystemRcPassed": ecosystem_rc_passed,
        "ecosystemRcDecision": compact_rc_decision,
        "ecosystemMatrix": compact_matrix,
        "stableReadiness": compact_stable_readiness,
        "copiedArtifacts": copied_artifacts,
        "redaction": {
            "privateArtifactsExcluded": list(PRIVATE_ARTIFACT_NAMES),
            "secretMaterialRedacted": True,
            "formPasswordsRedacted": True,
            "rawFeedBodiesExcluded": True,
            "rawRequestBodiesExcluded": True,
            "privateInsertUrisExcluded": True,
            "appProcessTokensRedacted": True,
            "browserSessionTokensRedacted": True,
            "signatureValuesRedacted": True,
            "rawUpdateRollbackOutputsExcluded": True,
            "absolutePathsSanitized": True,
        },
    }


def render_report(summary: dict[str, Any]) -> str:
    history = summary.get("historyComparison", {})
    history_status = history.get("status", "missing") if isinstance(history, dict) else "missing"
    decision = summary.get("promotionDecision")
    if not isinstance(decision, str) or not decision:
        decision = promotion_decision(
            str(summary["status"]),
            bool(summary.get("releaseCandidatePassed", True)),
        )
    lines = [
        "# Release Certification Report",
        "",
        f"- Promotion decision: `{decision}`",
        f"- History comparison: `{report_status_label(history_status)}`",
        f"- Ecosystem gates: `{report_status_label(summary.get('ecosystemGateStatus', 'missing'))}`",
        f"- Mode: `{summary['mode']}`",
        f"- Status: `{summary['status']}`",
        f"- Release-candidate gate: `{'passed' if summary['releaseCandidatePassed'] else 'failed'}`",
        f"- Generated: `{summary['generatedAt']}`",
        f"- Summary: `{summary['summaryPath']}`",
        f"- Artifacts: `{summary['artifactsDir']}`",
        "",
    ]
    append_history_comparison(lines, summary)
    append_ecosystem_rc_gate(lines, summary)
    append_ecosystem_gates(lines, summary)
    append_ecosystem_matrix_summary(lines, summary)
    append_stable_readiness_summary(lines, summary)
    append_waivers(lines, summary)
    append_regressions(lines, summary)
    lines.extend(["## Evidence Summary", "", "| Evidence | Status | Required for RC | Source | Summary |", "| --- | --- | --- | --- | --- |"])
    for item in summary["evidence"]:
        required = "yes" if item["requiredForReleaseCandidate"] else "no"
        lines.append(
            "| `{id}` | `{status}` | {required} | `{source}` | {summary_text} |".format(
                id=item["id"],
                status=item["status"],
                required=required,
                source=item["source"],
                summary_text=str(item["summary"]).replace("|", "\\|"),
            )
        )
    lines.extend(["", "## Release Operations", ""])
    append_detail(lines, summary, "release-certification.ecosystem-matrix")
    append_detail(lines, summary, ECOSYSTEM_RC_EVIDENCE_ID)
    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS:
        append_detail(lines, summary, evidence_id)
    lines.extend(["", "## Hyphanet Interop", ""])
    append_detail(lines, summary, "interop.smoke")
    append_detail(lines, summary, "interop.extended")
    lines.extend(["", "## Performance Regression", ""])
    append_detail(lines, summary, "performance.smoke")
    lines.extend(["", "## Live Network Beta", ""])
    for evidence_id in LIVE_NETWORK_BETA_EVIDENCE_IDS:
        append_detail(lines, summary, evidence_id)
    lines.extend(["", "## App Platform", ""])
    for evidence_id in (
        "app-platform.first-party",
        FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID,
        "app-platform.devtools-cli",
        "app-platform.developer-beta-toolkit",
        "app-platform.docs-portal",
        "app-platform.beta-program",
        "app-platform.beta-tutorials",
        "app-platform.docs-redaction",
        *PUBLIC_BETA_DOCS_EVIDENCE_IDS,
        *THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS,
        "platform-api.contract",
        "app-vault.capabilities",
        "app-platform.identity-profile-publish",
        "app-platform.generated-document-insert",
        "app-platform.content-fetch",
        "app-platform.content-subscriptions",
        "network-content.subscription-scheduler",
        "app-platform.durable-app-data-store",
        "app-data.backup-restore-portability",
        "app-platform.trust-graph-preview",
        "app-platform.trust-graph-rc-scope-and-safety",
        "app-platform.trust-graph-durable-store",
        "app-platform.trust-graph-exchange",
        "app-platform.trust-social-beta-hardening",
        "app-platform.trust-social-content-format-profiles",
        "app-platform.trust-statement-signing",
        "app-platform.social-message-signing",
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
        "app-platform.trust-social-beta-hardening",
        "app-platform.trust-social-content-format-profiles",
        "migration.social-mail-preview",
        *APP_SERVICE_DISCOVERY_AND_GRANT_EVIDENCE_IDS,
        "legacy-plugin.migration-guide",
        "legacy-plugin.social-inbox-spike",
        "legacy-plugin.migration-finalization",
        "apphost.sandbox-provider",
        *PUBLIC_BETA_SECURITY_EVIDENCE_IDS,
        "app-update.lifecycle",
        "app-update.scheduler",
        "app-update.live-catalog-refresh",
        "app-update.rollback",
        "app-update.data-migration-contract",
        *OPERATOR_BETA_EVIDENCE_IDS,
        *OPERATOR_RC_EVIDENCE_IDS,
        "apphost.live",
    ):
        append_detail(lines, summary, evidence_id)
    lines.extend(["", "## Legacy Admin Retirement", ""])
    append_detail(lines, summary, "legacy.retirement")
    append_detail(lines, summary, "legacy-admin.removal-wave-1")
    append_detail(lines, summary, "legacy-admin.removal-wave-2")
    append_detail(lines, summary, "legacy-admin.removal-wave-3")
    append_detail(lines, summary, "legacy-admin.removal-wave-4")
    append_detail(lines, summary, "legacy-admin.removal-wave-5")
    append_detail(lines, summary, "legacy-admin.final-admin-surface")
    append_detail(lines, summary, "legacy-admin.browse-retained")
    append_detail(lines, summary, "legacy-admin.emergency-fallback-retained")
    lines.extend(
        [
            "",
            "## Redaction Rules",
            "",
            "- Private signing keys, form passwords, app process tokens, browser-session tokens, raw request bodies, raw feed bodies, raw update or rollback command output, raw app-data backup payloads, private insert URIs, and raw signatures are not included.",
            "- Local absolute paths, including absolute staging paths, are sanitized as `<repo>`, `<workdir>`, `<home>`, or `<path>` placeholders.",
            "- Catalog scratch paths, staged bundle paths, installed bundle paths, data/cache/run paths, and rollback backup paths are sanitized.",
            "- `artifacts/private-insert-uris.json` is excluded even if an interop summary references it.",
            "",
        ]
    )
    return "\n".join(lines)


def markdown_cell(value: Any) -> str:
    text = str(value)
    return text.replace("\n", " ").replace("|", "\\|")


def markdown_code_list(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return "none"
    return ", ".join(f"`{markdown_cell(value)}`" for value in values)


def coverage_result(value: Any) -> str:
    return "pass" if value is True else "fail"


def coverage_notes(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return "No gaps."
    return markdown_code_list(values)


def render_ecosystem_matrix_report(matrix: dict[str, Any]) -> str:
    counts = matrix.get("counts", {}) if isinstance(matrix.get("counts"), dict) else {}
    coverage = matrix.get("coverage", {}) if isinstance(matrix.get("coverage"), dict) else {}
    rows = matrix.get("rows", []) if isinstance(matrix.get("rows"), list) else []
    lines = [
        "# Ecosystem Certification Matrix",
        "",
        f"- Promotion decision: `{matrix.get('promotionDecision', 'block')}`",
        f"- Matrix status: `{matrix.get('status', 'missing')}`",
        f"- Mode: `{matrix.get('mode', 'missing')}`",
        f"- Generated: `{matrix.get('generatedAt', '')}`",
        f"- Previous summary: `{'present' if matrix.get('previousSummaryPresent') else 'missing'}`",
        f"- Previous matrix: `{'present' if matrix.get('previousMatrixPresent') else 'missing'}`",
        f"- Release blockers: `{counts.get('releaseBlockers', 0)}`",
        "",
        "## Coverage",
        "",
        "| Check | Result | Notes |",
        "| --- | --- | --- |",
        "| Required evidence covered | `{}` | {} |".format(
            coverage_result(coverage.get("requiredEvidenceCovered")),
            coverage_notes(
                (coverage.get("missingRequiredEvidenceIds") or [])
                + (coverage.get("unmappedRequiredEvidenceIds") or [])
            ),
        ),
        "| Ecosystem gates covered | `{}` | {} |".format(
            coverage_result(coverage.get("ecosystemGatesCovered")),
            coverage_notes(coverage.get("unmappedGateIds")),
        ),
        "| First-party apps covered | `{}` | {} |".format(
            coverage_result(coverage.get("firstPartyAppsCovered")),
            coverage_notes(coverage.get("missingFirstPartyApps")),
        ),
        "| Docs covered | `{}` | {} |".format(
            coverage_result(coverage.get("docsCovered")),
            coverage_notes((coverage.get("rowsWithoutDocs") or []) + (coverage.get("missingDocPaths") or [])),
        ),
        "| Redaction | `{}` | {} |".format(
            coverage_result(coverage.get("redactionPassed")),
            "Private material excluded." if coverage.get("redactionPassed") else "Review matrix redaction flags.",
        ),
        "",
        "## Matrix",
        "",
        "| Category | Row | Status | Previous | Regression | Blocker | Evidence | Gates | Waivers | Recommendation |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        if not isinstance(row, dict):
            continue
        lines.append(
            "| {category} | {row_title} | `{status}` | `{previous}` | `{regression}` | {blocker} | {evidence} | {gates} | {waivers} | {recommendation} |".format(
                category=markdown_cell(row.get("category", "")),
                row_title=markdown_cell(row.get("title", row.get("id", ""))),
                status=markdown_cell(row.get("status", "missing")),
                previous=markdown_cell(row.get("previousStatus", "missing")),
                regression=markdown_cell(row.get("regressionStatus", "not-comparable")),
                blocker="yes" if row.get("releaseBlocker") else "no",
                evidence=markdown_code_list(row.get("evidenceIds")),
                gates=markdown_code_list(row.get("gateIds")),
                waivers=markdown_code_list(row.get("waiverIds")),
                recommendation=markdown_cell(row.get("recommendation", "")),
            )
        )
    non_passing = [
        row for row in rows if isinstance(row, dict) and row.get("status") != "pass"
    ]
    if non_passing:
        lines.extend(["", "## Non-Passing Rows", ""])
        for row in non_passing:
            issue_ids = row.get("issueIds", [])
            details = row.get("details", {}) if isinstance(row.get("details"), dict) else {}
            waiver_reasons = details.get("waiverReasons", {}) if isinstance(details.get("waiverReasons"), dict) else {}
            lines.extend(
                [
                    f"### `{row.get('id', '')}`",
                    "",
                    f"- Status: `{row.get('status', 'missing')}`",
                    f"- Release blocker: `{'yes' if row.get('releaseBlocker') else 'no'}`",
                    f"- Regression: `{row.get('regressionStatus', 'not-comparable')}`",
                    f"- Issues: {markdown_code_list(issue_ids)}",
                    f"- Waivers: {markdown_code_list(row.get('waiverIds'))}",
                ]
            )
            if waiver_reasons:
                for waiver_id in sorted(waiver_reasons):
                    lines.append(f"- Waiver `{markdown_cell(waiver_id)}`: {markdown_cell(waiver_reasons[waiver_id])}")
            lines.extend([f"- Recommendation: {markdown_cell(row.get('recommendation', ''))}", ""])
    lines.extend(
        [
            "## Redaction",
            "",
            "The matrix is derived from sanitized summary fields. It does not include raw request bodies, raw feed bodies, raw trust documents, raw signatures, tokens, private insert URIs, or absolute local filesystem paths.",
            "",
        ]
    )
    return "\n".join(lines)


def append_ecosystem_matrix_summary(lines: list[str], summary: dict[str, Any]) -> None:
    matrix = summary.get("ecosystemMatrix", {})
    if not isinstance(matrix, dict):
        return
    coverage = matrix.get("coverage", {}) if isinstance(matrix.get("coverage"), dict) else {}
    lines.extend(
        [
            "## Ecosystem Certification Matrix",
            "",
            f"- Matrix status: `{summary.get('ecosystemMatrixStatus', 'missing')}`",
            f"- Matrix report: `{summary.get('ecosystemMatrixReportPath', '')}`",
            f"- Rows: `{matrix.get('rowCount', 0)}`",
            f"- Release blockers: `{matrix.get('releaseBlockerCount', 0)}`",
            f"- Required evidence covered: `{'yes' if coverage.get('requiredEvidenceCovered') else 'no'}`",
            f"- Ecosystem gates covered: `{'yes' if coverage.get('ecosystemGatesCovered') else 'no'}`",
            "",
        ]
    )


def append_stable_readiness_summary(lines: list[str], summary: dict[str, Any]) -> None:
    stable = summary.get("stableReadiness", {})
    if not isinstance(stable, dict):
        return
    lines.extend(
        [
            "## Stable 1.0 Readiness",
            "",
            f"- Status: `{stable.get('status', 'missing')}`",
            f"- Decision: `{stable.get('decision', 'not-attached')}`",
            f"- Stable ready: `{str(stable.get('stableReady', False)).lower()}`",
            f"- Required: `{str(stable.get('required', False)).lower()}`",
            f"- Blockers: `{stable.get('blockerCount', 0)}`",
            f"- Warnings: `{stable.get('warningCount', 0)}`",
            f"- Allowed limitations: `{stable.get('allowedLimitationCount', 0)}`",
            f"- Disallowed limitations: `{stable.get('disallowedLimitationCount', 0)}`",
            f"- Redaction: `{stable.get('redactionStatus', 'missing')}`",
            f"- Summary: {stable.get('summary', '')}",
            "",
        ]
    )


def append_ecosystem_rc_gate(lines: list[str], summary: dict[str, Any]) -> None:
    compact = summary.get("ecosystemRcGate", {})
    gates = summary.get("ecosystemGates", [])
    gate = None
    if isinstance(gates, list):
        gate = next(
            (
                candidate
                for candidate in gates
                if isinstance(candidate, dict) and candidate.get("id") == ECOSYSTEM_RC_GATE_ID
            ),
            None,
        )
    details = (
        gate.get("details", {})
        if isinstance(gate, dict) and isinstance(gate.get("details"), dict)
        else {}
    )
    waiver_ids = detail_waiver_ids(details)
    lines.extend(
        [
            "## Ecosystem RC Certification Gate",
            "",
            f"- Gate: `{ECOSYSTEM_RC_GATE_ID}`",
            f"- Status: `{compact.get('status', 'missing')}`",
            f"- Promotion decision: `{summary.get('ecosystemRcDecision', 'FAIL')}`",
            f"- Release blocker: `{'yes' if compact.get('releaseBlocker') else 'no'}`",
            f"- Blocking gates: {markdown_code_list(details.get('blockingGateIds'))}",
            f"- Failed evidence: `{compact.get('failedEvidenceCount', 0)}`",
            f"- Missing evidence: `{compact.get('missingEvidenceCount', 0)}`",
            f"- Warning evidence: `{compact.get('warningEvidenceCount', 0)}`",
            f"- Live-network required: `{'yes' if details.get('liveNetworkRequired') else 'no'}`",
            f"- Network-scale soak satisfied: `{'yes' if details.get('networkScaleSoakSatisfied') else 'no'}`",
            f"- Redaction passed: `{'yes' if details.get('redactionPassed') else 'no'}`",
            f"- Waivers: `{compact.get('waiverCount', 0)}` {markdown_code_list(waiver_ids)}",
            "",
        ]
    )


def append_history_comparison(lines: list[str], summary: dict[str, Any]) -> None:
    history = summary.get("historyComparison", {})
    if not isinstance(history, dict):
        return
    previous = history.get("previous", {}) if isinstance(history.get("previous"), dict) else {}
    current = history.get("current", {}) if isinstance(history.get("current"), dict) else {}
    lines.extend(
        [
            "## Historical Comparison",
            "",
            f"- Status: `{history.get('status', 'missing')}`",
            f"- Summary: {history.get('summary', 'No historical comparison was produced.')}",
            f"- Previous generated: `{previous.get('generatedAt', '')}`",
            f"- Previous git SHA: `{previous.get('gitSha', '')}`",
            f"- Previous release version: `{previous.get('releaseVersion', '')}`",
            f"- Current generated: `{current.get('generatedAt', '')}`",
            f"- Current git SHA: `{current.get('gitSha', '')}`",
            f"- Current release version: `{current.get('releaseVersion', '')}`",
            "",
        ]
    )


def append_ecosystem_gates(lines: list[str], summary: dict[str, Any]) -> None:
    gates = summary.get("ecosystemGates", [])
    if not isinstance(gates, list):
        return
    lines.extend(["## Ecosystem Gates", "", "| Gate | Status | Blocker | Summary |", "| --- | --- | --- | --- |"])
    ordered = sorted(
        [gate for gate in gates if isinstance(gate, dict)],
        key=lambda gate: (gate.get("status") != "fail", gate.get("status") != "warn", str(gate.get("id", ""))),
    )
    for gate in ordered:
        lines.append(
            "| `{id}` | `{status}` | {blocker} | {summary_text} |".format(
                id=gate.get("id", ""),
                status=gate.get("status", "missing"),
                blocker="yes" if gate.get("releaseBlocker") else "no",
                summary_text=str(gate.get("summary", "")).replace("|", "\\|"),
            )
        )
    lines.append("")


def append_waivers(lines: list[str], summary: dict[str, Any]) -> None:
    waivers = summary.get("waiverRecords")
    if not isinstance(waivers, list):
        legacy_waivers = summary.get("waivers", [])
        waivers = legacy_waivers if isinstance(legacy_waivers, list) else []
    if not isinstance(waivers, list):
        return
    lines.extend(["## Waivers", ""])
    if not waivers:
        lines.extend(["No waivers were recorded.", ""])
        return
    lines.extend(["| Waiver | Evidence/Gate | Active | Expires | Reason |", "| --- | --- | --- | --- | --- |"])
    for waiver in waivers:
        if not isinstance(waiver, dict):
            continue
        lines.append(
            "| `{id}` | `{evidence}` | `{active}` | `{expires}` | {reason} |".format(
                id=waiver.get("id", ""),
                evidence=waiver.get("evidenceId", ""),
                active=waiver.get("active", False),
                expires=waiver.get("expiresAt", ""),
                reason=str(waiver.get("reason", "")).replace("|", "\\|"),
            )
        )
    lines.append("")


def append_regressions(lines: list[str], summary: dict[str, Any]) -> None:
    history = summary.get("historyComparison", {})
    if not isinstance(history, dict):
        return
    diffs = history.get("evidenceDiffs", [])
    if not isinstance(diffs, list):
        return
    important = [
        diff
        for diff in diffs
        if isinstance(diff, dict) and diff.get("classification") in {"regression", "removed"}
    ]
    lines.extend(["## Regressions Since Previous Certified Release", ""])
    if not important:
        lines.extend(["No evidence regressions were detected.", ""])
        return
    lines.extend(
        [
            "| Evidence | Previous | Current | Classification | Blocker | Reason |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for diff in important:
        lines.append(
            "| `{id}` | `{previous}` | `{current}` | `{classification}` | {blocker} | {reason} |".format(
                id=diff.get("id", ""),
                previous=diff.get("previousStatus", ""),
                current=diff.get("currentStatus", ""),
                classification=diff.get("classification", ""),
                blocker="yes" if diff.get("releaseBlocker") else "no",
                reason=str(diff.get("reason", "")).replace("|", "\\|"),
            )
        )
    lines.append("")


def append_detail(lines: list[str], summary: dict[str, Any], evidence_id: str) -> None:
    item = next((entry for entry in summary["evidence"] if entry["id"] == evidence_id), None)
    if item is None:
        return
    lines.append(f"### `{evidence_id}`")
    lines.append("")
    lines.append(f"- Status: `{item['status']}`")
    lines.append(f"- Source: `{item['source']}`")
    lines.append(f"- Summary: {item['summary']}")
    details = item.get("details", {})
    if details:
        compact = json.dumps(details, indent=2, sort_keys=True)
        lines.extend(["", "```json", compact, "```"])
    lines.append("")


def gather_evidence(settings: Settings, waiver_context: WaiverContext) -> list[EvidenceItem]:
    evidence = [
        interop_evidence(
            "interop.smoke",
            settings.interop_smoke_summary,
            True,
            "smoke",
            settings.workspace_root,
            settings.out_dir,
        ),
        interop_evidence(
            "interop.extended",
            settings.interop_extended_summary,
            False,
            "extended",
            settings.workspace_root,
            settings.out_dir,
        ),
        perf_evidence(settings.perf_smoke_summary, True, settings.workspace_root, settings.out_dir),
    ]
    evidence.extend(
        app_platform_evidence(
            settings.app_platform_summary,
            settings.workspace_root,
            settings.out_dir,
            settings.mode,
        )
    )
    security_item = security_drills_evidence(
        settings.security_drills_summary,
        settings.workspace_root,
        settings.out_dir,
        settings.mode,
    )
    app_platform_security_items = [
        item for item in evidence if item.id == security_item.id
    ]
    evidence = [item for item in evidence if item.id != security_item.id]
    evidence.append(combine_security_response_evidence(app_platform_security_items, security_item))
    evidence.extend(
        live_network_beta_evidence(
            settings.live_network_summary,
            settings.workspace_root,
            settings.out_dir,
            settings.mode,
            settings.live_network_beta_enabled,
            settings.live_network_beta_required,
        )
    )
    evidence.append(
        network_scale_soak_evidence(
            settings.network_scale_soak_summary,
            settings.workspace_root,
            settings.out_dir,
            settings.mode,
        )
    )
    evidence.extend(
        multi_node_beta_soak_evidence(
            settings.multi_node_soak_summary,
            settings.workspace_root,
            settings.out_dir,
            settings.mode,
            settings.multi_node_soak_required,
        )
    )
    app_platform_docs_items = app_platform_docs_evidence(settings.workspace_root, settings.out_dir)
    app_platform_docs_item_ids = {item.id for item in app_platform_docs_items}
    evidence = [item for item in evidence if item.id not in app_platform_docs_item_ids]
    evidence.extend(app_platform_docs_items)
    evidence.extend(production_beta_go_no_go_evidence(settings.workspace_root, settings.out_dir))
    expected_stable_release_id = stable_readiness_expected_release_id(settings, evidence)
    evidence.extend(
        stable_readiness_evidence(
            settings.stable_readiness_summary,
            settings.stable_readiness_required,
            settings.workspace_root,
            settings.out_dir,
            expected_stable_release_id,
        )
    )
    return [
        sanitize_evidence_item(
            with_waiver_record(
                item,
                active_waiver_for_evidence_item(waiver_context, item, settings.mode),
            ),
            settings.workspace_root,
            settings.out_dir,
        )
        for item in evidence
    ]


def render_history_comparison(history: dict[str, Any]) -> str:
    lines = [
        "# Release Certification History Comparison",
        "",
        f"- Status: `{history.get('status', 'missing')}`",
        f"- Summary: {history.get('summary', '')}",
        "",
        "## Evidence Diffs",
        "",
        "| Evidence | Previous | Current | Classification | Blocker | Reason |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    diffs = history.get("evidenceDiffs", [])
    if isinstance(diffs, list):
        for diff in diffs:
            if not isinstance(diff, dict):
                continue
            lines.append(
                "| `{id}` | `{previous}` | `{current}` | `{classification}` | {blocker} | {reason} |".format(
                    id=diff.get("id", ""),
                    previous=diff.get("previousStatus", ""),
                    current=diff.get("currentStatus", ""),
                    classification=diff.get("classification", ""),
                    blocker="yes" if diff.get("releaseBlocker") else "no",
                    reason=str(diff.get("reason", "")).replace("|", "\\|"),
                )
            )
    gates = history.get("ecosystemGates", [])
    if isinstance(gates, list):
        lines.extend(["", "## Ecosystem Gates", "", "| Gate | Status | Blocker | Summary |", "| --- | --- | --- | --- |"])
        for gate in gates:
            if not isinstance(gate, dict):
                continue
            lines.append(
                "| `{id}` | `{status}` | {blocker} | {summary_text} |".format(
                    id=gate.get("id", ""),
                    status=gate.get("status", "missing"),
                    blocker="yes" if gate.get("releaseBlocker") else "no",
                    summary_text=str(gate.get("summary", "")).replace("|", "\\|"),
                )
            )
    lines.append("")
    return "\n".join(lines)


def safe_history_label(summary: dict[str, Any]) -> str:
    metadata = summary.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    for value in (
        metadata.get("releaseVersion"),
        summary.get("historyLabel"),
        metadata.get("gitCommit"),
        metadata.get("githubSha"),
    ):
        if isinstance(value, str) and value.strip():
            label = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-")
            if label:
                return label[:80]
    return "current"


def write_history_artifacts(settings: Settings, summary: dict[str, Any]) -> None:
    if not settings.write_history:
        return
    history_dir = resolve_path(settings.workspace_root, settings.history_dir)
    comparison = summary.get("historyComparison", {})
    label = settings.history_label.strip() or safe_history_label(summary)
    safe_label = re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip("-") if label else "current"
    if not safe_label:
        safe_label = "current"
    if summary.get("status") == "fail" or summary.get("releaseCandidatePassed") is False:
        failed_dir = history_dir / "failed" / safe_label
        write_json(failed_dir / SUMMARY_FILE_NAME, summary)
        if isinstance(comparison, dict):
            write_json(failed_dir / HISTORY_COMPARISON_FILE_NAME, comparison)
        return
    write_json(history_dir / "latest-summary.json", summary)
    if isinstance(comparison, dict):
        write_json(history_dir / "latest-history-comparison.json", comparison)
    release_dir = history_dir / "releases" / safe_label
    write_json(release_dir / SUMMARY_FILE_NAME, summary)
    if isinstance(comparison, dict):
        write_json(release_dir / HISTORY_COMPARISON_FILE_NAME, comparison)


def run(settings: Settings) -> tuple[dict[str, Any], int]:
    settings.out_dir.mkdir(parents=True, exist_ok=True)
    generated_at = utc_now()
    waiver_context = load_waiver_context(settings, dt.datetime.now(dt.timezone.utc))
    previous_summary, previous_source, previous_error = load_previous_summary(settings)
    copied = collect_source_artifacts(settings, settings.out_dir)
    base_evidence = gather_evidence(settings, waiver_context)
    metadata = collect_metadata(settings)

    def evaluate_history_and_gates(current_evidence: list[EvidenceItem]) -> tuple[dict[str, Any], list[GateResult]]:
        comparison = compare_history(
            settings,
            previous_summary,
            previous_source,
            previous_error,
            current_evidence,
            generated_at,
            metadata,
            waiver_context,
        )
        gates = evaluate_ecosystem_gates(
            settings, current_evidence, previous_summary, comparison, metadata, waiver_context
        )
        comparison["ecosystemGates"] = [gate.to_json() for gate in gates]
        comparison = dict(sanitize_value(comparison, settings.workspace_root, settings.out_dir))
        sanitized_gates = [
            GateResult(
                id=str(gate["id"]),
                status=normalize_evidence_status(str(gate["status"])),
                release_blocker=bool(gate.get("releaseBlocker")),
                summary=str(gate.get("summary", "")),
                details=gate.get("details", {}) if isinstance(gate.get("details"), dict) else {},
            )
            for gate in comparison.get("ecosystemGates", [])
            if isinstance(gate, dict)
        ]
        return comparison, sanitized_gates

    matrix_evidence = placeholder_ecosystem_matrix_evidence(settings.workspace_root, settings.out_dir)
    rc_gate_evidence = placeholder_ecosystem_rc_gate_evidence(settings.workspace_root, settings.out_dir)
    evidence = [*base_evidence, matrix_evidence, rc_gate_evidence]
    history_comparison: dict[str, Any] = {}
    ecosystem_gates: list[GateResult] = []
    ecosystem_matrix: dict[str, Any] = {}
    for _ in range(5):
        history_comparison, ecosystem_gates = evaluate_history_and_gates(evidence)
        final_gate = next((gate for gate in ecosystem_gates if gate.id == ECOSYSTEM_RC_GATE_ID), None)
        next_rc_gate_evidence = ecosystem_rc_gate_evidence(
            final_gate, settings.workspace_root, settings.out_dir
        )
        evidence_for_matrix = [*base_evidence, matrix_evidence, next_rc_gate_evidence]
        ecosystem_matrix = build_ecosystem_matrix(
            settings,
            evidence_for_matrix,
            previous_summary,
            history_comparison,
            ecosystem_gates,
            waiver_context,
            generated_at,
        )
        next_matrix_evidence = ecosystem_matrix_evidence(
            ecosystem_matrix, settings.workspace_root, settings.out_dir
        )
        if next_matrix_evidence == matrix_evidence:
            if next_rc_gate_evidence == rc_gate_evidence:
                evidence = evidence_for_matrix
                break
        matrix_evidence = next_matrix_evidence
        rc_gate_evidence = next_rc_gate_evidence
        evidence = [*base_evidence, matrix_evidence, rc_gate_evidence]
    else:
        history_comparison, ecosystem_gates = evaluate_history_and_gates(evidence)
        final_gate = next((gate for gate in ecosystem_gates if gate.id == ECOSYSTEM_RC_GATE_ID), None)
        rc_gate_evidence = ecosystem_rc_gate_evidence(
            final_gate, settings.workspace_root, settings.out_dir
        )
        evidence = [*base_evidence, matrix_evidence, rc_gate_evidence]
        ecosystem_matrix = build_ecosystem_matrix(
            settings,
            evidence,
            previous_summary,
            history_comparison,
            ecosystem_gates,
            waiver_context,
            generated_at,
        )
    summary = build_summary(
        settings,
        evidence,
        copied,
        generated_at,
        metadata,
        history_comparison,
        ecosystem_gates,
        waiver_context,
        ecosystem_matrix,
    )
    write_json(settings.out_dir / SUMMARY_FILE_NAME, summary)
    write_json(settings.out_dir / HISTORY_COMPARISON_FILE_NAME, history_comparison)
    write_text(settings.out_dir / HISTORY_COMPARISON_REPORT_FILE_NAME, render_history_comparison(history_comparison))
    write_json(settings.out_dir / ECOSYSTEM_MATRIX_FILE_NAME, ecosystem_matrix)
    write_text(
        settings.out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME,
        render_ecosystem_matrix_report(ecosystem_matrix),
    )
    report = render_report(summary)
    write_text(settings.out_dir / REPORT_FILE_NAME, report)
    write_history_artifacts(settings, summary)
    exit_code = 1 if summary["status"] == "fail" else 0
    return summary, exit_code


def parse_key_value(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise argparse.ArgumentTypeError(f"Expected key=value, got {value}")
        key, text = value.split("=", 1)
        if not key:
            raise argparse.ArgumentTypeError(f"Expected non-empty key in {value}")
        result[key] = text
    return result


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def settings_from_args(args: argparse.Namespace) -> Settings:
    workspace_root = args.workspace_root.resolve()
    out_dir = (workspace_root / args.out_dir).resolve() if not args.out_dir.is_absolute() else args.out_dir.resolve()
    previous_summary = resolve_path(workspace_root, args.previous_summary) if args.previous_summary else None
    history_dir = resolve_path(workspace_root, args.history_dir)
    waiver_files = tuple(resolve_path(workspace_root, path) for path in args.waiver_file)
    mode = args.mode or os.environ.get("CRYPTAD_CERT_MODE", "pr")
    if mode not in MODES:
        raise SystemExit(f"--mode must be one of {', '.join(MODES)}")
    live_network_beta_enabled = args.live_network_beta or env_flag("CRYPTAD_CERT_LIVE_NETWORK_BETA")
    live_network_beta_required = args.require_live_network_beta or env_flag("CRYPTAD_CERT_REQUIRE_LIVE_NETWORK_BETA")
    if live_network_beta_required:
        live_network_beta_enabled = True
    security_drills_summary_arg = (
        args.security_drills_summary
        or args.security_response_summary
        or os.environ.get("CRYPTAD_CERT_SECURITY_DRILLS_SUMMARY")
    )
    stable_readiness_summary_arg = (
        args.stable_readiness_summary
        or args.stable_1_0_readiness_summary
        or os.environ.get("CRYPTAD_CERT_STABLE_READINESS_SUMMARY")
    )
    return Settings(
        workspace_root=workspace_root,
        out_dir=out_dir,
        mode=mode,
        interop_smoke_summary=resolve_path(workspace_root, args.interop_smoke_summary),
        interop_extended_summary=resolve_path(workspace_root, args.interop_extended_summary),
        perf_smoke_summary=resolve_path(workspace_root, args.perf_smoke_summary),
        app_platform_summary=resolve_path(workspace_root, args.app_platform_summary),
        live_network_summary=resolve_path(workspace_root, args.live_network_summary),
        network_scale_soak_summary=resolve_path(workspace_root, args.network_scale_soak_summary),
        live_network_beta_enabled=live_network_beta_enabled,
        live_network_beta_required=live_network_beta_required,
        waivers=parse_key_value(args.waive),
        metadata=parse_key_value(args.metadata),
        skip_git_metadata=args.skip_git_metadata,
        previous_summary=previous_summary,
        require_history=args.require_history,
        history_dir=history_dir,
        write_history=args.write_history,
        history_label=args.history_label,
        waiver_files=waiver_files,
        multi_node_soak_summary=resolve_path(workspace_root, args.multi_node_soak_summary),
        multi_node_soak_required=args.require_multi_node_soak,
        security_drills_summary=(
            resolve_path(workspace_root, Path(security_drills_summary_arg))
            if security_drills_summary_arg
            else None
        ),
        stable_readiness_summary=(
            resolve_path(workspace_root, Path(stable_readiness_summary_arg))
            if stable_readiness_summary_arg
            else None
        ),
        stable_readiness_required=(
            args.require_stable_readiness
            or env_flag("CRYPTAD_CERT_REQUIRE_STABLE_READINESS")
        ),
    )


def resolve_path(workspace_root: Path, path: Path) -> Path:
    return (workspace_root / path).resolve() if not path.is_absolute() else path.resolve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run Python-only self-tests.")
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--mode", choices=MODES, default=None)
    parser.add_argument("--interop-smoke-summary", type=Path, default=Path("build/interop-smoke/summary.json"))
    parser.add_argument("--interop-extended-summary", type=Path, default=Path("build/interop-extended/summary.json"))
    parser.add_argument("--perf-smoke-summary", type=Path, default=Path("build/perf-smoke/summary.json"))
    parser.add_argument(
        "--app-platform-summary",
        type=Path,
        default=DEFAULT_OUT_DIR / "app-platform-smoke" / "summary.json",
    )
    parser.add_argument(
        "--live-network-summary",
        type=Path,
        default=DEFAULT_OUT_DIR / "live-network-beta-smoke" / "summary.json",
    )
    parser.add_argument(
        "--network-scale-soak-summary",
        type=Path,
        default=DEFAULT_OUT_DIR / "network-scale-soak" / "summary.json",
    )
    parser.add_argument(
        "--multi-node-soak-summary",
        type=Path,
        default=DEFAULT_OUT_DIR / "multi-node-beta-soak" / "summary.json",
    )
    parser.add_argument(
        "--security-drills-summary",
        type=Path,
        default=None,
        help="Redacted security response drill summary produced by security_response_runbook.py.",
    )
    parser.add_argument(
        "--security-response-summary",
        type=Path,
        default=None,
        help="Deprecated alias for --security-drills-summary.",
    )
    parser.add_argument(
        "--stable-readiness-summary",
        type=Path,
        default=None,
        help="Stable 1.0 readiness summary produced by stable_1_0_readiness.py.",
    )
    parser.add_argument(
        "--stable-1-0-readiness-summary",
        dest="stable_1_0_readiness_summary",
        type=Path,
        default=None,
        help="Alias for --stable-readiness-summary.",
    )
    parser.add_argument("--live-network-beta", action="store_true", help="Expect optional live-network beta evidence.")
    parser.add_argument(
        "--require-live-network-beta",
        action="store_true",
        help="Treat missing or failing live-network beta evidence as release-blocking.",
    )
    parser.add_argument(
        "--require-multi-node-soak",
        action="store_true",
        help="Treat missing or failing multi-node beta soak evidence as release-blocking.",
    )
    parser.add_argument(
        "--require-stable-readiness",
        action="store_true",
        help="Treat missing or failing Stable 1.0 readiness evidence as release-blocking.",
    )
    parser.add_argument("--waive", action="append", default=[], metavar="ID=REASON")
    parser.add_argument("--waiver-file", action="append", default=[], type=Path)
    parser.add_argument("--previous-summary", type=Path, default=None)
    parser.add_argument("--require-history", action="store_true")
    parser.add_argument("--history-dir", type=Path, default=DEFAULT_HISTORY_DIR)
    parser.add_argument("--write-history", action="store_true")
    parser.add_argument("--history-label", default="")
    parser.add_argument("--metadata", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--skip-git-metadata", action="store_true")
    return parser


def run_self_test(repo_root: Path) -> None:
    fixture_dir = repo_root / "tools/release-certification/fixtures"
    with tempfile.TemporaryDirectory(prefix="cryptad-cert-self-test-") as temp_name:
        workspace = Path(temp_name) / "repo"
        out_dir = workspace / "build/release-certification"
        (workspace / "build/interop-smoke").mkdir(parents=True)
        (workspace / "build/interop-extended").mkdir(parents=True)
        (workspace / "build/perf-smoke").mkdir(parents=True)
        (out_dir / "app-platform-smoke").mkdir(parents=True)
        (out_dir / "network-scale-soak").mkdir(parents=True)
        (out_dir / "multi-node-beta-soak").mkdir(parents=True)
        for spec in ecosystem_matrix_row_specs():
            for doc_path in spec.docs:
                source_doc = repo_root / doc_path
                target_doc = workspace / doc_path
                target_doc.parent.mkdir(parents=True, exist_ok=True)
                assert source_doc.is_file(), f"matrix doc path missing: {doc_path}"
                shutil.copy(source_doc, target_doc)
        docs_check_paths = {
            *app_platform_docs_check.REQUIRED_DOCS,
            *app_platform_docs_check.REQUIRED_PORTAL_LINKS,
            *app_platform_docs_check.ISSUE_TEMPLATES,
            app_platform_docs_check.PUBLIC_BETA_KNOWN_ISSUES_METADATA,
            app_platform_docs_check.PUBLIC_BETA_SAFE_FEEDBACK_FIXTURE,
            *app_platform_docs_check.PUBLIC_BETA_NEGATIVE_FEEDBACK_FIXTURES,
            "README.md",
            "samples/third-party/hello-stable-app/README.md",
            "tools/interop/README.md",
            "tools/perf/README.md",
        }
        for source_doc in repo_root.glob("docs/**/*.md"):
            target_doc = workspace / source_doc.relative_to(repo_root)
            target_doc.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(source_doc, target_doc)
        for doc_path in sorted(docs_check_paths):
            source_doc = repo_root / doc_path
            target_doc = workspace / doc_path
            target_doc.parent.mkdir(parents=True, exist_ok=True)
            assert source_doc.is_file(), f"docs-check path missing: {doc_path}"
            shutil.copy(source_doc, target_doc)
        shutil.copy(fixture_dir / "self-test-interop-smoke.json", workspace / "build/interop-smoke/summary.json")
        shutil.copy(
            fixture_dir / "self-test-interop-extended.json",
            workspace / "build/interop-extended/summary.json",
        )
        shutil.copy(fixture_dir / "self-test-perf-smoke.json", workspace / "build/perf-smoke/summary.json")
        shutil.copy(
            fixture_dir / "self-test-app-platform-smoke.json",
            out_dir / "app-platform-smoke/summary.json",
        )
        shutil.copy(
            fixture_dir / "self-test-network-scale-soak.json",
            out_dir / "network-scale-soak/summary.json",
        )
        multi_node_config = multi_node_beta_soak.validate_config(
            multi_node_beta_soak.load_config(fixture_dir / "self-test-multi-node-beta-soak.json")
        )
        multi_node_summary = multi_node_beta_soak.build_summary(
            multi_node_config,
            out_dir=out_dir / "multi-node-beta-soak",
            base_dir=fixture_dir,
        )
        write_json(out_dir / "multi-node-beta-soak/summary.json", multi_node_summary)
        write_text(
            out_dir / "multi-node-beta-soak/multi-node-beta-soak-summary.md",
            multi_node_beta_soak.render_report(multi_node_summary),
        )
        security_drills_summary = out_dir / "security-drills/security-drills-summary.json"
        security_response_runbook.drill_run_all(
            repo_root / security_response_runbook.DEFAULT_MODEL,
            out_dir / "security-drills",
            security_drills_summary,
            release_id="cryptad-production-beta-self-test",
            generated_at=security_response_runbook.utc_now(),
        )
        settings = Settings(
            workspace_root=workspace.resolve(),
            out_dir=out_dir.resolve(),
            mode="release-candidate",
            interop_smoke_summary=workspace / "build/interop-smoke/summary.json",
            interop_extended_summary=workspace / "build/interop-extended/summary.json",
            perf_smoke_summary=workspace / "build/perf-smoke/summary.json",
            app_platform_summary=out_dir / "app-platform-smoke/summary.json",
            live_network_summary=out_dir / "live-network-beta-smoke/summary.json",
            network_scale_soak_summary=out_dir / "network-scale-soak/summary.json",
            live_network_beta_enabled=False,
            live_network_beta_required=False,
            multi_node_soak_summary=out_dir / "multi-node-beta-soak/summary.json",
            multi_node_soak_required=False,
            security_drills_summary=security_drills_summary,
            waivers={},
            metadata={
                "selfTest": "true",
                "candidateReleaseId": "cryptad-production-beta-self-test",
            },
            skip_git_metadata=True,
            history_dir=workspace / "build/no-auto-history",
        )
        security_item = security_drills_evidence(
            security_drills_summary,
            workspace.resolve(),
            out_dir.resolve(),
            "release-candidate",
        )
        assert security_item.status == "pass", security_item
        missing_artifacts_dir = workspace / "security-drills-missing-artifacts"
        missing_artifacts_summary = missing_artifacts_dir / "security-drills-summary.json"
        security_drills_summary_value = read_json(security_drills_summary)
        assert isinstance(security_drills_summary_value, dict), security_drills_summary
        write_json(missing_artifacts_summary, security_drills_summary_value)
        missing_artifacts_item = security_drills_evidence(
            missing_artifacts_summary,
            workspace.resolve(),
            out_dir.resolve(),
            "release-candidate",
        )
        assert missing_artifacts_item.status == "fail", missing_artifacts_item
        assert any(
            "security drill artifact for reviewer-key-compromise is missing" == error
            for error in missing_artifacts_item.details.get("validationErrors", [])
        ), missing_artifacts_item.details
        tampered_artifacts_dir = workspace / "security-drills-tampered-artifacts"
        shutil.copytree(security_drills_summary.parent, tampered_artifacts_dir)
        tampered_summary_path = tampered_artifacts_dir / "security-drills-summary.json"
        tampered_artifact_path = (
            tampered_artifacts_dir
            / security_response_runbook.DRILL_OUTPUT_FILENAMES["reviewer-key-compromise"]
        )
        tampered_artifact = read_json(tampered_artifact_path)
        assert isinstance(tampered_artifact, dict), tampered_artifact_path
        tampered_artifact["steps"][0]["safeSummary"] = "Tampered but redaction-safe drill text."
        write_json(tampered_artifact_path, tampered_artifact)
        tampered_summary = read_json(tampered_summary_path)
        assert isinstance(tampered_summary, dict), tampered_summary_path
        for artifact_entry in tampered_summary.get("artifacts", []):
            if (
                isinstance(artifact_entry, dict)
                and artifact_entry.get("scenario") == "reviewer-key-compromise"
            ):
                artifact_entry["digest"] = security_response_runbook.sha256_path(
                    tampered_artifact_path
                )
                break
        write_json(tampered_summary_path, tampered_summary)
        tampered_artifacts_item = security_drills_evidence(
            tampered_summary_path,
            workspace.resolve(),
            out_dir.resolve(),
            "release-candidate",
        )
        assert tampered_artifacts_item.status == "fail", tampered_artifacts_item
        assert any(
            "security drill artifact for reviewer-key-compromise failed offline verification" == error
            for error in tampered_artifacts_item.details.get("validationErrors", [])
        ), tampered_artifacts_item.details
        stale_artifacts_dir = workspace / "security-drills-stale-artifacts"
        stale_artifacts_summary = stale_artifacts_dir / "security-drills-summary.json"
        fresh_summary_generated_at = security_response_runbook.utc_now()
        fresh_summary_time = security_response_runbook.parse_timestamp(fresh_summary_generated_at)
        assert fresh_summary_time is not None, fresh_summary_generated_at
        stale_artifact_generated_at = (
            fresh_summary_time
            - dt.timedelta(days=security_response_runbook.DEFAULT_MAX_AGE_DAYS + 2)
        ).isoformat().replace("+00:00", "Z")
        security_response_runbook.drill_run_all(
            repo_root / security_response_runbook.DEFAULT_MODEL,
            stale_artifacts_dir,
            stale_artifacts_summary,
            release_id="cryptad-production-beta-self-test",
            generated_at=stale_artifact_generated_at,
        )
        stale_summary = read_json(stale_artifacts_summary)
        assert isinstance(stale_summary, dict), stale_artifacts_summary
        stale_summary["generatedAt"] = fresh_summary_generated_at
        write_json(stale_artifacts_summary, stale_summary)
        stale_artifacts_item = security_drills_evidence(
            stale_artifacts_summary,
            workspace.resolve(),
            out_dir.resolve(),
            "release-candidate",
        )
        assert stale_artifacts_item.status == "fail", stale_artifacts_item
        assert any(
            str(error).startswith("security drill artifact for reviewer-key-compromise is stale:")
            for error in stale_artifacts_item.details.get("validationErrors", [])
        ), stale_artifacts_item.details
        redaction_unsafe_security_drills = read_json(security_drills_summary)
        assert isinstance(redaction_unsafe_security_drills, dict), security_drills_summary
        redaction_unsafe_security_drills["redaction"] = {
            "status": "fail",
            "rawSensitiveMaterialExcluded": True,
            "findings": ["safe redaction finding: support bundle material excluded"],
        }
        redaction_unsafe_security_drills_path = (
            workspace / "redaction-unsafe-security-drills-summary.json"
        )
        write_json(redaction_unsafe_security_drills_path, redaction_unsafe_security_drills)
        redaction_unsafe_security_item = security_drills_evidence(
            redaction_unsafe_security_drills_path,
            workspace.resolve(),
            out_dir.resolve(),
            "release-candidate",
        )
        assert redaction_unsafe_security_item.status == "fail", redaction_unsafe_security_item
        assert (
            "safe redaction finding: support bundle material excluded"
            in redaction_unsafe_security_item.details.get("redactionFindings", [])
        ), redaction_unsafe_security_item.details
        production_beta_drills_summary = (
            out_dir / "security-drills-production-beta/security-drills-summary.json"
        )
        security_response_runbook.drill_run_all(
            repo_root / security_response_runbook.DEFAULT_MODEL,
            out_dir / "security-drills-production-beta",
            production_beta_drills_summary,
            release_id="cryptad-production-beta-self-test",
            generated_at=security_response_runbook.utc_now(),
            mode="production-beta",
        )
        production_beta_security_item = security_drills_evidence(
            production_beta_drills_summary,
            workspace.resolve(),
            out_dir.resolve(),
            "release-candidate",
        )
        assert production_beta_security_item.status == "pass", production_beta_security_item
        assert production_beta_security_item.details["mode"] == "production-beta", (
            production_beta_security_item.details
        )
        write_json(
            settings.live_network_summary,
            {
                "schemaVersion": 1,
                "kind": "live-network-beta-smoke",
                "mode": "release-candidate",
                "enabled": True,
                "required": True,
                "status": "fail",
                "node": {"baseUrlShape": "http://127.0.0.1:<port>", "localhostOnly": True},
                "evidence": [
                    {
                        "id": "live-network-beta.preflight",
                        "status": "fail",
                        "requiredForReleaseCandidate": True,
                        "summary": "stale live summary should be ignored when live beta is disabled.",
                        "source": "live-network-beta-self-test",
                        "details": {"enabled": True, "required": True},
                    }
                ],
                "redaction": {"status": "fail"},
            },
        )
        write_text(
            settings.live_network_summary.parent / "live-network-beta-smoke-report.md",
            "# stale live report\n\nThis stale report should not be copied when live-network beta is disabled.\n",
        )
        failing_app_platform_summary = read_json(settings.app_platform_summary)
        assert failing_app_platform_summary is not None, settings.app_platform_summary
        for entry in failing_app_platform_summary["evidence"]:
            if entry.get("id") == "production-security.response-runbook":
                entry["status"] = "fail"
                entry["summary"] = "Security response runbook integration failed."
                entry["details"] = {"checks": {"runbookDocExists": False}}
                break
        else:
            raise AssertionError("production-security.response-runbook fixture evidence is missing")
        failing_app_platform_summary_path = (
            out_dir / "app-platform-smoke/failing-security-response-summary.json"
        )
        write_json(failing_app_platform_summary_path, failing_app_platform_summary)
        failing_settings = dataclasses.replace(
            settings,
            app_platform_summary=failing_app_platform_summary_path,
        )
        failing_evidence_by_id = {
            item.id: item for item in gather_evidence(failing_settings, WaiverContext())
        }
        failing_security_evidence = failing_evidence_by_id[
            "production-security.response-runbook"
        ]
        assert failing_security_evidence.status == "fail", failing_security_evidence
        assert failing_security_evidence.details["componentStatuses"] == {
            "appPlatformRunbook": "fail",
            "securityDrills": "pass",
        }, failing_security_evidence.details
        summary, exit_code = run(settings)
        assert exit_code == 0, summary
        assert summary["status"] == "warn", summary
        assert summary["promotionDecision"] == "PASS WITH WARNINGS", summary
        assert summary["releaseCandidatePassed"] is True, summary
        assert summary["ecosystemRcDecision"] == "PASS_WITH_WARNINGS", summary
        assert summary["ecosystemRcPassed"] is True, summary
        assert summary["ecosystemRcGate"]["id"] == ECOSYSTEM_RC_GATE_ID, summary
        assert summary["ecosystemRcGate"]["status"] == "warn", summary
        assert not any("live-network-beta" in artifact for artifact in summary["copiedArtifacts"]), summary[
            "copiedArtifacts"
        ]
        assert not (out_dir / "artifacts/live-network-beta-smoke-summary.json").exists(), summary["copiedArtifacts"]
        assert not (out_dir / "artifacts/live-network-beta-smoke-report.md").exists(), summary["copiedArtifacts"]
        assert summary["waivers"] == {}, summary
        assert summary["waiverRecords"] == [], summary
        assert summary["historyComparison"]["status"] == "warn", summary
        assert (out_dir / HISTORY_COMPARISON_FILE_NAME).is_file(), summary
        assert (out_dir / HISTORY_COMPARISON_REPORT_FILE_NAME).is_file(), summary
        assert (out_dir / ECOSYSTEM_MATRIX_FILE_NAME).is_file(), summary
        assert (out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME).is_file(), summary
        matrix = read_json(out_dir / ECOSYSTEM_MATRIX_FILE_NAME)
        assert matrix is not None, summary
        assert matrix["schemaVersion"] == ECOSYSTEM_MATRIX_SCHEMA_VERSION, matrix
        assert matrix["kind"] == "ecosystem-certification-matrix", matrix
        assert matrix["coverage"]["requiredEvidenceCovered"] is True, matrix
        assert matrix["coverage"]["ecosystemGatesCovered"] is True, matrix
        assert matrix["coverage"]["firstPartyAppsCovered"] is True, matrix
        assert matrix["coverage"]["docsCovered"] is True, matrix
        assert matrix["coverage"]["redactionPassed"] is True, matrix
        assert set(matrix["coverage"]["coveredFirstPartyApps"]) == set(EXPECTED_FIRST_PARTY_APPS), matrix
        matrix_rows_by_id = {row["id"]: row for row in matrix["rows"]}
        pr253_app_service_evidence_ids = APP_SERVICE_DEPENDENCY_AND_GRANT_BUNDLE_EVIDENCE_IDS
        for row_id in (
            "app-update",
            "first-party-beta-catalog",
            "production-catalog-channels",
            "first-party-app-maintenance-policy",
            "ecosystem-security-advisory-and-revocation",
            "production-security-response-runbook",
            "developer-beta-toolkit",
            "app-platform-beta-docs-and-program",
            "third-party-developer-beta-program",
            "app-store-submission-and-review",
            "review-governance-transparency",
            "app-vault-and-generated-documents",
            "content-fetch-and-networked-content",
            "app-data-backup-restore-portability",
            "trust-graph-preview-platform",
            "social-inbox-preview",
            "legacy-plugin-migration",
            "apphost-sandbox-provider",
            "public-beta-security-hardening",
            "app-platform-user-consent-flow",
            "operator-beta-ux-and-recovery",
            "operator-rc-recovery-and-support-workflow",
            "platform-api-contract",
            "interop-smoke",
            "performance-smoke",
            "live-network-beta-certification",
            "legacy-retirement",
            "ecosystem-certification-matrix",
            ECOSYSTEM_RC_MATRIX_ROW_ID,
            "app-service-discovery-and-grants",
        ):
            assert row_id in matrix_rows_by_id, row_id
        rc_gate_row = matrix_rows_by_id[ECOSYSTEM_RC_MATRIX_ROW_ID]
        assert ECOSYSTEM_RC_EVIDENCE_ID in rc_gate_row["requiredEvidenceIds"], rc_gate_row
        assert ECOSYSTEM_RC_GATE_ID in rc_gate_row["gateIds"], rc_gate_row
        app_services_row = matrix_rows_by_id["app-service-discovery-and-grants"]
        for evidence_id in pr253_app_service_evidence_ids:
            assert evidence_id in app_services_row["requiredEvidenceIds"], app_services_row
        app_store_row = matrix_rows_by_id["app-store-submission-and-review"]
        for evidence_id in THIRD_PARTY_INTAKE_EVIDENCE_IDS:
            assert evidence_id in app_store_row["requiredEvidenceIds"], app_store_row
        disabled_live_row = matrix_rows_by_id["live-network-beta-certification"]
        assert disabled_live_row["status"] == "pass", disabled_live_row
        assert disabled_live_row["releaseBlocker"] is False, disabled_live_row
        assert not any(
            issue_id.startswith("evidence.live-network-beta.")
            for issue_id in disabled_live_row.get("issueIds", [])
        ), disabled_live_row
        stable_not_requested_row = matrix_rows_by_id["stable-1-0-readiness"]
        assert stable_not_requested_row["status"] == "pass", stable_not_requested_row
        assert stable_not_requested_row["releaseBlocker"] is False, stable_not_requested_row
        assert stable_not_requested_row["previousStatus"] == "pass", stable_not_requested_row
        assert stable_not_requested_row["regressionStatus"] == "unchanged", stable_not_requested_row
        assert stable_not_requested_row["details"]["notRequested"] is True, stable_not_requested_row
        assert stable_not_requested_row["details"]["required"] is False, stable_not_requested_row
        assert not any(
            issue_id.startswith("evidence.stable-1.0.")
            for issue_id in stable_not_requested_row.get("issueIds", [])
        ), stable_not_requested_row
        covered_evidence_ids = {
            evidence_id
            for row in matrix["rows"]
            for evidence_id in row.get("evidenceIds", [])
        }
        for evidence_id, item in {
            item["id"]: item for item in summary["evidence"]
        }.items():
            if item["requiredForReleaseCandidate"]:
                assert evidence_id in covered_evidence_ids, evidence_id
        for evidence_id in (
            "app-platform.trust-graph-preview",
            "app-platform.trust-graph-durable-store",
            "app-platform.trust-graph-exchange",
            "app-platform.trust-statement-signing",
            "app-platform.social-message-signing",
            "app-review.governance",
            "app-review.reviewer-key-lifecycle",
            "app-review.transparency-log",
            "app-review.review-history-api",
            "app-review.first-party-review-chain",
            "reference-app.trust-graph",
            "reference-app.trust-graph-durable-exchange",
            "reference-app.social-inbox",
            "reference-app.social-inbox-rc-threading",
            "app-platform.trust-social-beta-hardening",
            "app-platform.trust-social-content-format-profiles",
            "migration.social-mail-preview",
            "legacy-plugin.freeze-policy",
            "legacy-plugin.migration-guide",
            "legacy-plugin.social-inbox-spike",
            "legacy-plugin.migration-finalization",
            "legacy-admin.removal-wave-2",
            "legacy-admin.removal-wave-3",
            "legacy-admin.removal-wave-4",
            "legacy-admin.removal-wave-5",
            "legacy-admin.final-admin-surface",
            "legacy-admin.browse-retained",
            "legacy-admin.emergency-fallback-retained",
            "app-platform.docs-portal",
            "app-platform.beta-program",
            "app-platform.beta-tutorials",
            "app-platform.docs-redaction",
            "app-data.backup-restore-portability",
            "app-platform.user-consent-flow",
            "operator-beta.app-data-backup-restore",
            *pr253_app_service_evidence_ids,
            ECOSYSTEM_RC_EVIDENCE_ID,
            *OPERATOR_RC_EVIDENCE_IDS,
            *ECOSYSTEM_SECURITY_EVIDENCE_IDS,
        ):
            assert evidence_id in covered_evidence_ids, evidence_id
        gate_ids = {gate["id"] for gate in summary["ecosystemGates"]}
        assert ECOSYSTEM_RC_GATE_ID in gate_ids, gate_ids
        covered_gate_ids = {gate_id for row in matrix["rows"] for gate_id in row.get("gateIds", [])}
        assert gate_ids <= covered_gate_ids, (gate_ids, covered_gate_ids)
        assert summary["ecosystemMatrixPath"].endswith(ECOSYSTEM_MATRIX_FILE_NAME), summary
        assert summary["ecosystemMatrixReportPath"].endswith(ECOSYSTEM_MATRIX_REPORT_FILE_NAME), summary
        assert summary["ecosystemMatrix"]["schemaVersion"] == ECOSYSTEM_MATRIX_SCHEMA_VERSION, summary
        assert summary["ecosystemMatrix"]["rowCount"] == len(matrix["rows"]), summary
        evidence_by_id = {item["id"]: item for item in summary["evidence"]}
        assert evidence_by_id["release-certification.ecosystem-matrix"][
            "requiredForReleaseCandidate"
        ] is True
        assert evidence_by_id[ECOSYSTEM_RC_EVIDENCE_ID]["requiredForReleaseCandidate"] is True
        assert evidence_by_id[ECOSYSTEM_RC_EVIDENCE_ID]["status"] == "warn", evidence_by_id
        assert evidence_by_id["app-update.lifecycle"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["app-platform.user-consent-flow"]["status"] == "pass", evidence_by_id
        assert (
            evidence_by_id["app-platform.user-consent-flow"]["requiredForReleaseCandidate"] is True
        )
        assert evidence_by_id["app-update.lifecycle"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["app-update.scheduler"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["app-update.scheduler"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["app-update.rollback"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["app-update.rollback"]["requiredForReleaseCandidate"] is True
        for evidence_id in ECOSYSTEM_SECURITY_EVIDENCE_IDS:
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id
            assert evidence_by_id[evidence_id]["requiredForReleaseCandidate"] is True
        for evidence_id in OPERATOR_RC_EVIDENCE_IDS:
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id
            assert evidence_by_id[evidence_id]["requiredForReleaseCandidate"] is True
        for evidence_id in (
            "app-platform.docs-portal",
            "app-platform.beta-program",
            "app-platform.beta-tutorials",
            "app-platform.docs-redaction",
        ):
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id
            assert evidence_by_id[evidence_id]["requiredForReleaseCandidate"] is True
        report_text = (out_dir / REPORT_FILE_NAME).read_text(encoding="utf-8")
        for evidence_id in (
            "app-platform.docs-portal",
            "app-platform.beta-program",
            "app-platform.beta-tutorials",
            "app-platform.docs-redaction",
            "app-data.backup-restore-portability",
            "operator-beta.app-data-backup-restore",
        ):
            assert f"### `{evidence_id}`" in report_text, evidence_id
        assert "redactionFindings" in report_text, report_text
        assert evidence_by_id["app-vault.capabilities"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["app-vault.capabilities"]["requiredForReleaseCandidate"] is True
        assert (
            evidence_by_id["app-platform.identity-profile-publish"]["status"] == "pass"
        ), evidence_by_id
        assert (
            evidence_by_id["app-platform.generated-document-insert"]["status"] == "pass"
        ), evidence_by_id
        assert evidence_by_id["app-platform.content-fetch"]["status"] == "pass", evidence_by_id
        assert (
            evidence_by_id["app-platform.content-subscriptions"]["status"] == "pass"
        ), evidence_by_id
        assert (
            evidence_by_id["network-content.subscription-scheduler"]["status"] == "pass"
        ), evidence_by_id
        assert (
            evidence_by_id["app-platform.durable-app-data-store"]["status"] == "pass"
        ), evidence_by_id
        assert (
            evidence_by_id["app-data.backup-restore-portability"]["status"] == "pass"
        ), evidence_by_id
        assert evidence_by_id["app-data.backup-restore-portability"][
            "requiredForReleaseCandidate"
        ] is True
        assert (
            evidence_by_id["operator-beta.app-data-backup-restore"]["status"] == "pass"
        ), evidence_by_id
        assert evidence_by_id["app-platform.trust-graph-preview"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["app-platform.trust-graph-preview"][
            "requiredForReleaseCandidate"
        ] is True
        assert (
            evidence_by_id["app-platform.trust-graph-durable-store"]["status"] == "pass"
        ), evidence_by_id
        assert (
            evidence_by_id["app-platform.trust-graph-exchange"]["status"] == "pass"
        ), evidence_by_id
        assert (
            evidence_by_id["app-platform.trust-statement-signing"]["status"] == "pass"
        ), evidence_by_id
        assert evidence_by_id["app-platform.trust-statement-signing"][
            "requiredForReleaseCandidate"
        ] is True
        assert evidence_by_id["app-platform.social-message-signing"]["status"] == "pass", (
            evidence_by_id
        )
        assert evidence_by_id["app-platform.social-message-signing"][
            "requiredForReleaseCandidate"
        ] is True
        for evidence_id in (
            "app-review.governance",
            "app-review.reviewer-key-lifecycle",
            "app-review.transparency-log",
            "app-review.review-history-api",
            "app-review.first-party-review-chain",
        ):
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id
            assert evidence_by_id[evidence_id]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["reference-app.profile-publisher"]["status"] == "pass", evidence_by_id
        assert (
            evidence_by_id["reference-app.profile-publisher-app-data"]["status"] == "pass"
        ), evidence_by_id
        assert evidence_by_id["reference-app.feed-reader"]["status"] == "pass", evidence_by_id
        assert (
            evidence_by_id["reference-app.feed-reader-subscriptions"]["status"] == "pass"
        ), evidence_by_id
        assert evidence_by_id["reference-app.feed-reader-app-data"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["reference-app.trust-graph"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["reference-app.trust-graph"]["requiredForReleaseCandidate"] is True
        assert (
            evidence_by_id["reference-app.trust-graph-durable-exchange"]["status"] == "pass"
        ), evidence_by_id
        assert (
            evidence_by_id["reference-app.trust-graph-app-data-preview"]["status"] == "pass"
        ), evidence_by_id
        for evidence_id in (
            "reference-app.social-inbox",
            "reference-app.social-inbox-signed-message",
            "reference-app.social-inbox-subscriptions",
            "reference-app.social-inbox-app-data",
            "reference-app.social-inbox-trust-annotations",
            "reference-app.social-inbox-rc-threading",
            "app-platform.trust-social-beta-hardening",
            "app-platform.trust-social-content-format-profiles",
            "reference-app.social-inbox-service-grant",
            "migration.social-mail-preview",
            "legacy-plugin.freeze-policy",
            "legacy-plugin.migration-guide",
            "legacy-plugin.social-inbox-spike",
            "legacy-plugin.migration-finalization",
        ):
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id
            assert evidence_by_id[evidence_id]["requiredForReleaseCandidate"] is True
        for evidence_id in (
            "app-services.registry",
            "app-services.grants",
            *pr253_app_service_evidence_ids,
            "app-services.trust-score-provider",
            "app-services.web-shell",
            "app-services.redaction",
        ):
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id
            assert evidence_by_id[evidence_id]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-admin.removal-wave-1"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["legacy-admin.removal-wave-1"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-admin.removal-wave-2"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["legacy-admin.removal-wave-2"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-admin.removal-wave-3"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["legacy-admin.removal-wave-3"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-admin.removal-wave-4"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["legacy-admin.removal-wave-4"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-admin.removal-wave-5"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["legacy-admin.removal-wave-5"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-admin.final-admin-surface"]["status"] == "pass", evidence_by_id
        assert (
            evidence_by_id["legacy-admin.final-admin-surface"]["requiredForReleaseCandidate"]
            is True
        )
        assert evidence_by_id["legacy-admin.browse-retained"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["legacy-admin.browse-retained"]["requiredForReleaseCandidate"] is True
        assert (
            evidence_by_id["legacy-admin.emergency-fallback-retained"]["status"] == "pass"
        ), evidence_by_id
        assert (
            evidence_by_id["legacy-admin.emergency-fallback-retained"][
                "requiredForReleaseCandidate"
            ]
            is True
        )
        optional_skip_status, optional_skip_release_passed = determine_overall_status(
            "release-candidate",
            [
                EvidenceItem("catalog.smoke", "pass", True, "passed", "<repo>/summary.json", {}),
                EvidenceItem("apphost.live", "skip", False, "not requested", "<repo>/summary.json", {}),
            ],
            WaiverContext(),
        )
        assert optional_skip_status == "pass", optional_skip_status
        assert optional_skip_release_passed is True, optional_skip_release_passed
        report = (out_dir / REPORT_FILE_NAME).read_text(encoding="utf-8")
        matrix_report = (out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME).read_text(encoding="utf-8")
        assert "Release Certification Report" in report
        assert "Historical Comparison" in report
        assert "Ecosystem RC Certification Gate" in report
        assert "Ecosystem Gates" in report
        assert "Ecosystem Certification Matrix" in report
        assert ECOSYSTEM_MATRIX_REPORT_FILE_NAME in report
        assert "Ecosystem Certification Matrix" in matrix_report
        assert "Required evidence covered" in matrix_report
        assert "Waivers" in report
        encoded = json.dumps(summary, sort_keys=True) + json.dumps(matrix, sort_keys=True) + matrix_report
        for forbidden in ("CRYPTAD_APP_TOKEN", "USK@private", str(workspace)):
            assert forbidden not in encoded, f"self-test leaked {forbidden}"
        feed_body_metadata = sanitize_value(
            {
                "rawFeedBody": "<feed><entry>private body</entry></feed>",
                "rawFeedBodyBase64": "opaque-feed-body-base64",
                "rawRequestBody": "uri=SSK@private",
                "requestBodyText": "opaque-request-body-text",
                "feedContentPreview": "opaque-feed-preview",
                "rawFeedBodySource": "opaque-feed-body-source",
                "requestBodySource": "opaque-request-body-source",
                "feedSummary": "3 entries",
                "rawFeedBodyRedacted": True,
                "rawFeedBodiesExcluded": True,
                "rawMessageBody": "private social message body",
                "messageBodyText": "private social message text",
                "rawFetchedBody": "{\"messages\":[{\"body\":\"private fetched body\"}]}",
                "fetchedBodyPreview": "private fetched preview",
                "rawMessageBodiesExcludedFromEvidence": True,
            },
            workspace,
            out_dir,
        )
        assert feed_body_metadata["rawFeedBody"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["rawFeedBodyBase64"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["rawRequestBody"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["requestBodyText"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["feedContentPreview"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["rawFeedBodySource"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["requestBodySource"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["feedSummary"] == "3 entries", feed_body_metadata
        assert feed_body_metadata["rawFeedBodyRedacted"] is True, feed_body_metadata
        assert feed_body_metadata["rawFeedBodiesExcluded"] is True, feed_body_metadata
        assert feed_body_metadata["rawMessageBody"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["messageBodyText"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["rawFetchedBody"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["fetchedBodyPreview"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["rawMessageBodiesExcludedFromEvidence"] is True, feed_body_metadata
        interop_item = next(item for item in summary["evidence"] if item["id"] == "interop.smoke")
        assert "artifacts/private-insert-uris.json" not in json.dumps(interop_item)

        direct_rc_waiver_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/direct-rc-gate-waiver-cert").resolve(),
            waivers={ECOSYSTEM_RC_GATE_ID: "Release manager accepted temporary RC gate warning."},
        )
        direct_rc_waiver_summary, direct_rc_waiver_exit_code = run(direct_rc_waiver_settings)
        assert direct_rc_waiver_exit_code == 0, direct_rc_waiver_summary
        assert direct_rc_waiver_summary["ecosystemRcGate"]["status"] == "warn", (
            direct_rc_waiver_summary
        )
        assert direct_rc_waiver_summary["ecosystemRcGate"]["waiverCount"] == 1, (
            direct_rc_waiver_summary
        )
        direct_rc_gate = next(
            gate
            for gate in direct_rc_waiver_summary["ecosystemGates"]
            if gate["id"] == ECOSYSTEM_RC_GATE_ID
        )
        assert direct_rc_gate["details"]["waiverId"] == ECOSYSTEM_RC_GATE_ID, direct_rc_gate
        direct_rc_evidence = next(
            item
            for item in direct_rc_waiver_summary["evidence"]
            if item["id"] == ECOSYSTEM_RC_EVIDENCE_ID
        )
        assert direct_rc_evidence["details"]["waiverCount"] == 1, direct_rc_evidence
        assert ECOSYSTEM_RC_GATE_ID in direct_rc_evidence["details"]["details"]["waiverIds"], (
            direct_rc_evidence
        )
        direct_rc_report = (
            direct_rc_waiver_settings.out_dir / REPORT_FILE_NAME
        ).read_text(encoding="utf-8")
        assert (
            f"- Waivers: `1` `{ECOSYSTEM_RC_GATE_ID}`" in direct_rc_report
        ), direct_rc_report

        previous_good_path = workspace / "build/previous-good/release-certification-summary.json"
        previous_good = {
            "schemaVersion": SCHEMA_VERSION,
            "tool": TOOL_NAME,
            "mode": "release-candidate",
            "status": "pass",
            "releaseCandidatePassed": True,
            "generatedAt": "2026-05-01T00:00:00Z",
            "metadata": {"gitCommit": "previous-sha", "releaseVersion": "2026.05.0"},
            "evidence": summary["evidence"],
        }
        write_json(previous_good_path, previous_good)
        previous_production_beta_path = workspace / "build/previous-good/production-beta-summary.json"
        previous_production_beta = {
            "schemaVersion": 1,
            "kind": "cryptad-production-beta-release-summary",
            "tool": "production-beta-release",
            "releaseId": "cryptad-beta-2026.05.0",
            "version": "2026.05.0",
            "generatedAt": "2026-05-01T00:00:00Z",
            "status": "pass",
            "promotionReady": True,
            "artifactBaseUri": "https://downloads.crypta.invalid/production-beta/2026.05.0",
            "metadata": {"gitCommit": "previous-sha", "releaseVersion": "2026.05.0"},
        }
        previous_candidate_fixture = read_json(multi_node_beta_soak.previous_candidate_fixture_path()) or {}
        previous_candidate_source_metadata = {
            field: json.loads(json.dumps(previous_candidate_fixture[field], sort_keys=True))
            for field in multi_node_beta_soak.PREVIOUS_CANDIDATE_SOURCE_METADATA_FIELDS
            if field in previous_candidate_fixture
        }
        for app in previous_candidate_source_metadata.get("firstPartyApps", []):
            if isinstance(app, dict):
                app["version"] = "2026.05.0"
        previous_production_beta.update(previous_candidate_source_metadata)
        write_json(previous_production_beta_path, previous_production_beta)
        previous_candidate_good_path = workspace / "build/previous-good/previous-beta-candidate-summary.json"
        previous_candidate_good = multi_node_beta_soak.build_previous_candidate_summary(
            previous_good,
            previous_production_beta,
            release_certification_digest=multi_node_beta_soak.sha256_path(previous_good_path),
            production_beta_digest=multi_node_beta_soak.sha256_path(previous_production_beta_path),
            generated_at="2026-05-01T00:00:00Z",
        )
        write_json(previous_candidate_good_path, previous_candidate_good)
        previous_matrix_good_path = workspace / "build/previous-matrix-good/release-certification-summary.json"
        previous_matrix_good = dict(previous_good)
        previous_matrix_good["evidence"] = [
            (
                item
                if item.get("id") != "release-certification.ecosystem-matrix"
                else (item | {"status": "pass", "summary": "Ecosystem certification matrix status is pass."})
            )
            for item in summary["evidence"]
        ]
        previous_matrix_good["ecosystemMatrix"] = {
            "schemaVersion": ECOSYSTEM_MATRIX_SCHEMA_VERSION,
            "status": "pass",
            "rowCount": len(matrix["rows"]),
            "releaseBlockerCount": 0,
            "coverage": matrix["coverage"],
            "rowStatuses": {row["id"]: "pass" for row in matrix["rows"]},
            "matrixDiffs": [],
        }
        write_json(previous_matrix_good_path, previous_matrix_good)
        multi_node_pass_config = multi_node_beta_soak.validate_config(
            multi_node_beta_soak.load_config(fixture_dir / "self-test-multi-node-beta-soak.json")
        )
        multi_node_pass_config["previousCandidate"]["summaryPath"] = str(previous_candidate_good_path)
        multi_node_pass_config["previousCandidate"]["version"] = previous_candidate_good["version"]
        multi_node_pass_path = workspace / "build/multi-node-pass/summary.json"
        multi_node_pass_summary = multi_node_beta_soak.build_summary(
            multi_node_pass_config,
            out_dir=multi_node_pass_path.parent,
            base_dir=fixture_dir,
        )
        write_json(multi_node_pass_path, multi_node_pass_summary)
        write_text(
            multi_node_pass_path.parent / multi_node_beta_soak.REPORT_FILE_NAME,
            multi_node_beta_soak.render_report(multi_node_pass_summary),
        )
        multi_node_disabled_required_path = workspace / "build/multi-node-disabled-required/summary.json"
        multi_node_disabled_required_summary = json.loads(json.dumps(multi_node_pass_summary, sort_keys=True))
        disabled_backup = multi_node_beta_soak.scenario_map(multi_node_disabled_required_summary)["backup-restore"]
        disabled_backup["status"] = "warn"
        disabled_backup["summary"] = "Scenario is disabled in the topology config."
        disabled_backup["evidence"] = {
            "evidenceId": "multi-node-beta.backup-restore",
            "configured": False,
            "strict": False,
        }
        multi_node_disabled_required_summary["scenarioStatuses"]["backup-restore"] = "warn"
        multi_node_disabled_required_summary["status"] = "warn"
        multi_node_disabled_required_summary["promotionReady"] = True
        multi_node_disabled_required_summary["warnings"] = ["backup-restore has warnings"]
        write_json(multi_node_disabled_required_path, multi_node_disabled_required_summary)
        multi_node_disabled_required_items = multi_node_beta_soak_evidence(
            multi_node_disabled_required_path,
            workspace,
            out_dir,
            "release-candidate",
            False,
        )
        multi_node_disabled_umbrella = next(
            item for item in multi_node_disabled_required_items if item.id == "multi-node-beta.soak"
        )
        multi_node_disabled_backup = next(
            item for item in multi_node_disabled_required_items if item.id == "multi-node-beta.backup-restore"
        )
        assert multi_node_disabled_umbrella.status == "fail", multi_node_disabled_umbrella
        assert multi_node_disabled_backup.status == "fail", multi_node_disabled_backup
        assert "backup-restore" in multi_node_disabled_umbrella.details.get("disabledRequiredScenarios", []), (
            multi_node_disabled_umbrella
        )
        assert (
            "scenario backup-restore is disabled but required in release-candidate"
            in multi_node_disabled_umbrella.details.get("validationErrors", [])
        ), multi_node_disabled_umbrella
        multi_node_publish_leak_path = workspace / "build/multi-node-publish-leak/summary.json"
        multi_node_publish_leak_summary = json.loads(json.dumps(multi_node_pass_summary, sort_keys=True))
        multi_node_publish_leak_summary["blockers"] = [
            "rawBackupPayload: backup bundle bytes /srv/runner/work/cryptad/private-state"
        ]
        multi_node_publish_leak_summary["warnings"] = ["/etc/cryptad/private-state"]
        multi_node_publish_leak_summary["redaction"]["rawBackupPayload"] = "backup bundle bytes"
        multi_node_publish_leak_summary["redaction"]["findings"] = [
            {
                "kind": "raw-backup-payload",
                "location": "/srv/runner/work/cryptad/private-state",
                "source": "validation",
                "rawBackupPayload": "backup bundle bytes",
            }
        ]
        write_json(multi_node_publish_leak_path, multi_node_publish_leak_summary)
        write_text(
            multi_node_publish_leak_path.parent / multi_node_beta_soak.REPORT_FILE_NAME,
            "rawBackupPayload: backup bundle bytes\n/srv/runner/work/cryptad/private-state\n",
        )
        multi_node_publish_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/multi-node-publish-cert").resolve(),
            multi_node_soak_summary=multi_node_publish_leak_path,
        )
        collect_source_artifacts(multi_node_publish_settings, multi_node_publish_settings.out_dir)
        published_multi_node_summary = (
            multi_node_publish_settings.out_dir / "artifacts/multi-node-beta-soak-summary.json"
        ).read_text(encoding="utf-8")
        published_multi_node_report = (
            multi_node_publish_settings.out_dir / "artifacts/multi-node-beta-soak-report.md"
        ).read_text(encoding="utf-8")
        for forbidden in ("rawBackupPayload", "backup bundle bytes", "/srv/runner", "/etc/cryptad"):
            assert forbidden not in published_multi_node_summary, published_multi_node_summary
            assert forbidden not in published_multi_node_report, published_multi_node_report
        published_multi_node_summary_json = json.loads(published_multi_node_summary)
        assert (
            published_multi_node_summary_json["redaction"]["checks"]["failOnTokens"] is True
        ), published_multi_node_summary_json
        assert "Multi-node Beta Soak Report Redacted" in published_multi_node_report, published_multi_node_report
        multi_node_publish_tmp_path = workspace / "build/multi-node-publish-leak/summary.json.tmp"
        write_json(multi_node_publish_tmp_path, multi_node_publish_leak_summary)
        multi_node_publish_tmp_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/multi-node-publish-tmp-cert").resolve(),
            multi_node_soak_summary=multi_node_publish_tmp_path,
        )
        collect_source_artifacts(multi_node_publish_tmp_settings, multi_node_publish_tmp_settings.out_dir)
        published_multi_node_tmp_summary = (
            multi_node_publish_tmp_settings.out_dir / "artifacts/multi-node-beta-soak-summary.json"
        ).read_text(encoding="utf-8")
        for forbidden in ("rawBackupPayload", "backup bundle bytes", "/srv/runner", "/etc/cryptad"):
            assert forbidden not in published_multi_node_tmp_summary, published_multi_node_tmp_summary
        published_multi_node_tmp_summary_json = json.loads(published_multi_node_tmp_summary)
        assert (
            published_multi_node_tmp_summary_json["redaction"]["checks"]["failOnTokens"] is True
        ), published_multi_node_tmp_summary_json
        multi_node_leaky_path = workspace / "build/multi-node-leaky/summary.json"
        multi_node_leaky_summary = json.loads(json.dumps(multi_node_pass_summary, sort_keys=True))
        multi_node_leaky_summary.setdefault("evidence", {})["rawAppData"] = {"value": "unredacted value"}
        write_json(multi_node_leaky_path, multi_node_leaky_summary)
        multi_node_leaky_items = multi_node_beta_soak_evidence(
            multi_node_leaky_path,
            workspace,
            out_dir,
            "release-candidate",
            True,
        )
        multi_node_leaky_redaction = next(
            item for item in multi_node_leaky_items if item.id == "multi-node-beta.redaction"
        )
        assert multi_node_leaky_redaction.status == "fail", multi_node_leaky_redaction
        assert evidence_item_has_unwaivable_redaction_findings(multi_node_leaky_redaction), (
            multi_node_leaky_redaction
        )
        assert any(
            finding.get("kind") == "raw-app-data" and finding.get("source") == "validation"
            for finding in multi_node_leaky_redaction.details.get("redactionFindings", [])
            if isinstance(finding, dict)
        ), multi_node_leaky_redaction
        multi_node_unsafe_flags_path = workspace / "build/multi-node-unsafe-flags/summary.json"
        multi_node_unsafe_flags_summary = json.loads(json.dumps(multi_node_pass_summary, sort_keys=True))
        unsafe_support_evidence = multi_node_beta_soak.scenario_map(multi_node_unsafe_flags_summary)[
            "support-bundle-drill"
        ]["evidence"]
        unsafe_support_evidence["privateInsertUrisIncluded"] = True
        unsafe_support_evidence["tokensIncluded"] = True
        unsafe_support_evidence["redactionScanStatus"] = "fail"
        write_json(multi_node_unsafe_flags_path, multi_node_unsafe_flags_summary)
        multi_node_unsafe_flags_items = multi_node_beta_soak_evidence(
            multi_node_unsafe_flags_path,
            workspace,
            out_dir,
            "release-candidate",
            True,
        )
        multi_node_unsafe_flags_redaction = next(
            item for item in multi_node_unsafe_flags_items if item.id == "multi-node-beta.redaction"
        )
        assert multi_node_unsafe_flags_redaction.status == "fail", multi_node_unsafe_flags_redaction
        assert evidence_item_has_unwaivable_redaction_findings(multi_node_unsafe_flags_redaction), (
            multi_node_unsafe_flags_redaction
        )
        assert any(
            finding.get("kind") == "forbidden-included-flag" and finding.get("source") == "validation"
            for finding in multi_node_unsafe_flags_redaction.details.get("redactionFindings", [])
            if isinstance(finding, dict)
        ), multi_node_unsafe_flags_redaction
        assert any(
            finding.get("kind") == "redaction-scan-status" and finding.get("source") == "validation"
            for finding in multi_node_unsafe_flags_redaction.details.get("redactionFindings", [])
            if isinstance(finding, dict)
        ), multi_node_unsafe_flags_redaction
        multi_node_disabled_checks_path = workspace / "build/multi-node-disabled-checks/summary.json"
        multi_node_disabled_checks_summary = json.loads(json.dumps(multi_node_pass_summary, sort_keys=True))
        multi_node_disabled_checks_summary["redaction"]["checks"]["failOnTokens"] = False
        write_json(multi_node_disabled_checks_path, multi_node_disabled_checks_summary)
        multi_node_disabled_checks_items = multi_node_beta_soak_evidence(
            multi_node_disabled_checks_path,
            workspace,
            out_dir,
            "release-candidate",
            True,
        )
        multi_node_disabled_checks_redaction = next(
            item for item in multi_node_disabled_checks_items if item.id == "multi-node-beta.redaction"
        )
        assert multi_node_disabled_checks_redaction.status == "fail", multi_node_disabled_checks_redaction
        assert evidence_item_has_unwaivable_redaction_findings(multi_node_disabled_checks_redaction), (
            multi_node_disabled_checks_redaction
        )
        assert any(
            finding.get("kind") == "disabled-redaction-check" and finding.get("source") == "validation"
            for finding in multi_node_disabled_checks_redaction.details.get("redactionFindings", [])
            if isinstance(finding, dict)
        ), multi_node_disabled_checks_redaction
        multi_node_non_promotable_path = workspace / "build/multi-node-non-promotable/summary.json"
        multi_node_non_promotable_summary = json.loads(json.dumps(multi_node_pass_summary, sort_keys=True))
        multi_node_non_promotable_summary["promotionReady"] = False
        write_json(multi_node_non_promotable_path, multi_node_non_promotable_summary)
        multi_node_non_promotable_items = multi_node_beta_soak_evidence(
            multi_node_non_promotable_path,
            workspace,
            out_dir,
            "release-candidate",
            True,
        )
        multi_node_non_promotable_soak = next(
            item for item in multi_node_non_promotable_items if item.id == "multi-node-beta.soak"
        )
        assert multi_node_non_promotable_soak.status == "fail", multi_node_non_promotable_soak
        assert multi_node_non_promotable_soak.details["promotionReady"] is False, multi_node_non_promotable_soak
        with_previous_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/with-previous-cert").resolve(),
            previous_summary=previous_good_path,
            multi_node_soak_summary=multi_node_pass_path,
        )
        with_previous_summary, with_previous_exit_code = run(with_previous_settings)
        assert with_previous_exit_code == 0, with_previous_summary
        assert with_previous_summary["status"] == "warn", with_previous_summary
        assert with_previous_summary["historyComparison"]["status"] == "pass", with_previous_summary
        assert with_previous_summary["ecosystemGateStatus"] == "warn", with_previous_summary
        assert with_previous_summary["ecosystemRcGate"]["status"] == "warn", with_previous_summary
        assert with_previous_summary["ecosystemMatrix"]["coverage"]["requiredEvidenceCovered"] is True
        assert with_previous_summary["ecosystemMatrix"]["coverage"]["ecosystemGatesCovered"] is True
        with_previous_matrix = read_json(with_previous_settings.out_dir / ECOSYSTEM_MATRIX_FILE_NAME)
        assert with_previous_matrix is not None, with_previous_summary
        assert with_previous_matrix["previousSummaryPresent"] is True, with_previous_matrix
        assert with_previous_matrix["previousMatrixPresent"] is False, with_previous_matrix

        history_store = workspace / "build/release-certification-history"
        write_history_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/write-history-cert").resolve(),
            previous_summary=previous_good_path,
            write_history=True,
            history_dir=history_store,
            history_label="2026.05.0",
        )
        write_history_summary, write_history_exit_code = run(write_history_settings)
        assert write_history_exit_code == 0, write_history_summary
        assert (history_store / "latest-summary.json").is_file(), write_history_summary
        assert (history_store / "latest-history-comparison.json").is_file(), write_history_summary
        assert (
            history_store / "releases/2026.05.0/release-certification-summary.json"
        ).is_file(), write_history_summary
        protected_latest_summary = read_json(history_store / "latest-summary.json")
        assert protected_latest_summary is not None, write_history_summary
        written_history_encoded = json.dumps(read_json(history_store / "latest-summary.json"), sort_keys=True)
        assert str(workspace) not in written_history_encoded, written_history_encoded

        def write_app_summary_variant(name: str, mutate: Any) -> Path:
            app_summary = read_json(settings.app_platform_summary)
            assert app_summary is not None
            mutate(app_summary)
            path = workspace / f"build/{name}/summary.json"
            write_json(path, app_summary)
            return path

        def update_evidence(summary_value: dict[str, Any], evidence_id: str, mutate: Any) -> None:
            evidence_list = summary_value.get("evidence", [])
            assert isinstance(evidence_list, list)
            for entry in evidence_list:
                if isinstance(entry, dict) and entry.get("id") == evidence_id:
                    mutate(entry)
                    return
            raise AssertionError(f"missing evidence {evidence_id}")

        def run_with_previous(name: str, **overrides: Any) -> tuple[dict[str, Any], int]:
            previous_summary_override = overrides.pop("previous_summary", previous_good_path)
            multi_node_summary_override = overrides.pop("multi_node_soak_summary", multi_node_pass_path)
            variant_settings = dataclasses.replace(
                settings,
                out_dir=(workspace / f"build/{name}").resolve(),
                previous_summary=previous_summary_override,
                multi_node_soak_summary=multi_node_summary_override,
                **overrides,
            )
            return run(variant_settings)

        def gate_by_id(summary_value: dict[str, Any], gate_id: str) -> dict[str, Any]:
            for gate in summary_value.get("ecosystemGates", []):
                if isinstance(gate, dict) and gate.get("id") == gate_id:
                    return gate
            raise AssertionError(f"missing gate {gate_id}")

        def matrix_row_by_id(out_path: Path, row_id: str) -> dict[str, Any]:
            matrix_value = read_json(out_path / ECOSYSTEM_MATRIX_FILE_NAME)
            assert matrix_value is not None
            for row in matrix_value.get("rows", []):
                if isinstance(row, dict) and row.get("id") == row_id:
                    return row
            raise AssertionError(f"missing matrix row {row_id}")

        def evidence_by_id(summary_value: dict[str, Any], evidence_id: str) -> dict[str, Any]:
            for item in summary_value.get("evidence", []):
                if isinstance(item, dict) and item.get("id") == evidence_id:
                    return item
            raise AssertionError(f"missing evidence {evidence_id}")

        clean_happy_summary, clean_happy_exit_code = run_with_previous(
            "clean-happy-cert",
            previous_summary=previous_matrix_good_path,
        )
        assert clean_happy_exit_code == 0, clean_happy_summary
        assert clean_happy_summary["status"] == "pass", clean_happy_summary
        assert clean_happy_summary["promotionDecision"] == "PASS", clean_happy_summary
        assert clean_happy_summary["releaseCandidatePassed"] is True, clean_happy_summary
        assert clean_happy_summary["ecosystemGateStatus"] == "pass", clean_happy_summary
        assert clean_happy_summary["ecosystemRcDecision"] == "PASS", clean_happy_summary
        assert clean_happy_summary["ecosystemRcPassed"] is True, clean_happy_summary
        assert clean_happy_summary["ecosystemRcGate"]["status"] == "pass", clean_happy_summary
        clean_happy_row = matrix_row_by_id(
            workspace / "build/clean-happy-cert",
            ECOSYSTEM_RC_MATRIX_ROW_ID,
        )
        assert clean_happy_row["status"] == "pass", clean_happy_row
        assert clean_happy_summary["ecosystemMatrix"]["status"] == "pass", clean_happy_summary

        waived_rc_gate_missing_soak_summary, waived_rc_gate_missing_soak_exit_code = run_with_previous(
            "waived-rc-gate-missing-network-scale-soak-cert",
            previous_summary=previous_matrix_good_path,
            network_scale_soak_summary=workspace / "build/missing-network-scale-soak/summary.json",
            waivers={ECOSYSTEM_RC_GATE_ID: "Release manager waived aggregate RC gate."},
        )
        assert waived_rc_gate_missing_soak_exit_code == 1, waived_rc_gate_missing_soak_summary
        assert waived_rc_gate_missing_soak_summary["releaseCandidatePassed"] is False, (
            waived_rc_gate_missing_soak_summary
        )
        assert waived_rc_gate_missing_soak_summary["ecosystemRcDecision"] == "FAIL", (
            waived_rc_gate_missing_soak_summary
        )
        assert waived_rc_gate_missing_soak_summary["ecosystemRcPassed"] is False, (
            waived_rc_gate_missing_soak_summary
        )
        waived_rc_gate = gate_by_id(
            waived_rc_gate_missing_soak_summary,
            ECOSYSTEM_RC_GATE_ID,
        )
        assert waived_rc_gate["status"] == "warn", waived_rc_gate
        assert waived_rc_gate["releaseBlocker"] is False, waived_rc_gate
        assert waived_rc_gate["details"]["waiverId"] == ECOSYSTEM_RC_GATE_ID, waived_rc_gate
        waived_soak_row_summary, waived_soak_row_exit_code = run_with_previous(
            "waived-network-scale-soak-row-cert",
            previous_summary=previous_matrix_good_path,
            network_scale_soak_summary=workspace / "build/missing-network-scale-soak/summary.json",
            waivers={
                "network-scale-soak-and-subscription-budget": (
                    "Release manager accepted temporary missing network-scale soak evidence."
                )
            },
        )
        assert waived_soak_row_exit_code == 0, waived_soak_row_summary
        assert waived_soak_row_summary["releaseCandidatePassed"] is True, (
            waived_soak_row_summary
        )
        assert waived_soak_row_summary["promotionDecision"] == "PASS WITH WARNINGS", (
            waived_soak_row_summary
        )
        waived_soak_rc_gate = gate_by_id(waived_soak_row_summary, ECOSYSTEM_RC_GATE_ID)
        assert waived_soak_rc_gate["status"] == "warn", waived_soak_rc_gate
        assert waived_soak_rc_gate["releaseBlocker"] is False, waived_soak_rc_gate
        assert waived_soak_rc_gate["details"]["networkScaleSoakSatisfied"] is True, (
            waived_soak_rc_gate
        )
        assert NETWORK_SCALE_SOAK_EVIDENCE_ID in waived_soak_rc_gate["details"][
            "waivedEvidenceIds"
        ], waived_soak_rc_gate
        assert NETWORK_SCALE_SOAK_EVIDENCE_ID not in waived_soak_rc_gate["details"][
            "failedEvidenceIds"
        ], waived_soak_rc_gate
        waived_soak_row = matrix_row_by_id(
            workspace / "build/waived-network-scale-soak-row-cert",
            "network-scale-soak-and-subscription-budget",
        )
        assert waived_soak_row["status"] == "warn", waived_soak_row
        assert waived_soak_row["releaseBlocker"] is False, waived_soak_row

        missing_pr253_path = write_app_summary_variant(
            "missing-pr253-app-service-evidence",
            lambda value: value.update(
                {
                    "evidence": [
                        item
                        for item in value["evidence"]
                        if item.get("id") not in pr253_app_service_evidence_ids
                    ]
                }
            ),
        )
        missing_pr253_items = app_platform_evidence(
            missing_pr253_path,
            workspace,
            out_dir,
            "release-candidate",
        )
        missing_pr253_by_id = {item.id: item for item in missing_pr253_items}
        for evidence_id in pr253_app_service_evidence_ids:
            assert missing_pr253_by_id[evidence_id].status == "missing", missing_pr253_by_id
            assert missing_pr253_by_id[evidence_id].required_for_release_candidate is True
        missing_pr253_summary, missing_pr253_exit_code = run_with_previous(
            "missing-pr253-app-service-cert",
            app_platform_summary=missing_pr253_path,
            previous_summary=previous_matrix_good_path,
        )
        assert missing_pr253_exit_code == 1, missing_pr253_summary
        assert missing_pr253_summary["status"] == "fail", missing_pr253_summary
        assert missing_pr253_summary["releaseCandidatePassed"] is False, missing_pr253_summary
        assert missing_pr253_summary["ecosystemRcGate"]["status"] == "fail", missing_pr253_summary
        assert gate_by_id(missing_pr253_summary, "ecosystem.reference-content-apps")[
            "status"
        ] == "fail"
        missing_pr253_row = matrix_row_by_id(
            workspace / "build/missing-pr253-app-service-cert",
            "app-service-discovery-and-grants",
        )
        assert missing_pr253_row["status"] == "fail", missing_pr253_row
        assert missing_pr253_row["releaseBlocker"] is True, missing_pr253_row

        dependency_redaction_findings_path = write_app_summary_variant(
            "dependency-redaction-findings",
            lambda value: update_evidence(
                value,
                "app-services.dependency-redaction",
                lambda entry: (
                    entry.update({"status": "fail"}),
                    entry.setdefault("details", {}).update(
                        {
                            "redactionFindings": [
                                {
                                    "path": "tools/release-certification/app-platform-smoke/summary.json",
                                    "issue": "raw-service-invocation-body",
                                }
                            ]
                        }
                    ),
                ),
            ),
        )
        waived_dependency_redaction_summary, waived_dependency_redaction_exit_code = run_with_previous(
            "waived-dependency-redaction-findings-cert",
            app_platform_summary=dependency_redaction_findings_path,
            previous_summary=previous_matrix_good_path,
            waivers={
                ECOSYSTEM_RC_GATE_ID: (
                    "Release manager attempted to waive aggregate RC gate redaction failure."
                ),
                "app-services.dependency-redaction": (
                    "Release manager attempted to waive app-service dependency redaction findings."
                )
            },
        )
        assert waived_dependency_redaction_exit_code == 1, waived_dependency_redaction_summary
        assert waived_dependency_redaction_summary["releaseCandidatePassed"] is False, (
            waived_dependency_redaction_summary
        )
        assert waived_dependency_redaction_summary["ecosystemRcPassed"] is False, (
            waived_dependency_redaction_summary
        )
        dependency_redaction_evidence = evidence_by_id(
            waived_dependency_redaction_summary,
            "app-services.dependency-redaction",
        )
        assert dependency_redaction_evidence["status"] == "fail", dependency_redaction_evidence
        assert "waived" not in dependency_redaction_evidence["details"], (
            dependency_redaction_evidence
        )
        dependency_redaction_rc_gate = gate_by_id(
            waived_dependency_redaction_summary,
            ECOSYSTEM_RC_GATE_ID,
        )
        assert dependency_redaction_rc_gate["status"] == "fail", dependency_redaction_rc_gate
        assert dependency_redaction_rc_gate["releaseBlocker"] is True, dependency_redaction_rc_gate
        assert "waived" not in dependency_redaction_rc_gate["details"], dependency_redaction_rc_gate
        assert dependency_redaction_rc_gate["details"]["redactionPassed"] is False, (
            dependency_redaction_rc_gate
        )
        assert "app-services.dependency-redaction" in dependency_redaction_rc_gate["details"][
            "redactionFailureEvidenceIds"
        ], dependency_redaction_rc_gate
        assert dependency_redaction_rc_gate["details"]["unwaivableFailureEvidenceIds"] == [
            "app-services.dependency-redaction"
        ], dependency_redaction_rc_gate
        dependency_redaction_row = matrix_row_by_id(
            workspace / "build/waived-dependency-redaction-findings-cert",
            "app-service-discovery-and-grants",
        )
        assert dependency_redaction_row["status"] == "fail", dependency_redaction_row
        assert dependency_redaction_row["releaseBlocker"] is True, dependency_redaction_row
        assert "app-services.dependency-redaction" not in dependency_redaction_row.get(
            "waiverIds", []
        ), dependency_redaction_row
        assert dependency_redaction_row["details"]["unwaivableRedactionEvidenceIds"] == [
            "app-services.dependency-redaction"
        ], dependency_redaction_row

        def write_live_network_summary(
            name: str,
            *,
            enabled: bool,
            required: bool,
            statuses: dict[str, str],
            mode: str = "release-candidate",
            kind: str = "live-network-beta-smoke",
        ) -> Path:
            evidence = []
            evidence_statuses = []
            for evidence_id in LIVE_NETWORK_BETA_EVIDENCE_IDS:
                status = statuses.get(evidence_id, "pass")
                evidence_statuses.append(status)
                evidence_enabled = enabled
                if evidence_id == "live-network-beta.app-service-score" and status == "skip":
                    evidence_enabled = False
                evidence.append(
                    {
                        "id": evidence_id,
                        "status": status,
                        "requiredForReleaseCandidate": (
                            required and evidence_id in LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS
                        )
                        or evidence_id == "live-network-beta.redaction",
                        "summary": f"{evidence_id} self-test status is {status}.",
                        "source": "live-network-beta-self-test",
                        "details": {
                            "enabled": evidence_enabled,
                            "required": required,
                            "node": {
                                "baseUrlShape": "http://127.0.0.1:<port>",
                                "localhostOnly": True,
                            },
                            "redaction": {
                                "status": "pass",
                                "forbiddenPatternsChecked": True,
                                "rawBodiesStored": False,
                                "privateInsertUrisStored": False,
                                "localPathsStored": False,
                            },
                            "stepCounts": {"total": len(LIVE_NETWORK_BETA_EVIDENCE_IDS), "passed": 9},
                            "artifactPaths": ["<repo>/build/release-certification/live-network-beta-smoke/summary.json"],
                        },
                    }
                )
            path = workspace / f"build/{name}/summary.json"
            write_json(
                path,
                {
                    "schemaVersion": 1,
                    "kind": kind,
                    "mode": mode,
                    "enabled": enabled,
                    "required": required,
                    "status": aggregate_status_values(evidence_statuses),
                    "node": {
                        "baseUrlShape": "http://127.0.0.1:<port>",
                        "localhostOnly": True,
                        "version": "redacted",
                        "build": "redacted",
                    },
                    "evidence": evidence,
                    "redaction": {
                        "status": "pass",
                        "forbiddenPatternsChecked": True,
                        "rawBodiesStored": False,
                        "privateInsertUrisStored": False,
                        "localPathsStored": False,
                    },
                },
            )
            return path

        candidate_bound_network_soak = read_json(settings.network_scale_soak_summary)
        assert candidate_bound_network_soak is not None
        candidate_bound_network_soak["releaseId"] = "cryptad-beta-self-test"
        safe_candidate_bound_network_soak, candidate_bound_network_soak_errors = (
            allowlisted_network_scale_soak_summary(candidate_bound_network_soak)
        )
        assert candidate_bound_network_soak_errors == [], candidate_bound_network_soak_errors
        assert safe_candidate_bound_network_soak["releaseId"] == "cryptad-beta-self-test", (
            safe_candidate_bound_network_soak
        )

        raw_network_soak = read_json(settings.network_scale_soak_summary)
        assert raw_network_soak is not None
        raw_network_soak["queueHtml"] = "<html>private queue details</html>"
        raw_network_soak["rawFetchedContent"] = "USK@private-fetched-content"
        raw_network_soak["apps"]["social-inbox"]["rawFetchedContent"] = (
            "private social inbox document"
        )
        raw_network_soak["apps"]["feed-reader"]["queueHtml"] = "<html>feed queue</html>"
        raw_network_soak["trustGraph"]["rawStatementBody"] = "raw trust statement body"
        raw_network_soak["redaction"]["rawContent"] = "private redaction field"
        raw_network_soak_path = workspace / "build/network-scale-raw-soak/summary.json"
        write_json(raw_network_soak_path, raw_network_soak)
        raw_network_soak_summary, raw_network_soak_exit_code = run_with_previous(
            "network-scale-raw-soak-cert",
            network_scale_soak_summary=raw_network_soak_path,
        )
        assert raw_network_soak_exit_code == 1, raw_network_soak_summary
        raw_network_soak_item = evidence_by_id(
            raw_network_soak_summary,
            NETWORK_SCALE_SOAK_EVIDENCE_ID,
        )
        assert raw_network_soak_item["status"] == "fail", raw_network_soak_item
        assert any(
            "unsupported fields" in error
            for error in raw_network_soak_item["details"]["errors"]
        ), raw_network_soak_item
        copied_raw_network_soak = read_json(
            workspace
            / "build/network-scale-raw-soak-cert/artifacts/network-scale-soak-summary.json"
        )
        assert copied_raw_network_soak is not None, raw_network_soak_summary
        assert "rawFetchedContent" not in copied_raw_network_soak["apps"]["social-inbox"]
        assert "queueHtml" not in copied_raw_network_soak["apps"]["feed-reader"]
        assert "rawStatementBody" not in copied_raw_network_soak["trustGraph"]
        raw_network_soak_report = (
            workspace / "build/network-scale-raw-soak-cert" / REPORT_FILE_NAME
        ).read_text(encoding="utf-8")
        encoded_raw_network_soak = (
            json.dumps(raw_network_soak_summary, sort_keys=True)
            + json.dumps(copied_raw_network_soak, sort_keys=True)
            + raw_network_soak_report
        )
        for forbidden in (
            "<html>private queue details</html>",
            "private-fetched-content",
            "private social inbox document",
            "<html>feed queue</html>",
            "raw trust statement body",
            "private redaction field",
        ):
            assert forbidden not in encoded_raw_network_soak, encoded_raw_network_soak

        missing_network_redaction_status = read_json(settings.network_scale_soak_summary)
        assert missing_network_redaction_status is not None
        missing_network_redaction_status["redaction"].pop("status", None)
        missing_network_redaction_status_path = (
            workspace / "build/network-scale-missing-redaction-status/summary.json"
        )
        write_json(missing_network_redaction_status_path, missing_network_redaction_status)
        (
            missing_network_redaction_status_summary,
            missing_network_redaction_status_exit_code,
        ) = run_with_previous(
            "network-scale-missing-redaction-status-cert",
            network_scale_soak_summary=missing_network_redaction_status_path,
        )
        assert missing_network_redaction_status_exit_code == 1, (
            missing_network_redaction_status_summary
        )
        missing_network_redaction_status_item = evidence_by_id(
            missing_network_redaction_status_summary,
            NETWORK_SCALE_SOAK_EVIDENCE_ID,
        )
        assert missing_network_redaction_status_item["status"] == "fail", (
            missing_network_redaction_status_item
        )
        assert "redaction.status must be one of the supported values" in (
            missing_network_redaction_status_item["details"]["errors"]
        ), missing_network_redaction_status_item

        fractional_network_soak = read_json(settings.network_scale_soak_summary)
        assert fractional_network_soak is not None
        fractional_network_soak["durationHoursSimulated"] = 24.5
        fractional_network_soak["apps"]["social-inbox"]["pollAttempts"] = -0.1
        fractional_network_soak["trustGraph"]["importsAttempted"] = float("nan")
        fractional_network_soak_path = workspace / "build/network-scale-fractional-soak/summary.json"
        write_json(fractional_network_soak_path, fractional_network_soak)
        fractional_network_soak_summary, fractional_network_soak_exit_code = run_with_previous(
            "network-scale-fractional-soak-cert",
            network_scale_soak_summary=fractional_network_soak_path,
        )
        assert fractional_network_soak_exit_code == 1, fractional_network_soak_summary
        fractional_network_soak_item = evidence_by_id(
            fractional_network_soak_summary,
            NETWORK_SCALE_SOAK_EVIDENCE_ID,
        )
        assert fractional_network_soak_item["status"] == "fail", fractional_network_soak_item
        assert (
            fractional_network_soak_item["details"]["errors"].count(
                "durationHoursSimulated must be an integer"
            )
            == 1
        ), fractional_network_soak_item
        assert (
            "apps.social-inbox.pollAttempts must be an integer"
            in fractional_network_soak_item["details"]["errors"]
        ), fractional_network_soak_item
        assert (
            "trustGraph.importsAttempted must be an integer"
            in fractional_network_soak_item["details"]["errors"]
        ), fractional_network_soak_item
        copied_fractional_network_soak = read_json(
            workspace
            / "build/network-scale-fractional-soak-cert/artifacts/network-scale-soak-summary.json"
        )
        assert copied_fractional_network_soak is not None, fractional_network_soak_summary
        encoded_fractional_network_soak = (
            json.dumps(fractional_network_soak_summary, sort_keys=True)
            + json.dumps(copied_fractional_network_soak, sort_keys=True)
        )
        assert "NaN" not in encoded_fractional_network_soak, encoded_fractional_network_soak
        assert "24.5" not in encoded_fractional_network_soak, encoded_fractional_network_soak
        assert "-0.1" not in encoded_fractional_network_soak, encoded_fractional_network_soak

        live_disabled_evidence = {item["id"]: item for item in summary["evidence"]}
        for evidence_id in LIVE_NETWORK_BETA_EVIDENCE_IDS:
            assert live_disabled_evidence[evidence_id]["status"] == "skip", live_disabled_evidence
            assert live_disabled_evidence[evidence_id]["requiredForReleaseCandidate"] is False, (
                live_disabled_evidence
            )
        disabled_live_gate = gate_by_id(summary, "ecosystem.live-network-beta")
        assert disabled_live_gate["status"] == "pass", disabled_live_gate
        assert disabled_live_gate["releaseBlocker"] is False, disabled_live_gate

        optional_live_path = write_live_network_summary(
            "live-network-optional-failing",
            enabled=True,
            required=False,
            statuses={"live-network-beta.content-fetch": "fail"},
        )
        optional_live_summary, optional_live_exit_code = run_with_previous(
            "live-network-optional-failing-cert",
            live_network_summary=optional_live_path,
            live_network_beta_enabled=True,
        )
        assert optional_live_exit_code == 0, optional_live_summary
        assert optional_live_summary["releaseCandidatePassed"] is True, optional_live_summary
        assert optional_live_summary["promotionDecision"] == "PASS WITH WARNINGS", optional_live_summary
        assert optional_live_summary["ecosystemRcDecision"] == "PASS_WITH_WARNINGS", optional_live_summary
        optional_live_gate = gate_by_id(optional_live_summary, "ecosystem.live-network-beta")
        assert optional_live_gate["status"] == "warn", optional_live_gate
        assert optional_live_gate["releaseBlocker"] is False, optional_live_gate
        optional_live_row = matrix_row_by_id(
            workspace / "build/live-network-optional-failing-cert",
            "live-network-beta-certification",
        )
        assert optional_live_row["status"] == "warn", optional_live_row
        assert optional_live_row["releaseBlocker"] is False, optional_live_row

        optional_missing_live_summary, optional_missing_live_exit_code = run_with_previous(
            "live-network-optional-missing-cert",
            live_network_summary=workspace / "build/missing-live-network-optional/summary.json",
            live_network_beta_enabled=True,
        )
        assert optional_missing_live_exit_code == 0, optional_missing_live_summary
        assert optional_missing_live_summary["releaseCandidatePassed"] is True, (
            optional_missing_live_summary
        )
        assert optional_missing_live_summary["ecosystemRcDecision"] == "PASS_WITH_WARNINGS", (
            optional_missing_live_summary
        )
        optional_missing_rc_gate = gate_by_id(
            optional_missing_live_summary,
            ECOSYSTEM_RC_GATE_ID,
        )
        assert optional_missing_rc_gate["status"] == "warn", optional_missing_rc_gate
        assert optional_missing_rc_gate["releaseBlocker"] is False, optional_missing_rc_gate
        assert optional_missing_rc_gate["details"]["redactionPassed"] is True, optional_missing_rc_gate
        assert "live-network-beta.redaction" not in optional_missing_rc_gate["details"].get(
            "redactionFailureEvidenceIds", []
        ), optional_missing_rc_gate
        optional_missing_live_gate = gate_by_id(
            optional_missing_live_summary,
            "ecosystem.live-network-beta",
        )
        assert optional_missing_live_gate["status"] == "warn", optional_missing_live_gate
        assert optional_missing_live_gate["releaseBlocker"] is False, optional_missing_live_gate
        optional_missing_live_evidence = {
            item["id"]: item for item in optional_missing_live_summary["evidence"]
        }
        assert optional_missing_live_evidence["live-network-beta.redaction"]["status"] == "missing", (
            optional_missing_live_evidence
        )
        assert optional_missing_live_evidence["live-network-beta.redaction"][
            "requiredForReleaseCandidate"
        ] is False

        required_missing_summary, required_missing_exit_code = run_with_previous(
            "live-network-required-missing-cert",
            live_network_summary=workspace / "build/missing-live-network/summary.json",
            live_network_beta_enabled=True,
            live_network_beta_required=True,
        )
        assert required_missing_exit_code == 1, required_missing_summary
        assert required_missing_summary["releaseCandidatePassed"] is False, required_missing_summary
        assert required_missing_summary["ecosystemRcGate"]["status"] == "fail", required_missing_summary
        required_missing_gate = gate_by_id(required_missing_summary, "ecosystem.live-network-beta")
        assert required_missing_gate["status"] == "fail", required_missing_gate
        assert required_missing_gate["releaseBlocker"] is True, required_missing_gate
        required_missing_evidence = {item["id"]: item for item in required_missing_summary["evidence"]}
        for evidence_id in LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS:
            assert required_missing_evidence[evidence_id]["status"] == "missing", required_missing_evidence
            assert required_missing_evidence[evidence_id]["requiredForReleaseCandidate"] is True, (
                required_missing_evidence
            )
        waived_required_missing_live_summary, waived_required_missing_live_exit_code = (
            run_with_previous(
                "live-network-required-missing-row-waived-cert",
                live_network_summary=workspace / "build/missing-live-network-waived/summary.json",
                live_network_beta_enabled=True,
                live_network_beta_required=True,
                waivers={
                    "live-network-beta-certification": (
                        "Release manager accepted temporary missing required live-network beta evidence."
                    )
                },
            )
        )
        assert waived_required_missing_live_exit_code == 0, waived_required_missing_live_summary
        assert waived_required_missing_live_summary["releaseCandidatePassed"] is True, (
            waived_required_missing_live_summary
        )
        assert waived_required_missing_live_summary["promotionDecision"] == "PASS WITH WARNINGS", (
            waived_required_missing_live_summary
        )
        waived_required_missing_live_gate = gate_by_id(
            waived_required_missing_live_summary,
            "ecosystem.live-network-beta",
        )
        assert waived_required_missing_live_gate["status"] == "warn", (
            waived_required_missing_live_gate
        )
        assert waived_required_missing_live_gate["releaseBlocker"] is False, (
            waived_required_missing_live_gate
        )
        waived_required_missing_rc_gate = gate_by_id(
            waived_required_missing_live_summary,
            ECOSYSTEM_RC_GATE_ID,
        )
        assert waived_required_missing_rc_gate["status"] == "warn", (
            waived_required_missing_rc_gate
        )
        assert waived_required_missing_rc_gate["releaseBlocker"] is False, (
            waived_required_missing_rc_gate
        )
        assert waived_required_missing_rc_gate["details"]["liveNetworkSatisfied"] is True, (
            waived_required_missing_rc_gate
        )
        assert set(LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS).issubset(
            set(waived_required_missing_rc_gate["details"]["waivedEvidenceIds"])
        ), waived_required_missing_rc_gate
        waived_required_missing_live_row = matrix_row_by_id(
            workspace / "build/live-network-required-missing-row-waived-cert",
            "live-network-beta-certification",
        )
        assert waived_required_missing_live_row["status"] == "warn", waived_required_missing_live_row
        assert waived_required_missing_live_row["releaseBlocker"] is False, (
            waived_required_missing_live_row
        )

        required_failing_path = write_live_network_summary(
            "live-network-required-failing",
            enabled=True,
            required=True,
            statuses={"live-network-beta.catalog-usk-fetch": "fail"},
        )
        required_failing_summary, required_failing_exit_code = run_with_previous(
            "live-network-required-failing-cert",
            live_network_summary=required_failing_path,
            live_network_beta_enabled=True,
            live_network_beta_required=True,
        )
        assert required_failing_exit_code == 1, required_failing_summary
        assert required_failing_summary["releaseCandidatePassed"] is False, required_failing_summary
        assert required_failing_summary["ecosystemRcGate"]["status"] == "fail", required_failing_summary
        required_failing_gate = gate_by_id(required_failing_summary, "ecosystem.live-network-beta")
        assert required_failing_gate["status"] == "fail", required_failing_gate
        assert required_failing_gate["details"]["failureEvidenceIds"] == [
            "live-network-beta.catalog-usk-fetch"
        ], required_failing_gate
        required_failing_row = matrix_row_by_id(
            workspace / "build/live-network-required-failing-cert",
            "live-network-beta-certification",
        )
        assert required_failing_row["status"] == "fail", required_failing_row
        assert required_failing_row["releaseBlocker"] is True, required_failing_row

        required_passing_path = write_live_network_summary(
            "live-network-required-passing",
            enabled=True,
            required=True,
            statuses={},
        )
        required_passing_summary, required_passing_exit_code = run_with_previous(
            "live-network-required-passing-cert",
            live_network_summary=required_passing_path,
            live_network_beta_enabled=True,
            live_network_beta_required=True,
        )
        assert required_passing_exit_code == 0, required_passing_summary
        assert required_passing_summary["releaseCandidatePassed"] is True, required_passing_summary
        required_passing_gate = gate_by_id(required_passing_summary, "ecosystem.live-network-beta")
        assert required_passing_gate["status"] == "pass", required_passing_gate
        required_passing_evidence = {item["id"]: item for item in required_passing_summary["evidence"]}
        for evidence_id in LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS:
            assert required_passing_evidence[evidence_id]["requiredForReleaseCandidate"] is True, (
                required_passing_evidence
            )
        required_passing_row = matrix_row_by_id(
            workspace / "build/live-network-required-passing-cert",
            "live-network-beta-certification",
        )
        assert required_passing_row["releaseBlocker"] is False, required_passing_row

        required_without_score_path = write_live_network_summary(
            "live-network-required-without-score",
            enabled=True,
            required=True,
            statuses={"live-network-beta.app-service-score": "skip"},
        )
        required_without_score_summary, required_without_score_exit_code = run_with_previous(
            "live-network-required-without-score-cert",
            live_network_summary=required_without_score_path,
            live_network_beta_enabled=True,
            live_network_beta_required=True,
        )
        assert required_without_score_exit_code == 0, required_without_score_summary
        required_without_score_gate = gate_by_id(required_without_score_summary, "ecosystem.live-network-beta")
        assert required_without_score_gate["status"] == "pass", required_without_score_gate
        assert "warningEvidenceIds" not in required_without_score_gate["details"], required_without_score_gate
        required_without_score_row = matrix_row_by_id(
            workspace / "build/live-network-required-without-score-cert",
            "live-network-beta-certification",
        )
        assert required_without_score_row["status"] == "pass", required_without_score_row
        assert required_without_score_row["releaseBlocker"] is False, required_without_score_row

        portal_linked_doc = workspace / "docs/app-owned-ui.md"
        original_portal_linked_doc = portal_linked_doc.read_text(encoding="utf-8")
        try:
            portal_linked_doc.write_text(
                original_portal_linked_doc
                + "\n[Broken docs-only link](missing-docs-only-link.md)\n",
                encoding="utf-8",
            )
            waived_docs_link_summary, waived_docs_link_exit_code = run_with_previous(
                "waived-docs-link-cert",
                waivers={
                    "app-platform.docs-redaction": (
                        "Release manager accepted a temporary docs-only link gap."
                    )
                },
            )
            assert waived_docs_link_exit_code == 0, waived_docs_link_summary
            assert waived_docs_link_summary["releaseCandidatePassed"] is True, waived_docs_link_summary
            waived_docs_link_evidence = {
                item["id"]: item for item in waived_docs_link_summary["evidence"]
            }
            docs_link_evidence = waived_docs_link_evidence["app-platform.docs-redaction"]
            assert docs_link_evidence["status"] == "warn", docs_link_evidence
            assert docs_link_evidence["details"]["waived"] is True, docs_link_evidence
            assert docs_link_evidence["details"]["redactionFindings"] == [], docs_link_evidence
            assert {
                "source": "docs/app-owned-ui.md",
                "target": "missing-docs-only-link.md",
                "reason": "missing",
            } in docs_link_evidence["details"]["brokenLinks"], docs_link_evidence
            waived_docs_link_row_summary, waived_docs_link_row_exit_code = run_with_previous(
                "waived-docs-link-row-cert",
                waivers={
                    "app-platform-beta-docs-and-program": (
                        "Release manager accepted a temporary docs-only row gap."
                    )
                },
            )
            assert waived_docs_link_row_exit_code == 0, waived_docs_link_row_summary
            assert waived_docs_link_row_summary["releaseCandidatePassed"] is True, (
                waived_docs_link_row_summary
            )
            docs_link_row_evidence = {
                item["id"]: item for item in waived_docs_link_row_summary["evidence"]
            }
            docs_link_row_docs_evidence = docs_link_row_evidence["app-platform.docs-redaction"]
            assert docs_link_row_docs_evidence["status"] == "fail", docs_link_row_docs_evidence
            assert docs_link_row_docs_evidence["details"]["redactionFindings"] == [], (
                docs_link_row_docs_evidence
            )
            docs_link_row = matrix_row_by_id(
                workspace / "build/waived-docs-link-row-cert",
                "app-platform-beta-docs-and-program",
            )
            assert docs_link_row["status"] == "warn", docs_link_row
            assert docs_link_row["releaseBlocker"] is False, docs_link_row
            assert "app-platform-beta-docs-and-program" in docs_link_row["waiverIds"], (
                docs_link_row
            )
            docs_link_row_rc_gate = gate_by_id(
                waived_docs_link_row_summary, ECOSYSTEM_RC_GATE_ID
            )
            assert docs_link_row_rc_gate["status"] == "warn", docs_link_row_rc_gate
            assert docs_link_row_rc_gate["releaseBlocker"] is False, docs_link_row_rc_gate
            assert docs_link_row_rc_gate["details"]["redactionPassed"] is True, (
                docs_link_row_rc_gate
            )
            assert "app-platform.docs-redaction" in docs_link_row_rc_gate["details"][
                "waivedEvidenceIds"
            ], docs_link_row_rc_gate
            assert "app-platform.docs-redaction" not in docs_link_row_rc_gate["details"][
                "failedEvidenceIds"
            ], docs_link_row_rc_gate
            assert "app-platform-beta-docs-and-program" in docs_link_row_rc_gate["details"][
                "waiverIds"
            ], docs_link_row_rc_gate

            portal_linked_doc.write_text(
                original_portal_linked_doc
                + "\nAuthorization: Bearer concrete-token-value\n",
                encoding="utf-8",
            )
            waived_docs_redaction_summary, waived_docs_redaction_exit_code = run_with_previous(
                "waived-docs-redaction-cert",
                waivers={
                    "app-platform.docs-redaction": (
                        "Release manager attempted to waive a docs redaction finding."
                    ),
                    "evidence.app-platform.docs-redaction": (
                        "Release manager attempted to waive a docs redaction issue id."
                    ),
                    "app-platform-beta-docs-and-program": (
                        "Release manager attempted to waive a docs redaction row."
                    ),
                },
            )
            assert waived_docs_redaction_exit_code == 1, waived_docs_redaction_summary
            assert (
                waived_docs_redaction_summary["releaseCandidatePassed"] is False
            ), waived_docs_redaction_summary
            docs_redaction_rc_gate = gate_by_id(
                waived_docs_redaction_summary, ECOSYSTEM_RC_GATE_ID
            )
            assert docs_redaction_rc_gate["status"] == "fail", docs_redaction_rc_gate
            assert docs_redaction_rc_gate["releaseBlocker"] is True, docs_redaction_rc_gate
            assert docs_redaction_rc_gate["details"]["redactionPassed"] is False, (
                docs_redaction_rc_gate
            )
            assert "app-platform-beta-docs-and-program" not in docs_redaction_rc_gate[
                "details"
            ].get("waiverIds", []), docs_redaction_rc_gate
            waived_docs_redaction_evidence = {
                item["id"]: item for item in waived_docs_redaction_summary["evidence"]
            }
            docs_redaction_evidence = waived_docs_redaction_evidence[
                "app-platform.docs-redaction"
            ]
            assert docs_redaction_evidence["status"] == "fail", docs_redaction_evidence
            assert "waived" not in docs_redaction_evidence["details"], docs_redaction_evidence
            assert {
                "path": "docs/app-owned-ui.md",
                "issue": "authorization-header",
            } in docs_redaction_evidence["details"]["redactionFindings"], docs_redaction_evidence
            docs_redaction_row = matrix_row_by_id(
                workspace / "build/waived-docs-redaction-cert",
                "app-platform-beta-docs-and-program",
            )
            assert docs_redaction_row["status"] == "fail", docs_redaction_row
            assert docs_redaction_row["releaseBlocker"] is True, docs_redaction_row
            assert "app-platform.docs-redaction" not in docs_redaction_row.get(
                "waiverIds", []
            ), docs_redaction_row
            assert "evidence.app-platform.docs-redaction" not in docs_redaction_row.get(
                "waiverIds", []
            ), docs_redaction_row
            assert "app-platform-beta-docs-and-program" not in docs_redaction_row.get(
                "waiverIds", []
            ), docs_redaction_row
            assert "Waiver recorded" not in docs_redaction_row["summary"], docs_redaction_row
            assert "waived" not in docs_redaction_row["recommendation"].lower(), (
                docs_redaction_row
            )
            assert docs_redaction_row["details"]["unwaivableRedactionEvidenceIds"] == [
                "app-platform.docs-redaction"
            ], docs_redaction_row
            failed_report = (
                workspace / "build/waived-docs-redaction-cert" / REPORT_FILE_NAME
            ).read_text(encoding="utf-8")
            assert "### `app-platform.docs-redaction`" in failed_report, failed_report
            assert "redactionFindings" in failed_report, failed_report
            assert "docs/app-owned-ui.md" in failed_report, failed_report
        finally:
            portal_linked_doc.write_text(original_portal_linked_doc, encoding="utf-8")

        unmapped_required_path = write_app_summary_variant(
            "unmapped-required-evidence",
            lambda value: value.setdefault("evidence", []).append(
                {
                    "id": "self-test.required-unmapped",
                    "status": "pass",
                    "requiredForReleaseCandidate": True,
                    "summary": "Self-test required evidence without a matrix row.",
                    "source": "self-test",
                    "details": {},
                }
            ),
        )
        unmapped_required_summary, unmapped_required_exit_code = run_with_previous(
            "unmapped-required-cert",
            app_platform_summary=unmapped_required_path,
        )
        assert unmapped_required_exit_code == 1, unmapped_required_summary
        unmapped_required_matrix = read_json(workspace / "build/unmapped-required-cert" / ECOSYSTEM_MATRIX_FILE_NAME)
        assert unmapped_required_matrix is not None, unmapped_required_summary
        assert unmapped_required_matrix["coverage"]["requiredEvidenceCovered"] is False, (
            unmapped_required_matrix
        )
        assert unmapped_required_matrix["coverage"]["unmappedRequiredEvidenceIds"] == [
            "self-test.required-unmapped"
        ], unmapped_required_matrix
        assert unmapped_required_matrix["coverage"]["unwaivedIssueIds"] == [
            "matrix.required-evidence-unmapped"
        ], unmapped_required_matrix
        unmapped_required_row = matrix_row_by_id(
            workspace / "build/unmapped-required-cert",
            "ecosystem-certification-matrix",
        )
        assert unmapped_required_row["status"] == "fail", unmapped_required_row
        assert unmapped_required_row["releaseBlocker"] is True, unmapped_required_row

        waived_unmapped_summary, waived_unmapped_exit_code = run_with_previous(
            "waived-unmapped-required-cert",
            app_platform_summary=unmapped_required_path,
            waivers={
                "matrix.required-evidence-unmapped": (
                    "Release manager accepted the temporary matrix row coverage gap."
                )
            },
        )
        assert waived_unmapped_exit_code == 0, waived_unmapped_summary
        assert waived_unmapped_summary["status"] == "warn", waived_unmapped_summary
        assert waived_unmapped_summary["releaseCandidatePassed"] is True, waived_unmapped_summary
        waived_unmapped_matrix = read_json(
            workspace / "build/waived-unmapped-required-cert" / ECOSYSTEM_MATRIX_FILE_NAME
        )
        assert waived_unmapped_matrix is not None, waived_unmapped_summary
        assert waived_unmapped_matrix["status"] == "warn", waived_unmapped_matrix
        assert waived_unmapped_matrix["releaseCandidatePassed"] is True, waived_unmapped_matrix
        assert waived_unmapped_matrix["coverage"]["requiredEvidenceCovered"] is False, (
            waived_unmapped_matrix
        )
        assert waived_unmapped_matrix["coverage"]["waivedIssueIds"] == [
            "matrix.required-evidence-unmapped"
        ], waived_unmapped_matrix
        assert waived_unmapped_matrix["coverage"]["unwaivedIssueIds"] == [], waived_unmapped_matrix
        waived_unmapped_row = matrix_row_by_id(
            workspace / "build/waived-unmapped-required-cert",
            "ecosystem-certification-matrix",
        )
        assert waived_unmapped_row["status"] == "warn", waived_unmapped_row
        assert waived_unmapped_row["releaseBlocker"] is False, waived_unmapped_row
        assert "matrix.required-evidence-unmapped" in waived_unmapped_row["waiverIds"], (
            waived_unmapped_row
        )

        signed_bundles_skip_path = write_app_summary_variant(
            "signed-bundles-skip",
            lambda value: (
                value.update({"mode": "pr"}),
                update_evidence(
                    value,
                    "app-platform.signed-bundles",
                    lambda entry: entry.update(
                        {
                            "status": "skip",
                            "summary": "Signing keys were not available in PR mode.",
                        }
                    ),
                ),
            ),
        )
        signed_bundles_skip_summary, _signed_bundles_skip_exit_code = run_with_previous(
            "signed-bundles-skip-pr-cert",
            mode="pr",
            previous_summary=None,
            app_platform_summary=signed_bundles_skip_path,
        )
        assert signed_bundles_skip_summary["status"] == "warn", signed_bundles_skip_summary
        assert signed_bundles_skip_summary["ecosystemMatrix"]["status"] == "warn", (
            signed_bundles_skip_summary
        )
        assert signed_bundles_skip_summary["ecosystemMatrix"]["releaseBlockerCount"] == 0, (
            signed_bundles_skip_summary
        )
        signed_bundles_skip_row = matrix_row_by_id(
            workspace / "build/signed-bundles-skip-pr-cert",
            "first-party-beta-catalog",
        )
        assert signed_bundles_skip_row["status"] == "warn", signed_bundles_skip_row
        assert signed_bundles_skip_row["releaseBlocker"] is False, signed_bundles_skip_row
        assert "evidence.app-platform.signed-bundles" in signed_bundles_skip_row["issueIds"], (
            signed_bundles_skip_row
        )

        failing_history_path = write_app_summary_variant(
            "write-history-failing-app",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: entry.update({"status": "fail"}),
            ),
        )
        failing_write_history_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/write-history-failing-cert").resolve(),
            previous_summary=previous_good_path,
            app_platform_summary=failing_history_path,
            write_history=True,
            history_dir=history_store,
            history_label="failed-candidate",
        )
        failing_write_history_summary, failing_write_history_exit_code = run(
            failing_write_history_settings
        )
        assert failing_write_history_exit_code == 1, failing_write_history_summary
        assert (
            read_json(history_store / "latest-summary.json") == protected_latest_summary
        ), failing_write_history_summary
        assert (
            history_store / "failed/failed-candidate/release-certification-summary.json"
        ).is_file(), failing_write_history_summary

        require_history_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/require-history-cert").resolve(),
            require_history=True,
        )
        require_history_summary, require_history_exit_code = run(require_history_settings)
        assert require_history_exit_code == 1, require_history_summary
        assert require_history_summary["historyComparison"]["status"] == "fail", require_history_summary

        malformed_previous_path = workspace / "build/malformed-previous/summary.json"
        malformed_previous_path.parent.mkdir(parents=True, exist_ok=True)
        malformed_previous_path.write_text('{"schemaVersion": 1', encoding="utf-8")
        malformed_previous_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/malformed-previous-cert").resolve(),
            previous_summary=malformed_previous_path,
        )
        malformed_previous_summary, malformed_previous_exit_code = run(malformed_previous_settings)
        assert malformed_previous_exit_code == 1, malformed_previous_summary
        assert malformed_previous_summary["historyComparison"]["status"] == "fail", malformed_previous_summary

        invalid_previous_path = workspace / "build/invalid-previous/summary.json"
        write_json(invalid_previous_path, {})
        invalid_previous_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/invalid-previous-cert").resolve(),
            previous_summary=invalid_previous_path,
            require_history=True,
        )
        invalid_previous_summary, invalid_previous_exit_code = run(invalid_previous_settings)
        assert invalid_previous_exit_code == 1, invalid_previous_summary
        assert invalid_previous_summary["historyComparison"]["status"] == "fail", invalid_previous_summary

        previous_candidate_as_history_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/previous-candidate-as-history-cert").resolve(),
            previous_summary=previous_candidate_good_path,
            require_history=True,
        )
        previous_candidate_as_history_summary, previous_candidate_as_history_exit_code = run(
            previous_candidate_as_history_settings
        )
        assert previous_candidate_as_history_exit_code == 1, previous_candidate_as_history_summary
        assert previous_candidate_as_history_summary["historyComparison"]["status"] == "fail", (
            previous_candidate_as_history_summary
        )
        assert "not release-certification history baselines" in previous_candidate_as_history_summary[
            "historyComparison"
        ]["summary"], previous_candidate_as_history_summary

        app_smoke_as_previous_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/app-smoke-as-previous-cert").resolve(),
            previous_summary=settings.app_platform_summary,
            require_history=True,
        )
        app_smoke_as_previous_summary, app_smoke_as_previous_exit_code = run(
            app_smoke_as_previous_settings
        )
        assert app_smoke_as_previous_exit_code == 1, app_smoke_as_previous_summary
        assert (
            app_smoke_as_previous_summary["historyComparison"]["status"] == "fail"
        ), app_smoke_as_previous_summary

        platform_fail_path = write_app_summary_variant(
            "platform-contract-fail",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: entry.update({"status": "fail", "summary": "strict compatibility failed"}),
            ),
        )
        platform_fail_summary, platform_fail_exit_code = run_with_previous(
            "platform-contract-fail-cert", app_platform_summary=platform_fail_path
        )
        assert platform_fail_exit_code == 1, platform_fail_summary
        platform_diff = next(
            diff
            for diff in platform_fail_summary["historyComparison"]["evidenceDiffs"]
            if diff["id"] == "platform-api.contract"
        )
        assert platform_diff["classification"] == "regression", platform_diff
        assert platform_diff["releaseBlocker"] is True, platform_diff
        platform_matrix_row = matrix_row_by_id(
            workspace / "build/platform-contract-fail-cert",
            "platform-api-contract",
        )
        assert platform_matrix_row["status"] == "fail", platform_matrix_row
        assert platform_matrix_row["releaseBlocker"] is True, platform_matrix_row
        platform_fail_with_matrix_summary, platform_fail_with_matrix_exit_code = run_with_previous(
            "platform-contract-fail-with-matrix-cert",
            app_platform_summary=platform_fail_path,
            previous_summary=previous_matrix_good_path,
        )
        assert platform_fail_with_matrix_exit_code == 1, platform_fail_with_matrix_summary
        platform_matrix_regression_row = matrix_row_by_id(
            workspace / "build/platform-contract-fail-with-matrix-cert",
            "platform-api-contract",
        )
        assert platform_matrix_regression_row["previousStatus"] == "pass", platform_matrix_regression_row
        assert platform_matrix_regression_row["regressionStatus"] == "regressed-blocker", (
            platform_matrix_regression_row
        )

        ui_warn_path = write_app_summary_variant(
            "ui-lint-warn",
            lambda value: update_evidence(
                value,
                "app-ui.lint",
                lambda entry: (
                    entry.update({"status": "warn"}),
                    entry.setdefault("details", {})
                    .setdefault("apps", {})
                    .setdefault("queue-manager", {})
                    .setdefault("summary", {})
                    .update({"warnings": 1}),
                ),
            ),
        )
        ui_warn_summary, ui_warn_exit_code = run_with_previous(
            "ui-lint-warn-cert", app_platform_summary=ui_warn_path
        )
        assert ui_warn_exit_code == 0, ui_warn_summary
        assert ui_warn_summary["status"] == "warn", ui_warn_summary
        assert gate_by_id(ui_warn_summary, "ecosystem.app-ui-quality")["status"] == "warn"

        optional_missing_summary, optional_missing_exit_code = run_with_previous(
            "optional-interop-missing-cert",
            interop_extended_summary=workspace / "build/missing-optional-interop/summary.json",
        )
        assert optional_missing_exit_code == 0, optional_missing_summary
        assert optional_missing_summary["status"] == "warn", optional_missing_summary
        optional_diff = next(
            diff
            for diff in optional_missing_summary["historyComparison"]["evidenceDiffs"]
            if diff["id"] == "interop.extended"
        )
        assert optional_diff["classification"] == "regression", optional_diff
        assert optional_diff["releaseBlocker"] is False, optional_diff

        previous_without_rollback = dict(previous_good)
        previous_without_rollback["evidence"] = [
            item for item in previous_good["evidence"] if item["id"] != "app-update.rollback"
        ]
        previous_without_rollback_path = workspace / "build/previous-without-rollback/summary.json"
        write_json(previous_without_rollback_path, previous_without_rollback)
        new_required_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/new-required-cert").resolve(),
            previous_summary=previous_without_rollback_path,
        )
        new_required_summary, new_required_exit_code = run(new_required_settings)
        assert new_required_exit_code == 0, new_required_summary
        new_required_diff = next(
            diff
            for diff in new_required_summary["historyComparison"]["evidenceDiffs"]
            if diff["id"] == "app-update.rollback"
        )
        assert new_required_diff["classification"] == "new", new_required_diff

        previous_with_removed_optional = dict(previous_good)
        previous_with_removed_optional["evidence"] = list(previous_good["evidence"]) + [
            {
                "id": "optional.old-evidence",
                "status": "pass",
                "requiredForReleaseCandidate": False,
                "summary": "Old optional evidence.",
                "source": "<repo>/old.json",
                "details": {},
            }
        ]
        previous_with_removed_optional_path = workspace / "build/previous-with-removed-optional/summary.json"
        write_json(previous_with_removed_optional_path, previous_with_removed_optional)
        removed_optional_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/removed-optional-cert").resolve(),
            previous_summary=previous_with_removed_optional_path,
        )
        removed_optional_summary, removed_optional_exit_code = run(removed_optional_settings)
        assert removed_optional_exit_code == 0, removed_optional_summary
        removed_optional_diff = next(
            diff
            for diff in removed_optional_summary["historyComparison"]["evidenceDiffs"]
            if diff["id"] == "optional.old-evidence"
        )
        assert removed_optional_diff["classification"] == "removed", removed_optional_diff
        assert removed_optional_diff["releaseBlocker"] is False, removed_optional_diff

        previous_with_removed_required = dict(previous_good)
        previous_with_removed_required["evidence"] = list(previous_good["evidence"]) + [
            {
                "id": "required.old-evidence",
                "status": "pass",
                "requiredForReleaseCandidate": True,
                "summary": "Old required evidence.",
                "source": "<repo>/old.json",
                "details": {},
            }
        ]
        previous_with_removed_required_path = workspace / "build/previous-with-removed-required/summary.json"
        write_json(previous_with_removed_required_path, previous_with_removed_required)
        waived_removed_required_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/waived-removed-required-cert").resolve(),
            previous_summary=previous_with_removed_required_path,
            waivers={"required.old-evidence": "Release manager accepted removal of retired required evidence."},
        )
        waived_removed_required_summary, waived_removed_required_exit_code = run(
            waived_removed_required_settings
        )
        assert waived_removed_required_exit_code == 0, waived_removed_required_summary
        removed_required_diff = next(
            diff
            for diff in waived_removed_required_summary["historyComparison"]["evidenceDiffs"]
            if diff["id"] == "required.old-evidence"
        )
        assert removed_required_diff["classification"] == "removed", removed_required_diff
        assert removed_required_diff["releaseBlocker"] is False, removed_required_diff
        assert (
            gate_by_id(
                waived_removed_required_summary, "ecosystem.required-evidence-regressions"
            )["status"]
            == "warn"
        )

        def set_stable_baseline_details(
            entry: dict[str, Any],
            capabilities: list[str],
            endpoints: list[str],
            endpoint_capabilities: dict[str, list[str]] | None = None,
            endpoint_access: dict[str, dict[str, bool]] | None = None,
            endpoint_action_labels: dict[str, str] | None = None,
        ) -> None:
            contract_details = entry.setdefault("details", {})
            contract_details["stableBaseline"] = {
                "name": "1.0",
                "contractVersion": 19,
                "capabilityCount": len(capabilities),
                "endpointCount": len(endpoints),
                "capabilities": capabilities,
                "endpoints": endpoints,
            }
            contract_details["stableBaselineCapabilities"] = capabilities
            contract_details["stableBaselineEndpoints"] = endpoints
            contract_details["stableBaselineCapabilityCount"] = len(capabilities)
            contract_details["stableBaselineEndpointCount"] = len(endpoints)
            contract_details["stableCapabilities"] = capabilities
            contract_details["stableEndpoints"] = endpoints
            if endpoint_capabilities is not None:
                contract_details["stableEndpointRequiredCapabilities"] = endpoint_capabilities
            if endpoint_access is not None:
                contract_details["stableEndpointAppAccess"] = endpoint_access
            contract_details["stableEndpointActionLabels"] = (
                endpoint_action_labels
                if endpoint_action_labels is not None
                else {endpoint: endpoint for endpoint in endpoints}
            )

        previous_pre_freeze_summary = json.loads(json.dumps(previous_good))
        for entry in previous_pre_freeze_summary["evidence"]:
            if entry["id"] == "platform-api.contract":
                contract_details = entry.setdefault("details", {})
                for key in (
                    "stableBaseline",
                    "stableBaselineCapabilities",
                    "stableBaselineEndpoints",
                    "stableBaselineCapabilityCount",
                    "stableBaselineEndpointCount",
                    "stableEndpointRequiredCapabilities",
                    "stableEndpointAppAccess",
                    "stableEndpointActionLabels",
                ):
                    contract_details.pop(key, None)
                contract_details["stableCapabilities"] = [
                    "queue.read",
                    "trust.read",
                    "trust.write",
                ]
                contract_details["stableEndpoints"] = [
                    "GET /queue",
                    "GET /trust-graph/audit",
                    "POST /trust-graph/import-uri",
                ]
                contract_details["stableCapabilityCount"] = 3
                contract_details["stableEndpointCount"] = 3
        previous_pre_freeze_path = workspace / "build/previous-pre-freeze/summary.json"
        write_json(previous_pre_freeze_path, previous_pre_freeze_summary)
        pre_freeze_warning_summary, pre_freeze_warning_exit_code = run_with_previous(
            "pre-freeze-history-warning-cert",
            previous_summary=previous_pre_freeze_path,
        )
        assert pre_freeze_warning_exit_code == 0, pre_freeze_warning_summary
        pre_freeze_warning_platform_gate = gate_by_id(
            pre_freeze_warning_summary, "ecosystem.platform-api-compatibility"
        )
        assert pre_freeze_warning_platform_gate["status"] == "warn", pre_freeze_warning_platform_gate
        assert "failureEvidenceIds" not in pre_freeze_warning_platform_gate["details"], (
            pre_freeze_warning_platform_gate
        )
        assert any(
            "stable baseline comparison is status-limited" in warning
            for warning in pre_freeze_warning_platform_gate["details"].get("warnings", [])
        ), pre_freeze_warning_platform_gate

        pre_freeze_required_history_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/pre-freeze-required-history-cert").resolve(),
            previous_summary=previous_pre_freeze_path,
            require_history=True,
        )
        pre_freeze_required_history_summary, pre_freeze_required_history_exit_code = run(
            pre_freeze_required_history_settings
        )
        assert pre_freeze_required_history_exit_code == 1, pre_freeze_required_history_summary
        pre_freeze_required_platform_gate = gate_by_id(
            pre_freeze_required_history_summary, "ecosystem.platform-api-compatibility"
        )
        assert (
            pre_freeze_required_platform_gate["status"] == "fail"
        ), pre_freeze_required_platform_gate
        assert pre_freeze_required_platform_gate["details"]["failureEvidenceIds"] == [
            "platform-api.previous-contract-snapshot",
            "platform-api.stable-breaking-change-check",
            "platform-api.contract",
        ], pre_freeze_required_platform_gate
        assert pre_freeze_required_platform_gate["details"]["unwaivableFailureEvidenceIds"] == [
            "platform-api.previous-contract-snapshot",
            "platform-api.stable-breaking-change-check",
        ], pre_freeze_required_platform_gate
        assert any(
            "stable baseline comparison is required" in failure
            for failure in pre_freeze_required_platform_gate["details"].get("failures", [])
        ), pre_freeze_required_platform_gate
        assert (
            "warningEvidenceIds" not in pre_freeze_required_platform_gate["details"]
            or "platform-api.stable-breaking-change-check"
            not in pre_freeze_required_platform_gate["details"].get("warningEvidenceIds", [])
        ), pre_freeze_required_platform_gate
        pre_freeze_required_matrix_row = matrix_row_by_id(
            workspace / "build/pre-freeze-required-history-cert",
            "platform-api-contract",
        )
        assert pre_freeze_required_matrix_row["status"] == "fail", (
            pre_freeze_required_matrix_row
        )
        assert pre_freeze_required_matrix_row["releaseBlocker"] is True, (
            pre_freeze_required_matrix_row
        )

        previous_contract_v3 = json.loads(json.dumps(previous_good))
        for entry in previous_contract_v3["evidence"]:
            if entry["id"] == "platform-api.contract":
                entry["details"]["contractVersion"] = 3
                endpoint_capabilities = {
                    "/api/v1/apps/current": ["queue.read"],
                    "/api/v1/apps/old": ["queue.read"],
                }
                endpoint_access = {
                    "/api/v1/apps/current": {
                        "appProcessPrincipalsAllowed": True,
                        "appBrowserPrincipalsAllowed": True,
                    },
                    "/api/v1/apps/old": {
                        "appProcessPrincipalsAllowed": True,
                        "appBrowserPrincipalsAllowed": True,
                    },
                }
                set_stable_baseline_details(
                    entry,
                    ["platform.compat.extra", "queue.read"],
                    ["/api/v1/apps/old", "/api/v1/apps/current"],
                    endpoint_capabilities,
                    endpoint_access,
                )
        previous_contract_v3_path = workspace / "build/previous-contract-v3/summary.json"
        write_json(previous_contract_v3_path, previous_contract_v3)
        current_contract_sets_path = write_app_summary_variant(
            "current-contract-sets",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: entry.setdefault("details", {}).update(
                    {
                        "contractVersion": 2,
                        "stableBaseline": {
                            "name": "1.0",
                            "contractVersion": 19,
                            "capabilityCount": 1,
                            "endpointCount": 1,
                            "capabilities": ["queue.read"],
                            "endpoints": ["/api/v1/apps/current"],
                        },
                        "stableBaselineCapabilities": ["queue.read"],
                        "stableBaselineEndpoints": ["/api/v1/apps/current"],
                        "stableBaselineCapabilityCount": 1,
                        "stableBaselineEndpointCount": 1,
                        "stableEndpointRequiredCapabilities": {
                            "/api/v1/apps/current": ["queue.read"]
                        },
                        "stableEndpointAppAccess": {
                            "/api/v1/apps/current": {
                                "appProcessPrincipalsAllowed": True,
                                "appBrowserPrincipalsAllowed": True,
                            }
                        },
                        "stableEndpointActionLabels": {
                            "/api/v1/apps/current": "apps.current"
                        },
                    }
                ),
            ),
        )
        contract_regression_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/contract-regression-cert").resolve(),
            previous_summary=previous_contract_v3_path,
            app_platform_summary=current_contract_sets_path,
        )
        contract_regression_summary, contract_regression_exit_code = run(contract_regression_settings)
        assert contract_regression_exit_code == 1, contract_regression_summary
        assert gate_by_id(contract_regression_summary, "ecosystem.platform-api-compatibility")["status"] == "fail"

        previous_contract_nonempty_sets = json.loads(json.dumps(previous_good))
        for entry in previous_contract_nonempty_sets["evidence"]:
            if entry["id"] == "platform-api.contract":
                entry["details"]["contractVersion"] = 2
                set_stable_baseline_details(
                    entry,
                    ["queue.read"],
                    ["/api/v1/apps/current"],
                    {
                    "/api/v1/apps/current": ["queue.read"]
                    },
                    {
                    "/api/v1/apps/current": {
                        "appProcessPrincipalsAllowed": True,
                        "appBrowserPrincipalsAllowed": True,
                    }
                    },
                )
        previous_contract_nonempty_sets_path = workspace / "build/previous-contract-nonempty-sets/summary.json"
        write_json(previous_contract_nonempty_sets_path, previous_contract_nonempty_sets)
        current_contract_empty_sets_path = write_app_summary_variant(
            "current-contract-empty-sets",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: entry.setdefault("details", {}).update(
                    {
                        "contractVersion": 2,
                        "stableBaseline": {
                            "name": "1.0",
                            "contractVersion": 19,
                            "capabilityCount": 0,
                            "endpointCount": 0,
                            "capabilities": [],
                            "endpoints": [],
                        },
                        "stableBaselineCapabilities": [],
                        "stableBaselineEndpoints": [],
                        "stableBaselineCapabilityCount": 0,
                        "stableBaselineEndpointCount": 0,
                        "stableEndpointRequiredCapabilities": {},
                        "stableEndpointAppAccess": {},
                        "stableEndpointActionLabels": {},
                    }
                ),
            ),
        )
        empty_sets_regression_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/contract-empty-sets-regression-cert").resolve(),
            previous_summary=previous_contract_nonempty_sets_path,
            app_platform_summary=current_contract_empty_sets_path,
        )
        empty_sets_regression_summary, empty_sets_regression_exit_code = run(
            empty_sets_regression_settings
        )
        assert empty_sets_regression_exit_code == 1, empty_sets_regression_summary
        assert (
            gate_by_id(
                empty_sets_regression_summary, "ecosystem.platform-api-compatibility"
            )["status"]
            == "fail"
        )

        def set_contract_count_details(
            entry: dict[str, Any], capability_count: int, endpoint_count: int, stable_count: int
        ) -> None:
            contract_details = entry.setdefault("details", {})
            contract_details.pop("stableBaseline", None)
            contract_details.pop("stableBaselineCapabilities", None)
            contract_details.pop("stableBaselineEndpoints", None)
            contract_details.pop("stableBaselineCapabilityCount", None)
            contract_details.pop("stableBaselineEndpointCount", None)
            contract_details.pop("stableCapabilities", None)
            contract_details.pop("stableEndpoints", None)
            contract_details.pop("stableEndpointRequiredCapabilities", None)
            contract_details.pop("stableEndpointAppAccess", None)
            contract_details.pop("stableEndpointActionLabels", None)
            contract_details.pop("stableCapabilityCount", None)
            contract_details.pop("stableEndpointCount", None)
            contract_details.update(
                {
                    "contractVersion": 2,
                    "capabilityCount": capability_count,
                    "endpointCount": endpoint_count,
                    "stabilityCounts": {"stable": stable_count},
                }
            )

        previous_contract_total_count_drop = json.loads(json.dumps(previous_good))
        for entry in previous_contract_total_count_drop["evidence"]:
            if entry["id"] == "platform-api.contract":
                set_contract_count_details(entry, 20, 80, 75)
        previous_contract_total_count_drop_path = (
            workspace / "build/previous-contract-total-count-drop/summary.json"
        )
        write_json(previous_contract_total_count_drop_path, previous_contract_total_count_drop)
        current_contract_total_count_drop_path = write_app_summary_variant(
            "current-contract-total-count-drop",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: set_contract_count_details(entry, 19, 79, 75),
            ),
        )
        total_count_drop_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/contract-total-count-drop-cert").resolve(),
            previous_summary=previous_contract_total_count_drop_path,
            app_platform_summary=current_contract_total_count_drop_path,
        )
        total_count_drop_summary, total_count_drop_exit_code = run(total_count_drop_settings)
        assert total_count_drop_exit_code == 0, total_count_drop_summary
        assert (
            gate_by_id(total_count_drop_summary, "ecosystem.platform-api-compatibility")["status"]
            == "pass"
        )

        current_contract_stable_count_drop_path = write_app_summary_variant(
            "current-contract-stable-count-drop",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: set_contract_count_details(entry, 19, 79, 74),
            ),
        )
        stable_count_drop_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/contract-stable-count-drop-cert").resolve(),
            previous_summary=previous_contract_total_count_drop_path,
            app_platform_summary=current_contract_stable_count_drop_path,
        )
        stable_count_drop_summary, stable_count_drop_exit_code = run(stable_count_drop_settings)
        assert stable_count_drop_exit_code == 1, stable_count_drop_summary
        assert (
            gate_by_id(stable_count_drop_summary, "ecosystem.platform-api-compatibility")["status"]
            == "fail"
        )

        previous_contract_endpoint_caps = json.loads(json.dumps(previous_good))
        for entry in previous_contract_endpoint_caps["evidence"]:
            if entry["id"] == "platform-api.contract":
                entry["details"]["contractVersion"] = 2
                entry["details"]["stableEndpointRequiredCapabilities"] = entry["details"].get(
                    "stableEndpointRequiredCapabilities", {}
                ) | {"GET /queue": ["queue.read"]}
                entry["details"]["stableEndpointAppAccess"] = entry["details"].get(
                    "stableEndpointAppAccess", {}
                ) | {
                    "GET /queue": {
                        "appProcessPrincipalsAllowed": True,
                        "appBrowserPrincipalsAllowed": True,
                    }
                }
        previous_contract_endpoint_caps_path = workspace / "build/previous-contract-endpoint-caps/summary.json"
        write_json(previous_contract_endpoint_caps_path, previous_contract_endpoint_caps)
        current_contract_endpoint_caps_path = write_app_summary_variant(
            "current-contract-endpoint-caps",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: entry.setdefault("details", {}).update(
                    {
                        "contractVersion": 2,
                        "stableEndpointRequiredCapabilities": entry.setdefault("details", {})
                        .get("stableEndpointRequiredCapabilities", {})
                        | {"GET /queue": ["queue.write"]},
                        "stableEndpointAppAccess": entry.setdefault("details", {}).get(
                            "stableEndpointAppAccess", {}
                        )
                        | {
                            "GET /queue": {
                                "appProcessPrincipalsAllowed": True,
                                "appBrowserPrincipalsAllowed": True,
                            }
                        },
                    }
                ),
            ),
        )
        endpoint_capability_regression_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/contract-endpoint-capability-regression-cert").resolve(),
            previous_summary=previous_contract_endpoint_caps_path,
            app_platform_summary=current_contract_endpoint_caps_path,
        )
        endpoint_capability_regression_summary, endpoint_capability_regression_exit_code = run(
            endpoint_capability_regression_settings
        )
        assert endpoint_capability_regression_exit_code == 1, endpoint_capability_regression_summary
        endpoint_capability_regression_gate = gate_by_id(
            endpoint_capability_regression_summary, "ecosystem.platform-api-compatibility"
        )
        assert endpoint_capability_regression_gate["status"] == "fail", endpoint_capability_regression_gate
        assert (
            "GET /queue"
            in endpoint_capability_regression_gate["details"]["stableEndpointCapabilityChanges"][0]["endpoint"]
        ), endpoint_capability_regression_gate
        assert endpoint_capability_regression_gate["details"]["unwaivableFailureEvidenceIds"] == [
            "platform-api.stable-breaking-change-check"
        ], endpoint_capability_regression_gate

        current_contract_endpoint_caps_missing_path = write_app_summary_variant(
            "current-contract-endpoint-caps-missing",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: entry.setdefault("details", {}).update(
                    {
                        "contractVersion": 2,
                        "stableEndpointRequiredCapabilities": {
                            endpoint: capabilities
                            for endpoint, capabilities in entry.setdefault("details", {})
                            .get("stableEndpointRequiredCapabilities", {})
                            .items()
                            if endpoint != "GET /queue"
                        },
                    }
                ),
            ),
        )
        endpoint_capability_missing_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/contract-endpoint-capability-missing-cert").resolve(),
            previous_summary=previous_contract_endpoint_caps_path,
            app_platform_summary=current_contract_endpoint_caps_missing_path,
        )
        endpoint_capability_missing_summary, endpoint_capability_missing_exit_code = run(
            endpoint_capability_missing_settings
        )
        assert endpoint_capability_missing_exit_code == 1, endpoint_capability_missing_summary
        endpoint_capability_missing_gate = gate_by_id(
            endpoint_capability_missing_summary, "ecosystem.platform-api-compatibility"
        )
        assert endpoint_capability_missing_gate["status"] == "fail", (
            endpoint_capability_missing_gate
        )
        assert endpoint_capability_missing_gate["details"][
            "stableEndpointRequiredCapabilitiesMissing"
        ] == ["GET /queue"], endpoint_capability_missing_gate
        assert endpoint_capability_missing_gate["details"]["unwaivableFailureEvidenceIds"] == [
            "platform-api.stable-breaking-change-check"
        ], endpoint_capability_missing_gate

        previous_contract_endpoint_access = json.loads(json.dumps(previous_good))
        for entry in previous_contract_endpoint_access["evidence"]:
            if entry["id"] == "platform-api.contract":
                entry["details"]["contractVersion"] = 2
                entry["details"]["stableEndpointRequiredCapabilities"] = entry["details"].get(
                    "stableEndpointRequiredCapabilities", {}
                ) | {"GET /queue": ["queue.read"]}
                entry["details"]["stableEndpointAppAccess"] = entry["details"].get(
                    "stableEndpointAppAccess", {}
                ) | {
                    "GET /queue": {
                        "appProcessPrincipalsAllowed": True,
                        "appBrowserPrincipalsAllowed": True,
                    }
                }
        previous_contract_endpoint_access_path = workspace / "build/previous-contract-endpoint-access/summary.json"
        write_json(previous_contract_endpoint_access_path, previous_contract_endpoint_access)
        current_contract_endpoint_access_path = write_app_summary_variant(
            "current-contract-endpoint-access",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: entry.setdefault("details", {}).update(
                    {
                        "contractVersion": 2,
                        "stableEndpointRequiredCapabilities": entry.setdefault("details", {})
                        .get("stableEndpointRequiredCapabilities", {})
                        | {"GET /queue": ["queue.read"]},
                        "stableEndpointAppAccess": entry.setdefault("details", {}).get(
                            "stableEndpointAppAccess", {}
                        )
                        | {
                            "GET /queue": {
                                "appProcessPrincipalsAllowed": False,
                                "appBrowserPrincipalsAllowed": True,
                            }
                        },
                    }
                ),
            ),
        )
        endpoint_access_regression_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/contract-endpoint-access-regression-cert").resolve(),
            previous_summary=previous_contract_endpoint_access_path,
            app_platform_summary=current_contract_endpoint_access_path,
        )
        endpoint_access_regression_summary, endpoint_access_regression_exit_code = run(
            endpoint_access_regression_settings
        )
        assert endpoint_access_regression_exit_code == 1, endpoint_access_regression_summary
        endpoint_access_regression_gate = gate_by_id(
            endpoint_access_regression_summary, "ecosystem.platform-api-compatibility"
        )
        assert endpoint_access_regression_gate["status"] == "fail", endpoint_access_regression_gate
        assert (
            "GET /queue"
            in endpoint_access_regression_gate["details"]["stableEndpointAccessChanges"][0]["endpoint"]
        ), endpoint_access_regression_gate
        assert (
            endpoint_access_regression_gate["details"]["stableEndpointAccessChanges"][0]["current"][
                "appProcessPrincipalsAllowed"
            ]
            is False
        ), endpoint_access_regression_gate
        assert endpoint_access_regression_gate["details"]["unwaivableFailureEvidenceIds"] == [
            "platform-api.stable-breaking-change-check"
        ], endpoint_access_regression_gate

        current_contract_endpoint_access_missing_path = write_app_summary_variant(
            "current-contract-endpoint-access-missing",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: entry.setdefault("details", {}).update(
                    {
                        "contractVersion": 2,
                        "stableEndpointAppAccess": {
                            endpoint: access
                            for endpoint, access in entry.setdefault("details", {})
                            .get("stableEndpointAppAccess", {})
                            .items()
                            if endpoint != "GET /queue"
                        },
                    }
                ),
            ),
        )
        endpoint_access_missing_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/contract-endpoint-access-missing-cert").resolve(),
            previous_summary=previous_contract_endpoint_access_path,
            app_platform_summary=current_contract_endpoint_access_missing_path,
        )
        endpoint_access_missing_summary, endpoint_access_missing_exit_code = run(
            endpoint_access_missing_settings
        )
        assert endpoint_access_missing_exit_code == 1, endpoint_access_missing_summary
        endpoint_access_missing_gate = gate_by_id(
            endpoint_access_missing_summary, "ecosystem.platform-api-compatibility"
        )
        assert endpoint_access_missing_gate["status"] == "fail", endpoint_access_missing_gate
        assert endpoint_access_missing_gate["details"]["stableEndpointAppAccessMissing"] == [
            "GET /queue"
        ], endpoint_access_missing_gate
        assert endpoint_access_missing_gate["details"]["unwaivableFailureEvidenceIds"] == [
            "platform-api.stable-breaking-change-check"
        ], endpoint_access_missing_gate

        previous_contract_endpoint_labels = json.loads(json.dumps(previous_good))
        for entry in previous_contract_endpoint_labels["evidence"]:
            if entry["id"] == "platform-api.contract":
                entry["details"]["contractVersion"] = 2
                entry["details"]["stableEndpointActionLabels"]["GET /queue"] = "queue.read"
        previous_contract_endpoint_labels_path = (
            workspace / "build/previous-contract-endpoint-labels/summary.json"
        )
        write_json(previous_contract_endpoint_labels_path, previous_contract_endpoint_labels)
        current_contract_endpoint_labels_path = write_app_summary_variant(
            "current-contract-endpoint-labels",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: entry.setdefault("details", {}).update(
                    {
                        "contractVersion": 2,
                        "stableEndpointActionLabels": (
                            entry.setdefault("details", {}).get("stableEndpointActionLabels", {})
                            | {"GET /queue": "queue.read.changed"}
                        ),
                    }
                ),
            ),
        )
        endpoint_label_regression_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/contract-endpoint-label-regression-cert").resolve(),
            previous_summary=previous_contract_endpoint_labels_path,
            app_platform_summary=current_contract_endpoint_labels_path,
        )
        endpoint_label_regression_summary, endpoint_label_regression_exit_code = run(
            endpoint_label_regression_settings
        )
        assert endpoint_label_regression_exit_code == 1, endpoint_label_regression_summary
        endpoint_label_regression_gate = gate_by_id(
            endpoint_label_regression_summary, "ecosystem.platform-api-compatibility"
        )
        assert endpoint_label_regression_gate["status"] == "fail", endpoint_label_regression_gate
        assert (
            "GET /queue"
            in endpoint_label_regression_gate["details"]["stableEndpointActionLabelChanges"][0][
                "endpoint"
            ]
        ), endpoint_label_regression_gate
        assert (
            endpoint_label_regression_gate["details"]["stableEndpointActionLabelChanges"][0][
                "current"
            ]
            == "queue.read.changed"
        ), endpoint_label_regression_gate
        assert endpoint_label_regression_gate["details"]["unwaivableFailureEvidenceIds"] == [
            "platform-api.stable-breaking-change-check"
        ], endpoint_label_regression_gate

        current_contract_endpoint_labels_missing_path = write_app_summary_variant(
            "current-contract-endpoint-labels-missing",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: entry.setdefault("details", {}).update(
                    {
                        "contractVersion": 2,
                        "stableEndpointActionLabels": {
                            endpoint: label
                            for endpoint, label in entry.setdefault("details", {})
                            .get("stableEndpointActionLabels", {})
                            .items()
                            if endpoint != "GET /queue"
                        },
                    }
                ),
            ),
        )
        endpoint_label_missing_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/contract-endpoint-label-missing-cert").resolve(),
            previous_summary=previous_contract_endpoint_labels_path,
            app_platform_summary=current_contract_endpoint_labels_missing_path,
        )
        endpoint_label_missing_summary, endpoint_label_missing_exit_code = run(
            endpoint_label_missing_settings
        )
        assert endpoint_label_missing_exit_code == 1, endpoint_label_missing_summary
        endpoint_label_missing_gate = gate_by_id(
            endpoint_label_missing_summary, "ecosystem.platform-api-compatibility"
        )
        assert endpoint_label_missing_gate["status"] == "fail", endpoint_label_missing_gate
        assert endpoint_label_missing_gate["details"]["stableEndpointActionLabelsMissing"] == [
            "GET /queue"
        ], endpoint_label_missing_gate
        assert endpoint_label_missing_gate["details"]["unwaivableFailureEvidenceIds"] == [
            "platform-api.stable-breaking-change-check"
        ], endpoint_label_missing_gate

        concrete_baseline_endpoints = ["GET /apps/current", "GET /apps/old"]
        concrete_endpoint_capabilities = {
            "GET /apps/current": ["queue.read"],
            "GET /apps/old": ["queue.read"],
        }
        concrete_endpoint_access = {
            "GET /apps/current": {
                "appProcessPrincipalsAllowed": True,
                "appBrowserPrincipalsAllowed": True,
            },
            "GET /apps/old": {
                "appProcessPrincipalsAllowed": True,
                "appBrowserPrincipalsAllowed": True,
            },
        }
        concrete_endpoint_labels = {
            "GET /apps/current": "apps.current",
            "GET /apps/old": "apps.old",
        }

        previous_concrete_endpoint_metadata = json.loads(json.dumps(previous_good))
        for entry in previous_concrete_endpoint_metadata["evidence"]:
            if entry["id"] == "platform-api.contract":
                entry["details"]["contractVersion"] = 2
                set_stable_baseline_details(
                    entry,
                    ["queue.read"],
                    concrete_baseline_endpoints,
                    concrete_endpoint_capabilities,
                    concrete_endpoint_access,
                    concrete_endpoint_labels,
                )
        previous_concrete_endpoint_metadata_path = (
            workspace / "build/previous-concrete-endpoint-metadata/summary.json"
        )
        write_json(previous_concrete_endpoint_metadata_path, previous_concrete_endpoint_metadata)

        def write_current_concrete_endpoint_metadata(
            name: str,
            endpoint_capabilities: dict[str, list[str]],
            endpoint_access: dict[str, dict[str, bool]],
            endpoint_labels: dict[str, str],
        ) -> Path:
            def update_contract(entry: dict[str, Any]) -> None:
                entry.setdefault("details", {})["contractVersion"] = 2
                set_stable_baseline_details(
                    entry,
                    ["queue.read"],
                    concrete_baseline_endpoints,
                    endpoint_capabilities,
                    endpoint_access,
                    endpoint_labels,
                )

            return write_app_summary_variant(
                name,
                lambda value: update_evidence(
                    value, "platform-api.contract", update_contract
                ),
            )

        padded_endpoint_capability_path = write_current_concrete_endpoint_metadata(
            "current-padded-endpoint-capabilities",
            {
                "GET /apps/current": ["queue.read"],
                "GET /apps/extra": ["queue.read"],
            },
            concrete_endpoint_access,
            concrete_endpoint_labels,
        )
        padded_endpoint_capability_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/padded-endpoint-capability-cert").resolve(),
            previous_summary=previous_concrete_endpoint_metadata_path,
            app_platform_summary=padded_endpoint_capability_path,
        )
        padded_endpoint_capability_summary, padded_endpoint_capability_exit_code = run(
            padded_endpoint_capability_settings
        )
        assert padded_endpoint_capability_exit_code == 1, padded_endpoint_capability_summary
        padded_endpoint_capability_gate = gate_by_id(
            padded_endpoint_capability_summary, "ecosystem.platform-api-compatibility"
        )
        assert padded_endpoint_capability_gate["status"] == "fail", (
            padded_endpoint_capability_gate
        )
        assert padded_endpoint_capability_gate["details"][
            "stableEndpointRequiredCapabilitiesMissing"
        ] == ["GET /apps/old"], padded_endpoint_capability_gate

        padded_endpoint_access_path = write_current_concrete_endpoint_metadata(
            "current-padded-endpoint-access",
            concrete_endpoint_capabilities,
            {
                "GET /apps/current": {
                    "appProcessPrincipalsAllowed": True,
                    "appBrowserPrincipalsAllowed": True,
                },
                "GET /apps/extra": {
                    "appProcessPrincipalsAllowed": True,
                    "appBrowserPrincipalsAllowed": True,
                },
            },
            concrete_endpoint_labels,
        )
        padded_endpoint_access_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/padded-endpoint-access-cert").resolve(),
            previous_summary=previous_concrete_endpoint_metadata_path,
            app_platform_summary=padded_endpoint_access_path,
        )
        padded_endpoint_access_summary, padded_endpoint_access_exit_code = run(
            padded_endpoint_access_settings
        )
        assert padded_endpoint_access_exit_code == 1, padded_endpoint_access_summary
        padded_endpoint_access_gate = gate_by_id(
            padded_endpoint_access_summary, "ecosystem.platform-api-compatibility"
        )
        assert padded_endpoint_access_gate["status"] == "fail", padded_endpoint_access_gate
        assert padded_endpoint_access_gate["details"]["stableEndpointAppAccessMissing"] == [
            "GET /apps/old"
        ], padded_endpoint_access_gate

        padded_endpoint_labels_path = write_current_concrete_endpoint_metadata(
            "current-padded-endpoint-labels",
            concrete_endpoint_capabilities,
            concrete_endpoint_access,
            {
                "GET /apps/current": "apps.current",
                "GET /apps/extra": "apps.extra",
            },
        )
        padded_endpoint_label_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/padded-endpoint-label-cert").resolve(),
            previous_summary=previous_concrete_endpoint_metadata_path,
            app_platform_summary=padded_endpoint_labels_path,
        )
        padded_endpoint_label_summary, padded_endpoint_label_exit_code = run(
            padded_endpoint_label_settings
        )
        assert padded_endpoint_label_exit_code == 1, padded_endpoint_label_summary
        padded_endpoint_label_gate = gate_by_id(
            padded_endpoint_label_summary, "ecosystem.platform-api-compatibility"
        )
        assert padded_endpoint_label_gate["status"] == "fail", padded_endpoint_label_gate
        assert padded_endpoint_label_gate["details"]["stableEndpointActionLabelsMissing"] == [
            "GET /apps/old"
        ], padded_endpoint_label_gate

        current_contract_endpoint_labels_unavailable_path = write_app_summary_variant(
            "current-contract-endpoint-labels-unavailable",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: entry.setdefault("details", {}).pop(
                    "stableEndpointActionLabels", None
                ),
            ),
        )
        endpoint_label_unavailable_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/contract-endpoint-label-unavailable-cert").resolve(),
            previous_summary=previous_contract_endpoint_labels_path,
            app_platform_summary=current_contract_endpoint_labels_unavailable_path,
            waivers={
                "ecosystem.platform-api-compatibility": (
                    "Release manager attempted to waive missing current action-label metadata."
                ),
                "platform-api.stable-breaking-change-check": (
                    "Release manager attempted to waive missing current action-label metadata."
                ),
            },
        )
        endpoint_label_unavailable_summary, endpoint_label_unavailable_exit_code = run(
            endpoint_label_unavailable_settings
        )
        assert endpoint_label_unavailable_exit_code == 1, endpoint_label_unavailable_summary
        endpoint_label_unavailable_gate = gate_by_id(
            endpoint_label_unavailable_summary, "ecosystem.platform-api-compatibility"
        )
        assert endpoint_label_unavailable_gate["status"] == "fail", (
            endpoint_label_unavailable_gate
        )
        assert "waived" not in endpoint_label_unavailable_gate["details"], (
            endpoint_label_unavailable_gate
        )
        assert endpoint_label_unavailable_gate["details"]["unwaivableFailureEvidenceIds"] == [
            "platform-api.stable-breaking-change-check"
        ], endpoint_label_unavailable_gate
        assert any(
            "action-label metadata is unavailable" in failure
            for failure in endpoint_label_unavailable_gate["details"].get("failures", [])
        ), endpoint_label_unavailable_gate

        previous_contract_endpoint_labels_unavailable = json.loads(
            json.dumps(previous_contract_endpoint_labels)
        )
        for entry in previous_contract_endpoint_labels_unavailable["evidence"]:
            if entry["id"] == "platform-api.contract":
                entry["details"].pop("stableEndpointActionLabels", None)
        previous_contract_endpoint_labels_unavailable_path = (
            workspace / "build/previous-contract-endpoint-labels-unavailable/summary.json"
        )
        write_json(
            previous_contract_endpoint_labels_unavailable_path,
            previous_contract_endpoint_labels_unavailable,
        )
        previous_label_unavailable_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/previous-endpoint-label-unavailable-cert").resolve(),
            previous_summary=previous_contract_endpoint_labels_unavailable_path,
            require_history=True,
            waivers={
                "ecosystem.platform-api-compatibility": (
                    "Release manager attempted to waive missing previous action-label metadata."
                ),
                "platform-api.stable-breaking-change-check": (
                    "Release manager attempted to waive missing previous action-label metadata."
                ),
            },
        )
        previous_label_unavailable_summary, previous_label_unavailable_exit_code = run(
            previous_label_unavailable_settings
        )
        assert previous_label_unavailable_exit_code == 1, previous_label_unavailable_summary
        previous_label_unavailable_gate = gate_by_id(
            previous_label_unavailable_summary, "ecosystem.platform-api-compatibility"
        )
        assert previous_label_unavailable_gate["status"] == "fail", (
            previous_label_unavailable_gate
        )
        assert "waived" not in previous_label_unavailable_gate["details"], (
            previous_label_unavailable_gate
        )
        assert previous_label_unavailable_gate["details"]["unwaivableFailureEvidenceIds"] == [
            "platform-api.stable-breaking-change-check"
        ], previous_label_unavailable_gate
        assert any(
            "Previous stable endpoint action-label metadata is unavailable" in failure
            for failure in previous_label_unavailable_gate["details"].get("failures", [])
        ), previous_label_unavailable_gate

        def set_contract_raw_endpoint_details(
            entry: dict[str, Any], routes: list[str], stable_count: int
        ) -> None:
            contract_details = entry.setdefault("details", {})
            contract_details.pop("stableBaseline", None)
            contract_details.pop("stableBaselineCapabilities", None)
            contract_details.pop("stableBaselineEndpoints", None)
            contract_details.pop("stableBaselineCapabilityCount", None)
            contract_details.pop("stableBaselineEndpointCount", None)
            contract_details.pop("stableEndpoints", None)
            contract_details.pop("stableEndpointRequiredCapabilities", None)
            contract_details.pop("stableEndpointAppAccess", None)
            contract_details.pop("stableEndpointActionLabels", None)
            contract_details.update(
                {
                    "contractVersion": 2,
                    "endpointCount": len(routes),
                    "stabilityCounts": {"stable": stable_count},
                    "endpoints": [
                        {
                            "method": "GET",
                            "routeTemplate": route,
                            "actionLabel": route,
                            "stability": "stable",
                            "appProcessPrincipalsAllowed": True,
                            "appBrowserPrincipalsAllowed": True,
                        }
                        for route in routes
                    ],
                }
            )

        previous_contract_raw_endpoints = json.loads(json.dumps(previous_good))
        for entry in previous_contract_raw_endpoints["evidence"]:
            if entry["id"] == "platform-api.contract":
                set_contract_raw_endpoint_details(
                    entry,
                    ["/apps/{appId}/old", "/apps/{appId}/current"],
                    2,
                )
        previous_contract_raw_endpoints_path = workspace / "build/previous-contract-raw-endpoints/summary.json"
        write_json(previous_contract_raw_endpoints_path, previous_contract_raw_endpoints)
        current_contract_raw_endpoint_removal_path = write_app_summary_variant(
            "current-contract-raw-endpoint-removal",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: set_contract_raw_endpoint_details(
                    entry,
                    ["/apps/{appId}/current", "/apps/{appId}/new"],
                    2,
                ),
            ),
        )
        raw_endpoint_removal_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/contract-raw-endpoint-removal-cert").resolve(),
            previous_summary=previous_contract_raw_endpoints_path,
            app_platform_summary=current_contract_raw_endpoint_removal_path,
        )
        raw_endpoint_removal_summary, raw_endpoint_removal_exit_code = run(
            raw_endpoint_removal_settings
        )
        assert raw_endpoint_removal_exit_code == 1, raw_endpoint_removal_summary
        raw_endpoint_removal_gate = gate_by_id(
            raw_endpoint_removal_summary, "ecosystem.platform-api-compatibility"
        )
        assert raw_endpoint_removal_gate["status"] == "fail", raw_endpoint_removal_gate
        assert "GET /apps/{appId}/old" in raw_endpoint_removal_gate["summary"], raw_endpoint_removal_gate

        first_party_apps_map_path = write_app_summary_variant(
            "first-party-apps-map",
            lambda value: update_evidence(
                value,
                "app-platform.first-party",
                lambda entry: entry.setdefault("details", {}).update(
                    {
                        "apps": {
                            "queue-manager": {},
                            "publisher": {},
                            "site-publisher": {},
                            "profile-publisher": {},
                            "feed-reader": {},
                            "social-inbox": {},
                            "trust-graph": {},
                        }
                    }
                ),
            ),
        )
        first_party_apps_map_summary, first_party_apps_map_exit_code = run_with_previous(
            "first-party-apps-map-cert", app_platform_summary=first_party_apps_map_path
        )
        assert first_party_apps_map_exit_code == 0, first_party_apps_map_summary
        assert gate_by_id(first_party_apps_map_summary, "ecosystem.first-party-apps")["status"] == "pass"

        first_party_missing_path = write_app_summary_variant(
            "first-party-missing",
            lambda value: update_evidence(
                value,
                "app-platform.first-party",
                lambda entry: entry.setdefault("details", {}).update({"apps": ["queue-manager", "publisher"]}),
            ),
        )
        first_party_missing_summary, first_party_missing_exit_code = run_with_previous(
            "first-party-missing-cert", app_platform_summary=first_party_missing_path
        )
        assert first_party_missing_exit_code == 1, first_party_missing_summary
        assert gate_by_id(first_party_missing_summary, "ecosystem.first-party-apps")["status"] == "fail"

        reference_missing_path = write_app_summary_variant(
            "reference-missing",
            lambda value: update_evidence(
                value,
                "reference-apps.content",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        reference_missing_summary, reference_missing_exit_code = run_with_previous(
            "reference-missing-cert", app_platform_summary=reference_missing_path
        )
        assert reference_missing_exit_code == 1, reference_missing_summary
        assert gate_by_id(reference_missing_summary, "ecosystem.reference-content-apps")["status"] == "fail"

        feed_reader_missing_path = write_app_summary_variant(
            "feed-reader-missing",
            lambda value: update_evidence(
                value,
                "reference-app.feed-reader",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        feed_reader_missing_summary, feed_reader_missing_exit_code = run_with_previous(
            "feed-reader-missing-cert", app_platform_summary=feed_reader_missing_path
        )
        assert feed_reader_missing_exit_code == 1, feed_reader_missing_summary
        assert (
            gate_by_id(feed_reader_missing_summary, "ecosystem.reference-content-apps")["status"]
            == "fail"
        )

        feed_reader_subscription_missing_path = write_app_summary_variant(
            "feed-reader-subscriptions-missing",
            lambda value: update_evidence(
                value,
                "reference-app.feed-reader-subscriptions",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        feed_reader_subscription_missing_summary, feed_reader_subscription_missing_exit_code = (
            run_with_previous(
                "feed-reader-subscriptions-missing-cert",
                app_platform_summary=feed_reader_subscription_missing_path,
            )
        )
        assert (
            feed_reader_subscription_missing_exit_code == 1
        ), feed_reader_subscription_missing_summary
        assert (
            gate_by_id(
                feed_reader_subscription_missing_summary, "ecosystem.reference-content-apps"
            )["status"]
            == "fail"
        )

        trust_graph_missing_path = write_app_summary_variant(
            "trust-graph-missing",
            lambda value: update_evidence(
                value,
                "reference-app.trust-graph",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        trust_graph_missing_summary, trust_graph_missing_exit_code = run_with_previous(
            "trust-graph-missing-cert", app_platform_summary=trust_graph_missing_path
        )
        assert trust_graph_missing_exit_code == 1, trust_graph_missing_summary
        assert (
            gate_by_id(trust_graph_missing_summary, "ecosystem.reference-content-apps")[
                "status"
            ]
            == "fail"
        )

        content_fetch_missing_path = write_app_summary_variant(
            "content-fetch-missing",
            lambda value: update_evidence(
                value,
                "app-platform.content-fetch",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        content_fetch_missing_summary, content_fetch_missing_exit_code = run_with_previous(
            "content-fetch-missing-cert", app_platform_summary=content_fetch_missing_path
        )
        assert content_fetch_missing_exit_code == 1, content_fetch_missing_summary
        assert (
            gate_by_id(content_fetch_missing_summary, "ecosystem.reference-content-apps")[
                "status"
            ]
            == "fail"
        )

        content_subscription_missing_path = write_app_summary_variant(
            "content-subscriptions-missing",
            lambda value: update_evidence(
                value,
                "app-platform.content-subscriptions",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        content_subscription_missing_summary, content_subscription_missing_exit_code = (
            run_with_previous(
                "content-subscriptions-missing-cert",
                app_platform_summary=content_subscription_missing_path,
            )
        )
        assert content_subscription_missing_exit_code == 1, content_subscription_missing_summary
        assert (
            gate_by_id(
                content_subscription_missing_summary, "ecosystem.reference-content-apps"
            )["status"]
            == "fail"
        )

        subscription_scheduler_missing_path = write_app_summary_variant(
            "subscription-scheduler-missing",
            lambda value: update_evidence(
                value,
                "network-content.subscription-scheduler",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        subscription_scheduler_missing_summary, subscription_scheduler_missing_exit_code = (
            run_with_previous(
                "subscription-scheduler-missing-cert",
                app_platform_summary=subscription_scheduler_missing_path,
            )
        )
        assert (
            subscription_scheduler_missing_exit_code == 1
        ), subscription_scheduler_missing_summary
        assert (
            gate_by_id(
                subscription_scheduler_missing_summary, "ecosystem.reference-content-apps"
            )["status"]
            == "fail"
        )

        trust_preview_missing_path = write_app_summary_variant(
            "trust-preview-missing",
            lambda value: update_evidence(
                value,
                "app-platform.trust-graph-preview",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        trust_preview_missing_summary, trust_preview_missing_exit_code = run_with_previous(
            "trust-preview-missing-cert", app_platform_summary=trust_preview_missing_path
        )
        assert trust_preview_missing_exit_code == 1, trust_preview_missing_summary
        assert (
            gate_by_id(trust_preview_missing_summary, "ecosystem.reference-content-apps")[
                "status"
            ]
            == "fail"
        )

        trust_signing_missing_path = write_app_summary_variant(
            "trust-signing-missing",
            lambda value: update_evidence(
                value,
                "app-platform.trust-statement-signing",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        trust_signing_missing_summary, trust_signing_missing_exit_code = run_with_previous(
            "trust-signing-missing-cert", app_platform_summary=trust_signing_missing_path
        )
        assert trust_signing_missing_exit_code == 1, trust_signing_missing_summary
        assert (
            gate_by_id(trust_signing_missing_summary, "ecosystem.reference-content-apps")[
                "status"
            ]
            == "fail"
        )

        social_inbox_missing_path = write_app_summary_variant(
            "social-inbox-missing",
            lambda value: update_evidence(
                value,
                "reference-app.social-inbox",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        social_inbox_missing_summary, social_inbox_missing_exit_code = run_with_previous(
            "social-inbox-missing-cert", app_platform_summary=social_inbox_missing_path
        )
        assert social_inbox_missing_exit_code == 1, social_inbox_missing_summary
        assert (
            gate_by_id(social_inbox_missing_summary, "ecosystem.reference-content-apps")[
                "status"
            ]
            == "fail"
        )

        social_message_signing_missing_path = write_app_summary_variant(
            "social-message-signing-missing",
            lambda value: update_evidence(
                value,
                "app-platform.social-message-signing",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        social_message_signing_missing_summary, social_message_signing_missing_exit_code = (
            run_with_previous(
                "social-message-signing-missing-cert",
                app_platform_summary=social_message_signing_missing_path,
            )
        )
        assert social_message_signing_missing_exit_code == 1, (
            social_message_signing_missing_summary
        )
        assert (
            gate_by_id(social_message_signing_missing_summary, "ecosystem.reference-content-apps")[
                "status"
            ]
            == "fail"
        )

        trusted_review_fail_path = write_app_summary_variant(
            "trusted-review-fail",
            lambda value: update_evidence(
                value,
                "app-review.trusted-receipts",
                lambda entry: entry.update({"status": "fail"}),
            ),
        )
        trusted_review_fail_summary, trusted_review_fail_exit_code = run_with_previous(
            "trusted-review-fail-cert", app_platform_summary=trusted_review_fail_path
        )
        assert trusted_review_fail_exit_code == 1, trusted_review_fail_summary
        assert (
            gate_by_id(trusted_review_fail_summary, "ecosystem.app-review-trust")["status"]
            == "fail"
        )

        missing_review_governance_ids = {
            "app-review.governance",
            "app-review.reviewer-key-lifecycle",
            "app-review.transparency-log",
            "app-review.review-history-api",
            "app-review.first-party-review-chain",
        }
        missing_review_governance_path = write_app_summary_variant(
            "missing-review-governance",
            lambda value: value.update(
                {
                    "evidence": [
                        item
                        for item in value["evidence"]
                        if item.get("id") not in missing_review_governance_ids
                    ]
                }
            ),
        )
        missing_review_governance_items = app_platform_evidence(
            missing_review_governance_path, workspace, out_dir, "release-candidate"
        )
        missing_review_governance_by_id = {
            item.id: item for item in missing_review_governance_items
        }
        for evidence_id in missing_review_governance_ids:
            assert (
                missing_review_governance_by_id[evidence_id].status == "missing"
            ), missing_review_governance_by_id
        (
            missing_review_governance_summary,
            missing_review_governance_exit_code,
        ) = run_with_previous(
            "missing-review-governance-cert",
            app_platform_summary=missing_review_governance_path,
        )
        assert missing_review_governance_exit_code == 1, missing_review_governance_summary
        missing_review_governance_gate = gate_by_id(
            missing_review_governance_summary, "ecosystem.app-review-trust"
        )
        assert (
            missing_review_governance_gate["status"] == "fail"
        ), missing_review_governance_gate
        for evidence_id in missing_review_governance_ids:
            assert (
                evidence_id in missing_review_governance_gate["details"]["failureEvidenceIds"]
            ), missing_review_governance_gate

        rollback_fail_path = write_app_summary_variant(
            "rollback-fail",
            lambda value: update_evidence(
                value,
                "app-update.rollback",
                lambda entry: entry.update({"status": "fail"}),
            ),
        )
        rollback_fail_summary, rollback_fail_exit_code = run_with_previous(
            "rollback-fail-cert", app_platform_summary=rollback_fail_path
        )
        assert rollback_fail_exit_code == 1, rollback_fail_summary
        assert gate_by_id(rollback_fail_summary, "ecosystem.app-update-rollback")["status"] == "fail"

        scheduler_fail_path = write_app_summary_variant(
            "scheduler-fail",
            lambda value: update_evidence(
                value,
                "app-update.scheduler",
                lambda entry: entry.update({"status": "fail"}),
            ),
        )
        scheduler_fail_summary, scheduler_fail_exit_code = run_with_previous(
            "scheduler-fail-cert", app_platform_summary=scheduler_fail_path
        )
        assert scheduler_fail_exit_code == 1, scheduler_fail_summary
        assert gate_by_id(scheduler_fail_summary, "ecosystem.app-update-rollback")["status"] == "fail"

        vault_missing_capability_path = write_app_summary_variant(
            "vault-missing-capability",
            lambda value: update_evidence(
                value,
                "app-vault.capabilities",
                lambda entry: entry.setdefault("details", {}).update({"capabilities": ["vault.secrets.read"]}),
            ),
        )
        vault_missing_capability_summary, vault_missing_capability_exit_code = run_with_previous(
            "vault-missing-capability-cert", app_platform_summary=vault_missing_capability_path
        )
        assert vault_missing_capability_exit_code == 1, vault_missing_capability_summary
        assert gate_by_id(vault_missing_capability_summary, "ecosystem.app-vault")["status"] == "fail"
        waived_vault_evidence_summary, waived_vault_evidence_exit_code = run_with_previous(
            "waived-vault-evidence-cert",
            app_platform_summary=vault_missing_capability_path,
            waivers={"app-vault.capabilities": "Release manager accepted vault evidence gap."},
        )
        assert waived_vault_evidence_exit_code == 0, waived_vault_evidence_summary
        waived_vault_gate = gate_by_id(waived_vault_evidence_summary, "ecosystem.app-vault")
        assert waived_vault_gate["status"] == "warn", waived_vault_gate
        assert waived_vault_gate["releaseBlocker"] is False, waived_vault_gate
        assert waived_vault_gate["details"]["waived"] is True, waived_vault_gate
        assert waived_vault_gate["details"]["waivedEvidenceIds"] == ["app-vault.capabilities"], waived_vault_gate
        waived_vault_row = matrix_row_by_id(
            workspace / "build/waived-vault-evidence-cert",
            "app-vault-and-generated-documents",
        )
        assert waived_vault_row["status"] == "warn", waived_vault_row
        assert waived_vault_row["releaseBlocker"] is False, waived_vault_row
        assert "app-vault.capabilities" in waived_vault_row["waiverIds"], waived_vault_row
        waived_vault_clean_summary, waived_vault_clean_exit_code = run_with_previous(
            "waived-vault-clean-history-cert",
            app_platform_summary=vault_missing_capability_path,
            previous_summary=previous_matrix_good_path,
            waivers={"app-vault.capabilities": "Release manager accepted vault evidence gap."},
        )
        assert waived_vault_clean_exit_code == 0, waived_vault_clean_summary
        assert waived_vault_clean_summary["status"] == "warn", waived_vault_clean_summary
        assert waived_vault_clean_summary["promotionDecision"] == "PASS WITH WARNINGS", (
            waived_vault_clean_summary
        )
        assert waived_vault_clean_summary["releaseCandidatePassed"] is True, (
            waived_vault_clean_summary
        )
        assert waived_vault_clean_summary["ecosystemRcGate"]["status"] == "warn", (
            waived_vault_clean_summary
        )
        assert waived_vault_clean_summary["ecosystemRcGate"]["waiverCount"] == 1, (
            waived_vault_clean_summary
        )
        waived_vault_rc_row = matrix_row_by_id(
            workspace / "build/waived-vault-clean-history-cert",
            ECOSYSTEM_RC_MATRIX_ROW_ID,
        )
        assert waived_vault_rc_row["status"] == "warn", waived_vault_rc_row
        assert waived_vault_rc_row["releaseBlocker"] is False, waived_vault_rc_row
        assert "app-vault.capabilities" in waived_vault_rc_row["waiverIds"], waived_vault_rc_row

        vault_missing_redaction_path = write_app_summary_variant(
            "vault-missing-redaction",
            lambda value: update_evidence(
                value,
                "app-vault.capabilities",
                lambda entry: entry.setdefault("details", {}).pop("redaction", None),
            ),
        )
        vault_missing_redaction_summary, vault_missing_redaction_exit_code = run_with_previous(
            "vault-missing-redaction-cert", app_platform_summary=vault_missing_redaction_path
        )
        assert vault_missing_redaction_exit_code == 1, vault_missing_redaction_summary
        assert gate_by_id(vault_missing_redaction_summary, "ecosystem.app-vault")["status"] == "fail"

        sandbox_best_effort_path = write_app_summary_variant(
            "sandbox-best-effort",
            lambda value: update_evidence(
                value,
                "apphost.sandbox-provider",
                lambda entry: entry.setdefault("details", {}).update({"supportLevel": "best-effort"}),
            ),
        )
        sandbox_best_effort_summary, sandbox_best_effort_exit_code = run_with_previous(
            "sandbox-best-effort-cert", app_platform_summary=sandbox_best_effort_path
        )
        assert sandbox_best_effort_exit_code == 1, sandbox_best_effort_summary
        assert gate_by_id(sandbox_best_effort_summary, "ecosystem.sandbox-provider")["status"] == "fail"
        waived_sandbox_evidence_summary, waived_sandbox_evidence_exit_code = run_with_previous(
            "waived-sandbox-evidence-cert",
            app_platform_summary=sandbox_best_effort_path,
            waivers={"apphost.sandbox-provider": "Release manager accepted sandbox provider gap."},
        )
        assert waived_sandbox_evidence_exit_code == 0, waived_sandbox_evidence_summary
        waived_sandbox_evidence_gate = gate_by_id(
            waived_sandbox_evidence_summary, "ecosystem.sandbox-provider"
        )
        assert waived_sandbox_evidence_gate["status"] == "warn", waived_sandbox_evidence_gate
        assert waived_sandbox_evidence_gate["releaseBlocker"] is False, waived_sandbox_evidence_gate
        assert waived_sandbox_evidence_gate["details"]["waived"] is True, waived_sandbox_evidence_gate
        assert waived_sandbox_evidence_gate["details"]["waivedEvidenceIds"] == [
            "apphost.sandbox-provider"
        ], waived_sandbox_evidence_gate

        legacy_removed_path = write_app_summary_variant(
            "legacy-wave-removed",
            lambda value: value.update(
                {
                    "evidence": [
                        entry
                        for entry in value["evidence"]
                        if entry.get("id") != "legacy-admin.removal-wave-1"
                    ]
                }
            ),
        )
        legacy_removed_summary, legacy_removed_exit_code = run_with_previous(
            "legacy-wave-removed-cert", app_platform_summary=legacy_removed_path
        )
        assert legacy_removed_exit_code == 1, legacy_removed_summary
        assert gate_by_id(legacy_removed_summary, "ecosystem.legacy-retirement")["status"] == "fail"

        legacy_wave_two_removed_path = write_app_summary_variant(
            "legacy-wave-two-removed",
            lambda value: value.update(
                {
                    "evidence": [
                        entry
                        for entry in value["evidence"]
                        if entry.get("id") != "legacy-admin.removal-wave-2"
                    ]
                }
            ),
        )
        legacy_wave_two_removed_summary, legacy_wave_two_removed_exit_code = run_with_previous(
            "legacy-wave-two-removed-cert", app_platform_summary=legacy_wave_two_removed_path
        )
        assert legacy_wave_two_removed_exit_code == 1, legacy_wave_two_removed_summary
        assert (
            gate_by_id(legacy_wave_two_removed_summary, "ecosystem.legacy-retirement")["status"]
            == "fail"
        )

        legacy_wave_three_removed_path = write_app_summary_variant(
            "legacy-wave-three-removed",
            lambda value: value.update(
                {
                    "evidence": [
                        entry
                        for entry in value["evidence"]
                        if entry.get("id") != "legacy-admin.removal-wave-3"
                    ]
                }
            ),
        )
        legacy_wave_three_removed_summary, legacy_wave_three_removed_exit_code = (
            run_with_previous(
                "legacy-wave-three-removed-cert",
                app_platform_summary=legacy_wave_three_removed_path,
            )
        )
        assert legacy_wave_three_removed_exit_code == 1, legacy_wave_three_removed_summary
        assert (
            gate_by_id(legacy_wave_three_removed_summary, "ecosystem.legacy-retirement")["status"]
            == "fail"
        )

        legacy_wave_four_removed_path = write_app_summary_variant(
            "legacy-wave-four-removed",
            lambda value: value.update(
                {
                    "evidence": [
                        entry
                        for entry in value["evidence"]
                        if entry.get("id") != "legacy-admin.removal-wave-4"
                    ]
                }
            ),
        )
        legacy_wave_four_removed_summary, legacy_wave_four_removed_exit_code = run_with_previous(
            "legacy-wave-four-removed-cert",
            app_platform_summary=legacy_wave_four_removed_path,
        )
        assert legacy_wave_four_removed_exit_code == 1, legacy_wave_four_removed_summary
        assert (
            gate_by_id(legacy_wave_four_removed_summary, "ecosystem.legacy-retirement")["status"]
            == "fail"
        )

        legacy_wave_five_removed_path = write_app_summary_variant(
            "legacy-wave-five-removed",
            lambda value: value.update(
                {
                    "evidence": [
                        entry
                        for entry in value["evidence"]
                        if entry.get("id") != "legacy-admin.removal-wave-5"
                    ]
                }
            ),
        )
        legacy_wave_five_removed_summary, legacy_wave_five_removed_exit_code = run_with_previous(
            "legacy-wave-five-removed-cert",
            app_platform_summary=legacy_wave_five_removed_path,
        )
        assert legacy_wave_five_removed_exit_code == 1, legacy_wave_five_removed_summary
        assert (
            gate_by_id(legacy_wave_five_removed_summary, "ecosystem.legacy-retirement")["status"]
            == "fail"
        )

        waiver_file_path = workspace / "docs/release-waivers/self-test.json"
        write_json(
            waiver_file_path,
            {
                "version": 1,
                "release": "self-test",
                "waivers": [
                    {
                        "id": "ecosystem.sandbox-provider",
                        "evidenceId": "ecosystem.sandbox-provider",
                        "status": "approved",
                        "approvedBy": "release-manager",
                        "reason": f"token=hunter2 accepted for fixture {workspace}/secret",
                        "expiresAt": "2099-01-01T00:00:00Z",
                        "allowReleaseCandidate": True,
                    }
                ],
            },
        )
        waived_sandbox_summary, waived_sandbox_exit_code = run_with_previous(
            "waived-sandbox-cert",
            app_platform_summary=sandbox_best_effort_path,
            waiver_files=(waiver_file_path,),
        )
        assert waived_sandbox_exit_code == 0, waived_sandbox_summary
        assert waived_sandbox_summary["status"] == "warn", waived_sandbox_summary
        assert waived_sandbox_summary["waivers"] == {}, waived_sandbox_summary
        assert len(waived_sandbox_summary["waiverRecords"]) == 1, waived_sandbox_summary
        waived_sandbox_gate = gate_by_id(waived_sandbox_summary, "ecosystem.sandbox-provider")
        assert waived_sandbox_gate["status"] == "warn", waived_sandbox_gate
        assert waived_sandbox_gate["details"]["waived"] is True, waived_sandbox_gate
        waived_report = (workspace / "build/waived-sandbox-cert" / REPORT_FILE_NAME).read_text(
            encoding="utf-8"
        )
        waived_encoded = json.dumps(waived_sandbox_summary, sort_keys=True) + waived_report
        for forbidden in ("hunter2", str(workspace)):
            assert forbidden not in waived_encoded, f"structured waiver leaked {forbidden}"

        dashboard_waiver_file_path = workspace / "docs/release-waivers/dashboard-schema.json"
        write_json(
            dashboard_waiver_file_path,
            {
                "schemaVersion": 1,
                "releaseId": "self-test",
                "waivers": [
                    {
                        "id": "waiver-ecosystem-sandbox-provider-dashboard-schema",
                        "evidenceId": "ecosystem.sandbox-provider",
                        "severity": "blocker",
                        "scope": "release-candidate",
                        "rationale": "Release manager accepted the sandbox provider evidence gap.",
                        "approvedBy": "release-manager",
                        "owner": "release-engineering",
                        "createdAt": "2026-06-24T00:00:00Z",
                        "expiresAt": "2099-01-01T00:00:00Z",
                        "references": ["self-test"],
                    }
                ],
            },
        )
        dashboard_waived_summary, dashboard_waived_exit_code = run_with_previous(
            "dashboard-waiver-schema-cert",
            app_platform_summary=sandbox_best_effort_path,
            waiver_files=(dashboard_waiver_file_path,),
        )
        assert dashboard_waived_exit_code == 0, dashboard_waived_summary
        assert dashboard_waived_summary["status"] == "warn", dashboard_waived_summary
        assert len(dashboard_waived_summary["waiverRecords"]) == 1, dashboard_waived_summary
        dashboard_waived_record = dashboard_waived_summary["waiverRecords"][0]
        assert dashboard_waived_record["allowReleaseCandidate"] is True, dashboard_waived_record
        assert dashboard_waived_record["reason"] == (
            "Release manager accepted the sandbox provider evidence gap."
        ), dashboard_waived_record
        dashboard_waived_gate = gate_by_id(dashboard_waived_summary, "ecosystem.sandbox-provider")
        assert dashboard_waived_gate["status"] == "warn", dashboard_waived_gate
        assert dashboard_waived_gate["details"]["waived"] is True, dashboard_waived_gate

        malformed_rc_waiver_file_path = workspace / "docs/release-waivers/nonboolean.json"
        write_json(
            malformed_rc_waiver_file_path,
            {
                "version": 1,
                "waivers": [
                    {
                        "id": "ecosystem.sandbox-provider",
                        "evidenceId": "ecosystem.sandbox-provider",
                        "status": "approved",
                        "approvedBy": "release-manager",
                        "reason": "Malformed release-candidate flag.",
                        "expiresAt": "2099-01-01T00:00:00Z",
                        "allowReleaseCandidate": "false",
                    }
                ],
            },
        )
        malformed_rc_waiver_summary, malformed_rc_waiver_exit_code = run_with_previous(
            "malformed-rc-waiver-cert",
            app_platform_summary=sandbox_best_effort_path,
            waiver_files=(malformed_rc_waiver_file_path,),
        )
        assert malformed_rc_waiver_exit_code == 1, malformed_rc_waiver_summary
        assert gate_by_id(malformed_rc_waiver_summary, "ecosystem.waivers")["status"] == "fail"
        malformed_sandbox_gate = gate_by_id(
            malformed_rc_waiver_summary, "ecosystem.sandbox-provider"
        )
        assert malformed_sandbox_gate["status"] == "fail", malformed_sandbox_gate
        assert "waived" not in malformed_sandbox_gate["details"], malformed_sandbox_gate

        malformed_waiver_redaction_file_path = workspace / "docs/release-waivers/redaction.json"
        write_json(
            malformed_waiver_redaction_file_path,
            {
                "version": 1,
                "waivers": [
                    {
                        "id": "ecosystem.sandbox-provider",
                        "evidenceId": "ecosystem.sandbox-provider",
                        "status": f"token=hunter2 {workspace}/status",
                        "approvedBy": "release-manager",
                        "reason": "Malformed status and expiry should remain sanitized.",
                        "expiresAt": f"token=expires-secret {workspace}/expires",
                        "allowReleaseCandidate": True,
                    }
                ],
            },
        )
        malformed_waiver_redaction_summary, malformed_waiver_redaction_exit_code = run_with_previous(
            "malformed-waiver-redaction-cert",
            app_platform_summary=sandbox_best_effort_path,
            waiver_files=(malformed_waiver_redaction_file_path,),
        )
        assert malformed_waiver_redaction_exit_code == 1, malformed_waiver_redaction_summary
        malformed_waiver_redaction_report = (
            workspace / "build/malformed-waiver-redaction-cert" / REPORT_FILE_NAME
        ).read_text(encoding="utf-8")
        malformed_waiver_redaction_encoded = (
            json.dumps(malformed_waiver_redaction_summary, sort_keys=True)
            + malformed_waiver_redaction_report
        )
        for forbidden in ("hunter2", "expires-secret", str(workspace)):
            assert (
                forbidden not in malformed_waiver_redaction_encoded
            ), f"malformed waiver leaked {forbidden}"

        expired_waiver_file_path = workspace / "docs/release-waivers/expired.json"
        write_json(
            expired_waiver_file_path,
            {
                "version": 1,
                "waivers": [
                    {
                        "id": "ecosystem.sandbox-provider",
                        "evidenceId": "ecosystem.sandbox-provider",
                        "status": "approved",
                        "approvedBy": "release-manager",
                        "reason": "Expired waiver.",
                        "expiresAt": "2000-01-01T00:00:00Z",
                        "allowReleaseCandidate": True,
                    }
                ],
            },
        )
        expired_waiver_summary, expired_waiver_exit_code = run_with_previous(
            "expired-waiver-cert",
            app_platform_summary=sandbox_best_effort_path,
            waiver_files=(expired_waiver_file_path,),
        )
        assert expired_waiver_exit_code == 1, expired_waiver_summary
        assert gate_by_id(expired_waiver_summary, "ecosystem.waivers")["status"] == "fail"
        wrong_mode_extended = interop_evidence(
            "interop.extended",
            settings.interop_smoke_summary,
            False,
            "extended",
            workspace,
            out_dir,
        )
        assert wrong_mode_extended.status == "warn", wrong_mode_extended
        assert wrong_mode_extended.details["expectedMode"] == "extended", wrong_mode_extended
        assert wrong_mode_extended.details["mode"] == "smoke", wrong_mode_extended
        assert wrong_mode_extended.details["modeMatches"] is False, wrong_mode_extended

        missing_extended_flow_path = workspace / "build/interop-extended-missing-flow/summary.json"
        missing_extended_flow = read_json(settings.interop_extended_summary)
        assert missing_extended_flow is not None
        missing_extended_flow["flows"].pop("persistent_request_replay", None)
        write_json(missing_extended_flow_path, missing_extended_flow)
        missing_extended_flow_item = interop_evidence(
            "interop.extended",
            missing_extended_flow_path,
            False,
            "extended",
            workspace,
            out_dir,
        )
        assert missing_extended_flow_item.status == "warn", missing_extended_flow_item
        assert "persistent_request_replay" in missing_extended_flow_item.details["missingRequiredFlows"]

        collect_perf_path = workspace / "build/perf-collect/summary.json"
        collect_perf = read_json(settings.perf_smoke_summary)
        assert collect_perf is not None
        collect_perf["mode"] = "collect"
        collect_perf["status"] = "warning"
        write_json(collect_perf_path, collect_perf)
        collect_perf_item = perf_evidence(collect_perf_path, True, workspace, out_dir)
        assert collect_perf_item.status == "fail", collect_perf_item
        assert collect_perf_item.details["expectedMode"] == "smoke", collect_perf_item
        assert collect_perf_item.details["mode"] == "collect", collect_perf_item
        assert collect_perf_item.details["modeMatches"] is False, collect_perf_item
        collect_perf_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/collect-perf-cert").resolve(),
            perf_smoke_summary=collect_perf_path,
        )
        collect_perf_summary, collect_perf_exit_code = run(collect_perf_settings)
        assert collect_perf_exit_code == 1, collect_perf_summary
        assert collect_perf_summary["status"] == "fail", collect_perf_summary
        assert collect_perf_summary["releaseCandidatePassed"] is False, collect_perf_summary

        pr_app_summary_path = workspace / "build/app-platform-pr/summary.json"
        pr_app_summary = read_json(settings.app_platform_summary)
        assert pr_app_summary is not None
        pr_app_summary["mode"] = "pr"
        pr_app_summary["status"] = "warn"
        write_json(pr_app_summary_path, pr_app_summary)
        pr_app_items = app_platform_evidence(pr_app_summary_path, workspace, out_dir, "release-candidate")
        assert all(
            item.status == "fail" for item in pr_app_items if item.required_for_release_candidate
        ), pr_app_items
        assert pr_app_items[0].details["expectedMode"] == "release-candidate", pr_app_items
        assert pr_app_items[0].details["mode"] == "pr", pr_app_items
        assert pr_app_items[0].details["modeMatches"] is False, pr_app_items
        pr_app_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/pr-app-cert").resolve(),
            app_platform_summary=pr_app_summary_path,
        )
        pr_app_cert_summary, pr_app_exit_code = run(pr_app_settings)
        assert pr_app_exit_code == 1, pr_app_cert_summary
        assert pr_app_cert_summary["status"] == "fail", pr_app_cert_summary
        assert pr_app_cert_summary["releaseCandidatePassed"] is False, pr_app_cert_summary

        missing_update_evidence_path = workspace / "build/app-platform-missing-update/summary.json"
        missing_update_summary = read_json(settings.app_platform_summary)
        assert missing_update_summary is not None
        missing_update_summary["evidence"] = [
            item
            for item in missing_update_summary["evidence"]
            if item.get("id")
            not in {
                "app-update.lifecycle",
                "app-update.scheduler",
                "app-update.rollback",
                "app-update.data-migration-contract",
            }
        ]
        write_json(missing_update_evidence_path, missing_update_summary)
        missing_update_items = app_platform_evidence(
            missing_update_evidence_path, workspace, out_dir, "release-candidate"
        )
        missing_update_by_id = {item.id: item for item in missing_update_items}
        assert missing_update_by_id["app-update.lifecycle"].status == "missing", missing_update_by_id
        assert missing_update_by_id["app-update.scheduler"].status == "missing", missing_update_by_id
        assert missing_update_by_id["app-update.rollback"].status == "missing", missing_update_by_id
        assert (
            missing_update_by_id["app-update.data-migration-contract"].status == "missing"
        ), missing_update_by_id
        missing_update_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/missing-update-cert").resolve(),
            app_platform_summary=missing_update_evidence_path,
        )
        missing_update_cert_summary, missing_update_exit_code = run(missing_update_settings)
        assert missing_update_exit_code == 1, missing_update_cert_summary
        assert missing_update_cert_summary["status"] == "fail", missing_update_cert_summary
        assert missing_update_cert_summary["releaseCandidatePassed"] is False, missing_update_cert_summary
        missing_update_row = matrix_row_by_id(workspace / "build/missing-update-cert", "app-update")
        assert missing_update_row["status"] == "fail", missing_update_row
        assert missing_update_row["releaseBlocker"] is True, missing_update_row

        stale_artifact = out_dir / "artifacts/stale-from-previous-run.txt"
        stale_artifact.write_text("old evidence\n", encoding="utf-8")
        rerun_summary, rerun_exit_code = run(settings)
        assert rerun_exit_code == 0, rerun_summary
        assert not stale_artifact.exists(), stale_artifact
        assert "stale-from-previous-run.txt" not in json.dumps(rerun_summary, sort_keys=True)
        repo_tmp_path = workspace / "build/tmp-release-certification/release-certification-summary.json"
        assert (
            scrub_text(str(repo_tmp_path), workspace, out_dir)
            == "<repo>/build/tmp-release-certification/release-certification-summary.json"
        )
        with tempfile.TemporaryDirectory(prefix="cryptad-cert-symlink-target-") as target_name:
            with tempfile.TemporaryDirectory(prefix="cryptad-cert-symlink-parent-") as link_parent_name:
                symlink_root = Path(link_parent_name) / "repo-link"
                try:
                    symlink_root.symlink_to(Path(target_name), target_is_directory=True)
                except (NotImplementedError, OSError):
                    symlink_root = None
                if symlink_root is not None:
                    symlink_workspace = symlink_root / "repo"
                    symlink_out_dir = symlink_workspace / "build/release-certification"
                    symlink_path = (
                        symlink_workspace / "build/tmp-release-certification/release-certification-summary.json"
                    )
                    assert (
                        scrub_text(str(symlink_path), symlink_workspace, symlink_out_dir)
                        == "<repo>/build/tmp-release-certification/release-certification-summary.json"
                    )
        assert (
            normalize_redacted_separators(r"<repo>\build\tmp-release-certification\release-certification-summary.json")
            == "<repo>/build/tmp-release-certification/release-certification-summary.json"
        )
        windows_scrubbed = scrub_text(
            r"keys at D:\release\signing.pem and \\builder\share\certs\catalog.pem",
            workspace,
            out_dir,
        )
        assert r"D:\release" not in windows_scrubbed, windows_scrubbed
        assert r"\\builder\share" not in windows_scrubbed, windows_scrubbed
        assert "<path>/signing.pem" in windows_scrubbed, windows_scrubbed
        assert "<path>/catalog.pem" in windows_scrubbed, windows_scrubbed
        file_uri_scrubbed = scrub_text(
            "metadata file:///home/alice/signing/key.pem file:///D:/keys/catalog.pem",
            workspace,
            out_dir,
        )
        assert "/home/alice/signing" not in file_uri_scrubbed, file_uri_scrubbed
        assert "D:/keys" not in file_uri_scrubbed, file_uri_scrubbed
        assert "file://<path>/key.pem" in file_uri_scrubbed, file_uri_scrubbed
        assert "file://<path>/catalog.pem" in file_uri_scrubbed, file_uri_scrubbed
        route_scrubbed = scrub_text(
            "/apps/install /apps/cert-smoke/runtime /api/v1/diagnostics "
            "/mnt/secrets/signing/key.pem",
            workspace,
            out_dir,
        )
        assert "/apps/install" in route_scrubbed, route_scrubbed
        assert "/apps/cert-smoke/runtime" in route_scrubbed, route_scrubbed
        assert "/api/v1/diagnostics" in route_scrubbed, route_scrubbed
        assert "/mnt/secrets/signing/key.pem" not in route_scrubbed, route_scrubbed
        assert "<path>/key.pem" in route_scrubbed, route_scrubbed
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
            workspace,
            out_dir,
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
                "capabilities": [
                    "vault.secrets.read",
                    "vault.secrets.write",
                    "vault.identities.read",
                    "vault.identities.create",
                    "vault.identities.use",
                    "vault.identities.manage",
                ],
                "secretValue": "stored-secret",
                "identityPrivateKey": "private-identity-key",
                "identitySeed": "identity-seed",
                "recoveryPhrase": "alpha beta gamma",
                "mnemonicPhrase": "delta epsilon zeta",
                "accountMnemonic": "eta theta iota",
                "publicIdentityId": "identity-public-id",
            },
            workspace,
            out_dir,
        )
        assert vault_metadata["capabilities"][0] == "vault.secrets.read", vault_metadata
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
            "capability=vault.identities.use",
            workspace,
            out_dir,
        )
        for forbidden in ("seed-secret", "alpha beta", "delta epsilon", "eta theta", "vault-secret"):
            assert forbidden not in vault_scrubbed, vault_scrubbed
        assert "vault.identities.use" in vault_scrubbed, vault_scrubbed
        signature_scrubbed = scrub_text(
            "signature.value.base64=raw-signature signature.algorithm=Ed25519",
            workspace,
            out_dir,
        )
        assert "raw-signature" not in signature_scrubbed, signature_scrubbed
        assert "Ed25519" in signature_scrubbed, signature_scrubbed
        body_label_scrubbed = scrub_text(
            "raw trust statement body: signed-trust-document\n"
            "raw message body: private-social-body\n"
            "request body: form-password=secret\n"
            "raw feed body: <script>alert(1)</script>",
            workspace,
            out_dir,
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
        pem_scrubbed = scrub_text(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "openssh-private-key-body\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
            "public reviewer key id remains",
            workspace,
            out_dir,
        )
        for forbidden in (
            "BEGIN OPENSSH PRIVATE KEY",
            "openssh-private-key-body",
            "END OPENSSH PRIVATE KEY",
        ):
            assert forbidden not in pem_scrubbed, pem_scrubbed
        assert "public reviewer key id remains" in pem_scrubbed, pem_scrubbed
        truncated_pem_scrubbed = scrub_text(
            "before\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "truncated-openssh-private-key-body\n"
            "more-private-key-body",
            workspace,
            out_dir,
        )
        for forbidden in (
            "BEGIN OPENSSH PRIVATE KEY",
            "truncated-openssh-private-key-body",
            "more-private-key-body",
        ):
            assert forbidden not in truncated_pem_scrubbed, truncated_pem_scrubbed
        assert "before" in truncated_pem_scrubbed, truncated_pem_scrubbed
        credential_scrubbed = scrub_text(
            'Authorization: Bearer report-secret\n'
            'Cookie: session=abc; csrf=def\n'
            '{"token":"json-secret","authorization":"Bearer json-secret","password":"pw"} '
            "authorization=Bearer inline-secret "
            "rawMessageBody=private-social-body rawFetchedBody=private-fetched-body "
            "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64=base64-secret "
            "privateKeyBase64=key-secret clientSecret=client-secret api_password=api-secret "
            "privateKeyPresent=false",
            workspace,
            out_dir,
        )
        for forbidden in (
            "Bearer report-secret",
            "session=abc",
            "csrf=def",
            "json-secret",
            '"pw"',
            "inline-secret",
            "base64-secret",
            "key-secret",
            "client-secret",
            "api-secret",
            "private-social-body",
            "private-fetched-body",
        ):
            assert forbidden not in credential_scrubbed, credential_scrubbed
        assert "Authorization: <redacted>" in credential_scrubbed, credential_scrubbed
        assert "Cookie: <redacted>" in credential_scrubbed, credential_scrubbed
        assert '"token":"<redacted>"' in credential_scrubbed, credential_scrubbed
        assert "authorization=<redacted>" in credential_scrubbed, credential_scrubbed
        assert "privateKeyPresent=false" in credential_scrubbed, credential_scrubbed

        external_out_dir = Path(temp_name) / "external-cert"
        external_settings = dataclasses.replace(settings, out_dir=external_out_dir.resolve())
        external_summary, external_exit_code = run(external_settings)
        assert external_exit_code == 0, external_summary
        assert external_summary["summaryPath"].startswith("<workdir>/"), external_summary
        assert external_summary["reportPath"].startswith("<workdir>/"), external_summary
        assert external_summary["ecosystemMatrixPath"].startswith("<workdir>/"), external_summary
        assert (external_out_dir / SUMMARY_FILE_NAME).is_file(), external_summary
        assert (external_out_dir / ECOSYSTEM_MATRIX_FILE_NAME).is_file(), external_summary
        assert str(external_out_dir) not in json.dumps(external_summary, sort_keys=True), external_summary

        missing_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/missing-cert").resolve(),
            interop_smoke_summary=workspace / "build/missing-interop/summary.json",
        )
        missing_summary, missing_exit_code = run(missing_settings)
        assert missing_exit_code == 1, missing_summary
        assert missing_summary["status"] == "fail", missing_summary
        assert missing_summary["releaseCandidatePassed"] is False, missing_summary

        malformed_path = workspace / "build/malformed-interop/summary.json"
        malformed_path.parent.mkdir(parents=True, exist_ok=True)
        malformed_path.write_text('{"status": "success"', encoding="utf-8")
        malformed_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/malformed-cert").resolve(),
            interop_smoke_summary=malformed_path,
        )
        malformed_summary, malformed_exit_code = run(malformed_settings)
        assert malformed_exit_code == 1, malformed_summary
        assert malformed_summary["status"] == "fail", malformed_summary
        malformed_interop = next(item for item in malformed_summary["evidence"] if item["id"] == "interop.smoke")
        assert malformed_interop["status"] == "missing", malformed_interop
        assert (malformed_settings.out_dir / REPORT_FILE_NAME).is_file(), malformed_summary
        assert not any(
            artifact.endswith("/interop-smoke-summary.json")
            for artifact in malformed_summary["copiedArtifacts"]
        ), malformed_summary

        pr_missing_settings = dataclasses.replace(
            missing_settings,
            out_dir=(workspace / "build/pr-missing-cert").resolve(),
            mode="pr",
        )
        pr_missing_summary, pr_missing_exit_code = run(pr_missing_settings)
        assert pr_missing_exit_code == 0, pr_missing_summary
        assert pr_missing_summary["status"] == "warn", pr_missing_summary
        assert pr_missing_summary["releaseCandidatePassed"] is False, pr_missing_summary
        assert pr_missing_summary["promotionDecision"] == "FAIL", pr_missing_summary

        nightly_missing_settings = dataclasses.replace(
            missing_settings,
            out_dir=(workspace / "build/nightly-missing-cert").resolve(),
            mode="nightly",
        )
        nightly_missing_summary, nightly_missing_exit_code = run(nightly_missing_settings)
        assert nightly_missing_exit_code == 0, nightly_missing_summary
        assert nightly_missing_summary["status"] == "warn", nightly_missing_summary
        assert nightly_missing_summary["releaseCandidatePassed"] is False, nightly_missing_summary
        assert nightly_missing_summary["promotionDecision"] == "FAIL", nightly_missing_summary

        failing_perf = read_json(settings.perf_smoke_summary)
        assert failing_perf is not None
        failing_perf["status"] = "failure"
        failing_perf_path = workspace / "build/failing-perf/summary.json"
        write_json(failing_perf_path, failing_perf)
        nightly_failing_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/nightly-failing-cert").resolve(),
            mode="nightly",
            perf_smoke_summary=failing_perf_path,
        )
        nightly_failing_summary, nightly_failing_exit_code = run(nightly_failing_settings)
        assert nightly_failing_exit_code == 1, nightly_failing_summary
        assert nightly_failing_summary["status"] == "fail", nightly_failing_summary
        assert nightly_failing_summary["releaseCandidatePassed"] is False, nightly_failing_summary

        waived_settings = dataclasses.replace(
            missing_settings,
            out_dir=(workspace / "build/waived-cert").resolve(),
            waivers={"interop.smoke": "Release manager accepted CI artifact from upstream run."},
        )
        waived_summary, waived_exit_code = run(waived_settings)
        assert waived_exit_code == 0, waived_summary
        assert waived_summary["status"] == "warn", waived_summary
        assert waived_summary["waivers"] == {
            "interop.smoke": "Release manager accepted CI artifact from upstream run."
        }, waived_summary
        assert waived_summary["waiverRecords"][0]["source"] == "cli", waived_summary
        waived_item = next(item for item in waived_summary["evidence"] if item["id"] == "interop.smoke")
        assert waived_item["details"]["waived"] is True

        sensitive_reason = f"token=hunter2 USK@private/insert /mnt/secrets/signing/key.pem {workspace}/secret"
        sensitive_waived_settings = dataclasses.replace(
            missing_settings,
            out_dir=(workspace / "build/sensitive-waived-cert").resolve(),
            waivers={"interop.smoke": sensitive_reason},
        )
        sensitive_waived_summary, sensitive_waived_exit_code = run(sensitive_waived_settings)
        assert sensitive_waived_exit_code == 0, sensitive_waived_summary
        sensitive_report = (
            sensitive_waived_settings.out_dir / REPORT_FILE_NAME
        ).read_text(encoding="utf-8")
        sensitive_matrix_report = (
            sensitive_waived_settings.out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME
        ).read_text(encoding="utf-8")
        sensitive_matrix = read_json(sensitive_waived_settings.out_dir / ECOSYSTEM_MATRIX_FILE_NAME)
        sensitive_encoded = (
            json.dumps(sensitive_waived_summary, sort_keys=True)
            + json.dumps(sensitive_matrix, sort_keys=True)
            + sensitive_report
            + sensitive_matrix_report
        )
        for forbidden in ("hunter2", "USK@private", "/mnt/secrets/signing/key.pem", str(workspace)):
            assert forbidden not in sensitive_encoded, f"waiver reason leaked {forbidden}"

        def stable_self_test_passing_domains() -> list[dict[str, Any]]:
            return [
                {
                    "id": domain_id,
                    "status": "pass",
                    "summary": "Synthetic Stable domain row passed.",
                    "evidenceIds": [],
                    "blockers": [],
                    "warnings": [],
                    "allowedLimitations": [],
                }
                for domain_id in STABLE_1_0_READINESS_DOMAIN_IDS
            ]

        def stable_self_test_domains_with(
            domain_id: str,
            **updates: Any,
        ) -> list[dict[str, Any]]:
            domains = stable_self_test_passing_domains()
            for domain in domains:
                if domain.get("id") == domain_id:
                    domain.update(updates)
                    return domains
            raise AssertionError(f"Stable self-test domain is missing {domain_id}")

        def stable_self_test_summary(
            release_id: str = "cryptad-production-beta-self-test",
            *,
            omitted_evidence_ids: set[str] | None = None,
        ) -> dict[str, Any]:
            omitted = omitted_evidence_ids or set()
            return {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": release_id,
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ready", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                    if evidence_id not in omitted
                ],
            }

        for failing_synthetic_evidence_id in (
            "stable-1.0.readiness-gate",
            "stable-1.0.redaction",
        ):
            stable_failed_reported_row_summary = stable_self_test_summary()
            for entry in stable_failed_reported_row_summary["evidence"]:
                if isinstance(entry, dict) and entry.get("id") == failing_synthetic_evidence_id:
                    entry["status"] = "fail"
                    entry["summary"] = (
                        f"{failing_synthetic_evidence_id} failed in the reported evidence row."
                    )
                    break
            else:
                raise AssertionError(
                    f"Stable self-test summary is missing {failing_synthetic_evidence_id}"
                )
            stable_failed_reported_row_path = (
                workspace
                / "build"
                / f"stable-readiness-reported-{failing_synthetic_evidence_id.replace('.', '-')}-fail.json"
            )
            write_json(stable_failed_reported_row_path, stable_failed_reported_row_summary)
            stable_failed_reported_row_items = stable_readiness_evidence(
                stable_failed_reported_row_path,
                True,
                workspace,
                out_dir,
                "cryptad-production-beta-self-test",
            )
            stable_failed_reported_row_item = next(
                item
                for item in stable_failed_reported_row_items
                if item.id == failing_synthetic_evidence_id
            )
            assert stable_failed_reported_row_item.status == "fail", (
                stable_failed_reported_row_item
            )
            assert stable_failed_reported_row_item.details[
                "reportedStableReadinessEvidenceStatus"
            ] == "fail", stable_failed_reported_row_item.details

        nested_security_drill_release_id = EvidenceItem(
            "production-security.response-runbook",
            "pass",
            True,
            "Synthetic security response runbook evidence passed.",
            "self-test",
            {
                "securityDrills": {
                    "details": {
                        "releaseId": "cryptad-cert-release-candidate",
                    },
                },
            },
        )
        settings_without_stable_candidate = dataclasses.replace(
            settings,
            metadata={"selfTest": "true"},
        )
        assert stable_readiness_expected_release_id(
            settings_without_stable_candidate,
            [nested_security_drill_release_id],
        ) == "", "nested security drill releaseId must not bind Stable readiness"
        top_level_security_release_id = dataclasses.replace(
            nested_security_drill_release_id,
            details={
                **nested_security_drill_release_id.details,
                "candidateReleaseId": "cryptad-beta-explicit",
            },
        )
        assert stable_readiness_expected_release_id(
            settings_without_stable_candidate,
            [top_level_security_release_id],
        ) == "", "production-security evidence releaseId must not implicitly bind Stable readiness"
        metadata_bound_settings = dataclasses.replace(
            settings_without_stable_candidate,
            metadata={
                **settings_without_stable_candidate.metadata,
                "candidateReleaseId": "cryptad-beta-metadata",
            },
        )
        assert stable_readiness_expected_release_id(
            metadata_bound_settings,
            [nested_security_drill_release_id],
        ) == "cryptad-beta-metadata"

        stable_missing_candidate_id_summary = (
            workspace / "build/stable-readiness-missing-candidate-id.json"
        )
        write_json(
            stable_missing_candidate_id_summary,
            stable_self_test_summary("cryptad-beta-from-production"),
        )
        stable_missing_candidate_id_settings = dataclasses.replace(
            settings_without_stable_candidate,
            out_dir=(workspace / "build/stable-missing-candidate-id-cert").resolve(),
            stable_readiness_summary=stable_missing_candidate_id_summary,
            stable_readiness_required=True,
        )
        stable_missing_candidate_id_cert, stable_missing_candidate_id_exit_code = run(
            stable_missing_candidate_id_settings
        )
        assert stable_missing_candidate_id_exit_code == 1, stable_missing_candidate_id_cert
        stable_missing_candidate_id_row = matrix_row_by_id(
            stable_missing_candidate_id_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_missing_candidate_id_row["status"] == "fail", stable_missing_candidate_id_row
        assert stable_missing_candidate_id_row["releaseBlocker"] is True, (
            stable_missing_candidate_id_row
        )
        assert "evidence.stable-1.0.readiness-gate" in stable_missing_candidate_id_row[
            "issueIds"
        ], stable_missing_candidate_id_row
        stable_missing_candidate_id_gate = next(
            item
            for item in stable_missing_candidate_id_cert["evidence"]
            if item["id"] == "stable-1.0.readiness-gate"
        )
        assert stable_missing_candidate_id_gate["details"]["validationErrors"] == [
            "candidate releaseId metadata is required when Stable readiness is required"
        ], stable_missing_candidate_id_gate

        stable_metadata_bound_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-metadata-bound-cert").resolve(),
            metadata={
                **settings.metadata,
                "candidateReleaseId": "cryptad-beta-from-production",
            },
            stable_readiness_summary=stable_missing_candidate_id_summary,
            stable_readiness_required=True,
        )
        stable_metadata_bound_cert, stable_metadata_bound_exit_code = run(
            stable_metadata_bound_settings
        )
        assert stable_metadata_bound_exit_code == 0, stable_metadata_bound_cert
        stable_metadata_bound_row = matrix_row_by_id(
            stable_metadata_bound_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_metadata_bound_row["status"] == "pass", stable_metadata_bound_row
        assert stable_metadata_bound_row["releaseBlocker"] is False, (
            stable_metadata_bound_row
        )

        stable_missing_summary_waived_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-missing-summary-waived-cert").resolve(),
            stable_readiness_summary=None,
            stable_readiness_required=True,
            waivers={
                "stable-1-0-readiness": "Attempted row waiver for missing Stable readiness.",
                "matrix.stable-readiness.redaction-failed": (
                    "Attempted matrix waiver for missing Stable readiness."
                ),
            },
        )
        stable_missing_summary_waived_cert, stable_missing_summary_waived_exit_code = run(
            stable_missing_summary_waived_settings
        )
        assert stable_missing_summary_waived_exit_code == 1, stable_missing_summary_waived_cert
        stable_missing_summary_waived_row = matrix_row_by_id(
            stable_missing_summary_waived_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_missing_summary_waived_row["status"] == "fail", (
            stable_missing_summary_waived_row
        )
        assert stable_missing_summary_waived_row["releaseBlocker"] is True, (
            stable_missing_summary_waived_row
        )
        assert stable_missing_summary_waived_row.get("waiverIds") == [], (
            stable_missing_summary_waived_row
        )
        assert "matrix.stable-readiness.redaction-failed" in stable_missing_summary_waived_row[
            "issueIds"
        ], stable_missing_summary_waived_row
        assert stable_missing_summary_waived_row["details"]["unwaivableIssueIds"] == [
            "matrix.stable-readiness.redaction-failed"
        ], stable_missing_summary_waived_row
        assert stable_missing_summary_waived_row["details"][
            "unwaivableRedactionEvidenceIds"
        ] == ["stable-1.0.redaction"], stable_missing_summary_waived_row

        def assert_required_stable_mode_failed(
            cert: dict[str, Any],
            exit_code: int,
            case_settings: Settings,
        ) -> None:
            assert exit_code == 1, cert
            assert cert["status"] == "fail", cert
            assert cert["promotionDecision"] == "FAIL", cert
            assert cert["releaseCandidatePassed"] is False, cert
            assert cert["ecosystemMatrixStatus"] == "fail", cert
            stable_row = matrix_row_by_id(
                case_settings.out_dir,
                STABLE_1_0_READINESS_MATRIX_ROW_ID,
            )
            assert stable_row["status"] == "fail", stable_row
            assert stable_row["releaseBlocker"] is True, stable_row

        for stable_required_mode in ("pr", "nightly"):
            stable_required_missing_settings = dataclasses.replace(
                settings,
                out_dir=(
                    workspace / f"build/stable-required-missing-{stable_required_mode}-cert"
                ).resolve(),
                mode=stable_required_mode,
                stable_readiness_summary=None,
                stable_readiness_required=True,
            )
            stable_required_missing_cert, stable_required_missing_exit_code = run(
                stable_required_missing_settings
            )
            assert_required_stable_mode_failed(
                stable_required_missing_cert,
                stable_required_missing_exit_code,
                stable_required_missing_settings,
            )

        stable_required_not_ready_summary = (
            workspace / "build/stable-readiness-required-not-ready.json"
        )
        stable_required_not_ready_value = stable_self_test_summary()
        stable_required_not_ready_value.update(
            {
                "status": "fail",
                "decision": "not-ready",
                "stableReady": False,
                "blockerCount": 1,
                "blockers": [
                    {
                        "id": "stable-required-self-test-blocker",
                        "evidenceId": "stable-1.0.readiness-gate",
                        "summary": "Synthetic Stable readiness blocker.",
                    }
                ],
            }
        )
        write_json(stable_required_not_ready_summary, stable_required_not_ready_value)
        for stable_required_mode in ("pr", "nightly"):
            stable_required_not_ready_settings = dataclasses.replace(
                settings,
                out_dir=(
                    workspace / f"build/stable-required-not-ready-{stable_required_mode}-cert"
                ).resolve(),
                mode=stable_required_mode,
                stable_readiness_summary=stable_required_not_ready_summary,
                stable_readiness_required=True,
            )
            stable_required_not_ready_cert, stable_required_not_ready_exit_code = run(
                stable_required_not_ready_settings
            )
            assert_required_stable_mode_failed(
                stable_required_not_ready_cert,
                stable_required_not_ready_exit_code,
                stable_required_not_ready_settings,
            )

        stable_release_mismatch_summary = workspace / "build/stable-readiness-release-mismatch.json"
        write_json(
            stable_release_mismatch_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-beta-old",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ready", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_release_mismatch_items = stable_readiness_evidence(
            stable_release_mismatch_summary,
            True,
            workspace,
            out_dir,
            "cryptad-production-beta-self-test",
        )
        stable_release_mismatch_gate = next(
            item
            for item in stable_release_mismatch_items
            if item.id == "stable-1.0.readiness-gate"
        )
        assert stable_release_mismatch_gate.status == "fail", stable_release_mismatch_gate
        assert stable_release_mismatch_gate.details["validationErrors"] == [
            "releaseId must match candidate cryptad-production-beta-self-test; summary releaseId is cryptad-beta-old"
        ], stable_release_mismatch_gate.details
        stable_release_mismatch_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-release-mismatch-cert").resolve(),
            metadata={
                **settings.metadata,
                "candidateReleaseId": "cryptad-production-beta-self-test",
            },
            stable_readiness_summary=stable_release_mismatch_summary,
            stable_readiness_required=True,
        )
        stable_release_mismatch_cert, stable_release_mismatch_exit_code = run(
            stable_release_mismatch_settings
        )
        assert stable_release_mismatch_exit_code == 1, stable_release_mismatch_cert
        stable_release_mismatch_row = matrix_row_by_id(
            stable_release_mismatch_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_release_mismatch_row["status"] == "fail", stable_release_mismatch_row
        assert stable_release_mismatch_row["releaseBlocker"] is True, stable_release_mismatch_row
        assert "evidence.stable-1.0.readiness-gate" in stable_release_mismatch_row["issueIds"], (
            stable_release_mismatch_row
        )
        assert "matrix.stable-readiness.evidence-not-passing" in stable_release_mismatch_row["issueIds"], (
            stable_release_mismatch_row
        )

        stable_missing_domains_summary = workspace / "build/stable-readiness-missing-domains.json"
        write_json(
            stable_missing_domains_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ready", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_missing_domains_items = stable_readiness_evidence(
            stable_missing_domains_summary,
            True,
            workspace,
            out_dir,
            "cryptad-production-beta-self-test",
        )
        stable_missing_domains_gate = next(
            item
            for item in stable_missing_domains_items
            if item.id == "stable-1.0.readiness-gate"
        )
        assert stable_missing_domains_gate.status == "fail", stable_missing_domains_gate
        assert stable_missing_domains_gate.details["validationErrors"] == [
            "domains must be a non-empty list"
        ], stable_missing_domains_gate.details
        stable_missing_domains_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-missing-domains-cert").resolve(),
            stable_readiness_summary=stable_missing_domains_summary,
            stable_readiness_required=True,
        )
        stable_missing_domains_cert, stable_missing_domains_exit_code = run(
            stable_missing_domains_settings
        )
        assert stable_missing_domains_exit_code == 1, stable_missing_domains_cert
        stable_missing_domains_row = matrix_row_by_id(
            stable_missing_domains_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_missing_domains_row["status"] == "fail", stable_missing_domains_row
        assert stable_missing_domains_row["releaseBlocker"] is True, stable_missing_domains_row
        assert "evidence.stable-1.0.readiness-gate" in stable_missing_domains_row["issueIds"], (
            stable_missing_domains_row
        )
        assert "matrix.stable-readiness.evidence-not-passing" in stable_missing_domains_row["issueIds"], (
            stable_missing_domains_row
        )

        stable_truncated_domains_summary = (
            workspace / "build/stable-readiness-truncated-domains.json"
        )
        stable_truncated_domains_value = stable_self_test_summary()
        stable_truncated_domains_value["domains"] = [
            {
                "id": "stub-domain",
                "status": "pass",
                "summary": "Synthetic truncated Stable domain row.",
                "evidenceIds": [],
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
            }
        ]
        write_json(stable_truncated_domains_summary, stable_truncated_domains_value)
        stable_truncated_domains_items = stable_readiness_evidence(
            stable_truncated_domains_summary,
            True,
            workspace,
            out_dir,
            "cryptad-production-beta-self-test",
        )
        stable_truncated_domains_gate = next(
            item
            for item in stable_truncated_domains_items
            if item.id == "stable-1.0.readiness-gate"
        )
        assert stable_truncated_domains_gate.status == "fail", stable_truncated_domains_gate
        assert any(
            error.startswith("domains are missing required IDs:")
            for error in stable_truncated_domains_gate.details["validationErrors"]
        ), stable_truncated_domains_gate.details
        stable_truncated_domains_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-truncated-domains-cert").resolve(),
            stable_readiness_summary=stable_truncated_domains_summary,
            stable_readiness_required=True,
        )
        stable_truncated_domains_cert, stable_truncated_domains_exit_code = run(
            stable_truncated_domains_settings
        )
        assert stable_truncated_domains_exit_code == 1, stable_truncated_domains_cert
        stable_truncated_domains_row = matrix_row_by_id(
            stable_truncated_domains_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_truncated_domains_row["status"] == "fail", stable_truncated_domains_row
        assert stable_truncated_domains_row["releaseBlocker"] is True, (
            stable_truncated_domains_row
        )

        stable_failed_domain_summary = workspace / "build/stable-readiness-failed-domain.json"
        write_json(
            stable_failed_domain_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_domains_with(
                    "production-beta-state",
                    status="fail",
                    summary="Synthetic failed Stable domain row.",
                ),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ready", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_failed_domain_items = stable_readiness_evidence(
            stable_failed_domain_summary,
            True,
            workspace,
            out_dir,
            "cryptad-production-beta-self-test",
        )
        stable_failed_domain_gate = next(
            item
            for item in stable_failed_domain_items
            if item.id == "stable-1.0.readiness-gate"
        )
        assert stable_failed_domain_gate.status == "fail", stable_failed_domain_gate
        assert stable_failed_domain_gate.details["validationErrors"] == [
            "domain production-beta-state status is fail"
        ], stable_failed_domain_gate.details

        stable_malformed_allowed_domain_summary = (
            workspace / "build/stable-readiness-malformed-domain-allowed-limitation.json"
        )
        write_json(
            stable_malformed_allowed_domain_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_domains_with(
                    "production-beta-state",
                    summary="Synthetic passed Stable domain row with malformed allowed limitation.",
                    allowedLimitations=[1],
                ),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ready", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_malformed_allowed_domain_items = stable_readiness_evidence(
            stable_malformed_allowed_domain_summary,
            True,
            workspace,
            out_dir,
            "cryptad-production-beta-self-test",
        )
        stable_malformed_allowed_domain_gate = next(
            item
            for item in stable_malformed_allowed_domain_items
            if item.id == "stable-1.0.readiness-gate"
        )
        assert stable_malformed_allowed_domain_gate.status == "fail", stable_malformed_allowed_domain_gate
        assert stable_malformed_allowed_domain_gate.details["validationErrors"] == [
            "domain production-beta-state allowedLimitations[0] must be an object"
        ], stable_malformed_allowed_domain_gate.details
        stable_malformed_allowed_domain_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-malformed-domain-allowed-limitation-cert").resolve(),
            stable_readiness_summary=stable_malformed_allowed_domain_summary,
            stable_readiness_required=True,
        )
        stable_malformed_allowed_domain_cert, stable_malformed_allowed_domain_exit_code = run(
            stable_malformed_allowed_domain_settings
        )
        assert stable_malformed_allowed_domain_exit_code == 1, stable_malformed_allowed_domain_cert
        stable_malformed_allowed_domain_row = matrix_row_by_id(
            stable_malformed_allowed_domain_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_malformed_allowed_domain_row["status"] == "fail", stable_malformed_allowed_domain_row
        assert stable_malformed_allowed_domain_row["releaseBlocker"] is True, stable_malformed_allowed_domain_row
        assert "evidence.stable-1.0.readiness-gate" in stable_malformed_allowed_domain_row["issueIds"], (
            stable_malformed_allowed_domain_row
        )
        assert "matrix.stable-readiness.evidence-not-passing" in stable_malformed_allowed_domain_row[
            "issueIds"
        ], stable_malformed_allowed_domain_row

        stable_domain_blocker_summary = workspace / "build/stable-readiness-domain-blocker.json"
        write_json(
            stable_domain_blocker_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_domains_with(
                    "production-beta-state",
                    summary="Synthetic Stable domain row with hidden blocker.",
                    blockers=[
                        {
                            "id": "stable-self-test-domain-blocker",
                            "evidenceId": "stable-1.0.production-beta-state",
                            "summary": "Synthetic Stable domain blocker.",
                        }
                    ],
                ),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ready", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_domain_blocker_items = stable_readiness_evidence(
            stable_domain_blocker_summary,
            True,
            workspace,
            out_dir,
            "cryptad-production-beta-self-test",
        )
        stable_domain_blocker_gate = next(
            item
            for item in stable_domain_blocker_items
            if item.id == "stable-1.0.readiness-gate"
        )
        assert stable_domain_blocker_gate.status == "fail", stable_domain_blocker_gate
        assert stable_domain_blocker_gate.details["validationErrors"] == [
            "domain production-beta-state contains 1 blocker(s)"
        ], stable_domain_blocker_gate.details
        stable_domain_blocker_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-domain-blocker-cert").resolve(),
            stable_readiness_summary=stable_domain_blocker_summary,
            stable_readiness_required=True,
        )
        stable_domain_blocker_cert, stable_domain_blocker_exit_code = run(
            stable_domain_blocker_settings
        )
        assert stable_domain_blocker_exit_code == 1, stable_domain_blocker_cert
        stable_domain_blocker_row = matrix_row_by_id(
            stable_domain_blocker_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_domain_blocker_row["status"] == "fail", stable_domain_blocker_row
        assert stable_domain_blocker_row["releaseBlocker"] is True, stable_domain_blocker_row
        assert "evidence.stable-1.0.readiness-gate" in stable_domain_blocker_row["issueIds"], (
            stable_domain_blocker_row
        )
        assert "matrix.stable-readiness.evidence-not-passing" in stable_domain_blocker_row["issueIds"], (
            stable_domain_blocker_row
        )

        stable_missing_redaction_summary = workspace / "build/stable-readiness-missing-redaction.json"
        write_json(
            stable_missing_redaction_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
            },
        )
        stable_items = stable_readiness_evidence(
            stable_missing_redaction_summary,
            True,
            workspace,
            out_dir,
        )
        stable_statuses = {item.id: item.status for item in stable_items}
        assert stable_statuses["stable-1.0.readiness-gate"] == "fail", stable_statuses
        assert stable_statuses["stable-1.0.redaction"] == "fail", stable_statuses
        stable_redaction_waived_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-redaction-waived-cert").resolve(),
            stable_readiness_summary=stable_missing_redaction_summary,
            stable_readiness_required=True,
            waivers={
                "stable-1-0-readiness": "Attempted row waiver for Stable redaction failure.",
                "matrix.stable-readiness.redaction-failed": "Attempted matrix issue waiver for Stable redaction failure.",
            },
        )
        stable_redaction_waived_summary, stable_redaction_waived_exit_code = run(
            stable_redaction_waived_settings
        )
        assert stable_redaction_waived_exit_code == 1, stable_redaction_waived_summary
        stable_redaction_waived_row = matrix_row_by_id(
            stable_redaction_waived_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_redaction_waived_row["status"] == "fail", stable_redaction_waived_row
        assert stable_redaction_waived_row["releaseBlocker"] is True, stable_redaction_waived_row
        assert stable_redaction_waived_row.get("waiverIds") == [], stable_redaction_waived_row
        assert stable_redaction_waived_row["details"]["unwaivableRedactionEvidenceIds"] == [
            "stable-1.0.redaction"
        ], stable_redaction_waived_row
        assert stable_redaction_waived_row["details"]["unwaivableIssueIds"] == [
            "matrix.stable-readiness.redaction-failed"
        ], stable_redaction_waived_row

        stable_redaction_warn_summary = workspace / "build/stable-readiness-redaction-warn.json"
        stable_redaction_warn_value = stable_self_test_summary()
        for entry in stable_redaction_warn_value["evidence"]:
            if isinstance(entry, dict) and entry.get("id") == "stable-1.0.redaction":
                entry["status"] = "warn"
                entry["summary"] = "Synthetic Stable redaction warning."
                break
        else:
            raise AssertionError("Stable self-test summary is missing stable-1.0.redaction")
        write_json(stable_redaction_warn_summary, stable_redaction_warn_value)
        stable_redaction_warn_items = stable_readiness_evidence(
            stable_redaction_warn_summary,
            True,
            workspace,
            out_dir,
            "cryptad-production-beta-self-test",
        )
        stable_redaction_warn_statuses = {
            item.id: item.status for item in stable_redaction_warn_items
        }
        assert stable_redaction_warn_statuses["stable-1.0.redaction"] == "warn", (
            stable_redaction_warn_statuses
        )
        stable_redaction_warn_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-redaction-warn-cert").resolve(),
            stable_readiness_summary=stable_redaction_warn_summary,
            stable_readiness_required=True,
        )
        stable_redaction_warn_cert, stable_redaction_warn_exit_code = run(
            stable_redaction_warn_settings
        )
        assert stable_redaction_warn_exit_code == 1, stable_redaction_warn_cert
        stable_redaction_warn_row = matrix_row_by_id(
            stable_redaction_warn_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_redaction_warn_row["status"] == "fail", stable_redaction_warn_row
        assert stable_redaction_warn_row["releaseBlocker"] is True, stable_redaction_warn_row
        assert stable_redaction_warn_row["details"]["unwaivableRedactionEvidenceIds"] == [
            "stable-1.0.redaction"
        ], stable_redaction_warn_row
        assert "matrix.stable-readiness.redaction-failed" in stable_redaction_warn_row[
            "issueIds"
        ], stable_redaction_warn_row

        stable_redaction_count_summary = workspace / "build/stable-readiness-redaction-count.json"
        write_json(
            stable_redaction_count_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findingCount": 1},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ready", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_redaction_count_items = stable_readiness_evidence(
            stable_redaction_count_summary,
            True,
            workspace,
            out_dir,
        )
        stable_redaction_count_statuses = {item.id: item.status for item in stable_redaction_count_items}
        assert stable_redaction_count_statuses["stable-1.0.readiness-gate"] == "fail", stable_redaction_count_statuses
        assert stable_redaction_count_statuses["stable-1.0.redaction"] == "fail", stable_redaction_count_statuses
        stable_redaction_count_redaction_item = next(
            item
            for item in stable_redaction_count_items
            if item.id == "stable-1.0.redaction"
        )
        assert evidence_item_has_unwaivable_redaction_findings(stable_redaction_count_redaction_item), (
            stable_redaction_count_redaction_item
        )
        assert stable_redaction_count_redaction_item.details["redaction"]["findingCount"] == 1, (
            stable_redaction_count_redaction_item
        )
        stable_redaction_count_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-redaction-count-cert").resolve(),
            stable_readiness_summary=stable_redaction_count_summary,
            stable_readiness_required=True,
            waivers={
                "stable-1.0.redaction": "Attempted evidence waiver for Stable redaction finding count.",
                "stable-1-0-readiness": "Attempted row waiver for Stable redaction finding count.",
                "matrix.stable-readiness.redaction-failed": (
                    "Attempted matrix waiver for Stable redaction finding count."
                ),
            },
        )
        stable_redaction_count_cert, stable_redaction_count_exit_code = run(stable_redaction_count_settings)
        assert stable_redaction_count_exit_code == 1, stable_redaction_count_cert
        stable_redaction_count_row = matrix_row_by_id(stable_redaction_count_settings.out_dir, "stable-1-0-readiness")
        assert stable_redaction_count_row["status"] == "fail", stable_redaction_count_row
        assert stable_redaction_count_row["releaseBlocker"] is True, stable_redaction_count_row
        assert stable_redaction_count_row.get("waiverIds") == [], stable_redaction_count_row
        assert stable_redaction_count_row["details"]["unwaivableRedactionEvidenceIds"] == [
            "stable-1.0.redaction"
        ], stable_redaction_count_row
        assert "evidence.stable-1.0.redaction" in stable_redaction_count_row["issueIds"], stable_redaction_count_row
        assert "matrix.stable-readiness.redaction-failed" in stable_redaction_count_row["issueIds"], stable_redaction_count_row

        for critical_count_value, critical_count_suffix in (
            (1, "critical-count"),
            (0.5, "fractional-critical-count"),
        ):
            stable_redaction_critical_count_summary = (
                workspace / f"build/stable-readiness-redaction-{critical_count_suffix}.json"
            )
            stable_redaction_critical_count_value = read_json(stable_redaction_count_summary) or {}
            stable_redaction_critical_count_value["redaction"] = {
                "status": "pass",
                "findings": [],
                "findingCount": 0,
                "criticalFindingCount": critical_count_value,
            }
            write_json(stable_redaction_critical_count_summary, stable_redaction_critical_count_value)
            stable_redaction_critical_count_items = stable_readiness_evidence(
                stable_redaction_critical_count_summary,
                True,
                workspace,
                out_dir,
            )
            stable_redaction_critical_count_statuses = {
                item.id: item.status for item in stable_redaction_critical_count_items
            }
            assert stable_redaction_critical_count_statuses["stable-1.0.readiness-gate"] == "fail", (
                stable_redaction_critical_count_statuses
            )
            assert stable_redaction_critical_count_statuses["stable-1.0.redaction"] == "fail", (
                stable_redaction_critical_count_statuses
            )
            stable_redaction_critical_count_redaction_item = next(
                item
                for item in stable_redaction_critical_count_items
                if item.id == "stable-1.0.redaction"
            )
            assert evidence_item_has_unwaivable_redaction_findings(
                stable_redaction_critical_count_redaction_item
            ), stable_redaction_critical_count_redaction_item
            assert stable_redaction_critical_count_redaction_item.details["redaction"][
                "criticalFindingCount"
            ] == critical_count_value, stable_redaction_critical_count_redaction_item
            stable_redaction_critical_count_settings = dataclasses.replace(
                settings,
                out_dir=(workspace / f"build/stable-redaction-{critical_count_suffix}-cert").resolve(),
                stable_readiness_summary=stable_redaction_critical_count_summary,
                stable_readiness_required=True,
                waivers={
                    "stable-1.0.redaction": (
                        "Attempted evidence waiver for Stable critical redaction count."
                    ),
                    "stable-1-0-readiness": (
                        "Attempted row waiver for Stable critical redaction count."
                    ),
                    "matrix.stable-readiness.redaction-failed": (
                        "Attempted matrix waiver for Stable critical redaction count."
                    ),
                },
            )
            stable_redaction_critical_count_cert, stable_redaction_critical_count_exit_code = run(
                stable_redaction_critical_count_settings
            )
            assert stable_redaction_critical_count_exit_code == 1, (
                stable_redaction_critical_count_cert
            )
            stable_redaction_critical_count_row = matrix_row_by_id(
                stable_redaction_critical_count_settings.out_dir,
                "stable-1-0-readiness",
            )
            assert stable_redaction_critical_count_row["status"] == "fail", (
                stable_redaction_critical_count_row
            )
            assert stable_redaction_critical_count_row["releaseBlocker"] is True, (
                stable_redaction_critical_count_row
            )
            assert stable_redaction_critical_count_row.get("waiverIds") == [], (
                stable_redaction_critical_count_row
            )
            assert stable_redaction_critical_count_row["details"]["unwaivableRedactionEvidenceIds"] == [
                "stable-1.0.redaction"
            ], stable_redaction_critical_count_row
            assert "evidence.stable-1.0.redaction" in stable_redaction_critical_count_row[
                "issueIds"
            ], stable_redaction_critical_count_row
            assert "matrix.stable-readiness.redaction-failed" in stable_redaction_critical_count_row[
                "issueIds"
            ], stable_redaction_critical_count_row

        stable_redaction_raw_flag_summary = workspace / "build/stable-readiness-redaction-raw-flag.json"
        stable_redaction_raw_flag_value = read_json(stable_redaction_count_summary) or {}
        stable_redaction_raw_flag_value["redaction"] = {
            "status": "pass",
            "findingCount": 0,
            "findings": [],
            "rawBodiesStored": True,
        }
        write_json(stable_redaction_raw_flag_summary, stable_redaction_raw_flag_value)
        stable_redaction_raw_flag_items = stable_readiness_evidence(
            stable_redaction_raw_flag_summary,
            True,
            workspace,
            out_dir,
        )
        stable_redaction_raw_flag_statuses = {
            item.id: item.status for item in stable_redaction_raw_flag_items
        }
        assert stable_redaction_raw_flag_statuses["stable-1.0.readiness-gate"] == "fail", (
            stable_redaction_raw_flag_statuses
        )
        assert stable_redaction_raw_flag_statuses["stable-1.0.redaction"] == "fail", (
            stable_redaction_raw_flag_statuses
        )
        stable_redaction_raw_flag_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-redaction-raw-flag-cert").resolve(),
            stable_readiness_summary=stable_redaction_raw_flag_summary,
            stable_readiness_required=True,
        )
        stable_redaction_raw_flag_cert, stable_redaction_raw_flag_exit_code = run(
            stable_redaction_raw_flag_settings
        )
        assert stable_redaction_raw_flag_exit_code == 1, stable_redaction_raw_flag_cert
        stable_redaction_raw_flag_row = matrix_row_by_id(
            stable_redaction_raw_flag_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_redaction_raw_flag_row["status"] == "fail", stable_redaction_raw_flag_row
        assert stable_redaction_raw_flag_row["releaseBlocker"] is True, stable_redaction_raw_flag_row
        assert "evidence.stable-1.0.redaction" in stable_redaction_raw_flag_row["issueIds"], (
            stable_redaction_raw_flag_row
        )
        assert "matrix.stable-readiness.redaction-failed" in stable_redaction_raw_flag_row[
            "issueIds"
        ], stable_redaction_raw_flag_row

        stable_excluded_from_evidence_summary = (
            workspace / "build/stable-readiness-excluded-from-evidence-redaction.json"
        )
        stable_excluded_from_evidence_value = read_json(stable_redaction_count_summary) or {}
        stable_excluded_from_evidence_value["redaction"] = {
            "status": "pass",
            "findingCount": 0,
            "findings": [],
            "rawBackupPayloadsExcludedFromEvidence": False,
        }
        write_json(stable_excluded_from_evidence_summary, stable_excluded_from_evidence_value)
        stable_excluded_from_evidence_items = stable_readiness_evidence(
            stable_excluded_from_evidence_summary,
            True,
            workspace,
            out_dir,
        )
        stable_excluded_from_evidence_statuses = {
            item.id: item.status for item in stable_excluded_from_evidence_items
        }
        assert stable_excluded_from_evidence_statuses["stable-1.0.readiness-gate"] == "fail", (
            stable_excluded_from_evidence_statuses
        )
        assert stable_excluded_from_evidence_statuses["stable-1.0.redaction"] == "fail", (
            stable_excluded_from_evidence_statuses
        )
        stable_excluded_from_evidence_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-excluded-from-evidence-redaction-cert").resolve(),
            stable_readiness_summary=stable_excluded_from_evidence_summary,
            stable_readiness_required=True,
        )
        (
            stable_excluded_from_evidence_cert,
            stable_excluded_from_evidence_exit_code,
        ) = run(stable_excluded_from_evidence_settings)
        assert stable_excluded_from_evidence_exit_code == 1, stable_excluded_from_evidence_cert
        stable_excluded_from_evidence_row = matrix_row_by_id(
            stable_excluded_from_evidence_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_excluded_from_evidence_row["status"] == "fail", (
            stable_excluded_from_evidence_row
        )
        assert stable_excluded_from_evidence_row["releaseBlocker"] is True, (
            stable_excluded_from_evidence_row
        )
        assert "evidence.stable-1.0.redaction" in stable_excluded_from_evidence_row["issueIds"], (
            stable_excluded_from_evidence_row
        )
        assert "matrix.stable-readiness.redaction-failed" in stable_excluded_from_evidence_row["issueIds"], (
            stable_excluded_from_evidence_row
        )

        stable_redaction_fractional_count_summary = workspace / "build/stable-readiness-redaction-fractional-count.json"
        write_json(
            stable_redaction_fractional_count_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findingCount": 0.5},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ready", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_redaction_fractional_count_items = stable_readiness_evidence(
            stable_redaction_fractional_count_summary,
            True,
            workspace,
            out_dir,
        )
        stable_redaction_fractional_count_statuses = {
            item.id: item.status for item in stable_redaction_fractional_count_items
        }
        assert stable_redaction_fractional_count_statuses["stable-1.0.readiness-gate"] == "fail", (
            stable_redaction_fractional_count_statuses
        )
        assert stable_redaction_fractional_count_statuses["stable-1.0.redaction"] == "fail", (
            stable_redaction_fractional_count_statuses
        )
        stable_redaction_fractional_count_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-redaction-fractional-count-cert").resolve(),
            stable_readiness_summary=stable_redaction_fractional_count_summary,
            stable_readiness_required=True,
        )
        stable_redaction_fractional_count_cert, stable_redaction_fractional_count_exit_code = run(
            stable_redaction_fractional_count_settings
        )
        assert stable_redaction_fractional_count_exit_code == 1, stable_redaction_fractional_count_cert
        stable_redaction_fractional_count_row = matrix_row_by_id(
            stable_redaction_fractional_count_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_redaction_fractional_count_row["status"] == "fail", (
            stable_redaction_fractional_count_row
        )
        assert stable_redaction_fractional_count_row["releaseBlocker"] is True, (
            stable_redaction_fractional_count_row
        )
        assert "evidence.stable-1.0.redaction" in stable_redaction_fractional_count_row["issueIds"], (
            stable_redaction_fractional_count_row
        )
        assert "matrix.stable-readiness.redaction-failed" in stable_redaction_fractional_count_row["issueIds"], (
            stable_redaction_fractional_count_row
        )

        stable_malformed_redaction_findings_summary = (
            workspace / "build/stable-readiness-malformed-redaction-findings.json"
        )
        write_json(
            stable_malformed_redaction_findings_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": "malformed-redaction-proof"},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ready", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_malformed_redaction_findings_items = stable_readiness_evidence(
            stable_malformed_redaction_findings_summary,
            True,
            workspace,
            out_dir,
        )
        stable_malformed_redaction_findings_statuses = {
            item.id: item.status for item in stable_malformed_redaction_findings_items
        }
        assert stable_malformed_redaction_findings_statuses["stable-1.0.readiness-gate"] == "fail", (
            stable_malformed_redaction_findings_statuses
        )
        assert stable_malformed_redaction_findings_statuses["stable-1.0.redaction"] == "fail", (
            stable_malformed_redaction_findings_statuses
        )
        stable_malformed_redaction_findings_details = next(
            item.details
            for item in stable_malformed_redaction_findings_items
            if item.id == "stable-1.0.redaction"
        )
        assert stable_malformed_redaction_findings_details["validationErrors"] == [
            "findings is not a list"
        ], stable_malformed_redaction_findings_details
        stable_malformed_redaction_findings_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-malformed-redaction-findings-cert").resolve(),
            stable_readiness_summary=stable_malformed_redaction_findings_summary,
            stable_readiness_required=True,
        )
        (
            stable_malformed_redaction_findings_cert,
            stable_malformed_redaction_findings_exit_code,
        ) = run(stable_malformed_redaction_findings_settings)
        assert stable_malformed_redaction_findings_exit_code == 1, stable_malformed_redaction_findings_cert
        stable_malformed_redaction_findings_row = matrix_row_by_id(
            stable_malformed_redaction_findings_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_malformed_redaction_findings_row["status"] == "fail", (
            stable_malformed_redaction_findings_row
        )
        assert stable_malformed_redaction_findings_row["releaseBlocker"] is True, (
            stable_malformed_redaction_findings_row
        )
        assert "evidence.stable-1.0.redaction" in stable_malformed_redaction_findings_row["issueIds"], (
            stable_malformed_redaction_findings_row
        )
        assert "matrix.stable-readiness.redaction-failed" in stable_malformed_redaction_findings_row["issueIds"], (
            stable_malformed_redaction_findings_row
        )

        stable_malformed_row_redaction_findings_summary = (
            workspace / "build/stable-readiness-malformed-row-redaction-findings.json"
        )
        malformed_row_redaction_evidence_id = "stable-1.0.production-beta-state"
        write_json(
            stable_malformed_row_redaction_findings_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"redactionFindings": "not-a-list"}
                        if evidence_id == malformed_row_redaction_evidence_id
                        else (
                            {"decision": "ready", "stableReady": True}
                            if evidence_id == "stable-1.0.readiness-gate"
                            else {}
                        ),
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_malformed_row_items = stable_readiness_evidence(
            stable_malformed_row_redaction_findings_summary,
            True,
            workspace,
            out_dir,
        )
        stable_malformed_row_statuses = {item.id: item.status for item in stable_malformed_row_items}
        assert stable_malformed_row_statuses[malformed_row_redaction_evidence_id] == "fail", (
            stable_malformed_row_statuses
        )
        stable_malformed_row_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-malformed-row-redaction-cert").resolve(),
            stable_readiness_summary=stable_malformed_row_redaction_findings_summary,
            stable_readiness_required=True,
            waivers={
                "stable-1-0-readiness": "Attempted row waiver for malformed Stable row redaction failure.",
                "matrix.stable-readiness.redaction-failed": "Attempted matrix issue waiver for malformed row redaction failure.",
            },
        )
        stable_malformed_row_cert, stable_malformed_row_exit_code = run(stable_malformed_row_settings)
        assert stable_malformed_row_exit_code == 1, stable_malformed_row_cert
        stable_malformed_row = matrix_row_by_id(
            stable_malformed_row_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_malformed_row["status"] == "fail", stable_malformed_row
        assert stable_malformed_row["releaseBlocker"] is True, stable_malformed_row
        assert stable_malformed_row.get("waiverIds") == [], stable_malformed_row
        assert malformed_row_redaction_evidence_id in stable_malformed_row["details"]["unwaivableRedactionEvidenceIds"], (
            stable_malformed_row
        )
        assert "matrix.stable-readiness.redaction-failed" in stable_malformed_row["issueIds"], (
            stable_malformed_row
        )

        stable_nested_redaction_summary = workspace / "build/stable-readiness-nested-redaction.json"
        nested_redaction_evidence_id = "stable-1.0.production-beta-state"
        write_json(
            stable_nested_redaction_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {
                            "redaction": {
                                "status": "pass",
                                "findings": [
                                    {
                                        "kind": "stable-readiness-fixture",
                                        "summary": "Synthetic nested Stable evidence redaction finding.",
                                    }
                                ],
                            }
                        }
                        if evidence_id == nested_redaction_evidence_id
                        else (
                            {"decision": "ready", "stableReady": True}
                            if evidence_id == "stable-1.0.readiness-gate"
                            else {}
                        ),
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_nested_items = stable_readiness_evidence(
            stable_nested_redaction_summary,
            True,
            workspace,
            out_dir,
        )
        stable_nested_statuses = {item.id: item.status for item in stable_nested_items}
        assert stable_nested_statuses[nested_redaction_evidence_id] == "fail", stable_nested_statuses
        stable_nested_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-nested-redaction-cert").resolve(),
            stable_readiness_summary=stable_nested_redaction_summary,
            stable_readiness_required=True,
            waivers={
                "stable-1-0-readiness": "Attempted row waiver for nested Stable redaction failure.",
                "matrix.stable-readiness.redaction-failed": "Attempted matrix issue waiver for nested Stable redaction failure.",
            },
        )
        stable_nested_cert, stable_nested_exit_code = run(stable_nested_settings)
        assert stable_nested_exit_code == 1, stable_nested_cert
        stable_nested_row = matrix_row_by_id(stable_nested_settings.out_dir, "stable-1-0-readiness")
        assert stable_nested_row["status"] == "fail", stable_nested_row
        assert stable_nested_row["releaseBlocker"] is True, stable_nested_row
        assert stable_nested_row.get("waiverIds") == [], stable_nested_row
        assert nested_redaction_evidence_id in stable_nested_row["details"]["unwaivableRedactionEvidenceIds"], stable_nested_row
        assert "matrix.stable-readiness.redaction-failed" in stable_nested_row["issueIds"], stable_nested_row

        stable_direct_detail_redaction_summary = (
            workspace / "build/stable-readiness-direct-detail-redaction.json"
        )
        direct_detail_redaction_evidence_id = "stable-1.0.production-beta-state"
        stable_direct_detail_redaction_value = stable_self_test_summary()
        for entry in stable_direct_detail_redaction_value["evidence"]:
            if isinstance(entry, dict) and entry.get("id") == direct_detail_redaction_evidence_id:
                entry["details"] = {"rawBackupPayloadsExcludedFromEvidence": False}
                break
        else:
            raise AssertionError(
                f"Stable self-test summary is missing {direct_detail_redaction_evidence_id}"
            )
        write_json(stable_direct_detail_redaction_summary, stable_direct_detail_redaction_value)
        stable_direct_detail_redaction_items = stable_readiness_evidence(
            stable_direct_detail_redaction_summary,
            True,
            workspace,
            out_dir,
        )
        stable_direct_detail_redaction_statuses = {
            item.id: item.status for item in stable_direct_detail_redaction_items
        }
        assert stable_direct_detail_redaction_statuses[direct_detail_redaction_evidence_id] == "fail", (
            stable_direct_detail_redaction_statuses
        )
        assert stable_direct_detail_redaction_statuses["stable-1.0.redaction"] == "fail", (
            stable_direct_detail_redaction_statuses
        )
        stable_direct_detail_redaction_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-direct-detail-redaction-cert").resolve(),
            stable_readiness_summary=stable_direct_detail_redaction_summary,
            stable_readiness_required=True,
            waivers={
                "stable-1-0-readiness": "Attempted row waiver for direct Stable detail redaction failure.",
                "matrix.stable-readiness.redaction-failed": "Attempted matrix issue waiver for direct Stable detail redaction failure.",
            },
        )
        (
            stable_direct_detail_redaction_cert,
            stable_direct_detail_redaction_exit_code,
        ) = run(stable_direct_detail_redaction_settings)
        assert stable_direct_detail_redaction_exit_code == 1, (
            stable_direct_detail_redaction_cert
        )
        stable_direct_detail_redaction_row = matrix_row_by_id(
            stable_direct_detail_redaction_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_direct_detail_redaction_row["status"] == "fail", (
            stable_direct_detail_redaction_row
        )
        assert stable_direct_detail_redaction_row["releaseBlocker"] is True, (
            stable_direct_detail_redaction_row
        )
        assert stable_direct_detail_redaction_row.get("waiverIds") == [], (
            stable_direct_detail_redaction_row
        )
        assert direct_detail_redaction_evidence_id in stable_direct_detail_redaction_row["details"][
            "unwaivableRedactionEvidenceIds"
        ], stable_direct_detail_redaction_row
        assert "matrix.stable-readiness.redaction-failed" in stable_direct_detail_redaction_row[
            "issueIds"
        ], stable_direct_detail_redaction_row

        stable_sanitized_false_summary = (
            workspace / "build/stable-readiness-sanitized-false.json"
        )
        stable_sanitized_false_value = stable_self_test_summary()
        for entry in stable_sanitized_false_value["evidence"]:
            if isinstance(entry, dict) and entry.get("id") == "stable-1.0.redaction":
                entry["details"] = {"localPathsSanitized": False}
                break
        else:
            raise AssertionError("Stable self-test summary is missing stable-1.0.redaction")
        write_json(stable_sanitized_false_summary, stable_sanitized_false_value)
        stable_sanitized_false_items = stable_readiness_evidence(
            stable_sanitized_false_summary,
            True,
            workspace,
            out_dir,
        )
        stable_sanitized_false_statuses = {
            item.id: item.status for item in stable_sanitized_false_items
        }
        assert stable_sanitized_false_statuses["stable-1.0.readiness-gate"] == "fail", (
            stable_sanitized_false_statuses
        )
        assert stable_sanitized_false_statuses["stable-1.0.redaction"] == "fail", (
            stable_sanitized_false_statuses
        )
        stable_sanitized_false_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-sanitized-false-cert").resolve(),
            stable_readiness_summary=stable_sanitized_false_summary,
            stable_readiness_required=True,
        )
        stable_sanitized_false_cert, stable_sanitized_false_exit_code = run(
            stable_sanitized_false_settings
        )
        assert stable_sanitized_false_exit_code == 1, stable_sanitized_false_cert
        stable_sanitized_false_row = matrix_row_by_id(
            stable_sanitized_false_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_sanitized_false_row["status"] == "fail", stable_sanitized_false_row
        assert stable_sanitized_false_row["releaseBlocker"] is True, (
            stable_sanitized_false_row
        )

        stable_sensitive_stored_summary = (
            workspace / "build/stable-readiness-sensitive-stored.json"
        )
        stable_sensitive_stored_value = stable_self_test_summary()
        for entry in stable_sensitive_stored_value["evidence"]:
            if isinstance(entry, dict) and entry.get("id") == "stable-1.0.redaction":
                entry["details"] = {"privateInsertUrisStored": True}
                break
        else:
            raise AssertionError("Stable self-test summary is missing stable-1.0.redaction")
        write_json(stable_sensitive_stored_summary, stable_sensitive_stored_value)
        stable_sensitive_stored_items = stable_readiness_evidence(
            stable_sensitive_stored_summary,
            True,
            workspace,
            out_dir,
        )
        stable_sensitive_stored_statuses = {
            item.id: item.status for item in stable_sensitive_stored_items
        }
        assert stable_sensitive_stored_statuses["stable-1.0.readiness-gate"] == "fail", (
            stable_sensitive_stored_statuses
        )
        assert stable_sensitive_stored_statuses["stable-1.0.redaction"] == "fail", (
            stable_sensitive_stored_statuses
        )
        stable_sensitive_stored_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-sensitive-stored-cert").resolve(),
            stable_readiness_summary=stable_sensitive_stored_summary,
            stable_readiness_required=True,
        )
        stable_sensitive_stored_cert, stable_sensitive_stored_exit_code = run(
            stable_sensitive_stored_settings
        )
        assert stable_sensitive_stored_exit_code == 1, stable_sensitive_stored_cert
        stable_sensitive_stored_row = matrix_row_by_id(
            stable_sensitive_stored_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_sensitive_stored_row["status"] == "fail", stable_sensitive_stored_row
        assert stable_sensitive_stored_row["releaseBlocker"] is True, (
            stable_sensitive_stored_row
        )

        stable_missing_schema_summary = workspace / "build/stable-readiness-missing-schema-version.json"
        write_json(
            stable_missing_schema_summary,
            {
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ready", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_missing_schema_items = stable_readiness_evidence(
            stable_missing_schema_summary,
            True,
            workspace,
            out_dir,
        )
        stable_missing_schema_statuses = {item.id: item.status for item in stable_missing_schema_items}
        assert stable_missing_schema_statuses["stable-1.0.readiness-gate"] == "fail", stable_missing_schema_statuses
        stable_missing_schema_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-missing-schema-cert").resolve(),
            stable_readiness_summary=stable_missing_schema_summary,
            stable_readiness_required=True,
        )
        stable_missing_schema_cert, stable_missing_schema_exit_code = run(stable_missing_schema_settings)
        assert stable_missing_schema_exit_code == 1, stable_missing_schema_cert
        stable_missing_schema_row = matrix_row_by_id(stable_missing_schema_settings.out_dir, "stable-1-0-readiness")
        assert stable_missing_schema_row["status"] == "fail", stable_missing_schema_row
        assert stable_missing_schema_row["releaseBlocker"] is True, stable_missing_schema_row
        assert "evidence.stable-1.0.readiness-gate" in stable_missing_schema_row["issueIds"], stable_missing_schema_row
        assert "matrix.stable-readiness.evidence-not-passing" in stable_missing_schema_row["issueIds"], stable_missing_schema_row

        stable_invalid_decision_summary = workspace / "build/stable-readiness-invalid-decision.json"
        write_json(
            stable_invalid_decision_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ship-it",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ship-it", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_invalid_decision_items = stable_readiness_evidence(
            stable_invalid_decision_summary,
            True,
            workspace,
            out_dir,
        )
        stable_invalid_decision_statuses = {
            item.id: item.status for item in stable_invalid_decision_items
        }
        assert stable_invalid_decision_statuses["stable-1.0.readiness-gate"] == "fail", (
            stable_invalid_decision_statuses
        )
        stable_invalid_decision_details = next(
            item.details
            for item in stable_invalid_decision_items
            if item.id == "stable-1.0.readiness-gate"
        )
        assert stable_invalid_decision_details["validationErrors"] == [
            "decision must be ready, ready-with-allowed-limitations, or not-ready"
        ], stable_invalid_decision_details
        stable_invalid_decision_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-invalid-decision-cert").resolve(),
            stable_readiness_summary=stable_invalid_decision_summary,
            stable_readiness_required=True,
        )
        stable_invalid_decision_cert, stable_invalid_decision_exit_code = run(
            stable_invalid_decision_settings
        )
        assert stable_invalid_decision_exit_code == 1, stable_invalid_decision_cert
        stable_invalid_decision_row = matrix_row_by_id(
            stable_invalid_decision_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_invalid_decision_row["status"] == "fail", stable_invalid_decision_row
        assert stable_invalid_decision_row["releaseBlocker"] is True, stable_invalid_decision_row
        assert "evidence.stable-1.0.readiness-gate" in stable_invalid_decision_row["issueIds"], (
            stable_invalid_decision_row
        )
        assert "matrix.stable-readiness.evidence-not-passing" in stable_invalid_decision_row["issueIds"], (
            stable_invalid_decision_row
        )

        stable_remaining_blockers_summary = workspace / "build/stable-readiness-remaining-blockers.json"
        write_json(
            stable_remaining_blockers_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 1,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 1,
                "domains": stable_self_test_passing_domains(),
                "blockers": [
                    {
                        "id": "stable-self-test-blocker",
                        "evidenceId": "stable-1.0.test",
                    }
                ],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [
                    {
                        "id": "stable-self-test-disallowed",
                    }
                ],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ready", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_remaining_items = stable_readiness_evidence(
            stable_remaining_blockers_summary,
            True,
            workspace,
            out_dir,
        )
        stable_remaining_statuses = {item.id: item.status for item in stable_remaining_items}
        assert stable_remaining_statuses["stable-1.0.readiness-gate"] == "fail", stable_remaining_statuses
        stable_remaining_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-remaining-blockers-cert").resolve(),
            stable_readiness_summary=stable_remaining_blockers_summary,
            stable_readiness_required=True,
        )
        stable_remaining_cert, stable_remaining_exit_code = run(stable_remaining_settings)
        assert stable_remaining_exit_code == 1, stable_remaining_cert
        stable_remaining_row = matrix_row_by_id(stable_remaining_settings.out_dir, "stable-1-0-readiness")
        assert stable_remaining_row["status"] == "fail", stable_remaining_row
        assert stable_remaining_row["releaseBlocker"] is True, stable_remaining_row
        assert "evidence.stable-1.0.readiness-gate" in stable_remaining_row["issueIds"], stable_remaining_row
        assert "matrix.stable-readiness.evidence-not-passing" in stable_remaining_row["issueIds"], stable_remaining_row

        stable_fractional_remaining_counts_summary = (
            workspace / "build/stable-readiness-fractional-remaining-counts.json"
        )
        write_json(
            stable_fractional_remaining_counts_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0.5,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0.5,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ready", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_fractional_remaining_count_items = stable_readiness_evidence(
            stable_fractional_remaining_counts_summary,
            True,
            workspace,
            out_dir,
        )
        stable_fractional_remaining_count_statuses = {
            item.id: item.status for item in stable_fractional_remaining_count_items
        }
        assert stable_fractional_remaining_count_statuses["stable-1.0.readiness-gate"] == "fail", (
            stable_fractional_remaining_count_statuses
        )
        stable_fractional_remaining_count_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-fractional-remaining-counts-cert").resolve(),
            stable_readiness_summary=stable_fractional_remaining_counts_summary,
            stable_readiness_required=True,
        )
        stable_fractional_remaining_count_cert, stable_fractional_remaining_count_exit_code = run(
            stable_fractional_remaining_count_settings
        )
        assert stable_fractional_remaining_count_exit_code == 1, stable_fractional_remaining_count_cert
        stable_fractional_remaining_count_row = matrix_row_by_id(
            stable_fractional_remaining_count_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_fractional_remaining_count_row["status"] == "fail", (
            stable_fractional_remaining_count_row
        )
        assert stable_fractional_remaining_count_row["releaseBlocker"] is True, (
            stable_fractional_remaining_count_row
        )
        assert "evidence.stable-1.0.readiness-gate" in stable_fractional_remaining_count_row["issueIds"], (
            stable_fractional_remaining_count_row
        )

        stable_blocker_records_summary = workspace / "build/stable-readiness-blocker-records.json"
        write_json(
            stable_blocker_records_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [
                    {
                        "id": "stable-self-test-blocker",
                        "evidenceId": "stable-1.0.readiness-gate",
                    }
                ],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [
                    {
                        "id": "stable-self-test-disallowed",
                    }
                ],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ready", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_blocker_record_items = stable_readiness_evidence(
            stable_blocker_records_summary,
            True,
            workspace,
            out_dir,
        )
        stable_blocker_record_statuses = {
            item.id: item.status for item in stable_blocker_record_items
        }
        assert stable_blocker_record_statuses["stable-1.0.readiness-gate"] == "fail", (
            stable_blocker_record_statuses
        )
        stable_blocker_record_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-blocker-records-cert").resolve(),
            stable_readiness_summary=stable_blocker_records_summary,
            stable_readiness_required=True,
        )
        stable_blocker_record_cert, stable_blocker_record_exit_code = run(stable_blocker_record_settings)
        assert stable_blocker_record_exit_code == 1, stable_blocker_record_cert
        stable_blocker_record_row = matrix_row_by_id(
            stable_blocker_record_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_blocker_record_row["status"] == "fail", stable_blocker_record_row
        assert stable_blocker_record_row["releaseBlocker"] is True, stable_blocker_record_row
        assert "evidence.stable-1.0.readiness-gate" in stable_blocker_record_row["issueIds"], (
            stable_blocker_record_row
        )
        assert "matrix.stable-readiness.evidence-not-passing" in stable_blocker_record_row["issueIds"], (
            stable_blocker_record_row
        )

        stable_allowed_record_summary = workspace / "build/stable-readiness-allowed-records.json"
        write_json(
            stable_allowed_record_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [
                    {
                        "id": "stable-self-test-allowed",
                        "title": "Self-test allowed Stable limitation",
                        "category": "ui-polish-accessibility-warning",
                        "classification": "allowed-for-stable-1.0",
                        "status": "open",
                        "summary": "Synthetic bounded Stable 1.0 limitation.",
                        "evidenceIds": ["stable-1.0.known-limitations"],
                        "boundedBy": "Self-test release manager bound for a non-blocking Stable limitation.",
                    }
                ],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ready", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_allowed_record_items = stable_readiness_evidence(
            stable_allowed_record_summary,
            True,
            workspace,
            out_dir,
        )
        stable_allowed_record_gate = next(
            item
            for item in stable_allowed_record_items
            if item.id == "stable-1.0.readiness-gate"
        )
        assert stable_allowed_record_gate.status == "fail", stable_allowed_record_gate
        assert stable_allowed_record_gate.details["validationErrors"] == [
            "allowedLimitationCount is 0 but allowedLimitations contains 1"
        ], stable_allowed_record_gate.details
        stable_allowed_record_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-allowed-records-cert").resolve(),
            stable_readiness_summary=stable_allowed_record_summary,
            stable_readiness_required=True,
        )
        stable_allowed_record_cert, stable_allowed_record_exit_code = run(
            stable_allowed_record_settings
        )
        assert stable_allowed_record_exit_code == 1, stable_allowed_record_cert
        stable_allowed_record_row = matrix_row_by_id(
            stable_allowed_record_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_allowed_record_row["status"] == "fail", stable_allowed_record_row
        assert stable_allowed_record_row["releaseBlocker"] is True, stable_allowed_record_row
        assert "evidence.stable-1.0.readiness-gate" in stable_allowed_record_row["issueIds"], (
            stable_allowed_record_row
        )
        assert "matrix.stable-readiness.evidence-not-passing" in stable_allowed_record_row["issueIds"], (
            stable_allowed_record_row
        )

        stable_malformed_allowed_record_summary = workspace / "build/stable-readiness-malformed-allowed-records.json"
        write_json(
            stable_malformed_allowed_record_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready-with-allowed-limitations",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 1,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [1],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ready-with-allowed-limitations", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_malformed_allowed_record_items = stable_readiness_evidence(
            stable_malformed_allowed_record_summary,
            True,
            workspace,
            out_dir,
        )
        stable_malformed_allowed_record_gate = next(
            item
            for item in stable_malformed_allowed_record_items
            if item.id == "stable-1.0.readiness-gate"
        )
        assert stable_malformed_allowed_record_gate.status == "fail", stable_malformed_allowed_record_gate
        assert stable_malformed_allowed_record_gate.details["validationErrors"] == [
            "allowedLimitations[0] must be an object"
        ], stable_malformed_allowed_record_gate.details
        stable_malformed_allowed_record_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-malformed-allowed-records-cert").resolve(),
            stable_readiness_summary=stable_malformed_allowed_record_summary,
            stable_readiness_required=True,
        )
        stable_malformed_allowed_record_cert, stable_malformed_allowed_record_exit_code = run(
            stable_malformed_allowed_record_settings
        )
        assert stable_malformed_allowed_record_exit_code == 1, stable_malformed_allowed_record_cert
        stable_malformed_allowed_record_row = matrix_row_by_id(
            stable_malformed_allowed_record_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_malformed_allowed_record_row["status"] == "fail", stable_malformed_allowed_record_row
        assert stable_malformed_allowed_record_row["releaseBlocker"] is True, stable_malformed_allowed_record_row
        assert "evidence.stable-1.0.readiness-gate" in stable_malformed_allowed_record_row["issueIds"], (
            stable_malformed_allowed_record_row
        )
        assert "matrix.stable-readiness.evidence-not-passing" in stable_malformed_allowed_record_row["issueIds"], (
            stable_malformed_allowed_record_row
        )

        stable_allowed_warning_summary = workspace / "build/stable-readiness-allowed-warning.json"
        write_json(
            stable_allowed_warning_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 1,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [
                    {
                        "id": "stable-self-test-allowed",
                        "title": "Self-test allowed Stable limitation",
                        "category": "ui-polish-accessibility-warning",
                        "classification": "allowed-for-stable-1.0",
                        "status": "open",
                        "summary": "Synthetic bounded Stable 1.0 limitation.",
                        "evidenceIds": ["stable-1.0.known-limitations"],
                        "boundedBy": "Self-test release manager bound for a non-blocking Stable limitation.",
                    }
                ],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ready", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                ],
            },
        )
        stable_allowed_warning_items = stable_readiness_evidence(
            stable_allowed_warning_summary,
            True,
            workspace,
            out_dir,
        )
        stable_allowed_warning_gate = next(
            item
            for item in stable_allowed_warning_items
            if item.id == "stable-1.0.readiness-gate"
        )
        assert stable_allowed_warning_gate.status == "warn", stable_allowed_warning_gate
        stable_allowed_warning_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-allowed-warning-cert").resolve(),
            stable_readiness_summary=stable_allowed_warning_summary,
            stable_readiness_required=True,
        )
        stable_allowed_warning_cert, stable_allowed_warning_exit_code = run(
            stable_allowed_warning_settings
        )
        assert stable_allowed_warning_exit_code == 0, stable_allowed_warning_cert
        stable_allowed_warning_row = matrix_row_by_id(
            stable_allowed_warning_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_allowed_warning_row["status"] == "warn", stable_allowed_warning_row
        assert stable_allowed_warning_row["releaseBlocker"] is False, stable_allowed_warning_row

        stable_extra_redaction_summary = workspace / "build/stable-readiness-extra-evidence-redaction.json"
        write_json(
            stable_extra_redaction_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    *[
                        {
                            "id": evidence_id,
                            "status": "pass",
                            "summary": f"{evidence_id} passed.",
                            "details": {"decision": "ready", "stableReady": True}
                            if evidence_id == "stable-1.0.readiness-gate"
                            else {},
                        }
                        for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                    ],
                    {
                        "id": "stable-1.0.extra-redaction-fixture",
                        "status": "pass",
                        "summary": "Synthetic extra Stable evidence row with redaction findings.",
                        "details": {
                            "redactionFindings": [
                                {
                                    "kind": "stable-readiness-fixture",
                                    "summary": "Synthetic extra Stable evidence redaction finding.",
                                }
                            ]
                        },
                    },
                ],
            },
        )
        stable_extra_redaction_items = stable_readiness_evidence(
            stable_extra_redaction_summary,
            True,
            workspace,
            out_dir,
        )
        stable_extra_redaction_statuses = {
            item.id: item.status for item in stable_extra_redaction_items
        }
        assert stable_extra_redaction_statuses["stable-1.0.readiness-gate"] == "fail", (
            stable_extra_redaction_statuses
        )
        assert stable_extra_redaction_statuses["stable-1.0.redaction"] == "fail", (
            stable_extra_redaction_statuses
        )
        stable_extra_redaction_details = next(
            item.details
            for item in stable_extra_redaction_items
            if item.id == "stable-1.0.redaction"
        )
        assert stable_extra_redaction_details["validationErrors"] == [
            "evidence rows contain redaction findings: stable-1.0.extra-redaction-fixture"
        ], stable_extra_redaction_details
        stable_extra_redaction_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-extra-evidence-redaction-cert").resolve(),
            stable_readiness_summary=stable_extra_redaction_summary,
            stable_readiness_required=True,
        )
        stable_extra_redaction_cert, stable_extra_redaction_exit_code = run(
            stable_extra_redaction_settings
        )
        assert stable_extra_redaction_exit_code == 1, stable_extra_redaction_cert
        stable_extra_redaction_row = matrix_row_by_id(
            stable_extra_redaction_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_extra_redaction_row["status"] == "fail", stable_extra_redaction_row
        assert stable_extra_redaction_row["releaseBlocker"] is True, stable_extra_redaction_row
        assert "evidence.stable-1.0.redaction" in stable_extra_redaction_row["issueIds"], (
            stable_extra_redaction_row
        )
        assert "matrix.stable-readiness.redaction-failed" in stable_extra_redaction_row["issueIds"], (
            stable_extra_redaction_row
        )

        stable_extra_status_redaction_summary = (
            workspace / "build/stable-readiness-extra-evidence-status-redaction.json"
        )
        write_json(
            stable_extra_status_redaction_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    *[
                        {
                            "id": evidence_id,
                            "status": "pass",
                            "summary": f"{evidence_id} passed.",
                            "details": {"decision": "ready", "stableReady": True}
                            if evidence_id == "stable-1.0.readiness-gate"
                            else {},
                        }
                        for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                    ],
                    {
                        "id": "stable-1.0.extra-status-redaction-fixture",
                        "status": "pass",
                        "summary": "Synthetic extra Stable evidence row with failed redaction status.",
                        "details": {"redaction": {"status": "fail"}},
                    },
                ],
            },
        )
        stable_extra_status_redaction_items = stable_readiness_evidence(
            stable_extra_status_redaction_summary,
            True,
            workspace,
            out_dir,
        )
        stable_extra_status_redaction_statuses = {
            item.id: item.status for item in stable_extra_status_redaction_items
        }
        assert stable_extra_status_redaction_statuses["stable-1.0.readiness-gate"] == "fail", (
            stable_extra_status_redaction_statuses
        )
        assert stable_extra_status_redaction_statuses["stable-1.0.redaction"] == "fail", (
            stable_extra_status_redaction_statuses
        )
        stable_extra_status_redaction_details = next(
            item.details
            for item in stable_extra_status_redaction_items
            if item.id == "stable-1.0.redaction"
        )
        assert stable_extra_status_redaction_details["validationErrors"] == [
            "evidence rows contain redaction findings: stable-1.0.extra-status-redaction-fixture"
        ], stable_extra_status_redaction_details
        stable_extra_status_redaction_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-extra-evidence-status-redaction-cert").resolve(),
            stable_readiness_summary=stable_extra_status_redaction_summary,
            stable_readiness_required=True,
        )
        stable_extra_status_redaction_cert, stable_extra_status_redaction_exit_code = run(
            stable_extra_status_redaction_settings
        )
        assert stable_extra_status_redaction_exit_code == 1, stable_extra_status_redaction_cert
        stable_extra_status_redaction_row = matrix_row_by_id(
            stable_extra_status_redaction_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_extra_status_redaction_row["status"] == "fail", (
            stable_extra_status_redaction_row
        )
        assert stable_extra_status_redaction_row["releaseBlocker"] is True, (
            stable_extra_status_redaction_row
        )
        assert "evidence.stable-1.0.redaction" in stable_extra_status_redaction_row["issueIds"], (
            stable_extra_status_redaction_row
        )
        assert "matrix.stable-readiness.redaction-failed" in stable_extra_status_redaction_row["issueIds"], (
            stable_extra_status_redaction_row
        )

        stable_duplicate_evidence_summary = workspace / "build/stable-readiness-duplicate-evidence.json"
        stable_duplicate_evidence_rows = [
            {
                "id": evidence_id,
                "status": "pass",
                "summary": f"{evidence_id} passed.",
                "details": {"decision": "ready", "stableReady": True}
                if evidence_id == "stable-1.0.readiness-gate"
                else {},
            }
            for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
        ]
        for index, entry in enumerate(stable_duplicate_evidence_rows):
            if entry["id"] == "stable-1.0.security-drills":
                stable_duplicate_evidence_rows.insert(
                    index,
                    {
                        "id": "stable-1.0.security-drills",
                        "status": "fail",
                        "summary": "Synthetic failed duplicate Stable security drills evidence.",
                        "details": {},
                    },
                )
                break
        else:
            raise AssertionError("stable-1.0.security-drills evidence missing from self-test fixture")
        write_json(
            stable_duplicate_evidence_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": stable_duplicate_evidence_rows,
            },
        )
        stable_duplicate_items = stable_readiness_evidence(
            stable_duplicate_evidence_summary,
            True,
            workspace,
            out_dir,
        )
        stable_duplicate_statuses = {item.id: item.status for item in stable_duplicate_items}
        assert stable_duplicate_statuses["stable-1.0.readiness-gate"] == "fail", (
            stable_duplicate_statuses
        )
        assert stable_duplicate_statuses["stable-1.0.security-drills"] == "fail", (
            stable_duplicate_statuses
        )
        stable_duplicate_details = next(
            item.details
            for item in stable_duplicate_items
            if item.id == "stable-1.0.readiness-gate"
        )
        assert stable_duplicate_details["validationErrors"] == [
            "evidence contains duplicate required IDs: stable-1.0.security-drills"
        ], stable_duplicate_details
        stable_duplicate_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-duplicate-evidence-cert").resolve(),
            stable_readiness_summary=stable_duplicate_evidence_summary,
            stable_readiness_required=True,
        )
        stable_duplicate_cert, stable_duplicate_exit_code = run(stable_duplicate_settings)
        assert stable_duplicate_exit_code == 1, stable_duplicate_cert
        stable_duplicate_row = matrix_row_by_id(stable_duplicate_settings.out_dir, "stable-1-0-readiness")
        assert stable_duplicate_row["status"] == "fail", stable_duplicate_row
        assert stable_duplicate_row["releaseBlocker"] is True, stable_duplicate_row
        assert "evidence.stable-1.0.security-drills" in stable_duplicate_row["issueIds"], stable_duplicate_row
        assert "matrix.stable-readiness.evidence-not-passing" in stable_duplicate_row["issueIds"], (
            stable_duplicate_row
        )

        for omitted_stable_evidence_id in (
            "stable-1.0.readiness-gate",
            "stable-1.0.redaction",
        ):
            stable_missing_compact_row_summary = (
                workspace
                / "build"
                / f"stable-readiness-missing-{omitted_stable_evidence_id.replace('.', '-')}.json"
            )
            write_json(
                stable_missing_compact_row_summary,
                stable_self_test_summary(
                    omitted_evidence_ids={omitted_stable_evidence_id},
                ),
            )
            stable_missing_compact_items = stable_readiness_evidence(
                stable_missing_compact_row_summary,
                True,
                workspace,
                out_dir,
            )
            stable_missing_compact_statuses = {
                item.id: item.status for item in stable_missing_compact_items
            }
            expected_missing_compact_status = (
                "fail"
                if omitted_stable_evidence_id == "stable-1.0.readiness-gate"
                else "missing"
            )
            assert stable_missing_compact_statuses[omitted_stable_evidence_id] == expected_missing_compact_status, (
                omitted_stable_evidence_id,
                stable_missing_compact_statuses,
            )
            stable_missing_compact_details = next(
                item.details
                for item in stable_missing_compact_items
                if item.id == omitted_stable_evidence_id
            )
            assert (
                f"{omitted_stable_evidence_id} is missing from stable readiness evidence"
                in stable_missing_compact_details["validationErrors"]
            ), stable_missing_compact_details
            if omitted_stable_evidence_id != "stable-1.0.readiness-gate":
                assert stable_missing_compact_statuses["stable-1.0.readiness-gate"] == "fail", (
                    omitted_stable_evidence_id,
                    stable_missing_compact_statuses,
                )

        stable_truncated_summary = workspace / "build/stable-readiness-truncated.json"
        write_json(
            stable_truncated_summary,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-readiness",
                "releaseId": "cryptad-production-beta-self-test",
                "status": "pass",
                "decision": "ready",
                "stableReady": True,
                "blockerCount": 0,
                "warningCount": 0,
                "allowedLimitationCount": 0,
                "disallowedLimitationCount": 0,
                "domains": stable_self_test_passing_domains(),
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
                "disallowedLimitations": [],
                "redaction": {"status": "pass", "findings": []},
                "evidence": [
                    {
                        "id": evidence_id,
                        "status": "pass",
                        "summary": f"{evidence_id} passed.",
                        "details": {"decision": "ready", "stableReady": True}
                        if evidence_id == "stable-1.0.readiness-gate"
                        else {},
                    }
                    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
                    if evidence_id != "stable-1.0.security-drills"
                ],
            },
        )
        stable_truncated_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/stable-truncated-cert").resolve(),
            stable_readiness_summary=stable_truncated_summary,
            stable_readiness_required=True,
            waivers={
                "stable-1-0-readiness": "Attempted row waiver for truncated Stable evidence.",
                "matrix.stable-readiness.evidence-not-passing": (
                    "Attempted matrix waiver for truncated Stable evidence."
                ),
            },
        )
        stable_truncated_cert, stable_truncated_exit_code = run(stable_truncated_settings)
        assert stable_truncated_exit_code == 1, stable_truncated_cert
        stable_truncated_row = matrix_row_by_id(
            stable_truncated_settings.out_dir,
            "stable-1-0-readiness",
        )
        assert stable_truncated_row["status"] == "fail", stable_truncated_row
        assert stable_truncated_row["releaseBlocker"] is True, stable_truncated_row
        assert stable_truncated_row.get("waiverIds") == [], stable_truncated_row
        assert "evidence.stable-1.0.security-drills" in stable_truncated_row[
            "issueIds"
        ], stable_truncated_row
        assert "matrix.stable-readiness.evidence-not-passing" in stable_truncated_row[
            "issueIds"
        ], stable_truncated_row
        assert stable_truncated_row["details"]["unwaivableIssueIds"] == [
            "matrix.stable-readiness.evidence-not-passing"
        ], stable_truncated_row


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        run_self_test(Path(__file__).resolve().parents[2])
        print("release-certification self-test passed")
        return 0
    settings = settings_from_args(args)
    summary, exit_code = run(settings)
    print(f"Release certification {summary['status']}: {settings.out_dir / REPORT_FILE_NAME}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
