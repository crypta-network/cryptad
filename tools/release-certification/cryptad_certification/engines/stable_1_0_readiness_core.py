"""Implementation segment for the core portion of ``stable_1_0_readiness.py``."""

from __future__ import annotations

import argparse

import copy

import dataclasses

import datetime as dt

import hashlib

import json

import math

import sys

import tempfile

from pathlib import Path

from typing import Any, Callable, Iterable

sys.dont_write_bytecode = True

TOOL_DIR = Path(__file__).resolve().parent

REPO_ROOT = TOOL_DIR.parents[1]

sys.path.insert(0, str(TOOL_DIR))

from cryptad_certification.engines import production_beta_go_no_go_dashboard as dashboard  # noqa: E402

from cryptad_certification.engines import multi_node_beta_soak  # noqa: E402

from cryptad_certification.engines import release_certification as certification  # noqa: E402

TOOL_NAME = "stable-1.0-readiness"

SCHEMA_VERSION = 1

DEFAULT_OUT_DIR = Path("build/stable-1.0-readiness")

DEFAULT_POLICY = TOOL_DIR / "stable-1.0-readiness-policy.json"

DEFAULT_LIMITATIONS = TOOL_DIR / "stable-1.0-known-limitations.json"

DEFAULT_PUBLIC_BETA_KNOWN_ISSUES = TOOL_DIR / "public-beta-known-issues.json"

FIXTURE_DIR = TOOL_DIR / "fixtures"

DEFAULT_GENERATED_AT = "1970-01-01T00:00:00Z"

SELF_TEST_VALIDATION_TIME = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)

ECOSYSTEM_MATRIX_REQUIRED_ROW_IDS = tuple(
    spec.id for spec in certification.ecosystem_matrix_row_specs()
)

SUMMARY_FILE = "stable-1.0-readiness-summary.json"

REPORT_FILE = "stable-1.0-readiness-report.md"

KNOWN_LIMITATIONS_FILE = "stable-1.0-known-limitations.json"

BLOCKERS_FILE = "stable-1.0-blockers.json"

PRODUCTION_BETA_REQUIRED_PIPELINE_STAGES = (
    "crypta-app-launcher-install",
    "gradle-full-build",
    "first-party-app-staging",
    "first-party-app-signing",
    "first-party-app-verification",
)

PRODUCTION_BETA_REQUIRED_PROMOTION_GATES = (
    "build.production-beta-complete",
    "workspace.clean-production-beta",
    "signing.production-keys",
)

PRODUCTION_BETA_REQUIRED_ARTIFACTS = (
    "redactionReport",
)

GO_NO_GO_SUMMARY_COUNT_FIELDS = (
    "blockers",
    "warnings",
    "waiversUsed",
    "criticalRedactionFindings",
    "criticalFindings",
)

GO_NO_GO_DOMAIN_IDS = tuple(str(spec["id"]) for spec in dashboard.DOMAIN_SPECS)

APP_IDS = (
    "queue-manager",
    "publisher",
    "site-publisher",
    "feed-reader",
    "profile-publisher",
    "trust-graph",
    "social-inbox",
)

PLATFORM_API_EVIDENCE_IDS = (
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

APP_ECOSYSTEM_EVIDENCE_IDS = (
    "app-platform.first-party",
    "app-platform.signed-bundles",
    "catalog.smoke",
    "catalog.production-channels",
    "catalog.operations-and-mirrors",
    "app-review.trusted-receipts",
    "app-review.first-party-catalog",
    "app-review.first-party-review-chain",
    "app-catalog.first-party-maintenance-policy",
    "first-party-app.beta-quality-pass",
    "app-data.backup-restore-portability",
    "app-update.data-migration-contract",
    "app-platform.privacy-preserving-beta-diagnostics",
)

THIRD_PARTY_EVIDENCE_IDS = (
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
    "third-party-developer.docs",
    "third-party-developer.sample-app-flow",
    "third-party-developer.compatibility-window",
    "third-party-developer.plugin-author-migration",
    "third-party-developer.redaction",
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

THIRD_PARTY_SAMPLE_FLOW_MILESTONES = (
    "pre review",
    "reviewed decision",
    "catalog candidate",
)

SECURITY_RESPONSE_EVIDENCE_IDS = (
    "catalog.security-advisories",
    "catalog.version-denylist",
    "app-review.receipt-revocation",
    "app-review.reviewer-key-compromise-flow",
    "app-update.security-denylist-gates",
    "production-security.response-runbook",
)

SECURITY_DRILL_RELEASE_MODES = ("production-beta", "release-candidate")

NETWORK_SCALE_EVIDENCE_IDS = (
    "network-scale.app-network-budget",
    "network-scale.content-fetch-budget",
    "network-scale.subscription-budget",
    "network-scale.queue-pressure-backoff",
    "network-scale.trust-graph-import-budget",
    "network-scale.social-inbox-multi-source-soak",
    "network-scale.redaction",
)

LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS = (
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

NETWORK_SCALE_REDACTION_PROOF_FIELDS = (
    "rawFetchedContentExcluded",
    "privateInsertUrisExcluded",
    "tokensExcluded",
    "absolutePathsExcluded",
    "queueHtmlExcluded",
)

NETWORK_SCALE_REQUIRED_APPS = ("social-inbox", "feed-reader")

NETWORK_SCALE_BUDGET_PROOF_FIELDS = (
    "globalFetchBudgetEnforced",
    "perAppFetchBudgetEnforced",
    "concurrencyLeasesReleased",
)

AUDITABLE_LIMITATION_REQUIRED_STRING_FIELDS = (
    "id",
    "title",
    "category",
    "classification",
    "status",
    "summary",
    "boundedBy",
)

MULTI_NODE_SCENARIO_EVIDENCE_IDS = (
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

LEGACY_EVIDENCE_IDS = (
    "legacy-plugin.freeze-policy",
    "legacy-plugin.migration-finalization",
    "legacy-admin.removal-wave-5",
    "legacy-admin.final-admin-surface",
    "legacy-admin.browse-retained",
    "legacy-admin.emergency-fallback-retained",
)

SUPPORT_FEEDBACK_EVIDENCE_IDS = (
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

APP_PLATFORM_DIRECT_EVIDENCE_IDS = tuple(
    dict.fromkeys(
        (
            *PLATFORM_API_EVIDENCE_IDS,
            *APP_ECOSYSTEM_EVIDENCE_IDS,
            *THIRD_PARTY_EVIDENCE_IDS,
            *SECURITY_RESPONSE_EVIDENCE_IDS,
            *NETWORK_SCALE_EVIDENCE_IDS,
            *LEGACY_EVIDENCE_IDS,
            *SUPPORT_FEEDBACK_EVIDENCE_IDS,
        )
    )
)

KNOWN_ISSUE_REQUIRED_FIELDS = (
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

KNOWN_ISSUE_REQUIRED_LIST_FIELDS = (
    "affectedChannels",
    "affectedAppIds",
    "affectedVersions",
)

KNOWN_ISSUE_REQUIRED_STRING_FIELDS = tuple(
    field for field in KNOWN_ISSUE_REQUIRED_FIELDS if field not in KNOWN_ISSUE_REQUIRED_LIST_FIELDS
)

DOC_PATHS = (
    "docs/stable-1.0-readiness-gate.md",
    "docs/stable-1.0-known-limitations.md",
    "docs/production-beta-go-no-go-dashboard.md",
    "docs/production-beta-release-pipeline.md",
    "docs/release-certification.md",
    "docs/public-beta/README.md",
    "docs/templates/beta-release-notes.md",
)

STABLE_EVIDENCE_IDS = (
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

RELEASE_CERTIFICATION_REDACTION_BOOL_FIELDS = (
    "secretMaterialRedacted",
    "formPasswordsRedacted",
    "rawFeedBodiesExcluded",
    "rawRequestBodiesExcluded",
    "privateInsertUrisExcluded",
    "appProcessTokensRedacted",
    "browserSessionTokensRedacted",
    "signatureValuesRedacted",
    "rawUpdateRollbackOutputsExcluded",
    "absolutePathsSanitized",
)

RELEASE_CERTIFICATION_REDACTION_STATUS_FIELDS = (
    "status",
    "findingCount",
    "findings",
)

@dataclasses.dataclass(frozen=True)
class Settings:
    workspace_root: Path
    out_dir: Path
    generated_at: str
    production_beta_summary: Path | None
    go_no_go_summary: Path | None
    release_certification_summary: Path | None
    ecosystem_matrix: Path | None
    app_platform_summary: Path | None
    multi_node_soak_summary: Path | None
    network_scale_soak_summary: Path | None
    security_drills_summary: Path | None
    public_beta_known_issues: Path | None
    policy: Path
    stable_known_limitations: Path
    waivers: Path | None

@dataclasses.dataclass(frozen=True)
class StableWaiver:
    id: str
    evidence_id: str
    scope: str
    status: str
    rationale: str
    approved_by: str
    owner: str
    expires_at: str
    references: tuple[str, ...]
    active: bool
    validation_errors: tuple[str, ...]
    source: str

    def matches(self, *targets: str) -> bool:
        target_set = {target for target in targets if target}
        return self.id in target_set or self.evidence_id in target_set

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "evidenceId": self.evidence_id,
            "scope": self.scope,
            "status": self.status,
            "rationale": self.rationale,
            "approvedBy": self.approved_by,
            "owner": self.owner,
            "expiresAt": self.expires_at,
            "references": list(self.references),
            "active": self.active,
            "validationErrors": list(self.validation_errors),
            "source": self.source,
        }

def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def read_json(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None

def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")

def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"

def parse_generated_at(value: str) -> str:
    return value.strip() if value else utc_now()

def resolve_path(workspace_root: Path, path: Path | None) -> Path | None:
    if path is None:
        return None
    return path.resolve() if path.is_absolute() else (workspace_root / path).resolve()

def display_path(path: Path, workspace_root: Path) -> str:
    return dashboard.display_path(path, workspace_root)

def input_reference(path: Path | None, workspace_root: Path) -> dict[str, Any]:
    if path is None:
        return {"status": "not-provided"}
    value: dict[str, Any] = {
        "status": "present" if path.is_file() else "missing",
        "path": display_path(path, workspace_root),
        "basename": path.name,
    }
    if path.is_file():
        value["sha256"] = sha256_file(path)
    return value

def normalize_status(value: Any) -> str:
    return dashboard.normalize_status(value)

def status_ok(value: Any) -> bool:
    return normalize_status(value) == "pass"

def positive_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text or not text.isdigit():
            return None
        parsed = int(text)
    else:
        return None
    return parsed if parsed > 0 else None

def strict_positive_int(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None

def strict_non_negative_int(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None

def non_negative_count(value: Any, default: int = 0) -> tuple[int, bool]:
    if value is None or value == "":
        return default, False
    if isinstance(value, bool):
        return default, True
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text or not text.isdigit():
            return default, True
        parsed = int(text)
    else:
        return default, True
    if parsed < 0:
        return default, True
    return parsed, False

def missing_true_fields(value: Any, fields: Iterable[str]) -> list[str]:
    if not isinstance(value, dict):
        return list(fields)
    return [field for field in fields if value.get(field) is not True]

def non_empty_string(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""

def schema_version_is_current(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == SCHEMA_VERSION

def schema_tool_errors(
    value: dict[str, Any],
    *,
    expected_tool: str,
    evidence_label: str,
) -> list[str]:
    errors: list[str] = []
    if not schema_version_is_current(value.get("schemaVersion")):
        errors.append(f"{evidence_label}.schemaVersion must be {SCHEMA_VERSION}")
    if str(value.get("tool", "missing")) != expected_tool:
        errors.append(f"{evidence_label}.tool must be {expected_tool}")
    return errors

def list_shape_errors(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list):
        return [f"{label} must be a list"]
    if not allow_empty and not value:
        return [f"{label} must not be empty"]
    malformed = [
        str(index)
        for index, item in enumerate(value)
        if not isinstance(item, dict)
    ]
    if malformed:
        return [f"{label} entries must be objects; malformed indexes: {', '.join(malformed)}"]
    return []

def string_array_values(value: Any, label: str, default: Iterable[str]) -> tuple[set[str], list[str]]:
    if value is None:
        return set(default), []
    if not isinstance(value, list):
        return set(default), [f"{label} must be a list"]
    if not value:
        return set(default), [f"{label} must not be empty"]
    malformed = [
        str(index)
        for index, item in enumerate(value)
        if not isinstance(item, str) or not item.strip()
    ]
    if malformed:
        return set(default), [
            f"{label} entries must be non-empty strings; malformed indexes: {', '.join(malformed)}"
        ]
    return {item.strip() for item in value}, []

def policy_string_set(policy: dict[str, Any], key: str) -> set[str]:
    values, _errors = string_array_values(policy.get(key), key, ())
    return values

def release_id_from_beta_version(value: Any) -> str:
    version = non_empty_string(value)
    if not version:
        return ""
    if version.startswith("cryptad-beta-"):
        return version
    safe_version = "".join(
        char if char.isalnum() or char in "._-" else "-"
        for char in version
    ).strip("-")
    return f"cryptad-beta-{safe_version}" if safe_version else ""

def multi_node_candidate_release_ids(summary: dict[str, Any]) -> list[tuple[str, str]]:
    identities: list[tuple[str, str]] = []
    release_id = non_empty_string(summary.get("releaseId"))
    if release_id:
        identities.append(("releaseId", release_id))
    current_candidate = summary.get("currentCandidate")
    if isinstance(current_candidate, dict):
        release_id = non_empty_string(current_candidate.get("releaseId"))
        if release_id:
            identities.append(("currentCandidate.releaseId", release_id))
    if identities:
        return identities
    if isinstance(current_candidate, dict):
        release_id = release_id_from_beta_version(current_candidate.get("version"))
        if release_id:
            identities.append(("currentCandidate.version", release_id))
    return identities

def network_scale_candidate_release_ids(summary: dict[str, Any]) -> list[tuple[str, str]]:
    identities: list[tuple[str, str]] = []
    for key in ("releaseId", "candidateReleaseId"):
        release_id = non_empty_string(summary.get(key))
        if release_id:
            identities.append((key, release_id))
    current_candidate = summary.get("currentCandidate")
    if isinstance(current_candidate, dict):
        release_id = non_empty_string(current_candidate.get("releaseId"))
        if release_id:
            identities.append(("currentCandidate.releaseId", release_id))
        release_id = release_id_from_beta_version(current_candidate.get("version"))
        if release_id:
            identities.append(("currentCandidate.version", release_id))
    return identities

def evidence_age_blocker(
    *,
    domain_id: str,
    evidence_id: str,
    title: str,
    source: str,
    generated_at: Any,
    now: dt.datetime,
    maximum_age_days: int,
    label: str,
) -> dict[str, Any] | None:
    timestamp = str(generated_at).strip() if generated_at is not None else ""
    parsed = dashboard.parse_time(timestamp) if timestamp else None
    if parsed is None:
        return blocker_issue(
            domain_id,
            evidence_id,
            f"{title} timestamp is missing or malformed",
            f"{label} generatedAt must be an ISO-8601 timestamp.",
            source,
        )
    if parsed > now:
        return blocker_issue(
            domain_id,
            evidence_id,
            f"{title} timestamp is in the future",
            f"{label} generatedAt {timestamp} is after readiness generation time {now.isoformat()}.",
            source,
        )
    age_days = (now - parsed).total_seconds() / 86_400
    if age_days > maximum_age_days:
        return blocker_issue(
            domain_id,
            evidence_id,
            f"{title} is stale",
            f"{label} age is {age_days:.1f} days; policy maximum is {maximum_age_days} days.",
            source,
        )
    return None

def stable_slug(value: str) -> str:
    result = []
    for char in value.lower():
        if char.isalnum():
            result.append(char)
        elif result and result[-1] != "-":
            result.append("-")
    return "".join(result).strip("-") or "item"

def issue(
    *,
    issue_id: str,
    evidence_id: str,
    domain_id: str,
    severity: str,
    classification: str,
    title: str,
    summary: str,
    source: str,
    waivable: bool = False,
    remediation: str = "",
    limitation_id: str = "",
) -> dict[str, Any]:
    value = {
        "id": issue_id,
        "evidenceId": evidence_id,
        "domainId": domain_id,
        "severity": severity,
        "classification": classification,
        "title": title,
        "summary": summary,
        "source": source,
        "waivable": waivable,
    }
    if remediation:
        value["remediation"] = remediation
    if limitation_id:
        value["limitationId"] = limitation_id
    return value

def warning_issue(domain_id: str, evidence_id: str, title: str, summary: str, source: str) -> dict[str, Any]:
    return issue(
        issue_id=f"{domain_id}.{stable_slug(evidence_id)}.warning",
        evidence_id=evidence_id,
        domain_id=domain_id,
        severity="warning",
        classification="stable-1.0-warning",
        title=title,
        summary=summary,
        source=source,
        waivable=True,
    )

def propagated_dashboard_warning(
    domain_id: str,
    dashboard_warning: dict[str, Any],
    index: int,
) -> dict[str, Any]:
    source_warning_id = non_empty_string(dashboard_warning.get("id")) or f"warnings[{index}]"
    source_evidence_id = non_empty_string(dashboard_warning.get("evidenceId"))
    title = non_empty_string(dashboard_warning.get("title")) or "Production beta dashboard warning"
    summary = non_empty_string(dashboard_warning.get("summary")) or (
        f"Production beta dashboard warning {source_warning_id} remains open for Stable review."
    )
    value = issue(
        issue_id=f"{domain_id}.go-no-go-warning-{index + 1}",
        evidence_id="stable-1.0.go-no-go-decision",
        domain_id=domain_id,
        severity="warning",
        classification="stable-1.0-warning",
        title=title,
        summary=summary,
        source="go-no-go-summary",
        waivable=True,
    )
    value["sourceWarningId"] = source_warning_id
    if source_evidence_id:
        value["sourceEvidenceId"] = source_evidence_id
    return value

def blocker_issue(
    domain_id: str,
    evidence_id: str,
    title: str,
    summary: str,
    source: str,
    *,
    issue_id: str = "",
    waivable: bool = False,
    remediation: str = "",
    limitation_id: str = "",
) -> dict[str, Any]:
    return issue(
        issue_id=issue_id or f"{domain_id}.{stable_slug(evidence_id)}.blocker",
        evidence_id=evidence_id,
        domain_id=domain_id,
        severity="blocker",
        classification="stable-1.0-blocker",
        title=title,
        summary=summary,
        source=source,
        waivable=waivable,
        remediation=remediation,
        limitation_id=limitation_id,
    )

def domain_result(
    domain_id: str,
    title: str,
    evidence_ids: Iterable[str],
    blockers: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
    allowed_limitations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    allowed = allowed_limitations or []
    if blockers:
        status = "fail"
        summary = blockers[0]["summary"]
    elif warnings or allowed:
        status = "warn"
        summary = warnings[0]["summary"] if warnings else f"{len(allowed)} allowed Stable 1.0 limitation(s) remain."
    else:
        status = "pass"
        summary = "Stable 1.0 domain criteria passed."
    return {
        "id": domain_id,
        "title": title,
        "status": status,
        "summary": summary,
        "evidenceIds": list(evidence_ids),
        "blockers": blockers,
        "warnings": warnings,
        "allowedLimitations": allowed,
    }

def evidence_map_from_summaries(*summaries: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for summary in summaries:
        if not isinstance(summary, dict):
            continue
        entries = summary.get("evidence")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            evidence_id = entry.get("id") or entry.get("evidenceId")
            if not isinstance(evidence_id, str) or not evidence_id:
                continue
            existing = result.get(evidence_id)
            if existing is None or (entry_ok(existing) and not entry_ok(entry)):
                result[evidence_id] = entry
    return result

def stable_evidence_map_from_summaries(
    release_certification: dict[str, Any] | None,
    app_platform: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    direct_app_evidence = evidence_map_from_summaries(app_platform)
    result = evidence_map_from_summaries(app_platform, release_certification)
    for evidence_id in APP_PLATFORM_DIRECT_EVIDENCE_IDS:
        if evidence_id not in direct_app_evidence:
            result.pop(evidence_id, None)
    return result

def app_platform_summary_envelope_blockers(
    summary: dict[str, Any] | None,
    domain_id: str,
) -> list[dict[str, Any]]:
    if not isinstance(summary, dict):
        return [
            blocker_issue(
                domain_id,
                "stable-1.0.app-ecosystem-maturity",
                "App-platform smoke summary envelope is missing",
                "Stable 1.0 requires the direct app-platform smoke summary envelope; "
                "release-certification evidence rows alone are not sufficient.",
                "app-platform-summary",
            )
        ]
    validation_errors = schema_tool_errors(
        summary,
        expected_tool="app-platform-smoke",
        evidence_label="appPlatformSummary",
    )
    status = normalize_status(summary.get("status", "missing"))
    if status != "pass":
        validation_errors.append(f"appPlatformSummary.status must be pass; got {status}")
    mode = non_empty_string(summary.get("mode")) or "missing"
    if mode != "release-candidate":
        validation_errors.append(
            f"appPlatformSummary.mode must be release-candidate; got {mode}"
        )
    for field in ("nonRelease", "nonProduction", "fixtureOnly"):
        if field in summary and summary.get(field) is not False:
            validation_errors.append(
                f"appPlatformSummary.{field} must be false when present"
            )
    evidence_entries = summary.get("evidence")
    validation_errors.extend(
        list_shape_errors(evidence_entries, "appPlatformSummary.evidence")
    )
    direct_evidence_ids: set[str] = set()
    if isinstance(evidence_entries, list):
        direct_evidence_ids = {
            non_empty_string(entry.get("id") or entry.get("evidenceId"))
            for entry in evidence_entries
            if isinstance(entry, dict)
        }
    missing_evidence_ids = [
        evidence_id
        for evidence_id in APP_PLATFORM_DIRECT_EVIDENCE_IDS
        if evidence_id not in direct_evidence_ids
    ]
    if missing_evidence_ids:
        displayed_missing = ", ".join(missing_evidence_ids[:12])
        remaining = len(missing_evidence_ids) - 12
        validation_errors.append(
            "appPlatformSummary.evidence is missing required Stable IDs: "
            + displayed_missing
            + (f" (+{remaining} more)" if remaining > 0 else "")
        )
    if validation_errors:
        return [
            blocker_issue(
                domain_id,
                "stable-1.0.app-ecosystem-maturity",
                "App-platform smoke summary envelope is not passing",
                "Stable 1.0 requires the attached app-platform smoke summary envelope to pass: "
                + "; ".join(validation_errors)
                + ".",
                "app-platform-summary",
            )
        ]
    return []

def attached_evidence_redaction_blockers(
    *named_summaries: tuple[str, dict[str, Any] | None],
) -> list[dict[str, Any]]:
    affected_rows: list[str] = []
    for source_name, summary in named_summaries:
        if not isinstance(summary, dict):
            continue
        entries = summary.get("evidence")
        if not isinstance(entries, list):
            continue
        for index, entry in enumerate(entries, start=1):
            if not isinstance(entry, dict) or not entry_has_redaction_findings(entry):
                continue
            evidence_id = entry.get("id") or entry.get("evidenceId") or f"row-{index}"
            affected_rows.append(f"{source_name}:{evidence_id}")
    if not affected_rows:
        return []
    return [
        blocker_issue(
            "redaction",
            "stable-1.0.redaction",
            "Attached release evidence has redaction findings",
            (
                "Attached release evidence rows contain non-waivable redaction findings: "
                + ", ".join(sorted(affected_rows))
                + "."
            ),
            "attached-release-evidence",
            issue_id="redaction.attached-release-evidence.blocker",
        )
    ]

def evidence_details(entry: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    details = entry.get("details")
    return details if isinstance(details, dict) else {}

def entry_has_redaction_findings(entry: dict[str, Any] | None) -> bool:
    return recursive_redaction_field_failure(entry)

def entry_ok(entry: dict[str, Any] | None) -> bool:
    return isinstance(entry, dict) and status_ok(entry.get("status")) and not entry_has_redaction_findings(entry)

def release_certification_redaction_passed(redaction: dict[str, Any] | None) -> tuple[bool, dict[str, Any]]:
    if not isinstance(redaction, dict):
        return False, {"status": "missing", "missing": list(RELEASE_CERTIFICATION_REDACTION_BOOL_FIELDS)}
    findings_value = redaction.get("findings")
    findings = findings_value if isinstance(findings_value, list) else []
    malformed_findings = "findings" in redaction and not isinstance(findings_value, list)
    finding_count, malformed_finding_count = non_negative_count(
        redaction.get("findingCount", len(findings))
    )
    critical_finding_count, malformed_critical_finding_count = non_negative_count(
        redaction.get("criticalFindingCount", 0)
    )
    status_value = redaction.get("status")
    required_fields = (
        RELEASE_CERTIFICATION_REDACTION_STATUS_FIELDS
        if status_value is not None
        else RELEASE_CERTIFICATION_REDACTION_BOOL_FIELDS
    )
    missing = [
        field
        for field in required_fields
        if field not in redaction
    ]
    known_false = [
        field
        for field in RELEASE_CERTIFICATION_REDACTION_BOOL_FIELDS
        if field in redaction and redaction.get(field) is not True
    ]
    details: dict[str, Any] = {
        "findingCount": finding_count
        if not malformed_finding_count
        else redaction.get("findingCount", len(findings)),
        "criticalFindingCount": critical_finding_count
        if not malformed_critical_finding_count
        else redaction.get("criticalFindingCount", 0),
        "missingFields": missing,
        "failedFields": known_false,
    }
    if malformed_finding_count:
        details["validationErrors"] = ["findingCount is not a non-negative integer"]
    if malformed_critical_finding_count:
        details.setdefault("validationErrors", []).append(
            "criticalFindingCount is not a non-negative integer"
        )
    if malformed_findings:
        details.setdefault("validationErrors", []).append("findings is not a list")
    unsafe_redaction_payload = recursive_redaction_failure(redaction)
    if unsafe_redaction_payload:
        details.setdefault("validationErrors", []).append(
            "redaction payload contains unsafe raw or unwaivable findings"
        )
    if status_value is not None:
        status = normalize_status(status_value)
        details["status"] = status
        passed = (
            status == "pass"
            and not findings
            and finding_count == 0
            and critical_finding_count == 0
            and not malformed_finding_count
            and not malformed_critical_finding_count
            and not malformed_findings
            and not missing
            and not known_false
            and not unsafe_redaction_payload
        )
        return passed, details
    passed = (
        not missing
        and not known_false
        and not findings
        and finding_count == 0
        and critical_finding_count == 0
        and not malformed_finding_count
        and not malformed_critical_finding_count
        and not malformed_findings
        and not unsafe_redaction_payload
    )
    details["status"] = "pass" if passed else "fail"
    return passed, details

def security_artifact_freshness_blocker(
    *,
    artifact: dict[str, Any],
    scenario: str,
    domain_id: str,
    now: dt.datetime,
    maximum_age_days: int,
) -> dict[str, Any] | None:
    if artifact.get("stale") is True:
        stale_reason = str(artifact.get("staleReason", "artifact is marked stale")).strip()
        return blocker_issue(
            domain_id,
            "stable-1.0.security-drills",
            "Security drill artifact is stale",
            f"Security drill artifact {scenario} is stale: {stale_reason or 'artifact is marked stale'}.",
            "security-drills-summary",
        )
    generated_at = artifact.get("generatedAt")
    if isinstance(generated_at, str) and generated_at.strip():
        return evidence_age_blocker(
            domain_id=domain_id,
            evidence_id="stable-1.0.security-drills",
            title="Security drill artifact",
            source="security-drills-summary",
            generated_at=generated_at,
            now=now,
            maximum_age_days=maximum_age_days,
            label=f"security drill artifact {scenario}",
        )
    age_days = artifact.get("ageDays")
    if isinstance(age_days, (int, float)) and not isinstance(age_days, bool):
        age_value = float(age_days)
        if not math.isfinite(age_value) or age_value < 0:
            return blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill artifact freshness evidence is malformed",
                f"Security drill artifact {scenario} ageDays must be a non-negative finite number.",
                "security-drills-summary",
            )
        if artifact.get("stale") is not False:
            return blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill artifact freshness evidence is missing",
                (
                    f"Security drill artifact {scenario} must report stale=false together "
                    "with ageDays when generatedAt is absent."
                ),
                "security-drills-summary",
            )
        if age_value > maximum_age_days:
            return blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill artifact is stale",
                (
                    f"Security drill artifact {scenario} age is {age_value:.1f} days; "
                    f"policy maximum is {maximum_age_days} days."
                ),
                "security-drills-summary",
            )
        return None
    if artifact.get("stale") is False:
        return blocker_issue(
            domain_id,
            "stable-1.0.security-drills",
            "Security drill artifact freshness evidence is missing",
            (
                f"Security drill artifact {scenario} reports stale=false but does not include "
                "a valid ageDays value."
            ),
            "security-drills-summary",
        )
    return blocker_issue(
        domain_id,
        "stable-1.0.security-drills",
        "Security drill artifact freshness evidence is missing",
        (
            f"Security drill artifact {scenario} must include generatedAt or the producer's "
            "stale/ageDays freshness fields."
        ),
        "security-drills-summary",
    )

def security_scenario_set(
    summary: dict[str, Any],
    field: str,
    domain_id: str,
) -> tuple[set[str], dict[str, Any] | None]:
    if field not in summary:
        return set(), blocker_issue(
            domain_id,
            "stable-1.0.security-drills",
            "Security drill scenario list is missing",
            f"{field} must be present as a list of scenario identifiers.",
            "security-drills-summary",
        )
    value = summary.get(field)
    if not isinstance(value, list):
        return set(), blocker_issue(
            domain_id,
            "stable-1.0.security-drills",
            "Security drill scenario list is malformed",
            f"{field} must be a list of scenario identifiers.",
            "security-drills-summary",
        )
    scenarios: set[str] = set()
    malformed_items: list[str] = []
    for index, item in enumerate(value):
        if isinstance(item, str) and item.strip():
            scenarios.add(item)
        else:
            malformed_items.append(f"{field}[{index}]")
    if malformed_items:
        return scenarios, blocker_issue(
            domain_id,
            "stable-1.0.security-drills",
            "Security drill scenario list is malformed",
            "Malformed scenario entries: " + ", ".join(malformed_items),
            "security-drills-summary",
        )
    return scenarios, None

def sha256_digest(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text.startswith("sha256:"):
        return False
    digest = text.removeprefix("sha256:")
    return len(digest) == 64 and all(char in "0123456789abcdefABCDEF" for char in digest)

def security_artifact_blockers(
    artifacts: Any,
    required: set[str],
    domain_id: str,
    now: dt.datetime,
    maximum_age_days: int | None,
) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    if not isinstance(artifacts, list):
        return [
            blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill artifact evidence is missing",
                "securityDrillsSummary.artifacts must be a non-empty list of artifact evidence objects.",
                "security-drills-summary",
            )
        ]
    if not artifacts:
        return [
            blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill artifact evidence is empty",
                "Stable 1.0 requires security drill artifacts for every required drill scenario.",
                "security-drills-summary",
            )
        ]

    scenario_counts: dict[str, int] = {}
    malformed_entries: list[str] = []
    malformed_scenarios: list[str] = []
    malformed_digests: list[str] = []
    missing_template_statuses: list[str] = []
    unknown_scenarios: list[str] = []
    failing_artifacts: list[str] = []
    object_artifacts: list[tuple[str, dict[str, Any]]] = []
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            malformed_entries.append(f"artifacts[{index}]")
            continue
        if not sha256_digest(artifact.get("digest")):
            malformed_digests.append(f"artifacts[{index}].digest")
        scenario = non_empty_string(artifact.get("scenario")) or non_empty_string(artifact.get("id"))
        if not scenario:
            malformed_scenarios.append(f"artifacts[{index}].scenario")
            scenario = f"artifact-{index}"
        else:
            scenario_counts[scenario] = scenario_counts.get(scenario, 0) + 1
            if scenario not in required:
                unknown_scenarios.append(scenario)
        if not status_ok(artifact.get("status")):
            failing_artifacts.append(scenario)
        if artifact.get("releaseNotesTemplateStatus") != "pass":
            missing_template_statuses.append(f"{scenario}.releaseNotesTemplateStatus")
        if artifact.get("advisoryTemplateStatus") != "pass":
            missing_template_statuses.append(f"{scenario}.advisoryTemplateStatus")
        object_artifacts.append((scenario, artifact))

    if malformed_entries or malformed_scenarios:
        malformed = [*malformed_entries, *malformed_scenarios]
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill artifact list is malformed",
                "Malformed security drill artifact entries: " + ", ".join(malformed) + ".",
                "security-drills-summary",
            )
        )
    if malformed_digests:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill artifact digest is missing or malformed",
                "Security drill artifacts must include sha256:<64 hex> digest values: "
                + ", ".join(malformed_digests)
                + ".",
                "security-drills-summary",
            )
        )
    if unknown_scenarios:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill artifact scenario is not required",
                "Security drill artifacts must only cover required production drills: "
                + ", ".join(sorted(set(unknown_scenarios)))
                + ".",
                "security-drills-summary",
            )
        )

    missing_required = sorted(required - set(scenario_counts))
    duplicate_required = sorted(
        scenario for scenario in required if scenario_counts.get(scenario, 0) > 1
    )
    if missing_required or duplicate_required:
        details: list[str] = []
        if missing_required:
            details.append("missing required artifacts: " + ", ".join(missing_required))
        if duplicate_required:
            details.append("duplicate required artifacts: " + ", ".join(duplicate_required))
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill artifacts do not cover required scenarios",
                "Stable 1.0 requires exactly one artifact for each required drill scenario; "
                + "; ".join(details)
                + ".",
                "security-drills-summary",
            )
        )

    if failing_artifacts:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill artifact status is not passing",
                "Security drill artifacts are not passing: "
                + ", ".join(sorted(set(failing_artifacts)))
                + ".",
                "security-drills-summary",
            )
        )

    if missing_template_statuses:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill artifact template proof is missing",
                "Security drill artifacts must include passing release-note and advisory template proof: "
                + ", ".join(missing_template_statuses)
                + ".",
                "security-drills-summary",
            )
        )

    if maximum_age_days is not None:
        for scenario, artifact in object_artifacts:
            artifact_freshness = security_artifact_freshness_blocker(
                artifact=artifact,
                scenario=scenario,
                domain_id=domain_id,
                now=now,
                maximum_age_days=maximum_age_days,
            )
            if artifact_freshness is not None:
                blockers.append(artifact_freshness)

    return blockers

def security_summary_structure_blockers(
    summary: dict[str, Any],
    required: set[str],
    domain_id: str,
) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    mode = str(summary.get("mode", "")).strip().lower()
    if mode not in SECURITY_DRILL_RELEASE_MODES:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill summary mode is not release-capable",
                "Stable 1.0 requires securityDrillsSummary.mode to be release-candidate or production-beta.",
                "security-drills-summary",
            )
        )
    if strict_positive_int(summary.get("maxAgeDays")) is None:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill summary freshness metadata is missing",
                "Stable 1.0 requires securityDrillsSummary.maxAgeDays to be a positive integer.",
                "security-drills-summary",
            )
        )
    required_scenarios, required_blocker = security_scenario_set(
        summary,
        "requiredScenarios",
        domain_id,
    )
    if required_blocker is not None:
        blockers.append(required_blocker)
    if required_scenarios != required:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill required scenario list does not match policy",
                "securityDrillsSummary.requiredScenarios must exactly match the Stable 1.0 policy scenarios.",
                "security-drills-summary",
            )
        )
    counts = summary.get("counts")
    expected_counts = {
        "required": len(required),
        "passed": len(required),
        "failed": 0,
        "missing": 0,
        "stale": 0,
        "malformed": 0,
    }
    malformed_counts: list[str] = []
    if not isinstance(counts, dict):
        malformed_counts.append("counts")
    else:
        for field, expected in expected_counts.items():
            value = strict_non_negative_int(counts.get(field))
            if value != expected:
                malformed_counts.append(f"counts.{field}")
    if malformed_counts:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill summary counts are missing or inconsistent",
                "Stable 1.0 requires producer summary counts to match the required passing drills: "
                + ", ".join(malformed_counts)
                + ".",
                "security-drills-summary",
            )
        )
    return blockers

def add_required_evidence_blockers(
    evidence: dict[str, dict[str, Any]],
    domain_id: str,
    evidence_ids: Iterable[str],
    source: str,
) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    for evidence_id in evidence_ids:
        entry = evidence.get(evidence_id)
        if entry_ok(entry):
            continue
        if entry is None:
            summary = f"Required evidence {evidence_id} is missing."
        elif entry_has_redaction_findings(entry):
            summary = f"Required evidence {evidence_id} has redaction findings."
        else:
            summary = f"Required evidence {evidence_id} status is {normalize_status(entry.get('status'))}."
        blockers.append(
            blocker_issue(
                domain_id,
                evidence_id,
                "Required Stable 1.0 evidence is not passing",
                summary,
                source,
            )
        )
    return blockers

def recursive_redaction_failure(value: Any) -> bool:
    if isinstance(value, dict):
        if "redaction" in value and recursive_redaction_failure(value["redaction"]):
            return True
        if "redactionFindings" in value:
            redaction_findings = value.get("redactionFindings")
            if not isinstance(redaction_findings, list) or bool(redaction_findings):
                return True
        if "findings" in value:
            findings = value.get("findings")
            if not isinstance(findings, list) or bool(findings):
                return True
        for count_key in ("findingCount", "criticalFindingCount"):
            if count_key in value:
                finding_count, malformed_finding_count = non_negative_count(value.get(count_key))
                if malformed_finding_count or finding_count > 0:
                    return True
        status = value.get("status")
        if "status" in value and (
            not isinstance(status, str) or status.strip().lower() != "pass"
        ):
            return True
        for key, child in value.items():
            if dashboard.redaction_proof_failure(key, child):
                return True
            if recursive_redaction_failure(child):
                return True
    elif isinstance(value, list):
        return any(recursive_redaction_failure(child) for child in value)
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
        or dashboard.redaction_proof_key(key)
    )

def apps_from_entry(entry: dict[str, Any] | None) -> set[str]:
    details = evidence_details(entry)
    apps = details.get("apps")
    if isinstance(apps, list):
        return {str(app) for app in apps}
    if isinstance(apps, dict):
        return {str(app) for app in apps}
    required = details.get("requiredFirstPartyApps")
    if isinstance(required, list):
        return {str(app) for app in required}
    catalog = details.get("catalog") if isinstance(details.get("catalog"), dict) else {}
    inspected = catalog.get("inspectedAppIds")
    if isinstance(inspected, list):
        return {str(app) for app in inspected}
    return set()

def load_waivers(path: Path | None, now: dt.datetime, workspace_root: Path) -> list[StableWaiver]:
    if path is None:
        return []
    value = read_json(path)
    if not isinstance(value, dict):
        return [
            StableWaiver(
                id="stable-waiver-file-invalid",
                evidence_id="stable-1.0.waiver-validation",
                scope="stable-1.0",
                status="invalid",
                rationale="",
                approved_by="",
                owner="",
                expires_at="",
                references=(),
                active=False,
                validation_errors=("waiver file is missing or invalid JSON",),
                source=display_path(path, workspace_root),
            )
        ]
    records = value.get("waivers")
    schema_version = value.get("schemaVersion", value.get("version"))
    if not schema_version_is_current(schema_version) or not isinstance(records, list):
        return [
            StableWaiver(
                id="stable-waiver-schema-invalid",
                evidence_id="stable-1.0.waiver-validation",
                scope="stable-1.0",
                status="invalid",
                rationale="",
                approved_by="",
                owner="",
                expires_at="",
                references=(),
                active=False,
                validation_errors=("waiver file must use schemaVersion 1 and a waivers array",),
                source=display_path(path, workspace_root),
            )
        ]
    waivers: list[StableWaiver] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            record = {}
        waiver_id = non_empty_string(record.get("id"))
        evidence_id = non_empty_string(record.get("evidenceId"))
        scope = non_empty_string(record.get("scope"))
        status = non_empty_string(record.get("status")).lower()
        rationale = non_empty_string(record.get("rationale", record.get("reason")))
        approved_by = non_empty_string(record.get("approvedBy"))
        owner = non_empty_string(record.get("owner"))
        expires_at = non_empty_string(record.get("expiresAt"))
        references_value = record.get("references")
        references = (
            tuple(non_empty_string(item) for item in references_value if non_empty_string(item))
            if isinstance(references_value, list)
            else ()
        )
        expiry = dashboard.parse_time(expires_at)
        validation_errors: list[str] = []
        if not waiver_id:
            validation_errors.append("id is required")
        if not evidence_id:
            validation_errors.append("evidenceId is required")
        if not rationale:
            validation_errors.append("rationale is required")
        if not approved_by:
            validation_errors.append("approvedBy is required")
        if not owner:
            validation_errors.append("owner is required")
        if not status:
            validation_errors.append("status is required")
        elif status != "approved":
            validation_errors.append("status must be approved")
        if scope not in {"stable-1.0", "stable-1.0-only", "stable-promotion", "all", "all-modes"}:
            validation_errors.append("scope must apply to stable-1.0")
        if not isinstance(references_value, list):
            validation_errors.append("references is required and must be an array")
        elif any(not non_empty_string(item) for item in references_value):
            validation_errors.append("references must contain only non-empty strings")
        elif not references:
            validation_errors.append("references must include at least one approval reference")
        if not expires_at:
            validation_errors.append("expiresAt is required")
        elif expiry is None:
            validation_errors.append("expiresAt must be an ISO-8601 timestamp")
        elif expiry <= now:
            validation_errors.append("waiver is expired")
        active = not validation_errors
        waivers.append(
            StableWaiver(
                id=waiver_id or f"stable-waiver-{index}",
                evidence_id=evidence_id or waiver_id or f"stable-waiver-{index}",
                scope=scope,
                status=status,
                rationale=rationale,
                approved_by=approved_by,
                owner=owner,
                expires_at=expires_at,
                references=references,
                active=active,
                validation_errors=tuple(validation_errors),
                source=display_path(path, workspace_root),
            )
        )
    return waivers

def active_waiver_for(waivers: list[StableWaiver], *targets: str) -> StableWaiver | None:
    return next((waiver for waiver in waivers if waiver.active and waiver.matches(*targets)), None)
