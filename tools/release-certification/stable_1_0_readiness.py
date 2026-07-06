#!/usr/bin/env python3
"""Build a redacted Stable 1.0 readiness report from production beta evidence."""

from __future__ import annotations

import argparse
import copy
import dataclasses
import datetime as dt
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Iterable


sys.dont_write_bytecode = True
TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
sys.path.insert(0, str(TOOL_DIR))

import production_beta_go_no_go_dashboard as dashboard  # noqa: E402
import multi_node_beta_soak  # noqa: E402


TOOL_NAME = "stable-1.0-readiness"
SCHEMA_VERSION = 1
DEFAULT_OUT_DIR = Path("build/stable-1.0-readiness")
DEFAULT_POLICY = TOOL_DIR / "stable-1.0-readiness-policy.json"
DEFAULT_LIMITATIONS = TOOL_DIR / "stable-1.0-known-limitations.json"
DEFAULT_PUBLIC_BETA_KNOWN_ISSUES = TOOL_DIR / "public-beta-known-issues.json"
FIXTURE_DIR = TOOL_DIR / "fixtures"
DEFAULT_GENERATED_AT = "1970-01-01T00:00:00Z"

SUMMARY_FILE = "stable-1.0-readiness-summary.json"
REPORT_FILE = "stable-1.0-readiness-report.md"
KNOWN_LIMITATIONS_FILE = "stable-1.0-known-limitations.json"
BLOCKERS_FILE = "stable-1.0-blockers.json"

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

SECURITY_RESPONSE_EVIDENCE_IDS = (
    "catalog.security-advisories",
    "catalog.version-denylist",
    "app-review.receipt-revocation",
    "app-review.reviewer-key-compromise-flow",
    "app-update.security-denylist-gates",
    "production-security.response-runbook",
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
    "public-beta.issue-templates",
    "public-beta.known-issues-tracker",
    "public-beta.feedback-to-backlog",
    "public-beta.release-notes-template",
    "public-beta.support-bundle-guidance",
    "public-beta.security-reporting-handoff",
    "public-beta.redaction-fixtures",
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
    except (OSError, json.JSONDecodeError):
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


def parse_generated_at(value: str) -> tuple[str, dt.datetime]:
    text = value.strip() if value else utc_now()
    parsed = dashboard.parse_time(text)
    if parsed is None:
        return text, dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    return text, parsed


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
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def non_empty_string(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


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
            if isinstance(evidence_id, str) and evidence_id:
                result[evidence_id] = entry
    return result


def evidence_details(entry: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    details = entry.get("details")
    return details if isinstance(details, dict) else {}


def entry_ok(entry: dict[str, Any] | None) -> bool:
    return isinstance(entry, dict) and status_ok(entry.get("status"))


def release_certification_redaction_passed(redaction: dict[str, Any] | None) -> tuple[bool, dict[str, Any]]:
    if not isinstance(redaction, dict):
        return False, {"status": "missing", "missing": list(RELEASE_CERTIFICATION_REDACTION_BOOL_FIELDS)}
    findings = redaction.get("findings") if isinstance(redaction.get("findings"), list) else []
    status_value = redaction.get("status")
    known_false = [
        field
        for field in RELEASE_CERTIFICATION_REDACTION_BOOL_FIELDS
        if field in redaction and redaction.get(field) is not True
    ]
    if status_value is not None:
        status = normalize_status(status_value)
        passed = status == "pass" and not findings and not known_false
        return passed, {
            "status": status,
            "findingCount": len(findings),
            "failedFields": known_false,
        }
    missing = [
        field
        for field in RELEASE_CERTIFICATION_REDACTION_BOOL_FIELDS
        if field not in redaction
    ]
    passed = not missing and not known_false and not findings
    return passed, {
        "status": "pass" if passed else "fail",
        "findingCount": len(findings),
        "missingFields": missing,
        "failedFields": known_false,
    }


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
        if float(age_days) > maximum_age_days:
            return blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill artifact is stale",
                (
                    f"Security drill artifact {scenario} age is {float(age_days):.1f} days; "
                    f"policy maximum is {maximum_age_days} days."
                ),
                "security-drills-summary",
            )
        return None
    if artifact.get("stale") is False:
        return None
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
        if "redactionFindings" in value and value.get("redactionFindings"):
            return True
        status = value.get("status")
        if isinstance(status, str) and normalize_status(status) == "fail":
            redaction_keys = {key.lower() for key in value}
            if "findings" in redaction_keys or "rawsensitivematerialexcluded" in redaction_keys:
                return True
        for key, child in value.items():
            lowered = str(key).lower()
            if (
                lowered.startswith("raw")
                and (lowered.endswith("included") or lowered.endswith("persisted") or lowered.endswith("inevidence"))
                and child is True
            ):
                return True
            if lowered.endswith("excluded") and child is False:
                return True
            if recursive_redaction_failure(child):
                return True
    elif isinstance(value, list):
        return any(recursive_redaction_failure(child) for child in value)
    return False


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
    if value.get("schemaVersion", value.get("version")) != 1 or not isinstance(records, list):
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
        waiver_id = str(record.get("id", f"stable-waiver-{index}")).strip()
        evidence_id = str(record.get("evidenceId", waiver_id)).strip()
        scope = str(record.get("scope", "")).strip()
        status = str(record.get("status", "approved")).strip().lower()
        rationale = str(record.get("rationale", record.get("reason", ""))).strip()
        approved_by = str(record.get("approvedBy", "")).strip()
        owner = str(record.get("owner", "")).strip()
        expires_at = str(record.get("expiresAt", "")).strip()
        references_value = record.get("references")
        references = (
            tuple(str(item).strip() for item in references_value if str(item).strip())
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
        if status != "approved":
            validation_errors.append("status must be approved")
        if scope not in {"stable-1.0", "stable-1.0-only", "stable-promotion", "all", "all-modes"}:
            validation_errors.append("scope must apply to stable-1.0")
        if not isinstance(references_value, list):
            validation_errors.append("references is required and must be an array")
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


def evaluate_production_beta_state(
    production: dict[str, Any] | None,
    go_no_go: dict[str, Any] | None,
    policy: dict[str, Any],
) -> dict[str, Any]:
    domain_id = "production-beta-state"
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    required_modes = set(policy.get("requiredReleaseModes", ["production-beta"]))
    if not isinstance(production, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.production-beta-state",
                "Production beta summary is missing",
                "Stable 1.0 readiness requires a production beta summary.",
                "production-beta-summary",
            )
        )
    else:
        mode = str(production.get("mode", "missing"))
        if mode not in required_modes:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta mode is not Stable-compatible",
                    f"Production beta summary mode is {mode}; required modes are {', '.join(sorted(required_modes))}.",
                    "production-beta-summary",
                )
            )
        if not status_ok(production.get("status")) or production.get("promotionReady") is not True:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta summary is not promotion-ready",
                    "Stable 1.0 readiness requires production beta status pass and promotionReady=true.",
                    "production-beta-summary",
                )
            )
        if production.get("nonRelease") is not False:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta summary is marked non-release",
                    "Stable 1.0 cannot depend on developer dry-run, fixture, emergency-skip, dirty workspace, or test-signing evidence.",
                    "production-beta-summary",
                )
            )
        signing = production.get("signingProfile")
        if not isinstance(signing, dict):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta signing profile is missing",
                    "Stable 1.0 requires explicit production signing and reviewer-key evidence.",
                    "production-beta-summary",
                )
            )
        else:
            required_signing_fields = (
                "kind",
                "generatedTestKeys",
                "appKeyId",
                "reviewerKeyId",
                "privateKeyMaterialIncluded",
            )
            missing_fields = [
                field
                for field in required_signing_fields
                if field not in signing
                or signing.get(field) is None
                or (isinstance(signing.get(field), str) and not signing.get(field).strip())
            ]
            if missing_fields:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.production-beta-state",
                        "Production beta signing evidence is incomplete",
                        "Stable 1.0 signing profile is missing fields: " + ", ".join(missing_fields) + ".",
                        "production-beta-summary",
                    )
                )
            if (
                signing.get("generatedTestKeys") is not False
                or str(signing.get("kind", "")) != "production"
                or signing.get("privateKeyMaterialIncluded") is not False
            ):
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.production-beta-state",
                        "Production beta summary uses non-production signing evidence",
                        "Stable 1.0 requires production signing and reviewer evidence, not fixture or generated test keys.",
                        "production-beta-summary",
                    )
                )
        redaction = production.get("redaction") if isinstance(production.get("redaction"), dict) else {}
        if (
            normalize_status(redaction.get("status", "missing")) != "pass"
            or redaction.get("findings")
            or recursive_redaction_failure(redaction)
        ):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.redaction",
                    "Production beta redaction did not pass",
                    "Stable 1.0 readiness cannot use redaction-unsafe production beta artifacts.",
                    "production-beta-summary",
                )
            )
        failed_gates = [
            str(gate.get("id"))
            for gate in production.get("promotion", {}).get("gates", [])
            if isinstance(gate, dict) and gate.get("status") != "pass"
        ]
        forbidden_gate_prefixes = (
            "fixture-evidence",
            "live.production-beta-skip",
            "build.",
            "workspace.",
            "multi-node-beta.previous-candidate",
        )
        forbidden_failed = [
            gate_id for gate_id in failed_gates if gate_id.startswith(forbidden_gate_prefixes)
        ]
        if forbidden_failed:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta promotion gates include Stable-forbidden failures",
                    "Failed production gates: " + ", ".join(forbidden_failed[:8]),
                    "production-beta-summary",
                )
            )
    if not isinstance(go_no_go, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.go-no-go-decision",
                "Production beta go/no-go dashboard is missing",
                "Stable 1.0 readiness requires the production beta dashboard decision.",
                "go-no-go-summary",
            )
        )
    else:
        decision = str(go_no_go.get("decision", "missing"))
        dashboard_mode = str(go_no_go.get("mode", "missing"))
        if dashboard_mode != "production-beta":
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.go-no-go-decision",
                    "Production beta go/no-go dashboard mode is not Stable-compatible",
                    f"Go/no-go dashboard mode is {dashboard_mode}; Stable 1.0 requires production-beta.",
                    "go-no-go-summary",
                )
            )
        if isinstance(production, dict):
            production_release_id = str(production.get("releaseId", "")).strip()
            dashboard_release_id = str(go_no_go.get("releaseId", "")).strip()
            if not production_release_id or dashboard_release_id != production_release_id:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.go-no-go-decision",
                        "Production beta go/no-go dashboard is not bound to this release",
                        (
                            "Stable 1.0 requires the go/no-go dashboard releaseId to match "
                            f"the production beta summary releaseId; dashboard={dashboard_release_id or 'missing'}, "
                            f"production={production_release_id or 'missing'}."
                        ),
                        "go-no-go-summary",
                    )
                )
        if decision not in {"go", "go-with-waivers"}:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.go-no-go-decision",
                    "Production beta go/no-go decision blocks Stable 1.0",
                    f"Go/no-go decision is {decision}.",
                    "go-no-go-summary",
                )
            )
        elif decision == "go-with-waivers":
            warnings.append(
                warning_issue(
                    domain_id,
                    "stable-1.0.go-no-go-decision",
                    "Production beta launch depends on waivers",
                    "Release managers must confirm production beta waivers do not cover Stable-forbidden blockers.",
                    "go-no-go-summary",
                )
            )
        if go_no_go.get("promotionReady") is not True:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.go-no-go-decision",
                    "Production beta dashboard is not promotion-ready",
                    "Stable 1.0 readiness requires dashboard promotionReady=true.",
                    "go-no-go-summary",
                )
            )
        redaction = go_no_go.get("redaction") if isinstance(go_no_go.get("redaction"), dict) else {}
        if normalize_status(redaction.get("status", "missing")) != "pass":
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.redaction",
                    "Go/no-go dashboard redaction did not pass",
                    "Stable 1.0 readiness cannot depend on a redaction-unsafe dashboard.",
                    "go-no-go-summary",
                )
            )
    return domain_result(
        domain_id,
        "Production beta release state",
        ("stable-1.0.production-beta-state", "stable-1.0.go-no-go-decision"),
        blockers,
        warnings,
    )


def evaluate_release_certification_summary(release_certification: dict[str, Any] | None) -> dict[str, Any]:
    domain_id = "release-certification-summary"
    blockers: list[dict[str, Any]] = []
    if not isinstance(release_certification, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.release-certification",
                "Release certification summary is missing",
                "Stable 1.0 readiness requires a passing release-certification summary.",
                "release-certification-summary",
            )
        )
    else:
        status = normalize_status(release_certification.get("status", "missing"))
        mode = str(release_certification.get("mode", "missing"))
        release_candidate_passed = release_certification.get("releaseCandidatePassed")
        if mode != "release-candidate":
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.release-certification",
                    "Release certification summary is not from release-candidate mode",
                    f"Stable 1.0 readiness requires release-candidate certification evidence; mode is {mode}.",
                    "release-certification-summary",
                )
            )
        if status != "pass" or release_candidate_passed is not True:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.release-certification",
                    "Release certification summary is not passing",
                    (
                        "Stable 1.0 readiness requires release-certification status pass "
                        f"and releaseCandidatePassed=true; status is {status}, "
                        f"releaseCandidatePassed is {release_candidate_passed!r}."
                    ),
                    "release-certification-summary",
                )
            )
        redaction = (
            release_certification.get("redaction")
            if isinstance(release_certification.get("redaction"), dict)
            else None
        )
        redaction_passed, _redaction_details = release_certification_redaction_passed(redaction)
        if not redaction_passed:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.redaction",
                    "Release certification redaction evidence is missing or failed",
                    "Stable 1.0 readiness cannot use redaction-unsafe release-certification artifacts.",
                    "release-certification-summary",
                )
            )
    return domain_result(
        domain_id,
        "Release certification aggregate",
        ("stable-1.0.release-certification",),
        blockers,
        [],
    )


def evaluate_policy(
    policy: dict[str, Any] | None,
    policy_path: Path,
    workspace_root: Path,
) -> dict[str, Any]:
    domain_id = "readiness-policy"
    blockers: list[dict[str, Any]] = []
    source = display_path(policy_path, workspace_root)
    if not isinstance(policy, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.readiness-gate",
                "Stable 1.0 readiness policy is missing or unreadable",
                "Stable 1.0 readiness requires a readable policy JSON file.",
                source,
            )
        )
    else:
        if policy.get("schemaVersion") != SCHEMA_VERSION or policy.get("kind") != "stable-1.0-readiness-policy":
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.readiness-gate",
                    "Stable 1.0 readiness policy schema is invalid",
                    "Stable 1.0 readiness requires schemaVersion=1 and kind=stable-1.0-readiness-policy.",
                    source,
                )
            )
        required_soak = policy.get("requiredSoak") if isinstance(policy.get("requiredSoak"), dict) else {}
        security = (
            policy.get("securityDrillCriteria")
            if isinstance(policy.get("securityDrillCriteria"), dict)
            else {}
        )
        if positive_int(required_soak.get("maximumEvidenceAgeDays")) is None:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.live-multi-node-soak",
                    "Stable soak evidence age policy is missing",
                    "requiredSoak.maximumEvidenceAgeDays must be a positive integer.",
                    source,
                )
            )
        if positive_int(security.get("maximumEvidenceAgeDays")) is None:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Stable security drill evidence age policy is missing",
                    "securityDrillCriteria.maximumEvidenceAgeDays must be a positive integer.",
                    source,
                )
            )
        for key in ("allowedLimitationCategories", "disallowedLimitationCategories", "nonWaivableBlockers"):
            if not isinstance(policy.get(key), list):
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.known-limitations",
                        "Stable readiness policy category list is missing",
                        f"{key} must be present as an array.",
                        source,
                    )
                )
    return domain_result(
        domain_id,
        "Stable 1.0 readiness policy",
        ("stable-1.0.readiness-gate",),
        blockers,
        [],
    )


def evaluate_platform_api(evidence: dict[str, dict[str, Any]], policy: dict[str, Any]) -> dict[str, Any]:
    domain_id = "platform-api-1.0"
    blockers = add_required_evidence_blockers(
        evidence,
        domain_id,
        PLATFORM_API_EVIDENCE_IDS,
        "release-certification",
    )
    baseline_entry = evidence.get("platform-api.stable-baseline")
    baseline_details = evidence_details(baseline_entry)
    baseline = baseline_details.get("stableBaseline") if isinstance(baseline_details.get("stableBaseline"), dict) else {}
    required_name = policy.get("platformApi10Criteria", {}).get("stableBaselineName", "1.0")
    if entry_ok(baseline_entry) and baseline.get("name") != required_name:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.platform-api-compatibility",
                "Platform API stable baseline identity is not 1.0",
                f"Stable baseline name is {baseline.get('name', 'missing')}; required {required_name}.",
                "platform-api.stable-baseline",
            )
        )
    if entry_ok(baseline_entry) and int(baseline.get("capabilityCount", 0) or 0) <= 0:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.platform-api-compatibility",
                "Platform API stable baseline has no capabilities",
                "Stable 1.0 requires a non-empty Platform API 1.0 baseline.",
                "platform-api.stable-baseline",
            )
        )
    breaking = evidence.get("platform-api.stable-breaking-change-check")
    breaking_details = evidence_details(breaking)
    breaking_errors = breaking_details.get("errors")
    if isinstance(breaking_errors, list) and breaking_errors:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.stable-api-breaking-change",
                "Stable API breaking-change check reported errors",
                f"Stable API breaking-change errors: {len(breaking_errors)}.",
                "platform-api.stable-breaking-change-check",
            )
        )
    compatibility = evidence_details(evidence.get("platform-api.compatibility-window")).get("compatibilityWindow")
    if isinstance(compatibility, dict):
        if compatibility.get("previousSnapshotRequiredInProductionBeta") is not True:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.platform-api-compatibility",
                    "Platform API previous-snapshot policy is not enforced",
                    "Stable 1.0 requires previous contract snapshot enforcement.",
                    "platform-api.compatibility-window",
                )
            )
        if compatibility.get("criticalStableRemovalWaiverAllowed") is not False:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.stable-api-breaking-change",
                    "Critical stable removals appear waiverable",
                    "Stable 1.0 does not accept critical stable removal waivers.",
                    "platform-api.compatibility-window",
                )
            )
    deprecation = evidence_details(evidence.get("platform-api.deprecation-window-policy"))
    if deprecation.get("criticalStableRemovalWaiverAllowed") is not False:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.stable-api-breaking-change",
                "Stable deprecation policy allows critical removal waivers",
                "Stable 1.0 requires non-waivable critical stable removal blockers.",
                "platform-api.deprecation-window-policy",
            )
        )
    return domain_result(
        domain_id,
        "Platform API 1.0 compatibility",
        PLATFORM_API_EVIDENCE_IDS,
        blockers,
        [],
    )


def evaluate_app_ecosystem(evidence: dict[str, dict[str, Any]]) -> dict[str, Any]:
    domain_id = "app-ecosystem-maturity"
    blockers = add_required_evidence_blockers(
        evidence,
        domain_id,
        APP_ECOSYSTEM_EVIDENCE_IDS,
        "release-certification",
    )
    for evidence_id in (
        "app-platform.first-party",
        "app-catalog.first-party-maintenance-policy",
        "first-party-app.beta-quality-pass",
        "app-review.first-party-catalog",
    ):
        apps = apps_from_entry(evidence.get(evidence_id))
        missing = sorted(set(APP_IDS) - apps)
        if entry_ok(evidence.get(evidence_id)) and missing:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.first-party-stable-app-readiness",
                    "First-party stable app coverage is incomplete",
                    f"{evidence_id} is missing apps: {', '.join(missing)}.",
                    evidence_id,
                )
            )
    maintenance = evidence_details(evidence.get("app-catalog.first-party-maintenance-policy"))
    maintenance_apps = maintenance.get("apps") if isinstance(maintenance.get("apps"), dict) else {}
    for app_id in APP_IDS:
        app_policy = maintenance_apps.get(app_id) if isinstance(maintenance_apps.get(app_id), dict) else {}
        maint = app_policy.get("maintenance") if isinstance(app_policy.get("maintenance"), dict) else {}
        backup = str(maint.get("backupRestore", "missing"))
        migration = str(maint.get("migrationPolicy", "missing"))
        if backup in {"unsupported", "missing", ""}:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.first-party-stable-app-readiness",
                    "Stable first-party app lacks backup/restore policy",
                    f"{app_id} backupRestore is {backup}.",
                    "app-catalog.first-party-maintenance-policy",
                )
            )
        if migration in {"missing", ""}:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.first-party-stable-app-readiness",
                    "Stable first-party app lacks migration policy",
                    f"{app_id} migrationPolicy is {migration}.",
                    "app-catalog.first-party-maintenance-policy",
                )
            )
    diagnostics = evidence.get("app-platform.privacy-preserving-beta-diagnostics")
    if recursive_redaction_failure(evidence_details(diagnostics)):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.redaction",
                "First-party diagnostics evidence has redaction failures",
                "Stable 1.0 cannot ship with privacy/security diagnostics redaction failures.",
                "app-platform.privacy-preserving-beta-diagnostics",
            )
        )
    return domain_result(domain_id, "App ecosystem maturity", APP_ECOSYSTEM_EVIDENCE_IDS, blockers, [])


def evaluate_third_party(evidence: dict[str, dict[str, Any]]) -> dict[str, Any]:
    domain_id = "third-party-intake"
    blockers = add_required_evidence_blockers(
        evidence,
        domain_id,
        THIRD_PARTY_EVIDENCE_IDS,
        "release-certification",
    )
    sample = evidence_details(evidence.get("third-party-developer.sample-app-flow"))
    sample_flow = sample.get("sampleFlow")
    if entry_ok(evidence.get("third-party-developer.sample-app-flow")) and not isinstance(sample_flow, list):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.third-party-intake",
                "Third-party sample app flow is not represented",
                "Stable 1.0 requires a sample submission through pre-review, review, catalog candidate, and install smoke.",
                "third-party-developer.sample-app-flow",
            )
        )
    return domain_result(domain_id, "Third-party app criteria", THIRD_PARTY_EVIDENCE_IDS, blockers, [])


def evaluate_security(
    evidence: dict[str, dict[str, Any]],
    security_summary: dict[str, Any] | None,
    policy: dict[str, Any],
    now: dt.datetime,
    candidate_release_id: str,
) -> dict[str, Any]:
    domain_id = "security-drills"
    blockers = add_required_evidence_blockers(
        evidence,
        domain_id,
        SECURITY_RESPONSE_EVIDENCE_IDS,
        "release-certification",
    )
    security_criteria = (
        policy.get("securityDrillCriteria")
        if isinstance(policy.get("securityDrillCriteria"), dict)
        else {}
    )
    required = set(security_criteria.get("requiredScenarios", []))
    max_age_days = positive_int(security_criteria.get("maximumEvidenceAgeDays"))
    if max_age_days is None:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill freshness policy is missing",
                "securityDrillCriteria.maximumEvidenceAgeDays must be a positive integer.",
                "stable-readiness-policy",
            )
        )
    if not isinstance(security_summary, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill summary is missing",
                "Stable 1.0 requires the redacted production security drill summary.",
                "security-drills-summary",
            )
        )
    else:
        if security_summary.get("kind") != "cryptad-security-response-drills-summary":
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Security drill summary has the wrong kind",
                    "Stable 1.0 requires kind=cryptad-security-response-drills-summary.",
                    "security-drills-summary",
                )
            )
        if not status_ok(security_summary.get("status")) or security_summary.get("promotionReady") is not True:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Security drill summary is not promotion-ready",
                    "All required Stable 1.0 security drill scenarios must pass.",
                    "security-drills-summary",
                )
            )
        security_release_id = str(security_summary.get("releaseId", "")).strip()
        if candidate_release_id and security_release_id != candidate_release_id:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Security drill summary is not bound to this release",
                    (
                        "Stable 1.0 requires the security drill releaseId to match the "
                        f"production beta releaseId; security={security_release_id or 'missing'}, "
                        f"production={candidate_release_id}."
                    ),
                    "security-drills-summary",
                )
            )
        if max_age_days is not None:
            freshness = evidence_age_blocker(
                domain_id=domain_id,
                evidence_id="stable-1.0.security-drills",
                title="Security drill summary",
                source="security-drills-summary",
                generated_at=security_summary.get("generatedAt"),
                now=now,
                maximum_age_days=max_age_days,
                label="security drill summary",
            )
            if freshness is not None:
                blockers.append(freshness)
            artifacts = security_summary.get("artifacts")
            if isinstance(artifacts, list):
                for index, artifact in enumerate(artifacts):
                    if not isinstance(artifact, dict):
                        continue
                    scenario = str(artifact.get("scenario", artifact.get("id", f"artifact-{index}")))
                    artifact_freshness = security_artifact_freshness_blocker(
                        artifact=artifact,
                        scenario=scenario,
                        domain_id=domain_id,
                        now=now,
                        maximum_age_days=max_age_days,
                    )
                    if artifact_freshness is not None:
                        blockers.append(artifact_freshness)
        passed = {str(item) for item in security_summary.get("passedScenarios", []) if isinstance(item, str)}
        failed = {str(item) for item in security_summary.get("failedScenarios", []) if isinstance(item, str)}
        missing = {str(item) for item in security_summary.get("missingScenarios", []) if isinstance(item, str)}
        stale = {str(item) for item in security_summary.get("staleScenarios", []) if isinstance(item, str)}
        malformed = {str(item) for item in security_summary.get("malformedScenarios", []) if isinstance(item, str)}
        not_passing = sorted((required - passed) | failed | missing | stale | malformed)
        if not_passing:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Required security drill scenarios are not passing",
                    "Scenario blockers: " + ", ".join(not_passing),
                    "security-drills-summary",
                )
            )
        redaction = security_summary.get("redaction") if isinstance(security_summary.get("redaction"), dict) else {}
        if normalize_status(redaction.get("status", "missing")) != "pass" or redaction.get("findings"):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.redaction",
                    "Security drill redaction did not pass",
                    "Stable 1.0 security drill artifacts must be redaction-safe.",
                    "security-drills-summary",
                )
            )
        release_notes = security_summary.get("releaseNotes") if isinstance(security_summary.get("releaseNotes"), dict) else {}
        advisory = security_summary.get("advisoryTemplate") if isinstance(security_summary.get("advisoryTemplate"), dict) else {}
        if normalize_status(release_notes.get("templateStatus", "missing")) != "pass":
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Security release notes template is missing",
                    "Stable 1.0 requires a security release notes template or draft.",
                    "security-drills-summary",
                )
            )
        if normalize_status(advisory.get("templateStatus", "missing")) != "pass":
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Security advisory template is missing",
                    "Stable 1.0 requires advisory and denylist response template evidence.",
                    "security-drills-summary",
                )
            )
        if security_summary.get("fixtureOnly") is True or security_summary.get("nonRelease") is True:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Security drill summary is marked non-release",
                    "Stable 1.0 cannot depend on fixture-only or non-release security drill evidence.",
                    "security-drills-summary",
                )
            )
    return domain_result(domain_id, "Security drill criteria", SECURITY_RESPONSE_EVIDENCE_IDS, blockers, [])


def network_operation_count(network_summary: dict[str, Any] | None) -> int:
    if not isinstance(network_summary, dict):
        return 0
    explicit = network_summary.get("operationCount")
    if isinstance(explicit, int) and not isinstance(explicit, bool):
        return explicit
    count = 0
    apps = network_summary.get("apps") if isinstance(network_summary.get("apps"), dict) else {}
    for app_summary in apps.values():
        if isinstance(app_summary, dict):
            for key in ("pollAttempts", "updatesObserved", "subscriptions"):
                value = app_summary.get(key)
                if isinstance(value, int) and not isinstance(value, bool):
                    count += value
    trust = network_summary.get("trustGraph") if isinstance(network_summary.get("trustGraph"), dict) else {}
    value = trust.get("importsAttempted")
    if isinstance(value, int) and not isinstance(value, bool):
        count += value
    return count


def evaluate_live_multi_node_soak(
    evidence: dict[str, dict[str, Any]],
    multi_node: dict[str, Any] | None,
    network: dict[str, Any] | None,
    policy: dict[str, Any],
    now: dt.datetime,
    candidate_release_id: str,
) -> dict[str, Any]:
    domain_id = "live-multi-node-soak"
    blockers = add_required_evidence_blockers(
        evidence,
        domain_id,
        NETWORK_SCALE_EVIDENCE_IDS,
        "release-certification",
    )
    required_soak = policy.get("requiredSoak") if isinstance(policy.get("requiredSoak"), dict) else {}
    accepted_multi = set(required_soak.get("acceptedMultiNodeModes", ["hybrid", "live"]))
    accepted_network = set(required_soak.get("acceptedNetworkScaleModes", ["simulated-rc-soak", "live-rc-soak"]))
    min_ops = positive_int(required_soak.get("minimumOperationCount")) or 500
    max_age_days = positive_int(required_soak.get("maximumEvidenceAgeDays"))
    if max_age_days is None:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.live-multi-node-soak",
                "Stable soak freshness policy is missing",
                "requiredSoak.maximumEvidenceAgeDays must be a positive integer.",
                "stable-readiness-policy",
            )
        )
    if not isinstance(multi_node, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.live-multi-node-soak",
                "Multi-node beta soak summary is missing",
                "Stable 1.0 requires previous-candidate upgrade and multi-node soak evidence.",
                "multi-node-beta-soak-summary",
            )
        )
    else:
        if candidate_release_id:
            release_identities = multi_node_candidate_release_ids(multi_node)
            mismatched_release_ids = [
                (source, release_id)
                for source, release_id in release_identities
                if release_id != candidate_release_id
            ]
            if not release_identities or mismatched_release_ids:
                if mismatched_release_ids:
                    release_id_source, multi_node_release_id = mismatched_release_ids[0]
                else:
                    release_id_source, multi_node_release_id = "missing", "missing"
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.live-multi-node-soak",
                        "Multi-node soak summary is not bound to this release",
                        "Stable 1.0 requires multi-node soak evidence to match the production beta "
                        f"releaseId; multi-node {release_id_source}={multi_node_release_id or 'missing'}, "
                        f"production={candidate_release_id}.",
                        "multi-node-beta-soak-summary",
                    )
                )
        mode = str(multi_node.get("mode", "missing"))
        if mode not in accepted_multi:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.live-multi-node-soak",
                    "Multi-node evidence mode is not Stable-compatible",
                    f"Multi-node mode is {mode}; accepted modes are {', '.join(sorted(accepted_multi))}.",
                    "multi-node-beta-soak-summary",
                )
            )
        if not status_ok(multi_node.get("status")) or multi_node.get("promotionReady") is not True:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.live-multi-node-soak",
                    "Multi-node beta soak summary is not promotion-ready",
                    "Stable 1.0 requires passing multi-node beta soak and upgrade evidence.",
                    "multi-node-beta-soak-summary",
                )
            )
        if max_age_days is not None:
            freshness = evidence_age_blocker(
                domain_id=domain_id,
                evidence_id="stable-1.0.live-multi-node-soak",
                title="Multi-node soak summary",
                source="multi-node-beta-soak-summary",
                generated_at=multi_node.get("generatedAt"),
                now=now,
                maximum_age_days=max_age_days,
                label="multi-node soak summary",
            )
            if freshness is not None:
                blockers.append(freshness)
        redaction = multi_node.get("redaction") if isinstance(multi_node.get("redaction"), dict) else {}
        if normalize_status(redaction.get("status", "missing")) != "pass" or redaction.get("findings"):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.redaction",
                    "Multi-node soak redaction did not pass",
                    "Stable 1.0 soak artifacts must not leak raw content, app data, private URIs, tokens, or paths.",
                    "multi-node-beta-soak-summary",
                )
            )
        scenario_statuses = (
            multi_node.get("scenarioStatuses")
            if isinstance(multi_node.get("scenarioStatuses"), dict)
            else {}
        )
        scenario_to_evidence = dict(multi_node_beta_soak.SCENARIO_EVIDENCE_IDS)
        for scenario_id, evidence_id in scenario_to_evidence.items():
            if normalize_status(scenario_statuses.get(scenario_id, "missing")) != "pass":
                blockers.append(
                    blocker_issue(
                        domain_id,
                        evidence_id,
                        "Multi-node Stable 1.0 scenario is not passing",
                        f"{scenario_id} status is {scenario_statuses.get(scenario_id, 'missing')}.",
                        "multi-node-beta-soak-summary",
                    )
                )
        upgrade = multi_node.get("previousCandidateUpgrade")
        if not isinstance(upgrade, dict) or normalize_status(upgrade.get("status", "missing")) != "pass":
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.previous-candidate-upgrade",
                    "Previous-candidate upgrade evidence is missing or failing",
                    "Stable 1.0 requires a passing previous-candidate upgrade drill with backup/restore and app-data migration.",
                    "multi-node-beta-soak-summary",
                )
            )
        else:
            for key in (
                "firstPartyAppMigrationStatus",
                "backupBeforeUpdateStatus",
                "restoreIntoCleanNodeStatus",
                "rollbackStatus",
                "socialInboxMigrationStatus",
                "trustGraphMigrationStatus",
                "supportBundleRedactionStatus",
            ):
                if normalize_status(upgrade.get(key, "missing")) != "pass":
                    blockers.append(
                        blocker_issue(
                            domain_id,
                            "stable-1.0.previous-candidate-upgrade",
                            "Previous-candidate upgrade subcheck is not passing",
                            f"{key} is {upgrade.get(key, 'missing')}.",
                            "multi-node-beta-soak-summary",
                        )
                    )
    if not isinstance(network, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.live-multi-node-soak",
                "Network-scale soak summary is missing",
                "Stable 1.0 requires network-scale or live RC soak evidence.",
                "network-scale-soak-summary",
            )
        )
    else:
        mode = str(network.get("mode", "missing"))
        if mode not in accepted_network:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.live-multi-node-soak",
                    "Network-scale soak mode is not Stable-compatible",
                    f"Network-scale mode is {mode}; accepted modes are {', '.join(sorted(accepted_network))}.",
                    "network-scale-soak-summary",
                )
            )
        if not status_ok(network.get("status")):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.live-multi-node-soak",
                    "Network-scale soak summary is not passing",
                    f"Network-scale status is {network.get('status', 'missing')}.",
                    "network-scale-soak-summary",
                )
            )
        if max_age_days is not None:
            freshness = evidence_age_blocker(
                domain_id=domain_id,
                evidence_id="stable-1.0.live-multi-node-soak",
                title="Network-scale soak summary",
                source="network-scale-soak-summary",
                generated_at=network.get("generatedAt"),
                now=now,
                maximum_age_days=max_age_days,
                label="network-scale soak summary",
            )
            if freshness is not None:
                blockers.append(freshness)
        operations = network_operation_count(network)
        if operations < min_ops:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.live-multi-node-soak",
                    "Network-scale soak operation count is insufficient",
                    f"Network-scale operation count is {operations}; policy minimum is {min_ops}.",
                    "network-scale-soak-summary",
                )
            )
        redaction = network.get("redaction") if isinstance(network.get("redaction"), dict) else None
        redaction_status = (
            normalize_status(redaction.get("status", "missing"))
            if isinstance(redaction, dict)
            else "missing"
        )
        if (
            redaction_status != "pass"
            or redaction.get("findings")
            or recursive_redaction_failure(redaction)
        ):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.redaction",
                    "Network-scale soak redaction did not pass",
                    "Stable 1.0 network-scale artifacts must be metadata-only.",
                    "network-scale-soak-summary",
                )
            )
    return domain_result(domain_id, "Live, multi-node, and network-scale evidence", (*NETWORK_SCALE_EVIDENCE_IDS, *MULTI_NODE_SCENARIO_EVIDENCE_IDS), blockers, [])


def evaluate_legacy(evidence: dict[str, dict[str, Any]]) -> dict[str, Any]:
    domain_id = "legacy-plugin-migration"
    blockers = add_required_evidence_blockers(
        evidence,
        domain_id,
        LEGACY_EVIDENCE_IDS,
        "release-certification",
    )
    final_surface = evidence_details(evidence.get("legacy-admin.final-admin-surface"))
    categories = final_surface.get("categories") if isinstance(final_surface.get("categories"), dict) else {}
    mutating_gap = final_surface.get("waveFivePromotedRouteIds")
    if isinstance(mutating_gap, list) and mutating_gap:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.legacy-admin-mutating-path",
                "Legacy admin promoted new Wave 5 paths",
                "Stable 1.0 forbids new legacy admin mutating paths outside explicit emergency-only classification.",
                "legacy-admin.final-admin-surface",
            )
        )
    if not isinstance(categories, dict) or "removedByDefaultAdmin" not in categories:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.legacy-plugin-migration",
                "Legacy admin final-surface categories are missing",
                "Stable 1.0 requires explicit maintenance-only, retained browse, and emergency fallback boundaries.",
                "legacy-admin.final-admin-surface",
            )
        )
    migration = evidence_details(evidence.get("legacy-plugin.migration-finalization")).get("checks")
    if isinstance(migration, dict):
        for key in (
            "cookbookExists",
            "migrationMatrixPresent",
            "webOfTrustMapsToTrustGraphLocalRc",
            "freetalkSoneMapsToSocialInboxRc",
            "freemailFutureMailPatternOnly",
            "oldPluginCompatibilityAbsent",
            "sourceSurfaceAuditPasses",
            "redactionChecksPass",
        ):
            if migration.get(key) is not True:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.legacy-plugin-migration",
                        "Legacy plugin migration criterion is not passing",
                        f"{key} is not true.",
                        "legacy-plugin.migration-finalization",
                    )
                )
    return domain_result(domain_id, "Legacy admin and plugin migration", LEGACY_EVIDENCE_IDS, blockers, [])


def evaluate_support_feedback(
    evidence: dict[str, dict[str, Any]],
    known_issues: dict[str, Any] | None,
    workspace_root: Path,
) -> dict[str, Any]:
    domain_id = "support-feedback-readiness"
    blockers = add_required_evidence_blockers(
        evidence,
        domain_id,
        SUPPORT_FEEDBACK_EVIDENCE_IDS,
        "release-certification",
    )
    if not isinstance(known_issues, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.known-limitations",
                "Public beta known issues tracker is missing",
                "Stable 1.0 requires a redaction-safe known issues tracker.",
                "public-beta-known-issues",
            )
        )
    else:
        redaction_policy = known_issues.get("redactionPolicy") if isinstance(known_issues.get("redactionPolicy"), dict) else {}
        for key, expected in (
            ("rawSupportBundlesStored", False),
            ("rawAppDataStored", False),
            ("rawContentStored", False),
            ("privateInsertUrisStored", False),
            ("absoluteLocalPathsStored", False),
        ):
            if redaction_policy.get(key) is not expected:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.support-feedback-redaction",
                        "Known issues tracker redaction policy is unsafe",
                        f"redactionPolicy.{key} must be {str(expected).lower()}.",
                        "public-beta-known-issues",
                    )
                )
        for known_issue in known_issues.get("knownIssues", []):
            if not isinstance(known_issue, dict):
                continue
            severity = str(known_issue.get("severity", "")).lower()
            status = str(known_issue.get("status", "")).lower()
            fixed = str(known_issue.get("fixedInReleaseId", "")).lower()
            open_issue = status not in {"fixed", "resolved", "closed"} and fixed in {"", "unfixed", "none"}
            if open_issue and ("critical" in severity or "blocker" in severity):
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.critical-known-issue",
                        "Unresolved critical known issue blocks Stable 1.0",
                        f"Known issue {known_issue.get('knownIssueId', 'unknown')} is unresolved with severity {known_issue.get('severity', 'missing')}.",
                        "public-beta-known-issues",
                    )
                )
    missing_docs = [path for path in DOC_PATHS if not (workspace_root / path).is_file()]
    if missing_docs:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.release-notes-known-limitations",
                "Stable 1.0 readiness documentation is incomplete",
                "Missing docs: " + ", ".join(missing_docs),
                "workspace-docs",
            )
        )
    return domain_result(domain_id, "Public beta support and feedback readiness", SUPPORT_FEEDBACK_EVIDENCE_IDS, blockers, [])


def limitation_open(limitation: dict[str, Any]) -> bool:
    return str(limitation.get("status", "")).lower() not in {"resolved", "fixed", "closed", "done"}


def safe_limitation(limitation: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "id",
        "title",
        "category",
        "classification",
        "status",
        "summary",
        "evidenceIds",
        "boundedBy",
    )
    return {key: limitation[key] for key in keys if key in limitation}


def evaluate_known_limitations(
    limitations_doc: dict[str, Any] | None,
    waivers: list[StableWaiver],
    policy: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    domain_id = "known-limitations"
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    allowed: list[dict[str, Any]] = []
    disallowed: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    allowed_categories = {
        str(category).strip()
        for category in policy.get("allowedLimitationCategories", [])
        if str(category).strip()
    }
    disallowed_categories = {
        str(category).strip()
        for category in policy.get("disallowedLimitationCategories", [])
        if str(category).strip()
    }
    if not isinstance(limitations_doc, dict) or not isinstance(limitations_doc.get("limitations"), list):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.known-limitations",
                "Stable 1.0 known limitations source is missing",
                "Stable 1.0 requires a deterministic known limitations source.",
                "stable-known-limitations",
            )
        )
        return domain_result(domain_id, "Known limitations", ("stable-1.0.known-limitations",), blockers, warnings), allowed, disallowed, resolved
    for raw in limitations_doc.get("limitations", []):
        if not isinstance(raw, dict):
            continue
        limitation = safe_limitation(raw)
        classification = str(raw.get("classification", "")).lower()
        is_open = limitation_open(raw)
        if not is_open:
            resolved.append(limitation)
            continue
        limitation_id = str(raw.get("id", "stable-1.0.unknown-limitation"))
        category = str(raw.get("category", "")).strip()
        if classification == "allowed-for-stable-1.0":
            if category in disallowed_categories:
                disallowed.append(limitation)
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.known-limitations",
                        "Stable-forbidden limitation category was marked allowed",
                        f"{limitation_id} uses disallowed category {category} and cannot be allowed for Stable 1.0.",
                        "stable-known-limitations",
                        limitation_id=limitation_id,
                    )
                )
            elif category not in allowed_categories:
                disallowed.append(limitation)
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.known-limitations",
                        "Allowed Stable limitation category is not policy-approved",
                        f"{limitation_id} uses category {category or 'missing'}, which is not in allowedLimitationCategories.",
                        "stable-known-limitations",
                        limitation_id=limitation_id,
                    )
                )
            else:
                allowed.append(limitation)
        elif classification == "requires-waiver-before-stable":
            waiver = active_waiver_for(waivers, limitation_id, f"limitation.{limitation_id}")
            if waiver is None:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.known-limitations",
                        "Stable limitation requires a waiver",
                        f"{limitation_id} is open and requires an explicit Stable 1.0 waiver.",
                        "stable-known-limitations",
                        waivable=True,
                        limitation_id=limitation_id,
                    )
                )
            else:
                warnings.append(
                    warning_issue(
                        domain_id,
                        "stable-1.0.known-limitations",
                        "Stable limitation is covered by waiver",
                        f"{limitation_id} remains open under waiver {waiver.id}.",
                        "stable-known-limitations",
                    )
                )
        elif classification in {"blocks-stable-1.0", "beta-only"}:
            disallowed.append(limitation)
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.known-limitations",
                    "Stable-forbidden limitation remains open",
                    f"{limitation_id} is {classification} and remains {raw.get('status', 'open')}.",
                    "stable-known-limitations",
                    limitation_id=limitation_id,
                )
            )
        else:
            disallowed.append(limitation)
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.known-limitations",
                    "Known limitation has an unknown classification",
                    f"{limitation_id} classification is {raw.get('classification', 'missing')}; Stable 1.0 requires a recognized classification.",
                    "stable-known-limitations",
                    limitation_id=limitation_id,
                )
            )
    return domain_result(domain_id, "Known limitations", ("stable-1.0.known-limitations",), blockers, warnings, allowed), allowed, disallowed, resolved


def validate_waivers_against_blockers(
    waivers: list[StableWaiver],
    blockers: list[dict[str, Any]],
    policy: dict[str, Any],
) -> list[dict[str, Any]]:
    validation: list[dict[str, Any]] = []
    non_waivable = set(policy.get("nonWaivableBlockers", []))
    for waiver in waivers:
        if waiver.validation_errors:
            validation.append(
                blocker_issue(
                    "known-limitations",
                    "stable-1.0.waiver-validation",
                    "Stable 1.0 waiver is invalid",
                    f"Waiver {waiver.id} is invalid: {'; '.join(waiver.validation_errors)}.",
                    waiver.source,
                )
            )
            continue
        for blocker in blockers:
            if not waiver.matches(
                str(blocker.get("id", "")),
                str(blocker.get("evidenceId", "")),
                str(blocker.get("limitationId", "")),
            ):
                continue
            if not blocker.get("waivable") or blocker.get("evidenceId") in non_waivable or blocker.get("id") in non_waivable:
                validation.append(
                    blocker_issue(
                        "known-limitations",
                        "stable-1.0.waiver-validation",
                        "Waiver targets a non-waivable Stable 1.0 blocker",
                        f"Waiver {waiver.id} cannot waive {blocker.get('evidenceId')}.",
                        waiver.source,
                    )
                )
    return validation


def build_inputs(settings: Settings) -> tuple[dict[str, Any], dict[str, Path], list[Path]]:
    paths: dict[str, Path] = {}
    values: dict[str, Any] = {}
    scan_targets: list[Path] = []
    mapping = {
        "productionBetaSummary": settings.production_beta_summary,
        "goNoGoSummary": settings.go_no_go_summary,
        "releaseCertificationSummary": settings.release_certification_summary,
        "ecosystemMatrix": settings.ecosystem_matrix,
        "appPlatformSummary": settings.app_platform_summary,
        "multiNodeSoakSummary": settings.multi_node_soak_summary,
        "networkScaleSoakSummary": settings.network_scale_soak_summary,
        "securityDrillsSummary": settings.security_drills_summary,
        "publicBetaKnownIssues": settings.public_beta_known_issues,
        "policy": settings.policy,
        "stableKnownLimitations": settings.stable_known_limitations,
        "waivers": settings.waivers,
    }
    for name, path in mapping.items():
        if path is None:
            continue
        paths[name] = path
        scan_targets.append(path)
        value = read_json(path)
        if value is not None:
            values[name] = value
    return values, paths, scan_targets


def evidence_item(evidence_id: str, status: str, summary: str, details: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": evidence_id,
        "status": status,
        "requiredForStable10": True,
        "summary": summary,
        "details": details,
    }


def build_summary(
    settings: Settings,
    domains: list[dict[str, Any]],
    redaction: dict[str, Any],
    input_paths: dict[str, Path],
    allowed_limitations: list[dict[str, Any]],
    disallowed_limitations: list[dict[str, Any]],
    resolved_limitations: list[dict[str, Any]],
    waivers: list[StableWaiver],
) -> dict[str, Any]:
    blockers = [blocker for domain in domains for blocker in domain.get("blockers", [])]
    warnings = [warning for domain in domains for warning in domain.get("warnings", [])]
    if redaction.get("status") != "pass":
        redaction_blocker = blocker_issue(
            "redaction",
            "stable-1.0.redaction",
            "Stable 1.0 readiness redaction scan failed",
            f"Stable 1.0 readiness scanner found {redaction.get('findingCount', 0)} finding(s).",
            "stable-readiness-redaction",
        )
        blockers.append(redaction_blocker)
        for domain in domains:
            if domain.get("id") == "redaction":
                domain.setdefault("blockers", []).append(redaction_blocker)
                domain["status"] = "fail"
                domain["summary"] = redaction_blocker["summary"]
                break
    blocker_count = len(blockers)
    warning_count = len(warnings)
    allowed_count = len(allowed_limitations)
    disallowed_count = len(disallowed_limitations)
    if blocker_count or disallowed_count or redaction.get("status") != "pass":
        status = "fail"
        decision = "not-ready"
        stable_ready = False
    elif allowed_count:
        status = "warn"
        decision = "ready-with-allowed-limitations"
        stable_ready = True
    elif warning_count:
        status = "warn"
        decision = "ready"
        stable_ready = True
    else:
        status = "pass"
        decision = "ready"
        stable_ready = True
    release_id = "stable-1.0-candidate"
    production = read_json(settings.production_beta_summary)
    if isinstance(production, dict) and isinstance(production.get("releaseId"), str):
        release_id = production["releaseId"]
    input_refs = {
        key: input_reference(input_paths.get(key), settings.workspace_root)
        for key in (
            "productionBetaSummary",
            "goNoGoSummary",
            "releaseCertificationSummary",
            "ecosystemMatrix",
            "appPlatformSummary",
            "multiNodeSoakSummary",
            "networkScaleSoakSummary",
            "securityDrillsSummary",
            "publicBetaKnownIssues",
            "policy",
            "stableKnownLimitations",
        )
    }
    evidence = [
        evidence_item(
            "stable-1.0.readiness-gate",
            status,
            f"Stable 1.0 readiness decision is {decision}.",
            {"decision": decision, "stableReady": stable_ready},
        )
    ]
    for domain in domains:
        evidence_id = {
            "production-beta-state": "stable-1.0.production-beta-state",
            "release-certification-summary": "stable-1.0.release-certification",
            "platform-api-1.0": "stable-1.0.platform-api-compatibility",
            "app-ecosystem-maturity": "stable-1.0.app-ecosystem-maturity",
            "third-party-intake": "stable-1.0.third-party-intake",
            "security-drills": "stable-1.0.security-drills",
            "live-multi-node-soak": "stable-1.0.live-multi-node-soak",
            "legacy-plugin-migration": "stable-1.0.legacy-plugin-migration",
            "support-feedback-readiness": "stable-1.0.support-feedback-readiness",
            "known-limitations": "stable-1.0.known-limitations",
            "redaction": "stable-1.0.redaction",
        }.get(str(domain.get("id")), f"stable-1.0.{domain.get('id', 'domain')}")
        evidence.append(
            evidence_item(
                evidence_id,
                str(domain.get("status", "missing")),
                str(domain.get("summary", "")),
                {
                    "blockerCount": len(domain.get("blockers", [])),
                    "warningCount": len(domain.get("warnings", [])),
                    "allowedLimitationCount": len(domain.get("allowedLimitations", [])),
                },
            )
        )
    summary = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "stable-1.0-readiness",
        "tool": TOOL_NAME,
        "generatedAt": settings.generated_at,
        "releaseId": release_id,
        "status": status,
        "decision": decision,
        "stableReady": stable_ready,
        "blockerCount": blocker_count,
        "warningCount": warning_count,
        "allowedLimitationCount": allowed_count,
        "disallowedLimitationCount": disallowed_count,
        "domains": domains,
        "blockers": blockers,
        "warnings": warnings,
        "allowedLimitations": allowed_limitations,
        "disallowedLimitations": disallowed_limitations,
        "resolvedLimitations": resolved_limitations,
        "redaction": redaction,
        "waivers": [waiver.to_json() for waiver in waivers],
        "inputs": input_refs,
        "evidence": evidence,
        "artifactRefs": {
            "summary": SUMMARY_FILE,
            "report": REPORT_FILE,
            "knownLimitations": KNOWN_LIMITATIONS_FILE,
            "blockers": BLOCKERS_FILE,
        },
    }
    return dashboard.sanitize_value(summary, settings.workspace_root, settings.out_dir)


def render_report(summary: dict[str, Any]) -> str:
    lines = [
        "# Stable 1.0 Readiness Report",
        "",
        f"- Release ID: `{summary.get('releaseId', '')}`",
        f"- Decision: `{summary.get('decision', '')}`",
        f"- Stable ready: `{str(summary.get('stableReady', False)).lower()}`",
        f"- Status: `{summary.get('status', '')}`",
        f"- Generated: `{summary.get('generatedAt', '')}`",
        f"- Blockers: `{summary.get('blockerCount', 0)}`",
        f"- Warnings: `{summary.get('warningCount', 0)}`",
        f"- Allowed limitations: `{summary.get('allowedLimitationCount', 0)}`",
        f"- Disallowed limitations: `{summary.get('disallowedLimitationCount', 0)}`",
        "",
        "## Domains",
        "",
        "| Domain | Status | Summary |",
        "| --- | --- | --- |",
    ]
    for domain in summary.get("domains", []):
        if isinstance(domain, dict):
            lines.append(
                "| {} | `{}` | {} |".format(
                    dashboard.markdown_cell(domain.get("title", domain.get("id", ""))),
                    domain.get("status", ""),
                    dashboard.markdown_cell(domain.get("summary", "")),
                )
            )
    lines.extend(["", "## Blockers", ""])
    blockers = summary.get("blockers") if isinstance(summary.get("blockers"), list) else []
    if not blockers:
        lines.append("No Stable 1.0 blockers.")
    else:
        for blocker in blockers:
            if isinstance(blocker, dict):
                lines.append(f"- `{blocker.get('evidenceId', '')}`: {blocker.get('summary', '')}")
    lines.extend(["", "## Warnings", ""])
    warnings = summary.get("warnings") if isinstance(summary.get("warnings"), list) else []
    if not warnings:
        lines.append("No Stable 1.0 warnings.")
    else:
        for warning in warnings:
            if isinstance(warning, dict):
                lines.append(f"- `{warning.get('evidenceId', '')}`: {warning.get('summary', '')}")
    lines.extend(["", "## Allowed Limitations", ""])
    allowed = summary.get("allowedLimitations") if isinstance(summary.get("allowedLimitations"), list) else []
    if not allowed:
        lines.append("No allowed limitations remain open.")
    else:
        for limitation in allowed:
            if isinstance(limitation, dict):
                lines.append(f"- `{limitation.get('id', '')}`: {limitation.get('summary', '')}")
    lines.extend(["", "## Disallowed Limitations", ""])
    disallowed = summary.get("disallowedLimitations") if isinstance(summary.get("disallowedLimitations"), list) else []
    if not disallowed:
        lines.append("No disallowed limitations remain open.")
    else:
        for limitation in disallowed:
            if isinstance(limitation, dict):
                lines.append(f"- `{limitation.get('id', '')}`: {limitation.get('summary', '')}")
    redaction = summary.get("redaction") if isinstance(summary.get("redaction"), dict) else {}
    lines.extend(
        [
            "",
            "## Redaction",
            "",
            f"- Status: `{redaction.get('status', 'missing')}`",
            f"- Findings: `{redaction.get('findingCount', 0)}`",
            f"- Critical findings: `{redaction.get('criticalFindingCount', 0)}`",
            "",
            "## Inputs",
            "",
        ]
    )
    inputs = summary.get("inputs") if isinstance(summary.get("inputs"), dict) else {}
    for name in sorted(inputs):
        value = inputs[name]
        if isinstance(value, dict):
            lines.append(f"- `{name}`: `{value.get('path', value.get('status', 'missing'))}`")
    lines.append("")
    return "\n".join(lines)


def write_artifacts(summary: dict[str, Any], settings: Settings) -> None:
    write_json(settings.out_dir / SUMMARY_FILE, summary)
    write_text(settings.out_dir / REPORT_FILE, render_report(summary))
    write_json(
        settings.out_dir / KNOWN_LIMITATIONS_FILE,
        {
            "schemaVersion": SCHEMA_VERSION,
            "kind": "stable-1.0-known-limitations-report",
            "generatedAt": summary.get("generatedAt", ""),
            "releaseId": summary.get("releaseId", ""),
            "allowedLimitations": summary.get("allowedLimitations", []),
            "disallowedLimitations": summary.get("disallowedLimitations", []),
            "resolvedLimitations": summary.get("resolvedLimitations", []),
        },
    )
    write_json(
        settings.out_dir / BLOCKERS_FILE,
        {
            "schemaVersion": SCHEMA_VERSION,
            "kind": "stable-1.0-blockers",
            "generatedAt": summary.get("generatedAt", ""),
            "releaseId": summary.get("releaseId", ""),
            "blockerCount": summary.get("blockerCount", 0),
            "blockers": summary.get("blockers", []),
        },
    )


def run(settings: Settings) -> tuple[dict[str, Any], int]:
    settings.out_dir.mkdir(parents=True, exist_ok=True)
    generated_at, now = parse_generated_at(settings.generated_at)
    settings = dataclasses.replace(settings, generated_at=generated_at)
    inputs, input_paths, scan_targets = build_inputs(settings)
    policy_value = inputs.get("policy")
    policy = policy_value if isinstance(policy_value, dict) else {}
    limitations = (
        inputs.get("stableKnownLimitations")
        if isinstance(inputs.get("stableKnownLimitations"), dict)
        else {}
    )
    waivers = load_waivers(settings.waivers, now, settings.workspace_root)
    redaction = dashboard.redaction_report(dashboard.scan_paths(scan_targets, settings.workspace_root, settings.out_dir))
    evidence = evidence_map_from_summaries(
        inputs.get("releaseCertificationSummary"),
        inputs.get("appPlatformSummary"),
    )
    production_summary = inputs.get("productionBetaSummary")
    candidate_release_id = (
        str(production_summary.get("releaseId", "")).strip()
        if isinstance(production_summary, dict)
        else ""
    )
    known_limitations_domain, allowed, disallowed, resolved = evaluate_known_limitations(
        limitations,
        waivers,
        policy,
    )
    domains = [
        evaluate_policy(
            policy_value if isinstance(policy_value, dict) else None,
            input_paths.get("policy", settings.policy),
            settings.workspace_root,
        ),
        evaluate_production_beta_state(
            inputs.get("productionBetaSummary"),
            inputs.get("goNoGoSummary"),
            policy,
        ),
        evaluate_release_certification_summary(inputs.get("releaseCertificationSummary")),
        evaluate_platform_api(evidence, policy),
        evaluate_app_ecosystem(evidence),
        evaluate_third_party(evidence),
        evaluate_security(
            evidence,
            inputs.get("securityDrillsSummary"),
            policy,
            now,
            candidate_release_id,
        ),
        evaluate_live_multi_node_soak(
            evidence,
            inputs.get("multiNodeSoakSummary"),
            inputs.get("networkScaleSoakSummary"),
            policy,
            now,
            candidate_release_id,
        ),
        evaluate_legacy(evidence),
        evaluate_support_feedback(
            evidence,
            inputs.get("publicBetaKnownIssues"),
            settings.workspace_root,
        ),
        known_limitations_domain,
        domain_result("redaction", "Redaction safety", ("stable-1.0.redaction",), [], []),
    ]
    validation_blockers = validate_waivers_against_blockers(
        waivers,
        [blocker for domain in domains for blocker in domain.get("blockers", [])],
        policy,
    )
    if validation_blockers:
        for domain in domains:
            if domain.get("id") == "known-limitations":
                domain.setdefault("blockers", []).extend(validation_blockers)
                domain["status"] = "fail"
                domain["summary"] = validation_blockers[0]["summary"]
                break
    summary = build_summary(settings, domains, redaction, input_paths, allowed, disallowed, resolved, waivers)
    write_artifacts(summary, settings)
    output_findings = dashboard.scan_paths(
        [
            settings.out_dir / SUMMARY_FILE,
            settings.out_dir / REPORT_FILE,
            settings.out_dir / KNOWN_LIMITATIONS_FILE,
            settings.out_dir / BLOCKERS_FILE,
        ],
        settings.workspace_root,
        settings.out_dir,
    )
    if output_findings:
        combined = [
            *redaction.get("findings", []),
            *output_findings,
        ]
        final_redaction = dashboard.redaction_report([finding for finding in combined if isinstance(finding, dict)])
        summary = build_summary(
            settings,
            domains,
            final_redaction,
            input_paths,
            allowed,
            disallowed,
            resolved,
            waivers,
        )
        write_artifacts(summary, settings)
    return summary, 0 if summary.get("stableReady") is True else 1


def write_case_files(root: Path, inputs: dict[str, Any], limitations: dict[str, Any]) -> dict[str, Path]:
    case_dir = root / "inputs"
    case_dir.mkdir(parents=True, exist_ok=True)
    mapping = {
        "productionBetaSummary": "production-beta-summary.json",
        "goNoGoSummary": "go-no-go-summary.json",
        "releaseCertificationSummary": "release-certification-summary.json",
        "ecosystemMatrix": "ecosystem-certification-matrix.json",
        "appPlatformSummary": "app-platform-summary.json",
        "multiNodeSoakSummary": "multi-node-beta-soak-summary.json",
        "networkScaleSoakSummary": "network-scale-soak-summary.json",
        "securityDrillsSummary": "security-drills-summary.json",
        "publicBetaKnownIssues": "public-beta-known-issues.json",
    }
    paths: dict[str, Path] = {}
    for key, file_name in mapping.items():
        if key in inputs:
            path = case_dir / file_name
            write_json(path, inputs[key])
            paths[key] = path
    limitations_path = case_dir / "stable-known-limitations.json"
    write_json(limitations_path, limitations)
    paths["stableKnownLimitations"] = limitations_path
    return paths


def base_self_test_inputs() -> tuple[dict[str, Any], dict[str, Any]]:
    go_fixture = dashboard.load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    go_inputs = copy.deepcopy(go_fixture["inputs"])
    app_platform = read_json(FIXTURE_DIR / "self-test-app-platform-smoke.json") or {}
    network = copy.deepcopy(read_json(FIXTURE_DIR / "self-test-network-scale-soak.json") or {})
    network["mode"] = "live-rc-soak"
    network["status"] = "pass"
    production = copy.deepcopy(go_inputs["productionBetaSummary"])
    production["releaseId"] = "cryptad-beta-270"
    production["version"] = "270"
    production["signingProfile"] = {
        "kind": "production",
        "generatedTestKeys": False,
        "appKeyId": "production-app-key",
        "reviewerKeyId": "production-reviewer-key",
        "privateKeyMaterialIncluded": False,
    }
    production["pipelineStages"] = {
        "crypta-app-launcher-install": {"status": "pass"},
        "gradle-full-build": {"status": "pass"},
        "first-party-app-staging": {"status": "pass"},
        "first-party-app-signing": {"status": "pass"},
        "first-party-app-verification": {"status": "pass"},
    }
    go_no_go = {
        "schemaVersion": 1,
        "tool": "production-beta-go-no-go-dashboard",
        "mode": "production-beta",
        "releaseId": "cryptad-beta-270",
        "decision": "go",
        "promotionReady": True,
        "summary": {
            "blockers": 0,
            "warnings": 0,
            "waiversUsed": 0,
            "criticalRedactionFindings": 0,
        },
        "redaction": {"schemaVersion": 1, "status": "pass", "findingCount": 0, "findings": []},
    }
    release_cert = {
        "schemaVersion": 1,
        "tool": "release-certification",
        "mode": "release-candidate",
        "status": "pass",
        "releaseCandidatePassed": True,
        "ecosystemRcPassed": True,
        "evidence": copy.deepcopy(app_platform.get("evidence", [])),
        "redaction": {
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
    security = copy.deepcopy(go_inputs["securityDrillsSummary"])
    security["releaseId"] = "cryptad-beta-270"
    security["generatedAt"] = DEFAULT_GENERATED_AT
    multi_node = copy.deepcopy(go_inputs["multiNodeBetaSoakSummary"])
    multi_node["mode"] = "hybrid"
    multi_node["generatedAt"] = DEFAULT_GENERATED_AT
    multi_node["currentCandidate"] = {"version": "270", "catalogChannel": "stable"}
    scenario_statuses = (
        multi_node.get("scenarioStatuses")
        if isinstance(multi_node.get("scenarioStatuses"), dict)
        else {}
    )
    multi_node["scenarioStatuses"] = {
        **{scenario_id: "pass" for scenario_id in multi_node_beta_soak.SCENARIO_EVIDENCE_IDS},
        **scenario_statuses,
    }
    network["generatedAt"] = DEFAULT_GENERATED_AT
    limitations = copy.deepcopy(read_json(DEFAULT_LIMITATIONS) or {})
    inputs = {
        "productionBetaSummary": production,
        "goNoGoSummary": go_no_go,
        "releaseCertificationSummary": release_cert,
        "ecosystemMatrix": copy.deepcopy(go_inputs["ecosystemMatrix"]),
        "appPlatformSummary": app_platform,
        "multiNodeSoakSummary": multi_node,
        "networkScaleSoakSummary": network,
        "securityDrillsSummary": security,
        "publicBetaKnownIssues": copy.deepcopy(read_json(DEFAULT_PUBLIC_BETA_KNOWN_ISSUES) or {}),
    }
    return inputs, limitations


def resolved_limitations(limitations: dict[str, Any]) -> dict[str, Any]:
    copy_value = copy.deepcopy(limitations)
    for limitation in copy_value.get("limitations", []):
        if isinstance(limitation, dict):
            limitation["status"] = "resolved"
    return copy_value


def mutate_evidence(inputs: dict[str, Any], evidence_id: str, mutator: Callable[[dict[str, Any]], None] | None = None, remove: bool = False) -> None:
    evidence = inputs["appPlatformSummary"]["evidence"]
    cert_evidence = inputs["releaseCertificationSummary"]["evidence"]
    for collection in (evidence, cert_evidence):
        if remove:
            collection[:] = [entry for entry in collection if not isinstance(entry, dict) or entry.get("id") != evidence_id]
            continue
        for entry in collection:
            if isinstance(entry, dict) and entry.get("id") == evidence_id and mutator is not None:
                mutator(entry)


def self_test_settings(workspace: Path, out_dir: Path, paths: dict[str, Path], waiver_path: Path | None = None) -> Settings:
    return Settings(
        workspace_root=workspace,
        out_dir=out_dir,
        generated_at=DEFAULT_GENERATED_AT,
        production_beta_summary=paths.get("productionBetaSummary"),
        go_no_go_summary=paths.get("goNoGoSummary"),
        release_certification_summary=paths.get("releaseCertificationSummary"),
        ecosystem_matrix=paths.get("ecosystemMatrix"),
        app_platform_summary=paths.get("appPlatformSummary"),
        multi_node_soak_summary=paths.get("multiNodeSoakSummary"),
        network_scale_soak_summary=paths.get("networkScaleSoakSummary"),
        security_drills_summary=paths.get("securityDrillsSummary"),
        public_beta_known_issues=paths.get("publicBetaKnownIssues"),
        policy=paths.get("policy", DEFAULT_POLICY),
        stable_known_limitations=paths["stableKnownLimitations"],
        waivers=waiver_path,
    )


def run_case(
    root: Path,
    name: str,
    mutator: Callable[[dict[str, Any], dict[str, Any], dict[str, Path]], Path | None] | None,
    expected_decision: str,
    *,
    expect_blocker: str | None = None,
    expect_allowed: str | None = None,
) -> None:
    inputs, limitations = base_self_test_inputs()
    if expected_decision == "ready":
        limitations = resolved_limitations(limitations)
    paths = write_case_files(root / name, inputs, limitations)
    path_keys_before_mutation = set(paths)
    waiver_path = mutator(inputs, limitations, paths) if mutator is not None else None
    if mutator is not None:
        path_overrides = {
            key: value
            for key, value in paths.items()
            if key not in path_keys_before_mutation or key == "policy"
        }
        paths = write_case_files(root / name, inputs, limitations)
        paths.update(path_overrides)
        if waiver_path is not None:
            paths["waivers"] = waiver_path
    settings = self_test_settings(root, root / "out" / name, paths, waiver_path)
    summary, _exit_code = run(settings)
    if summary["decision"] != expected_decision:
        raise AssertionError(f"{name} expected {expected_decision}, got {summary['decision']}: {summary}")
    if expect_blocker:
        blocker_ids = {str(blocker.get("evidenceId")) for blocker in summary.get("blockers", [])}
        if expect_blocker not in blocker_ids:
            raise AssertionError(f"{name} missing blocker {expect_blocker}: {summary.get('blockers')}")
    if expect_allowed:
        allowed_ids = {str(limitation.get("id")) for limitation in summary.get("allowedLimitations", [])}
        if expect_allowed not in allowed_ids:
            raise AssertionError(f"{name} missing allowed limitation {expect_allowed}: {summary.get('allowedLimitations')}")


def run_self_test() -> None:
    expected_cases = {
        "ready",
        "allowed-limitations",
        "missing-production",
        "production-not-ready",
        "production-missing-signing-profile",
        "production-missing-signing-field",
        "production-redaction-findings",
        "go-no-go-no-go",
        "go-no-go-wrong-release-id",
        "go-no-go-non-production-mode",
        "release-certification-failed",
        "release-certification-not-passed",
        "release-certification-non-rc-mode",
        "release-certification-missing-redaction",
        "release-certification-redaction-field-failed",
        "missing-platform-baseline",
        "stable-api-breaking-change",
        "missing-first-party",
        "missing-third-party",
        "stale-security",
        "security-release-id-mismatch",
        "multi-node-release-id-mismatch",
        "stale-security-summary-age",
        "stale-security-artifact-age",
        "missing-previous-upgrade",
        "app-data-migration-scenario-failed",
        "network-redaction-missing",
        "network-redaction-status-missing",
        "network-redaction-findings",
        "network-redaction-status-fail",
        "stale-soak-evidence",
        "insufficient-network",
        "critical-known-issue",
        "beta-only-limitation",
        "allowed-disallowed-category",
        "unknown-limitation-classification",
        "missing-policy",
        "redaction-unsafe",
        "invalid-waiver",
        "incomplete-waiver-metadata",
        "allowed-trust-graph",
        "allowed-social-inbox",
    }
    case_manifest = read_json(FIXTURE_DIR / "stable-1.0-readiness-cases.json")
    manifest_cases = {
        str(case.get("id"))
        for case in case_manifest.get("cases", [])
        if isinstance(case, dict)
    } if isinstance(case_manifest, dict) else set()
    if manifest_cases != expected_cases:
        raise AssertionError(
            "stable readiness fixture manifest does not match self-test cases: "
            f"missing={sorted(expected_cases - manifest_cases)} extra={sorted(manifest_cases - expected_cases)}"
        )
    with tempfile.TemporaryDirectory(prefix="cryptad-stable-readiness-self-test-") as temp_name:
        root = Path(temp_name)
        docs_root = root / "docs"
        (docs_root / "public-beta").mkdir(parents=True)
        (docs_root / "templates").mkdir(parents=True)
        for path in DOC_PATHS:
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"# {Path(path).stem}\n", encoding="utf-8")

        run_case(root, "ready", None, "ready")
        run_case(root, "allowed-limitations", lambda _i, _l, _p: None, "ready-with-allowed-limitations", expect_allowed="stable-1.0.trust-graph-local-scope")

        def missing_production(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs.pop("productionBetaSummary", None)

        run_case(root, "missing-production", missing_production, "not-ready", expect_blocker="stable-1.0.production-beta-state")

        def production_not_ready(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["productionBetaSummary"]["promotionReady"] = False

        run_case(root, "production-not-ready", production_not_ready, "not-ready", expect_blocker="stable-1.0.production-beta-state")

        def production_missing_signing_profile(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["productionBetaSummary"].pop("signingProfile", None)

        run_case(
            root,
            "production-missing-signing-profile",
            production_missing_signing_profile,
            "not-ready",
            expect_blocker="stable-1.0.production-beta-state",
        )

        def production_missing_signing_field(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["productionBetaSummary"]["signingProfile"].pop("generatedTestKeys", None)

        run_case(
            root,
            "production-missing-signing-field",
            production_missing_signing_field,
            "not-ready",
            expect_blocker="stable-1.0.production-beta-state",
        )

        def production_redaction_findings(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["productionBetaSummary"]["redaction"] = {
                "schemaVersion": 1,
                "status": "pass",
                "findingCount": 1,
                "findings": [
                    {
                        "kind": "redaction-fixture",
                        "location": "production-beta-summary",
                        "summary": "Synthetic redaction finding for Stable readiness validation.",
                    }
                ],
            }

        run_case(
            root,
            "production-redaction-findings",
            production_redaction_findings,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def go_no_go_no_go(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["goNoGoSummary"]["decision"] = "no-go"
            inputs["goNoGoSummary"]["promotionReady"] = False

        run_case(root, "go-no-go-no-go", go_no_go_no_go, "not-ready", expect_blocker="stable-1.0.go-no-go-decision")

        def go_no_go_wrong_release_id(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["goNoGoSummary"]["releaseId"] = "cryptad-beta-previous"

        run_case(
            root,
            "go-no-go-wrong-release-id",
            go_no_go_wrong_release_id,
            "not-ready",
            expect_blocker="stable-1.0.go-no-go-decision",
        )

        def go_no_go_non_production_mode(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["goNoGoSummary"]["mode"] = "developer-dry-run"

        run_case(
            root,
            "go-no-go-non-production-mode",
            go_no_go_non_production_mode,
            "not-ready",
            expect_blocker="stable-1.0.go-no-go-decision",
        )

        def release_certification_failed(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["releaseCertificationSummary"]["status"] = "fail"

        run_case(
            root,
            "release-certification-failed",
            release_certification_failed,
            "not-ready",
            expect_blocker="stable-1.0.release-certification",
        )

        def release_certification_not_passed(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["releaseCertificationSummary"]["releaseCandidatePassed"] = False

        run_case(
            root,
            "release-certification-not-passed",
            release_certification_not_passed,
            "not-ready",
            expect_blocker="stable-1.0.release-certification",
        )

        def release_certification_non_rc_mode(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["releaseCertificationSummary"]["mode"] = "pr"

        run_case(
            root,
            "release-certification-non-rc-mode",
            release_certification_non_rc_mode,
            "not-ready",
            expect_blocker="stable-1.0.release-certification",
        )

        def release_certification_missing_redaction(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["releaseCertificationSummary"].pop("redaction", None)

        run_case(
            root,
            "release-certification-missing-redaction",
            release_certification_missing_redaction,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def release_certification_redaction_field_failed(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["releaseCertificationSummary"]["redaction"]["privateInsertUrisExcluded"] = False

        run_case(
            root,
            "release-certification-redaction-field-failed",
            release_certification_redaction_field_failed,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def missing_baseline(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            mutate_evidence(inputs, "platform-api.stable-baseline", remove=True)

        run_case(root, "missing-platform-baseline", missing_baseline, "not-ready", expect_blocker="platform-api.stable-baseline")

        def stable_breaking(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            def mutate(entry: dict[str, Any]) -> None:
                entry["status"] = "fail"
                entry.setdefault("details", {})["errors"] = ["stable_api_endpoint_removed"]

            mutate_evidence(inputs, "platform-api.stable-breaking-change-check", mutate)

        run_case(root, "stable-api-breaking-change", stable_breaking, "not-ready", expect_blocker="platform-api.stable-breaking-change-check")

        def missing_first_party(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            mutate_evidence(inputs, "first-party-app.beta-quality-pass", remove=True)

        run_case(root, "missing-first-party", missing_first_party, "not-ready", expect_blocker="first-party-app.beta-quality-pass")

        def missing_third_party(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            mutate_evidence(inputs, "third-party-intake.beta-catalog-install-smoke", remove=True)

        run_case(root, "missing-third-party", missing_third_party, "not-ready", expect_blocker="third-party-intake.beta-catalog-install-smoke")

        def stale_security(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["securityDrillsSummary"]["staleScenarios"] = ["reviewer-key-compromise"]
            inputs["securityDrillsSummary"]["passedScenarios"] = [
                item for item in inputs["securityDrillsSummary"]["passedScenarios"] if item != "reviewer-key-compromise"
            ]

        run_case(root, "stale-security", stale_security, "not-ready", expect_blocker="stable-1.0.security-drills")

        def security_release_id_mismatch(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["securityDrillsSummary"]["releaseId"] = "cryptad-beta-previous"

        run_case(
            root,
            "security-release-id-mismatch",
            security_release_id_mismatch,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def multi_node_release_id_mismatch(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["multiNodeSoakSummary"]["releaseId"] = "cryptad-beta-previous"

        run_case(
            root,
            "multi-node-release-id-mismatch",
            multi_node_release_id_mismatch,
            "not-ready",
            expect_blocker="stable-1.0.live-multi-node-soak",
        )

        def stale_security_summary_age(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["securityDrillsSummary"]["generatedAt"] = "1969-11-01T00:00:00Z"

        run_case(root, "stale-security-summary-age", stale_security_summary_age, "not-ready", expect_blocker="stable-1.0.security-drills")

        def stale_security_artifact_age(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            artifact = inputs["securityDrillsSummary"]["artifacts"][0]
            artifact["stale"] = True
            artifact["ageDays"] = 31
            artifact["staleReason"] = "Artifact exceeds the Stable 1.0 freshness window."

        run_case(root, "stale-security-artifact-age", stale_security_artifact_age, "not-ready", expect_blocker="stable-1.0.security-drills")

        def missing_previous_upgrade(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["multiNodeSoakSummary"]["previousCandidateUpgrade"]["status"] = "missing"

        run_case(root, "missing-previous-upgrade", missing_previous_upgrade, "not-ready", expect_blocker="stable-1.0.previous-candidate-upgrade")

        def app_data_migration_scenario_failed(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["multiNodeSoakSummary"]["scenarioStatuses"]["app-data-migration"] = "fail"

        run_case(
            root,
            "app-data-migration-scenario-failed",
            app_data_migration_scenario_failed,
            "not-ready",
            expect_blocker="multi-node-beta.app-data-migration",
        )

        def network_redaction_missing(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["networkScaleSoakSummary"].pop("redaction", None)

        run_case(
            root,
            "network-redaction-missing",
            network_redaction_missing,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def network_redaction_status_missing(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["networkScaleSoakSummary"]["redaction"] = {"findings": []}

        run_case(
            root,
            "network-redaction-status-missing",
            network_redaction_status_missing,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def network_redaction_findings(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["networkScaleSoakSummary"]["redaction"] = {
                "status": "pass",
                "findings": [
                    {
                        "kind": "redaction-fixture",
                        "location": "network-scale-soak-summary",
                        "summary": "Synthetic network redaction finding for Stable readiness validation.",
                    }
                ],
            }

        run_case(
            root,
            "network-redaction-findings",
            network_redaction_findings,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def network_redaction_status_fail(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["networkScaleSoakSummary"]["redaction"] = {"status": "fail"}

        run_case(
            root,
            "network-redaction-status-fail",
            network_redaction_status_fail,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def stale_soak_evidence(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["multiNodeSoakSummary"]["generatedAt"] = "1969-11-01T00:00:00Z"
            inputs["networkScaleSoakSummary"]["generatedAt"] = "1969-11-01T00:00:00Z"

        run_case(root, "stale-soak-evidence", stale_soak_evidence, "not-ready", expect_blocker="stable-1.0.live-multi-node-soak")

        def insufficient_network(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["networkScaleSoakSummary"]["apps"] = {}
            inputs["networkScaleSoakSummary"]["trustGraph"] = {"importsAttempted": 0}

        run_case(root, "insufficient-network", insufficient_network, "not-ready", expect_blocker="stable-1.0.live-multi-node-soak")

        def critical_known_issue(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["publicBetaKnownIssues"]["knownIssues"].append(
                {
                    "knownIssueId": "PBKI-CRITICAL-001",
                    "status": "open",
                    "severity": "severity/critical",
                    "fixedInReleaseId": "unfixed",
                }
            )

        run_case(root, "critical-known-issue", critical_known_issue, "not-ready", expect_blocker="stable-1.0.critical-known-issue")

        def beta_only_limitation(_inputs: dict[str, Any], limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            limitations["limitations"].append(
                {
                    "id": "stable-1.0.beta-only-open",
                    "title": "Beta-only limitation remains",
                    "classification": "beta-only",
                    "category": "no-live-or-multi-node-evidence",
                    "status": "open",
                    "summary": "Self-test beta-only limitation.",
                }
            )

        run_case(root, "beta-only-limitation", beta_only_limitation, "not-ready", expect_blocker="stable-1.0.known-limitations")

        def allowed_disallowed_category(_inputs: dict[str, Any], limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            limitations["limitations"].append(
                {
                    "id": "stable-1.0.allowed-redaction-failure",
                    "title": "Disallowed category mislabeled allowed",
                    "classification": "allowed-for-stable-1.0",
                    "category": "redaction-failure",
                    "status": "open",
                    "summary": "Self-test disallowed category marked allowed.",
                }
            )

        run_case(root, "allowed-disallowed-category", allowed_disallowed_category, "not-ready", expect_blocker="stable-1.0.known-limitations")

        def unknown_limitation_classification(_inputs: dict[str, Any], limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            limitations["limitations"].append(
                {
                    "id": "stable-1.0.unknown-classification",
                    "title": "Unknown classification typo",
                    "classification": "allowed-for-stable",
                    "category": "no-rollback-path",
                    "status": "open",
                    "summary": "Self-test unknown classification.",
                }
            )

        run_case(root, "unknown-limitation-classification", unknown_limitation_classification, "not-ready", expect_blocker="stable-1.0.known-limitations")

        def missing_policy(_inputs: dict[str, Any], _limitations: dict[str, Any], paths: dict[str, Path]) -> None:
            paths["policy"] = paths["stableKnownLimitations"].parent / "missing-policy.json"

        run_case(root, "missing-policy", missing_policy, "not-ready", expect_blocker="stable-1.0.readiness-gate")

        def redaction_unsafe(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["goNoGoSummary"]["unsafeHeader"] = "Authorization: Bearer selftestsecret"

        run_case(root, "redaction-unsafe", redaction_unsafe, "not-ready", expect_blocker="stable-1.0.redaction")

        def invalid_waiver(inputs: dict[str, Any], _limitations: dict[str, Any], paths: dict[str, Path]) -> Path:
            inputs["productionBetaSummary"]["promotionReady"] = False
            waiver_path = paths["stableKnownLimitations"].parent / "waivers.json"
            write_json(
                waiver_path,
                {
                    "schemaVersion": 1,
                    "waivers": [
                        {
                            "id": "stable-waive-production",
                            "evidenceId": "stable-1.0.production-beta-state",
                            "scope": "stable-1.0",
                            "status": "approved",
                            "expiresAt": "2999-01-01T00:00:00Z",
                        }
                    ],
                },
            )
            return waiver_path

        run_case(root, "invalid-waiver", invalid_waiver, "not-ready", expect_blocker="stable-1.0.waiver-validation")

        def incomplete_waiver_metadata(
            _inputs: dict[str, Any],
            limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> Path:
            limitations["limitations"].append(
                {
                    "id": "stable-1.0.waiver-required-doc-followup",
                    "title": "Waiver-required docs follow-up",
                    "classification": "requires-waiver-before-stable",
                    "category": "ui-polish-accessibility-warning",
                    "status": "open",
                    "summary": "Self-test waiver-required limitation.",
                }
            )
            waiver_path = paths["stableKnownLimitations"].parent / "incomplete-waivers.json"
            write_json(
                waiver_path,
                {
                    "schemaVersion": 1,
                    "waivers": [
                        {
                            "id": "stable-waive-doc-followup",
                            "evidenceId": "stable-1.0.waiver-required-doc-followup",
                            "scope": "stable-1.0",
                            "status": "approved",
                            "expiresAt": "2999-01-01T00:00:00Z",
                        }
                    ],
                },
            )
            return waiver_path

        run_case(root, "incomplete-waiver-metadata", incomplete_waiver_metadata, "not-ready", expect_blocker="stable-1.0.waiver-validation")

        def only_trust_graph(_inputs: dict[str, Any], limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            for limitation in limitations["limitations"]:
                if limitation["id"] != "stable-1.0.trust-graph-local-scope":
                    limitation["status"] = "resolved"

        run_case(root, "allowed-trust-graph", only_trust_graph, "ready-with-allowed-limitations", expect_allowed="stable-1.0.trust-graph-local-scope")

        def only_social(_inputs: dict[str, Any], limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            for limitation in limitations["limitations"]:
                if limitation["id"] != "stable-1.0.social-inbox-no-legacy-protocol":
                    limitation["status"] = "resolved"

        run_case(root, "allowed-social-inbox", only_social, "ready-with-allowed-limitations", expect_allowed="stable-1.0.social-inbox-no-legacy-protocol")

    print("stable 1.0 readiness self-test passed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run offline Stable 1.0 readiness fixture tests.")
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--generated-at", default="")
    parser.add_argument("--production-beta-summary", type=Path)
    parser.add_argument("--go-no-go-summary", type=Path)
    parser.add_argument("--release-certification-summary", type=Path)
    parser.add_argument("--ecosystem-matrix", type=Path)
    parser.add_argument("--app-platform-summary", type=Path)
    parser.add_argument("--multi-node-soak-summary", type=Path)
    parser.add_argument("--multi-node-beta-soak-summary", type=Path)
    parser.add_argument("--network-scale-soak-summary", type=Path)
    parser.add_argument("--security-drills-summary", type=Path)
    parser.add_argument("--public-beta-known-issues", type=Path, default=DEFAULT_PUBLIC_BETA_KNOWN_ISSUES)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--stable-known-limitations", type=Path, default=DEFAULT_LIMITATIONS)
    parser.add_argument("--waivers", type=Path)
    return parser


def settings_from_args(args: argparse.Namespace) -> Settings:
    workspace = args.workspace_root.resolve()
    out_dir = args.out_dir.resolve() if args.out_dir.is_absolute() else (workspace / args.out_dir).resolve()
    multi_node = args.multi_node_beta_soak_summary or args.multi_node_soak_summary
    return Settings(
        workspace_root=workspace,
        out_dir=out_dir,
        generated_at=args.generated_at,
        production_beta_summary=resolve_path(workspace, args.production_beta_summary),
        go_no_go_summary=resolve_path(workspace, args.go_no_go_summary),
        release_certification_summary=resolve_path(workspace, args.release_certification_summary),
        ecosystem_matrix=resolve_path(workspace, args.ecosystem_matrix),
        app_platform_summary=resolve_path(workspace, args.app_platform_summary),
        multi_node_soak_summary=resolve_path(workspace, multi_node),
        network_scale_soak_summary=resolve_path(workspace, args.network_scale_soak_summary),
        security_drills_summary=resolve_path(workspace, args.security_drills_summary),
        public_beta_known_issues=resolve_path(workspace, args.public_beta_known_issues),
        policy=resolve_path(workspace, args.policy) or DEFAULT_POLICY,
        stable_known_limitations=resolve_path(workspace, args.stable_known_limitations) or DEFAULT_LIMITATIONS,
        waivers=resolve_path(workspace, args.waivers),
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        run_self_test()
        return 0
    settings = settings_from_args(args)
    summary, exit_code = run(settings)
    print(f"Stable 1.0 readiness {summary['decision']}: {settings.out_dir / SUMMARY_FILE}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
