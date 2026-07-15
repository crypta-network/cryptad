"""Reviewer-facing Stable 1.0 RC reports, checksums, and deterministic archive support."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import re
import tarfile
from pathlib import Path
from typing import Any, Iterable

from cryptad_certification.io import write_json, write_text
from cryptad_certification.redaction import scan_value

from .stable_1_0_rc_core import file_digest, placeholder_findings

_RELEASE_NOTES_TEMPLATE = (
    Path(__file__).resolve().parents[4]
    / "docs"
    / "templates"
    / "stable-1.0-rc-release-notes.md"
)
_RELEASE_NOTES_TEMPLATE_MARKER = "<!-- cryptad-stable-rc-release-notes-template:v1 -->"
_RELEASE_NOTES_BLOCKS = (
    "candidate_identity",
    "upgrade_and_recovery",
    "platform_api",
    "catalog_and_apps",
    "content_profiles",
    "operational_evidence",
    "allowed_limitations",
    "known_issues",
    "accepted_waivers",
    "accepted_exceptions",
    "support_and_security",
    "final_review",
)
_RELEASE_NOTES_TOKEN_RE = re.compile(r"\{\{([a-z_]+)\}\}")


def render_freeze_report(freeze: dict[str, Any], drift: dict[str, Any]) -> str:
    """Render a compact reviewer index for every frozen domain."""

    candidate = freeze.get("candidate", {})
    platform = freeze.get("platformApi", {})
    catalog = freeze.get("stableCatalog", {})
    limitations = freeze.get("limitationsAndPolicy", {})
    lines = [
        "# Stable 1.0 RC Release Freeze",
        "",
        "This is a release-candidate freeze, not a Stable 1.0 general-availability declaration.",
        "",
        f"- Candidate release ID: `{candidate.get('releaseId', 'missing')}`",
        f"- Integer build version: `{candidate.get('buildVersion', 'missing')}`",
        f"- Source commit: `{candidate.get('sourceCommit', 'missing')}`",
        f"- Production distribution digest: `{candidate.get('productionDistributionDigest', 'missing')}`",
        f"- Freeze content digest: `{freeze.get('contentDigest', 'missing')}`",
        f"- Freeze mode: `{drift.get('freezeMode', 'missing')}`",
        f"- Drift status: `{drift.get('status', 'missing')}`",
        f"- Platform API baseline: `{platform.get('baselineName', 'missing')}` at contract `{platform.get('baselineContractVersion', 'missing')}`",
        f"- Platform API baseline digest: `{platform.get('baselineDigest', 'missing')}`",
        f"- Stable catalog: `{catalog.get('catalogId', 'missing')}` edition `{catalog.get('edition', 'missing')}`",
        f"- Stable catalog artifact timestamp: `{catalog.get('artifactTimestamp', 'missing')}`",
        f"- Stable catalog digest: `{catalog.get('catalogDigest', 'missing')}`",
        f"- First-party apps: `{len(freeze.get('firstPartyApps', []))}`",
        f"- Content-format profiles: `{len(freeze.get('contentFormatProfiles', []))}`",
        f"- Allowed Stable limitations: `{limitations.get('allowedLimitationCount', 'missing')}`",
        f"- Accepted freeze exceptions: `{len(freeze.get('acceptedFreezeExceptions', []))}`",
        "",
    ]
    return "\n".join(lines)


def render_go_no_go(summary: dict[str, Any]) -> str:
    """Render the final Stable RC decision and exact blocker guidance."""

    lines = [
        "# Stable 1.0 RC Go/No-Go",
        "",
        f"- Decision: `{summary.get('decision', 'no-go')}`",
        f"- Status: `{summary.get('status', 'fail')}`",
        f"- Promotion ready: `{str(summary.get('promotionReady') is True).lower()}`",
        f"- Non-release: `{str(summary.get('nonRelease') is True).lower()}`",
        f"- Stable ready: `{str(summary.get('stableReady') is True).lower()}`",
        f"- Freeze status: `{summary.get('freeze', {}).get('status', 'fail')}`",
        f"- Freeze drift: `{summary.get('freeze', {}).get('driftStatus', 'invalid-freeze')}`",
        f"- Redaction: `{summary.get('redactionStatus', 'fail')}`",
        "",
        "## Blockers",
        "",
    ]
    blockers = summary.get("blockers") if isinstance(summary.get("blockers"), list) else []
    if not blockers:
        lines.append("None.")
    for blocker in blockers:
        if not isinstance(blocker, dict):
            continue
        lines.extend(
            [
                f"- `{blocker.get('id', 'unknown')}`: {blocker.get('summary', '')}",
                f"  Remediation: {blocker.get('remediation', 'Regenerate the protected evidence.')}",
            ]
        )
    lines.extend(["", "## Allowed Stable limitations", ""])
    limitations = summary.get("allowedLimitations")
    if not isinstance(limitations, list) or not limitations:
        lines.append("None.")
    else:
        for limitation in limitations:
            if isinstance(limitation, dict):
                lines.append(
                    f"- `{limitation.get('id', 'unknown')}`: {limitation.get('summary', limitation.get('title', ''))}"
                )
    lines.append("")
    return "\n".join(lines)


def render_release_notes(
    freeze: dict[str, Any],
    previous_candidate: dict[str, Any],
    accepted_waivers: list[dict[str, Any]],
    accepted_exceptions: list[dict[str, Any]],
    *,
    public_known_issues: dict[str, Any] | None = None,
    stable_readiness: dict[str, Any] | None = None,
    operational_inputs: dict[str, dict[str, Any]] | None = None,
    drift: dict[str, Any] | None = None,
) -> str:
    """Populate the checked-in v1 release-note template with frozen, public-safe facts."""

    template = _load_release_notes_template()
    candidate = _object(freeze, "candidate")
    platform = _object(freeze, "platformApi")
    catalog = _object(freeze, "stableCatalog")
    apps = _objects(freeze, "firstPartyApps")
    profiles = _objects(freeze, "contentFormatProfiles")
    limitations = _objects(_object(freeze, "limitationsAndPolicy"), "allowedLimitations")
    frozen_exceptions = _objects(freeze, "acceptedFreezeExceptions")
    if accepted_exceptions != frozen_exceptions:
        raise ValueError("release-note exception history does not match the freeze")
    known_issues = (
        _objects(public_known_issues, "knownIssues")
        if public_known_issues is not None
        else []
    )
    operations = operational_inputs or {}
    stable = stable_readiness or {}
    freeze_drift = drift or {"status": "no-drift", "regenerated": False}
    previous_release = previous_candidate.get("releaseId") or _nested(
        previous_candidate, "subject", "releaseId"
    )
    if not previous_release:
        raise ValueError("previous-candidate release identity is missing")

    blocks = {
        "candidate_identity": _release_candidate_block(freeze, candidate),
        "upgrade_and_recovery": _release_upgrade_block(previous_candidate, previous_release, catalog, apps),
        "platform_api": _release_platform_block(platform),
        "catalog_and_apps": _release_catalog_apps_block(catalog, apps),
        "content_profiles": _release_profiles_block(profiles),
        "operational_evidence": _release_operations_block(operations),
        "allowed_limitations": _release_limitations_block(limitations),
        "known_issues": _release_known_issues_block(known_issues),
        "accepted_waivers": _release_waivers_block(accepted_waivers),
        "accepted_exceptions": _release_exceptions_block(frozen_exceptions),
        "support_and_security": _release_support_block(apps),
        "final_review": _release_final_block(stable, freeze_drift),
    }
    rendered = template
    for block_name in _RELEASE_NOTES_BLOCKS:
        rendered = rendered.replace("{{" + block_name + "}}", blocks[block_name])
    if _RELEASE_NOTES_TOKEN_RE.search(rendered):
        raise ValueError("release-note template contains an unresolved block token")
    normalized = "\n".join(line.rstrip() for line in rendered.splitlines()).rstrip() + "\n"
    if scan_value(normalized) or placeholder_findings(normalized):
        raise ValueError("rendered release notes failed redaction validation")
    return normalized


def _load_release_notes_template() -> str:
    if _RELEASE_NOTES_TEMPLATE.is_symlink() or not _RELEASE_NOTES_TEMPLATE.is_file():
        raise ValueError("Stable RC release-note template is missing or unsafe")
    template = _RELEASE_NOTES_TEMPLATE.read_text(encoding="utf-8")
    if not template.startswith(_RELEASE_NOTES_TEMPLATE_MARKER + "\n"):
        raise ValueError("Stable RC release-note template has the wrong version")
    tokens = tuple(_RELEASE_NOTES_TOKEN_RE.findall(template))
    if tokens != _RELEASE_NOTES_BLOCKS:
        raise ValueError("Stable RC release-note template blocks are incomplete or out of order")
    if scan_value(template) or placeholder_findings(template):
        raise ValueError("Stable RC release-note template failed redaction validation")
    return template


def _object(value: dict[str, Any], key: str) -> dict[str, Any]:
    child = value.get(key)
    if not isinstance(child, dict):
        raise ValueError(f"release-note context {key} is missing or malformed")
    return child


def _objects(value: dict[str, Any], key: str) -> list[dict[str, Any]]:
    children = value.get(key)
    if not isinstance(children, list) or any(not isinstance(child, dict) for child in children):
        raise ValueError(f"release-note context {key} is missing or malformed")
    return children


def _nested(value: dict[str, Any], parent: str, child: str) -> Any:
    nested = value.get(parent)
    return nested.get(child) if isinstance(nested, dict) else None


def _markdown(value: Any) -> str:
    if value is None or isinstance(value, (dict, list)):
        raise ValueError("release-note scalar is missing or malformed")
    text = str(value).strip()
    if not text or any(ord(character) < 32 for character in text):
        raise ValueError("release-note scalar is empty or contains control characters")
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("`", "\\`")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _code(value: Any) -> str:
    return f"`{_markdown(value)}`"


def _display(value: Any, fallback: str) -> str:
    return _markdown(value if value not in (None, "") else fallback)


def _joined(values: Any, fallback: str = "none") -> str:
    if not isinstance(values, list):
        return _markdown(fallback)
    return ", ".join(_markdown(value) for value in values) if values else _markdown(fallback)


def _release_candidate_block(freeze: dict[str, Any], candidate: dict[str, Any]) -> str:
    build = candidate.get("buildVersion")
    return "\n".join(
        [
            "- Product milestone: Stable 1.0 RC",
            "- Release status: release candidate; not general availability",
            f"- Candidate release ID: {_code(candidate.get('releaseId'))}",
            f"- Integer Cryptad build: {_code(build)}",
            f"- Intended tag after separate release approval: {_code('v' + str(build))}",
            f"- Source commit and ref: {_code(candidate.get('sourceCommit'))}; {_code(candidate.get('sourceRef'))}",
            f"- Source provenance digest: {_code(candidate.get('sourceProvenanceDigest'))}",
            f"- Production distribution digest: {_code(candidate.get('productionDistributionDigest'))}",
            f"- Stable RC freeze digest: {_code(freeze.get('contentDigest'))}",
        ]
    )


def _release_upgrade_block(
    previous: dict[str, Any],
    previous_release: Any,
    catalog: dict[str, Any],
    apps: list[dict[str, Any]],
) -> str:
    rollback = _object(catalog, "verifiedRollback")
    app_data = previous.get("appData") if isinstance(previous.get("appData"), dict) else {}
    recovery = "; ".join(
        f"{_markdown(app.get('appId'))}: schema {_display(app.get('appDataSchemaVersion'), 'not-applicable')}, "
        f"migration {_markdown(app.get('migrationReadiness'))}, backup and restore {_markdown(app.get('backupRestore'))}"
        for app in apps
    )
    return "\n".join(
        [
            f"- Supported upgrade source: {_code(previous_release)} build {_code(_display(previous.get('version'), 'contract-not-supplied'))}",
            f"- Previous-candidate result: status {_code(_display(previous.get('status'), 'validated-pass'))}; promotion ready {_code(_display(previous.get('promotionReady'), 'validated'))}",
            f"- Previous-candidate restore drill: {_code(_display(app_data.get('restoreDrillStatus'), 'validated-pass'))}",
            f"- Catalog rollback: revision {_code(rollback.get('revision'))}, status {_code(rollback.get('status'))}, digest {_code(rollback.get('digest'))}",
            "- App-data recovery: " + recovery,
            "- Rollback does not itself restore app data; follow the frozen backup and restore contract before rollback.",
        ]
    )


def _release_platform_block(platform: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"- Stable baseline: {_code(platform.get('baselineName'))}; contract {_code(platform.get('baselineContractVersion'))}",
            f"- Authoritative baseline digest: {_code(platform.get('baselineDigest'))}",
            f"- Generated contract: version {_code(platform.get('currentContractVersion'))}; digest {_code(platform.get('currentContractDigest'))}",
            f"- Compatibility-window policy digest: {_code(platform.get('compatibilityWindowPolicyDigest'))}",
            f"- Stable surface: {_code(platform.get('stableCapabilityCount'))} capabilities; {_code(platform.get('stableEndpointCount'))} endpoints",
            f"- Experimental surface (not part of the stable baseline): {_code(platform.get('experimentalCapabilityCount'))} capabilities; {_code(platform.get('experimentalEndpointCount'))} endpoints",
            f"- Stable-breaking-change verification: {_code(platform.get('stableBreakingChangeVerification'))}; report {_code(platform.get('verificationReportDigest'))}",
        ]
    )


def _health(value: Any) -> str:
    if not isinstance(value, dict):
        raise ValueError("release-note catalog health is malformed")
    return (
        f"status {_code(value.get('status'))}, signature verified {_code(value.get('signatureVerified'))}, "
        f"revision {_code(value.get('revision'))}, digest {_code(value.get('digest'))}"
    )


def _release_catalog_apps_block(catalog: dict[str, Any], apps: list[dict[str, Any]]) -> str:
    mirrors = catalog.get("mirrorHealth")
    if not isinstance(mirrors, list) or not mirrors:
        raise ValueError("release-note mirror health is missing or malformed")
    lines = [
        f"- Catalog: {_code(catalog.get('catalogId'))}, channel {_code(catalog.get('channel'))}, version {_code(catalog.get('catalogVersion'))}, edition {_code(catalog.get('edition'))}, revision {_code(catalog.get('revision'))}",
        f"- Signed catalog digests: catalog {_code(catalog.get('catalogDigest'))}; signature {_code(catalog.get('signatureDigest'))}; alias {_code(catalog.get('signatureAliasDigest'))}",
        f"- Catalog signing key ID: {_code(catalog.get('catalogSigningKeyId'))}",
        f"- Frozen catalog and review artifact timestamp: {_code(catalog.get('artifactTimestamp'))}",
        f"- Catalog key rotation: {_code(_object(catalog, 'keyRotationStatus').get('status'))}; compromised {_code(_object(catalog, 'keyRotationStatus').get('compromised'))}",
        "- Primary health: " + _health(catalog.get("primaryHealth")),
        "- Mirror health: " + "; ".join(_health(mirror) + ", transport fallback only `true`" for mirror in mirrors),
        f"- Advisory and denylist counts: {_code(catalog.get('securityAdvisoryCount'))} and {_code(catalog.get('denylistCount'))}",
        "",
        "| App identity and support | Signed bundle and review | Frozen metadata digests | API compatibility | App-data and recovery |",
        "| --- | --- | --- | --- | --- |",
    ]
    for app in apps:
        limitation = _display(app.get("allowedStableLimitationId"), "none")
        lines.append(
            "| "
            + " | ".join(
                [
                    f"{_code(app.get('appId'))} {_code(app.get('version'))}; channel {_code(app.get('channel'))}; {_code(app.get('supportStatus'))} and {_code(app.get('supportLevel'))}; deprecation {_code(app.get('deprecationStatus'))}; replacement {_code(_display(app.get('replacementAppId'), 'none'))}",
                    f"{_code(app.get('bundleDigest'))} ({_code(app.get('bundleSizeBytes'))} bytes); signing {_code(app.get('appSigningKeyId'))}; receipt {_code(app.get('reviewReceiptDigest'))}; reviewer {_code(app.get('reviewerKeyId'))}",
                    f"manifest {_code(app.get('manifestDigest'))}; permissions {_code(app.get('declaredPermissionSetDigest'))}; beta readiness {_code(app.get('betaReadinessEvidenceDigest'))}; support {_code(app.get('supportMetadataDigest'))}",
                    f"target {_code(app.get('targetApiStability'))}; {_code(app.get('apiCompatibilityResult'))}; evidence {_code(app.get('apiCompatibilityEvidenceDigest'))}",
                    f"schema {_code(_display(app.get('appDataSchemaVersion'), 'not-applicable'))}; migration {_code(app.get('migrationReadiness'))}; backup and restore {_code(app.get('backupRestore'))}; diagnostics {_code(app.get('redactedDiagnosticsReadiness'))}; limitation {_code(limitation)}",
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def _release_profiles_block(profiles: list[dict[str, Any]]) -> str:
    lines = [
        "| Profile ID | Version/status | Rules digests | Maximum size | Signature payload | Compatibility evidence |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for profile in profiles:
        sizes = _object(profile, "maximumSizePolicy")
        signing = _object(profile, "signaturePayloadRules")
        lines.append(
            "| "
            + " | ".join(
                [
                    _code(profile.get("profileId")),
                    f"{_code(profile.get('version'))} and {_code(profile.get('status'))}",
                    f"descriptor {_code(profile.get('descriptorDigest'))}; canonicalization {_code(profile.get('canonicalizationRulesDigest'))}",
                    f"document {_code(sizes.get('documentBytes'))}; signed payload {_code(_display(sizes.get('signedPayloadBytes'), 'not-applicable'))}",
                    f"signed {_code(signing.get('signed'))}; domain {_code(_display(signing.get('signingDomain'), 'not-applicable'))}",
                    _code(profile.get("parserValidatorCompatibilityEvidenceDigest")),
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def _operation(value: dict[str, Any] | None) -> str:
    row = value or {}
    status = row.get("status") or row.get("decision") or row.get("result") or "validated-pass"
    timestamp = row.get("generatedAt") or row.get("timestamp") or "candidate-bound immutable evidence"
    return f"status {_code(status)}; freshness {_code(timestamp)}"


def _release_operations_block(operations: dict[str, dict[str, Any]]) -> str:
    app_platform = operations.get("appPlatform", {})
    evidence = app_platform.get("evidence") if isinstance(app_platform, dict) else []
    evidence_rows = {
        row.get("id"): row
        for row in evidence
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    } if isinstance(evidence, list) else {}
    return "\n".join(
        [
            f"- Security drill: {_operation(operations.get('securityDrills'))}",
            f"- Previous candidate: {_operation(operations.get('previousCandidate'))}",
            f"- Live network: {_operation(operations.get('liveNetwork'))}",
            f"- Multi-node: {_operation(operations.get('multiNodeSoak'))}",
            f"- Network scale: {_operation(operations.get('networkScaleSoak'))}",
            f"- Sandbox provider: {_operation(evidence_rows.get('apphost.sandbox-provider'))}",
            f"- Third-party intake: {_operation(operations.get('thirdPartyIntake'))}",
            f"- Support and feedback readiness: {_operation(evidence_rows.get('public-beta.support-feedback-loop'))}",
        ]
    )


def _release_limitations_block(limitations: list[dict[str, Any]]) -> str:
    if not limitations:
        return "None."
    lines = [
        "| Limitation ID | Public-safe summary | Scope and boundary | Owner | Evidence |",
        "| --- | --- | --- | --- | --- |",
    ]
    for limitation in sorted(limitations, key=lambda row: str(row.get("id", ""))):
        lines.append(
            f"| {_code(limitation.get('id'))} | {_markdown(limitation.get('title'))}: {_markdown(limitation.get('summary'))} | {_markdown(limitation.get('category'))}; {_markdown(limitation.get('classification'))}; {_markdown(limitation.get('boundedBy'))} | {_code(limitation.get('owner'))} | {_joined(limitation.get('evidenceIds'))} |"
        )
    return "\n".join(lines)


def _release_known_issues_block(issues: list[dict[str, Any]]) -> str:
    if not issues:
        return "None."
    lines = [
        "| Issue ID | Status | Area/severity | Affected scope | Safe workaround and fixed-in state |",
        "| --- | --- | --- | --- | --- |",
    ]
    for issue in sorted(issues, key=lambda row: str(row.get("knownIssueId", ""))):
        affected = "; ".join(
            [
                "channels " + _joined(issue.get("affectedChannels")),
                "apps " + _joined(issue.get("affectedAppIds")),
                "versions " + _joined(issue.get("affectedVersions")),
            ]
        )
        lines.append(
            f"| {_code(issue.get('knownIssueId'))} | {_code(issue.get('status'))} | {_markdown(issue.get('area'))}/{_markdown(issue.get('severity'))} | {affected} | {_markdown(issue.get('workaroundSummary'))}; fixed in {_code(issue.get('fixedInReleaseId'))} |"
        )
    return "\n".join(lines)


def _release_waivers_block(waivers: list[dict[str, Any]]) -> str:
    if not waivers:
        return "None."
    lines = [
        "| Waiver ID | Scope/evidence | Reason | Owner/approver | Expiry | Applied blockers |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for waiver in sorted(waivers, key=lambda row: str(row.get("id", ""))):
        lines.append(
            f"| {_code(waiver.get('id'))} | {_markdown(waiver.get('scope'))}; {_code(waiver.get('evidenceId'))} | {_markdown(waiver.get('rationale'))} | {_markdown(waiver.get('owner'))}; {_markdown(waiver.get('approvedBy'))} | {_code(waiver.get('expiresAt'))} | {_joined(waiver.get('usedBy'))} |"
        )
    return "\n".join(lines)


def _release_exceptions_block(exceptions: list[dict[str, Any]]) -> str:
    if not exceptions:
        return "None."
    lines = [
        "| Exception ID | Frozen item | Blocker/security reference | Digest transition | Authorization | Rerun/result |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for record in sorted(exceptions, key=lambda row: str(row.get("exceptionId", ""))):
        lines.append(
            f"| {_code(record.get('exceptionId'))} | {_markdown(record.get('affectedSection'))}.{_markdown(record.get('affectedItem'))} | {_markdown(record.get('issueKind'))}: {_markdown(record.get('issueReference'))}; {_markdown(record.get('reason'))} | {_code(record.get('beforeDigest'))} → {_code(record.get('afterDigest'))} | {_markdown(record.get('owner'))}; {_markdown(record.get('approver'))}; {_code(record.get('createdAt'))}–{_code(record.get('expiresAt'))} | {_joined(record.get('requiredRerunScope'))}; {_code(record.get('finalVerificationResult'))} |"
        )
    return "\n".join(lines)


def _release_support_block(apps: list[dict[str, Any]]) -> str:
    links = sorted({_markdown(app.get("supportUri")) for app in apps})
    if not links:
        raise ValueError("release-note support links are missing")
    return "\n".join(
        [
            "- Validated operator support links: " + ", ".join(links),
            "- Security reporting: https://github.com/crypta-network/cryptad/security/policy",
            "- Keep private reports, raw app data, content, insert material, identity data, and unredacted diagnostics outside this public draft.",
        ]
    )


def _release_final_block(stable: dict[str, Any], drift: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"- Stable readiness decision: {_code(_display(stable.get('decision'), 'validated-ready'))}; stable ready {_code(_display(stable.get('stableReady'), 'validated'))}",
            f"- Freeze verification: {_code(drift.get('status'))}; regenerated after approved exception {_code(drift.get('regenerated') is True)}",
            "- Redaction status: the final `redaction-report.json` must be `pass`.",
            "- Stable RC decision: the final promotion summary is authoritative and must be `go` or `go-with-waivers` with `promotionReady=true` and `nonRelease=false`.",
            "- This draft does not claim that a tag, GitHub Release, publication, or Stable 1.0 GA operation occurred.",
        ]
    )


def build_redaction_report(values: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    """Scan every generated structured value and return path-free findings."""

    findings: list[dict[str, str]] = []
    for label, value in values:
        for finding in scan_value(value):
            findings.append(
                {
                    "artifact": label,
                    "category": str(finding.get("category", "redaction")),
                    "summary": str(finding.get("summary", "unsafe generated value")),
                }
            )
    return {
        "schemaVersion": 1,
        "status": "pass" if not findings else "fail",
        "findingCount": len(findings),
        "findings": findings,
        "guarantees": {
            "absoluteLocalPathsExcluded": not findings,
            "privateInsertMaterialExcluded": not findings,
            "rawAppDataExcluded": not findings,
            "rawContentExcluded": not findings,
            "rawSignaturesExcluded": not findings,
            "secretValuesExcluded": not findings,
        },
    }


def write_checksums(path: Path, members: Iterable[Path]) -> dict[str, str]:
    """Write GNU-compatible relative checksums without absolute paths."""

    root = path.parent.resolve()
    rows: list[tuple[str, str]] = []
    seen: set[str] = set()
    for member in members:
        resolved = member.resolve()
        relative = resolved.relative_to(root).as_posix()
        if relative in seen or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError(f"duplicate or unsafe checksum member: {relative}")
        if member.is_symlink() or not member.is_file():
            raise ValueError(f"checksum member is missing or unsafe: {relative}")
        seen.add(relative)
        rows.append((relative, file_digest(resolved).removeprefix("sha256:")))
    rows.sort()
    write_text(path, "\n".join(f"{digest}  {relative}" for relative, digest in rows))
    return {relative: f"sha256:{digest}" for relative, digest in rows}


def write_named_checksums(path: Path, members: Iterable[tuple[str, Path]]) -> dict[str, str]:
    """Write checksums for caller-defined safe archive-root-relative member names."""

    rows: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, member in members:
        _validate_archive_name(name)
        if name in seen:
            raise ValueError(f"duplicate checksum member name: {name}")
        resolved = _regular_source(member, name)
        seen.add(name)
        rows.append((name, file_digest(resolved).removeprefix("sha256:")))
    rows.sort()
    write_text(path, "\n".join(f"{digest}  {name}" for name, digest in rows))
    return {name: f"sha256:{digest}" for name, digest in rows}


def verify_checksums(
    path: Path,
    required_targets: dict[str, Path] | None = None,
) -> list[str]:
    """Verify strict checksum rows and optionally bind required names to copied artifacts."""

    errors: list[str] = []
    seen: set[str] = set()
    parsed: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        digest, separator, relative = line.partition("  ")
        candidate = Path(relative)
        if (
            not separator
            or relative in seen
            or candidate.is_absolute()
            or ".." in candidate.parts
            or re.fullmatch(r"[0-9a-f]{64}", digest.lower()) is None
        ):
            errors.append(f"checksums line {line_number} is malformed")
            continue
        seen.add(relative)
        parsed[relative] = digest.lower()
        target = path.parent / candidate
        if target.is_symlink() or not target.is_file():
            errors.append(f"checksums target is missing or unsafe: {relative}")
            continue
        if file_digest(target).removeprefix("sha256:") != digest.lower():
            errors.append(f"checksum mismatch: {relative}")
    for name, target in (required_targets or {}).items():
        expected_digest = parsed.get(name)
        if expected_digest is None:
            errors.append(f"checksums omits required target: {name}")
            continue
        if target.is_symlink() or not target.is_file():
            errors.append(f"required checksum target is missing or unsafe: {name}")
            continue
        if file_digest(target).removeprefix("sha256:") != expected_digest:
            errors.append(f"checksum mismatch for copied target: {name}")
    return errors


def create_deterministic_archive(
    archive_path: Path,
    members: Iterable[tuple[str, Path]],
) -> None:
    """Create a normalized tar.gz with stable order, ownership, modes, and timestamps."""

    materialized: list[tuple[str, Path]] = []
    for name, original_path in members:
        _validate_archive_name(name)
        materialized.append((name, _regular_source(original_path, name)))
    materialized.sort()
    temporary = archive_path.with_name(f".{archive_path.name}.tmp")
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with temporary.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for name, path in materialized:
                        data = path.read_bytes()
                        info = tarfile.TarInfo(name=f"stable-1.0-rc/{name}")
                        info.size = len(data)
                        info.mode = 0o644
                        info.mtime = 0
                        info.uid = 0
                        info.gid = 0
                        info.uname = "root"
                        info.gname = "root"
                        archive.addfile(info, io.BytesIO(data))
        os.replace(temporary, archive_path)
    finally:
        if temporary.exists():
            temporary.unlink()


def verify_deterministic_archive(archive_path: Path) -> list[str]:
    """Reject unsafe members and non-normalized metadata in the Stable RC outer archive."""

    errors: list[str] = []
    seen: set[str] = set()
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            names = [member.name for member in archive.getmembers()]
            if names != sorted(names):
                errors.append("archive member order is not deterministic")
            for member in archive.getmembers():
                try:
                    _validate_archive_name(member.name)
                except ValueError as exc:
                    errors.append(str(exc))
                if member.name in seen:
                    errors.append(f"duplicate archive member: {member.name}")
                seen.add(member.name)
                if not member.isfile():
                    errors.append(f"non-regular archive member: {member.name}")
                if (
                    member.mtime != 0
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != "root"
                    or member.gname != "root"
                    or member.mode != 0o644
                ):
                    errors.append(f"non-normalized archive metadata: {member.name}")
            errors.extend(_verify_archive_payload_checksums(archive))
    except (OSError, tarfile.TarError):
        errors.append("Stable RC archive is invalid")
    return errors


def _verify_archive_payload_checksums(archive: tarfile.TarFile) -> list[str]:
    """Bind every non-checksum archive member to the embedded checksum manifest."""

    root = "stable-1.0-rc/"
    checksum_name = root + "payload-checksums.txt"
    members = {member.name: member for member in archive.getmembers() if member.isfile()}
    checksum_member = members.get(checksum_name)
    if checksum_member is None:
        return ["archive payload-checksums.txt is missing"]
    extracted = archive.extractfile(checksum_member)
    if extracted is None:
        return ["archive payload-checksums.txt cannot be read"]
    try:
        lines = extracted.read().decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return ["archive payload-checksums.txt is not UTF-8"]
    errors: list[str] = []
    expected: set[str] = set()
    for number, line in enumerate(lines, start=1):
        digest, separator, relative = line.partition("  ")
        target_name = root + relative
        try:
            _validate_archive_name(relative)
        except ValueError:
            separator = ""
        if (
            not separator
            or relative in expected
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or target_name == checksum_name
        ):
            errors.append(f"archive payload checksum line {number} is malformed")
            continue
        expected.add(relative)
        member = members.get(target_name)
        if member is None:
            errors.append(f"archive payload checksum target is missing: {relative}")
            continue
        stream = archive.extractfile(member)
        if stream is None or hashlib.sha256(stream.read()).hexdigest() != digest:
            errors.append(f"archive payload checksum mismatch: {relative}")
    actual = {name.removeprefix(root) for name in members if name != checksum_name}
    for missing in sorted(actual - expected):
        errors.append(f"archive member is not checksummed: {missing}")
    for extra in sorted(expected - actual):
        errors.append(f"archive checksum names a missing member: {extra}")
    return errors


def _regular_source(path: Path, label: str) -> Path:
    """Resolve a present regular file only after rejecting symlinks in its source path."""

    absolute = path.absolute()
    for component in (absolute, *absolute.parents):
        if component.is_symlink():
            raise ValueError(f"archive source is missing or unsafe: {label}")
    if not absolute.is_file():
        raise ValueError(f"archive source is missing or unsafe: {label}")
    return absolute.resolve(strict=True)


def _validate_archive_name(name: str) -> None:
    path = Path(name)
    forbidden = {".DS_Store", "__MACOSX"}
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"unsafe archive member path: {name}")
    for part in path.parts:
        if part.startswith("._") or part in forbidden:
            raise ValueError(f"forbidden archive member: {name}")
        lower = part.lower()
        if any(
            marker in lower
            for marker in (
                "private-key",
                "private_key",
                "insert-uri",
                "insert_uri",
                "token",
                "cookie",
                "password",
                "credential",
                "authorization",
                "certificate",
            )
        ) or Path(lower).suffix in {
            ".key",
            ".pem",
            ".p8",
            ".p12",
            ".pfx",
            ".jks",
            ".keystore",
            ".pkcs8",
        }:
            raise ValueError(f"secret-like archive member name: {name}")
