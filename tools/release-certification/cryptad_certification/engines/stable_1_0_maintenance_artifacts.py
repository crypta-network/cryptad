"""Deterministic, public-safe Stable 1.0 maintenance reports and release notes."""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Any, Iterable

from cryptad_certification.redaction import scan_value

from .stable_1_0_maintenance_core import CHECKSUMS_FILE, PROVENANCE_FILE
from .stable_1_0_rc_core import placeholder_findings

_TEMPLATE = (
    Path(__file__).resolve().parents[4]
    / "docs"
    / "templates"
    / "stable-1.0-maintenance-release-notes.md"
)
_MARKER = "<!-- cryptad-stable-maintenance-release-notes-template:v1 -->"
_TOKEN_RE = re.compile(r"\{\{([A-Za-z_]+)\}\}")
_TOKENS = (
    "identity",
    "classification",
    "fixes",
    "BACKPORT_RELEASE_TRAIN",
    "security",
    "platform_api",
    "catalog_apps",
    "migration_recovery",
    "packages",
    "core_updater",
    "limitations",
    "support",
    "verification",
    "publication_status",
)
_PUNCTUATION = frozenset("!#*+-<>()[]\\^_`{|}~")


def _scalar(value: Any) -> str:
    if value is None or isinstance(value, (dict, list, bool)):
        raise ValueError("maintenance release-note scalar is malformed")
    text = str(value).strip()
    if not text or any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in text
    ):
        raise ValueError("maintenance release-note scalar is empty or unsafe")
    if placeholder_findings(text) or scan_value(text):
        raise ValueError("maintenance release-note scalar is a placeholder or private value")
    return text


def _escape(value: Any) -> str:
    return "".join(
        "\\" + character if character in _PUNCTUATION else character
        for character in _scalar(value)
    )


def _code(value: Any) -> str:
    text = _scalar(value)
    longest = max((len(match.group()) for match in re.finditer(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    padding = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{padding}{text}{padding}{fence}"


def _load_template() -> str:
    if _TEMPLATE.is_symlink() or not _TEMPLATE.is_file():
        raise ValueError("maintenance release-note template is missing or unsafe")
    value = _TEMPLATE.read_text(encoding="utf-8")
    if not value.startswith(_MARKER + "\n") or tuple(_TOKEN_RE.findall(value)) != _TOKENS:
        raise ValueError("maintenance release-note template contract is invalid")
    if scan_value(value) or placeholder_findings(value):
        raise ValueError("maintenance release-note template is not public-safe")
    return value


def _bullet_rows(values: Any, *, empty: str) -> str:
    if not isinstance(values, list) or not values:
        return empty
    return "\n".join(f"- {_escape(value)}" for value in values)


def render_release_notes(
    release_id: str,
    build_version: str,
    release_class: str,
    predecessor_build: str,
    candidate: dict[str, Any],
    publication_state: str,
    train_public_fixes: list[dict[str, Any]],
    train_deferred_fix_ids: list[str],
    train_digest: str,
) -> str:
    """Render one strict maintenance/hotfix note from candidate-bound public facts."""

    scope = candidate.get("changeScope") if isinstance(candidate.get("changeScope"), dict) else {}
    api = candidate.get("platformApi") if isinstance(candidate.get("platformApi"), dict) else {}
    catalog = candidate.get("stableCatalog") if isinstance(candidate.get("stableCatalog"), dict) else {}
    limitations = candidate.get("limitations") if isinstance(candidate.get("limitations"), dict) else {}
    packages = candidate.get("packages") if isinstance(candidate.get("packages"), list) else []
    incident = scope.get("incidentId")
    security = (
        f"Critical advisory {_code(incident)} is addressed. Public details remain limited to the "
        "incident-safe advisory; protected exploit and key material are never release assets."
        if release_class == "security-hotfix"
        else "No expedited security-hotfix policy is used by this routine maintenance release."
    )
    package_rows = [
        f"{row.get('os')} {row.get('arch')} {row.get('packageType')} ({row.get('packageKey')})"
        for row in packages
        if isinstance(row, dict)
    ]
    train_rows: list[str] = []
    for row in train_public_fixes:
        if not isinstance(row, dict):
            continue
        public_summary = _scalar(row.get("publicSummary"))
        train_row = (
            f"{row.get('fixId')} — {row.get('classification')} — "
            f"{row.get('affectedComponentSummary')} — summary: {public_summary} — "
            f"provenance: {row.get('provenanceMode')} — lineage: "
            f"{row.get('lineageDigest')}"
        )
        public_security_summary = row.get("publicSecuritySummary")
        if public_security_summary is not None:
            train_row += (
                f" — security summary: {_scalar(public_security_summary)}"
            )
        if (
            row.get("disclosureState") == "disclosed"
            and row.get("advisoryOpaqueId")
        ):
            train_row += f" — advisory {row.get('advisoryOpaqueId')}"
        train_rows.append(train_row)
    train_rows.append(f"Exact release-train validation digest: {train_digest}")
    train_rows.extend(
        f"Deferred known issue carried forward: {fix_id}"
        for fix_id in train_deferred_fix_ids
    )
    blocks = {
        "identity": (
            f"Cryptad Stable 1.0 build {_code(build_version)} uses annotated tag "
            f"{_code('v' + build_version)} and follows published predecessor build "
            f"{_code(predecessor_build)}. Release record: {_code(release_id)}."
        ),
        "classification": (
            "This is a routine Stable 1.0 maintenance release."
            if release_class == "maintenance"
            else "This is a narrowly authorized Stable 1.0 critical security hotfix."
        ),
        "fixes": _bullet_rows(
            scope.get("publicUserVisibleFixes"),
            empty="Candidate scope contains compatibility-preserving maintenance fixes only.",
        ),
        "BACKPORT_RELEASE_TRAIN": _bullet_rows(
            train_rows,
            empty="No authenticated release-train fix rows were supplied.",
        ),
        "security": security,
        "platform_api": (
            f"Platform API baseline {_code(api.get('baselineName'))} is preserved. Current contract "
            f"version is {_code(api.get('currentContractVersion'))}; stable-removal and deprecation-clock "
            "checks passed against both GA and the predecessor."
        ),
        "catalog_apps": (
            f"Stable catalog {_code(catalog.get('catalogId'))} advances to edition "
            f"{_code(catalog.get('edition'))}, revision {_code(catalog.get('revision'))}. "
            "The seven first-party app ids, stable channel, review/signing trust, and support "
            "commitments remain enforced."
        ),
        "migration_recovery": (
            "Protected evidence passed predecessor and required direct-GA upgrades, daemon and app "
            "rollback, app-data migration, backup-before-update, restore-after-failure, grant "
            "revalidation, durable-state preservation, and operator recovery."
        ),
        "packages": _bullet_rows(package_rows, empty="No package target was declared."),
        "core_updater": (
            f"CoreUpdater discovers integer build {_code(build_version)} from the package-based "
            "descriptor and selects only an authenticated AppEnv OS/architecture package key."
        ),
        "limitations": (
            f"Added: {_code(limitations.get('addedCount'))}; resolved: "
            f"{_code(limitations.get('resolvedCount'))}; unchanged: "
            f"{_code(limitations.get('unchangedCount'))}. See the candidate-bound limitations delta."
        ),
        "support": (
            "Take a backup before updating and retain the predecessor package until validation "
            "completes. Attach only the redacted operator support bundle; never attach raw content, "
            "raw app data, identity data, keys, insert URIs, cookies, or tokens."
        ),
        "verification": (
            f"Verify every asset with {_code(CHECKSUMS_FILE)} and {_code(PROVENANCE_FILE)}. Any "
            "post-authorization byte change requires a new candidate freeze and authorization."
        ),
        "publication_status": (
            f"Prepared state: {_code(publication_state)}. These notes do not claim public release "
            "completion until the protected operation and independent receipt verification pass."
        ),
    }
    return _TOKEN_RE.sub(lambda match: blocks[match.group(1)], _load_template())


def render_go_no_go(summary: dict[str, Any]) -> str:
    """Render a compact deterministic maintenance decision report."""

    lines = [
        "# Stable 1.0 maintenance go/no-go",
        "",
        f"- Release: {_code(summary.get('releaseId'))}",
        f"- Build/tag: {_code(summary.get('buildVersion'))} / {_code('v' + str(summary.get('buildVersion')))}",
        f"- Class: {_code(summary.get('releaseClass'))}",
        f"- Decision: **{_escape(summary.get('decision'))}**",
        f"- Publication state: {_code(summary.get('publicationState'))}",
        f"- Exact-byte publication ready: {_code(str(summary.get('promotionReady')).lower())}",
        "",
        "## Blockers",
        "",
    ]
    blockers = summary.get("blockers")
    if isinstance(blockers, list) and blockers:
        for row in blockers:
            if isinstance(row, dict):
                lines.append(f"- {_code(row.get('id'))}: {_escape(row.get('summary', row.get('message')))}")
    else:
        lines.append("No blocker is open.")
    lines.extend(["", "## Warnings", ""])
    warnings = summary.get("warnings")
    if isinstance(warnings, list) and warnings:
        for row in warnings:
            if isinstance(row, dict):
                lines.append(f"- {_code(row.get('id'))}: {_escape(row.get('summary', row.get('message')))}")
    else:
        lines.append("No warning is open.")
    lines.extend(
        [
            "",
            "Publication is a separate protected operation. A validation result alone never creates ",
            "a tag, GitHub Release, catalog edition, CoreUpdater insert, or announcement.",
        ]
    )
    return "\n".join(lines)


def build_redaction_report(items: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    """Scan a complete public artifact set and attribute every finding."""

    findings: list[dict[str, Any]] = []
    for artifact, value in items:
        for finding in scan_value(value):
            findings.append({"artifact": artifact, **finding})
        for finding in placeholder_findings(value):
            findings.append(
                {
                    "artifact": artifact,
                    "category": "placeholder",
                    "summary": str(finding),
                }
            )
    return {
        "schemaVersion": 1,
        "status": "pass" if not findings else "fail",
        "findingCount": len(findings),
        "findings": findings,
        "guarantees": {
            "privateKeysExcluded": not findings,
            "privateInsertUrisExcluded": not findings,
            "tokensAndHeadersExcluded": not findings,
            "rawContentAndAppDataExcluded": not findings,
            "identityMaterialExcluded": not findings,
            "absoluteRunnerPathsExcluded": not findings,
        },
    }
