"""Deterministic, redaction-safe reports for Stable 1.0 GA promotion."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote, urlsplit, urlunsplit

from cryptad_certification.redaction import scan_value

from .stable_1_0_ga_core import (
    CHECKSUMS_FILE,
    PROVENANCE_FILE,
    is_public_https_uri,
    public_audit_redaction_findings,
)
from .stable_1_0_rc_core import placeholder_findings

_TEMPLATE = (
    Path(__file__).resolve().parents[4]
    / "docs"
    / "templates"
    / "stable-1.0-ga-release-notes.md"
)
_TEMPLATE_MARKER = "<!-- cryptad-stable-ga-release-notes-template:v1 -->"
_TEMPLATE_BLOCKS = (
    "milestone_identity",
    "exact_rc_provenance",
    "upgrade_recovery_backup",
    "platform_api",
    "catalog_and_apps",
    "content_profiles",
    "allowed_limitations",
    "security_and_support",
    "legacy_boundaries",
    "checksums_and_provenance",
    "publication_status",
    "support_and_security_reporting",
)
_TOKEN_RE = re.compile(r"\{\{([a-z_]+)\}\}")
_MARKDOWN_PUNCTUATION = frozenset("!#*+-<>()[]\\^_`{|}~")


def _scalar_text(value: Any) -> str:
    """Return one required, control-free scalar without changing its contents."""

    if value is None or isinstance(value, (dict, list, bool)):
        raise ValueError("Stable GA release-note scalar is missing or malformed")
    text = str(value).strip()
    if not text or any(ord(character) < 32 for character in text):
        raise ValueError("Stable GA release-note scalar is empty or contains controls")
    return text


def _safe(value: Any) -> str:
    text = _scalar_text(value)
    return (
        text.replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _public_https_link(value: Any) -> str:
    text = _scalar_text(value)
    if not is_public_https_uri(text):
        raise ValueError("Stable GA public support URI is not public HTTPS")
    parsed = urlsplit(text)
    hostname = parsed.hostname or ""
    netloc = f"[{hostname}]" if ":" in hostname else hostname
    if parsed.port is not None:
        netloc += f":{parsed.port}"
    safe_path = quote(parsed.path, safe="/:@&=+$,;~.-_%")
    return urlunsplit((parsed.scheme, netloc, safe_path, "", ""))


def _safe_markdown_text(value: Any) -> str:
    """Return one control-free scalar escaped for untrusted inline Markdown text."""

    return "".join(
        "\\" + character if character in _MARKDOWN_PUNCTUATION else character
        for character in _scalar_text(value)
    )


def _load_template() -> str:
    if _TEMPLATE.is_symlink() or not _TEMPLATE.is_file():
        raise ValueError("Stable GA release-note template is missing or unsafe")
    template = _TEMPLATE.read_text(encoding="utf-8")
    if not template.startswith(_TEMPLATE_MARKER + "\n"):
        raise ValueError("Stable GA release-note template has the wrong version")
    if tuple(_TOKEN_RE.findall(template)) != _TEMPLATE_BLOCKS:
        raise ValueError("Stable GA release-note template blocks are incomplete or out of order")
    if scan_value(template) or placeholder_findings(template):
        raise ValueError("Stable GA release-note template failed redaction validation")
    return template


def _limitations_block(limitations: list[dict[str, Any]]) -> str:
    if not limitations:
        return "No policy-approved Stable limitation remains open."
    rows = []
    for limitation in limitations:
        rows.append(
            f"- **Limitation ID:** {_safe_markdown_text(limitation.get('id'))} — "
            f"**{_safe_markdown_text(limitation.get('title'))}:** "
            f"{_safe_markdown_text(limitation.get('summary'))} Boundary: "
            f"{_safe_markdown_text(limitation.get('boundedBy'))}"
        )
    return "\n".join(rows)


def _catalog_apps_block(catalog: dict[str, Any], apps: list[dict[str, Any]]) -> str:
    lines = [
        f"The signed `{_safe(catalog.get('catalogId'))}` stable catalog remains at edition "
        f"`{_safe(catalog.get('edition'))}` and revision `{_safe(catalog.get('revision'))}`. "
        "GA uses the exact catalog and signature bytes frozen by the selected RC; it does not "
        "rewrite entries, artifact URLs, review receipts, or signing metadata.",
        "",
        "The frozen first-party set is:",
        "",
    ]
    for app in apps:
        lines.append(
            f"- `{_safe(app.get('appId'))}` `{_safe(app.get('version'))}` — "
            f"support `{_safe(app.get('supportLevel'))}`, app-data schema "
            f"`{_safe(app.get('appDataSchemaVersion'))}`; "
            f"[support]({_public_https_link(app.get('supportUri'))})"
        )
    return "\n".join(lines)


def _profiles_block(profiles: list[dict[str, Any]]) -> str:
    lines = [
        "The profile registry and canonicalization rules are byte-identical to the RC freeze. "
        "GA does not promote experimental formats or change parser membership.",
        "",
    ]
    lines.extend(
        f"- `{_safe(row.get('profileId'))}` version `{_safe(row.get('version'))}` — "
        f"`{_safe(row.get('status'))}`"
        for row in profiles
    )
    return "\n".join(lines)


def render_release_notes(
    freeze: dict[str, Any],
    validation: dict[str, Any],
    promotion: dict[str, Any],
) -> str:
    """Populate the checked-in Stable GA template from authenticated frozen facts."""

    template = _load_template()
    candidate = freeze.get("candidate") if isinstance(freeze.get("candidate"), dict) else {}
    platform = freeze.get("platformApi") if isinstance(freeze.get("platformApi"), dict) else {}
    catalog = freeze.get("stableCatalog") if isinstance(freeze.get("stableCatalog"), dict) else {}
    apps = [row for row in freeze.get("firstPartyApps", []) if isinstance(row, dict)]
    profiles = [row for row in freeze.get("contentFormatProfiles", []) if isinstance(row, dict)]
    limitations_policy = freeze.get("limitationsAndPolicy") if isinstance(freeze.get("limitationsAndPolicy"), dict) else {}
    limitations = [row for row in limitations_policy.get("allowedLimitations", []) if isinstance(row, dict)]
    scenarios = validation.get("scenarios") if isinstance(validation.get("scenarios"), dict) else {}
    install = scenarios.get("installationPackaging") if isinstance(scenarios.get("installationPackaging"), dict) else {}
    targets = install.get("targets") if isinstance(install.get("targets"), list) else []
    target_names = ", ".join(
        " ".join(
            _safe_markdown_text(row.get(field))
            for field in ("operatingSystem", "architecture", "packageType")
        )
        for row in targets
        if isinstance(row, dict)
    ) or "the protected release-supported target matrix"
    prior = scenarios.get("upgradeRollbackStatePreservation") if isinstance(scenarios.get("upgradeRollbackStatePreservation"), dict) else {}
    previous_candidate = (
        f"{prior.get('previousReleaseId')} (build {prior.get('previousBuildVersion')})"
        if prior.get("previousReleaseId") and prior.get("previousBuildVersion")
        else "the required previous published candidate"
    )
    blocks = {
        "milestone_identity": (
            f"This material promotes Stable milestone `1.0` for integer Cryptad build "
            f"`{_safe(candidate.get('buildVersion'))}`. The expected annotated tag is "
            f"`v{_safe(candidate.get('buildVersion'))}` and the expected stabilization branch "
            f"is `release/{_safe(candidate.get('buildVersion'))}`."
        ),
        "exact_rc_provenance": (
            f"The selected source commit is `{_safe(candidate.get('sourceCommit'))}`. The "
            f"canonical RC freeze digest is `{_safe(freeze.get('contentDigest'))}` and the exact "
            f"immutable product digest is `{_safe(candidate.get('productionDistributionDigest'))}`. "
            "Post-freeze validation exercised those bytes; GA does not rebuild the daemon, "
            "catalog, or first-party app bundles."
        ),
        "upgrade_recovery_backup": (
            f"Protected validation covered clean install and lifecycle behavior on {target_names}. "
            f"Upgrade and recovery started from `{_safe(previous_candidate)}` "
            "and passed daemon recovery, stable-catalog rollback, first-party app rollback, "
            "app-data migration, backup-before-migration, restore, and deliberately failed-update "
            "support-bundle scenarios. Operators should take a backup before upgrade and retain "
            "the previous published package until post-upgrade checks pass."
        ),
        "platform_api": (
            f"Platform API baseline `{_safe(platform.get('baselineName'))}` remains frozen at "
            f"contract `{_safe(platform.get('baselineContractVersion'))}` with digest "
            f"`{_safe(platform.get('baselineDigest'))}`. The current contract is "
            f"`{_safe(platform.get('currentContractVersion'))}` and stable breaking-change "
            "verification passed. Stable compatibility and deprecation windows remain governed "
            "by the published Platform API support policy."
        ),
        "catalog_and_apps": _catalog_apps_block(catalog, apps),
        "content_profiles": _profiles_block(profiles),
        "allowed_limitations": _limitations_block(limitations),
        "security_and_support": (
            "The exact RC passed current production security-response drills, catalog/app/reviewer "
            "key-state checks, denylist and advisory fail-closed behavior, sandbox-provider checks, "
            "privacy-preserving diagnostics, support-bundle redaction, live-network validation, "
            "Hyphanet interoperability, performance comparison, and the policy-required live soak."
        ),
        "legacy_boundaries": (
            "The legacy in-process plugin runtime and new legacy-admin feature work remain frozen. "
            "Stable 1.0 does not restore old plugin ABIs or Freetalk, Sone, Freemail, or WebOfTrust "
            "compatibility. FProxy browsing, content rendering/filtering, startup and recovery, and "
            "the documented emergency support fallbacks remain available."
        ),
        "checksums_and_provenance": (
            f"Verify release assets with `{CHECKSUMS_FILE}` and the RC-to-GA binding in "
            f"`{PROVENANCE_FILE}`. The product digest must equal the selected RC product digest; "
            "any mismatch requires a new PR-283 refreeze and complete validation."
        ),
        "publication_status": (
            f"Current prepared state: `{_safe(promotion.get('publicationState'))}`. Validation or "
            "authorization alone does not mean the tag, GitHub Release, catalog, update descriptor, "
            "or network publication exists. Actual publication requires the protected Stable GA "
            "job and an independently verified publication receipt."
        ),
        "support_and_security_reporting": (
            "Use the first-party app support links above or the "
            "[public support tracker](https://github.com/crypta-network/cryptad/issues) for "
            "ordinary issues. Report security issues privately by following the "
            "[security reporting instructions]"
            "(https://github.com/crypta-network/cryptad/blob/main/docs/SECURITY.md); "
            "do not attach private keys, insert URIs, raw app data, raw content, or identity material "
            "to public issues."
        ),
    }
    rendered = template
    for name in _TEMPLATE_BLOCKS:
        rendered = rendered.replace("{{" + name + "}}", blocks[name])
    if _TOKEN_RE.search(rendered):
        raise ValueError("Stable GA release-note template contains an unresolved token")
    normalized = "\n".join(line.rstrip() for line in rendered.splitlines()).rstrip() + "\n"
    if scan_value(normalized) or placeholder_findings(normalized):
        raise ValueError("rendered Stable GA release notes failed redaction validation")
    return normalized


def render_go_no_go(summary: dict[str, Any]) -> str:
    """Render a concise pre-publication or post-publication GA decision report."""

    lines = [
        "# Stable 1.0 GA Go/No-Go",
        "",
        f"- Decision: `{summary.get('decision', 'no-go')}`",
        f"- Status: `{summary.get('status', 'fail')}`",
        f"- Promotion ready: `{str(summary.get('promotionReady') is True).lower()}`",
        f"- Non-release: `{str(summary.get('nonRelease') is True).lower()}`",
        f"- Publication state: `{summary.get('publicationState', 'validated')}`",
        f"- Exact RC binding: `{str(summary.get('payloadIdentity', {}).get('bitIdentical') is True).lower()}`",
        f"- Authorization: `{summary.get('publicationReadiness', {}).get('authorizationStatus', 'fail')}`",
        f"- Payload identity: `{str(summary.get('payloadIdentity', {}).get('bitIdentical') is True).lower()}`",
        f"- Redaction: `{summary.get('redaction', {}).get('status', 'fail')}`",
        "",
        "## Blockers",
        "",
    ]
    blockers = summary.get("blockers")
    if not isinstance(blockers, list) or not blockers:
        lines.append("None.")
    else:
        for blocker in blockers:
            if isinstance(blocker, dict):
                lines.extend(
                    [
                        f"- **Blocker ID:** {_safe_markdown_text(blocker.get('id', 'unknown'))} — "
                        f"{_safe_markdown_text(blocker.get('summary', ''))}",
                        "  Remediation: "
                        f"{_safe_markdown_text(blocker.get('remediation', 'Return to the protected release workflow.'))}",
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
                    "- **Limitation ID:** "
                    f"{_safe_markdown_text(limitation.get('id', 'unknown'))} — "
                    f"{_safe_markdown_text(limitation.get('summary', limitation.get('title', '')))}"
                )
    return "\n".join(lines).rstrip() + "\n"


def build_redaction_report(values: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    """Scan every planned public GA value without echoing matched material."""

    findings: list[dict[str, str]] = []
    for artifact, value in values:
        for finding in public_audit_redaction_findings(value):
            findings.append(
                {
                    "artifact": artifact,
                    "category": str(finding.get("category", "redaction")),
                    "summary": str(finding.get("summary", "unsafe generated value")),
                }
            )
        for _path in placeholder_findings(value):
            findings.append(
                {
                    "artifact": artifact,
                    "category": "placeholder",
                    "summary": "production placeholder material is not allowed",
                }
            )
    return {
        "schemaVersion": 1,
        "status": "pass" if not findings else "fail",
        "findingCount": len(findings),
        "findings": findings,
        "guarantees": {
            "absoluteLocalPathsExcluded": not findings,
            "authorizationHeadersExcluded": not findings,
            "privateInsertMaterialExcluded": not findings,
            "privateSigningMaterialExcluded": not findings,
            "rawAppDataExcluded": not findings,
            "rawContentExcluded": not findings,
            "rawSupportBundlesExcluded": not findings,
            "secretValuesExcluded": not findings,
        },
    }
