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
    "docs/feed-reader-reference-app.md",
    "docs/social-inbox-reference-app.md",
    "docs/trust-graph-preview.md",
    "docs/legacy-plugin-migration-guide.md",
    "docs/release-certification.md",
    "docs/SECURITY.md",
)

NEW_DOCS = (
    "docs/app-platform-developer-portal.md",
    "docs/app-platform-beta-tutorials.md",
    "docs/app-platform-beta-known-limitations.md",
    "docs/app-platform-beta-program.md",
)

ISSUE_TEMPLATES = (
    ".github/ISSUE_TEMPLATE/app-platform-beta-feedback.yml",
    ".github/ISSUE_TEMPLATE/app-submission-beta.yml",
    ".github/ISSUE_TEMPLATE/developer-beta-feedback.yml",
    ".github/ISSUE_TEMPLATE/app-review-appeal.yml",
    ".github/ISSUE_TEMPLATE/platform-api-compatibility.yml",
    ".github/ISSUE_TEMPLATE/plugin-migration-feedback.yml",
)

REQUIRED_PORTAL_LINKS = tuple(
    path for path in REQUIRED_DOCS if path != "docs/app-platform-developer-portal.md"
) + (
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
    r"[\"']?(?:CRYPTAD_APP_TOKEN|browserSessionToken|appProcessToken|"
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
    r"\b[\"']?(?:CRYPTAD_APP_TOKEN|browserSessionToken|appProcessToken)[\"']?\s*[:=]\s*"
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
    files.append(workspace_root / "README.md")
    return sorted({path for path in files if path.is_file()})


def broken_markdown_links(workspace_root: Path) -> list[dict[str, str]]:
    broken: list[dict[str, str]] = []
    for markdown_file in markdown_files_to_check(workspace_root):
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


def redaction_files_to_check(workspace_root: Path) -> list[Path]:
    files = [workspace_root / path for path in (*REQUIRED_DOCS, *REQUIRED_PORTAL_LINKS)]
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


def redaction_findings(workspace_root: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for path in redaction_files_to_check(workspace_root):
        relative = display_path(path.relative_to(workspace_root))
        text = read_text(path)
        for issue, pattern in REDACTION_CHECKS:
            if pattern.search(text):
                findings.append({"path": relative, "issue": issue})
        if has_disallowed_local_path(text):
            findings.append({"path": relative, "issue": "local-absolute-path"})
    return findings


def portal_link_status(workspace_root: Path) -> dict[str, bool]:
    targets = markdown_link_targets(
        workspace_root, workspace_root / "docs/app-platform-developer-portal.md"
    )
    return {path: path in targets for path in REQUIRED_PORTAL_LINKS}


def readme_links_portal(workspace_root: Path) -> bool:
    return "docs/app-platform-developer-portal.md" in markdown_link_targets(
        workspace_root, workspace_root / "README.md"
    )


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

    missing_docs = sorted(path for path, present in required_docs.items() if not present)
    missing_issue_templates = sorted(path for path, present in issue_templates.items() if not present)
    missing_portal_links = sorted(path for path, present in portal_links.items() if not present)

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
            "tools/release-certification/app_platform_docs_check.py",
            {
                "internalLinksOk": not broken_links,
                "brokenLinks": broken_links,
                "redactionOk": not redaction,
                "redactionFindings": redaction,
                "externalUrlsFetched": False,
            },
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
        for path in sorted({*REQUIRED_DOCS, *REQUIRED_PORTAL_LINKS}):
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
        "Placeholder: USK@.../profile.json"
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
