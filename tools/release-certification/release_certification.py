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


TOOL_NAME = "release-certification"
SCHEMA_VERSION = 1
DEFAULT_OUT_DIR = Path("build/release-certification")
SUMMARY_FILE_NAME = "release-certification-summary.json"
REPORT_FILE_NAME = "release-certification-report.md"
CERT_STATUSES = ("pass", "warn", "fail", "skip", "missing")
MODES = ("pr", "nightly", "release-candidate")
PRIVATE_ARTIFACT_NAMES = ("private-insert-uris.json",)
SENSITIVE_KEY_PATTERN = (
    r"token|password|passwd|secret|credential|authorization|cookie|set-cookie|"
    r"private[-_ ]?key|formPassword|browserSessionToken|CRYPTAD_APP_TOKEN|X-Crypta-App-Session|"
    r"identity[-_ ]?seed|recovery[-_ ]?phrase|mnemonic"
)
SENSITIVE_KEY_RE = re.compile(
    rf"({SENSITIVE_KEY_PATTERN})",
    re.IGNORECASE,
)
SENSITIVE_HEADER_RE = re.compile(
    r"(?P<prefix>\b(?:Authorization|Cookie|Set-Cookie|X-Crypta-App-Session)\s*:\s*)"
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
    r"(?<![A-Za-z0-9_:/.\->])/(?:api/v1|apps|app/node|\.well-known)(?:/[^\s\])},;\"'?]*)?"
)
NON_SECRET_METADATA_SUFFIXES = (
    "available",
    "configured",
    "enabled",
    "excluded",
    "present",
    "redacted",
    "required",
    "source",
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
class Settings:
    workspace_root: Path
    out_dir: Path
    mode: str
    interop_smoke_summary: Path
    interop_extended_summary: Path
    perf_smoke_summary: Path
    app_platform_summary: Path
    waivers: dict[str, str]
    metadata: dict[str, str]
    skip_git_metadata: bool


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


def should_redact_key_name(key_hint: str) -> bool:
    normalized = normalize_key_name(key_hint)
    if not normalized:
        return False
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
    }:
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
    if should_redact_key_name(key_hint):
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


def with_waiver(
    item: EvidenceItem, waivers: dict[str, str], workspace_root: Path, out_dir: Path
) -> EvidenceItem:
    reason = waivers.get(item.id)
    if not reason or item.status == "pass":
        return item
    safe_reason = scrub_text(reason, workspace_root, out_dir)
    details = dict(item.details)
    details["waived"] = True
    details["waiverReason"] = safe_reason
    return EvidenceItem(
        id=item.id,
        status="warn",
        required_for_release_candidate=item.required_for_release_candidate,
        summary=f"{item.summary} Waiver recorded: {safe_reason}",
        source=item.source,
        details=details,
    )


def sanitize_evidence_item(item: EvidenceItem, workspace_root: Path, out_dir: Path) -> EvidenceItem:
    return EvidenceItem(
        id=item.id,
        status=item.status,
        required_for_release_candidate=item.required_for_release_candidate,
        summary=scrub_text(item.summary, workspace_root, out_dir),
        source=scrub_text(item.source, workspace_root, out_dir),
        details=dict(sanitize_value(item.details, workspace_root, out_dir)),
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
        "app-platform.devtools-cli",
        "platform-api.contract",
        "app-vault.capabilities",
        "app-platform.signed-bundles",
        "catalog.smoke",
        "app-review.trusted-receipts",
        "app-review.policy",
        "app-review.first-party-catalog",
        "app-ui.design-system",
        "app-ui.lint",
        "app-ui.first-party-adoption",
        "app-ui.smoke",
        "legacy.retirement",
        "apphost.sandbox-provider",
        "app-update.lifecycle",
        "app-update.rollback",
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


def determine_overall_status(mode: str, evidence: list[EvidenceItem]) -> tuple[str, bool]:
    required_bad = [
        item
        for item in evidence
        if item.required_for_release_candidate and item.status in {"fail", "missing", "skip"}
        and not item.details.get("waived")
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
            if item.required_for_release_candidate and item.status == "fail" and not item.details.get("waived")
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
        "interop-smoke-report.md": settings.interop_smoke_summary.parent / "artifacts" / "interop-report.md",
        "interop-extended-report.md": settings.interop_extended_summary.parent / "artifacts" / "interop-report.md",
        "performance-smoke-report.md": settings.perf_smoke_summary.parent / "artifacts" / "perf-report.md",
        "app-platform-smoke-report.md": settings.app_platform_summary.parent / "app-platform-smoke-report.md",
    }
    copied: list[str] = []
    for target_name, source_path in source_map.items():
        if not source_path.is_file():
            continue
        if any(name in str(source_path) for name in PRIVATE_ARTIFACT_NAMES):
            continue
        target_path = artifacts_dir / target_name
        if source_path.suffix == ".json":
            value = read_json(source_path)
            if value is None:
                continue
            write_json(target_path, sanitize_value(value, settings.workspace_root, out_dir))
        else:
            target_path.write_text(
                scrub_text(source_path.read_text(encoding="utf-8"), settings.workspace_root, out_dir),
                encoding="utf-8",
            )
        copied.append(display_path(target_path, settings.workspace_root, out_dir))
    return copied


def build_summary(settings: Settings, evidence: list[EvidenceItem], copied_artifacts: list[str]) -> dict[str, Any]:
    status, release_candidate_passed = determine_overall_status(settings.mode, evidence)
    metadata = {}
    metadata.update(collect_git_metadata(settings))
    metadata.update(collect_ci_metadata(os.environ))
    metadata.update(settings.metadata)
    sanitized_metadata = sanitize_value(metadata, settings.workspace_root, settings.out_dir)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "mode": settings.mode,
        "status": status,
        "releaseCandidatePassed": release_candidate_passed,
        "generatedAt": utc_now(),
        "workspaceRoot": "<repo>",
        "summaryPath": display_path(settings.out_dir / SUMMARY_FILE_NAME, settings.workspace_root, settings.out_dir),
        "reportPath": display_path(settings.out_dir / REPORT_FILE_NAME, settings.workspace_root, settings.out_dir),
        "artifactsDir": display_path(settings.out_dir / "artifacts", settings.workspace_root, settings.out_dir),
        "metadata": sanitized_metadata,
        "waivers": sanitize_value(settings.waivers, settings.workspace_root, settings.out_dir),
        "counts": evidence_counts(evidence),
        "evidence": [item.to_json() for item in evidence],
        "copiedArtifacts": copied_artifacts,
        "redaction": {
            "privateArtifactsExcluded": list(PRIVATE_ARTIFACT_NAMES),
            "secretMaterialRedacted": True,
            "rawUpdateRollbackOutputsExcluded": True,
            "absolutePathsSanitized": True,
        },
    }


def render_report(summary: dict[str, Any]) -> str:
    lines = [
        "# Release Certification Report",
        "",
        f"- Mode: `{summary['mode']}`",
        f"- Status: `{summary['status']}`",
        f"- Release-candidate gate: `{'passed' if summary['releaseCandidatePassed'] else 'failed'}`",
        f"- Generated: `{summary['generatedAt']}`",
        f"- Summary: `{summary['summaryPath']}`",
        f"- Artifacts: `{summary['artifactsDir']}`",
        "",
        "## Evidence Summary",
        "",
        "| Evidence | Status | Required for RC | Source | Summary |",
        "| --- | --- | --- | --- | --- |",
    ]
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
    lines.extend(["", "## Hyphanet Interop", ""])
    append_detail(lines, summary, "interop.smoke")
    append_detail(lines, summary, "interop.extended")
    lines.extend(["", "## Performance Regression", ""])
    append_detail(lines, summary, "performance.smoke")
    lines.extend(["", "## App Platform", ""])
    for evidence_id in (
        "app-platform.first-party",
        "app-platform.devtools-cli",
        "platform-api.contract",
        "app-vault.capabilities",
        "app-platform.signed-bundles",
        "catalog.smoke",
        "app-review.trusted-receipts",
        "app-review.policy",
        "app-review.first-party-catalog",
        "app-ui.design-system",
        "app-ui.lint",
        "app-ui.first-party-adoption",
        "app-ui.smoke",
        "apphost.sandbox-provider",
        "app-update.lifecycle",
        "app-update.rollback",
        "apphost.live",
    ):
        append_detail(lines, summary, evidence_id)
    lines.extend(["", "## Legacy Admin Retirement", ""])
    append_detail(lines, summary, "legacy.retirement")
    lines.extend(
        [
            "",
            "## Redaction Rules",
            "",
            "- Private signing keys, form passwords, app process tokens, browser-session tokens, raw request bodies, raw update or rollback command output, and private insert URIs are not included.",
            "- Local absolute paths are sanitized as `<repo>`, `<workdir>`, `<home>`, or `<path>` placeholders.",
            "- Catalog scratch paths, staged bundle paths, installed bundle paths, data/cache/run paths, and rollback backup paths are sanitized.",
            "- `artifacts/private-insert-uris.json` is excluded even if an interop summary references it.",
            "",
        ]
    )
    return "\n".join(lines)


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


def gather_evidence(settings: Settings) -> list[EvidenceItem]:
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
    return [
        sanitize_evidence_item(
            with_waiver(item, settings.waivers, settings.workspace_root, settings.out_dir),
            settings.workspace_root,
            settings.out_dir,
        )
        for item in evidence
    ]


def run(settings: Settings) -> tuple[dict[str, Any], int]:
    settings.out_dir.mkdir(parents=True, exist_ok=True)
    copied = collect_source_artifacts(settings, settings.out_dir)
    evidence = gather_evidence(settings)
    summary = build_summary(settings, evidence, copied)
    write_json(settings.out_dir / SUMMARY_FILE_NAME, summary)
    report = render_report(summary)
    write_text(settings.out_dir / REPORT_FILE_NAME, report)
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


def settings_from_args(args: argparse.Namespace) -> Settings:
    workspace_root = args.workspace_root.resolve()
    out_dir = (workspace_root / args.out_dir).resolve() if not args.out_dir.is_absolute() else args.out_dir.resolve()
    mode = args.mode or os.environ.get("CRYPTAD_CERT_MODE", "pr")
    if mode not in MODES:
        raise SystemExit(f"--mode must be one of {', '.join(MODES)}")
    return Settings(
        workspace_root=workspace_root,
        out_dir=out_dir,
        mode=mode,
        interop_smoke_summary=resolve_path(workspace_root, args.interop_smoke_summary),
        interop_extended_summary=resolve_path(workspace_root, args.interop_extended_summary),
        perf_smoke_summary=resolve_path(workspace_root, args.perf_smoke_summary),
        app_platform_summary=resolve_path(workspace_root, args.app_platform_summary),
        waivers=parse_key_value(args.waive),
        metadata=parse_key_value(args.metadata),
        skip_git_metadata=args.skip_git_metadata,
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
    parser.add_argument("--waive", action="append", default=[], metavar="ID=REASON")
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
        shutil.copy2(fixture_dir / "self-test-interop-smoke.json", workspace / "build/interop-smoke/summary.json")
        shutil.copy2(
            fixture_dir / "self-test-interop-extended.json",
            workspace / "build/interop-extended/summary.json",
        )
        shutil.copy2(fixture_dir / "self-test-perf-smoke.json", workspace / "build/perf-smoke/summary.json")
        shutil.copy2(
            fixture_dir / "self-test-app-platform-smoke.json",
            out_dir / "app-platform-smoke/summary.json",
        )
        settings = Settings(
            workspace_root=workspace.resolve(),
            out_dir=out_dir.resolve(),
            mode="release-candidate",
            interop_smoke_summary=workspace / "build/interop-smoke/summary.json",
            interop_extended_summary=workspace / "build/interop-extended/summary.json",
            perf_smoke_summary=workspace / "build/perf-smoke/summary.json",
            app_platform_summary=out_dir / "app-platform-smoke/summary.json",
            waivers={},
            metadata={"selfTest": "true"},
            skip_git_metadata=True,
        )
        summary, exit_code = run(settings)
        assert exit_code == 0, summary
        assert summary["status"] == "pass", summary
        assert summary["releaseCandidatePassed"] is True, summary
        evidence_by_id = {item["id"]: item for item in summary["evidence"]}
        assert evidence_by_id["app-update.lifecycle"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["app-update.lifecycle"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["app-update.rollback"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["app-update.rollback"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["app-vault.capabilities"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["app-vault.capabilities"]["requiredForReleaseCandidate"] is True
        optional_skip_status, optional_skip_release_passed = determine_overall_status(
            "release-candidate",
            [
                EvidenceItem("catalog.smoke", "pass", True, "passed", "<repo>/summary.json", {}),
                EvidenceItem("apphost.live", "skip", False, "not requested", "<repo>/summary.json", {}),
            ],
        )
        assert optional_skip_status == "pass", optional_skip_status
        assert optional_skip_release_passed is True, optional_skip_release_passed
        report = (out_dir / REPORT_FILE_NAME).read_text(encoding="utf-8")
        assert "Release Certification Report" in report
        encoded = json.dumps(summary, sort_keys=True)
        for forbidden in ("CRYPTAD_APP_TOKEN", "USK@private", str(workspace)):
            assert forbidden not in encoded, f"self-test leaked {forbidden}"
        interop_item = next(item for item in summary["evidence"] if item["id"] == "interop.smoke")
        assert "artifacts/private-insert-uris.json" not in json.dumps(interop_item)
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
            if item.get("id") not in {"app-update.lifecycle", "app-update.rollback"}
        ]
        write_json(missing_update_evidence_path, missing_update_summary)
        missing_update_items = app_platform_evidence(
            missing_update_evidence_path, workspace, out_dir, "release-candidate"
        )
        missing_update_by_id = {item.id: item for item in missing_update_items}
        assert missing_update_by_id["app-update.lifecycle"].status == "missing", missing_update_by_id
        assert missing_update_by_id["app-update.rollback"].status == "missing", missing_update_by_id
        missing_update_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/missing-update-cert").resolve(),
            app_platform_summary=missing_update_evidence_path,
        )
        missing_update_cert_summary, missing_update_exit_code = run(missing_update_settings)
        assert missing_update_exit_code == 1, missing_update_cert_summary
        assert missing_update_cert_summary["status"] == "fail", missing_update_cert_summary
        assert missing_update_cert_summary["releaseCandidatePassed"] is False, missing_update_cert_summary

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
        credential_scrubbed = scrub_text(
            'Authorization: Bearer report-secret\n'
            'Cookie: session=abc; csrf=def\n'
            '{"token":"json-secret","authorization":"Bearer json-secret","password":"pw"} '
            "authorization=Bearer inline-secret "
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
        assert (external_out_dir / SUMMARY_FILE_NAME).is_file(), external_summary
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

        nightly_missing_settings = dataclasses.replace(
            missing_settings,
            out_dir=(workspace / "build/nightly-missing-cert").resolve(),
            mode="nightly",
        )
        nightly_missing_summary, nightly_missing_exit_code = run(nightly_missing_settings)
        assert nightly_missing_exit_code == 0, nightly_missing_summary
        assert nightly_missing_summary["status"] == "warn", nightly_missing_summary
        assert nightly_missing_summary["releaseCandidatePassed"] is False, nightly_missing_summary

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
        sensitive_encoded = json.dumps(sensitive_waived_summary, sort_keys=True) + sensitive_report
        for forbidden in ("hunter2", "USK@private", "/mnt/secrets/signing/key.pem", str(workspace)):
            assert forbidden not in sensitive_encoded, f"waiver reason leaked {forbidden}"


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
