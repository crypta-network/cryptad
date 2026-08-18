"""Shared validation and canonical-digest helpers for Stable 1.0 RC execution."""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable

from cryptad_certification.io import read_json
from cryptad_certification.envelope import validate_envelope
from cryptad_certification.models import RunContext
from cryptad_certification.redaction import scan_value
from cryptad_certification.schema_validation import validate_schema

SCHEMA_VERSION = 1
TOOL_NAME = "stable-1.0-rc"
TOOL_VERSION = 1
STABLE_MILESTONE = "1.0"
FREEZE_KIND = "stable-1.0-rc-freeze"
CATALOG_OPERATIONS_KIND = "stable-1.0-rc-catalog-operations"
CATALOG_OPERATIONS_SCHEMA = "stable-1.0-rc-catalog-operations-v1.schema.json"
FREEZE_EXCEPTIONS_KIND = "stable-1.0-rc-freeze-exceptions"
FREEZE_EXCEPTIONS_SCHEMA = "stable-1.0-rc-freeze-exceptions-v1.schema.json"

SUMMARY_FILE = "stable-1.0-rc-promotion-summary.json"
REPORT_FILE = "stable-1.0-rc-go-no-go.md"
FREEZE_FILE = "stable-1.0-rc-freeze.json"
FREEZE_SIDECAR_FILE = "stable-1.0-rc-freeze.sha256"
FREEZE_REPORT_FILE = "stable-1.0-rc-freeze-report.md"
DRIFT_REPORT_FILE = "stable-1.0-rc-drift-report.json"
KNOWN_LIMITATIONS_FILE = "stable-1.0-rc-known-limitations.json"
RELEASE_NOTES_FILE = "stable-1.0-rc-release-notes.md"
REDACTION_REPORT_FILE = "redaction-report.json"
CHECKSUMS_FILE = "checksums.txt"
PROVENANCE_FILE = "provenance.json"
SUPPORTING_VERIFIER_FILES = (
    "content-format-profiles.json",
    "feed-reader-api-compatibility.json",
    "platform-api-current-contract.json",
    "platform-api-stable-diff.json",
    "profile-publisher-api-compatibility.json",
    "publisher-api-compatibility.json",
    "queue-manager-api-compatibility.json",
    "site-publisher-api-compatibility.json",
    "social-inbox-api-compatibility.json",
    "trust-graph-api-compatibility.json",
)

FINAL_DECISION_EVIDENCE_ID = "stable-1.0-rc.final-decision"

EVIDENCE_IDS = (
    "stable-1.0-rc.prerequisites",
    "stable-1.0-rc.candidate-binding",
    "stable-1.0-rc.production-beta",
    "stable-1.0-rc.stable-readiness",
    "stable-1.0-rc.platform-api-freeze",
    "stable-1.0-rc.catalog-freeze",
    "stable-1.0-rc.first-party-app-freeze",
    "stable-1.0-rc.content-format-freeze",
    "stable-1.0-rc.limitations-freeze",
    "stable-1.0-rc.freeze-verification",
    "stable-1.0-rc.archive-hygiene",
    "stable-1.0-rc.provenance",
    "stable-1.0-rc.redaction",
    "stable-1.0-rc.release-notes",
    FINAL_DECISION_EVIDENCE_ID,
)

REQUIRED_STABLE_DOMAIN_IDS = (
    "readiness-policy",
    "production-beta-state",
    "release-certification-summary",
    "ecosystem-certification-matrix",
    "platform-api-1.0",
    "app-ecosystem-maturity",
    "third-party-intake",
    "security-drills",
    "live-multi-node-soak",
    "legacy-plugin-migration",
    "support-feedback-readiness",
    "known-limitations",
    "redaction",
)

REQUIRED_PIPELINE_STAGES = (
    "crypta-app-launcher-install",
    "gradle-full-build",
    "first-party-app-staging",
    "first-party-app-signing",
    "first-party-app-verification",
)

FIRST_PARTY_APP_IDS = frozenset(
    {
        "queue-manager",
        "publisher",
        "site-publisher",
        "profile-publisher",
        "social-inbox",
        "feed-reader",
        "trust-graph",
    }
)

CONTENT_PROFILE_IDS = (
    "crypta.profile.v1",
    "crypta.feed.snapshot.v1",
    "crypta.trust.statement.v1",
    "crypta.social.message.v1",
    "crypta.social.outbox.v1",
)

EXISTING_INPUT_COMPONENTS = {
    "appPlatform": "app-platform",
    "ecosystemMatrix": "release-certification",
    "goNoGo": "go-no-go",
    "liveNetwork": "live-network-beta",
    "multiNodeSoak": "multi-node-beta/run",
    "networkScaleSoak": "network-scale-soak",
    "previousCandidate": "migration/previous-candidate",
    "productionBeta": "production-beta",
    "releaseCertification": "release-certification",
    "releaseHistory": "migration/release-history",
    "securityDrills": "security-response/drill-verify-all",
    "stableReadiness": "stable-readiness",
    "thirdPartyIntake": "production-beta",
}

REQUIRED_EVIDENCE_INPUTS = tuple(EXISTING_INPUT_COMPONENTS)
HISTORICAL_RELEASE_INPUT_KEYS = frozenset({"previousCandidate", "releaseHistory"})
EMBEDDED_PRODUCTION_INPUTS = {
    "appPlatform": "evidence/app-platform-smoke.json",
    "ecosystemMatrix": "evidence/ecosystem-certification-matrix.json",
    "goNoGo": "reports/go-no-go-dashboard.json",
    "releaseCertification": "evidence/ecosystem-rc-certification.json",
    "stableReadiness": "reports/stable-1.0-readiness/stable-1.0-readiness-summary.json",
}
SAME_RUN_INPUT_KEYS = ("productionBeta", *EMBEDDED_PRODUCTION_INPUTS)
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
BUILD_VERSION_RE = re.compile(r"[1-9][0-9]*\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40,64}\Z")
PLACEHOLDER_RE = re.compile(
    r"(?i)(?:example\.invalid|\bREPLACE_ME\b|\bREPLACE_WITH_[A-Z0-9_]+\b|"
    r"PBKI-EXAMPLE-001|cryptad-beta-example|BACKLOG-PUBLIC-BETA-CATALOG-MIRROR-EXAMPLE)"
)


@dataclasses.dataclass(frozen=True)
class LoadedInput:
    """One validated reusable input and the digest of its original envelope or file."""

    key: str
    path: Path
    value: dict[str, Any]
    digest: str


@dataclasses.dataclass(frozen=True)
class SourceIdentity:
    """Candidate source identity without local filesystem information."""

    commit: str
    ref: str
    digest: str


@dataclasses.dataclass
class ValidationState:
    """Accumulate redaction-safe Stable RC blockers and warnings."""

    blockers: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    warnings: list[dict[str, Any]] = dataclasses.field(default_factory=list)

    def block(self, issue_id: str, evidence_id: str, summary: str, remediation: str) -> None:
        self.blockers.append(
            {
                "id": issue_id,
                "evidenceId": evidence_id,
                "severity": "blocker",
                "summary": summary,
                "remediation": remediation,
                "waivable": False,
            }
        )

    def warn(self, issue_id: str, evidence_id: str, summary: str) -> None:
        self.warnings.append(
            {
                "id": issue_id,
                "evidenceId": evidence_id,
                "severity": "warning",
                "summary": summary,
                "waivable": False,
            }
        )


def canonical_json(value: Any) -> str:
    """Serialize a semantic value using the Stable RC canonical JSON rules."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def semantic_digest(value: Any) -> str:
    """Return a normalized SHA-256 digest of canonical JSON."""

    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def file_digest(path: Path) -> str:
    """Return a normalized SHA-256 digest of exact file bytes."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def parse_timestamp(value: Any) -> dt.datetime | None:
    """Parse one RFC 3339 timestamp into UTC, returning ``None`` when malformed."""

    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def freshness_error(value: Any, now: dt.datetime, maximum_age_days: int, label: str) -> str | None:
    """Return a redaction-safe freshness failure for an evidence timestamp."""

    parsed = parse_timestamp(value)
    if parsed is None:
        return f"{label} generatedAt is missing or malformed"
    if parsed > now:
        return f"{label} generatedAt is in the future"
    if now - parsed > dt.timedelta(days=maximum_age_days):
        return f"{label} is older than {maximum_age_days} days"
    return None


def placeholder_findings(value: Any, path: str = "$") -> list[str]:
    """Return JSON paths containing production placeholder markers."""

    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            findings.extend(placeholder_findings(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(placeholder_findings(child, f"{path}[{index}]"))
    elif isinstance(value, str) and PLACEHOLDER_RE.search(value):
        findings.append(path)
    return findings


def _configured_path(context: RunContext, key: str) -> Path | None:
    raw = context.manifest.inputs.get(key)
    if not isinstance(raw, str) or not raw:
        return None
    supplied = Path(raw)
    candidate = supplied if supplied.is_absolute() else context.workspace_root / supplied
    absolute = candidate.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError(f"Stable RC input path contains a symlink: {key}")
    resolved = absolute.resolve()
    if not supplied.is_absolute():
        try:
            resolved.relative_to(context.workspace_root.resolve())
        except ValueError as exc:
            raise ValueError(f"Stable RC input escapes the workspace: {key}") from exc
    return resolved


def _original_input_path(context: RunContext, key: str) -> Path | None:
    configured = _configured_path(context, key)
    if configured is not None:
        return configured
    component = EXISTING_INPUT_COMPONENTS.get(key)
    if component is None:
        return None
    path = context.run_root / component / "summary.json"
    return path if path.is_file() else None


def load_existing_input(context: RunContext, key: str) -> LoadedInput:
    """Load one established v2 input through the existing candidate-binding adapter."""

    original = _original_input_path(context, key)
    if original is None or original.is_symlink() or not original.is_file():
        raise ValueError(f"required Stable RC input is missing: {key}")
    if _configured_path(context, key) is None:
        if key != "productionBeta":
            raise ValueError(
                f"Stable RC requires inputs.{key} to name candidate-bound reusable evidence"
            )
        envelope = read_json(original)
        validate_envelope(envelope, "production-beta-release", context.manifest.release.release_id)
        subject = envelope["subject"]
        if (
            subject.get("profile") != "stable-review"
            or subject.get("component") != "production-beta"
            or subject.get("version") != context.manifest.release.version
            or envelope["result"].get("status") != "pass"
            or envelope["result"].get("exitCode") != 0
            or envelope["redaction"].get("status") != "pass"
        ):
            raise ValueError("same-run production-beta envelope is not candidate-bound and passing")
        payload = envelope.get("payload")
        legacy_value = payload.get("legacy") if isinstance(payload, dict) else None
        if not isinstance(legacy_value, dict) or scan_value(legacy_value):
            raise ValueError("same-run production-beta envelope payload is missing or unsafe")
        return LoadedInput(key, original, legacy_value, file_digest(original))
    # Import lazily because the legacy adapter imports this engine to execute the Stable RC.
    from cryptad_certification import legacy

    migrated_kind = {
        "previousCandidate": "previous-candidate",
        "releaseHistory": "release-history",
    }.get(key)
    extracted = legacy._legacy_input_path(  # noqa: SLF001 - shared adapter contract
        context,
        key,
        migrated_kind=migrated_kind,
    )
    if extracted is None or extracted.is_symlink() or not extracted.is_file():
        raise ValueError(f"Stable RC input could not be unwrapped: {key}")
    value = read_json(extracted)
    if not isinstance(value, dict):
        raise ValueError(f"Stable RC input payload must be an object: {key}")
    if key == "stableReadiness":
        envelope = read_json(original)
        if not isinstance(envelope, dict) or envelope.get("subject", {}).get("profile") != "stable-review":
            raise ValueError("inputs.stableReadiness must be produced with profile stable-review")
    return LoadedInput(key, original, value, file_digest(original))


def load_raw_input(context: RunContext, key: str, required: bool = True) -> LoadedInput | None:
    """Load one strict raw JSON input that intentionally has no legacy v2 mapping."""

    path = _configured_path(context, key)
    if path is None:
        if required:
            raise ValueError(f"required Stable RC input is missing: {key}")
        return None
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Stable RC input is missing or unsafe: {key}")
    value = read_json(path)
    if not isinstance(value, dict):
        raise ValueError(f"Stable RC input must be a JSON object: {key}")
    findings = scan_value(value)
    if findings:
        raise ValueError(f"Stable RC input failed redaction validation: {key}")
    return LoadedInput(key, path, value, file_digest(path))


def _embedded_production_path(native_root: Path, relative: str, key: str) -> Path:
    """Resolve one same-run production artifact without following symlinked components."""

    supplied = Path(relative)
    if supplied.is_absolute() or ".." in supplied.parts:
        raise ValueError(f"production-beta embedded Stable RC input path is unsafe: {key}")
    if native_root.is_symlink() or not native_root.is_dir():
        raise ValueError("production-beta native artifact directory is missing or unsafe")
    current = native_root
    for part in supplied.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(
                f"production-beta embedded Stable RC input path contains a symlink: {key}"
            )
    resolved = current.resolve()
    try:
        resolved.relative_to(native_root.resolve())
    except ValueError as exc:
        raise ValueError(
            f"production-beta embedded Stable RC input escapes its artifact root: {key}"
        ) from exc
    if not resolved.is_file():
        raise ValueError(f"production-beta output omits embedded Stable RC input: {key}")
    return resolved


def load_candidate_inputs(context: RunContext, native_root: Path) -> dict[str, LoadedInput]:
    """Load protected external evidence plus summaries embedded by the production pipeline."""

    configured_same_run = [
        key for key in SAME_RUN_INPUT_KEYS if key in context.manifest.inputs
    ]
    if configured_same_run:
        names = ", ".join(f"inputs.{key}" for key in configured_same_run)
        raise ValueError(f"Stable RC same-run inputs are not externally configurable: {names}")
    inputs: dict[str, LoadedInput] = {"productionBeta": load_existing_input(context, "productionBeta")}
    for key, relative in EMBEDDED_PRODUCTION_INPUTS.items():
        path = _embedded_production_path(native_root, relative, key)
        value = read_json(path)
        if not isinstance(value, dict) or scan_value(value):
            raise ValueError(f"production-beta embedded Stable RC input is malformed or unsafe: {key}")
        inputs[key] = LoadedInput(key, path, value, file_digest(path))
    for key in (
        "liveNetwork",
        "multiNodeSoak",
        "networkScaleSoak",
        "previousCandidate",
        "releaseHistory",
        "securityDrills",
    ):
        inputs[key] = load_existing_input(context, key)
    third_party = load_raw_input(context, "thirdPartyIntake")
    if third_party is None:
        raise ValueError("required Stable RC input is missing: thirdPartyIntake")
    inputs["thirdPartyIntake"] = third_party
    return inputs


def _git(context: RunContext, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=context.workspace_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise ValueError("candidate git metadata is unavailable")
    return result.stdout.strip()


def source_identity(context: RunContext, release_certification: dict[str, Any]) -> SourceIdentity:
    """Bind the current clean workspace to release-certification source metadata."""

    if context.manifest.execution.get("skipGitMetadata") is True:
        raise ValueError("Stable RC forbids execution.skipGitMetadata")
    if context.manifest.execution.get("allowDirtyWorkspace") is True:
        raise ValueError("Stable RC forbids execution.allowDirtyWorkspace")
    status = _git(context, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise ValueError("Stable RC requires a clean git workspace")
    commit = _git(context, "rev-parse", "HEAD").lower()
    if COMMIT_RE.fullmatch(commit) is None:
        raise ValueError("candidate git commit is malformed")
    # Branch names differ between a protected CI checkout and a release-manager checkout. Bind the
    # public source reference to the immutable commit so the same candidate freezes identically.
    ref = f"commit:{commit}"
    metadata = (
        release_certification.get("metadata")
        if isinstance(release_certification.get("metadata"), dict)
        else {}
    )
    recorded = str(
        metadata.get("gitCommit")
        or metadata.get("githubSha")
        or release_certification.get("gitCommit")
        or ""
    ).lower()
    if recorded != commit:
        raise ValueError("release-certification source commit does not match candidate HEAD")
    return SourceIdentity(commit, ref, semantic_digest({"commit": commit, "ref": ref}))


def _status_pass(value: Any) -> bool:
    return str(value or "").lower() in {"pass", "passed", "success"}


def release_certification_is_promotable(value: dict[str, Any]) -> bool:
    """Preserve the established RC pass/warn result contract."""

    status = str(value.get("status") or "").lower()
    return value.get("releaseCandidatePassed") is True and (
        _status_pass(status) or status == "warn"
    )


def stable_vulnerability_governance_errors(
    value: dict[str, Any],
) -> list[str]:
    """Require the exact non-waivable PR-288 evidence and child gate in an RC result."""

    evidence = value.get("evidence")
    evidence = evidence if isinstance(evidence, list) else []
    evidence_rows = [
        row
        for row in evidence
        if isinstance(row, dict)
        and row.get("id") == "stable-vulnerability.release-promotion"
    ]
    gates = value.get("ecosystemGates")
    gates = gates if isinstance(gates, list) else []
    gate_rows = [
        row
        for row in gates
        if isinstance(row, dict)
        and row.get("id") == "ecosystem.stable-vulnerability"
    ]
    errors: list[str] = []
    if len(evidence_rows) != 1:
        errors.append("release certification omits exact Stable vulnerability evidence")
    else:
        row = evidence_rows[0]
        details = row.get("details")
        details = details if isinstance(details, dict) else {}
        if (
            row.get("status") != "pass"
            or row.get("requiredForReleaseCandidate") is not True
            or details.get("authenticated") is not True
            or details.get("blockingStablePromotion") is not False
            or details.get("nonWaivable") is not True
            or details.get("validationErrors") != []
        ):
            errors.append("Stable vulnerability release evidence is not passing")
    if len(gate_rows) != 1:
        errors.append("release certification omits the Stable vulnerability gate")
    else:
        gate = gate_rows[0]
        details = gate.get("details")
        details = details if isinstance(details, dict) else {}
        if (
            gate.get("status") != "pass"
            or gate.get("releaseBlocker") is not False
            or details.get("nonWaivable") is not True
            or details.get("evidenceId")
            != "stable-vulnerability.release-promotion"
        ):
            errors.append("Stable vulnerability child gate is not passing")
    return errors


def stable_release_authority_governance_errors(
    value: dict[str, Any],
    *,
    evidence_id: str,
    gate_id: str,
    label: str,
) -> list[str]:
    """Require one exact non-waivable final Stable authority and child gate."""

    evidence = value.get("evidence")
    evidence = evidence if isinstance(evidence, list) else []
    evidence_rows = [
        row
        for row in evidence
        if isinstance(row, dict) and row.get("id") == evidence_id
    ]
    gates = value.get("ecosystemGates")
    gates = gates if isinstance(gates, list) else []
    gate_rows = [
        row for row in gates if isinstance(row, dict) and row.get("id") == gate_id
    ]
    errors: list[str] = []
    if len(evidence_rows) != 1:
        errors.append(f"release certification omits exact {label} evidence")
    else:
        row = evidence_rows[0]
        details = row.get("details")
        details = details if isinstance(details, dict) else {}
        if (
            row.get("status") != "pass"
            or row.get("requiredForReleaseCandidate") is not True
            or details.get("authenticated") is not True
            or details.get("promotionReady") is not True
            or details.get("nonWaivable") is not True
            or details.get("validationErrors") != []
        ):
            errors.append(f"{label} release evidence is not passing")
    if len(gate_rows) != 1:
        errors.append(f"release certification omits the {label} gate")
    else:
        gate = gate_rows[0]
        details = gate.get("details")
        details = details if isinstance(details, dict) else {}
        if (
            gate.get("status") != "pass"
            or gate.get("releaseBlocker") is not False
            or details.get("nonWaivable") is not True
            or details.get("evidenceId") != evidence_id
        ):
            errors.append(f"{label} child gate is not passing")
    return errors


def ecosystem_matrix_is_promotable(value: dict[str, Any]) -> bool:
    """Return whether the established matrix permits release promotion."""

    status = str(value.get("status") or "").lower()
    blocker_count = value.get("releaseBlockerCount")
    return (
        (_status_pass(status) or status == "warn")
        and type(blocker_count) is int
        and blocker_count == 0
    )


def _top_level_release_proof_errors(value: dict[str, Any], label: str) -> list[str]:
    errors: list[str] = []
    if not _status_pass(value.get("status")):
        errors.append(f"{label} status is not pass")
    for field in ("fixtureOnly", "simulatedOnly", "nonRelease", "nonProduction"):
        if field in value and value.get(field) is not False:
            errors.append(f"{label} {field} is not false")
    return errors


def explicit_production_classification_errors(
    value: dict[str, Any],
    label: str,
) -> list[str]:
    """Require raw release proof to state every non-production classification as false."""

    return [
        f"{label} {field} must be present and false"
        for field in ("fixtureOnly", "simulatedOnly", "nonRelease", "nonProduction")
        if value.get(field) is not False
    ]


def validate_prerequisites(
    context: RunContext,
    inputs: dict[str, LoadedInput],
    catalog_operations: LoadedInput,
    now: dt.datetime,
    state: ValidationState,
) -> None:
    """Validate release-critical producer results without re-evaluating Stable policy domains."""

    release_id = context.manifest.release.release_id
    build_version = context.manifest.release.version
    if context.manifest.release.profile != "stable-review":
        state.block(
            "stable-1.0-rc.profile",
            "stable-1.0-rc.prerequisites",
            "Stable RC execution requires release.profile stable-review.",
            "Run the protected stable-review pipeline.",
        )
    if not isinstance(build_version, str) or BUILD_VERSION_RE.fullmatch(build_version) is None:
        state.block(
            "stable-1.0-rc.build-version",
            "stable-1.0-rc.candidate-binding",
            "Stable RC buildVersion must be a positive integer string.",
            "Use the repository integer build version, not a semantic product version.",
        )
    forbidden_execution = (
        "allowTestSigningInProduction",
        "emergencySkipBuild",
        "emergencySkipLiveNetwork",
        "fixtureEvidence",
        "skipFullBuild",
        "skipGitMetadata",
        "skipGradle",
    )
    for field in forbidden_execution:
        if context.manifest.execution.get(field) is True:
            state.block(
                f"stable-1.0-rc.execution.{field}",
                "stable-1.0-rc.prerequisites",
                f"Stable RC forbids execution.{field}=true.",
                "Rerun the complete protected pipeline without release-stage skips or fixtures.",
            )

    production = inputs["productionBeta"].value
    validate_production_beta(production, release_id, str(build_version or ""), state)

    go_no_go = inputs["goNoGo"].value
    decision = go_no_go.get("decision")
    if (
        decision not in {"go", "go-with-waivers"}
        or go_no_go.get("promotionReady") is not True
    ):
        state.block(
            "stable-1.0-rc.production-go-no-go",
            "stable-1.0-rc.prerequisites",
            "Production go/no-go evidence is not promotable.",
            "Resolve dashboard blockers and regenerate the candidate-bound decision.",
        )

    certification = inputs["releaseCertification"].value
    if not release_certification_is_promotable(certification):
        state.block(
            "stable-1.0-rc.release-certification",
            "stable-1.0-rc.prerequisites",
            "Release certification is not passing.",
            "Regenerate the complete release-certification result.",
        )
    for error in stable_vulnerability_governance_errors(certification):
        state.block(
            "stable-1.0-rc.stable-vulnerability",
            "stable-1.0-rc.prerequisites",
            error + ".",
            "Regenerate release certification with the current authenticated "
            "ledger-wide Stable vulnerability promotion handoff.",
        )
    for authority, evidence_id, gate_id in (
        (
            "Stable supply-chain",
            "stable-supply-chain.release-promotion",
            "ecosystem.stable-supply-chain",
        ),
        (
            "Stable dependency-vulnerability",
            "stable-dependency-vulnerability.release-promotion",
            "ecosystem.stable-dependency-vulnerability",
        ),
    ):
        for error in stable_release_authority_governance_errors(
            certification,
            evidence_id=evidence_id,
            gate_id=gate_id,
            label=authority,
        ):
            state.block(
                f"stable-1.0-rc.{gate_id.removeprefix('ecosystem.')}",
                "stable-1.0-rc.prerequisites",
                error + ".",
                f"Regenerate release certification with the current authenticated {authority} promotion handoff.",
            )
    matrix = inputs["ecosystemMatrix"].value
    if not ecosystem_matrix_is_promotable(matrix):
        state.block(
            "stable-1.0-rc.ecosystem-matrix",
            "stable-1.0-rc.prerequisites",
            "Ecosystem matrix is missing, malformed, or has release blockers.",
            "Resolve all ecosystem release blockers and regenerate the matrix.",
        )

    validate_stable_readiness(inputs["stableReadiness"].value, release_id, now, inputs, state)
    validate_live_inputs(
        inputs,
        release_id,
        str(build_version or ""),
        now,
        state,
    )
    validate_catalog_operations(
        catalog_operations.value,
        release_id,
        str(build_version or ""),
        now,
        state,
    )

    for loaded in [*inputs.values(), catalog_operations]:
        findings = scan_value(loaded.value)
        if findings:
            state.block(
                f"stable-1.0-rc.redaction.{loaded.key}",
                "stable-1.0-rc.redaction",
                f"Input {loaded.key} contains redaction findings.",
                "Replace the input with a redaction-safe candidate-bound summary.",
            )
        placeholders = placeholder_findings(loaded.value)
        if placeholders:
            state.block(
                f"stable-1.0-rc.placeholder.{loaded.key}",
                "stable-1.0-rc.redaction",
                f"Input {loaded.key} contains production placeholder metadata.",
                "Replace example and REPLACE_ME metadata before Stable RC execution.",
            )


def validate_production_beta(
    production: dict[str, Any],
    release_id: str,
    build_version: str,
    state: ValidationState,
) -> None:
    """Validate the protected production summary consumed by Stable RC execution."""

    for error in _top_level_release_proof_errors(production, "production-beta summary"):
        state.block(
            "stable-1.0-rc.production-beta-state",
            "stable-1.0-rc.production-beta",
            error + ".",
            "Regenerate passing production-beta evidence for this candidate.",
        )
    if production.get("promotionReady") is not True or production.get("nonRelease") is not False:
        state.block(
            "stable-1.0-rc.production-beta-promotion",
            "stable-1.0-rc.production-beta",
            "Production-beta evidence is not promotionReady=true and nonRelease=false.",
            "Complete every production-beta gate with production signing.",
        )
    if production.get("releaseId") != release_id or str(production.get("version")) != build_version:
        state.block(
            "stable-1.0-rc.production-beta-binding",
            "stable-1.0-rc.candidate-binding",
            "Production-beta identity does not match the Stable RC candidate.",
            "Attach evidence produced for the exact release ID and integer build.",
        )
    signing = production.get("signingProfile") if isinstance(production.get("signingProfile"), dict) else {}
    if (
        signing.get("kind") != "production"
        or signing.get("generatedTestKeys") is not False
        or signing.get("privateKeyMaterialIncluded") is not False
    ):
        state.block(
            "stable-1.0-rc.production-signing",
            "stable-1.0-rc.production-beta",
            "Production-beta signing profile is not protected production signing.",
            "Rerun with configured production app and reviewer signing identities.",
        )
    if production.get("workspaceStatusKnown") is not True or production.get("dirtyWorkspace") is not False:
        state.block(
            "stable-1.0-rc.production-workspace",
            "stable-1.0-rc.candidate-binding",
            "Production-beta workspace was dirty or its status was unknown.",
            "Rebuild from a clean candidate-bound workspace.",
        )
    stages = production.get("pipelineStages") if isinstance(production.get("pipelineStages"), dict) else {}
    for stage in REQUIRED_PIPELINE_STAGES:
        row = stages.get(stage) if isinstance(stages.get(stage), dict) else {}
        if row.get("status") != "pass":
            state.block(
                f"stable-1.0-rc.pipeline-stage.{stage}",
                "stable-1.0-rc.production-beta",
                f"Required production pipeline stage {stage} is not passing.",
                "Rerun the full build, stage, sign, and verify pipeline.",
            )


def validate_stable_readiness(
    summary: dict[str, Any],
    release_id: str,
    now: dt.datetime,
    inputs: dict[str, LoadedInput],
    state: ValidationState,
) -> None:
    """Reuse PR-282 Stable-readiness validation and add RC freshness/profile requirements."""

    from cryptad_certification.engines import production_beta_go_no_go_dashboard as dashboard

    for issue in dashboard.stable_readiness_issues(summary, True, release_id):
        if issue.severity in {"blocker", "critical"}:
            state.block(
                issue.id,
                "stable-1.0-rc.stable-readiness",
                issue.summary,
                "Regenerate a passing, complete Stable 1.0 readiness result for this candidate.",
            )
        elif issue.id != "stable-1.0.readiness-summary.allowed-limitations":
            state.warn(issue.id, "stable-1.0-rc.stable-readiness", issue.summary)
    domains = summary.get("domains")
    domain_ids = [row.get("id") for row in domains if isinstance(row, dict)] if isinstance(domains, list) else []
    if tuple(domain_ids) != REQUIRED_STABLE_DOMAIN_IDS or len(set(domain_ids)) != len(domain_ids):
        state.block(
            "stable-1.0-rc.stable-readiness-domains",
            "stable-1.0-rc.stable-readiness",
            "Stable readiness domains are missing, duplicated, truncated, or reordered.",
            "Regenerate Stable readiness with the PR-282 producer.",
        )
    maximum_age_days = 30
    # The policy is frozen separately; the established current default is used only if unavailable.
    policy_path = inputs.get("stableReadinessPolicy")
    if policy_path is not None:
        required_soak = policy_path.value.get("requiredSoak")
        if isinstance(required_soak, dict) and type(required_soak.get("maximumEvidenceAgeDays")) is int:
            maximum_age_days = required_soak["maximumEvidenceAgeDays"]
    error = freshness_error(summary.get("generatedAt"), now, maximum_age_days, "Stable readiness")
    if error:
        state.block(
            "stable-1.0-rc.stable-readiness-freshness",
            "stable-1.0-rc.stable-readiness",
            error + ".",
            "Regenerate Stable readiness from fresh candidate evidence.",
        )


def validate_live_inputs(
    inputs: dict[str, LoadedInput],
    release_id: str,
    build_version: str,
    now: dt.datetime,
    state: ValidationState,
) -> None:
    """Require real, fresh live/multi-node/network/security/intake evidence."""

    specifications = (
        ("liveNetwork", {"live", "production", "release-candidate"}, 30),
        ("multiNodeSoak", {"live", "hybrid"}, 30),
        ("networkScaleSoak", {"live-rc-soak"}, 30),
        ("securityDrills", set(), 30),
        ("thirdPartyIntake", set(), 30),
        ("previousCandidate", set(), None),
        ("releaseHistory", set(), None),
        ("appPlatform", set(), 30),
    )
    for key, accepted_modes, maximum_age_days in specifications:
        value = inputs[key].value
        errors = (
            []
            if key == "thirdPartyIntake"
            else _top_level_release_proof_errors(value, key)
        )
        if key == "thirdPartyIntake":
            if not _status_pass(value.get("status")):
                errors.append(f"{key} status is not pass")
            errors.extend(explicit_production_classification_errors(value, key))
            if value.get("releaseId") != release_id:
                errors.append(f"{key} releaseId is missing or does not match the candidate")
            if value.get("buildVersion") != build_version:
                errors.append(f"{key} buildVersion is missing or does not match the candidate")
        elif (
            key not in HISTORICAL_RELEASE_INPUT_KEYS
            and value.get("releaseId") not in {None, release_id}
        ):
            errors.append(f"{key} releaseId does not match the candidate")
        if accepted_modes:
            mode = str(value.get("mode") or value.get("evidenceMode") or "")
            if mode not in accepted_modes:
                errors.append(f"{key} mode is not protected live evidence")
        if maximum_age_days is not None:
            evidence_time = (
                value.get("generatedAt")
                or value.get("finishedAt")
                or value.get("verifiedAt")
                or value.get("createdAt")
            )
            freshness = freshness_error(evidence_time, now, maximum_age_days, key)
            if freshness:
                errors.append(freshness)
        for error in errors:
            state.block(
                f"stable-1.0-rc.evidence.{key}",
                "stable-1.0-rc.prerequisites",
                error + ".",
                "Attach fresh, real, candidate-bound protected evidence.",
            )

    sandbox = evidence_by_id(inputs["appPlatform"].value).get("apphost.sandbox-provider")
    if not isinstance(sandbox, dict) or not _status_pass(sandbox.get("status")):
        state.block(
            "stable-1.0-rc.evidence.sandbox-provider",
            "stable-1.0-rc.prerequisites",
            "AppHost sandbox-provider evidence is missing or failing.",
            "Rerun the protected sandbox-provider tests for the candidate.",
        )


def validate_catalog_operations(
    value: dict[str, Any],
    release_id: str,
    build_version: str,
    now: dt.datetime,
    state: ValidationState,
) -> None:
    """Validate the protected current-candidate stable catalog operations contract."""

    errors = validate_schema(value, CATALOG_OPERATIONS_SCHEMA)
    expected_scalars = {
        "schemaVersion": 1,
        "kind": CATALOG_OPERATIONS_KIND,
        "releaseId": release_id,
        "buildVersion": build_version,
        "status": "pass",
        "fixtureOnly": False,
        "simulatedOnly": False,
        "nonRelease": False,
        "channel": "stable",
    }
    errors.extend(
        f"{key} must be {expected!r}"
        for key, expected in expected_scalars.items()
        if value.get(key) != expected
    )
    for key in ("catalogId", "signingKeyId"):
        if not isinstance(value.get(key), str) or not value[key].strip():
            errors.append(f"{key} must be a non-empty string")
    if COMMIT_RE.fullmatch(str(value.get("sourceCommit", "")).lower()) is None:
        errors.append("sourceCommit is malformed")
    generated_at = parse_timestamp(value.get("generatedAt"))
    artifact_timestamp = parse_timestamp(value.get("artifactTimestamp"))
    if artifact_timestamp is None:
        errors.append("artifactTimestamp is malformed")
    elif generated_at is not None and artifact_timestamp > generated_at:
        errors.append("artifactTimestamp cannot be later than generatedAt")
    if type(value.get("revision")) is not int or value["revision"] < 0:
        errors.append("revision must be a non-negative integer")
    for key in ("catalogDigest", "signatureDigest"):
        if DIGEST_RE.fullmatch(str(value.get(key, ""))) is None:
            errors.append(f"{key} is malformed")
    for count in ("advisoryCount", "denylistCount"):
        if type(value.get(count)) is not int or value[count] < 0:
            errors.append(f"{count} must be a non-negative integer")
    rotation = value.get("keyRotation") if isinstance(value.get("keyRotation"), dict) else {}
    if rotation != {"status": "complete", "compromised": False}:
        errors.append("keyRotation must be complete and uncompromised")
    primary = value.get("primary")
    errors.extend(_catalog_health_errors(primary, "primary"))
    if isinstance(primary, dict):
        if primary.get("revision") != value.get("revision"):
            errors.append("primary revision does not bind the current catalog revision")
        if primary.get("digest") != value.get("catalogDigest"):
            errors.append("primary digest does not bind the current catalog artifact")
    mirrors = value.get("mirrors")
    if not isinstance(mirrors, list) or not mirrors:
        errors.append("mirrors must contain at least one verified mirror")
    else:
        for index, mirror in enumerate(mirrors):
            errors.extend(_catalog_health_errors(mirror, f"mirrors[{index}]"))
            if not isinstance(mirror, dict) or mirror.get("transportFallbackOnly") is not True:
                errors.append(f"mirrors[{index}] must be transport fallback only")
    rollback = value.get("rollback") if isinstance(value.get("rollback"), dict) else {}
    if rollback.get("status") != "pass" or rollback.get("signatureVerified") is not True:
        errors.append("rollback must be passing and signature verified")
    if type(rollback.get("revision")) is not int or rollback.get("revision", -1) < 0:
        errors.append("rollback revision must be a non-negative integer")
    if DIGEST_RE.fullmatch(str(rollback.get("digest", ""))) is None:
        errors.append("rollback digest is malformed")
    current_revision = value.get("revision")
    rollback_revision = rollback.get("revision")
    if (
        type(current_revision) is int
        and type(rollback_revision) is int
        and rollback_revision >= current_revision
    ):
        errors.append("rollback revision must precede the current catalog revision")
    if rollback.get("digest") == value.get("catalogDigest"):
        errors.append("rollback digest must bind a distinct prior catalog artifact")
    redaction = value.get("redaction") if isinstance(value.get("redaction"), dict) else {}
    if redaction.get("status") != "pass" or redaction.get("findingCount") != 0 or redaction.get("findings") != []:
        errors.append("redaction must pass with zero findings")
    freshness = freshness_error(value.get("generatedAt"), now, 30, "catalog operations")
    if freshness:
        errors.append(freshness)
    for error in errors:
        state.block(
            "stable-1.0-rc.catalog-operations",
            "stable-1.0-rc.catalog-freeze",
            error + ".",
            "Regenerate protected stable catalog-operations evidence for this candidate.",
        )


def _catalog_health_errors(value: Any, label: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label} health is missing"]
    errors: list[str] = []
    if value.get("status") != "pass" or value.get("signatureVerified") is not True:
        errors.append(f"{label} must pass the catalog signature check")
    if type(value.get("revision")) is not int or value.get("revision", -1) < 0:
        errors.append(f"{label} revision is malformed")
    if DIGEST_RE.fullmatch(str(value.get("digest", ""))) is None:
        errors.append(f"{label} digest is malformed")
    return errors


def evidence_by_id(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index redaction-safe evidence rows by identifier."""

    result: dict[str, dict[str, Any]] = {}
    entries = summary.get("evidence")
    if not isinstance(entries, list):
        return result
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        evidence_id = entry.get("id") or entry.get("evidenceId")
        if isinstance(evidence_id, str) and evidence_id and evidence_id not in result:
            result[evidence_id] = entry
    return result


def all_unique(values: Iterable[str]) -> bool:
    """Return whether all strings in an iterable are unique."""

    materialized = list(values)
    return len(materialized) == len(set(materialized))
